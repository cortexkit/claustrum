import { afterEach, describe, expect, test } from 'bun:test'
import { randomBytes } from 'node:crypto'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildFlags,
  buildFrame,
  computeProof,
  decodeHeader,
  encodeFrame,
  FrameType,
  HEADER_LEN,
  Priority,
  PROTOCOL_VERSION,
  SERVER_PROOF_DOMAIN,
} from '@cortexkit/subc-client'
import { ClaustrumClient } from '../index'

// How long the fake daemon refuses route.open with module_warming, the refusal the
// real daemon sends while the vault is still starting after a restart. Older subc
// clients gave up on such refusals after six attempts, which with the default backoff
// (100, 200, 400, 800, 1600 ms between them) is about 3.1 s. The window must be longer
// than that so this test fails on a client that still has the attempt cap.
const WARMING_WINDOW_MS = 4_000

type FakeSubcDaemon = {
  server: Server
  connectionFile: string
  routeOpens: { refused: number; accepted: number }
  dataRequests: unknown[]
}

const cleanups: Array<() => Promise<void>> = []

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()))
})

/**
 * A minimal subc daemon speaking the real handshake and frame envelope over TCP, so
 * the test drives the SDK's own managed call path (route.open retries included)
 * rather than a stubbed `call()`.
 */
async function startWarmingDaemon(warmingWindowMs: number): Promise<FakeSubcDaemon> {
  const dir = await mkdtemp(join(tmpdir(), 'claustrum-route-retry-'))
  const key = randomBytes(32)
  const daemonId = randomBytes(16)
  const routeOpens = { refused: 0, accepted: 0 }
  const dataRequests: unknown[] = []
  const sockets = new Set<Socket>()
  // The warming window starts at the first route.open, the moment a caller first
  // observes the vault as unavailable.
  let firstOpenAt: number | undefined

  const server = createServer((socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    socket.on('error', () => undefined)
    let buffer = Buffer.alloc(0)
    let stage: 'hello' | 'auth' | 'frames' = 'hello'
    let clientNonce = Buffer.alloc(0)
    const serverNonce = randomBytes(32)

    const writeAuthMessage = (value: unknown): void => {
      const json = Buffer.from(JSON.stringify(value), 'utf8')
      const prefix = Buffer.alloc(4)
      prefix.writeUInt32LE(json.length, 0)
      socket.write(Buffer.concat([prefix, json]))
    }
    const reply = (ty: FrameType, channel: number, epoch: number, corr: bigint, body: unknown): void => {
      const bytes = body === undefined ? new Uint8Array(0) : Buffer.from(JSON.stringify(body), 'utf8')
      socket.write(encodeFrame(buildFrame(ty, buildFlags(false, Priority.Interactive, false), channel, epoch, corr, bytes)))
    }

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk])
      for (;;) {
        if (stage !== 'frames') {
          if (buffer.length < 4) return
          const len = buffer.readUInt32LE(0)
          if (buffer.length < 4 + len) return
          const message = JSON.parse(buffer.subarray(4, 4 + len).toString('utf8')) as Record<string, unknown>
          buffer = buffer.subarray(4 + len)
          if (stage === 'hello') {
            clientNonce = Buffer.from(message.client_nonce as number[])
            writeAuthMessage({
              daemon_id: Array.from(daemonId),
              server_nonce: Array.from(serverNonce),
              daemon_ver: 'fake',
              server_proof: Array.from(computeProof(key, SERVER_PROOF_DOMAIN, clientNonce, serverNonce, daemonId)),
            })
            stage = 'auth'
          } else {
            stage = 'frames'
          }
          continue
        }
        if (buffer.length < HEADER_LEN) return
        const header = decodeHeader(buffer.subarray(0, HEADER_LEN))
        if (buffer.length < HEADER_LEN + header.len) return
        const body = buffer.subarray(HEADER_LEN, HEADER_LEN + header.len)
        buffer = buffer.subarray(HEADER_LEN + header.len)
        if (header.ty === FrameType.Ping) {
          reply(FrameType.Pong, header.channel, header.epoch, header.corr, undefined)
          continue
        }
        if (header.ty !== FrameType.Request) continue
        const request = JSON.parse(body.toString('utf8')) as Record<string, unknown>
        if (header.channel === 0 && request.op === 'route.open') {
          firstOpenAt ??= Date.now()
          if (Date.now() - firstOpenAt < warmingWindowMs) {
            routeOpens.refused += 1
            reply(FrameType.Error, 0, 0, header.corr, { code: 'module_warming', message: 'vault is warming up' })
          } else {
            routeOpens.accepted += 1
            reply(FrameType.Response, 0, 0, header.corr, { route_channel: 7, route_epoch: 1 })
          }
          continue
        }
        if (header.channel === 7) {
          dataRequests.push(request)
          reply(FrameType.Response, 7, header.epoch, header.corr, {
            result: { payload: [111, 107], record_version: 3 },
          })
        }
      }
    })
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fake daemon has no TCP address')

  const connectionFile = join(dir, 'connection.json')
  await writeFile(connectionFile, JSON.stringify({
    schema: 1,
    wire_version: PROTOCOL_VERSION,
    endpoints: [{ host: '127.0.0.1', port: address.port }],
    key: Array.from(key),
    daemon_id: Array.from(daemonId),
    pid: process.pid,
    daemon_ver: 'fake',
  }))
  // The SDK refuses a connection file readable by anyone but its owner.
  await chmod(connectionFile, 0o600)

  cleanups.push(async () => {
    for (const socket of sockets) socket.destroy()
    await new Promise<void>((resolve) => server.close(() => resolve()))
    await rm(dir, { recursive: true, force: true })
  })
  return { server, connectionFile, routeOpens, dataRequests }
}

describe('ClaustrumClient route.open retry', () => {
  test('waits out a vault warm-up longer than the old six-attempt retry cap', async () => {
    const daemon = await startWarmingDaemon(WARMING_WINDOW_MS)
    const client = await ClaustrumClient.connect({
      connectionFile: daemon.connectionFile,
      identity: { project_root: '/tmp/project', harness: 'opencode', session: 'store-test' },
      logger: () => undefined,
    })
    try {
      const started = Date.now()
      const credential = await client.getCredential('handle-1')
      const elapsed = Date.now() - started

      expect(credential).toMatchObject({ material: 'ok', recordVersion: 3 })
      expect(elapsed).toBeGreaterThanOrEqual(WARMING_WINDOW_MS)
      // The old client surfaced the sixth refusal as a failure, so a success after at
      // least six refusals proves the call outlived that attempt cap.
      expect(daemon.routeOpens.refused).toBeGreaterThanOrEqual(6)
      expect(daemon.routeOpens.accepted).toBe(1)
      expect(daemon.dataRequests).toEqual([
        { method: 'credential.get', params: { handle: 'handle-1', force_refresh: false } },
      ])
    } finally {
      client.close()
    }
  }, 20_000)
})
