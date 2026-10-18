import { expect, test } from 'bun:test'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildFlags, buildFrame, computeProof, decodeHeader, encodeFrame, FrameType, HEADER_LEN, Priority, SERVER_PROOF_DOMAIN, SubcClient } from '@cortexkit/subc-client'
import { ClaustrumClient } from '../index'

const refused = { result: { error: { class: 'permanent', code: 'not_found' } } }
const first = { kind: 'changed', epoch: 'epoch', seq: 1, view: 'view', keys: 'keys' }
type Script = { notices: unknown[]; terminal: FrameType; body?: unknown }

async function withRoute(scripts: Script[], listReply: unknown, run: (client: ClaustrumClient, requests: Record<string, unknown>[], transport: SubcClient) => Promise<void>) {
  const key = new Uint8Array(32).fill(7), daemonId = new Uint8Array(16).fill(9)
  const sockets = new Set<Socket>()
  const requests: Record<string, unknown>[] = []
  let failure: unknown
  let channel = 0
  const server = createServer((socket) => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket))
    let buffer = Buffer.alloc(0), phase = 0
    const sendAuth = (body: unknown) => {
      const bytes = Buffer.from(JSON.stringify(body)), size = Buffer.alloc(4)
      size.writeUInt32LE(bytes.length); socket.write(Buffer.concat([size, bytes]))
    }
    socket.on('data', (data) => {
      try {
        buffer = Buffer.concat([buffer, typeof data === 'string' ? Buffer.from(data) : data])
        for (;;) {
          if (phase < 2) {
            if (buffer.length < 4 || buffer.length < 4 + buffer.readUInt32LE()) return
            const length = buffer.readUInt32LE(), body = JSON.parse(buffer.subarray(4, 4 + length).toString())
            buffer = buffer.subarray(4 + length)
            if (phase++ === 0) {
              const nonce = new Uint8Array(32).fill(5)
              sendAuth({ daemon_id: [...daemonId], server_nonce: [...nonce], daemon_ver: 'test',
                server_proof: [...computeProof(key, SERVER_PROOF_DOMAIN, Uint8Array.from(body.client_nonce), nonce, daemonId)] })
            }
            continue
          }
          if (buffer.length < HEADER_LEN) return
          const header = decodeHeader(buffer.subarray(0, HEADER_LEN))
          if (buffer.length < HEADER_LEN + header.len) return
          const bytes = buffer.subarray(HEADER_LEN, HEADER_LEN + header.len)
          buffer = buffer.subarray(HEADER_LEN + header.len)
          if (header.ty !== FrameType.Request) continue
          const body = JSON.parse(bytes.toString())
          const send = (ty: FrameType, value?: unknown) => socket.write(encodeFrame(buildFrame(ty,
            buildFlags(false, Priority.Interactive, false), header.channel, header.epoch, header.corr,
            value === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(value)))))
          // Channel zero uses subc's control envelope, not the vault's read envelope.
          if (header.channel === 0) {
            expect(body.op).toBe('route.open')
            send(FrameType.Response, { route_channel: ++channel, route_epoch: 1 })
            continue
          }
          requests.push(body)
          if (!isVaultReadEnvelope(body)) {
            send(FrameType.Error, { code: 'invalid_request', message: 'request body not decodable' })
            continue
          }
          if (body.method === 'credential.list_scoped') send(FrameType.Response, listReply)
          else {
            expect(body.method).toBe('auth.watch_scoped')
            expect(body.params).toEqual({ enrollment_token: 'token' })
            const script = scripts.shift()!
            for (const notice of script.notices) send(FrameType.StreamData, notice)
            send(script.terminal, script.body)
          }
        }
      } catch (error) { failure = error; socket.destroy() }
    })
  })
  const dir = await mkdtemp(join(tmpdir(), 'watch-wire-'))
  let client: ClaustrumClient | undefined
  try {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('no address')
    const path = join(dir, 'connection.json')
    await writeFile(path, JSON.stringify({ schema: 1, endpoints: [{ host: '127.0.0.1', port: address.port }],
      key: [...key], daemon_id: [...daemonId], pid: process.pid }), { mode: 0o600 })
    let transport!: SubcClient
    client = await ClaustrumClient.connect({ connectionFile: path, logger: () => {},
      connector: async (options) => { transport = await SubcClient.connect(options); return transport } })
    try { await run(client, requests, transport) }
    catch (error) { throw failure ?? error }
    if (failure) throw failure
    expect(scripts).toHaveLength(0)
  } finally {
    client?.close(); for (const socket of sockets) socket.destroy()
    await new Promise<void>((resolve) => server.close(() => resolve()))
    await rm(dir, { recursive: true, force: true })
  }
}

test('watch real SDK route distinguishes all endings including revocation and drain', async () => {
  const options = { enrollmentToken: 'token' }
  for (const [terminal, body, kind] of [
    [FrameType.Response, refused, 'refused'],
    [FrameType.Error, { code: 'unknown_method', message: 'old vault' }, 'unsupported'],
    [FrameType.Error, { code: 'route_closed', message: 'lost route' }, 'transport_lost'],
  ] as const) {
    await withRoute([{ notices: [], terminal, body }], refused, async (client) => {
      expect(await client.watchScoped(() => {}, options).closed).toMatchObject({ kind })
    })
  }
  await withRoute([{ notices: [first], terminal: FrameType.StreamEnd }], null, async (client) => {
    expect(await client.watchScoped(() => {}, options).closed).toEqual({ kind: 'ended' })
  })
  await withRoute([{ notices: [], terminal: FrameType.StreamEnd }], { result: { credentials: [], view: 'view' } }, async (client, requests) => {
    expect(await client.watchScoped(() => {}, options).closed).toEqual({ kind: 'not_accepting' })
    expect(requests.filter((body) => body.method === 'credential.list_scoped')).toHaveLength(1)
  })
  await withRoute([{ notices: [first], terminal: FrameType.Response, body: refused },
    { notices: [], terminal: FrameType.Response, body: refused }], refused, async (client, requests) => {
    expect(await client.watchScoped(() => {}, options).closed).toEqual({ kind: 'ended' })
    expect(await client.watchScoped(() => {}, options).closed).toMatchObject({ kind: 'refused', error: { code: 'not_found' } })
    expect(requests.filter((body) => body.method === 'auth.watch_scoped')).toHaveLength(2)
    expect(requests.filter((body) => body.method === 'credential.list_scoped')).toHaveLength(1)
  })
})

test('watch and confirming list send exact method request envelopes', async () => {
  await withRoute([{ notices: [], terminal: FrameType.StreamEnd }],
    { result: { credentials: [], view: 'view' } }, async (client, requests) => {
      expect(await client.watchScoped(() => {}, { enrollmentToken: 'token' }).closed)
        .toEqual({ kind: 'not_accepting' })
      expect(requests).toEqual([
        { method: 'auth.watch_scoped', params: { enrollment_token: 'token' } },
        { method: 'credential.list_scoped', params: { enrollment_token: 'token' } },
      ])
    })
})

// The stand-in must refuse exactly what the vault refuses, or a client sending the
// wrong envelope passes here and fails live. This checks the stand-in's own rule
// directly; the request-shape test above proves the clients send what it accepts.
test('watch wire stand-in accepts only the vault read envelope', () => {
  for (const body of [
    { op: 'auth.watch_scoped', params: {} },
    { op: 'credential.list_scoped', params: {} },
    { method: 'auth.watch_scoped', op: 'auth.watch_scoped', params: {} },
    { method: 'credential.list_scoped', params: {}, extra: true },
    { method: 1, params: {} },
    null,
    ['credential.list_scoped'],
  ]) expect(isVaultReadEnvelope(body)).toBe(false)
  expect(isVaultReadEnvelope({ method: 'credential.list_scoped' })).toBe(true)
  expect(isVaultReadEnvelope({ method: 'auth.watch_scoped', params: {} })).toBe(true)
})

/** The vault's read envelope: exactly `method` (a string) and an optional `params`. */
function isVaultReadEnvelope(body: unknown): body is { method: string; params?: unknown } {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return false
  const keys = Object.keys(body).sort().join(',')
  return (keys === 'method' || keys === 'method,params') && typeof (body as { method: unknown }).method === 'string'
}
