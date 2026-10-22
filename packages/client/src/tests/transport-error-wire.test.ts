import { expect, test } from 'bun:test'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
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
  SERVER_PROOF_DOMAIN,
  SubcCallError,
  SubcClient,
} from '@cortexkit/subc-client'
import { ClaustrumClient, ClaustrumCredentialError } from '../index'

// How a transport Error frame (`{code, message}`, no class) becomes a credential error,
// and when the client spends its one reconnect on it. The vault side is a stand-in daemon
// spoken to through the real SDK, so the codes arrive exactly as a live vault's would.

type Reply = { type: FrameType; body?: unknown }
type Answer = (method: string, params: unknown) => Reply

const KEY = new Uint8Array(32).fill(7)
const DAEMON_ID = new Uint8Array(16).fill(9)
const PROPOSE = { name: 'consumer', requestSecretHash: '0'.repeat(64) }
const PROPOSED = { result: { request_id: 'request-id' } }

function errorFrame(code: string): Reply {
  return { type: FrameType.Error, body: { code, message: `stand-in ${code}` } }
}

/** The vault's read envelope: exactly `method` (a string) and an optional `params`. */
function isVaultReadEnvelope(body: unknown): body is { method: string; params?: unknown } {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return false
  const keys = Object.keys(body).sort().join(',')
  return (keys === 'method' || keys === 'method,params') && typeof (body as { method: unknown }).method === 'string'
}

type Vault = {
  server: Server
  sockets: Set<Socket>
  /** Every read-envelope request the stand-in received, across all connections. */
  requests: { method: string; params?: unknown }[]
  /** TCP connections the stand-in accepted. */
  connections: () => number
  failure: () => unknown
  connectionFile: string
}

async function startVault(dir: string, answer: Answer): Promise<Vault> {
  const sockets = new Set<Socket>()
  const requests: { method: string; params?: unknown }[] = []
  let connections = 0
  let failure: unknown
  let channel = 0
  const server = createServer((socket) => {
    connections += 1
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    let buffer = Buffer.alloc(0)
    let phase = 0
    const sendAuth = (body: unknown) => {
      const bytes = Buffer.from(JSON.stringify(body))
      const size = Buffer.alloc(4)
      size.writeUInt32LE(bytes.length)
      socket.write(Buffer.concat([size, bytes]))
    }
    socket.on('data', (data) => {
      try {
        buffer = Buffer.concat([buffer, typeof data === 'string' ? Buffer.from(data) : data])
        for (;;) {
          if (phase < 2) {
            if (buffer.length < 4 || buffer.length < 4 + buffer.readUInt32LE()) return
            const length = buffer.readUInt32LE()
            const body = JSON.parse(buffer.subarray(4, 4 + length).toString())
            buffer = buffer.subarray(4 + length)
            if (phase++ === 0) {
              const nonce = new Uint8Array(32).fill(5)
              sendAuth({
                daemon_id: [...DAEMON_ID],
                server_nonce: [...nonce],
                daemon_ver: 'test',
                server_proof: [...computeProof(KEY, SERVER_PROOF_DOMAIN, Uint8Array.from(body.client_nonce), nonce, DAEMON_ID)],
              })
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
          const send = (reply: Reply) => socket.write(encodeFrame(buildFrame(reply.type,
            buildFlags(false, Priority.Interactive, false), header.channel, header.epoch, header.corr,
            reply.body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(reply.body)))))
          // Channel zero uses subc's control envelope, not the vault's read envelope.
          if (header.channel === 0) {
            expect(body.op).toBe('route.open')
            send({ type: FrameType.Response, body: { route_channel: ++channel, route_epoch: 1 } })
            continue
          }
          // Strict, as the vault is: anything but the read envelope is refused as undecodable.
          if (!isVaultReadEnvelope(body)) {
            send(errorFrame('invalid_request'))
            continue
          }
          requests.push(body)
          send(answer(body.method, body.params))
        }
      } catch (error) {
        failure = error
        socket.destroy()
      }
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('stand-in vault has no TCP address')
  const connectionFile = join(dir, `connection-${address.port}.json`)
  await writeConnectionFile(connectionFile, address.port)
  return { server, sockets, requests, connections: () => connections, failure: () => failure, connectionFile }
}

async function writeConnectionFile(path: string, port: number): Promise<void> {
  await writeFile(path, JSON.stringify({
    schema: 1,
    endpoints: [{ host: '127.0.0.1', port }],
    key: [...KEY],
    daemon_id: [...DAEMON_ID],
    pid: process.pid,
  }), { mode: 0o600 })
}

/** A connection file for a port nothing listens on, so a connect to it is refused. */
async function deadConnectionFile(dir: string): Promise<string> {
  const probe = createServer()
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve))
  const address = probe.address()
  if (!address || typeof address === 'string') throw new Error('probe has no TCP address')
  await new Promise<void>((resolve) => probe.close(() => resolve()))
  const path = join(dir, 'dead-connection.json')
  await writeConnectionFile(path, address.port)
  return path
}

type Context = {
  client: ClaustrumClient
  vault: Vault
  /** How many times the client asked its connector for a connection, the first included. */
  connects: () => number
}

/**
 * Run `body` against a stand-in vault. `reconnectTo`, when given, picks the connection
 * file for every connect after the first, so a test can make the reconnect itself fail.
 */
async function withVault(
  answer: Answer,
  body: (context: Context) => Promise<void>,
  reconnectTo?: (dir: string) => Promise<string>,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'transport-error-wire-'))
  let vault: Vault | undefined
  let client: ClaustrumClient | undefined
  try {
    vault = await startVault(dir, answer)
    const reconnectFile = reconnectTo === undefined ? undefined : await reconnectTo(dir)
    let connects = 0
    const started = vault
    client = await ClaustrumClient.connect({
      connectionFile: started.connectionFile,
      logger: () => {},
      connector: async (options) => {
        connects += 1
        const connectionFile = connects > 1 && reconnectFile !== undefined ? reconnectFile : options.connectionFile
        return SubcClient.connect({ ...options, connectionFile })
      },
    })
    try {
      await body({ client, vault: started, connects: () => connects })
    } catch (error) {
      throw started.failure() ?? error
    }
    if (started.failure()) throw started.failure()
  } finally {
    client?.close()
    if (vault) {
      for (const socket of vault.sockets) socket.destroy()
      await new Promise<void>((resolve) => vault!.server.close(() => resolve()))
    }
    await rm(dir, { recursive: true, force: true })
  }
}

async function failureOf(call: Promise<unknown>): Promise<ClaustrumCredentialError> {
  const outcome = await call.then(() => undefined, (error: unknown) => error)
  expect(outcome).toBeInstanceOf(ClaustrumCredentialError)
  return outcome as ClaustrumCredentialError
}

test('unknown_method from a vault that predates the op is permanent and never reconnected', async () => {
  await withVault(() => errorFrame('unknown_method'), async ({ client, vault, connects }) => {
    const error = await failureOf(client.enrollPropose(PROPOSE))
    expect({ code: error.code, class: error.class, action: error.action })
      .toEqual({ code: 'unknown_method', class: 'permanent', action: 'gone' })
    expect(vault.requests).toEqual([{
      method: 'auth.enroll_propose',
      params: { proposed_name: 'consumer', request_secret_hash: '0'.repeat(64) },
    }])
    expect(vault.connections()).toBe(1)
    expect(connects()).toBe(1)
  })
})

test('a transient terminal error reconnects once and retries the call', async () => {
  let calls = 0
  await withVault(() => (++calls === 1 ? errorFrame('module_timeout') : { type: FrameType.Response, body: PROPOSED }),
    async ({ client, vault, connects }) => {
      expect(await client.enrollPropose(PROPOSE)).toEqual({ requestId: 'request-id' })
      expect(vault.requests.map((request) => request.method)).toEqual(['auth.enroll_propose', 'auth.enroll_propose'])
      expect(vault.connections()).toBe(2)
      expect(connects()).toBe(2)
    })
})

test('a failed reconnect keeps the original code and class', async () => {
  await withVault(() => errorFrame('module_timeout'), async ({ client, vault, connects }) => {
    const error = await failureOf(client.enrollPropose(PROPOSE))
    expect({ code: error.code, class: error.class, action: error.action })
      .toEqual({ code: 'module_timeout', class: 'transient', action: 'retry' })
    // The reconnect really was attempted, and really failed: the stand-in saw one
    // connection and one request, and the second connect went to a dead port.
    expect(connects()).toBe(2)
    expect(vault.connections()).toBe(1)
    expect(vault.requests).toHaveLength(1)
  }, deadConnectionFile)
})

test('a failed retry after a reconnect keeps the original code and class', async () => {
  let calls = 0
  await withVault(() => errorFrame(++calls === 1 ? 'module_timeout' : 'route_wedged'),
    async ({ client, vault, connects }) => {
      const error = await failureOf(client.enrollPropose(PROPOSE))
      expect({ code: error.code, class: error.class }).toEqual({ code: 'module_timeout', class: 'transient' })
      expect(connects()).toBe(2)
      expect(vault.requests).toHaveLength(2)
    })
})

/**
 * The remaining definitive codes, which a real vault or daemon sends in other
 * situations than an unknown operation. Some are sent before a route exists, so these
 * are fed as the SDK error the client receives rather than through the stand-in.
 * `unknown_method` is pinned on the wire by its own test above.
 */
test('every other definitive transport code is permanent and skips the reconnect', async () => {
  for (const code of [
    'invalid_params',
    'invalid_request',
    'flow_scopes_unsupported',
    'invalid_control_body',
    'unknown_module',
    'missing_identity',
  ]) {
    let connects = 0
    let calls = 0
    const client = await ClaustrumClient.connect({
      logger: () => {},
      connector: async () => {
        connects += 1
        return {
          call: async () => {
            calls += 1
            throw new SubcCallError('terminal', `terminal ${code}`, code)
          },
          close: () => {},
        } as never
      },
    })
    try {
      const error = await failureOf(client.getCredential('credential-handle'))
      expect({ code: error.code, class: error.class, action: error.action })
        .toEqual({ code, class: 'permanent', action: 'gone' })
      expect({ code, connects, calls }).toEqual({ code, connects: 1, calls: 1 })
    } finally {
      client.close()
    }
  }
})
