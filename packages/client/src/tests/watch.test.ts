import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { ClaustrumClient, ScopedWatchError, type PolicyWatchNotice, type ScopedWatchNotice } from '../index'
import { decodeScopedWatchNotice } from '../watch'
import { rejectionOf } from './settle'

const fixture = JSON.parse(readFileSync(new URL('../../../../crates/credentials-module/tests/fixtures/enrollment_wire_contract.json', import.meta.url), 'utf8'))
// `op` labels sections in the producer fixture; route request bodies use `method`.
const samples: string[] = fixture.operations.find((op: { op: string }) => op.op === 'auth.watch_scoped').success
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const notice = (seq = 1, epoch = 'epoch-a'): ScopedWatchNotice => ({ kind: 'changed', epoch, seq, view: 'view', keys: 'keys' })
const refusal = { result: { error: { code: 'not_found', class: 'permanent' } } }
type Script = { notices: Uint8Array[]; failure?: string; hold?: boolean }

function isReadRequest(body: unknown): boolean {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return false
  const keys = Object.keys(body).sort().join(',')
  return (keys === 'method' || keys === 'method,params') &&
    'method' in body && typeof body.method === 'string'
}

// Like the SDK, this stand-in erases terminal Response bodies and StreamEnd alike.
class WatchDaemon {
  opens: unknown[][] = []
  requests: unknown[] = []
  reads: unknown[][] = []
  cancels = 0
  routesClosed = 0
  scripts: Script[] = []
  reply: unknown = { result: { credentials: [], view: 'view' } }
  async routeOpen(...args: unknown[]) { this.opens.push(args); return { channel: this.opens.length, epoch: 1 } }
  subscribe(_route: unknown, body: unknown, onEvent: (bytes: Uint8Array) => void) {
    this.requests.push(body)
    const script = this.scripts.shift()!
    let resolve!: () => void
    const closed = new Promise<void>((yes, no) => {
      resolve = yes
      queueMicrotask(() => {
        if (!isReadRequest(body)) {
          no(Object.assign(new Error('request body not decodable'), { code: 'invalid_request' }))
          return
        }
        for (const bytes of script.notices) onEvent(bytes)
        if (script.failure) no(Object.assign(new Error(script.failure), { code: script.failure }))
        else if (!script.hold) yes()
      })
    })
    return { closed, unsubscribe: () => { this.cancels++; resolve() } }
  }
  async call(...args: unknown[]) {
    this.reads.push(args)
    if (!isReadRequest({ method: args[1], params: args[2] })) {
      throw Object.assign(new Error('request body not decodable'), { code: 'invalid_request' })
    }
    return this.reply
  }
  async closeRoute() { this.routesClosed++ }
  close() {}
}
async function clientWith(daemon: WatchDaemon) {
  return ClaustrumClient.connect({ connectionFile: '/nonexistent/watch.json', identity: { project_root: '/project' } as never,
    connector: async () => daemon as never, logger: () => {} })
}

function policySample(caseName: string) {
  const contract = readFileSync(new URL('../../../../docs/wire-contract-v1.md', import.meta.url), 'utf8')
  const sample = contract.split(`<!-- golden:${caseName} -->\n\`\`\`json\n`)[1]?.split('\n```')[0]
  if (sample === undefined) throw new Error(`missing policy wire sample: ${caseName}`)
  return JSON.parse(sample)
}

test('policyActive preserves the exact policy text and distinguishes no policy from a refusal', async () => {
  const daemon = new WatchDaemon()
  const client = await clientWith(daemon)
  try {
    daemon.reply = policySample('policy.active.none')
    expect(await client.policyActive()).toBeNull()
    const ready = policySample('policy.active.ready')
    daemon.reply = ready
    expect(await client.policyActive()).toEqual({
      version: 1, manifestVersion: 41, policySha256: ready.result.policy_sha256, policyText: ready.result.policy_text,
    })
    daemon.reply = refusal
    expect(await rejectionOf(client.policyActive())).toMatchObject({ code: 'not_found', class: 'permanent' })
    daemon.reply = { result: { ...ready.result, policy_text: null } }
    expect(await rejectionOf(client.policyActive())).toMatchObject({ code: 'invalid_response' })
    expect(daemon.reads.map((call) => call.slice(0, 3))).toEqual(Array(4).fill(['claustrum', 'policy.active', {}]))
  } finally {
    client.close()
  }
})

test('policyWatch decodes both vault snapshots and confirms a zero-notice close once', async () => {
  const daemon = new WatchDaemon()
  const active = policySample('policy.watch.changed')
  daemon.scripts = [{ notices: [encode(policySample('policy.watch.initial')), encode(active)] }, { notices: [] }]
  const client = await clientWith(daemon)
  try {
    const received: PolicyWatchNotice[] = []
    expect(await client.policyWatch((notice) => received.push(notice)).closed).toEqual({ kind: 'ended' })
    expect(received).toEqual([
      { kind: 'changed', seq: 1, epoch: '00112233445566778899aabbccddeeff', version: null, policySha256: null },
      { kind: 'changed', seq: 2, epoch: '00112233445566778899aabbccddeeff', version: 1, policySha256: active.policy_sha256 },
    ])
    expect(daemon.reads).toHaveLength(0)
    daemon.reply = refusal
    expect(await client.policyWatch(() => {}).closed).toMatchObject({ kind: 'refused', error: { code: 'not_found' } })
    expect(daemon.reads.map((call) => call.slice(0, 3))).toEqual([['claustrum', 'policy.active', {}]])
    expect(daemon.requests).toEqual(Array(2).fill({ method: 'policy.watch', params: {} }))
  } finally {
    client.close()
  }
})

test('policyToken sends the exact request and never falls back after a refusal', async () => {
  const daemon = new WatchDaemon()
  const client = await clientWith(daemon)
  const input = { identity: 'github_app:agent', service: 'github', kind: 'add_issue_comment', resource: 'org/r', policyVersion: 1 }
  try {
    daemon.reply = { result: {
      token: 'fixture-token-1', expires_at_ms: 4_102_444_800_000, repositories: ['org/r'],
      permissions: { issues: 'write', pull_requests: 'write' },
    } }
    expect(await client.policyToken(input)).toEqual({
      token: 'fixture-token-1', expiresAtMs: 4_102_444_800_000, repositories: ['org/r'],
      permissions: { issues: 'write', pull_requests: 'write' },
    })
    daemon.reply = { result: { error: { code: 'policy_version_not_active', class: 'permanent' } } }
    expect(await rejectionOf(client.policyToken(input))).toMatchObject({ code: 'policy_version_not_active', class: 'permanent' })
    expect(daemon.reads.map((call) => call.slice(0, 3))).toEqual(Array(2).fill([
      'claustrum', 'credential.policy_token',
      { identity: 'github_app:agent', service: 'github', kind: 'add_issue_comment', resource: 'org/r', policy_version: 1 },
    ]))
  } finally {
    client.close()
  }
})

test('watch stand-in rejects op and extra read-envelope keys', async () => {
  for (const body of [
    { op: 'auth.watch_scoped', params: {} },
    { method: 'auth.watch_scoped', op: 'auth.watch_scoped', params: {} },
    { method: 'auth.watch_scoped', params: {}, extra: true },
    { method: 1, params: {} },
  ]) {
    const daemon = new WatchDaemon(); daemon.scripts = [{ notices: [] }]
    expect(await rejectionOf(daemon.subscribe({}, body, () => {}).closed)).toMatchObject({ code: 'invalid_request' })
  }
})

test('watch decodes the producer notices exactly', () => {
  expect(samples.length).toBe(2)
  expect(samples.map((sample) => decodeScopedWatchNotice(new TextEncoder().encode(sample)))).toEqual([
    { epoch: '00000000000000000000000000000000', keys: 'gWYprQh+NPmmtg2ZrKBrOv9X/F9BYAiK+6rtaHR2xxA=', kind: 'changed', seq: 1, view: 'rPhZ9o1s0Wch9jJpeg+26jdk2qZprdASbtIqmCl+UAs=' },
    { epoch: '00000000000000000000000000000000', keys: 'gWYprQh+NPmmtg2ZrKBrOv9X/F9BYAiK+6rtaHR2xxA=', kind: 'changed', seq: 2, view: 'JXPDNv9w8FmY4sWcMnCsBojYO47GMGxdKyWRcdJ16Ko=' },
  ])
})

test('watch malformed notices reject with a typed error and cancel', async () => {
  const missing = notice() as Record<string, unknown>; delete missing.keys
  for (const value of [null, [], missing, { ...notice(), extra: true }, { ...notice(), kind: 'other' },
    { ...notice(), epoch: '' }, { ...notice(), epoch: 1 }, ...[0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '1'].map((seq) => ({ ...notice(), seq })),
    { ...notice(), view: null }, { ...notice(), keys: 1 }]) {
    const daemon = new WatchDaemon(); daemon.scripts = [{ notices: [encode(value)], hold: true }]
    const watch = (await clientWith(daemon)).watchScoped(() => { throw new Error('must not deliver') })
    expect(await rejectionOf(watch.closed)).toMatchObject({ name: 'ScopedWatchError', code: 'invalid_notice' })
    expect(daemon.cancels).toBe(1)
    expect(daemon.reads).toHaveLength(0)
  }
  expect(() => decodeScopedWatchNotice(new Uint8Array([255]))).toThrow(ScopedWatchError)
  expect(() => decodeScopedWatchNotice(new TextEncoder().encode('{'))).toThrow(ScopedWatchError)
})

test('watch forwards sequence gaps and new epochs without hiding changes and reports ended', async () => {
  const daemon = new WatchDaemon()
  daemon.scripts = [{ notices: [encode(notice()), encode(notice(3)), encode(notice(1, 'epoch-b'))] }]
  const received: ScopedWatchNotice[] = []
  const watch = (await clientWith(daemon)).watchScoped((value) => received.push(value), { enrollmentToken: 'token' })
  expect(await watch.closed).toEqual({ kind: 'ended' })
  expect(received).toEqual([notice(), notice(3), notice(1, 'epoch-b')])
  expect(daemon.requests).toEqual([{ method: 'auth.watch_scoped', params: { enrollment_token: 'token' } }])
  expect(daemon.opens[0]![2]).toEqual({ consumerIdentity: null })
  expect(daemon.reads).toHaveLength(0)
  expect(daemon.opens).toHaveLength(1)
})

test('watch immediate refusal confirms listScoped once and never reopens', async () => {
  const daemon = new WatchDaemon(); daemon.reply = refusal; daemon.scripts = [{ notices: [] }]
  const outcome = await (await clientWith(daemon)).watchScoped(() => {}, { enrollmentToken: 'token' }).closed
  expect(outcome).toMatchObject({ kind: 'refused', error: { code: 'not_found', class: 'permanent' } })
  expect(daemon.reads).toHaveLength(1)
  expect(daemon.reads[0]!.slice(0, 3)).toEqual(['claustrum', 'credential.list_scoped', { enrollment_token: 'token' }])
  expect(daemon.opens).toHaveLength(1)
})

test('watch mid-stream revocation is terminal after the caller reopens once', async () => {
  const daemon = new WatchDaemon(); daemon.reply = refusal
  daemon.scripts = [{ notices: [encode(notice())] }, { notices: [] }]
  const client = await clientWith(daemon)
  const first = await client.watchScoped(() => {}).closed
  expect(first).toEqual({ kind: 'ended' })
  const final = first.kind === 'ended' ? await client.watchScoped(() => {}).closed : first
  expect(final).toMatchObject({ kind: 'refused', error: { code: 'not_found' } })
  expect(daemon.opens).toHaveLength(2)
  expect(daemon.reads).toHaveLength(1)
})

test('watch draining zero-notice close reports not_accepting after one successful list', async () => {
  const daemon = new WatchDaemon(); daemon.scripts = [{ notices: [] }]
  expect(await (await clientWith(daemon)).watchScoped(() => {}).closed).toEqual({ kind: 'not_accepting' })
  expect(daemon.reads).toHaveLength(1)
  expect(daemon.opens).toHaveLength(1)
})

test('watch route_closed reports transport loss without reconnecting', async () => {
  const daemon = new WatchDaemon(); daemon.scripts = [{ notices: [encode(notice())], failure: 'route_closed' }]
  expect(await (await clientWith(daemon)).watchScoped(() => {}).closed).toMatchObject({ kind: 'transport_lost', error: { code: 'route_closed' } })
  expect(daemon.opens).toHaveLength(1)
  expect(daemon.reads).toHaveLength(0)
})

test('watch unknown_method reports unsupported for polling fallback', async () => {
  const daemon = new WatchDaemon(); daemon.scripts = [{ notices: [], failure: 'unknown_method' }]
  expect(await (await clientWith(daemon)).watchScoped(() => {}).closed).toEqual({ kind: 'unsupported' })
  expect(daemon.reads).toHaveLength(0)
})

test('watch stop is idempotent and callback failure is typed', async () => {
  const daemon = new WatchDaemon(); daemon.scripts = [{ notices: [], hold: true }, { notices: [encode(notice())], hold: true }]
  const client = await clientWith(daemon)
  const watch = client.watchScoped(() => {})
  await Promise.resolve(); watch.stop(); watch.stop()
  expect(await watch.closed).toEqual({ kind: 'stopped' })
  const broken = client.watchScoped(() => { throw new Error('callback') })
  expect(await rejectionOf(broken.closed)).toMatchObject({ code: 'callback_failed' })
  expect(daemon.cancels).toBe(2)
})
