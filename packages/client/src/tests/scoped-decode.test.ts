import { describe, expect, test } from 'bun:test'
import { ClaustrumClient } from '../wire.js'

/**
 * THE DECODERS I RULED WERE MINE, DRIVEN WITH REAL PAYLOADS.
 *
 * I told a consumer seat that Claustrum owns the security-sensitive wire decoders so two
 * independent implementations cannot drift -- then shipped six methods whose decoders had
 * ZERO tests. `scoped.test.ts` pins request SHAPES against the producer fixture and never
 * drives a decoder, so it would pass against a decoder that returned nothing at all.
 *
 * Every negative arm here is the fail-closed property: a decoder that shrugs at a
 * malformed field hands its caller a plausible object built from garbage, and the caller
 * has no way to tell that from a real answer.
 */

interface Call {
  method: string
  params: unknown
}

class FakeDaemon {
  readonly calls: Call[] = []
  closed = false

  constructor(readonly responses: unknown[] = []) {}

  async call(_moduleId: string, method: string, params: unknown): Promise<unknown> {
    this.calls.push({ method, params })
    return this.responses.shift() ?? { result: {} }
  }

  close(): void {
    this.closed = true
  }
}

async function clientWith(responses: unknown[]): Promise<{ client: ClaustrumClient; daemon: FakeDaemon }> {
  const daemon = new FakeDaemon(responses)
  const client = await ClaustrumClient.connect({
    projectRoot: '/project/root',
    storagePath: '/project/root/store.db',
    connector: async () => daemon as never,
  })
  return { client, daemon }
}

const ROW = {
  id: 'oauth:anthropic',
  categories: ['llm-provider'],
  type: 'subscription',
  serves: ['anthropic'],
  refresh_adapter: 'anthropic',
  state: 'active',
  record_version: 232,
  operations: ['read'],
  created_at_ms: 1_750_000_000_000,
}

describe('list_scoped decoding', () => {
  test('a covered row survives the round trip with its adapter intact', async () => {
    const { client, daemon } = await clientWith([{ result: { credentials: [ROW], grants: [], view: 'v1-digest' } }])
    const { rows, view } = await client.listScoped('t'.repeat(64))

    expect(rows).toHaveLength(1)
    expect(rows[0]!.id).toBe('oauth:anthropic')
    // The field the whole adapter change exists for: `serves` says which model vendors
    // are reachable, the adapter says which protocol the credential speaks, and only the
    // second answers "may I send this to Anthropic's own endpoints".
    expect(rows[0]!.refreshAdapter).toBe('anthropic')
    expect(rows[0]!.recordVersion).toBe(232)
    expect(daemon.calls[0]!.method).toBe('credential.list_scoped')
  })

  test('a static credential decodes with no adapter rather than an invented one', async () => {
    const { client } = await clientWith([
      { result: { credentials: [{ ...ROW, id: 'apikey:openrouter', refresh_adapter: undefined }], grants: [], view: 'v1-digest' } },
    ])
    const { rows } = await client.listScoped()

    // apikey:openrouter SERVES Anthropic models and speaks no refresh protocol. Absent is
    // the honest answer, and a consumer selecting on the adapter must not match it.
    expect(rows[0]!.refreshAdapter).toBeUndefined()
  })

  /**
   * THE ARM THAT MATTERS. An empty list is a LEGITIMATE answer for a caller whose grants
   * cover nothing, so it must decode cleanly rather than throw -- but it must also be
   * distinguishable from a shape the decoder failed to understand, which is the next test.
   */
  test('an empty inventory is an answer, not a failure', async () => {
    const { client } = await clientWith([{ result: { credentials: [], grants: [], view: 'v1-empty' } }])
    expect((await client.listScoped('t'.repeat(64))).rows).toEqual([])
  })

  test('a row missing its id is refused rather than decoded into a nameless entry', async () => {
    const { id: _dropped, ...withoutId } = ROW
    const { client } = await clientWith([{ result: { credentials: [withoutId], grants: [], view: 'v1' } }])
    // A nameless row would be routed against by SOMETHING -- whichever field the consumer
    // happened to trust -- so failing closed is the only safe outcome.
    expect(client.listScoped()).rejects.toThrow()
  })

  test('a non-integer record_version is refused, because it is a comparison cursor', async () => {
    const { client } = await clientWith([
      { result: { credentials: [{ ...ROW, record_version: 'twelve' }], grants: [], view: 'v1' } },
    ])
    // A version that decodes to NaN compares false against everything, so a consumer's
    // "has this changed" check would answer no forever.
    expect(client.listScoped()).rejects.toThrow()
  })

  test('a categories array holding a non-string is refused, not silently coerced', async () => {
    const { client } = await clientWith([
      { result: { credentials: [{ ...ROW, categories: ['llm-provider', 7] }], grants: [], view: 'v1' } },
    ])
    expect(client.listScoped()).rejects.toThrow()
  })
})

describe('the cursor and the rotate fence, both missing from 0.2.0', () => {
  /**
   * THE CURSOR MUST SURVIVE THE DECODER. 0.2.0 returned a bare array and dropped `view`,
   * which leaves a consumer unable to tell "nothing changed" from "I never asked" -- so it
   * reconciles on every poll or not at all. Reported by the anthropic-auth seat before
   * they built on it.
   */
  test('listScoped returns the view alongside the rows', async () => {
    const { client } = await clientWith([
      { result: { credentials: [ROW], grants: [], view: 'digest-abc' } },
    ])
    const inventory = await client.listScoped('t'.repeat(64))
    expect(inventory.view).toBe('digest-abc')
    expect(inventory.rows).toHaveLength(1)
  })

  test('a reply with no view is refused rather than decoded into an absent cursor', async () => {
    const { client } = await clientWith([{ result: { credentials: [ROW], grants: [] } }])
    // An undefined cursor compares unequal to everything, so a consumer would reconcile
    // forever and read it as churn in the vault.
    expect(client.listScoped()).rejects.toThrow()
  })

  /**
   * THE ROTATE FENCE IS REQUIRED BY THE PRODUCER. `EnrollRotateParams` takes
   * `expected_token_generation` as a NON-OPTIONAL u64, so 0.2.0's `{ token }` could not
   * decode at all -- every rotation would have failed on a live vault, and nothing in the
   * client suite drove that method.
   */
  test('enrollRotate sends the generation fence the vault requires', async () => {
    const { client, daemon } = await clientWith([
      { result: { token: 'b'.repeat(64), token_generation: 2 } },
    ])
    const rotated = await client.enrollRotate({ token: 'a'.repeat(64), expectedTokenGeneration: 1 })

    expect(rotated.tokenGeneration).toBe(2)
    const sent = daemon.calls[0]!.params as Record<string, unknown>
    expect(sent.expected_token_generation).toBe(1)
    expect(Object.keys(sent).sort()).toEqual(['expected_token_generation', 'token'])
  })
})

describe('enrollment poll decoding', () => {
  test('pending is a normal outcome and carries no token', async () => {
    const { client } = await clientWith([{ result: { status: 'pending' } }])
    expect(await client.enrollPoll({ requestId: 'r', requestSecret: 's' })).toEqual({ status: 'pending' })
  })

  test('approved yields the token exactly once, with its generation', async () => {
    const { client } = await clientWith([
      { result: { status: 'approved', name: 'consumer', token: 'a'.repeat(64), token_generation: 1 } },
    ])
    expect(await client.enrollPoll({ requestId: 'r', requestSecret: 's' })).toEqual({
      status: 'approved',
      name: 'consumer',
      token: 'a'.repeat(64),
      tokenGeneration: 1,
    })
  })

  /**
   * AN APPROVED OUTCOME WITH NO TOKEN MUST THROW, NOT RETURN `undefined`.
   *
   * This is the arm a permissive decoder fails: returning `{status:'approved', token:
   * undefined}` would have the consumer persist an empty token, write it to a 0600 file,
   * and discover the problem on its first spend -- long after the ceremony that could
   * have been retried.
   */
  test('an approved outcome missing its token is refused', async () => {
    const { client } = await clientWith([
      { result: { status: 'approved', name: 'consumer', token_generation: 1 } },
    ])
    expect(client.enrollPoll({ requestId: 'r', requestSecret: 's' })).rejects.toThrow()
  })

  test('an unrecognised status is refused rather than treated as pending', async () => {
    const { client } = await clientWith([{ result: { status: 'thinking-about-it' } }])
    // Treating an unknown status as pending would make a consumer poll forever against a
    // vault that had already answered.
    expect(client.enrollPoll({ requestId: 'r', requestSecret: 's' })).rejects.toThrow()
  })
})
