import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { decodeScopedInventory } from '../wire.js'

/**
 * THE PRODUCER OWNS THIS FIXTURE. It is written by Rust tests that serialise the real
 * request types, so a shape here that disagrees with the daemon fails on the OTHER side
 * first. That direction is the whole point: a fixture I hand-wrote would be a second
 * expression of my own belief about the wire, and would agree with a wrong client.
 *
 * Eleven days ago a consumer's `#[serde(untagged)]` decoder silently discarded a field
 * the vault had started sending. No row, no error, no trace -- found only when someone
 * read their decoder against the producer. This file is that reading, made automatic.
 */
const FIXTURE = join(
  import.meta.dir,
  '../../../../crates/credentials-module/tests/fixtures/enrollment_wire_contract.json',
)

interface FixtureRow {
  op: string
  request: string
}

function fixtureRequest(op: string): Record<string, unknown> {
  const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as { operations: FixtureRow[] }
  const row = fixture.operations.find((entry) => entry.op === op)
  if (row === undefined) throw new Error(`no fixture row for ${op}`)
  return JSON.parse(row.request) as Record<string, unknown>
}

describe('the client speaks the producer-pinned wire', () => {
  /**
   * ABSENT MEANS ABSENT, and this is the arm that would have caught my own defect.
   * `ReportAuthFailureParams` serialised `"handle":null` until an emitter printed it --
   * a decoder written against that would treat an explicit null as a meaningful value.
   * The fixture must never carry a null for an unused address.
   */
  test('the report omits the address it is not using rather than nulling it', () => {
    const request = fixtureRequest('credential.report_auth_failure')
    expect(Object.hasOwn(request, 'handle')).toBe(false)
    expect(Object.keys(request).sort()).toEqual([
      'credential_id',
      'enrollment_token',
      'provider_status',
      'record_version',
      'reporter_source',
    ])
  })

  /**
   * THE WHOLE REPLY, DECODED BY THE REAL DECODER.
   *
   * The `reply` row is serialised by the producer's own test from the real
   * `ListScopedResult`, wrapped as it goes on the wire, with a `view` computed by the
   * production digest. So this is the only assertion here whose expected side this package
   * did not write.
   */
  test('the client decodes the golden reply the producer serialises', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
      operations: (FixtureRow & { reply?: string })[]
    }
    const reply = fixture.operations.find((entry) => entry.op === 'credential.list_scoped')?.reply
    if (reply === undefined) throw new Error('no golden reply for credential.list_scoped')

    const inventory = decodeScopedInventory(JSON.parse(reply), () => {})
    // The Rust enrollment wire fixture covers all four methods and a github_app record with no method.
    expect(inventory.rows.map((row) => row.id)).toEqual([
      'antigravity:google',
      'apikey:openrouter',
      'chatgpt:openai',
      'github_app:plex-alfonso',
      'oauth:anthropic',
    ])
    const full = inventory.rows.find((row) => row.id === 'oauth:anthropic')
    const bare = inventory.rows.find((row) => row.id === 'apikey:openrouter')
    expect(full?.credentialType).toBe('oauth')
    expect(full?.refreshAdapter).toBe('anthropic')
    expect(full?.id).toBe('oauth:anthropic')
    expect(bare?.credentialType).toBe('apikey')
    expect(bare?.refreshAdapter).toBeUndefined()
    expect(full?.orgName).toBe('Example Org')
    expect(full?.email).toBe('consumer@example.invalid')
    expect(bare?.orgName).toBeUndefined()
    expect(bare?.accountId).toBeUndefined()
    expect(inventory.view.length).toBeGreaterThan(0)
  })

  test('provider metadata survives every producer fixture projection', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
      operations: (FixtureRow & { row?: string; reply?: string; list_only_reply?: string })[]
    }
    const entry = fixture.operations.find((row) => row.op === 'credential.list_scoped')!
    const responses = [
      { result: { credentials: [JSON.parse(entry.row!)], view: 'fixture-row' } },
      JSON.parse(entry.reply!),
      JSON.parse(entry.list_only_reply!),
    ]
    for (const response of responses) {
      const inventory = decodeScopedInventory(response, () => {})
      for (const [index, row] of inventory.rows.entries()) {
        const emitted = response.result.credentials[index]
        expect(row.providerIds).toEqual(emitted.provider_ids)
        expect(row.authMethod).toBe(emitted.auth_method)
        expect(row.planTier).toBe(emitted.plan_tier)
        expect(row.planTierSource).toBe(emitted.plan_tier_source)
      }
    }
    const rows = decodeScopedInventory(responses[1], () => {}).rows
    expect(rows.map((row) => row.authMethod)).toEqual(['antigravity', 'apikey', 'chatgpt', undefined, 'oauth'])
    expect(rows.some((row) => row.providerIds.length === 0)).toBe(true)
    expect(rows.some((row) => row.providerIds.length > 1)).toBe(true)
    expect(rows.some((row) => row.planTierSource === 'operator')).toBe(true)
    expect(rows.some((row) => row.planTierSource === 'detected')).toBe(true)
    expect(rows.some((row) => row.planTier === undefined && row.planTierSource === undefined)).toBe(true)
    const github = rows.find((row) => row.id === 'github_app:plex-alfonso')!
    expect(github.refreshAdapter).toBe('github_app')
    expect(github.authMethod).toBeUndefined()
  })

  for (const [field, invalidValues] of [
    ['provider_ids', [null, 'aa', ['aa', 7]]],
    ['auth_method', [null, 7, '', 'unknown']],
    ['plan_tier_source', [null, 7, '', 'unknown', 'Detected']],
    ['plan_tier', [null, 7, [], '', 'Pro', '2x', '_max', 'max-5x', 'a b', 'é', 'max_5x\n', 'a'.repeat(33)]],
  ] as const) {
    for (const [index, invalid] of invalidValues.entries()) {
      test(`fixture refuses malformed ${field} case ${index}`, () => {
        const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
          operations: (FixtureRow & { reply?: string })[]
        }
        const reply = fixture.operations.find((entry) => entry.op === 'credential.list_scoped')!.reply!
        const response = JSON.parse(reply)
        if (invalid === undefined) delete response.result.credentials[1][field]
        else response.result.credentials[1][field] = invalid
        expect(() => decodeScopedInventory(response, () => {})).toThrow()
      })
    }
  }

  // A daemon from before provider ids omits the key on every row. The listing must still
  // decode, with each row reporting no ids, or a newer client cannot talk to an older
  // daemon at all.
  test('a reply without provider_ids, as an older daemon sends it, decodes as no ids', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
      operations: (FixtureRow & { reply?: string })[]
    }
    const response = JSON.parse(fixture.operations.find((entry) => entry.op === 'credential.list_scoped')!.reply!)
    for (const row of response.result.credentials) {
      delete row.provider_ids
      delete row.auth_method
    }
    const decoded = decodeScopedInventory(response, () => {})
    expect(decoded.rows.length).toBe(response.result.credentials.length)
    expect(decoded.rows.every((row) => row.providerIds.length === 0)).toBe(true)
  })

  test('a reply without plan_tier decodes as an unknown tier against older vaults', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as { operations: (FixtureRow & { reply?: string })[] }
    const response = JSON.parse(fixture.operations.find((entry) => entry.op === 'credential.list_scoped')!.reply!)
    for (const row of response.result.credentials) {
      delete row.plan_tier
      delete row.plan_tier_source
    }
    const decoded = decodeScopedInventory(response, () => {})
    expect(decoded.rows.length).toBe(response.result.credentials.length)
    expect(decoded.rows.every((row) => row.planTier === undefined)).toBe(true)
    expect(decoded.rows.every((row) => row.planTierSource === undefined)).toBe(true)
  })

  test('plan tiers accept bounded syntax including digits after underscores, not a vocabulary', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as { operations: (FixtureRow & { reply?: string })[] }
    const response = JSON.parse(fixture.operations.find((entry) => entry.op === 'credential.list_scoped')!.reply!)
    for (const tier of ['a', 'pro_200', 'unrecognised_tier', 'a'.repeat(32)]) {
      response.result.credentials[0].plan_tier = tier
      expect(decodeScopedInventory(response, () => {}).rows[0]!.planTier).toBe(tier)
    }
  })

  test('provider ids are decoded as open strings, not client-validated catalog ids', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
      operations: (FixtureRow & { reply?: string })[]
    }
    const response = JSON.parse(fixture.operations.find((entry) => entry.op === 'credential.list_scoped')!.reply!)
    response.result.credentials[0].provider_ids = ['', 'Unknown.Provider']
    expect(decodeScopedInventory(response, () => {}).rows[0]!.providerIds).toEqual(['', 'Unknown.Provider'])
  })

  /**
   * A caller holding only the metadata-only `list` grant gets the roster with identity and
   * the refresh adapter, and its row's `operations` says `list`. The decoder reads
   * operations as open strings, so an operation it has never seen must pass through
   * rather than refuse the whole reply.
   */
  test('the client decodes the golden reply to a list-only caller', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
      operations: (FixtureRow & { list_only_reply?: string })[]
    }
    const reply = fixture.operations.find((entry) => entry.op === 'credential.list_scoped')?.list_only_reply
    if (reply === undefined) throw new Error('no golden list-only reply for credential.list_scoped')

    const inventory = decodeScopedInventory(JSON.parse(reply), () => {})
    expect(inventory.rows).toHaveLength(1)
    const row = inventory.rows[0]
    expect(row?.operations).toEqual(['list'])
    expect(row?.accountId).toBe('00000000-0000-4000-8000-000000000000')
    expect(row?.refreshAdapter).toBe('anthropic')
    expect(row?.email).toBe('consumer@example.invalid')
  })

  test('the ceremony rows are pinned too, so a consumer can build against them offline', () => {
    expect(Object.keys(fixtureRequest('auth.enroll_propose')).sort()).toEqual([
      'proposed_name',
      'request_secret_hash',
    ])
    expect(Object.keys(fixtureRequest('auth.enroll_poll')).sort()).toEqual(['request_id', 'request_secret'])
  })
})

/**
 * THE GRANT COUNT IS WHAT TELLS "NO GRANT" FROM "A GRANT THAT REACHES NOTHING".
 *
 * A consumer granted a category no credential carries gets `rows: []`, exactly what a
 * caller with no grant gets, so without the count it can only report an empty vault.
 * Every case below starts from the `credential.list_scoped` reply in the vault-generated
 * fixture (`enrollment_wire_contract.json`), so `grants` and `grant_tuples` keep the exact
 * field names the vault sends.
 */
describe('list_scoped grant count and tuples', () => {
  const goldenReply = (key: 'reply' | 'list_only_reply' = 'reply') => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
      operations: (FixtureRow & { reply?: string; list_only_reply?: string })[]
    }
    const entry = fixture.operations.find((row) => row.op === 'credential.list_scoped')!
    return JSON.parse(entry[key]!) as { result: Record<string, unknown> }
  }

  test('present grants and grant_tuples decode from the producer reply', () => {
    const inventory = decodeScopedInventory(goldenReply(), () => {})
    expect(inventory.grants).toBe(2)
    expect(inventory.grantTuples).toEqual([
      { selectorKind: 'category', selector: 'llm-provider', operation: 'read' },
      { selectorKind: 'category', selector: 'github-app-native', operation: 'read' },
    ])
    const listOnly = decodeScopedInventory(goldenReply('list_only_reply'), () => {})
    expect(listOnly.grants).toBe(1)
    expect(listOnly.grantTuples).toEqual([{ selectorKind: 'category', selector: 'llm-provider', operation: 'list' }])
  })

  test('a grant that reaches nothing is distinguishable from no grant', () => {
    const reaching = goldenReply()
    reaching.result.credentials = []
    const noGrant = goldenReply()
    noGrant.result.credentials = []
    noGrant.result.grants = 0
    noGrant.result.grant_tuples = []
    const a = decodeScopedInventory(reaching, () => {})
    const b = decodeScopedInventory(noGrant, () => {})
    expect(a.rows).toEqual([])
    expect(b.rows).toEqual([])
    expect(a.grants).toBe(2)
    expect(b.grants).toBe(0)
  })

  test('an older vault without grants or grant_tuples decodes them as undefined', () => {
    const response = goldenReply()
    delete response.result.grants
    delete response.result.grant_tuples
    const inventory = decodeScopedInventory(response, () => {})
    expect(inventory.rows.length).toBe(5)
    expect(inventory.grants).toBeUndefined()
    expect(inventory.grantTuples).toBeUndefined()
  })

  for (const [index, invalid] of [-1, '3', 1.5, null, []].entries()) {
    test(`a malformed grants count is refused, case ${index}`, () => {
      const response = goldenReply()
      response.result.grants = invalid
      expect(() => decodeScopedInventory(response, () => {})).toThrow()
    })
  }

  const validTuple = { operation: 'read', selector: 'llm-provider', selector_kind: 'category' }
  for (const [index, invalid] of [
    { ...validTuple, selector: 7 },
    { operation: 'read', selector: 'llm-provider' },
    { ...validTuple, extra: 'x' },
    'category:llm-provider',
    null,
  ].entries()) {
    test(`a malformed grant tuple is refused, case ${index}`, () => {
      const response = goldenReply()
      response.result.grant_tuples = [validTuple, invalid]
      expect(() => decodeScopedInventory(response, () => {})).toThrow()
    })
  }

  test('a grant_tuples value that is not an array is refused', () => {
    const response = goldenReply()
    response.result.grant_tuples = { 0: validTuple }
    expect(() => decodeScopedInventory(response, () => {})).toThrow()
  })
})
