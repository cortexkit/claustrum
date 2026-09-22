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
  test('list_scoped sends exactly the keys the vault accepts', () => {
    expect(Object.keys(fixtureRequest('credential.list_scoped')).sort()).toEqual(['enrollment_token'])
  })

  test('get_scoped carries the id, the token and the ttl demand', () => {
    expect(Object.keys(fixtureRequest('credential.get_scoped')).sort()).toEqual([
      'credential_id',
      'enrollment_token',
      'min_ttl_ms',
    ])
  })

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
   * THE REPLY SHAPE, WHICH THE REQUEST PINS CANNOT SEE.
   *
   * My own decoder read `credential_type` where the wire says `type` -- the Rust field is
   * renamed -- and refused EVERY valid row, while every request-shape assertion above
   * stayed green. A request fixture cannot catch a reply-decoding defect, and I wrote the
   * decoder from the Rust struct instead of from a served payload.
   */
  test('the client decodes the row the producer actually emits', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
      operations: (FixtureRow & { row?: string })[]
    }
    const row = fixture.operations.find((entry) => entry.op === 'credential.list_scoped')?.row
    if (row === undefined) throw new Error('no pinned row for credential.list_scoped')
    const decoded = JSON.parse(row) as Record<string, unknown>

    // Exactly the keys the client reads, named as the WIRE names them.
    expect(Object.hasOwn(decoded, 'type')).toBe(true)
    expect(Object.hasOwn(decoded, 'credential_type')).toBe(false)
    expect(Object.hasOwn(decoded, 'id')).toBe(true)
    expect(Object.hasOwn(decoded, 'credential_id')).toBe(false)
    expect(decoded.refresh_adapter).toBe('anthropic')
  })

  /**
   * THE WHOLE REPLY, DECODED BY THE REAL DECODER.
   *
   * The key checks above pass on a decoder that reads the wrong key -- they assert what the
   * fixture holds, not what this client does with it. A downstream consumer lost an
   * evening to exactly that: its decoder, its stub and its fixture all spelled `kind` and
   * agreed with each other while the vault had always sent `type`.
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
    // One row carries every optional field and one carries none, so the decoder is
    // exercised on each optional key both present and absent.
    expect(inventory.rows.map((row) => row.id)).toEqual(['apikey:openrouter', 'oauth:anthropic'])
    const full = inventory.rows.find((row) => row.id === 'oauth:anthropic')
    const bare = inventory.rows.find((row) => row.id === 'apikey:openrouter')
    expect(full?.credentialType).toBe('oauth')
    expect(full?.refreshAdapter).toBe('anthropic')
    expect(bare?.credentialType).toBe('apikey')
    expect(bare?.refreshAdapter).toBeUndefined()
    expect(full?.orgName).toBe('Example Org')
    expect(full?.email).toBe('consumer@example.invalid')
    expect(bare?.orgName).toBeUndefined()
    expect(bare?.accountId).toBeUndefined()
    expect(inventory.view.length).toBeGreaterThan(0)
  })

  test('the ceremony rows are pinned too, so a consumer can build against them offline', () => {
    expect(Object.keys(fixtureRequest('auth.enroll_propose')).sort()).toEqual([
      'proposed_name',
      'request_secret_hash',
    ])
    expect(Object.keys(fixtureRequest('auth.enroll_poll')).sort()).toEqual(['request_id', 'request_secret'])
  })
})
