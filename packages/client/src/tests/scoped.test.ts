import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

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

  test('the ceremony rows are pinned too, so a consumer can build against them offline', () => {
    expect(Object.keys(fixtureRequest('auth.enroll_propose')).sort()).toEqual([
      'proposed_name',
      'request_secret_hash',
    ])
    expect(Object.keys(fixtureRequest('auth.enroll_poll')).sort()).toEqual(['request_id', 'request_secret'])
  })
})
