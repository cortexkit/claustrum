import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ClaustrumCredentialError } from '../errors.js'
import { decodeCredential, decodeStatus } from '../wire.js'

/**
 * Golden `credential.get` and `credential.status` replies, decoded by the real decoders.
 *
 * THE PRODUCER OWNS THESE BYTES. The Rust test
 * `handle_read_wire_fixture_pins_get_and_status_replies` serialises them from the real reply
 * types and the real status surface, so a reply here that disagrees with the daemon fails on
 * the Rust side first. A reply this package wrote itself would only restate its own belief
 * about the wire and would agree with a wrong decoder.
 *
 * Two defects shipped while these replies were unpinned: `decodeCredential` dropped five
 * served fields for weeks, and `decodeStatus` refused the unresolved-handle shape because it
 * demanded a `record_version` the producer deliberately omits there.
 */
const FIXTURE = join(
  import.meta.dir,
  '../../../../crates/credentials-module/tests/fixtures/enrollment_wire_contract.json',
)

type Reply = { result: Record<string, unknown> }

/** The fixture's success replies for `op`, in the order its `success_cases` names them. */
function fixtureReplies(op: string): Reply[] {
  const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
    operations: { op: string; success?: unknown }[]
  }
  const row = fixture.operations.find((entry) => entry.op === op)
  if (row === undefined || !Array.isArray(row.success)) throw new Error(`no golden replies for ${op}`)
  return row.success.map((reply) => JSON.parse(reply as string) as Reply)
}

test('served material refuses invalid UTF-8 as invalid_response', () => {
  for (const payload of [[255], [0xc3], [0xc0, 0xaf], [0xed, 0xa0, 0x80]]) {
    try {
      decodeCredential({ result: { payload, record_version: 1 } }, () => {})
      throw new Error('accepted invalid UTF-8')
    } catch (error) {
      expect(error).toBeInstanceOf(ClaustrumCredentialError)
      expect(error).toMatchObject({ code: 'invalid_response' })
    }
  }
  expect(decodeCredential({ result: { payload: [0xc3, 0xa9], record_version: 1 } }, () => {}).material).toBe('é')
})

const noLog = (): void => {}

/**
 * Where one wire key lands in the decoded object. `expected` turns the wire value into the
 * value the decoder must produce; it defaults to the wire value unchanged.
 */
type KeyMapping = { property: string; expected?: (wire: unknown) => unknown }

const GET_KEYS: Record<string, KeyMapping> = {
  // The payload is surfaced only as decoded text, never as the raw byte array.
  payload: {
    property: 'material',
    expected: (wire) => new TextDecoder().decode(Uint8Array.from(wire as number[])),
  },
  expires_at_ms: { property: 'expiresAtMs' },
  record_version: { property: 'recordVersion' },
  credential_id: { property: 'credentialId' },
  project_id: { property: 'projectId' },
  account_id: { property: 'accountId' },
  email: { property: 'email' },
  org_name: { property: 'orgName' },
}

/**
 * Wire keys `decodeCredential` deliberately does not surface, each with the reason. Empty
 * because every key the producer sends is decoded. A key belongs here only after someone has
 * decided a consumer never needs it; adding one to make the coverage test pass is exactly the
 * silent drop this list exists to prevent.
 */
const GET_IGNORED: ReadonlyMap<string, string> = new Map()

const STATUS_KEYS: Record<string, KeyMapping> = {
  ready: { property: 'ready' },
  last_error_code: { property: 'lastErrorCode' },
  lease_held: { property: 'leaseHeld' },
  credential_id: { property: 'credentialId' },
  record_version: { property: 'recordVersion' },
  stale_pending: { property: 'stalePending' },
}

/** Wire keys `decodeStatus` deliberately does not surface, with reasons. Empty, as above. */
const STATUS_IGNORED: ReadonlyMap<string, string> = new Map()

/**
 * Every key in the reply must be decoded into the returned object with the value the wire
 * carried, or be named in the ignore list. Checking the decoded VALUE rather than only the
 * key set means a decoder that reads the wrong key, or drops the field, still fails here.
 */
function assertEveryKeyAccounted(
  op: string,
  reply: Reply,
  decoded: Record<string, unknown>,
  mapping: Record<string, KeyMapping>,
  ignored: ReadonlyMap<string, string>,
): void {
  for (const [key, wire] of Object.entries(reply.result)) {
    if (ignored.has(key)) continue
    const entry = mapping[key]
    if (entry === undefined) {
      throw new Error(
        `${op} reply key \`${key}\` is neither decoded nor in the ignore list. Decode it into ` +
          'the returned object (and map it in this test), or add it to the ignore list with the ' +
          'reason no consumer needs it.',
      )
    }
    const want = entry.expected === undefined ? wire : entry.expected(wire)
    expect({ key, value: decoded[entry.property] }).toEqual({ key, value: want })
  }
  // The reverse direction: a key the reply omits must not surface as a value.
  for (const [key, entry] of Object.entries(mapping)) {
    if (!Object.hasOwn(reply.result, key)) {
      expect({ key, value: decoded[entry.property] }).toEqual({ key, value: undefined })
    }
  }
}

describe('credential.get golden replies', () => {
  test('every credential.get fixture key is decoded or explicitly ignored', () => {
    const replies = fixtureReplies('credential.get')
    for (const reply of replies) {
      const decoded = decodeCredential(reply, noLog) as unknown as Record<string, unknown>
      assertEveryKeyAccounted('credential.get', reply, decoded, GET_KEYS, GET_IGNORED)
    }
    // A mapping for a key no golden reply carries is not exercised by anything above.
    const served = new Set(replies.flatMap((reply) => Object.keys(reply.result)))
    expect(Object.keys(GET_KEYS).filter((key) => !served.has(key))).toEqual([])
  })

  test('the full reply decodes to every served field', () => {
    const [full] = fixtureReplies('credential.get')
    expect(decodeCredential(full, noLog)).toEqual({
      material: 'fixture-not-a-secret',
      expiresAtMs: 1_900_000_000_000,
      recordVersion: 42,
      credentialId: 'oauth:example',
      projectId: 'example-project-000000',
      accountId: '00000000-0000-4000-8000-000000000000',
      email: 'consumer@example.invalid',
      orgName: 'Example Org',
    })
  })

  test('absent optional fields decode as absent and a null expiry as null', () => {
    const [, bare] = fixtureReplies('credential.get')
    const credential = decodeCredential(bare, noLog)
    expect(credential.material).toBe('fixture-not-a-secret')
    expect(credential.recordVersion).toBe(7)
    expect(credential.expiresAtMs).toBeNull()
    expect(credential.credentialId).toBeUndefined()
    expect(credential.projectId).toBeUndefined()
    expect(credential.accountId).toBeUndefined()
    expect(credential.email).toBeUndefined()
    expect(credential.orgName).toBeUndefined()
  })

  test('the get decoder still refuses malformed values', () => {
    const [full] = fixtureReplies('credential.get')
    const cases: [Record<string, unknown>, string][] = [
      [{ payload: 'not-bytes' }, 'invalid_response'],
      [{ payload: [] }, 'invalid_response'],
      [{ record_version: '42' }, 'invalid_record_version'],
      [{ record_version: -1 }, 'invalid_record_version'],
      [{ expires_at_ms: 'soon' }, 'invalid_expiry'],
      [{ credential_id: 42 }, 'invalid_response'],
      [{ org_name: null }, 'invalid_response'],
    ]
    for (const [override, code] of cases) {
      const malformed = { result: { ...full.result, ...override } }
      let thrown: unknown
      try {
        decodeCredential(malformed, noLog)
      } catch (error) {
        thrown = error
      }
      expect(thrown).toBeInstanceOf(ClaustrumCredentialError)
      expect({ override, code: (thrown as ClaustrumCredentialError).code }).toEqual({ override, code })
    }
  })
})

describe('credential.status golden replies', () => {
  test('every credential.status fixture key is decoded or explicitly ignored', () => {
    const replies = fixtureReplies('credential.status')
    for (const reply of replies) {
      const decoded = decodeStatus(reply, noLog) as unknown as Record<string, unknown>
      assertEveryKeyAccounted('credential.status', reply, decoded, STATUS_KEYS, STATUS_IGNORED)
    }
    const served = new Set(replies.flatMap((reply) => Object.keys(reply.result)))
    expect(Object.keys(STATUS_KEYS).filter((key) => !served.has(key))).toEqual([])
  })

  test('a resolved handle decodes with its credential id and version', () => {
    const [resolved] = fixtureReplies('credential.status')
    expect(decodeStatus(resolved, noLog)).toEqual({
      ready: true,
      lastErrorCode: null,
      leaseHeld: true,
      credentialId: 'apikey:active',
      recordVersion: 1,
      stalePending: false,
    })
  })

  /**
   * A revoked or unknown handle is an ordinary answer, not a protocol error. The vault omits
   * `record_version` there on purpose (a sentinel would read as older than every real
   * version), so a decoder that demands it turns "this handle is gone" into a thrown
   * `invalid_status` the caller cannot act on.
   */
  test('an unresolved handle is not ready, not_found, and carries no record version', () => {
    const [, unresolved] = fixtureReplies('credential.status')
    const status = decodeStatus(unresolved, noLog)
    expect(status).toEqual({ ready: false, lastErrorCode: 'not_found', leaseHeld: true })
    // Omitted rather than set to undefined, so `'recordVersion' in status` is false too.
    expect(Object.hasOwn(status, 'recordVersion')).toBe(false)
    expect(Object.hasOwn(status, 'credentialId')).toBe(false)
    expect(Object.hasOwn(status, 'stalePending')).toBe(false)
  })

  test('the status decoder still refuses malformed values', () => {
    const [resolved] = fixtureReplies('credential.status')
    const overrides: Record<string, unknown>[] = [
      { ready: 'yes' },
      { last_error_code: 5 },
      { lease_held: 1 },
      { credential_id: 42 },
      // The producer omits an unknown version; it never sends one that is not a
      // non-negative integer, so each of these is malformed rather than "absent".
      { record_version: null },
      { record_version: '1' },
      { record_version: -1 },
      { record_version: 1.5 },
      { stale_pending: 'no' },
    ]
    for (const override of overrides) {
      const malformed = { result: { ...resolved.result, ...override } }
      let thrown: unknown
      try {
        decodeStatus(malformed, noLog)
      } catch (error) {
        thrown = error
      }
      expect(thrown).toBeInstanceOf(ClaustrumCredentialError)
      expect({ override, code: (thrown as ClaustrumCredentialError).code }).toEqual({
        override,
        code: 'invalid_status',
      })
    }
  })
})
