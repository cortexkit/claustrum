import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ClaustrumClient } from '../wire.js'

// These successes are produced by key_and_scoped_wire_fixture_pins_real_success_replies
// through the vault's real dispatcher over synthetic records, not client-written replies.
function fixtureReply(op: string): unknown {
  const fixture = JSON.parse(readFileSync(join(
    import.meta.dir,
    '../../../../crates/credentials-module/tests/fixtures/enrollment_wire_contract.json',
  ), 'utf8')) as { operations: { op: string; success?: string[] | string; reply?: string }[] }
  const row = fixture.operations.find((row) => row.op === op)
  if (row?.reply !== undefined) return JSON.parse(row.reply)
  const successes = row?.success
  if (!Array.isArray(successes) || successes.length !== 1) throw new Error(`no golden success for ${op}`)
  return JSON.parse(successes[0]!)
}

async function clientFor(op: string, capture: (params: unknown) => void = () => {}): Promise<ClaustrumClient> {
  return ClaustrumClient.connect({
    logger: () => {},
    connector: async () => ({
      call: async (_module: string, method: string, params: unknown) => {
        expect(method).toBe(op)
        capture(params)
        return fixtureReply(op)
      },
      close: () => {},
    }) as never,
  })
}

test('producer get_scoped success decodes through the real client method', async () => {
  const requests: unknown[] = []
  const client = await clientFor('credential.get_scoped', (params) => requests.push(params))
  try {
    expect(await client.getScoped({ credentialId: 'oauth:anthropic', enrollmentToken: 'fixture-token', minTtlMs: 300_000 })).toEqual({
      material: 'fixture-not-a-secret',
      credentialId: 'oauth:anthropic',
      expiresAtMs: 4_102_444_800_000,
      recordVersion: 1,
    })
    expect(requests).toEqual([{ credential_id: 'oauth:anthropic', enrollment_token: 'fixture-token', min_ttl_ms: 300_000 }])
  } finally {
    client.close()
  }
})

test('list_scoped emits only the enrollment token and decodes the producer reply', async () => {
  const requests: unknown[] = []
  const client = await clientFor('credential.list_scoped', (params) => requests.push(params))
  try {
    const inventory = await client.listScoped('fixture-token')
    expect(requests).toEqual([{ enrollment_token: 'fixture-token' }])
    expect(inventory.rows.find((row) => row.id === 'oauth:anthropic')?.refreshAdapter).toBe('anthropic')
  } finally {
    client.close()
  }
})

test('producer report_auth_failure receipt is accepted by both addressing methods', async () => {
  const client = await clientFor('credential.report_auth_failure')
  try {
    expect(await client.reportAuthFailureScoped({
      credentialId: 'oauth:anthropic',
      providerStatus: 401,
      recordVersion: 1,
      reporterSource: 'direct',
    })).toBeUndefined()
    expect(await client.reportAuthFailure({
      handle: 'ckh_fixture',
      providerStatus: 401,
      recordVersion: 1,
      reporterSource: 'direct',
    })).toBeUndefined()
  } finally {
    client.close()
  }
})
