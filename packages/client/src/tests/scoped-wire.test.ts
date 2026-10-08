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
  ), 'utf8')) as { operations: { op: string; success?: string[] }[] }
  const successes = fixture.operations.find((row) => row.op === op)?.success
  if (!Array.isArray(successes) || successes.length !== 1) throw new Error(`no golden success for ${op}`)
  return JSON.parse(successes[0]!)
}

async function clientFor(op: string): Promise<ClaustrumClient> {
  return ClaustrumClient.connect({
    logger: () => {},
    connector: async () => ({
      call: async (_module: string, method: string) => {
        expect(method).toBe(op)
        return fixtureReply(op)
      },
      close: () => {},
    }) as never,
  })
}

test('producer get_scoped success decodes through the real client method', async () => {
  const client = await clientFor('credential.get_scoped')
  try {
    expect(await client.getScoped({ credentialId: 'oauth:anthropic', minTtlMs: 300_000 })).toEqual({
      material: 'fixture-not-a-secret',
      credentialId: 'oauth:anthropic',
      expiresAtMs: 4_102_444_800_000,
      recordVersion: 1,
    })
  } finally {
    client.close()
  }
})

test('producer report_auth_failure receipt is accepted by both addressing methods', async () => {
  const client = await clientFor('credential.report_auth_failure')
  try {
    await expect(client.reportAuthFailureScoped({
      credentialId: 'oauth:anthropic',
      providerStatus: 401,
      recordVersion: 1,
      reporterSource: 'direct',
    })).resolves.toBeUndefined()
    await expect(client.reportAuthFailure({
      handle: 'ckh_fixture',
      providerStatus: 401,
      recordVersion: 1,
      reporterSource: 'direct',
    })).resolves.toBeUndefined()
  } finally {
    client.close()
  }
})
