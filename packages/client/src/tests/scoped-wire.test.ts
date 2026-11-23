import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ClaustrumClient } from '../wire.js'
import { rejectionOf } from './settle'

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

async function clientFor(
  op: string,
  capture: (params: unknown) => void = () => {},
  reply: () => unknown = () => fixtureReply(op),
): Promise<ClaustrumClient> {
  return ClaustrumClient.connect({
    logger: () => {},
    connector: async () => ({
      call: async (_module: string, method: string, params: unknown) => {
        expect(method).toBe(op)
        capture(params)
        return reply()
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
      hosts: ['api.anthropic.com'],
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
    expect(inventory.rows.find((row) => row.id === 'github_app:plex-alfonso')?.githubApp)
      .toEqual({ appId: '4617236', slug: 'plex-alfonso' })
  } finally {
    client.close()
  }
})

test('list_scoped preserves the producer App ID string and rejects malformed GitHub App rows', async () => {
  const vector = JSON.parse(readFileSync(join(
    import.meta.dir,
    '../../../../crates/credentials-module/tests/vectors/list-scoped-v2.json',
  ), 'utf8')) as { cases: { case: string; reply: { result: { credentials: Record<string, unknown>[] } } }[] }
  const reply = vector.cases.find((entry) => entry.case === 'github_app_identity')!.reply
  const client = await clientFor('credential.list_scoped', undefined, () => reply)
  try {
    const { rows } = await client.listScoped()
    expect(rows[0]?.githubApp).toEqual({ appId: '9007199254740993', slug: 'listing-vector' })

    const row = reply.result.credentials[0]!
    delete row.github_app
    const legacy = await client.listScoped()
    expect(legacy.rows).toHaveLength(1)
    expect(legacy.rows[0]).not.toHaveProperty('githubApp')

    for (const malformed of [
      { app_id: 4617236, slug: 'listing-vector' },
      { app_id: '9007199254740993' },
      null,
    ]) {
      row.github_app = malformed
      expect(await rejectionOf(client.listScoped())).toMatchObject({ code: 'invalid_response' })
    }
  } finally {
    client.close()
  }
})

test('list_scoped decodes the learned organization sample and refuses malformed ids', async () => {
  const vector = JSON.parse(readFileSync(join(
    import.meta.dir,
    '../../../../crates/credentials-module/tests/vectors/list-scoped-v2.json',
  ), 'utf8')) as { cases: { case: string; reply: { result: { credentials: Record<string, unknown>[] } } }[] }
  let reply = vector.cases.find((entry) => entry.case === 'catalog_and_lifecycle')!.reply
  const client = await clientFor('credential.list_scoped', undefined, () => reply)
  try {
    const legacy = await client.listScoped()
    expect(legacy.rows).toHaveLength(4)
    for (const row of legacy.rows) expect(row).not.toHaveProperty('orgId')

    reply = vector.cases.find((entry) => entry.case === 'learned_org')!.reply
    const learned = await client.listScoped()
    expect(learned.rows).toHaveLength(1)
    expect(learned.rows[0]).toMatchObject({
      id: 'apikey:anthropic:work', orgId: 'c57dea1d-dfac-4ad7-9dee-123456789abc',
    })
    expect(learned.rows[0]?.accountId).toBeUndefined()

    const row = reply.result.credentials[0]!
    for (const valid of ['AZaz09-_.:', 'a'.repeat(128)]) {
      row.org_id = valid
      expect((await client.listScoped()).rows[0]?.orgId).toBe(valid)
    }
    for (const malformed of [null, 7, '', 'a'.repeat(129), 'a/b', 'id\n', 'id\u200b']) {
      row.org_id = malformed
      expect(await rejectionOf(client.listScoped())).toMatchObject({ code: 'invalid_response' })
    }
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

test('reportUsageScoped sends the scoped quota reading and accepts a queued receipt', async () => {
  const requests: unknown[] = []
  const client = await clientFor('usage.report_scoped', (params) => requests.push(params), () => ({
    result: { accepted: true },
  }))
  try {
    expect(await client.reportUsageScoped({
      credentialId: 'oauth:anthropic',
      reading: { observedAtMs: 1_793_600_000_000, provider: 'claude', utilization: 0.41 },
      enrollmentToken: 'fixture-token',
    })).toBeUndefined()
    expect(requests).toEqual([{
      credential_id: 'oauth:anthropic',
      reading: { observedAtMs: 1_793_600_000_000, provider: 'claude', utilization: 0.41 },
      enrollment_token: 'fixture-token',
    }])
  } finally {
    client.close()
  }
})

test('reportUsageScoped preserves a not_found credential error', async () => {
  const client = await clientFor('usage.report_scoped', undefined, () => ({
    result: { error: { code: 'not_found', class: 'permanent' } },
  }))
  try {
    expect(await rejectionOf(client.reportUsageScoped({
      credentialId: 'oauth:anthropic',
      reading: {},
    }))).toMatchObject({ code: 'not_found', class: 'permanent' })
  } finally {
    client.close()
  }
})

for (const [label, reply] of [
  ['missing accepted', { result: {} }],
  ['false accepted', { result: { accepted: false } }],
  ['string accepted', { result: { accepted: 'true' } }],
  ['numeric accepted', { result: { accepted: 1 } }],
  ['missing result', {}],
  ['null reply', null],
] as const) {
  test(`reportUsageScoped refuses ${label} as invalid_response`, async () => {
    const client = await clientFor('usage.report_scoped', undefined, () => reply)
    try {
      expect(await rejectionOf(client.reportUsageScoped({
        credentialId: 'oauth:anthropic',
        reading: {},
      }))).toMatchObject({ code: 'invalid_response' })
    } finally {
      client.close()
    }
  })
}
