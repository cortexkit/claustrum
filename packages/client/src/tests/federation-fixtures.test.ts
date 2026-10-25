import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ClaustrumCredentialError } from '../errors.js'
import { decodeCredential, decodeScopedInventory, decodeStatus } from '../wire.js'

// The vault's producer tests pin these shapes with its real serializers; clients
// consume the same fixture so a producer-only wire rename cannot pass unnoticed.
const fixture = JSON.parse(readFileSync(join(
  import.meta.dir,
  '../../../../crates/credentials-module/tests/fixtures/federation_wire_contract.json',
), 'utf8')) as {
  clients: {
    cases: { adapter: string; get: unknown; status: unknown }[]
    inventory: unknown
    refusal: unknown
  }
}

test('remote Anthropic and Antigravity producer get replies decode', () => {
  expect(fixture.clients.cases.map((row) => row.adapter)).toEqual(['anthropic', 'antigravity'])
  for (const row of fixture.clients.cases) {
    const got = decodeCredential(row.get, () => {})
    expect(got).toEqual({
      material: `fixture-${row.adapter}-access-not-a-secret`,
      credentialId: `oauth:${row.adapter}:fixture`,
      expiresAtMs: null,
      recordVersion: 1,
      accountId: `fixture-${row.adapter}-account`,
      email: 'fixture@example.invalid',
      orgName: 'Fixture Team',
      ...(row.adapter === 'antigravity' ? { projectId: 'fixture-managed-project' } : {}),
    })
  }
})

test('remote inventory producer rows decode through decodeScopedInventory', () => {
  const inventory = decodeScopedInventory(fixture.clients.inventory, () => {})
  expect(inventory.rows).toHaveLength(2)
  for (const [adapter, method] of [['anthropic', 'oauth'], ['antigravity', 'antigravity']] as const) {
    const row = inventory.rows.find((entry) => entry.id === `oauth:${adapter}:fixture`)
    expect(row).toMatchObject({
      credentialType: 'oauth', refreshAdapter: adapter, authMethod: method,
      categories: ['llm-provider'], accountId: `fixture-${adapter}-account`,
      email: 'fixture@example.invalid', orgName: 'Fixture Team', state: 'active', recordVersion: 1,
    })
  }
})

test('optional remote status additions do not break the current status decoder', () => {
  // This is decoder compatibility, not a TS remote-status API: statusCredential
  // sends only a handle, and a remote record cannot have one.
  for (const row of fixture.clients.cases) {
    const status = decodeStatus(row.status, () => {})
    expect(status.ready).toBe(true)
    expect(status.recordVersion).toBe(1)
    expect(status.stalePending).toBe(false)
  }
})

test('a remote refusal with remedy_member decodes as a structured credential error', () => {
  try {
    decodeCredential(fixture.clients.refusal, () => {})
    throw new Error('expected a classified remote refusal')
  } catch (error) {
    expect(error).toBeInstanceOf(ClaustrumCredentialError)
    expect(error).toMatchObject({ code: 'remote_setup_incomplete', class: 'permanent' })
  }
})
