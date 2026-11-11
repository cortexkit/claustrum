import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { decodeCredential, decodeScopedInventory } from '../wire.js'

function producerReply(caseName = 'catalog_and_lifecycle'): any {
  const vector = JSON.parse(readFileSync(new URL('../../../../crates/credentials-module/tests/vectors/list-scoped-v2.json', import.meta.url), 'utf8'))
  const entry = vector.cases.find((row: { case: string }) => row.case === caseName)
  if (!entry) throw new Error(`producer list vector has no ${caseName}`)
  return entry.reply
}

test('provider catalog decodes real vault rows with service, incarnation and tier time', () => {
  const decoded = decodeScopedInventory(producerReply(), () => {})
  const kimi = decoded.rows.find((row) => row.id === 'apikey:kimi-for-coding')!
  expect(kimi.provider).toBe('kimi-for-coding')
  expect(kimi.incarnation).toBe('00000000000000000000000000000002')
  expect(kimi.planTierObservedAtMs).toBe(1_700_000_000_000)
  expect(decoded.rows.find((row) => row.id === 'apikey:exa')!.planTierObservedAtMs).toBeUndefined()
})

test('provider catalog tolerates older vault omissions and explicit nulls', () => {
  for (const nulls of [false, true]) {
    const reply = producerReply()
    for (const row of reply.result.credentials) {
      for (const field of ['provider', 'incarnation', 'plan_tier_observed_at_ms']) {
        if (nulls) row[field] = null
        else delete row[field]
      }
    }
    const decoded = decodeScopedInventory(reply, () => {})
    expect(decoded.rows).toHaveLength(4)
    for (const row of decoded.rows) {
      expect(row.provider).toBeUndefined()
      expect(row.incarnation).toBeUndefined()
      expect(row.planTierObservedAtMs).toBeUndefined()
    }
  }
})

test('provider catalog rejects malformed additive metadata', () => {
  for (const [field, value] of [['provider', 1], ['incarnation', []], ['plan_tier_observed_at_ms', 'yesterday'], ['plan_tier_observed_at_ms', 1.5]] as const) {
    const reply = producerReply()
    reply.result.credentials[0][field] = value
    expect(() => decodeScopedInventory(reply, () => {})).toThrow()
  }
})

function producerGetScopedReply(caseName = 'catalog_with_evidence'): any {
  const vector = JSON.parse(readFileSync(new URL('../../../../crates/credentials-module/tests/vectors/get-scoped-v1.json', import.meta.url), 'utf8'))
  const entry = vector.cases.find((row: { case: string }) => row.case === caseName)
  if (!entry) throw new Error(`producer get_scoped vector has no ${caseName}`)
  return entry.reply
}

test('provider catalog decodes producer Fusiform ids, hosts and absence', () => {
  const reply = producerReply('descriptor_presence')
  const decoded = decodeScopedInventory(reply, () => {})
  expect(decoded.rows).toHaveLength(3)
  for (const [index, row] of decoded.rows.entries()) {
    const wire = reply.result.credentials[index]
    expect(row.id).toBe(wire.id)
    expect(row.hosts).toEqual(wire.hosts)
    expect(row.fusiformProviderId).toBe(wire.fusiform_provider_id)
  }
  const openai = decoded.rows.find((row) => row.id === 'apikey:openai')!
  expect(openai.hosts).toEqual(['api.openai.com'])
  expect(openai.fusiformProviderId).toBe('openai')
  const oauth = decoded.rows.find((row) => row.id === 'oauth:anthropic')!
  expect(oauth.hosts).toBeUndefined()
  expect(oauth.fusiformProviderId).toBeUndefined()
})

test('provider catalog decodes empty hosts missing from vectors', () => {
  const reply = producerReply('descriptor_presence')
  // The vectors omit explicitly empty host lists; exercise that presence separately.
  expect(reply.result.credentials[2].hosts).toBeUndefined()
  reply.result.credentials[2].hosts = []
  const decoded = decodeScopedInventory(reply, () => {})
  expect(decoded.rows[1]!.fusiformProviderId).toBe('openai')
  expect(decoded.rows[2]!.hosts).toEqual([])
})

test('provider catalog treats omitted and null Fusiform ids and hosts as absent', () => {
  for (const nulls of [false, true]) {
    const reply = producerReply('descriptor_presence')
    for (const row of reply.result.credentials) {
      for (const field of ['fusiform_provider_id', 'hosts']) {
        if (nulls) row[field] = null
        else delete row[field]
      }
    }
    const decoded = decodeScopedInventory(reply, () => {})
    expect(decoded.rows).toHaveLength(3)
    for (const row of decoded.rows) {
      expect(row.fusiformProviderId).toBeUndefined()
      expect(row.hosts).toBeUndefined()
    }
  }
})

test('provider catalog rejects malformed Fusiform ids and hosts', () => {
  for (const [field, value] of [
    ['fusiform_provider_id', 1], ['fusiform_provider_id', []],
    ['hosts', 'api.openai.com'], ['hosts', [1]], ['hosts', [null]],
  ] as const) {
    const reply = producerReply('descriptor_presence')
    reply.result.credentials[0][field] = value
    expect(() => decodeScopedInventory(reply, () => {})).toThrow()
  }
})

test('get_scoped decodes real auth, hosts and invalid-key evidence', () => {
  for (const caseName of ['catalog_with_evidence', 'catalog_without_evidence']) {
    const reply = producerGetScopedReply(caseName)
    const decoded = decodeCredential(reply, () => {})
    expect(decoded.material).toBe('vector-test-key')
    expect(decoded.auth).toEqual({ header: 'authorization', scheme: 'bearer' })
    expect(decoded.hosts).toEqual(reply.result.hosts)
    if (caseName === 'catalog_with_evidence') {
      expect(decoded.hosts).toEqual(['api.openai.com'])
      expect(decoded.invalidKey).toEqual({ status: 401, errorCode: 'invalid_api_key', errorCodeField: '/error/code' })
    } else {
      expect(reply.result.invalid_key).toBeNull()
      expect(decoded.invalidKey).toBeUndefined()
    }
  }
  const reply = producerGetScopedReply('oauth_without_descriptor')
  for (const field of ['auth', 'hosts', 'invalid_key']) expect(Object.hasOwn(reply.result, field)).toBe(false)
  const decoded = decodeCredential(reply, () => {})
  expect(decoded.material).toBe('vector-test-key')
  expect(decoded.auth).toBeUndefined()
  expect(decoded.hosts).toBeUndefined()
  expect(decoded.invalidKey).toBeUndefined()
})

test('get_scoped decodes descriptor values missing from vectors', () => {
  // Preserve the catalog descriptors and inject only wire values absent from the vectors.
  const reply = producerGetScopedReply('oauth_without_descriptor')
  reply.result.auth = { header: 'authorization', scheme: 'raw' }
  expect(decodeCredential(reply, () => {}).auth).toEqual({ header: 'authorization', scheme: 'raw' })
  for (const status of [0, 65535]) {
    const reply = producerGetScopedReply('oauth_without_descriptor')
    reply.result.hosts = []
    reply.result.invalid_key = { status, error_code: null, error_code_field: null }
    const decoded = decodeCredential(reply, () => {})
    expect(decoded.hosts).toEqual([])
    expect(decoded.invalidKey).toEqual({ status, errorCode: undefined, errorCodeField: undefined })
  }
})

test('get_scoped treats omitted and null descriptors as absent', () => {
  for (const nulls of [false, true]) {
    const reply = producerGetScopedReply()
    for (const field of ['auth', 'hosts', 'invalid_key']) {
      if (nulls) reply.result[field] = null
      else delete reply.result[field]
    }
    const decoded = decodeCredential(reply, () => {})
    expect(decoded.auth).toBeUndefined()
    expect(decoded.hosts).toBeUndefined()
    expect(decoded.invalidKey).toBeUndefined()
  }
})

test('get_scoped rejects malformed auth, hosts and invalid-key evidence', () => {
  for (const [field, value] of [
    ['auth', []], ['auth', 'bearer'], ['auth', {}],
    ['auth', { header: 1, scheme: 'raw' }], ['auth', { header: 'authorization' }],
    ['auth', { header: 'authorization', scheme: 'basic' }],
    ['auth', { header: 'authorization', scheme: null }],
    ['hosts', 'api.openai.com'], ['hosts', [1]], ['hosts', [null]],
    ['invalid_key', []], ['invalid_key', 'unauthorized'], ['invalid_key', {}],
    ['invalid_key', { status: '401' }], ['invalid_key', { status: 1.5 }],
    ['invalid_key', { status: -1 }], ['invalid_key', { status: 65536 }],
    ['invalid_key', { status: 401, error_code: 1, error_code_field: null }],
    ['invalid_key', { status: 401, error_code: null, error_code_field: [] }],
    ['invalid_key', { status: 401, error_code: 'invalid_api_key', error_code_field: null }],
    ['invalid_key', { status: 401, error_code: null, error_code_field: '/error/code' }],
  ] as const) {
    const reply = producerGetScopedReply()
    reply.result[field] = value
    expect(() => decodeCredential(reply, () => {})).toThrow()
  }
})
