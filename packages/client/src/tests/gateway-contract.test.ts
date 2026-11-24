import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { ClaustrumClient, decodeCredential, decodeScopedInventory } from '../wire'

// Producer-generated gateway samples share the vault's checksum-pinned vector directory.
function producerSample(file: string): { result: Record<string, unknown> } {
  return JSON.parse(readFileSync(new URL(
    `../../../../crates/credentials-module/tests/vectors/${file}`,
    import.meta.url,
  ), 'utf8'))
}

test('list_scoped decodes gateway producer samples with bracketed IPv6 hosts', () => {
  const inventory = decodeScopedInventory(producerSample('gateway-list-scoped-v1.json'), () => {})
  expect(inventory.rows.map((row) => row.id)).toEqual([
    'apikey:anthropic-gw-acme', 'apikey:anthropic-gw-acme:empty',
  ])
  for (const row of inventory.rows) {
    expect(row.authMethod).toBe('gateway')
    expect(row.hosts).toEqual(['[::1]'])
    expect(row.categories).toEqual(['llm-gateway'])
    expect(row.providerIds).toEqual(['anthropic-gw-acme'])
    expect(row.serves).toEqual(['anthropic'])
  }
})

test('list_scoped decodes the advertised auth_method and keeps an omitted method absent', () => {
  for (const value of ['apikey', 'chatgpt', 'antigravity', 'oauth', 'gateway'] as const) {
    const sample = producerSample('gateway-list-scoped-v1.json')
    const rows = sample.result.credentials as Record<string, unknown>[]
    rows[0]!.auth_method = value
    expect(decodeScopedInventory(sample, () => {}).rows[0]!.authMethod).toBe(value)
  }
  const sample = producerSample('gateway-list-scoped-v1.json')
  const rows = sample.result.credentials as Record<string, unknown>[]
  delete rows[0]!.auth_method
  const inventory = decodeScopedInventory(sample, () => {})
  expect(inventory.rows).toHaveLength(2)
  expect(inventory.rows[0]!.authMethod).toBeUndefined()
  expect(inventory.undecodableRows).toBeUndefined()
})

for (const [label, value] of [
  ['null', null], ['boolean', false], ['number', 7], ['array', []], ['object', {}],
  ['empty string', ''], ['unknown string', 'unknown'], ['wrong case', 'Gateway'],
  ['trailing space', 'gateway '], ['trailing newline', 'gateway\n'],
] as const) {
  test(`list_scoped drops only the row with ${label} as auth_method`, () => {
    const sample = producerSample('gateway-list-scoped-v1.json')
    const rows = sample.result.credentials as Record<string, unknown>[]
    rows[0]!.auth_method = value
    const inventory = decodeScopedInventory(sample, () => {})
    expect(inventory.undecodableRows).toEqual(['apikey:anthropic-gw-acme: invalid_response'])
    expect(inventory.rows.map(({ id, authMethod }) => ({ id, authMethod }))).toEqual([
      { id: 'apikey:anthropic-gw-acme:empty', authMethod: 'gateway' },
    ])
  })
}

for (const [label, file, headers] of [
  ['populated', 'gateway-get-scoped-v1.json', { 'x-a': 'a"b\\c', 'x-z': 'engineering' }],
  ['empty', 'gateway-get-scoped-empty-headers-v1.json', {}],
] as const) {
  test(`get_scoped decodes ${label} gateway sample through text and byte reads`, async () => {
    const sample = producerSample(file)
    const client = await ClaustrumClient.connect({
      logger: () => {},
      connector: async () => ({
        call: async (_module: string, method: string) => {
          expect(method).toBe('credential.get_scoped')
          return sample
        },
        close: () => {},
      }) as never,
    })
    try {
      const input = { credentialId: sample.result.credential_id as string }
      const text = await client.getScoped(input)
      const bytes = await client.getScopedBytes(input)
      expect(text.material).toBe('vector-test-key')
      expect(bytes.material).toEqual(new TextEncoder().encode('vector-test-key'))
      for (const credential of [text, bytes]) {
        expect(credential.credentialId).toBe(input.credentialId)
        expect(credential.baseUrl).toBe('http://[::1]:4000/v1')
        expect(credential.auth).toEqual({ header: 'authorization', scheme: 'bearer' })
        expect(credential.hosts).toEqual(['[::1]'])
        expect(credential.headers).toEqual(headers)
        expect(credential.invalidKey).toBeUndefined()
      }
    } finally {
      client.close()
    }
  })
}

test('get_scoped accepts the non-gateway baseline without gateway fields', () => {
  const sample = producerSample('get-scoped-non-gateway-baseline-v1.json')
  expect(Object.hasOwn(sample.result, 'base_url')).toBe(false)
  expect(Object.hasOwn(sample.result, 'headers')).toBe(false)
  const credential = decodeCredential(sample, () => {})
  expect(credential.material).toBe('vector-test-key')
  expect(credential.baseUrl).toBeUndefined()
  expect(credential.headers).toBeUndefined()
  expect(credential.hosts).toEqual(['api.openai.com'])
})

test('get_scoped accepts each gateway field independently', () => {
  const withoutUrl = producerSample('gateway-get-scoped-v1.json')
  delete withoutUrl.result.base_url
  const headersOnly = decodeCredential(withoutUrl, () => {})
  expect(headersOnly.baseUrl).toBeUndefined()
  expect(headersOnly.headers).toEqual({ 'x-a': 'a"b\\c', 'x-z': 'engineering' })

  const withoutHeaders = producerSample('gateway-get-scoped-v1.json')
  delete withoutHeaders.result.headers
  const urlOnly = decodeCredential(withoutHeaders, () => {})
  expect(urlOnly.baseUrl).toBe('http://[::1]:4000/v1')
  expect(urlOnly.headers).toBeUndefined()
})

for (const [field, invalidValues] of [
  ['base_url', [null, 7, false, [], {}]],
  ['headers', [
    null, 'x-a=value', 7, false, [], ['value'],
    { 'x-a': 7 }, { 'x-a': null }, { 'x-a': false },
    { 'x-a': [] }, { 'x-a': {} }, { 'x-a': 'valid', 'x-z': 7 },
  ]],
] as const) {
  test(`get_scoped refuses malformed present ${field}`, () => {
    for (const value of invalidValues) {
      const sample = producerSample('gateway-get-scoped-v1.json')
      sample.result[field] = value
      expect(() => decodeCredential(sample, () => {})).toThrow()
    }
  })
}
