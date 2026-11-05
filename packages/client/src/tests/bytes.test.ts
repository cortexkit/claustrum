import { expect, test } from 'bun:test'
import { ClaustrumClient, type ServedCredentialBytes } from '../index.js'
import { rejectionOf } from './settle.js'

const reply = {
  result: {
    payload: [0, 255, 195, 40, 128],
    record_version: 7,
    expires_at_ms: 4102444800000,
    credential_id: 'cookie:binary',
    account_id: 'account',
    project_id: 'project',
    email: 'operator',
    org_name: 'workspace',
  },
}

test('byte get methods preserve non-UTF-8 payloads and metadata', async () => {
  const calls: { method: string; params: unknown }[] = []
  const client = await ClaustrumClient.connect({
    logger: () => {},
    connector: async () => ({
      call: async (_module: string, method: string, params: unknown) => {
        calls.push({ method, params })
        return reply
      },
      close: () => {},
    }) as never,
  })
  try {
    const byHandle: ServedCredentialBytes = await client.getCredentialBytes('handle', 1000)
    const byId: ServedCredentialBytes = await client.getScopedBytes({
      credentialId: 'cookie:binary', enrollmentToken: 'enrollment', minTtlMs: 2000,
    })
    for (const credential of [byHandle, byId]) {
      expect(credential).toEqual({
        material: new Uint8Array([0, 255, 195, 40, 128]),
        recordVersion: 7,
        expiresAtMs: 4102444800000,
        credentialId: 'cookie:binary',
        accountId: 'account',
        projectId: 'project',
        email: 'operator',
        orgName: 'workspace',
      })
    }
    expect(calls).toEqual([
      { method: 'credential.get', params: { handle: 'handle', min_ttl_ms: 1000, force_refresh: false } },
      { method: 'credential.get_scoped', params: { credential_id: 'cookie:binary', enrollment_token: 'enrollment', min_ttl_ms: 2000 } },
    ])
  } finally {
    client.close()
  }
})

test('text get methods still refuse non-UTF-8 payloads', async () => {
  const client = await ClaustrumClient.connect({
    logger: () => {},
    connector: async () => ({ call: async () => reply, close: () => {} }) as never,
  })
  try {
    expect(await rejectionOf(client.getCredential('handle'))).toMatchObject({ code: 'invalid_response' })
    expect(await rejectionOf(client.getScoped({ credentialId: 'cookie:binary' }))).toMatchObject({ code: 'invalid_response' })
  } finally {
    client.close()
  }
})

test('byte get methods still refuse malformed payload arrays', async () => {
  for (const payload of [[], [256], [-1], [1.5], ['1']]) {
    const client = await ClaustrumClient.connect({
      logger: () => {},
      connector: async () => ({
        call: async () => ({ result: { payload, record_version: 1 } }),
        close: () => {},
      }) as never,
    })
    try {
      expect(await rejectionOf(client.getCredentialBytes('handle'))).toMatchObject({ code: 'invalid_response' })
      expect(await rejectionOf(client.getScopedBytes({ credentialId: 'cookie:binary' }))).toMatchObject({ code: 'invalid_response' })
    } finally {
      client.close()
    }
  }
})
