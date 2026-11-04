import { expect, test } from 'bun:test'
import { asCredentialError, credentialErrorAction, ERROR_CLASS_WIRE_SET } from '../errors.js'
import { readFile } from 'node:fs/promises'

test('unknown credential classes retain their raw class without prescribing a retry', () => {
  for (const rawClass of ['future_class', '', 'unknown', undefined, null, 7]) {
    const logs: string[] = []
    const error = asCredentialError(
      { result: { error: { class: rawClass, code: 'future_code', message: 'private material' } } },
      'invalid_response',
      (value) => logs.push(value),
    )
    expect(error).toMatchObject({ class: 'unknown', action: 'degraded', code: 'future_code' })
    expect(Reflect.get(error, 'rawClass')).toBe(typeof rawClass === 'string' ? rawClass : undefined)
    expect(logs).toEqual([typeof rawClass === 'string' ? rawClass : 'unknown'])
    expect(error.message).not.toContain('private material')
    expect(credentialErrorAction(error.class)).toBe('degraded')
  }
  expect(ERROR_CLASS_WIRE_SET).not.toContain('unknown')
})

test('account pool guidance uses stable identity instead of the material cursor', async () => {
  const wire = await readFile(new URL('../wire.ts', import.meta.url), 'utf8')
  const served = wire.slice(wire.indexOf('export type ServedCredential = {'), wire.indexOf('  accountId?: string'))
  expect(served).toContain('`accountId` with `refreshAdapter`')
  expect(served).toContain('never `recordVersion`')
  expect(served).not.toContain('joins `accountId` with `recordVersion`')

  const contract = await readFile(new URL('../../../../docs/wire-contract-v1.md', import.meta.url), 'utf8')
  const status = contract.slice(contract.indexOf('`credential_id` is absent for overall readiness'), contract.indexOf('**An unresolved handle'))
  expect(status).toContain('the refresh adapter, never `record_version`')
  expect(status).toContain('cached material, not to identify an account pool')
})
