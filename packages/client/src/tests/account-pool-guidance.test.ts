import { expect, test } from 'bun:test'
import { readFile } from 'node:fs/promises'

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
