import { expect, test } from 'bun:test'
import { createPrivateDirectory, createPrivateFile } from '@cortexkit/store'
import { readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { privateCreationCode } from '../private-path.js'
import { privateFixtureDirectory } from './ancestor-fixture.js'

test('normalizes native create collisions and absence without weakening security refusals', () => {
  for (const win32Code of [80, 183]) {
    expect(privateCreationCode({ code: 'ERR_PRIVATE_FILES_SECURITY', reason: 'io-error', win32Code })).toBe('EEXIST')
  }
  for (const win32Code of [2, 3]) {
    expect(privateCreationCode({ code: 'ERR_PRIVATE_FILES_SECURITY', reason: 'io-error', win32Code })).toBe('ENOENT')
  }
  expect(privateCreationCode({ code: 'EEXIST' })).toBe('EEXIST')
  expect(privateCreationCode({ code: 'ERR_PRIVATE_FILES_SECURITY', reason: 'extra-ace', win32Code: 183 })).toBe('ERR_PRIVATE_FILES_SECURITY')
  expect(privateCreationCode({ code: 'ERR_PRIVATE_FILES_SECURITY', reason: 'io-error', win32Code: 5 })).toBe('ERR_PRIVATE_FILES_SECURITY')
  expect(privateCreationCode(undefined)).toBeUndefined()
})

test('private creation is exclusive for both files and directories on every platform', async () => {
  const root = await privateFixtureDirectory('claustrum-exclusive-')
  try {
    const path = join(root, 'file')
    await createPrivateFile(path, 'original')
    const fileError = await createPrivateFile(path, 'replacement').catch((error: unknown) => error)
    expect(privateCreationCode(fileError)).toBe('EEXIST')
    expect(await readFile(path, 'utf8')).toBe('original')
    const directory = join(root, 'directory')
    await createPrivateDirectory(directory)
    const directoryError = await createPrivateDirectory(directory).catch((error: unknown) => error)
    expect(privateCreationCode(directoryError)).toBe('EEXIST')
  } finally { await rm(root, { recursive: true, force: true }) }
})
