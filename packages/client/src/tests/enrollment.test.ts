import { privateFixtureDirectory, withSharedAncestorGroup } from './ancestor-fixture.js'
import { checkOwnerOnlyPathAsync } from '@cortexkit/store'
import { afterEach, describe, expect, test } from 'bun:test'
import { chmod, mkdtemp, mkdir, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { writeEnrollmentTokenFile } from '../enrollment.js'
import { writeEnrollmentTokenFile as writeFixtureToken } from './injected-files.js'
import { rejectionOf, throwerOf } from './settle'

const roots: string[] = []
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

const onPosix = process.platform !== 'win32'

describe('enrollment token file', () => {
  test('writes the token and generation atomically with owner-only protection', async () => {
    const root = await privateFixtureDirectory('claustrum-enrollment-')
    roots.push(root)
    await chmod(root, 0o700)
    const path = join(root, 'consumer.json')
    const value = { token: 'ab'.repeat(32), token_generation: 2 }

    await writeEnrollmentTokenFile(path, value)

    if (onPosix) expect((await stat(path)).mode & 0o777).toBe(0o600)
    expect(await checkOwnerOnlyPathAsync(path)).toEqual({ ok: true })
    expect(JSON.parse(await readFile(path, 'utf8'))).toEqual(value)
    const replacement = { ...value, token_generation: 3 }
    await writeEnrollmentTokenFile(path, replacement)
    expect(JSON.parse(await readFile(path, 'utf8'))).toEqual(replacement)
    expect(await checkOwnerOnlyPathAsync(path)).toEqual({ ok: true })
  })

  for (const [mode, name] of [
    [0o777, 'refuses a 0777 non-sticky ancestor before creating the token file'],
    [0o775, 'refuses a 0775 shared-group ancestor before creating the token file'],
  ] as const) {
    test.skipIf(!onPosix)(name, async () => {
      const root = await mkdtemp(join(tmpdir(), 'claustrum-enrollment-'))
      roots.push(root)
      await chmod(root, 0o700)
      const unsafe = join(root, 'unsafe')
      const child = join(unsafe, 'private')
      await mkdir(child, { recursive: true, mode: 0o700 })
      await chmod(unsafe, mode)

      const path = join(child, 'consumer.json')
      await withSharedAncestorGroup(unsafe, async () => {
        expect(await throwerOf(
          writeFixtureToken(path, { token: 'cd'.repeat(32), token_generation: 1 }),
        )).toThrow(/enrollment token folder .* is not private: (group|world)-writable ancestor/)
      })
      expect(await rejectionOf(stat(path))).toMatchObject({ code: 'ENOENT' })
    })
  }
})
