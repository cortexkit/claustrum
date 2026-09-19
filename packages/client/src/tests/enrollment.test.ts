import { afterEach, describe, expect, test } from 'bun:test'
import { chmod, mkdtemp, mkdir, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { writeEnrollmentTokenFile } from '../enrollment.js'

const roots: string[] = []
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

const onPosix = process.platform !== 'win32'

describe('enrollment token file', () => {
  test.skipIf(!onPosix)('writes the token and generation atomically at mode 0600', async () => {
    const root = await mkdtemp(join(tmpdir(), 'claustrum-enrollment-'))
    roots.push(root)
    await chmod(root, 0o700)
    const path = join(root, 'consumer.json')
    const value = { token: 'ab'.repeat(32), token_generation: 2 }

    await writeEnrollmentTokenFile(path, value)

    expect((await stat(path)).mode & 0o777).toBe(0o600)
    expect(JSON.parse(await readFile(path, 'utf8'))).toEqual(value)
  })

  test.skipIf(!onPosix)('refuses a 0777 non-sticky ancestor before creating the token file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'claustrum-enrollment-'))
    roots.push(root)
    await chmod(root, 0o700)
    const unsafe = join(root, 'unsafe')
    const child = join(unsafe, 'private')
    await mkdir(child, { recursive: true, mode: 0o700 })
    await chmod(unsafe, 0o777)

    const path = join(child, 'consumer.json')
    await expect(
      writeEnrollmentTokenFile(path, { token: 'cd'.repeat(32), token_generation: 1 }),
    ).rejects.toThrow('group- or world-writable without sticky bit')
    await expect(stat(path)).rejects.toMatchObject({ code: 'ENOENT' })
  })
})
