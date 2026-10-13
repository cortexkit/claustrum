import { test, expect } from 'bun:test'
import { writeFile, rm, readFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { type OwnerOnlyPathAsyncOptions, type OwnerOnlyPathMetadata } from '@cortexkit/store'
import { privatePathContext } from '../private-path.js'
import { writeEnrollmentTokenFile } from '../enrollment.js'
import { accountOptions, privateFixtureDirectory } from './ancestor-fixture.js'

const cases = [
  ['private group', true, {}],
  ['self member', true, { group: 'alice:x:20:alice\n' }],
  ['other member', false, { group: 'alice:x:20:bob\n' }],
  ['other primary', false, { passwd: 'alice:x:10:20::/:/bin/sh\nbob:x:11:20::/:/bin/sh\n' }],
  ['absent uid', false, { passwd: 'bob:x:11:21::/:/bin/sh\n' }],
  ['absent gid', false, { group: 'bob:x:21:\n' }],
  ['missing passwd', false, { missing: 'passwd' }],
  ['missing group', false, { missing: 'group' }],
  ['unreadable passwd', false, { unreadable: 'passwd' }],
  ['unreadable group', false, { unreadable: 'group' }],
  ['world writable', false, { mode: 0o777 }],
  ['non-root sticky ancestor', false, { mode: 0o1777 }],
  ['root sticky ancestor with an owner-only child', true, { mode: 0o1777, uid: 0 }],
  ['foreign-owned 0755 ancestor', false, { mode: 0o755, uid: 11 }],
  ['other owner', false, { uid: 11 }],
  ['other gid', false, { gid: 21 }],
  ['malformed passwd', false, { passwd: 'broken\n' }],
  ['malformed group', false, { group: 'broken\n' }],
] as const

type Overrides = { passwd?: string; group?: string; missing?: string; unreadable?: string; mode?: number; uid?: number; gid?: number }

function fixtureOptions(accounts: OwnerOnlyPathAsyncOptions, value: Overrides): OwnerOnlyPathAsyncOptions {
  const directory = (path: string): OwnerOnlyPathMetadata => ({
    isDirectory: () => true,
    mode: path === '/home/alice/.config' ? value.mode ?? 0o775 : path === '/home/alice/.config/cortexkit' ? 0o700 : 0o755,
    uid: path === '/home/alice/.config' ? value.uid ?? 10 : path.startsWith('/home/alice') ? 10 : 0,
    gid: path === '/home/alice/.config' ? value.gid ?? 20 : 20,
  })
  // The policy sees a complete Unix account/ancestor fixture. Actual creation still
  // uses a private host directory, independent of the runner's uid, gid and account files.
  return { ...accounts, platform: 'linux', fs: {
    ...accounts.fs,
    realpath: async () => '/home/alice/.config/cortexkit',
    stat: async (path) => directory(path),
    lstat: async (path) => directory(path),
  } }
}

for (const [name, accepted, overrides] of cases) {
  test(`ancestor rule ${name}`, async () => {
    const dir = await privateFixtureDirectory('ancestor-rule-')
    const value: Overrides = overrides
    try {
      await writeFile(join(dir, 'passwd'), value.passwd ?? '# comment\n\nalice:x:10:20::/:/bin/sh\n')
      await writeFile(join(dir, 'group'), value.group ?? '# comment\n\nalice:x:20:\n')
      if (value.missing) await rm(join(dir, value.missing))
      // Reading a directory fails even for privileged test runners.
      if (value.unreadable) { await rm(join(dir, value.unreadable)); await mkdir(join(dir, value.unreadable)) }
      const options = fixtureOptions(accountOptions(10, 20, join(dir, 'passwd'), join(dir, 'group')), value)
      const path = join(dir, 'private', 'token.json')
      await privatePathContext.run(options, async () => {
        const result = writeEnrollmentTokenFile(path, { token: 'a'.repeat(64), token_generation: 1 })
        if (accepted) { await result; expect(JSON.parse(await readFile(path, 'utf8')).token_generation).toBe(1) }
        else { await expect(result).rejects.toThrow('is not private:'); await expect(readFile(path)).rejects.toMatchObject({ code: 'ENOENT' }) }
      })
    } finally { await rm(dir, { recursive: true, force: true }) }
  })
}

for (const distribution of ['Ubuntu', 'Fedora']) {
  test(`enrollment private ancestor succeeds on ${distribution} with umask 0002 and 0775 .config`, async () => {
    const dir = await privateFixtureDirectory('enrollment-private-')
    const previous = process.umask(0o002)
    try {
      await writeFile(join(dir, 'passwd'), 'alice:x:10:20::/home/alice:/bin/sh\n')
      await writeFile(join(dir, 'group'), 'alice:x:20:\n')
      const options = fixtureOptions(accountOptions(10, 20, join(dir, 'passwd'), join(dir, 'group')), {})
      await privatePathContext.run(options, async () => {
        const path = join(dir, '.config', 'cortexkit', 'token.json')
        await writeEnrollmentTokenFile(path, { token: 'b'.repeat(64), token_generation: 1 })
        expect(JSON.parse(await readFile(path, 'utf8')).token_generation).toBe(1)
      })
    } finally { process.umask(previous); await rm(dir, { recursive: true, force: true }) }
  })
}
