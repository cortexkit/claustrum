import { test, expect } from 'bun:test'
import { mkdtemp, writeFile, rm, chmod, stat, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { acceptsAncestor, ancestorIdentityContext } from '../ancestor-permissions.js'
import { writeEnrollmentTokenFile } from '../enrollment.js'

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
  ['sticky', true, { mode: 0o1777 }],
  ['other owner', false, { uid: 11 }],
  ['other gid', false, { gid: 21 }],
  ['malformed passwd', false, { passwd: 'broken\n' }],
  ['malformed group', false, { group: 'broken\n' }],
] as const
for (const [name, accepted, overrides] of cases) {
  test(`ancestor rule ${name}`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ancestor-rule-'))
    const value = overrides as { passwd?: string; group?: string; missing?: string; unreadable?: string; mode?: number; uid?: number; gid?: number }
    try {
      await writeFile(join(dir, 'passwd'), value.passwd ?? '# comment\n\nalice:x:10:20::/:/bin/sh\n')
      await writeFile(join(dir, 'group'), value.group ?? '# comment\n\nalice:x:20:\n')
      if (value.missing) await rm(join(dir, value.missing))
      // Reading a directory fails even for privileged test runners.
      if (value.unreadable) { await rm(join(dir, value.unreadable)); await import('node:fs/promises').then(({ mkdir }) => mkdir(join(dir, value.unreadable!))) }
      expect(await acceptsAncestor({ mode: value.mode ?? 0o775, uid: value.uid ?? 10, gid: value.gid ?? 20 }, {
        euid: 10, egid: 20, passwdPath: join(dir, 'passwd'), groupPath: join(dir, 'group'),
      })).toBe(accepted)
    } finally { await rm(dir, { recursive: true, force: true }) }
  })
}
// POSIX only, like the other permission tests: Windows reports every directory as
// group- and world-writable and has no effective uid or gid, so the client refuses
// there regardless of the account files, exactly as before this rule.
const onPosix = process.platform !== 'win32'
for (const otherMember of [false, true]) {
  test.skipIf(!onPosix)(`enrollment private ancestor ${otherMember ? 'refuses other member' : 'succeeds'}`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'enrollment-private-'))
    try {
      const metadata = await stat(dir)
      const passwdPath = join(dir, 'passwd'), groupPath = join(dir, 'group')
      await writeFile(passwdPath, `alice:x:${metadata.uid}:${metadata.gid}::/:/bin/sh\n`)
      await writeFile(groupPath, `alice:x:${metadata.gid}:${otherMember ? 'bob' : ''}\n`)
      await chmod(dir, 0o775)
      const path = join(dir, 'private', 'token.json')
      await ancestorIdentityContext.run({ euid: metadata.uid, egid: metadata.gid, passwdPath, groupPath }, async () => {
        const result = writeEnrollmentTokenFile(path, { token: 'a'.repeat(64), token_generation: 1 })
        if (otherMember) await expect(result).rejects.toThrow(`enrollment token ancestor ${await import('node:fs/promises').then(({ realpath }) => realpath(dir))} is group- or world-writable without sticky bit`)
        else { await result; expect(JSON.parse(await readFile(path, 'utf8')).token_generation).toBe(1) }
      })
    } finally { await rm(dir, { recursive: true, force: true }) }
  })
}
