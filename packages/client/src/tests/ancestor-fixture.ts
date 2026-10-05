import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ancestorIdentityContext } from '../ancestor-permissions.js'

/** Supply complete local account data proving the directory's group is shared. */
export async function withSharedAncestorGroup<T>(directory: string, action: () => Promise<T>): Promise<T> {
  const metadata = await stat(directory)
  const fixture = await mkdtemp(join(tmpdir(), 'claustrum-account-fixture-'))
  const passwdPath = join(fixture, 'passwd'), groupPath = join(fixture, 'group')
  try {
    await writeFile(passwdPath, `alice:x:${metadata.uid}:${metadata.gid}::/:/bin/sh\n`)
    await writeFile(groupPath, `alice:x:${metadata.gid}:bob\n`)
    return await ancestorIdentityContext.run({ euid: metadata.uid, egid: metadata.gid, passwdPath, groupPath }, action)
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
}
