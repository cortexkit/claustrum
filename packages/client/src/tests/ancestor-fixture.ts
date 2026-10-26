import { mkdtemp, rm, stat, readFile, writeFile } from 'node:fs/promises'
import { createPrivateDirectory, type OwnerOnlyPathAsyncOptions } from '@cortexkit/store'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { privatePathContext } from './injected-files.js'

// Handle-reader unit tests inject file and parent stats. A root-owned 0755 ancestor
// passes @cortexkit/store's path check, isolating descriptor reads and validation order.
export const readerFixtureOptions: OwnerOnlyPathAsyncOptions = { platform: 'linux', euid: 1000, egid: 1000, fs: {
  realpath: async () => '/',
  stat: async () => ({ isDirectory: () => true, mode: 0o755, uid: 0, gid: 0 }),
  lstat: async () => ({ isDirectory: () => true, mode: 0o755, uid: 0, gid: 0 }),
} }

export function accountOptions(euid: number, egid: number, passwdPath: string, groupPath: string): OwnerOnlyPathAsyncOptions {
  return { euid, egid, fs: { readFile: (path) => readFile(path === '/etc/passwd' ? passwdPath : path === '/etc/group' ? groupPath : path) } }
}

/** Windows fixtures need real private ACLs, not Node's emulated chmod bits. */
export async function privateFixtureDirectory(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix))
  if (process.platform === 'win32') {
    await rm(path, { recursive: true })
    await createPrivateDirectory(path)
  }
  return path
}

/** Supply complete local account data proving the directory's group is shared. */
export async function withSharedAncestorGroup<T>(directory: string, action: () => Promise<T>): Promise<T> {
  const metadata = await stat(directory)
  const fixture = await mkdtemp(join(tmpdir(), 'claustrum-account-fixture-'))
  const passwdPath = join(fixture, 'passwd'), groupPath = join(fixture, 'group')
  try {
    await writeFile(passwdPath, `alice:x:${metadata.uid}:${metadata.gid}::/:/bin/sh\n`)
    await writeFile(groupPath, `alice:x:${metadata.gid}:bob\n`)
    return await privatePathContext.run(accountOptions(metadata.uid, metadata.gid, passwdPath, groupPath), action)
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
}
