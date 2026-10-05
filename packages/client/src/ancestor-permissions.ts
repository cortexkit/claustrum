import { AsyncLocalStorage } from 'node:async_hooks'
import { readFile } from 'node:fs/promises'

// Internal context keeps fixture identities out of the client's public API and isolates concurrent tests.
export type AncestorIdentity = { euid: number | undefined; egid: number | undefined; passwdPath: string; groupPath: string }
export const ancestorIdentityContext = new AsyncLocalStorage<AncestorIdentity>()

function records(source: string, count: number): string[][] {
  return source.split('\n').filter((line) => line.trim() !== '' && !line.trimStart().startsWith('#')).map((line) => {
    const fields = line.split(':')
    if (fields.length !== count || !fields[0] || /\s/.test(fields[0]) || !/^\d+$/.test(fields[2]) || !Number.isSafeInteger(Number(fields[2])) || Number(fields[2]) > 0xffffffff || (count === 7 && (!/^\d+$/.test(fields[3]) || !Number.isSafeInteger(Number(fields[3])) || Number(fields[3]) > 0xffffffff))) {
      throw new Error('malformed account record')
    }
    if (count === 4 && fields[3] !== '' && fields[3]!.split(',').some((name) => name === '' || /\s/.test(name))) throw new Error('malformed group members')
    return fields
  })
}

export async function acceptsAncestor(metadata: { mode: number; uid?: number; gid?: number }, identity: AncestorIdentity = ancestorIdentityContext.getStore() ?? {
  euid: process.geteuid?.(), egid: process.getegid?.(), passwdPath: '/etc/passwd', groupPath: '/etc/group',
}): Promise<boolean> {
  if ((metadata.mode & 0o022) === 0 || (metadata.mode & 0o1000) !== 0) return true
  if ((metadata.mode & 0o002) !== 0 || identity.euid === undefined || identity.egid === undefined || metadata.uid !== identity.euid || metadata.gid !== identity.egid) return false
  try {
    const passwd = records(new TextDecoder('utf-8', { fatal: true }).decode(await readFile(identity.passwdPath)), 7)
    const groups = records(new TextDecoder('utf-8', { fatal: true }).decode(await readFile(identity.groupPath)), 4)
    const users = passwd.filter((entry) => Number(entry[2]) === identity.euid)
    const matchingGroups = groups.filter((entry) => Number(entry[2]) === identity.egid)
    if (users.length !== 1 || matchingGroups.length !== 1) return false
    const name = users[0]![0]!
    return (matchingGroups[0]![3] === '' || matchingGroups[0]![3]!.split(',').every((member) => member === name)) &&
      !passwd.some((entry) => Number(entry[2]) !== identity.euid && Number(entry[3]) === identity.egid)
  } catch {
    // Local files must prove exclusivity; unavailable or malformed NSS data cannot grant an exception.
    return false
  }
}
