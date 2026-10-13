import { AsyncLocalStorage } from 'node:async_hooks'
import { stat } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { checkOwnerOnlyPathAsync, createPrivateDirectory, type OwnerOnlyPathAsyncOptions, type OwnerOnlyPathResult } from '@cortexkit/store'

// Tests run the ownership check against fixture uids and account files through this
// context, isolated per concurrent test. It is internal: the package `exports` map
// exposes only the index, so consumers cannot reach it.
export const privatePathContext = new AsyncLocalStorage<OwnerOnlyPathAsyncOptions>()

export const checkPrivatePath = (path: string, options?: OwnerOnlyPathAsyncOptions) => checkOwnerOnlyPathAsync(resolve(path), privatePathContext.getStore() ?? options)

/**
 * The refusal text for a path the store judged not private. It names the folder and the
 * store's own reason (foreign owner, world-writable, a sticky folder without an
 * owner-only child, a Windows ACL problem, ...), so the operator sees the actual cause.
 */
export function notPrivate(subject: string, result: Extract<OwnerOnlyPathResult, { ok: false }>): string {
  return `${subject} ${result.path} is not private: ${result.reason}`
}

/** Native creation errors use Win32 numbers rather than Node's exclusive-create codes. */
export function privateCreationCode(error: unknown): string | undefined {
  const value = error as { code?: string; reason?: string; win32Code?: number } | undefined
  if (value?.code === 'ERR_PRIVATE_FILES_SECURITY' && value.reason === 'io-error') {
    if (value.win32Code === 80 || value.win32Code === 183) return 'EEXIST'
    if (value.win32Code === 2 || value.win32Code === 3) return 'ENOENT'
  }
  return value?.code
}

/** Create missing components privately without repairing permissions on existing directories. */
export async function createPrivateParents(path: string): Promise<void> {
  try {
    await stat(path)
    return
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  const parent = dirname(path)
  if (parent !== path) await createPrivateParents(parent)
  try {
    await createPrivateDirectory(path)
  } catch (error) {
    if (privateCreationCode(error) !== 'EEXIST') throw error
    if (!(await stat(path)).isDirectory()) throw error
  }
}
