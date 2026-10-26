import { createPrivateFile } from '@cortexkit/store'
import { checkPrivatePath, createPrivateParents, notPrivate, privateCreationCode } from './private-path.js'
import { randomBytes } from 'node:crypto'
import { open, rename, unlink } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'

export type EnrollmentTokenFile = {
  token: string
  token_generation: number
}

const TOKEN_RE = /^[0-9a-f]{64}$/

function validateTokenFile(value: EnrollmentTokenFile): void {
  if (!TOKEN_RE.test(value.token)) throw new Error('enrollment token must be exactly 64 lowercase hex characters')
  if (!Number.isSafeInteger(value.token_generation) || value.token_generation < 1) {
    throw new Error('enrollment token generation must be a positive safe integer')
  }
}

export function createEnrollmentWriter(checkPath: typeof checkPrivatePath = checkPrivatePath) {
async function refuseWritableAncestor(parent: string): Promise<void> {
  const result = await checkPath(parent)
  if (!result.ok) throw new Error(notPrivate('enrollment token folder', result))
}

/**
 * Atomically replace a consumer's enrollment credential.
 *
 * Creation uses owner-only Unix permissions or native Windows ACLs before writing
 * any bytes. @cortexkit/store checks that ancestors cannot be replaced by other
 * users, and on Windows also verifies the completed parent's owner-only ACL.
 */
async function writeEnrollmentTokenFile(path: string, value: EnrollmentTokenFile): Promise<void> {
  validateTokenFile(value)
  path = resolve(path)
  const parent = dirname(path)
  // Native Windows creation rejects ancestors that other users can replace. A missing
  // private parent can be created under a safe but non-private folder; afterwards the
  // async check also requires the completed parent's protected owner-only ACL.
  if (process.platform !== 'win32') await refuseWritableAncestor(parent)
  await createPrivateParents(parent)
  await refuseWritableAncestor(parent)

  const temporary = join(parent, `.${basename(path)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  let created = false
  try {
    created = true
    try {
      await createPrivateFile(temporary, `${JSON.stringify(value)}\n`)
    } catch (error) {
      if (privateCreationCode(error) === 'EEXIST') created = false
      throw error
    }
    const descriptor = await open(temporary, 'r+')
    try {
      await descriptor.sync()
    } finally {
      await descriptor.close()
    }
    await rename(temporary, path)
    created = false
  } finally {
    if (created) await unlink(temporary).catch(() => undefined)
  }
}
  return writeEnrollmentTokenFile
}

export const writeEnrollmentTokenFile = createEnrollmentWriter()
