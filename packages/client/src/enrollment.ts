import { randomBytes } from 'node:crypto'
import { chmod, mkdir, open, realpath, rename, stat, unlink } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'

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

async function refuseWritableAncestor(parent: string): Promise<void> {
  let component: string
  try {
    component = await realpath(parent)
  } catch {
    // The following file operation reports the precise filesystem error. A permissions
    // verdict about a path that could not be resolved would hide that useful failure.
    return
  }

  for (;;) {
    const metadata = await stat(component).catch(() => undefined)
    // Canonicalisation already traversed this component. If a later stat races with a
    // rename, let the create/rename operation below report the concrete failure.
    if (metadata && (metadata.mode & 0o022) !== 0 && (metadata.mode & 0o1000) === 0) {
      throw new Error(`enrollment token ancestor ${component} is group- or world-writable without sticky bit`)
    }
    const next = dirname(component)
    if (next === component) return
    component = next
  }
}

/**
 * Atomically replace a consumer's enrollment credential.
 *
 * The file is always mode 0600 and every canonical ancestor is rejected when it is
 * group- or world-writable without sticky. This is the same rule implemented by the
 * shipped `refuse_writable_ancestor` symbol in `opencode_files.rs`.
 */
export async function writeEnrollmentTokenFile(path: string, value: EnrollmentTokenFile): Promise<void> {
  validateTokenFile(value)
  const parent = dirname(path)
  await mkdir(parent, { recursive: true, mode: 0o700 })
  await refuseWritableAncestor(parent)

  const temporary = join(parent, `.${basename(path)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  let created = false
  try {
    const descriptor = await open(temporary, 'wx', 0o600)
    created = true
    try {
      await descriptor.writeFile(`${JSON.stringify(value)}\n`, 'utf8')
      await descriptor.sync()
      await chmod(temporary, 0o600)
    } finally {
      await descriptor.close()
    }
    await rename(temporary, path)
    created = false
  } finally {
    if (created) await unlink(temporary).catch(() => undefined)
  }
}
