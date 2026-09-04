import { constants as fsConstants } from 'node:fs'
import { chmod, lstat, mkdir, open, readFile, rename, rm, stat, unlink } from 'node:fs/promises'
import { randomBytes, randomInt } from 'node:crypto'
import { dirname, join } from 'node:path'
import { HANDLE_FILE_CONTRACT, parseHandleFile, type OpenCodeHandleFileV1 } from './handles.js'

export const MANIFEST_LOCK = { ttlMs: 30_000, renewEveryMs: 10_000, ownerKeys: ['tenant', 'pid', 'claimed_at_ms', 'nonce'] as const, staleTargetRe: /^\.lock\.stale-\d+-[A-Za-z0-9_-]+$/ }
export type ManifestHandleAccount = OpenCodeHandleFileV1['providers'][number]['accounts'][number]
export type ManifestHandleProvider = OpenCodeHandleFileV1['providers'][number]
export type ManifestHandleFile = OpenCodeHandleFileV1
type Owner = { tenant: string; pid: number; claimed_at_ms: number; nonce: string }
type TestOptions = { ttlMs?: number; renewEveryMs?: number; retryMinMs?: number; retryMaxMs?: number; afterClaim?: () => Promise<void> | void; beforeEvict?: () => Promise<void>; afterEvictRenameAttempt?: () => Promise<void>; afterEvict?: () => void; beforeManifestRename?: (path: string) => Promise<void> }
let testOptions: TestOptions | undefined
export function __setManifestLockTestOptions(options?: TestOptions): void { testOptions = options }
const token = () => randomBytes(16).toString('base64url')
const code = (error: unknown) => (error as NodeJS.ErrnoException | undefined)?.code
const sleep = async (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

function parseOwner(source: string): Owner {
  const value = JSON.parse(source) as unknown
  if (!value || typeof value !== 'object') throw new Error('manifest lock owner invalid')
  const owner = value as Record<string, unknown>
  if (Object.keys(owner).sort().join('\0') !== [...MANIFEST_LOCK.ownerKeys].sort().join('\0') || typeof owner.tenant !== 'string' || typeof owner.pid !== 'number' || !Number.isInteger(owner.pid) || typeof owner.claimed_at_ms !== 'number' || !Number.isFinite(owner.claimed_at_ms) || typeof owner.nonce !== 'string') throw new Error('manifest lock owner invalid')
  return owner as Owner
}
const readOwner = async (path: string) => parseOwner(await readFile(path, 'utf8'))
async function writeOwner(lock: string, owner: Owner): Promise<void> {
  const target = join(lock, 'owner'); const temporary = join(lock, `owner.${process.pid}.${token()}.tmp`)
  let file: Awaited<ReturnType<typeof open>> | undefined
  try {
    file = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600)
    await file.chmod(0o600); await file.writeFile(`${JSON.stringify(owner)}\n`); await file.sync(); await file.close(); file = undefined
    await rename(temporary, target)
  } finally { await file?.close().catch(() => {}); await unlink(temporary).catch(() => {}) }
}

export async function withManifestLock<T>(path: string, tenant: string, fn: () => Promise<T> | T): Promise<T> {
  return withLockCommit(path, tenant, async () => fn())
}
async function withLockCommit<T>(path: string, tenant: string, fn: (commit: () => Promise<void>) => Promise<T> | T): Promise<T> {
  const lock = `${path}.lock`, ownerPath = join(lock, 'owner'), ttl = testOptions?.ttlMs ?? MANIFEST_LOCK.ttlMs, renewEvery = testOptions?.renewEveryMs ?? MANIFEST_LOCK.renewEveryMs, retryMin = testOptions?.retryMinMs ?? 25, retryMax = testOptions?.retryMaxMs ?? 75
  const nonce = token(), started = Date.now(), deadline = started + ttl
  while (true) {
    try { await mkdir(lock, { mode: 0o700 }); await writeOwner(lock, { tenant, pid: process.pid, claimed_at_ms: Date.now(), nonce }); await testOptions?.afterClaim?.(); break } catch (error) {
      if (code(error) !== 'EEXIST') { if (code(error) !== 'ENOENT') await rm(lock, { recursive: true, force: true }).catch(() => {}); throw error }
    }
    let observed: Owner | undefined
    try { observed = await readOwner(ownerPath) } catch (error) { if (code(error) !== 'ENOENT' && Date.now() >= deadline) throw new Error('manifest lock busy') }
    if (observed && started - observed.claimed_at_ms >= ttl) {
      await testOptions?.beforeEvict?.()
      const stale = `${lock}.stale-${observed.claimed_at_ms}-${observed.nonce}`
      let renameError: unknown
      try { await rename(lock, stale) } catch (error) { renameError = error }
      await testOptions?.afterEvictRenameAttempt?.()
      if (renameError === undefined) {
        const moved = await readOwner(join(stale, 'owner')).catch(() => undefined)
        if (moved?.nonce === observed.nonce && moved.claimed_at_ms === observed.claimed_at_ms) { testOptions?.afterEvict?.(); continue }
        await rename(stale, lock).catch(() => {})
      } else if (!['ENOENT', 'EEXIST', 'ENOTEMPTY'].includes(code(renameError) ?? '')) throw renameError
    }
    if (Date.now() >= deadline) throw new Error('manifest lock busy')
    await sleep(Math.min(randomInt(retryMin, retryMax + 1), Math.max(1, deadline - Date.now())))
  }
  let renewal = Promise.resolve(), failed = false, stopped = false
  const timer = setInterval(() => { renewal = renewal.then(async () => { if (failed) return; try { const current = await readOwner(ownerPath); if (current.nonce !== nonce || Date.now() - current.claimed_at_ms >= ttl) throw new Error('lease lost'); await writeOwner(lock, { ...current, claimed_at_ms: Date.now() }) } catch { failed = true } }) }, renewEvery)
  timer.unref?.()
  const commit = async () => { if (!stopped) { stopped = true; clearInterval(timer); await renewal }; const current = await readOwner(ownerPath).catch(() => undefined); if (failed || !current || current.nonce !== nonce || Date.now() - current.claimed_at_ms >= ttl) throw new Error('manifest lock renewal failed; write aborted') }
  try { const result = await fn(commit); if (failed) throw new Error('manifest lock renewal failed; write aborted'); return result } finally {
    if (!stopped) clearInterval(timer); await renewal
    const current = await readOwner(ownerPath).catch(() => undefined)
    if (!current || current.nonce !== nonce || Date.now() - current.claimed_at_ms >= ttl) console.warn('manifest lock lease lost, not releasing', { path, tenant })
    else {
      const release = `${lock}.release-${nonce}`
      try { await rename(lock, release); const moved = await readOwner(join(release, 'owner')).catch(() => undefined); if (!moved || moved.nonce !== nonce || Date.now() - moved.claimed_at_ms >= ttl) { await rename(release, lock).catch(() => {}); console.warn('manifest lock lease lost, not releasing', { path, tenant }) } else await rm(release, { recursive: true, force: true }) } catch { console.warn('manifest lock lease lost, not releasing', { path, tenant }) }
    }
  }
}

async function readManifest(path: string): Promise<ManifestHandleFile> {
  let metadata: Awaited<ReturnType<typeof lstat>>
  try { metadata = await lstat(path) } catch (error) { if (code(error) === 'ENOENT') return { version: 1, providers: [] }; throw error }
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error('handle file must be a regular file')
  if ((metadata.mode & 0o777) !== HANDLE_FILE_CONTRACT.mode) throw new Error('handle file mode must be exactly 0600')
  const source = await readFile(path); if (source.byteLength > HANDLE_FILE_CONTRACT.maxBytes) throw new Error('handle file exceeds 256 KiB')
  return parseHandleFile(JSON.parse(source.toString('utf8')))
}
const foreign = (file: ManifestHandleFile, tenant: string) => file.providers.filter((provider) => provider.serve !== tenant).map((provider) => JSON.stringify(provider))
async function prepareParent(path: string): Promise<void> { const parent = dirname(path); await mkdir(parent, { recursive: true, mode: 0o700 }); const metadata = await stat(parent); if (!metadata.isDirectory()) throw new Error('handle file parent must be a directory'); if ((metadata.mode & 0o002) !== 0 && (metadata.mode & 0o1000) === 0) throw new Error('handle file parent is world-writable without sticky bit'); await chmod(parent, 0o700) }
async function writeAtomic(path: string, file: ManifestHandleFile, commit: () => Promise<void>): Promise<void> {
  const bytes = Buffer.from(JSON.stringify(file)); if (bytes.byteLength > HANDLE_FILE_CONTRACT.maxBytes) throw new Error('handle file exceeds 256 KiB')
  const temporary = join(dirname(path), `.${path.split('/').pop()}.${process.pid}.${token()}.tmp`); let handle: Awaited<ReturnType<typeof open>> | undefined
  try { handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600); await handle.chmod(0o600); await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined; await chmod(temporary, 0o600); await testOptions?.beforeManifestRename?.(`${path}.lock`); await commit(); await rename(temporary, path) } finally { await handle?.close().catch(() => {}); await unlink(temporary).catch(() => {}) }
}
export async function writeHandleFileLocked(path: string, tenant: string, mutate: (file: ManifestHandleFile) => void | ManifestHandleFile | Promise<void | ManifestHandleFile>): Promise<void> {
  await prepareParent(path)
  await withLockCommit(path, tenant, async (commit) => {
    const before = await readManifest(path), working = structuredClone(before), result = await mutate(working), next = parseHandleFile(result ?? working), beforeForeign = foreign(before, tenant)
    if (JSON.stringify(foreign(next, tenant)) !== JSON.stringify(beforeForeign)) throw new Error('manifest mutation changed another tenant block')
    await writeAtomic(path, next, commit)
    if (((await lstat(path)).mode & 0o777) !== HANDLE_FILE_CONTRACT.mode) throw new Error('manifest readback mode is not 0600')
    const readback = await readManifest(path)
    if (JSON.stringify(readback) !== JSON.stringify(next)) throw new Error('manifest readback differs')
    if (JSON.stringify(foreign(readback, tenant)) !== JSON.stringify(beforeForeign)) throw new Error('manifest readback changed another tenant block')
  })
}
