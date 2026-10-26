import { privateFixtureDirectory, withSharedAncestorGroup } from './ancestor-fixture.js'
import { checkOwnerOnlyPathAsync, createPrivateDirectory, createPrivateFile } from '@cortexkit/store'
import { readHandleFile } from '../handles.js'
import { afterEach, describe, expect, test } from 'bun:test'
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { basename, join, posix, win32 } from 'node:path'

import {
  MANIFEST_LOCK,
  manifestLockQuarantinePrefix,
} from '../manifest-lock'
import { setLockOptions, withManifestLock, writeHandleFileLocked } from './injected-files.js'
import type { ManifestLockError, ManifestLockErrorCode } from '../index'
import { rejectionOf, throwerOf } from './settle'

const roots: string[] = []
const handle = (letter: string) => `ckh_${letter.repeat(43)}`
const sleep = async (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const RECLAIM_MARGIN_MS = 5_000

async function manifestPath(): Promise<string> {
  const root = await privateFixtureDirectory('claustrum-manifest-lock-')
  roots.push(root)
  return join(root, 'opencode-handles.json')
}

// The writer walks EVERY ancestor up to `/`, so the two ancestor tests depend on the whole
// path, not only the directory they chmod. os.tmpdir() follows TMPDIR, which can point under a
// group-writable directory, and then the refusal test would pass without its own chmod.
// `/tmp` is root-owned 1777 with `/` above it on Linux and macOS (where it resolves to
// /private/tmp), so only the test's own chmod decides the outcome.
async function cleanAncestorManifestPath(): Promise<string> {
  const root = await mkdtemp(join('/tmp', 'claustrum-manifest-lock-'))
  roots.push(root)
  return join(root, 'opencode-handles.json')
}

// Set mode 1777 with the chmod command, then confirm it took. Bun 1.3.14 on Linux drops the
// sticky bit from fs.chmod (0o1777 lands as 0777; measured in oven/bun:1.3.14, while macOS
// keeps it), so a fixture built with fs.chmod is not sticky there and the writer refuses it
// correctly, which reads as a writer bug.
async function makeSticky(dir: string): Promise<void> {
  const result = spawnSync('chmod', ['1777', dir])
  expect(result.status).toBe(0)
  expect((await stat(dir)).mode & 0o7777).toBe(0o1777)
}

function provider(provider: string, tenant: string) {
  return {
    provider,
    shape: 'api' as const,
    serve: tenant,
    accounts: [{
      label: 'main',
      handle: handle(provider[0] ?? 'A'),
      credential_id: `apikey:${provider}:main`,
    }],
  }
}

async function owner(path: string, claimedAtMs: number, tenant = 'other-tenant'): Promise<void> {
  const lockPath = `${path}.lock`
  await createPrivateDirectory(lockPath)
  await createPrivateFile(join(lockPath, 'owner'), `${JSON.stringify({
    tenant,
    pid: 41,
    claimed_at_ms: claimedAtMs,
    nonce: '0123456789abcdef0123456789abcdef',
  })}\n`)
}

async function quarantine(path: string, claimedAtMs: number, nonce: string, modifiedAtMs: number): Promise<string> {
  const target = `${path}.lock.stale-${claimedAtMs}-${nonce}`
  await mkdir(target, { mode: 0o700 })
  await utimes(target, modifiedAtMs / 1_000, modifiedAtMs / 1_000)
  return target
}

const reclaimOptions = (ttlMs = 100) => ({ ttlMs, renewEveryMs: 1_000, retryMinMs: 1, retryMaxMs: 1 })

afterEach(async () => {
  setLockOptions()
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

// Only Unix permission and link fixtures are gated. Locking and owner-only publication
// run on Windows too, where the store verifies native security descriptors instead of modes.
// Keep onPosix distinct from node:path's posix import.
const onPosix = process.platform !== 'win32'

// The lock refuses on Windows (see the first test), so every test that takes it runs
// on POSIX only. Pure tests of the shared constants and exports run everywhere.
const lockTest = onPosix ? test : test.skip

describe('manifest writer lock', () => {
  test.skipIf(onPosix)('refuses on Windows rather than risk two overlapping writers', async () => {
    const path = join(await mkdtemp(join(tmpdir(), 'claustrum-win-lock-')), 'opencode-handles.json')
    expect(await rejectionOf(withManifestLock(path, 'tenant', () => 'ran'))).toMatchObject({ code: 'unsupported_platform' })
    expect(await rejectionOf(writeHandleFileLocked(path, 'tenant', () => {}))).toMatchObject({ code: 'unsupported_platform' })
  })

  lockTest('lock directory and owner record are owner-only before the callback', async () => {
    const path = await manifestPath()
    await withManifestLock(path, 'tenant', async () => {
      expect(await checkOwnerOnlyPathAsync(`${path}.lock`)).toEqual({ ok: true })
      expect(await checkOwnerOnlyPathAsync(join(`${path}.lock`, 'owner'))).toEqual({ ok: true })
      if (onPosix) {
        expect((await stat(`${path}.lock`)).mode & 0o777).toBe(0o700)
        expect((await stat(join(`${path}.lock`, 'owner'))).mode & 0o777).toBe(0o600)
      }
    })
  })
  test.skipIf(!onPosix)('writer refuses writable ancestors before creating anything', async () => {
    const path = await cleanAncestorManifestPath()
    const root = join(path, '..')
    await chmod(root, 0o775)
    const target = join(root, 'private', 'manifest.json')
    await withSharedAncestorGroup(root, async () => {
      expect(await throwerOf(writeHandleFileLocked(target, 'tenant', () => {}))).toThrow('is not private: group-writable ancestor')
    })
    expect(await readdir(root)).toEqual([])
  })

  // Only a root-owned sticky folder is trusted; this one belongs to the test user, so it
  // counts as plain world-writable.
  test.skipIf(!onPosix)('writer refuses a sticky world-writable parent the user owns', async () => {
    const path = await cleanAncestorManifestPath()
    await makeSticky(join(path, '..'))
    expect(await throwerOf(writeHandleFileLocked(path, 'tenant', () => {}))).toThrow('is not private: world-writable ancestor')
  })

  test.skipIf(!onPosix)('writer refuses a parent owned by another uid before writing', async () => {
    const path = await manifestPath()
    const getuid = process.getuid!
    process.getuid = () => getuid() + 1
    try {
      expect(await throwerOf(writeHandleFileLocked(path, 'tenant', () => {}))).toThrow('not owned by the current uid')
      expect(await readdir(join(path, '..'))).toEqual([])
    } finally { process.getuid = getuid }
  })

  lockTest('ownerless lock older than ttl is evicted using directory mtime', async () => {
    const path = await manifestPath()
    setLockOptions(reclaimOptions())
    await mkdir(`${path}.lock`)
    const old = (Date.now() - 1_000) / 1_000
    await utimes(`${path}.lock`, old, old)
    expect(await withManifestLock(path, 'tenant', () => 'claimed')).toBe('claimed')
  })

  lockTest('ownerless lock with recent mtime is retained until ttl', async () => {
    const path = await manifestPath()
    setLockOptions(reclaimOptions())
    await mkdir(`${path}.lock`)
    const future = (Date.now() + 10_000) / 1_000
    await utimes(`${path}.lock`, future, future)
    expect(await rejectionOf(withManifestLock(path, 'tenant', () => {}))).toMatchObject({ code: 'lock_busy' })
    expect((await readdir(`${path}.lock`))).toEqual([])
  })

  lockTest('owner published during ownerless eviction is not stolen', async () => {
    const path = await manifestPath()
    setLockOptions({ ...reclaimOptions(), beforeEvict: async () => {
      await writeFile(join(`${path}.lock`, 'owner'), JSON.stringify({ tenant: 'other', pid: 1, claimed_at_ms: Date.now() + 10_000, nonce: 'other' }))
    } })
    await mkdir(`${path}.lock`)
    const old = (Date.now() - 1_000) / 1_000
    await utimes(`${path}.lock`, old, old)
    expect(await rejectionOf(withManifestLock(path, 'tenant', () => {}))).toMatchObject({ code: 'lock_busy' })
    expect(JSON.parse(await readFile(join(`${path}.lock`, 'owner'), 'utf8')).nonce).toBe('other')
  })

  lockTest('two concurrent tenant writers preserve both provider blocks', async () => {
    const path = await manifestPath()
    const firstEntered = Promise.withResolvers<void>()
    const releaseFirst = Promise.withResolvers<void>()

    const first = writeHandleFileLocked(path, 'anthropic-auth', async (file) => {
      firstEntered.resolve()
      await releaseFirst.promise
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })
    await firstEntered.promise
    const second = writeHandleFileLocked(path, 'openai-auth', (file) => {
      file.providers.push(provider('openai', 'openai-auth'))
    })
    releaseFirst.resolve()
    await Promise.all([first, second])

    const written = JSON.parse(await readFile(path, 'utf8')) as { providers: Array<{ provider: string }> }
    expect(written.providers.map((entry) => entry.provider).sort()).toEqual(['anthropic', 'openai'])
  })

  lockTest('stale owner is evicted by rename and retained as a quarantine directory', async () => {
    const path = await manifestPath()
    await owner(path, Date.now() - MANIFEST_LOCK.ttlMs - 1)

    await withManifestLock(path, 'anthropic-auth', async () => {})

    const suffixes = (await readdir(join(path, '..')))
      .filter((name) => name.startsWith(`${basename(path)}.lock.stale-`))
      .map((name) => name.slice(basename(path).length))
    expect(suffixes).toHaveLength(1)
    expect(MANIFEST_LOCK.staleTargetRe.test(suffixes[0]!)).toBe(true)
  })

  lockTest('quarantine younger than reclaim age is retained', async () => {
    const path = await manifestPath()
    setLockOptions(reclaimOptions())
    const target = await quarantine(path, 1, 'young_nonce', Date.now() - (100 + RECLAIM_MARGIN_MS - 1_000))

    await withManifestLock(path, 'claimant', async () => {})

    expect((await stat(target)).isDirectory()).toBe(true)
  })

  lockTest('quarantine older than reclaim age is reclaimed', async () => {
    const path = await manifestPath()
    setLockOptions(reclaimOptions())
    const target = await quarantine(path, 1, 'old_nonce', Date.now() - (100 + RECLAIM_MARGIN_MS + 1))

    await withManifestLock(path, 'claimant', async () => {})

    expect(await rejectionOf(stat(target))).toMatchObject({ code: 'ENOENT' })
  })

  lockTest('quarantine past ttl but inside margin is retained', async () => {
    const path = await manifestPath()
    setLockOptions(reclaimOptions())
    const target = await quarantine(path, 1, 'margin_nonce', Date.now() - 101)

    await withManifestLock(path, 'claimant', async () => {})

    expect((await stat(target)).isDirectory()).toBe(true)
  })

  lockTest('old quarantine name with recent mtime is retained', async () => {
    const path = await manifestPath()
    setLockOptions(reclaimOptions())
    const target = await quarantine(path, 1, 'recent_mtime_nonce', Date.now())

    await withManifestLock(path, 'claimant', async () => {})

    expect((await stat(target)).isDirectory()).toBe(true)
  })

  lockTest('reclaim leaves nonmatching siblings, the live lock, and another manifest quarantine', async () => {
    const path = await manifestPath()
    setLockOptions(reclaimOptions())
    const parent = join(path, '..')
    const nonmatching = join(parent, `${basename(path)}.lock.stale-not-a-timestamp-nonce`)
    const unrelatedFile = join(parent, 'unrelated')
    const otherQuarantine = await quarantine(join(parent, 'another-manifest.json'), 1, 'other_nonce', Date.now() - (100 + RECLAIM_MARGIN_MS + 1))
    await mkdir(nonmatching, { mode: 0o700 })
    await utimes(nonmatching, (Date.now() - (100 + RECLAIM_MARGIN_MS + 1)) / 1_000, (Date.now() - (100 + RECLAIM_MARGIN_MS + 1)) / 1_000)
    await writeFile(unrelatedFile, 'untouched')

    await withManifestLock(path, 'claimant', async () => {
      expect((await stat(`${path}.lock`)).isDirectory()).toBe(true)
    })

    expect((await stat(nonmatching)).isDirectory()).toBe(true)
    expect(await readFile(unrelatedFile, 'utf8')).toBe('untouched')
    expect((await stat(otherQuarantine)).isDirectory()).toBe(true)
  })

  test.skipIf(!onPosix)('reclaim failure does not fail acquisition', async () => {
    const path = await manifestPath()
    const parent = join(path, '..')
    const target = await quarantine(path, 1, 'unreadable_nonce', Date.now() - (100 + RECLAIM_MARGIN_MS + 1))
    // Refuse the sweep's readdir only after secure creation has inspected the parent.
    setLockOptions({ ...reclaimOptions(), afterClaim: () => chmod(parent, 0o300) })
    try {
      await withManifestLock(path, 'claimant', async () => {})
    } finally {
      await chmod(parent, 0o700)
    }

    expect((await stat(target)).isDirectory()).toBe(true)
  })

  lockTest('owner that becomes stale during the retry window is evicted', async () => {
    const path = await manifestPath()
    setLockOptions({ ttlMs: 80, renewEveryMs: 1_000, retryMinMs: 2, retryMaxMs: 3 })
    await owner(path, Date.now() - 30)

    await withManifestLock(path, 'anthropic-auth', async () => {})

    const suffixes = (await readdir(join(path, '..'))).filter((name) => name.startsWith(`${basename(path)}.lock.stale-`))
    expect(suffixes).toHaveLength(1)
  })

  lockTest('owner nonce containing a path traversal is invalid and never renamed', async () => {
    for (const nonce of ['../escape', 'a/b', 'a:b', 'a*b', 'a?b', 'a|b']) {
      const path = await manifestPath()
      const lockPath = `${path}.lock`
      setLockOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
      await mkdir(lockPath, { mode: 0o700 })
      await writeFile(join(lockPath, 'owner'), `${JSON.stringify({ tenant: 'squatter', pid: 41, claimed_at_ms: Date.now() - 31, nonce })}\n`, { mode: 0o600 })

      const error = (await withManifestLock(path, 'anthropic-auth', async () => {}).catch((caught) => caught)) as ManifestLockError & { code: ManifestLockErrorCode }

      expect(error.code).toBe('owner_invalid')
      expect((await stat(lockPath)).isDirectory()).toBe(true)
      expect((await readdir(join(path, '..'))).some((name) => name.includes('.lock.stale-'))).toBe(false)
      expect(await rejectionOf(stat(join(path, '..', 'escape')))).toMatchObject({ code: 'ENOENT' })
    }
  })

  lockTest('path-safe unfamiliar nonce alphabets remain evictable', async () => {
    for (const nonce of ['abc.def', 'AAAA====']) {
      const path = await manifestPath()
      const lockPath = `${path}.lock`
      setLockOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
      await mkdir(lockPath, { mode: 0o700 })
      await writeFile(join(lockPath, 'owner'), `${JSON.stringify({ tenant: 'newer-writer', pid: 41, claimed_at_ms: Date.now() - 31, nonce })}\n`, { mode: 0o600 })

      await withManifestLock(path, 'anthropic-auth', async () => {})

      expect((await readdir(join(path, '..'))).some((name) => name.startsWith(`${basename(path)}.lock.stale-`))).toBe(true)
    }
  })

  lockTest('unknown owner keys are busy while fresh and evictable once stale', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    setLockOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await mkdir(lockPath, { mode: 0o700 })
    const record = { tenant: 'newer-writer', pid: 41, claimed_at_ms: Date.now() + 1_000, nonce: 'newer_writer_nonce', generation: 2 }
    await writeFile(join(lockPath, 'owner'), `${JSON.stringify(record)}\n`, { mode: 0o600 })

    const freshError = (await withManifestLock(path, 'anthropic-auth', async () => {}).catch((caught) => caught)) as ManifestLockError & { code: ManifestLockErrorCode }
    expect(freshError.code).toBe('lock_busy')

    record.claimed_at_ms = Date.now() - 31
    await writeFile(join(lockPath, 'owner'), `${JSON.stringify(record)}\n`, { mode: 0o600 })
    await withManifestLock(path, 'anthropic-auth', async () => {})
    expect((await readdir(join(path, '..'))).some((name) => name.startsWith(`${basename(path)}.lock.stale-`))).toBe(true)
  })

  lockTest('malformed diagnostic owner fields do not prevent stale eviction', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    setLockOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await mkdir(lockPath, { mode: 0o700 })
    await writeFile(join(lockPath, 'owner'), `${JSON.stringify({ tenant: 41, pid: 'unknown', claimed_at_ms: Date.now() - 31, nonce: 'valid_nonce' })}\n`, { mode: 0o600 })

    await withManifestLock(path, 'anthropic-auth', async () => {})

    expect((await readdir(join(path, '..'))).some((name) => name.startsWith(`${basename(path)}.lock.stale-`))).toBe(true)
  })

  lockTest('renewing owner fails loudly after the bounded retry window', async () => {
    const path = await manifestPath()
    setLockOptions({ ttlMs: 40, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    // The owner's stamp sits a minute ahead, so it reads as fresh for the whole test no
    // matter how late a renewal tick runs. Stamping Date.now() made the owner's liveness
    // depend on the scheduler: on a loaded host a 5 ms tick can stall past the 40 ms TTL,
    // the owner then looks stale, and the claimant correctly evicts it, so the test failed
    // with a resolved promise while the lock was right. The renewal loop stays, so the
    // claimant still races real owner rewrites.
    const LIVE_AHEAD_MS = 60_000
    await owner(path, Date.now() + LIVE_AHEAD_MS)

    const started = Date.now()
    // clearInterval stops future ticks but cannot cancel one already awaiting I/O. An
    // unawaited tick that outlives the test writes into a root afterEach has removed, and
    // bun reports the ENOENT against whichever test runs next. So each tick is chained and
    // the chain is drained before the test returns. A failing tick is recorded, not left as
    // a rejected promise, because a rejection nobody is awaiting yet is itself unhandled.
    let tick = Promise.resolve(), tickError: unknown
    const renewal = setInterval(() => {
      tick = tick.then(async () => {
        if (tickError !== undefined) return
        const ownerPath = join(`${path}.lock`, 'owner')
        const current = JSON.parse(await readFile(ownerPath, 'utf8')) as Record<string, unknown>
        current.claimed_at_ms = Date.now() + LIVE_AHEAD_MS
        await writeFile(ownerPath, `${JSON.stringify(current)}\n`, { mode: 0o600 })
      }).catch((error: unknown) => { tickError = error })
    }, 5)
    try {
      expect(await throwerOf(withManifestLock(path, 'anthropic-auth', async () => {}))).toThrow('manifest lock busy')
      expect(Date.now() - started).toBeGreaterThanOrEqual(35)
    } finally { clearInterval(renewal); await tick }
    if (tickError !== undefined) throw tickError
  })

  lockTest('owner file exists while held and disappears with the lock after release', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`

    await withManifestLock(path, 'anthropic-auth', async () => {
      const parsed = JSON.parse(await readFile(join(lockPath, 'owner'), 'utf8')) as Record<string, unknown>
      expect(Object.keys(parsed).sort()).toEqual([...MANIFEST_LOCK.ownerKeys].sort())
      expect(parsed.tenant).toBe('anthropic-auth')
    })

    expect(await rejectionOf(stat(lockPath))).toMatchObject({ code: 'ENOENT' })
  })

  // POSIX only: stale eviction relies on renaming a lock another process may hold
  // open, which Windows refuses; the lock refuses on Windows (see the test below).
  test.skipIf(!onPosix)('two stale evictors produce one eviction winner and never overlap holders', async () => {
    const path = await manifestPath()
    await owner(path, Date.now() - MANIFEST_LOCK.ttlMs - 1)
    let waiting = 0
    const bothReady = Promise.withResolvers<void>()
    let evictionWins = 0
    setLockOptions({
      beforeEvict: async () => {
        waiting += 1
        if (waiting === 2) bothReady.resolve()
        await bothReady.promise
      },
      afterEvict: () => { evictionWins += 1 },
      retryMinMs: 2,
      retryMaxMs: 3,
    })
    let active = 0
    let maxActive = 0
    const hold = async () => {
      active += 1
      maxActive = Math.max(maxActive, active)
      await Bun.sleep(15)
      active -= 1
    }

    await Promise.all([
      withManifestLock(path, 'anthropic-auth', hold),
      withManifestLock(path, 'openai-auth', hold),
    ])

    expect(evictionWins).toBe(1)
    expect(maxActive).toBe(1)
  })

  // POSIX only: stale eviction relies on renaming a lock another process may hold
  // open, which Windows refuses; the lock refuses on Windows (see the test below).
  test.skipIf(!onPosix)('an evictor that observed stale owner cannot rename a replacement lock', async () => {
    const path = await manifestPath()
    const now = Date.now()
    await owner(path, now - 501)
    const loserObserved = Promise.withResolvers<void>()
    const allowLoserRename = Promise.withResolvers<void>()
    const replacementClaimed = Promise.withResolvers<void>()
    const allowReplacementRelease = Promise.withResolvers<void>()
    const renameAttempted = Promise.withResolvers<void>()
    const allowAttemptCompletion = Promise.withResolvers<void>()
    let beforeEvictCalls = 0
    let evictRenameAttempts = 0

    setLockOptions({
      ttlMs: 500,
      renewEveryMs: 1_000,
      retryMinMs: 2,
      retryMaxMs: 3,
      beforeEvict: async () => {
        beforeEvictCalls += 1
        if (beforeEvictCalls === 1) {
          loserObserved.resolve()
          await allowLoserRename.promise
        }
      },
      afterClaim: async () => {
        replacementClaimed.resolve()
        await allowReplacementRelease.promise
      },
      afterEvictRenameAttempt: async () => {
        evictRenameAttempts += 1
        if (evictRenameAttempts !== 2) return
        renameAttempted.resolve()
        await allowAttemptCompletion.promise
      },
    })

    const loser = withManifestLock(path, 'loser', async () => {})
    await loserObserved.promise
    const replacement = withManifestLock(path, 'replacement', async () => {})
    await replacementClaimed.promise
    allowLoserRename.resolve()
    await renameAttempted.promise
    allowReplacementRelease.resolve()
    await replacement
    allowAttemptCompletion.resolve()
    await loser

    expect(await rejectionOf(stat(`${path}.lock`))).toMatchObject({ code: 'ENOENT' })
  })

  lockTest('an expired holder does not release its directory and logs the lost lease', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    setLockOptions({ ttlMs: 40, renewEveryMs: 1_000, retryMinMs: 2, retryMaxMs: 3 })
    const warnings: unknown[][] = []
    const originalWarn = console.warn
    console.warn = (...args: unknown[]) => { warnings.push(args) }
    try {
      await withManifestLock(path, 'anthropic-auth', async () => {
        const ownerPath = join(lockPath, 'owner')
        const parsed = JSON.parse(await readFile(ownerPath, 'utf8')) as Record<string, unknown>
        parsed.claimed_at_ms = Date.now() - 41
        await writeFile(ownerPath, `${JSON.stringify(parsed)}\n`, { mode: 0o600 })
      })
    } finally {
      console.warn = originalWarn
    }

    expect(await stat(lockPath)).toBeDefined()
    expect(warnings.some((args) => args.includes('manifest lock lease lost, not releasing'))).toBe(true)
  })

  lockTest('atomic publication remains owner-only under umask 022', async () => {
    const path = await manifestPath()
    const previous = process.umask(0o022)
    try {
      await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
        file.providers.push(provider('anthropic', 'anthropic-auth'))
      })
    } finally {
      process.umask(previous)
    }
    if (onPosix) expect((await stat(path)).mode & 0o777).toBe(0o600)
    expect(await checkOwnerOnlyPathAsync(path)).toEqual({ ok: true })
    expect((await readHandleFile(path)).providers).toHaveLength(1)
  })

  lockTest('creates a missing manifest parent before claiming its colocated lock', async () => {
    const root = await privateFixtureDirectory('claustrum-manifest-parent-')
    roots.push(root)
    const path = join(root, 'nested', 'opencode-handles.json')

    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })

    if (onPosix) expect((await stat(path)).mode & 0o777).toBe(0o600)
    expect(await checkOwnerOnlyPathAsync(path)).toEqual({ ok: true })
    expect((await readHandleFile(path)).providers).toHaveLength(1)
  })

  test.skipIf(!onPosix)('leaves the mode of a pre-existing benign parent unchanged', async () => {
    const path = await manifestPath()
    const parent = join(path, '..')
    await chmod(parent, 0o755)
    const before = (await stat(parent)).mode & 0o777

    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })

    expect((await stat(parent)).mode & 0o777).toBe(before)
  })

  test.skipIf(!onPosix)('refuses a group-writable manifest parent without changing its mode', async () => {
    const path = await manifestPath()
    const parent = join(path, '..')
    await chmod(parent, 0o770)

    await withSharedAncestorGroup(parent, async () => {
      expect(await throwerOf(writeHandleFileLocked(path, 'anthropic-auth', () => {}))).toThrow('is not private: group-writable ancestor')
    })
    expect((await stat(parent)).mode & 0o777).toBe(0o770)
  })

  test('pins the shared lock constants and renewal bound', () => {
    expect(MANIFEST_LOCK.ttlMs).toBe(30_000)
    expect(MANIFEST_LOCK.renewEveryMs).toBe(10_000)
    expect(MANIFEST_LOCK.ownerKeys).toEqual(['tenant', 'pid', 'claimed_at_ms', 'nonce'])
    for (const [target, accepted] of [
      ['.lock.stale-1-nonce_2', true],
      ['.lock.stale-1-abc.def', true],
      ['.lock.stale-1-AAAA====', true],
      ['.lock.stale-1.bad', false],
      ['.lock.stale-1-a/b', false],
      ['.lock.stale-1-..', false],
      ['.lock.stale-1-a:b', false],
      ['.lock.stale-1-a*b', false],
      ['.lock.stale-1-a?b', false],
      ['.lock.stale-1-a|b', false],
      // Windows aliases trailing dots and spaces, collapsing distinct nonces onto one ABA target.
      ['.lock.stale-1-abc.', false],
      ['.lock.stale-1-abc ', false],
    ] as const) expect(MANIFEST_LOCK.staleTargetRe.test(target)).toBe(accepted)
    expect(MANIFEST_LOCK.renewEveryMs * 3).toBeLessThanOrEqual(MANIFEST_LOCK.ttlMs)
  })

  lockTest('reads a Rust-shaped owner fixture using the shared field contract', async () => {
    const path = await manifestPath()
    setLockOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await owner(path, Date.now() + 1_000, 'opencode-claustrum')
    expect(await throwerOf(withManifestLock(path, 'anthropic-auth', async () => {}))).toThrow('manifest lock busy')
  })

  test.skipIf(!onPosix)('refuses a dangling manifest symlink without replacing it', async () => {
    const path = await manifestPath()
    const target = join(path, '..', 'missing-target.json')
    await symlink(target, path)

    expect(await throwerOf(writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    }))).toThrow('handle file must be a regular file')

    expect((await lstat(path)).isSymbolicLink()).toBe(true)
    expect(await rejectionOf(stat(target))).toMatchObject({ code: 'ENOENT' })
  })

  // POSIX only: stale eviction relies on renaming a lock another process may hold
  // open, which Windows refuses; the lock refuses on Windows (see the test below).
  test.skipIf(!onPosix)('aborts before manifest rename when renewal loses the original lock path', async () => {
    const path = await manifestPath()
    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })
    const before = await readFile(path, 'utf8')
    setLockOptions({
      ttlMs: 100,
      renewEveryMs: 2,
      retryMinMs: 2,
      retryMaxMs: 3,
      beforeManifestRename: async (lockPath: string) => {
        await rename(lockPath, `${lockPath}.vanished`)
        await Bun.sleep(10)
      },
    } as never)

    expect(await throwerOf(writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers[0]!.accounts.push({
        label: 'backup',
        handle: handle('Z'),
        credential_id: 'apikey:anthropic:backup',
      })
    }))).toThrow('manifest lock renewal failed; write aborted')

    expect(await readFile(path, 'utf8')).toBe(before)
  })

  lockTest('pins unparseable owner records without eviction', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    setLockOptions({ ttlMs: 25, renewEveryMs: 8, retryMinMs: 2, retryMaxMs: 3 })
    for (const ownerSource of ['{']) {
      await mkdir(lockPath, { mode: 0o700 })
      if (ownerSource !== undefined) {
        await writeFile(join(lockPath, 'owner'), ownerSource, { mode: 0o600 })
      }

      const error = (await withManifestLock(path, 'anthropic-auth', async () => {}).catch((caught) => caught)) as ManifestLockError & { code: ManifestLockErrorCode }
      expect(error.code).toBe('owner_invalid')
      expect((await lstat(lockPath)).isDirectory()).toBe(true)
      expect((await readdir(join(path, '..'))).some((name) => name.includes('.lock.stale-'))).toBe(false)
      await rm(lockPath, { recursive: true })
    }
  })
})

describe('thrown errors carry a stable code', () => {
  // A tenant classifying "retry later" vs "the artefact is wrong" vs "the write was
  // abandoned" had only the message text to branch on, so any copy-edit here silently
  // reclassified a busy lock as an unknown error. openai-auth asked for this before
  // writing its conformance suite, which is the cheap moment to add it.
  lockTest('a busy lock throws code lock_busy', async () => {
    const path = await manifestPath()
    setLockOptions({ ttlMs: 400, retryMinMs: 5, retryMaxMs: 10 })
    await mkdir(`${path}.lock`, { mode: 0o700 })
    await writeFile(join(`${path}.lock`, 'owner'), `${JSON.stringify({ tenant: 'squatter', pid: 1, claimed_at_ms: Date.now() + 1_000, nonce: 'n'.repeat(22) })}\n`, { mode: 0o600 })
    const error = (await withManifestLock(path, 'probe', async () => {}).catch((e) => e)) as ManifestLockError & { code: ManifestLockErrorCode }
    expect(error.code).toBe('lock_busy')
    expect(MANIFEST_LOCK.errorCodes).toContain('lock_busy')
  })

  lockTest('an unparseable owner is invalid, never evicted, and keeps that code', async () => {
    const path = await manifestPath()
    setLockOptions({ ttlMs: 400, retryMinMs: 5, retryMaxMs: 10 })
    await mkdir(`${path}.lock`, { mode: 0o700 })
    await writeFile(join(`${path}.lock`, 'owner'), 'not json at all\n', { mode: 0o600 })
    const error = (await withManifestLock(path, 'probe', async () => {}).catch((e) => e)) as ManifestLockError & { code: ManifestLockErrorCode }
    expect(error.code).toBe('owner_invalid')
    // the squatter's lock must still be standing: unreadable owner is never evicted
    expect((await stat(`${path}.lock`)).isDirectory()).toBe(true)
    expect((await readFile(join(`${path}.lock`, 'owner'), 'utf8')).trim()).toBe('not json at all')
  })

  lockTest('a throwing callback releases the lock and re-raises the original error unwrapped', async () => {
    const path = await manifestPath()
    class EnrollRefusal extends Error {
      constructor() {
        super('identity mismatch')
        this.name = 'EnrollRefusal'
      }
    }
    const error = await withManifestLock(path, 'probe', async () => {
      throw new EnrollRefusal()
    }).catch((e) => e)
    expect(error).toBeInstanceOf(EnrollRefusal)
    expect((error as Error).message).toBe('identity mismatch')
    expect(await throwerOf(stat(`${path}.lock`))).toThrow()
    // The consumer-visible consequence: the next claimant is not stalled for the 30s
    // TTL. The lock file being gone (asserted above) is the release proof; this checks
    // that a second claim then succeeds. The race only stops a hang and names the
    // property. It does not measure speed: the bound sits well under the TTL so a
    // regressed release still fails here, and well above how long a claim takes on a
    // loaded Windows runner, where a 1s bound once failed with the lock file already
    // removed.
    let deadline: ReturnType<typeof setTimeout> | undefined
    const outcome = await Promise.race([
      withManifestLock(path, 'probe', async () => 'reacquired' as const),
      new Promise<string>((resolve) => {
        deadline = setTimeout(
          () => resolve('lock not released on throw: re-acquire still blocked after 10s'),
          10_000,
        )
      }),
    ]).finally(() => clearTimeout(deadline))
    expect(outcome).toBe('reacquired')
    // The test's own limit sits above the race's, so a hang fails with the message
    // above rather than as bun's unattributed per-test timeout.
  }, 20_000)

  lockTest('distinct manifest paths do not contend', async () => {
    const first = await manifestPath()
    const second = await manifestPath()
    let bothInside = false
    await withManifestLock(first, 'tenant-a', async () => {
      await withManifestLock(second, 'tenant-b', async () => {
        bothInside = true
      })
    })
    expect(bothInside).toBe(true)
  })
})

// The Windows arm of the quarantine sweep, tested WITHOUT pretending a POSIX runner is Windows.
// A filesystem test cannot reach this: on Linux `path.split('/')` and `basename` agree, so the
// defect this guards (a '/' split yielding the whole path on a backslash-separated path, making
// the sweep a silent no-op) passes every filesystem test in this file. Driving the derivation
// with path.win32.basename tests the actual platform claim.
describe('quarantine prefix derivation', () => {
  test('derives prefixes from POSIX and Windows path basenames', () => {
    expect(manifestLockQuarantinePrefix('/home/u/.config/ck/opencode-handles.json', posix.basename)).toBe('opencode-handles.json')
    expect(manifestLockQuarantinePrefix('C:\\Users\\u\\AppData\\ck\\opencode-handles.json', win32.basename)).toBe('opencode-handles.json')
    // The regression itself: a '/' split over a backslash path returns the whole path, so the
    // prefix never matches a bare directory entry and nothing is ever reclaimed.
    const viaSlashSplit = (p: string) => p.split('/').pop() ?? ''
    expect(manifestLockQuarantinePrefix('C:\\Users\\u\\AppData\\ck\\opencode-handles.json', viaSlashSplit))
      .toBe('C:\\Users\\u\\AppData\\ck\\opencode-handles.json')
  })

  test('a basename that yields nothing disables the sweep rather than matching everything', () => {
    expect(manifestLockQuarantinePrefix('/', posix.basename)).toBeUndefined()
    expect(manifestLockQuarantinePrefix('', posix.basename)).toBeUndefined()
  })
})
