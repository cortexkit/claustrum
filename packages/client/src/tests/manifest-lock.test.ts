import { afterEach, describe, expect, test } from 'bun:test'
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'

import {
  __setManifestLockTestOptions,
  MANIFEST_LOCK,
  withManifestLock,
  writeHandleFileLocked,
} from '../manifest-lock'
import type { ManifestLockError, ManifestLockErrorCode } from '../index'

const roots: string[] = []
const handle = (letter: string) => `ckh_${letter.repeat(43)}`
const sleep = async (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

async function manifestPath(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'claustrum-manifest-lock-'))
  roots.push(root)
  return join(root, 'opencode-handles.json')
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
  await mkdir(lockPath, { mode: 0o700 })
  await writeFile(join(lockPath, 'owner'), `${JSON.stringify({
    tenant,
    pid: 41,
    claimed_at_ms: claimedAtMs,
    nonce: '0123456789abcdef0123456789abcdef',
  })}\n`, { mode: 0o600 })
  await chmod(join(lockPath, 'owner'), 0o600)
}

afterEach(async () => {
  __setManifestLockTestOptions()
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('manifest writer lock', () => {
  test('two concurrent tenant writers preserve both provider blocks', async () => {
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

  test('stale owner is evicted by rename and retained as a quarantine directory', async () => {
    const path = await manifestPath()
    await owner(path, Date.now() - MANIFEST_LOCK.ttlMs - 1)

    await withManifestLock(path, 'anthropic-auth', async () => {})

    const suffixes = (await readdir(join(path, '..')))
      .filter((name) => name.startsWith(`${basename(path)}.lock.stale-`))
      .map((name) => name.slice(basename(path).length))
    expect(suffixes).toHaveLength(1)
    expect(MANIFEST_LOCK.staleTargetRe.test(suffixes[0]!)).toBe(true)
  })

  test('owner that becomes stale during the retry window is evicted', async () => {
    const path = await manifestPath()
    __setManifestLockTestOptions({ ttlMs: 80, renewEveryMs: 1_000, retryMinMs: 2, retryMaxMs: 3 })
    await owner(path, Date.now() - 30)

    await withManifestLock(path, 'anthropic-auth', async () => {})

    const suffixes = (await readdir(join(path, '..'))).filter((name) => name.startsWith(`${basename(path)}.lock.stale-`))
    expect(suffixes).toHaveLength(1)
  })

  test('owner nonce containing a path traversal is invalid and never renamed', async () => {
    for (const nonce of ['../escape', 'a/b', 'a:b', 'a*b', 'a?b', 'a|b']) {
      const path = await manifestPath()
      const lockPath = `${path}.lock`
      __setManifestLockTestOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
      await mkdir(lockPath, { mode: 0o700 })
      await writeFile(join(lockPath, 'owner'), `${JSON.stringify({ tenant: 'squatter', pid: 41, claimed_at_ms: Date.now() - 31, nonce })}\n`, { mode: 0o600 })

      const error = (await withManifestLock(path, 'anthropic-auth', async () => {}).catch((caught) => caught)) as Error & { code?: string }

      expect(error.code).toBe('owner_invalid')
      expect((await stat(lockPath)).isDirectory()).toBe(true)
      expect((await readdir(join(path, '..'))).some((name) => name.includes('.lock.stale-'))).toBe(false)
      await expect(stat(join(path, '..', 'escape'))).rejects.toMatchObject({ code: 'ENOENT' })
    }
  })

  test('path-safe unfamiliar nonce alphabets remain evictable', async () => {
    for (const nonce of ['abc.def', 'AAAA====']) {
      const path = await manifestPath()
      const lockPath = `${path}.lock`
      __setManifestLockTestOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
      await mkdir(lockPath, { mode: 0o700 })
      await writeFile(join(lockPath, 'owner'), `${JSON.stringify({ tenant: 'newer-writer', pid: 41, claimed_at_ms: Date.now() - 31, nonce })}\n`, { mode: 0o600 })

      await withManifestLock(path, 'anthropic-auth', async () => {})

      expect((await readdir(join(path, '..'))).some((name) => name.startsWith(`${basename(path)}.lock.stale-`))).toBe(true)
    }
  })

  test('unknown owner keys are busy while fresh and evictable once stale', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    __setManifestLockTestOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await mkdir(lockPath, { mode: 0o700 })
    const record = { tenant: 'newer-writer', pid: 41, claimed_at_ms: Date.now() + 1_000, nonce: 'newer_writer_nonce', generation: 2 }
    await writeFile(join(lockPath, 'owner'), `${JSON.stringify(record)}\n`, { mode: 0o600 })

    const freshError = (await withManifestLock(path, 'anthropic-auth', async () => {}).catch((caught) => caught)) as Error & { code?: string }
    expect(freshError.code).toBe('lock_busy')

    record.claimed_at_ms = Date.now() - 31
    await writeFile(join(lockPath, 'owner'), `${JSON.stringify(record)}\n`, { mode: 0o600 })
    await withManifestLock(path, 'anthropic-auth', async () => {})
    expect((await readdir(join(path, '..'))).some((name) => name.startsWith(`${basename(path)}.lock.stale-`))).toBe(true)
  })

  test('malformed diagnostic owner fields do not prevent stale eviction', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    __setManifestLockTestOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await mkdir(lockPath, { mode: 0o700 })
    await writeFile(join(lockPath, 'owner'), `${JSON.stringify({ tenant: 41, pid: 'unknown', claimed_at_ms: Date.now() - 31, nonce: 'valid_nonce' })}\n`, { mode: 0o600 })

    await withManifestLock(path, 'anthropic-auth', async () => {})

    expect((await readdir(join(path, '..'))).some((name) => name.startsWith(`${basename(path)}.lock.stale-`))).toBe(true)
  })

  test('renewing owner fails loudly after the bounded retry window', async () => {
    const path = await manifestPath()
    __setManifestLockTestOptions({ ttlMs: 40, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await owner(path, Date.now())

    const started = Date.now()
    const renewal = setInterval(async () => {
      const ownerPath = join(`${path}.lock`, 'owner')
      const current = JSON.parse(await readFile(ownerPath, 'utf8')) as Record<string, unknown>
      current.claimed_at_ms = Date.now()
      await writeFile(ownerPath, `${JSON.stringify(current)}\n`, { mode: 0o600 })
    }, 5)
    try {
      await expect(withManifestLock(path, 'anthropic-auth', async () => {})).rejects.toThrow('manifest lock busy')
      expect(Date.now() - started).toBeGreaterThanOrEqual(35)
    } finally { clearInterval(renewal) }
  })

  test('owner file exists while held and disappears with the lock after release', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`

    await withManifestLock(path, 'anthropic-auth', async () => {
      const parsed = JSON.parse(await readFile(join(lockPath, 'owner'), 'utf8')) as Record<string, unknown>
      expect(Object.keys(parsed).sort()).toEqual([...MANIFEST_LOCK.ownerKeys].sort())
      expect(parsed.tenant).toBe('anthropic-auth')
    })

    await expect(stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test('two stale evictors produce one eviction winner and never overlap holders', async () => {
    const path = await manifestPath()
    await owner(path, Date.now() - MANIFEST_LOCK.ttlMs - 1)
    let waiting = 0
    const bothReady = Promise.withResolvers<void>()
    let evictionWins = 0
    __setManifestLockTestOptions({
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

  test('an evictor that observed stale owner cannot rename a replacement lock', async () => {
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

    __setManifestLockTestOptions({
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

    await expect(stat(`${path}.lock`)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test('an expired holder does not release its directory and logs the lost lease', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    __setManifestLockTestOptions({ ttlMs: 40, renewEveryMs: 1_000, retryMinMs: 2, retryMaxMs: 3 })
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

    await expect(stat(lockPath)).resolves.toBeDefined()
    expect(warnings.some((args) => args.includes('manifest lock lease lost, not releasing'))).toBe(true)
  })

  test('atomic publication remains 0600 under umask 022', async () => {
    const path = await manifestPath()
    const previous = process.umask(0o022)
    try {
      await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
        file.providers.push(provider('anthropic', 'anthropic-auth'))
      })
    } finally {
      process.umask(previous)
    }
    expect((await stat(path)).mode & 0o777).toBe(0o600)
  })

  test('creates a missing manifest parent before claiming its colocated lock', async () => {
    const root = await mkdtemp(join(tmpdir(), 'claustrum-manifest-parent-'))
    roots.push(root)
    const path = join(root, 'nested', 'opencode-handles.json')

    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })

    expect((await stat(path)).mode & 0o777).toBe(0o600)
  })

  test('leaves the mode of a pre-existing benign parent unchanged', async () => {
    const path = await manifestPath()
    const parent = join(path, '..')
    await chmod(parent, 0o755)
    const before = (await stat(parent)).mode & 0o777

    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })

    expect((await stat(parent)).mode & 0o777).toBe(before)
  })

  test('refuses a group-writable manifest parent without changing its mode', async () => {
    const path = await manifestPath()
    const parent = join(path, '..')
    await chmod(parent, 0o770)

    await expect(writeHandleFileLocked(path, 'anthropic-auth', () => {})).rejects.toThrow('handle file parent must not be group- or other-writable')
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

  test('reads a Rust-shaped owner fixture using the shared field contract', async () => {
    const path = await manifestPath()
    __setManifestLockTestOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await owner(path, Date.now() + 1_000, 'opencode-claustrum')
    await expect(withManifestLock(path, 'anthropic-auth', async () => {})).rejects.toThrow('manifest lock busy')
  })

  test('refuses a dangling manifest symlink without replacing it', async () => {
    const path = await manifestPath()
    const target = join(path, '..', 'missing-target.json')
    await symlink(target, path)

    await expect(writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })).rejects.toThrow('handle file must be a regular file')

    expect((await lstat(path)).isSymbolicLink()).toBe(true)
    await expect(stat(target)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test('aborts before manifest rename when renewal loses the original lock path', async () => {
    const path = await manifestPath()
    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })
    const before = await readFile(path, 'utf8')
    __setManifestLockTestOptions({
      ttlMs: 100,
      renewEveryMs: 2,
      retryMinMs: 2,
      retryMaxMs: 3,
      beforeManifestRename: async (lockPath: string) => {
        await rename(lockPath, `${lockPath}.vanished`)
        await Bun.sleep(10)
      },
    } as never)

    await expect(writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers[0]!.accounts.push({
        label: 'backup',
        handle: handle('Z'),
        credential_id: 'apikey:anthropic:backup',
      })
    })).rejects.toThrow('manifest lock renewal failed; write aborted')

    expect(await readFile(path, 'utf8')).toBe(before)
  })

  test('pins missing and unparseable owner records without eviction', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    __setManifestLockTestOptions({ ttlMs: 25, renewEveryMs: 8, retryMinMs: 2, retryMaxMs: 3 })
    for (const ownerSource of [undefined, '{']) {
      await mkdir(lockPath, { mode: 0o700 })
      if (ownerSource !== undefined) {
        await writeFile(join(lockPath, 'owner'), ownerSource, { mode: 0o600 })
      }

      const error = (await withManifestLock(path, 'anthropic-auth', async () => {}).catch((caught) => caught)) as Error & { code?: string }
      expect(error.code).toBe(ownerSource === undefined ? 'lock_busy' : 'owner_invalid')
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
  test('a busy lock throws code lock_busy', async () => {
    const path = await manifestPath()
    __setManifestLockTestOptions({ ttlMs: 400, retryMinMs: 5, retryMaxMs: 10 })
    await mkdir(`${path}.lock`, { mode: 0o700 })
    await writeFile(join(`${path}.lock`, 'owner'), `${JSON.stringify({ tenant: 'squatter', pid: 1, claimed_at_ms: Date.now() + 1_000, nonce: 'n'.repeat(22) })}\n`, { mode: 0o600 })
    const error = (await withManifestLock(path, 'probe', async () => {}).catch((e) => e)) as Error & { code?: string }
    expect(error.code).toBe('lock_busy')
    expect(MANIFEST_LOCK.errorCodes).toContain('lock_busy')
  })

  test('the package entrypoint exports the lock error types', () => {
    const classify = (error: ManifestLockError): ManifestLockErrorCode => error.code
    expect(classify(Object.assign(new Error('busy'), { code: 'lock_busy' as const }))).toBe('lock_busy')
  })

  test('an unparseable owner is invalid, never evicted, and keeps that code', async () => {
    const path = await manifestPath()
    __setManifestLockTestOptions({ ttlMs: 400, retryMinMs: 5, retryMaxMs: 10 })
    await mkdir(`${path}.lock`, { mode: 0o700 })
    await writeFile(join(`${path}.lock`, 'owner'), 'not json at all\n', { mode: 0o600 })
    const error = (await withManifestLock(path, 'probe', async () => {}).catch((e) => e)) as Error & { code?: string }
    expect(error.code).toBe('owner_invalid')
    // the squatter's lock must still be standing: unreadable owner is never evicted
    expect((await stat(`${path}.lock`)).isDirectory()).toBe(true)
    expect((await readFile(join(`${path}.lock`, 'owner'), 'utf8')).trim()).toBe('not json at all')
  })

  test('a throwing callback releases the lock and re-raises the original error unwrapped', async () => {
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
    await expect(stat(`${path}.lock`)).rejects.toThrow()
    // The consumer-visible consequence: the next claimant is not stalled for a TTL.
    // Bounded by a race rather than by awaiting and measuring afterwards -- if release
    // regressed, the await itself would block for the full 30s TTL and the suite would
    // report a timeout with no attribution, which is indistinguishable from a slow box
    // or a hang anywhere else. Failing fast with the property named beats hanging.
    const started = Date.now()
    const outcome = await Promise.race([
      withManifestLock(path, 'probe', async () => 'reacquired' as const),
      sleep(1_000).then(() => 'lock not released on throw: re-acquire exceeded 1000ms' as const),
    ])
    expect(outcome).toBe('reacquired')
    expect(Date.now() - started).toBeLessThan(1_000)
  })

  test('distinct manifest paths do not contend', async () => {
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
