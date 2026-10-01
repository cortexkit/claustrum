import { afterEach, describe, expect, test } from 'bun:test'
import { chmod, mkdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  credentialIdMatchesProvider,
  HANDLE_FILE_CONTRACT,
  defaultHandleFilePath,
  handleFileRevision,
  parseHandleFile,
  readHandleFile,
  type OpenCodeHandleFileV1,
} from '../handles.js'
import { writeHandleFileLocked } from '../manifest-lock.js'

// POSIX ONLY, DELIBERATELY. The contract these tests assert -- mode exactly 0600, a
// non-world-writable parent, no symlink -- is a POSIX permission model. Windows has no
// such mode: node reports a synthesised value there, so `writeFile(..., {mode: 0o600})`
// produces a file the reader rejects, and even the VALID case fails.
//
// Skipped rather than weakened. Relaxing the reader on Windows would silently drop the
// custody guarantee on that platform; asserting a different mode there would assert a
// property of node's emulation rather than of the file. The honest state is that the
// handle-file contract is unimplemented on Windows -- tracked, not hidden, and the skip
// is what keeps it visible in the run output rather than passing vacuously.
const posix = process.platform !== 'win32'

// os.tmpdir(), not a hardcoded '/tmp'. Windows has no /tmp, so the literal would create a
// stray directory at the drive root -- a fourth instance of the same defect this repo has
// hit in Rust fixtures, in TS fixtures, and in a review worktree.
const root = join(tmpdir(), 'claustrum-client-handles-tests')
const handle = `ckh_${'a'.repeat(43)}`

afterEach(() => rm(root, { recursive: true, force: true }))

function validFile(): OpenCodeHandleFileV1 {
  return { version: 1, providers: [{ provider: 'deepseek', shape: 'api', serve: 'opencode-claustrum', accounts: [{ label: 'main', handle, credential_id: 'apikey:deepseek:main' }] }] }
}

describe('client handle-file contract', () => {
  test('exports the pinned resolver and contract constants', () => {
    expect(defaultHandleFilePath({ CLAUSTRUM_OPENCODE_HANDLES: '/tmp/custom.json' })).toBe('/tmp/custom.json')
    expect(HANDLE_FILE_CONTRACT.maxBytes).toBe(262144)
    expect(HANDLE_FILE_CONTRACT.mode).toBe(0o600)
    expect(HANDLE_FILE_CONTRACT.labelRe.test('main.account-1')).toBe(true)
    expect(HANDLE_FILE_CONTRACT.handleRe.test(handle)).toBe(true)
  })

  test.skipIf(!posix)('reads a valid owned 0600 manifest and computes its revision', async () => {
    await mkdir(root, { recursive: true, mode: 0o700 })
    const path = join(root, 'handles.json')
    await writeFile(path, `${JSON.stringify(validFile())}\n`, { mode: 0o600 })
    expect(await readHandleFile(path)).toEqual(validFile())
    expect(await handleFileRevision(path)).toMatch(/^\d+(\.\d+)?:\w{64}$/)
  })

  test.skipIf(!posix)('rejects insecure mode and world-writable parents', async () => {
    await mkdir(root, { recursive: true, mode: 0o777 })
    const path = join(root, 'handles.json')
    await writeFile(path, JSON.stringify(validFile()), { mode: 0o600 })
    await chmod(root, 0o777)
    await expect(readHandleFile(path)).rejects.toThrow('world-writable without sticky bit')
    await chmod(root, 0o700)
    await chmod(path, 0o640)
    await expect(readHandleFile(path)).rejects.toThrow('exactly 0600')
  })

  // A GROUP-WRITABLE PARENT IS REFUSED, NOT ONLY A WORLD-WRITABLE ONE.
  //
  // Directory write permission governs unlink and create, so anyone who can write the
  // parent replaces a mode-0600 file wholesale regardless of the file's own mode. The
  // owner check does not close it: a directory the user owns can still be 0770.
  //
  // Separate from the world-writable test on purpose. The refusal message contains the
  // substring 'world-writable' either way, so that test passes unchanged whether or not
  // the group bit is examined -- it cannot discriminate this behaviour, and a reader
  // would reasonably assume it does.
  test.skipIf(!posix)('rejects a group-writable parent even though the file is 0600', async () => {
    await mkdir(root, { recursive: true, mode: 0o700 })
    const path = join(root, 'handles.json')
    await writeFile(path, JSON.stringify(validFile()), { mode: 0o600 })
    await chmod(root, 0o770)
    await expect(readHandleFile(path)).rejects.toThrow('group- or world-writable')
    // The same directory without the group bit reads cleanly -- proving the refusal came
    // from that bit and not from something else about the fixture.
    await chmod(root, 0o700)
    expect(await readHandleFile(path)).toEqual(validFile())
  })

  // AN ANCESTOR IS REFUSED, NOT ONLY THE IMMEDIATE PARENT.
  //
  // A locked-down leaf under a permissive grandparent PASSES the immediate-parent check,
  // which is exactly what makes it the discriminating fixture: anyone who can create and
  // unlink in the grandparent renames the chain aside and substitutes their own.
  //
  // The control arm matters more than usual here. These fixtures live under /tmp, which is
  // 1777 -- so the walk reaches a group- AND world-writable directory on every single run,
  // and without the sticky exemption this test would fail for a reason that has nothing to
  // do with the bit it sets.
  test.skipIf(!posix)('rejects a group-writable ancestor even when the parent is 0700', async () => {
    const leaf = join(root, 'mid', 'leaf')
    await mkdir(leaf, { recursive: true, mode: 0o700 })
    await chmod(join(root, 'mid'), 0o700)
    await chmod(root, 0o700)
    const path = join(leaf, 'handles.json')
    await writeFile(path, JSON.stringify(validFile()), { mode: 0o600 })

    expect(await readHandleFile(path)).toEqual(validFile())

    await chmod(root, 0o770)
    await expect(readHandleFile(path)).rejects.toThrow('ancestor')
    await chmod(root, 0o700)
  })

  test('rejects invalid labels, handles, prototype keys, and oversized input', async () => {
    expect(() => parseHandleFile({ version: 1, providers: [{ ...validFile().providers[0], accounts: [{ ...validFile().providers[0].accounts[0], label: '__proto__' }] }] })).toThrow('invalid account label')
    expect(() => parseHandleFile({ version: 1, providers: [{ ...validFile().providers[0], accounts: [{ ...validFile().providers[0].accounts[0], handle: 'ckh_short' }] }] })).toThrow('invalid handle')
    await mkdir(root, { recursive: true, mode: 0o700 })
    const path = join(root, 'handles.json')
    await writeFile(path, 'x'.repeat(262145), { mode: 0o600 })
    await expect(readHandleFile(path)).rejects.toThrow('exceeds 256 KiB')
  })

  test('rejects invalid account minTtlMs values', () => {
    const provider = validFile().providers[0]
    for (const minTtlMs of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '100', null]) {
      const account = { ...provider.accounts[0], minTtlMs }
      expect(() => parseHandleFile({ version: 1, providers: [{ ...provider, accounts: [account] }] })).toThrow(
        'provider 0 account main has invalid minTtlMs',
      )
    }
  })

  test('preserves an explicit zero minTtlMs floor', () => {
    const provider = validFile().providers[0]
    const account = { ...provider.accounts[0], minTtlMs: 0 }
    expect(parseHandleFile({ version: 1, providers: [{ ...provider, accounts: [account] }] }).providers[0].accounts[0]).toEqual(account)
  })

  test('accepts omitted and distinct finite account minTtlMs floors', () => {
    const provider = validFile().providers[0]
    const second = { ...provider.accounts[0], label: 'backup', handle: `ckh_${'b'.repeat(43)}`, minTtlMs: 120000 }
    const parsed = parseHandleFile({ version: 1, providers: [{ ...provider, accounts: [provider.accounts[0], second] }] })
    expect(parsed.providers[0].accounts[0]).toEqual(provider.accounts[0])
    expect(parsed.providers[0].accounts[1]).toEqual(second)
  })

  test('preserves unknown account keys through the account spread', () => {
    const provider = validFile().providers[0]
    const account = { ...provider.accounts[0], tenant_extra: { region: 'eu' } }
    expect(parseHandleFile({ version: 1, providers: [{ ...provider, accounts: [account] }] }).providers[0].accounts[0]).toEqual(account)
  })

  test('preserves account keys it does not name in foreign provider blocks', async () => {
    await mkdir(root, { recursive: true, mode: 0o700 })
    const path = join(root, 'handles.json')
    const provider = validFile().providers[0]
    const own = { ...provider, provider: 'anthropic', shape: 'oauth' as const, serve: 'anthropic-auth', accounts: [{ ...provider.accounts[0], credential_id: 'oauth:anthropic:main' }] }
    const foreign = { ...provider, provider: 'xai', serve: 'opencode-claustrum', accounts: [{ ...provider.accounts[0], handle: `ckh_${'b'.repeat(43)}`, credential_id: 'apikey:xai:main', minTtlMs: 300000, tenant_routing: { region: 'eu', weights: { primary: 3, fallback: 1 } } }] }
    await writeFile(path, `${JSON.stringify({ version: 1, providers: [own, foreign] })}\n`, { mode: 0o600 })
    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers = file.providers.map((entry) => entry.serve === 'anthropic-auth'
        ? { ...entry, accounts: [...entry.accounts, { label: 'fallback', handle: `ckh_${'c'.repeat(43)}`, credential_id: 'oauth:anthropic:fallback' }] }
        : entry)
    })
    const after = await readHandleFile(path)
    expect(after.providers[0].accounts).toHaveLength(2)
    expect(after.providers[1]).toEqual(foreign)
    const preserved = after.providers[1].accounts[0] as Record<string, unknown>
    expect(preserved.label).toBe('main')
    expect(preserved.handle).toBe(`ckh_${'b'.repeat(43)}`)
    expect(preserved.credential_id).toBe('apikey:xai:main')
    expect(preserved.minTtlMs).toBe(300000)
    expect(preserved.tenant_routing).toEqual({ region: 'eu', weights: { primary: 3, fallback: 1 } })
  })

  test('matches credential IDs by provider segment without restricting kinds', () => {
    for (const value of ['oauth:xai', 'oauth:xai:work', 'chatgpt:openai', 'apikey:deepseek:main']) {
      expect(credentialIdMatchesProvider(value, value.split(':')[1])).toBe(true)
    }
    for (const value of ['oauth:openai', ':xai', 'oauth:xai:', 'oauth::xai', '', 3, null]) {
      expect(credentialIdMatchesProvider(value, 'xai')).toBe(false)
    }
  })

  test('preserves the historical parser fixture outcomes and exact messages', () => {
    const provider = validFile().providers[0]
    const account = provider.accounts[0]
    const fixtures: Array<[unknown, string]> = [
      [null, 'handle file must be an object'],
      [{ version: 2, providers: [] }, 'handle file must have version 1 and providers'],
      [{ version: 1, providers: [null] }, 'provider 0 must be an object'],
      [{ version: 1, providers: [{ ...provider, provider: '__proto__' }] }, 'provider 0 has invalid provider'],
      [{ version: 1, providers: [provider, provider] }, 'provider 1 duplicates provider deepseek'],
      [{ version: 1, providers: [{ ...provider, shape: 'other' }] }, 'provider 0 has invalid shape'],
      [{ version: 1, providers: [{ ...provider, serve: '' }] }, 'provider 0 requires serve'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, credential_id: 3 }] }] }, 'provider 0 has invalid accounts'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, label: '__proto__' }] }] }, 'provider 0 has an invalid account label'],
      [{ version: 1, providers: [{ ...provider, accounts: [account, account] }] }, 'provider 0 duplicates account label main'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, handle: 'ckh_short' }] }] }, 'provider 0 account main has invalid handle'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, credential_id: '' }] }] }, 'provider 0 account main has invalid credential id'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, superseded: ['ckh_short'] }] }] }, 'provider 0 account main has invalid superseded handle'],
    ]
    for (const [fixture, message] of fixtures) expect(() => parseHandleFile(fixture)).toThrow(message)
  })

  test('preserves historical reader validation order and normalized failures', async () => {
    const source = JSON.stringify(validFile())
    const regular = { isFile: () => true, mode: 0o100600, uid: 1000, size: source.length }
    const parent = { isFile: () => false, isDirectory: () => true, mode: 0o040755, uid: 1000 }
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      lstat: async () => regular,
      stat: async () => { throw new Error('parent denied') },
      readFile: async () => source,
    })).rejects.toThrow('cannot stat handle file parent: parent denied')
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      lstat: async () => regular,
      stat: async () => parent,
      readFile: async () => { throw new Error('read denied') },
    })).rejects.toThrow('cannot read handle file: read denied')
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      lstat: async () => ({ ...regular, mode: 0o100640, uid: 1001 }),
      stat: async () => { throw new Error('must not reach parent') },
      readFile: async () => { throw new Error('must not read') },
    })).rejects.toThrow('handle file mode must be exactly 0600')
  })

  test.skipIf(!posix)('preserves the historical symlink and grow-after-fstat fixture outcomes', async () => {
    await mkdir(root, { recursive: true, mode: 0o700 })
    const target = join(root, 'target.json')
    const link = join(root, 'handles.json')
    await writeFile(target, JSON.stringify(validFile()), { mode: 0o600 })
    await symlink(target, link)
    await expect(readHandleFile(link)).rejects.toThrow('handle file must not be a symlink')

    const chunk = Buffer.alloc(HANDLE_FILE_CONTRACT.maxBytes + 2, 0x78)
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      stat: async () => ({ isFile: () => false, isDirectory: () => true, mode: 0o040755, uid: 1000 }),
      open: async () => ({
        stat: async () => ({ isFile: () => true, mode: 0o100600, uid: 1000, size: 256 }),
        readFile: async () => chunk.toString('utf8'),
        read: (buffer, offset, length, position) => {
          const remaining = chunk.length - position
          if (remaining <= 0) return { bytesRead: 0 }
          const slice = chunk.subarray(position, position + Math.min(length, remaining))
          buffer.set(slice, offset)
          return { bytesRead: slice.length }
        },
        close: async () => {},
      }),
    })).rejects.toThrow('handle file exceeds 256 KiB')
  })

})
