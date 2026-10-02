import { readdirSync, statSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir, userInfo } from 'node:os'
import { join } from 'node:path'
import {
  PROTOCOL_VERSION,
  readConnectionFile,
  type Endpoint as SubcEndpoint,
} from '@cortexkit/subc-client'

export type ClaustrumEndpoint = SubcEndpoint

export type ClaustrumDetection =
  | {
      status: 'available'
      schema: number
      wireVersion: number
      endpoints: ClaustrumEndpoint[]
    }
  | { status: 'absent'; path: string }
  | { status: 'malformed'; path: string; reason: string }

const PRODUCTION_FILE_NAME = 'subc-connection.json'
const TEMP_PREFIX = 'subc-'
const TEMP_SUFFIX = '.connection.json'

// Keep discovery in the CLI's order: exclusive SUBC_CONNECTION_FILE, runtime,
// HOME, exact per-user temp name, then an unambiguous temp glob. The glob supports
// daemons whose token derivation differs without guessing between other users.
function homeTierPath(): string | undefined {
  const homeEnv = process.env.HOME
  return homeEnv ? join(homeEnv, '.local', 'share', 'cortexkit', 'run', PRODUCTION_FILE_NAME) : undefined
}

function highestPriorityAbsentMarker(): string {
  const runtime = process.env.XDG_RUNTIME_DIR
  if (runtime) return join(runtime, PRODUCTION_FILE_NAME)
  const home = homeTierPath()
  if (home) return home
  // HOME unset — the Rust tier falls through to the tempdir glob with no fixed path.
  // Surface the os-reported home so `detectClaustrumConnection` returns an `absent`
  // path the operator can fix; without this, the caller gets a misleading `./...` path.
  return join(userInfo().homedir, '.local', 'share', 'cortexkit', 'run', PRODUCTION_FILE_NAME)
}

function findExistingConnectionPath(): string | undefined {
  if (process.env.SUBC_CONNECTION_FILE) return process.env.SUBC_CONNECTION_FILE
  const runtime = process.env.XDG_RUNTIME_DIR
  if (runtime) {
    const p = join(runtime, PRODUCTION_FILE_NAME)
    if (safeIsFile(p)) return p
  }
  const home = homeTierPath()
  if (home && safeIsFile(home)) return home
  const exact = join(tmpdir(), `${TEMP_PREFIX}${userConnectionToken()}${TEMP_SUFFIX}`)
  if (safeIsFile(exact)) return exact
  const matches = listSubcConnectionFiles(tmpdir())
  // A single matching file IS the daemon; multiple matches mean different OS users
  // happened to share the temp dir. Picking one would route credential-bearing
  // requests at another user's daemon, so REFUSE both picks and the absent path.
  return matches.length === 1 ? matches[0] : undefined
}

export function userConnectionToken(getuid: (() => number) | null = process.getuid ?? null, env: NodeJS.ProcessEnv = process.env): string {
  if (getuid) return String(getuid())
  for (const key of ['USER', 'USERNAME', 'HOME', 'USERPROFILE']) {
    const value = env[key]
    if (value) return Array.from(value, (character) => /^[a-zA-Z0-9_-]$/.test(character) ? character : '_').join('')
  }
  return 'unknown'
}

export function getDefaultClaustrumConnectionPath(): string {
  return findExistingConnectionPath() ?? highestPriorityAbsentMarker()
}

export function resolveClaustrumConnectionPath(explicit?: string): string {
  return (
    explicit?.trim() ||
    process.env.SUBC_CONNECTION_FILE ||
    process.env.CLAUSTRUM_SUBC_CONNECTION?.trim() ||
    getDefaultClaustrumConnectionPath()
  )
}

function safeIsFile(path: string): boolean {
  try {
    return statSync(path).isFile()
  } catch {
    return false
  }
}

function listSubcConnectionFiles(dir: string): string[] {
  let entries: string[]
  try {
    entries = readdirSync(dir) as string[]
  } catch {
    return []
  }
  const matches: string[] = []
  for (const name of entries) {
    if (typeof name !== 'string') continue
    if (!name.startsWith(TEMP_PREFIX) || !name.endsWith(TEMP_SUFFIX)) continue
    const candidate = join(dir, name)
    if (safeIsFile(candidate)) matches.push(candidate)
  }
  matches.sort()
  return matches
}

// The transport's typed reader validates `wire_version` against PROTOCOL_VERSION but does
// not currently surface the value. Read it from the raw JSON so detection reports what the
// daemon actually advertised, with the PROTOCOL_VERSION fallback for legacy files that
// omitted the additive field.
async function readAdvertisedWireVersion(path: string): Promise<number | undefined> {
  let raw: string
  try {
    raw = await readFile(path, 'utf8')
  } catch {
    return undefined
  }
  try {
    const parsed = JSON.parse(raw) as { wire_version?: unknown }
    return typeof parsed.wire_version === 'number' ? parsed.wire_version : undefined
  } catch {
    return undefined
  }
}

export async function detectClaustrumConnection(
  explicitPath?: string,
): Promise<ClaustrumDetection> {
  const path = resolveClaustrumConnectionPath(explicitPath)
  let value: Awaited<ReturnType<typeof readConnectionFile>>
  try {
    value = await readConnectionFile(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { status: 'absent', path }
    }
    return {
      status: 'malformed',
      path,
      reason: 'connection file could not be read or validated',
    }
  }

  const advertised = await readAdvertisedWireVersion(path)
  return {
    status: 'available',
    schema: value.schema,
    wireVersion: advertised ?? PROTOCOL_VERSION,
    endpoints: value.endpoints,
  }
}
