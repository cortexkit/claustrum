import {
  SubcCallError,
  SubcClient,
  type BindIdentity,
} from '@cortexkit/subc-client'
import { resolveClaustrumConnectionPath } from './detect.js'
import {
  asCredentialError,
  ClaustrumCredentialError,
  hasCredentialError,
} from './errors.js'
import { storeIdentity } from './identity.js'

const CLAUSTRUM_MODULE_ID = 'claustrum'
const RECONNECT_BACKOFF_MS = 60_000

type ClaustrumTransport = Pick<SubcClient, 'call' | 'close'>

export type ClaustrumConnector = (options: {
  connectionFile: string
  handshakeTimeoutMs?: number
}) => Promise<SubcClient>

export type ClaustrumClientOptions = {
  connectionFile?: string
  handshakeTimeoutMs?: number
  projectRoot?: string
  storagePath?: string
  identity?: BindIdentity
  connector?: ClaustrumConnector
  logger?: (errorClass: string) => void
}

/**
 * Credential material plus optional non-secret identity metadata. Missing wire fields remain
 * `undefined`; a present non-string identity value rejects the response as invalid.
 */
export type ServedCredential = {
  material: string
  recordVersion: number
  expiresAtMs: number | null
  /**
   * Operator-chosen record label for verifying a caller-held binding. It is not a routing key:
   * account-scoped routing joins `accountId` with `recordVersion`.
   */
  credentialId?: string
  /** Non-secret Code Assist project identity, present only for antigravity credentials. */
  projectId?: string
  /**
   * Provider account identity the served token executes under. Account-scoped routing joins this
   * value with `recordVersion`; it is neither the operator's credential label nor the bearer handle.
   */
  accountId?: string
  /** Non-secret account display metadata captured at login. */
  email?: string
  /** Non-secret organization or workspace display metadata captured at login. */
  orgName?: string
}

export type CredentialStatus = {
  ready: boolean
  lastErrorCode: string | null
  leaseHeld: boolean
  recordVersion: number
  stalePending?: boolean
}

export type ClaustrumReporterSource =
  | 'direct'
  | 'relay_status_field'
  | 'relay_message_parse'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asRecordVersion(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined
}

function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === 'string'
}

function decodeCredential(response: unknown, logUnknownClass: (errorClass: string) => void): ServedCredential {
  if (hasCredentialError(response)) throw asCredentialError(response, 'invalid_response', logUnknownClass)
  const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
  const payload = result?.payload
  if (
    !Array.isArray(payload) ||
    payload.length === 0 ||
    !payload.every((value) => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 255)
  ) {
    throw asCredentialError(response, 'invalid_response', logUnknownClass)
  }
  const recordVersion = asRecordVersion(result?.record_version)
  if (recordVersion === undefined) {
    throw asCredentialError(response, 'invalid_record_version', logUnknownClass)
  }
  const rawExpiresAtMs = result?.expires_at_ms
  const expiresAtMs =
    rawExpiresAtMs === undefined || rawExpiresAtMs === null
      ? null
      : typeof rawExpiresAtMs === 'number' && Number.isFinite(rawExpiresAtMs)
        ? rawExpiresAtMs
        : undefined
  if (expiresAtMs === undefined) {
    throw asCredentialError(response, 'invalid_expiry', logUnknownClass)
  }
  const credentialId = result?.credential_id
  const projectId = result?.project_id
  const accountId = result?.account_id
  const email = result?.email
  const orgName = result?.org_name
  if (
    !isOptionalString(credentialId) ||
    !isOptionalString(projectId) ||
    !isOptionalString(accountId) ||
    !isOptionalString(email) ||
    !isOptionalString(orgName)
  ) {
    throw asCredentialError(response, 'invalid_response', logUnknownClass)
  }
  return {
    material: new TextDecoder().decode(Uint8Array.from(payload)),
    recordVersion,
    expiresAtMs,
    credentialId,
    projectId,
    accountId,
    email,
    orgName,
  }
}

function decodeStatus(response: unknown, logUnknownClass: (errorClass: string) => void): CredentialStatus {
  if (hasCredentialError(response)) throw asCredentialError(response, 'invalid_response', logUnknownClass)
  const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
  const recordVersion = asRecordVersion(result?.record_version)
  if (
    typeof result?.ready !== 'boolean' ||
    (result?.last_error_code !== undefined && result?.last_error_code !== null && typeof result?.last_error_code !== 'string') ||
    typeof result?.lease_held !== 'boolean' ||
    recordVersion === undefined ||
    (result?.stale_pending !== undefined && typeof result.stale_pending !== 'boolean')
  ) {
    throw asCredentialError(response, 'invalid_status', logUnknownClass)
  }
  return {
    ready: result.ready,
    lastErrorCode: result.last_error_code ?? null,
    leaseHeld: result.lease_held,
    recordVersion,
    ...(result.stale_pending === undefined ? {} : { stalePending: result.stale_pending }),
  }
}

export class ClaustrumClient {
  #client: ClaustrumTransport
  readonly #connector: ClaustrumConnector
  readonly #connectionFile: string
  readonly #handshakeTimeoutMs?: number
  readonly #identity: BindIdentity
  readonly #logger: (errorClass: string) => void
  #reconnecting: Promise<void> | null = null
  #nextReconnectAt = 0
  #closed = false

  private constructor(
    client: ClaustrumTransport,
    connector: ClaustrumConnector,
    connectionFile: string,
    handshakeTimeoutMs: number | undefined,
    identity: BindIdentity,
    logger: (errorClass: string) => void,
  ) {
    this.#client = client
    this.#connector = connector
    this.#connectionFile = connectionFile
    this.#handshakeTimeoutMs = handshakeTimeoutMs
    this.#identity = identity
    this.#logger = logger
  }

  static async connect(options: ClaustrumClientOptions = {}): Promise<ClaustrumClient> {
    const connectionFile = resolveClaustrumConnectionPath(options.connectionFile)
    const connector = options.connector ?? ((connectOptions) => SubcClient.connect(connectOptions))
    const identity = options.identity ?? storeIdentity(
      options.projectRoot ?? process.cwd(),
      options.storagePath ?? process.cwd(),
    )
    const client = await connector({
      connectionFile,
      handshakeTimeoutMs: options.handshakeTimeoutMs,
    })
    return new ClaustrumClient(
      client,
      connector,
      connectionFile,
      options.handshakeTimeoutMs,
      identity,
      options.logger ?? ((errorClass) => console.warn(errorClass)),
    )
  }

  async getCredential(handle: string, minTtlMs?: number): Promise<ServedCredential> {
    const response = await this.#call('credential.get', {
      handle,
      min_ttl_ms: minTtlMs,
      force_refresh: false,
    })
    return decodeCredential(response, this.#logger)
  }

  async statusCredential(handle: string): Promise<CredentialStatus> {
    const response = await this.#call('credential.status', { handle })
    return decodeStatus(response, this.#logger)
  }

  async reportAuthFailure(input: {
    handle: string
    providerStatus: number
    recordVersion: number
    reporterSource: ClaustrumReporterSource
  }): Promise<void> {
    const response = await this.#call('credential.report_auth_failure', {
      handle: input.handle,
      provider_status: input.providerStatus,
      record_version: input.recordVersion,
      reporter_source: input.reporterSource,
    })
    if (hasCredentialError(response)) throw asCredentialError(response, 'invalid_response', this.#logger)
    const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
    if (result?.accepted !== true) throw asCredentialError(response, 'invalid_response', this.#logger)
  }

  /**
   * Enumerate what this caller's grants cover.
   *
   * `params` is `{}` and must be PRESENT: the vault rejects an absent or null params
   * object, so a caller cannot ask a different question by omitting it.
   */
  async listScoped(enrollmentToken?: string): Promise<readonly ScopedInventoryRow[]> {
    const response = await this.#call(
      'credential.list_scoped',
      enrollmentToken === undefined ? {} : { enrollment_token: enrollmentToken },
    )
    return decodeScopedInventory(response, this.#logger)
  }

  /**
   * Fetch by credential id, authorized by a grant rather than a bearer handle.
   *
   * `minTtlMs` is a DEMAND, not a hint: if a real upstream exchange still cannot satisfy
   * it, the vault refuses with `ttl_unsatisfiable` (class `context_overflow`) rather than
   * serving a token that will die inside the caller's own margin. That class means
   * reduce-and-retry, never wait-and-retry.
   */
  async getScoped(input: {
    credentialId: string
    enrollmentToken?: string
    minTtlMs?: number
  }): Promise<ServedCredential> {
    const response = await this.#call('credential.get_scoped', {
      credential_id: input.credentialId,
      enrollment_token: input.enrollmentToken,
      min_ttl_ms: input.minTtlMs,
    })
    return decodeCredential(response, this.#logger)
  }

  /**
   * Report a served credential dead, addressed by id rather than by handle.
   *
   * VERSION-FENCED: `recordVersion` must be the one this caller was SERVED. A report
   * against a since-refreshed version is accepted and does nothing, which is the point --
   * a stale report must not kill a fresh token. `accepted: true` is the receipt that the
   * report was taken, never evidence that it applied.
   */
  async reportAuthFailureScoped(input: {
    credentialId: string
    enrollmentToken?: string
    providerStatus: number
    recordVersion: number
    reporterSource: ClaustrumReporterSource
  }): Promise<void> {
    const response = await this.#call('credential.report_auth_failure', {
      credential_id: input.credentialId,
      enrollment_token: input.enrollmentToken,
      provider_status: input.providerStatus,
      record_version: input.recordVersion,
      reporter_source: input.reporterSource,
    })
    if (hasCredentialError(response)) throw asCredentialError(response, 'invalid_response', this.#logger)
    const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
    if (result?.accepted !== true) throw asCredentialError(response, 'invalid_response', this.#logger)
  }

  /**
   * Propose an enrollment. The consumer mints `requestSecret` itself and sends only its
   * hash; the raw secret NEVER leaves the process, and it is what authorizes the poll.
   *
   * IDEMPOTENT ON (name, secret): re-proposing with the same secret returns the SAME
   * `requestId`. That exists because `requestId` is minted server-side, so a consumer
   * cannot persist it before proposing -- a crash in that window would otherwise leave it
   * holding a secret it cannot poll with and a name held until TTL. Persist the secret
   * BEFORE calling this, and a crash costs nothing.
   *
   * A different secret on the same name is a different caller and is refused.
   */
  async enrollPropose(input: { name: string; requestSecretHash: string }): Promise<{ requestId: string }> {
    const response = await this.#call('auth.enroll_propose', {
      proposed_name: input.name,
      request_secret_hash: input.requestSecretHash,
    })
    const result = decodeEnrollmentResult(response, this.#logger)
    const requestId = result.request_id
    if (typeof requestId !== 'string' || requestId.length === 0) {
      throw asCredentialError(response, 'invalid_response', this.#logger)
    }
    return { requestId }
  }

  /**
   * Poll a proposal. Returns `pending` until an operator decides, then exactly once
   * returns the token.
   *
   * THE TOKEN IS RETURNED ONCE. Persist it before doing anything else with it; a lost
   * token needs a fresh ceremony, not a second poll.
   */
  async enrollPoll(input: { requestId: string; requestSecret: string }): Promise<EnrollmentPollOutcome> {
    const response = await this.#call('auth.enroll_poll', {
      request_id: input.requestId,
      request_secret: input.requestSecret,
    })
    return decodeEnrollmentPoll(response, this.#logger)
  }

  /** Exchange a live token for its successor. The old token dies when the new one is issued. */
  async enrollRotate(input: { token: string }): Promise<{ token: string; tokenGeneration: number }> {
    const response = await this.#call('auth.enroll_rotate', { token: input.token })
    const result = decodeEnrollmentResult(response, this.#logger)
    const token = result.token
    const generation = result.token_generation
    if (typeof token !== 'string' || token.length === 0 || typeof generation !== 'number') {
      throw asCredentialError(response, 'invalid_response', this.#logger)
    }
    return { token, tokenGeneration: generation }
  }

  close(): void {
    this.#closed = true
    this.#client.close()
  }

  async #call(method: string, params: unknown): Promise<unknown> {
    try {
      return await this.#client.call(CLAUSTRUM_MODULE_ID, method, params, {
        identity: this.#identity,
        consumerIdentity: null,
      })
    } catch (error) {
      if (this.#shouldReconnect(error)) {
        try {
          await this.#reconnect()
        } catch (reconnectError) {
          throw this.#asTransportError(reconnectError)
        }
        try {
          return await this.#client.call(CLAUSTRUM_MODULE_ID, method, params, {
            identity: this.#identity,
            consumerIdentity: null,
          })
        } catch (retryError) {
          throw this.#asTransportError(retryError)
        }
      }
      throw this.#asTransportError(error)
    }
  }

  #asTransportError(error: unknown): ClaustrumCredentialError {
    if (error instanceof ClaustrumCredentialError) return error
    const code = error instanceof SubcCallError && error.code ? error.code : 'transport_error'
    return new ClaustrumCredentialError(code, 'transient', 'retry')
  }

  #shouldReconnect(error: unknown): boolean {
    return (
      !this.#closed &&
      error instanceof SubcCallError &&
      error.kind === 'terminal' &&
      error.code !== 'missing_identity' &&
      error.code !== 'invalid_control_body'
    )
  }

  async #reconnect(): Promise<void> {
    if (this.#closed) throw new Error('Claustrum client is closed')
    if (this.#reconnecting) {
      await this.#reconnecting
      return
    }
    const now = Date.now()
    if (now < this.#nextReconnectAt) throw new Error('Claustrum client reconnect is backed off')
    this.#nextReconnectAt = now + RECONNECT_BACKOFF_MS
    this.#reconnecting = this.#connector({
      connectionFile: this.#connectionFile,
      handshakeTimeoutMs: this.#handshakeTimeoutMs,
    })
      .then((client) => {
        if (this.#closed) {
          client.close()
          throw new Error('Claustrum client is closed')
        }
        const previous = this.#client
        this.#client = client
        previous.close()
      })
      .finally(() => {
        this.#reconnecting = null
      })
    await this.#reconnecting
  }
}

/**
 * A row from the caller's own grant-covered inventory.
 *
 * `serves` is the ROUTING AXIS, not the id spelling. `apikey:openrouter` and
 * `antigravity:google` both serve Anthropic models and contain no "anthropic"
 * anywhere in their ids, so a consumer that filters on the id segment silently
 * drops working accounts. Measured on a live vault: 8 Anthropic-capable rows, 3 of
 * them invisible to an id-substring filter.
 */
export interface ScopedInventoryRow {
  readonly id: string
  readonly categories: readonly string[]
  readonly credentialType: string
  readonly serves: readonly string[]
  /**
   * Which provider protocol this credential speaks. Absent for static keys.
   *
   * SELECT ON THIS, NOT ON `serves`, WHEN THE TOKEN GOES TO A PROVIDER'S OWN ENDPOINTS.
   * Measured on a live vault: eight rows serve Anthropic models and only five are Claude
   * OAuth -- openrouter, antigravity and cursor reach Anthropic models through their own
   * APIs. The id spelling does not separate them either: two contain no "anthropic" at
   * all, and `credentialType === 'oauth'` catches antigravity and cursor too.
   */
  readonly refreshAdapter?: string
  readonly state: string
  readonly recordVersion: number
  readonly operations: readonly string[]
  readonly createdAtMs: number | null
  readonly accountId?: string
  readonly email?: string
  readonly orgName?: string
}

function decodeScopedInventory(
  response: unknown,
  logUnknownClass: (errorClass: string) => void,
): readonly ScopedInventoryRow[] {
  if (hasCredentialError(response)) throw asCredentialError(response, 'invalid_response', logUnknownClass)
  const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
  const rows = result?.credentials
  if (!Array.isArray(rows)) throw asCredentialError(response, 'invalid_response', logUnknownClass)
  return rows.map((row) => {
    if (!isRecord(row)) throw asCredentialError(response, 'invalid_response', logUnknownClass)
    const recordVersion = asRecordVersion(row.record_version)
    if (recordVersion === undefined) {
      throw asCredentialError(response, 'invalid_record_version', logUnknownClass)
    }
    const strings = (value: unknown): readonly string[] => {
      if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
        throw asCredentialError(response, 'invalid_response', logUnknownClass)
      }
      return value
    }
    // THE FIELD IS `id`, NOT `credential_id`. `get` and `status` echo `credential_id`
    // for binding verification; an inventory row IS the credential, so it does not name
    // the concept twice. Reading the wrong key yields undefined for every row and says
    // nothing about why -- which is exactly what it did to my own probe.
    if (typeof row.id !== 'string' || typeof row.credential_type !== 'string' || typeof row.state !== 'string') {
      throw asCredentialError(response, 'invalid_response', logUnknownClass)
    }
    const createdAtMs =
      row.created_at_ms === undefined || row.created_at_ms === null
        ? null
        : typeof row.created_at_ms === 'number' && Number.isFinite(row.created_at_ms)
          ? row.created_at_ms
          : undefined
    if (createdAtMs === undefined) throw asCredentialError(response, 'invalid_response', logUnknownClass)
    if (!isOptionalString(row.refresh_adapter)) {
      throw asCredentialError(response, 'invalid_response', logUnknownClass)
    }
    if (!isOptionalString(row.account_id) || !isOptionalString(row.email) || !isOptionalString(row.org_name)) {
      throw asCredentialError(response, 'invalid_response', logUnknownClass)
    }
    return {
      id: row.id,
      categories: strings(row.categories),
      credentialType: row.credential_type,
      serves: strings(row.serves),
      state: row.state,
      refreshAdapter: row.refresh_adapter,
      recordVersion,
      operations: strings(row.operations),
      createdAtMs,
      accountId: row.account_id,
      email: row.email,
      orgName: row.org_name,
    }
  })
}

/** What a poll found. `pending` is not an error: the operator has not decided yet. */
export type EnrollmentPollOutcome =
  | { readonly status: 'pending' }
  | { readonly status: 'approved'; readonly name: string; readonly token: string; readonly tokenGeneration: number }
  | { readonly status: 'denied' }

function decodeEnrollmentResult(
  response: unknown,
  logUnknownClass: (errorClass: string) => void,
): Record<string, unknown> {
  if (hasCredentialError(response)) throw asCredentialError(response, 'invalid_response', logUnknownClass)
  const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
  if (result === undefined) throw asCredentialError(response, 'invalid_response', logUnknownClass)
  return result
}

function decodeEnrollmentPoll(
  response: unknown,
  logUnknownClass: (errorClass: string) => void,
): EnrollmentPollOutcome {
  const result = decodeEnrollmentResult(response, logUnknownClass)
  const status = result.status
  if (status === 'pending') return { status: 'pending' }
  if (status === 'denied') return { status: 'denied' }
  if (status !== 'approved') throw asCredentialError(response, 'invalid_response', logUnknownClass)
  const { name, token, token_generation: generation } = result
  if (
    typeof name !== 'string' ||
    typeof token !== 'string' ||
    token.length === 0 ||
    typeof generation !== 'number' ||
    !Number.isInteger(generation)
  ) {
    throw asCredentialError(response, 'invalid_response', logUnknownClass)
  }
  return { status: 'approved', name, token, tokenGeneration: generation }
}
