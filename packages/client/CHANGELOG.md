# Changelog

## 0.20.0

Unpublished until the vault runs database step 44; release still requires owner approval.

- `listScoped` exposes optional `planTierSinceMs`, the operator-supplied effective
  start of a plan. Consumers use it when present and fall back to
  `planTierObservedAtMs` otherwise. Present values must be non-negative integers.

## 0.19.0

Unpublished: release awaits owner approval after the gateway-capable vault is live.

- `listScoped` accepts `gateway` as the fifth `authMethod` value. Other unknown
  values still refuse rather than silently dropping a row.
- `getScoped` and `getScopedBytes` expose optional `baseUrl` and `headers` gateway
  settings. A present `base_url` must be a string and `headers` a string-to-string
  object; null and malformed values refuse. Older vaults and ordinary credentials
  may omit both fields. `hosts` preserves bracketed IPv6 loopback strings.

## 0.18.0

- `enrollPropose` takes an optional `requestedGrants`: up to four `read` or `list`
  grants, each on one exact credential id or one category, for example
  `{ selector: { category: 'llm-provider' }, operation: 'read' }`. The person sees
  them when approving the program, and one approval applies them, with no separate
  grant step. Re-proposing keeps the first request's list; it cannot widen it. It
  needs a vault built from claustrum commit b720df20 or later, the build that added
  one-step plugin approval. An older vault refuses the field as
  `invalid_params`, and the client never drops it for you: retry without it only if
  that is what you want, since malformed grants are refused with the same code.
- `listScoped` rows may carry `provider` (the vault's service name for the key, not
  a routing provider id), `incarnation` (changes when a credential id is re-created,
  so an old login is never mistaken for a new one under the same id) and
  `planTierObservedAtMs` (when the current plan tier was first seen). Each is absent
  when the vault does not send it.

## 0.17.0

- `enrollPropose` takes an optional `displayName`, a name the person sees and
  approves for the program (for example "Claude sign-in for Pi"). It is sent as
  `display_name` only when given. It needs claustrum 94b5c9a6 or newer; an older
  vault refuses the field as `invalid_params`, so omit it there. The vault refuses
  a name that is empty, longer than 40 characters, or contains control,
  bidirectional or zero-width characters, rather than shortening it.

## 0.16.0

- Export `newEnrollmentSecret()` to mint a 32-byte request secret and its
  decoded-byte SHA-256 hash, and `enrollmentSecretHash()` to hash a persisted
  secret while enforcing exactly 64 lowercase hex characters.
- Require `@cortexkit/subc-client` ^0.24.0 for negotiated FIFO request/watch
  windows and deadline-bounded retries of daemon-origin `route_busy` refusals.
  Older daemons retain the SDK's previous behavior. The client adds no busy retry.
- Raise the `@cortexkit/store` minimum to ^0.2.3.

## 0.15.0

### Breaking changes

Removed the OpenCode handle-file API, which was only used by the deleted
OpenCode custody plugin. The replacement `claustrum-auth` OpenCode/Pi plugin uses
enrollment instead and does not use this API.

Removed public exports:

- `defaultHandleFilePath`
- `readHandleFile`
- `handleFileRevision`
- `parseHandleFile`
- `HandleFileValidationError`
- `HANDLE_FILE_CONTRACT`
- `credentialIdMatchesProvider`
- `identifierIsValid`
- `HandleAccount`
- `HandleFileIo`
- `HandleProvider`
- `OpenCodeHandleFileV1`
- `writeHandleFileLocked`
- `withManifestLock`
- `manifestLockQuarantinePrefix`
- `MANIFEST_LOCK`
- `ManifestHandleAccount`
- `ManifestHandleFile`
- `ManifestHandleProvider`
- `ManifestLockError`
- `ManifestLockErrorCode`

The handle-file modules and their implementation factory `createManifestLock`
have also been removed. Transport, scoped operations, byte APIs, enrollment,
and credential error APIs are unchanged.
