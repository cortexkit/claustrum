# Changelog

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
