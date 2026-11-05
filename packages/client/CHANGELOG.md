# Changelog

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
