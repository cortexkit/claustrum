export {
  detectClaustrumConnection,
  getDefaultClaustrumConnectionPath,
  resolveClaustrumConnectionPath,
  type ClaustrumDetection,
  type ClaustrumEndpoint,
} from './detect.js'
export { storeIdentity, storageFingerprint } from './identity.js'
export {
  enrollmentSecretHash,
  newEnrollmentSecret,
  writeEnrollmentTokenFile,
  type EnrollmentTokenFile,
} from './enrollment.js'
export {
  ClaustrumCredentialError,
  credentialErrorAction,
  ERROR_CLASS_WIRE_SET,
  type ClaustrumCredentialErrorAction,
  type ClaustrumCredentialErrorClass,
} from './errors.js'
export {
  ClaustrumClient,
  type ActivePolicy,
  type ClaustrumClientOptions,
  type ClaustrumConnector,
  type ClaustrumReporterSource,
  type CredentialStatus,
  type EnrollmentPollOutcome,
  type PolicyToken,
  type PolicyTokenRequest,
  type ScopedGrantTuple,
  type ScopedInventory,
  type ScopedInventoryRow,
  type ServedCredential,
  type ServedCredentialBytes,
} from './wire.js'
export {
  ScopedWatchError,
  type PolicyWatch,
  type PolicyWatchNotice,
  type ScopedWatch,
  type ScopedWatchNotice,
  type ScopedWatchOptions,
  type ScopedWatchOutcome,
} from './watch.js'
