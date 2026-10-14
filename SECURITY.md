# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**
(<https://github.com/cortexkit/claustrum/security/advisories/new>). Do not open a public issue,
pull request or discussion for a suspected vulnerability.

Include what you found, the commit or release it affects, and the steps or a proof of concept
that reproduces it. A report that would require testing against someone else's vault or
provider account is not needed and not wanted; a local reproduction with a test vault is enough.

## What claustrum defends

claustrum is a local credential vault. Its threat model assumes the machine's kernel and the
user's login session are not compromised, and defends against the following.

- **Credential substitution.** A local process that can reach the supervisor's connection file
  must not be able to replace a credential another consumer uses. Every write requires a
  per-operation MAC keyed from the master key over the exact operation bytes, with a single-use
  nonce, or the offline lease with the master key; writes are create-only unless the caller
  asks to replace, and every write is recorded in the audit chain.
- **Silent loss or staleness across crashes.** A crash, power loss or lease handover during an
  OAuth refresh must not silently brick a credential or serve a token of unknown validity. An
  interrupted refresh resolves to `needs_reauth`, never to a silently dead token.
- **One bad record taking down the vault.** A corrupt record or a locked key store fails closed
  with a typed error and is quarantined alone; the vault keeps serving every other credential.
- **Impersonating the vault.** Only the process the supervisor spawned, echoing its launch
  nonce, can register as the `claustrum` module.
- **Offline disclosure.** Each record is encrypted with XChaCha20-Poly1305 under a master key
  held in the OS key store or an operator key file outside the data directory, and bound to its
  id and version so it cannot be relocated or rolled back. A backup of the data directory does
  not contain the master key.
- **Enumeration.** An unknown and a revoked handle, and an unknown and an ungranted credential
  id, produce identical replies.
- **Undetected tampering with history.** The audit chain is HMAC-linked, so an interior edit,
  reorder or insert fails verification.

How each of these is implemented, and the test that proves it, is in
[the architecture](docs/architecture.md).

## What it does not defend against

Stated plainly, so nobody relies on a property the vault does not have.

- **A determined process running as the same user.** It can read a consumer's `0600` handle
  file and fetch that credential, invoke the OS key store the way the vault does, or drive the
  vault's own binaries. Process hardening (non-dumpable on Linux, a restricted process DACL on
  Windows, the hardened runtime on macOS) blocks memory reads and debugger attachment from
  same-user processes, but a process with root or `SeDebugPrivilege` still gets in. The vault
  makes same-user reads detectable (fetch-rate alarms, `auth_events`), rate-limited and
  revocable per handle; it does not make them impossible.
- **A capability handle is a bearer token.** Whoever holds it can read the credential it names
  until it is revoked. The vault cannot tell a legitimate holder from a thief.
- **Truncation of the audit chain.** Deleting the newest entries leaves a shorter chain that
  still verifies. Detecting it needs an external witness recording the chain tip the daemon
  publishes in its health snapshot (`auditSeq`, `auditTipMac`); the vault does not run one.
- **Copies outside the vault.** Backups of consumer handle files and enrollment tokens, and old
  copies of a provider's own token files, are outside the vault's control. A whole-store restore
  brings back every handle that was live in the snapshot, including ones revoked since.
- **Provider-side behaviour.** The vault cannot tell whether a provider will still honour a
  credential until someone spends it, and it cannot interpret what a provider's refusal status
  means beyond 401 and 403.
- **Portability.** A vault is bound to one machine's key store or key file. Moving it means
  moving the master key separately.

Operator guidance for each of these is in [the operator runbook](docs/operator-runbook.md).
