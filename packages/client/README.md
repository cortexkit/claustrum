# @cortexkit/claustrum-client

Policy-free TypeScript transport for the Claustrum credential vault. Consumers own
credential caching, refresh, account scheduling, and retry policy.

## Wire contract callers depend on

• The daemon records a durable anomaly alarm after 64 fetches in 60 seconds or
  16 distinct handles on one connection. It still serves those requests. Timed-out
  gets count, and the detector resets on reconnect. Use one warm attempt per
  account per tick and apply per-handle backoff after transient failures.
• `credential.get` is bimodal: resident records return in microseconds, while an
  expiry-skew refresh can take seconds. Request paths should peek cached state,
  not call `get` speculatively.
• `permanent` with `not_found` means the handle is unknown OR revoked — uniform refusal
  by design (the vault cannot enumerate which). Treat it as gone either way; the
  prior record, if any, is kept.
• `auth_required` means the record is latched and needs reauthentication.
• `statusCredential` on an unknown or revoked handle RESOLVES, it does not throw: it
  returns `ready: false, lastErrorCode: 'not_found'` with `recordVersion`, `credentialId`
  and `stalePending` absent. Since 0.5.0 `CredentialStatus.recordVersion` is optional for
  that reason; handle `undefined` rather than defaulting it to a number, which would read
  as a version older than every real one.
• Unknown server error classes are bounded to `transient`; callers must retry them
  rather than treating a forward-compatible class as permanent.
• **Changed in 0.13.0:** a transport `Error` frame whose answer no retry or reconnect
  can change is reported as `permanent` with action `gone`, and the client no longer
  reconnects for it: `unknown_method`, `invalid_params`, `invalid_request`,
  `flow_scopes_unsupported`, `invalid_control_body`, `unknown_module`, and the SDK's
  pre-send `missing_identity`. These are not verdicts about a credential: do not mark
  anything gone or needing re-authentication on them; stop retrying and surface the
  code. `unknown_method` from a vault means the vault predates that operation (for
  example an enrollment op against a vault older than the enrollment ceremony):
  update the vault. `watchScoped` is the exception: there `unknown_method` resolves
  `closed` as `unsupported`, the signal to fall back to polling `listScoped`. Before 0.13.0 these were `transient`/`retry`. Every other
  transport failure is still `transient`/`retry`.
• Since 0.13.0, when a terminal transport failure makes the client reconnect and the
  reconnect or the retried call then fails, the error carries the ORIGINAL call's code
  and class. Earlier versions threw the reconnect's error instead, usually
  `transport_error`, hiding the original call's code.
• `listScoped` rows always carry `providerIds` (a required field since 0.6.0, so code
  that builds rows by hand, such as test fixtures, must set it). An empty array means
  no provider ids are set. Since 0.6.2 a daemon too old to send the field decodes the
  same way, so a newer client still lists against an older daemon. `authMethod` stays
  optional.
• Since 0.10.0 `listScoped` also returns `grants` (how many grants the caller holds)
  and `grantTuples` (`{ selectorKind, selector, operation }` per grant). They tell two
  empty listings apart: `rows: []` with `grants === 0` means the caller has no grant;
  `rows: []` with `grants > 0` means it holds a grant that currently reaches no
  credential, usually a category no credential carries yet (the operator's fix is
  `ck auth set-category`, or `ck auth reclassify --from-registry` for credentials created
  before categories existed). Both are `undefined` against a vault too old to send
  them; treat that as unknown, not as zero. A present but malformed value refuses the
  reply like any other malformed field.

The client sends `consumerIdentity: null` for every managed request so inherited
`SUBC_MODULE_ID` and `SUBC_LAUNCH_NONCE` cannot impersonate a supervising host.

**Changed in 0.11.0:** the client depends on `@cortexkit/subc-client` ^0.22.0 (was
^0.16.0). A host that also uses subc-client must move to the 0.22 line, so both share one
copy. One behaviour reaches callers: while the vault is restarting or refusing route
opens as retryable, a call now keeps retrying for up to 90 s (paced, with jitter) instead
of 30 s. Give every vault call on a latency-sensitive path its own timeout.

## Watching for changes

Since 0.12.0, `client.watchScoped(onNotice, { enrollmentToken? })` holds an
`auth.watch_scoped` request on a dedicated route. It returns `{ stop(), closed }`.
`stop()` is idempotent and resolves `closed` as `{ kind: 'stopped' }`. Notices have
exactly `{ kind: 'changed', epoch, seq, view, keys }`; malformed notices reject
`closed` with `ScopedWatchError` (`code: 'invalid_notice'`). Callback exceptions
also reject it (`callback_failed`); async callbacks must handle their own rejection.
Sequence gaps and new epochs are delivered, not silently filtered.

**The caller owns reconnecting and re-subscribing.** Read `listScoped` on connect.
On every notice, re-read if `view` differs from the last listing actually read,
`epoch` is new, or `seq` skipped. Notices are sheddable hints, not an event journal.
`keys` matters only to consumers that announce vault-held public keys: re-read
those keys when that digest changes, independently of the inventory view.

`@cortexkit/subc-client` 0.22 reports Response (including refusal) and STREAM_END
frames as the same successful subscription close, without the Response body.
Every accepted vault watch immediately sends notice seq 1, so the client uses
whether any notices arrived to interpret that ambiguous close:

| `closed` outcome | Caller action |
| --- | --- |
| `ended` (closed after notices) | Re-read and re-subscribe once for this close. A mid-watch revocation may take this extra round trip to discover. |
| `refused`, with the existing typed credential `error` | Stop. Never reconnect for that refusal. |
| `not_accepting` | Zero notices, then one successful `listScoped` confirmation. The vault may be draining: wait for reconnect or a caller-chosen delay, not a tight re-subscribe loop. |
| `transport_lost`, with the original SDK `error` (including `route_closed`) | Reconnect, re-read, then re-watch. |
| `unsupported` (`unknown_method`) | Fall back to polling `listScoped`. |

A zero-notice close performs exactly one `listScoped` using the same enrollment
token: its refusal becomes `refused`, its success becomes `not_accepting`. There is
no automatic retry or reconnection in that confirmation read. Malformed replies
reject `closed` with `ScopedWatchError('invalid_response')`.

```ts
let client = await ClaustrumClient.connect(connectionOptions)
for (;;) {
  let lastView = (await client.listScoped(token)).view // read on every connect/reopen
  let epoch: string | undefined
  let seq = 0
  let reads = Promise.resolve()
  let readError: unknown
  const watch = client.watchScoped((notice) => {
    const discontinuity = notice.epoch !== epoch || notice.seq !== seq + 1
    epoch = notice.epoch
    seq = notice.seq
    reads = reads.then(async () => {
      if (discontinuity || notice.view !== lastView) {
        const listing = await client.listScoped(token)
        lastView = listing.view // acknowledge the digest actually read, not the hint
        useInventory(listing)
      }
    }).catch((error) => { readError = error; watch.stop() })
    // Key-announcing callers separately compare notice.keys and re-read held keys.
  }, { enrollmentToken: token })
  let outcome
  try { outcome = await watch.closed; await reads; if (readError) throw readError }
  catch (error) { watch.stop(); throw error } // malformed notice/read/callback failure
  if (outcome.kind === 'ended') continue // one new watch per close, never hidden retries
  if (outcome.kind === 'transport_lost') {
    client.close()
    client = await ClaustrumClient.connect(connectionOptions)
    continue
  }
  if (outcome.kind === 'not_accepting') { await callerBackoff(); continue }
  if (outcome.kind === 'unsupported') await pollScopedInventory(client, token)
  break // refused or explicitly stopped
}
```

## OpenCode handle-file exports

`defaultHandleFilePath`, `readHandleFile`, `handleFileRevision`, and `parseHandleFile`
are exported for tenant plugins consuming the OpenCode handle manifest. The shared
`HANDLE_FILE_CONTRACT` is pinned to `maxBytes: 262144`, `mode: 0o600`,
`labelRe: /^[a-z0-9][a-z0-9._-]{0,63}$/`, and `handleRe: /^ckh_[A-Za-z0-9_-]{43}$/`.

### Private files and Windows support

Enrollment tokens support Windows as well as Unix. Reading a handle manifest works on
Windows; writing one does not: the manifest lock's stale-lock eviction renames a lock
another process may hold open, which Windows refuses, so `withManifestLock` and
`writeHandleFileLocked` reject on Windows with code `unsupported_platform` rather than
risk two writers overlapping. The client uses `@cortexkit/store` 0.2.1 or newer: exclusive private creation
protects files before any secret bytes are written, and atomic replacement keeps
that protection. Unix files use mode 0600 and new directories use 0700. On Windows,
the store's `@cortexkit/private-files` native module creates owner-only ACLs and the
async path check verifies real security descriptors, not Node's emulated mode bits
or an AppData-location heuristic. Existing directories are checked, not silently
repaired. Unsupported filesystems or unavailable native modules refuse the operation.
Windows requires supported local, ACL-persisting drives; UNC/network paths and
reparse points are refused. Windows ACL enforcement can only be qualified in CI,
not by passing Unix tests locally.

**Changed in 0.9.0:** Unix ancestors must now be owned by the current effective user
or root. A foreign-owned ancestor is refused even at mode 0755; a non-root-owned
sticky ancestor is also refused. Put the files under a folder you own. Root-owned
sticky directories such as `/tmp` remain usable when the immediate child is your
own non-group/world-writable directory. The Debian user-private-group exception is
preserved: an owned, non-sticky group-writable directory (including a 0775
`~/.config` under umask 0002) is accepted only when local `/etc/passwd` and
`/etc/group` prove the effective group contains no other users.

## Testing a consumer of this client

Three things on a developer box silently satisfy what a consumer's test is trying to
prove. Each was found by a consumer shipping green and failing elsewhere.

• **A connection file at the default path is a host fact, not a fixture.** If the vault
  runs on the machine, `detectClaustrumConnection` finds it whether or not a test set it
  up, so a suite can pass on the daemon's real socket and fail anywhere without one.
  Force it absent (`CLAUSTRUM_SUBC_CONNECTION=/nonexistent/x.json`, and clear
  `XDG_RUNTIME_DIR`) and prove the suite still passes.
• **Tests default into the operator's live config.** A suite that resolves
  `~/.config/opencode` without an override writes lock files and manifests beside real
  credentials — passing locally, and mutating state no CI runner has.
• **A bare `bun` run is not an oracle for module resolution.** The Bun CLI auto-installs
  a public dependency it cannot resolve; a compiled binary does not. All readings below
  are bun 1.3.14, same module, no `node_modules` — a toolchain behaviour with no version
  attached reads as permanent, and this one is a moving target by construction.

  ```
  bun run m.mjs / bun -e
      resolves, with or without a package.json in scope, from any cwd,
      on a cold install cache

  bun build --compile, static import
      error: Could not resolve: "X". Maybe you need to "bun install"?
      NO BINARY PRODUCED

  bun build --compile, dynamic import of a disk module
      builds; fails in the consumer's process at import:
      ERR_MODULE_NOT_FOUND Cannot find package 'X'
  ```

  Both compiled shapes matter and they fail at opposite ends. A bare dependency the
  compiler can see is refused early and loudly, before any artifact exists. One it cannot
  see — a plugin or a path-imported client loaded at runtime — survives the build and
  fails at import inside the host, which is exactly where a credential client cannot
  afford to fail. Since this client's consumers are daemons and plugins, exercise
  resolution under a compiled loader or the real host, never a bare CLI run.

  On macOS, sign the compiled probe (`codesign --force --sign -`) before trusting its
  result: a freshly linked unsigned binary is SIGKILLed, and `rc=137` with empty stderr
  reads as a resolution failure while being a signature one.

The shape is the same in all three: the producing machine supplies the thing under test.
A passing check on it is evidence only when the ambient supply is removed first.
