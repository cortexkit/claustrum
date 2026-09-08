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
  by design (the vault cannot enumerate which). Treat it as gone either way: re-run
  `ck auth migrate-opencode` to mint a fresh handle; the prior record, if any, is kept.
• `auth_required` means the record is latched and needs reauthentication.
• Unknown server error classes are bounded to `transient`; callers must retry them
  rather than treating a forward-compatible class as permanent.

The client sends `consumerIdentity: null` for every managed request so inherited
`SUBC_MODULE_ID` and `SUBC_LAUNCH_NONCE` cannot impersonate a supervising host.

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
  a public dependency it cannot resolve, needing only a `package.json` in scope; a
  compiled binary does not. Measured on the same module, same directory, no
  `node_modules`: compiled loader gives `ERR_MODULE_NOT_FOUND`, `bun -e` resolves. Since
  consumers of a credential client are daemons and plugins, exercise resolution under a
  compiled loader (`bun build --compile`) or the real host.

The shape is the same in all three: the producing machine supplies the thing under test.
A passing check on it is evidence only when the ambient supply is removed first.
