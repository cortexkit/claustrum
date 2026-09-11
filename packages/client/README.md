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
  a public dependency it cannot resolve; a compiled binary does not. All readings below
  are bun 1.3.14, same module, no `node_modules` — a toolchain behaviour with no version
  attached reads as permanent, and this one is a moving target by construction.

  ```
  bun run m.mjs / bun -e     resolves   with or without a package.json in scope,
                                        from any cwd, on a cold install cache
  bun build --compile        error: Could not resolve: "X". Maybe you need to
    (static import)                     "bun install"?  -- NO BINARY PRODUCED
  bun build --compile        builds; fails in the consumer's process at import:
    (dynamic import of a               ERR_MODULE_NOT_FOUND Cannot find package 'X'
     disk module)
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
