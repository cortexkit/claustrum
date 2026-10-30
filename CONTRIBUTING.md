# Contributing to claustrum

claustrum is a security boundary: it holds every credential the CortexKit fleet uses. Changes
are reviewed for what they do to custody, not only for whether tests pass.

## Agree the design first

Behaviour changes need an issue that a maintainer has labelled `design-approved` before the
pull request can be reviewed or merged. The `Design gate` workflow enforces this: put
`Approved issue: #<number>` (or `Refs #<number>`) in the pull request description, as the
[pull request template](.github/pull_request_template.md) shows. A maintainer can label a pull
request `trivial` instead when there is genuinely no design to agree. The design conversation
comes first because in a credential vault the expensive mistakes are in the shape of a change,
and a finished implementation is hard to argue with.

## The gate

```sh
./scripts/gate.sh
```

The gate checks your working tree, including uncommitted edits. Format, script contracts
and repository scans run locally first and fail fast without building test binaries. Then
one Linux job (`ck motor run`, 8 vCPUs) runs clippy, workspace tests, real-daemon e2e,
crash cuts, migration/release compatibility and release-artifact/picker assertions. The
Linux job runs concurrently with a native Windows job (`ck motor run --platform windows`)
and local Bun install/typecheck/hermetic tests. Windows shares its command list with
CI (`scripts/windows-ci.sh`): repository scans, formatting, both clippy feature sets,
workspace tests, native Credential Manager round trips, transport-free client and
feature-gated operator/crash-cut
tests. Windows Bun install/build/typecheck and package tests currently run only in GitHub
CI; the full-gate Windows runner reports all four as UNCHECKED because its offline Bun
cache is not yet available. On macOS, the default-feature release `ck-auth` build is also
placed on that machine.
Local lanes start only after **both** remote jobs print `job_id=`, so local writes cannot
invalidate a snapshot in progress. Apart from that macOS artifact build, no cargo check,
clippy or test runs on the host. Every arm reports its duration, and arms with a test-count floor also
report their counts; the final table includes lane wall times and the slowest arms. Run
it before every push.

It needs:

- the local Rust formatting toolchain, Bun and Python 3, plus access to `ck motor run`;
  the Linux runner needs Rust and Python; the Windows runner needs native Windows
  Rust with working clippy/rustfmt, Bun 1.x on PATH, Python 3, PowerShell and Git
  Bash (including `timeout`). Setup reports the installed versions, accepts Bun
  1.4.x as well as CI's 1.3.x, and never downloads or installs tools;
- a checkout of [`subconscious`](https://github.com/cortexkit/subconscious) beside this
  repository (or `CRED_SUBCONSCIOUS_ROOT` pointing at one), for the real-daemon end-to-end
  tests and the inbound-contract check.

The `subconscious` supervisor checkout is passed to both runners with `--sibling`.
Windows only copies its inbound-contract document; it does not build the supervisor.
For Windows, the caller's supervisor path is only a snapshot input: the worker receives
the relative path from the workspace to that sibling. The runner mirrors both caller
paths under the same root, so this also resolves siblings outside a worktree's parent.
Windows disables MSYS argument path conversion before native Python starts and for the
shared Bash lane's children. Linux keeps its existing sibling-path handoff. These paths
and fast-check's diff-selected files/crates travel as arguments rather than environment
variables the runner may filter. A supervisor path absent inside the job fails before
copying or building anything.
Remote workers use writable scratch trees because checks and the supervisor build must
not write into the runner's staged inputs. Linux copies both checkouts with dirty content
and history; its clones use command-scoped Git trust for each exact source `.git` path,
never global trust. Windows snapshots contain plain files without `.git`: its worker
copies those files, excluding build output and host-only Git pointers, without cloning.
Git-dependent Windows checks report UNCHECKED with a reason when metadata is unavailable;
CI's Windows checkout still runs them when Git metadata is present. Build output uses
the runner's writable `target` caches. Runner refusal/unreachability, unknown
outcome, timeout, cancellation and bad arguments all fail the gate; a successful exit
without test counts or a completion receipt also fails. There is no local-build fallback.
Runner failures include the last `ck motor run:` stderr diagnostic in the final failure
line (or explicitly say none was printed), while retaining the full output in the log.

The gate asserts a minimum passed-test count for each suite, so a suite that silently stops
running fails the gate instead of passing quietly. `cargo test --workspace` on its own is not
the gate: the real-daemon tests are `#[ignore]` by default and skip unless
`CRED_REQUIRE_DAEMON=1` is set, and the crash-cut suites compile to nothing without their
feature flags, printing `running 0 tests ... ok`. Read the counts, not the word `ok`.

A green gate covers Linux and native Windows checks, plus the selected host artifact.
The native-store integration tests exercise Linux Secret Service, not macOS Keychain;
they report UNCHECKED if D-Bus/gnome-keyring is absent. The GNU Windows cross-check is
also UNCHECKED unless its Rust target and MinGW compiler are installed on the runner.
Windows-only native/ACL/filesystem checks run on Windows, not a cross-compilation substitute.
GitHub supplies its own checkout/tool setup and may populate dependency caches.
Only the Linux job requests network access. Windows build-server jobs are offline by design:
Cargo uses the image's registry built from the committed lockfile. The four Windows Bun
steps are UNCHECKED with the reason "Windows jobs have no offline Bun cache yet; GitHub CI
runs these". Once offline Windows jobs have cached bun.lock packages, flip
`WINDOWS_MOTOR_HAS_OFFLINE_BUN_CACHE=1` in `scripts/windows-ci.sh` to enable them with frozen,
offline install; no other switch is needed. Missing required tools or Cargo cache entries
still fail rather than fetching.
The inbound-contract check reads the sibling document, never a URL.
Signing/hardened runtime and deployed binary
acceptance remain separate release-builder/operator checks.

`./scripts/fast-check.sh [--base <ref>]` follows the same scheduling rule: local format
and conditional script contracts first, then one Linux job for diff-scoped clippy/tests
and the always-on Rust wire/migration checks, in parallel with local TypeScript checks.
Scope is resolved before submission and passed explicitly, so dirty edits cannot vanish
when the runner makes its writable copy. Fast-check still omits the full gate's
feature-gated lint and crash-cut checks, e2e, native stores, native Windows and release-artifact checks.
Both commands
print summaries on failure too; an UNCHECKED arm is never presented as a passed arm.

Individual arms you can run without the sibling checkout:

```sh
python3 -m unittest discover -s scripts/tests
python3 scripts/check-doc-status.py
python3 scripts/threshold-controls.py
python3 scripts/endpoint-hosts.py
cargo test --workspace --locked --features credentials-core/test-support
bun run build && bun test packages
```

## Where code goes

| change | where |
|---|---|
| custody logic: records, the store and its migrations, encryption, master key, refresh, audit | `crates/credentials-core/src/` |
| a provider refresh adapter | `crates/credentials-core/src/refresh_adapters/`, with recorded HTTP fixtures; update the adapter count in [`docs/architecture.md`](docs/architecture.md) |
| a provider host or URL | the source constant, then `python3 scripts/endpoint-hosts.py --update` and review the diff of `docs/endpoint-hosts.txt` |
| a cryptographic domain separator | do not change one: existing vaults would stop opening. A new one is recorded in `docs/domain-separators.txt` by the same `--update` |
| a threshold constant (a cap, ceiling or limit) | name its boundary test in `docs/threshold-controls.txt`; `scripts/threshold-controls.py` refuses an unrecorded one |
| read-surface and admin-surface operations | `crates/credentials-module/src/read_surface.rs`, `admin_surface.rs`, wired in `main.rs`; document wire changes in [`docs/wire-contract-v1.md`](docs/wire-contract-v1.md) |
| an operator verb | `crates/credentials-module/src/bin/credentials_cli.rs` and `src/bin/cli_support/`; document it in [`docs/operator-runbook.md`](docs/operator-runbook.md) |
| a new audit op, alarm reason or auth-event kind | the enum in `crates/credentials-core/src/audit.rs`, and its row in the operator runbook's vocabulary tables (tests enforce this) |
| client decoders | `crates/claustrum-client` and `packages/client`, tested against the producer's fixtures |

Public docs in `docs/` describe the code as it is now. Design history, measurements and
incident notes do not belong there.

A bug fix ships with a test that fails without the fix.

### Development executable names

`ck-*` names are reserved for production binaries under `~/.local/share/cortexkit/bin/` and
`~/.local/share/cortexkit/staging/` (`ck` itself lives in `~/.local/bin`). Tests, rigs and
build-artifact smoke checks run artifacts under `ckdev-*` names: Rust tests use
`cortexkit_test_support::{ckdev_binary, dev_command}`, and shell scripts use
`scripts/lib/ckdev-binary.sh`. Both make a copy, never a hard link: a fresh hard link to cargo's
binary can be killed at exec on a loaded macOS host. `scripts/check-ckdev-execution.py` enforces
this in the gate and CI. The [execution audit](scripts/ckdev-execution-audit.md) records every
site.

## Committing

- One logical change per commit, with the code, its tests and its docs together.
- Subject line `<area>: <what changed>`, in the imperative, for example
  `login: route every device-only provider to the device flow`. The body says why.
- Comments explain the reason in plain language for a reader with no context. Do not reference
  ticket numbers or review labels in code comments.
- If a change makes an existing test fail, do not rewrite the test to match without saying why
  in the commit message: that test was a claim that a property mattered.
- Never commit credential material, master keys or vault databases. `.gitignore` excludes
  `*.key`, `store.db` and `*.vault`; keep it that way.

## Reviewing a contributor's branch

A squashed commit whose tree was built on an older base silently reverts everything that
landed in between, with no conflict and a green gate, because the removed code's tests leave
with it. Before reading the diff, read the file list:

```sh
git diff --stat <base>..<head>
```

and question any file the change has no business touching.
