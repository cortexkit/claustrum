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

The gate runs every check CI's test job runs, with the same flags, on your working tree:
format and clippy (including seam features and a Windows cross type-check), the script
contracts and scan checks, the Bun install, typecheck, build and hermetic tests, the workspace
tests, the real-daemon end-to-end tests, and the crash-cut suites. Run it before every push.

It needs:

- the Rust toolchain, Bun and Python 3;
- a checkout of [`subconscious`](https://github.com/cortexkit/subconscious) beside this
  repository (or `CRED_SUBCONSCIOUS_ROOT` pointing at one), for the real-daemon end-to-end
  tests and the inbound-contract check;
- `ckdev-mutate`, installed as described in [mutation testing](docs/mutation-testing.md).

The gate asserts a minimum passed-test count for each suite, so a suite that silently stops
running fails the gate instead of passing quietly. `cargo test --workspace` on its own is not
the gate: the real-daemon tests are `#[ignore]` by default and skip unless
`CRED_REQUIRE_DAEMON=1` is set, and the crash-cut suites compile to nothing without their
feature flags, printing `running 0 tests ... ok`. Read the counts, not the word `ok`.

A green local gate proves the checks pass on your platform. CI also runs Windows, so path
rendering, line endings and shell builtins are unverified until CI says so.

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
| a guarded safety property | a row in [`mutations.toml`](mutations.toml), proved with `ckdev-mutate prove` |

Public docs in `docs/` describe the code as it is now. Design history, measurements and
incident notes do not belong there.

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
