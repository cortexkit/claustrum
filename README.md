# claustrum

claustrum is the CortexKit credential vault: a daemon, run under the CortexKit supervisor,
that holds OAuth tokens, API keys, session cookies and signing keys encrypted at rest,
refreshes OAuth credentials before they expire, and serves each consumer only the credential it
is entitled to. One custody home means one refresher per OAuth grant, so two tools can never
race each other into a provider's token-reuse detection, and every write is gated by the master
key and recorded in a tamper-evident audit chain.

| crate or package | what it is |
|---|---|
| [`crates/credentials-core`](crates/credentials-core) | Custody logic: records, encryption envelope, master-key resolution, encrypted store, refresh adapters, audit chain, signing. |
| [`crates/credentials-module`](crates/credentials-module) | The daemon `ck-claustrum` and the operator CLI `ck-auth` (`ck auth <verb>`). |
| [`crates/claustrum-client`](crates/claustrum-client) | `cortexkit-claustrum-client`, the Rust client for supervised modules. |
| [`packages/client`](packages/client) | `@cortexkit/claustrum-client`, the TypeScript client. |
| [`packages/opencode`](packages/opencode) | `@cortexkit/opencode-claustrum`, an OpenCode plugin that serves provider slots from the vault. |

How the parts fit together, and the rules they keep, is in
[`docs/architecture.md`](docs/architecture.md).

## Build and test

These need only the Rust toolchain, Bun and Python 3; every published CortexKit crate comes
from crates.io:

```sh
cargo check --workspace --locked
cargo test --workspace --locked --features credentials-core/test-support
python3 -m unittest discover -s scripts/tests
bun install
bun run build          # required before the TypeScript packages can be imported
bun test packages
```

`bun run build` is not optional. `@cortexkit/claustrum-client` is a workspace package whose
`main` points into `dist/`, and `dist/` is not committed, so on a fresh clone or a new
`git worktree` `bun install` succeeds and leaves the package unresolvable: imports fail with
`Cannot find package '@cortexkit/claustrum-client'`, which reads like a missing dependency
rather than a missing build.

For daemon and `ck auth` iteration, check changed crates plus wire, authorization and migration safety,
build, deploy, observe the live change, then run the full gate and CI. Do not wait for the
integration CI to deploy a private local fix. Migrations still require the runbook's pre-migration
snapshot procedure **before** deployment.

```sh
./scripts/fast-check.sh                    # diff against origin/master, including local edits
./scripts/fast-check.sh --base HEAD^       # explicitly check the latest committed change
# Commit first; the build rechecks the clean committed source, then builds and signs it.
PROBE='<live command> should print <expected result>' ./scripts/release-build.sh --fast
# Deploy the staged binaries and restart claustrum; follow the runbook's Deploy section.
# Run scripts/accept-deploy.sh against the deployed revision and staged artifact directory.
./scripts/gate.sh                          # after live acceptance; also run train CI
```

The fast check prints its scope and omissions. It always runs the daemon wire/auth/refusal
tests, no-secret/no-direct-nonce-read scans, migration safety, and both clients' wire tests;
it is **not** the full gate. A fast build may be off `origin/master`, but must be clean and
committed, declare the live check in `PROBE`, and retain pinned signing identifiers and hardened runtime.
Its `build-info.txt` records the fast path and the observed remote ancestry. The default
release build and published release workflow retain their ancestry guards and full artifact
checks; public client releases are unchanged.

The full gate runs everything CI tests locally, with the feature flags and expected counts.
It also runs the real-daemon end-to-end tests and the inbound-contract check, which need a
checkout of [`subconscious`](https://github.com/cortexkit/subconscious) beside this repository,
and `ckdev-mutate` installed (see [mutation testing](docs/mutation-testing.md)):

```sh
./scripts/gate.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for what the gate checks and how to commit.

## Install and operate

`ck setup claustrum` installs the vault. **Claustrum releases require subc-core (the
supervisor core), version 0.20.83 or newer.** Upgrade the supervisor first when installing
from the release page; `ck setup claustrum` installs it first.

- [Operator runbook](docs/operator-runbook.md): install, master key, logins, grants and
  enrollments, backups and restore, key rotation, deploy and rollback.
- [Wire contract](docs/wire-contract-v1.md): the consumer-facing read surface.
- [Manifest signing](docs/gh-manifest-signing.md): the `gh` routing-manifest signing ceremony.
- [Security policy](SECURITY.md): how to report a vulnerability, and the threat model.

## License

MIT; see [LICENSE](LICENSE).
