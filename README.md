# claustrum

A credential vault that runs as a supervised daemon. It holds OAuth tokens, API
keys and signing keys encrypted at rest, refreshes OAuth credentials before they
expire, and serves each consumer only the credential it is entitled to.

The problem it exists to solve is credential sprawl: every tool that talks to a
provider ends up with its own copy of a token, its own refresh logic, and its own
way of going wrong. Two processes refreshing the same OAuth grant will eventually
race, and the provider's reuse detection revokes the whole token family. One
custody home removes the race by construction.

## The parts worth reading about

**Possession-only capability handles.** Consumers do not name credentials. They
present an unguessable handle — `ckh_…` — that the vault resolves to a credential
internally. A handle is a bearer token, so it can be given to one consumer and
revoked without touching any other holder, and a consumer never learns the id of
anything it was not given.

The consequence is a deliberate silence: an unknown handle and a *revoked* handle
return the identical refusal. That is not vagueness, it is the point — anything
that distinguished them would be an oracle for enumerating which handles exist.
The cost is that a refusal cannot be read as proof a handle is dead, so no
refusal on this surface licenses a consumer to destroy its own configuration.

**Value-level encryption.** Each record is sealed individually with
XChaCha20-Poly1305 under a master key that lives in the OS keychain or an
operator-held file. The record's version is bound into the AAD, so a record
cannot be silently rolled back to an earlier version of itself. A record that
fails to decrypt is quarantined alone; the rest of the vault keeps serving.

**Crash-safe refresh.** A token exchange is not atomic with the database write
that stores its result, so a crash in between can strand a credential. The vault
writes a durable intent *before* calling the provider and clears it in the same
fenced transaction that commits the new token. On boot, a surviving intent means
the process died mid-exchange, and the credential is reconciled rather than
silently served stale. This is tested by actually SIGKILLing the daemon at each
cut point, not by simulating it.

**A tamper-evident audit chain.** Every mutation appends an HMAC-chained entry
binding its predecessor, so no interior edit, reorder or insert survives
verification without the audit key. What it does *not* do on its own is resist
truncation: an attacker with database write access can delete a suffix and the
remaining prefix still verifies. The vault therefore publishes its chain tip
(sequence plus MAC) in its health snapshot, so an external witness can detect a
tail that vanished. The MAC matters as much as the sequence — a truncation
followed by fresh appends returns the sequence to its old value, and only the MAC
at that sequence reveals it is a different entry.

**Single-writer leasing.** The daemon and the CLI can both write, so writes are
fenced by an epoch-checked lease. A writer that loses the lease latches
permanently rather than clearing on its next success: having lost the fence once
means another writer took it, and a process that re-enabled itself would be
asserting authority it no longer holds.

## Layout

- `crates/credentials-core` — custody logic, wire-agnostic. Records, envelope,
  master-key resolution, refresh adapters, the audit chain, in-vault Ed25519
  signing, APNs provider-token minting.
- `crates/credentials-module` — the daemon and the operator CLI. Read surface,
  master-key-gated admin surface, capability handles, health probing.

## Using it

`ck-claustrum` is the daemon; it is launched by a supervisor and has no inbound
network surface of its own. `ck-auth` is the operator CLI — bootstrap a vault,
log in to a provider, mint and revoke handles, inspect state, verify the audit
chain. Most write verbs commit through the running daemon with zero downtime;
the offline path exists for bootstrap and master-key rotation.

**Releases from v0.1.3 need subc 0.17.20 or newer.** An older supervisor refuses
the module's HELLO with `malformed HELLO body: missing field "consumes"` and
parks it after three restarts. That message names a protocol field rather than a
version mismatch, so it reads as a broken release when it is a supervisor that
predates the field being optional — upgrade the supervisor first. This concerns
you only if you install from the release page by hand; `ck setup claustrum`
installs core first by construction.

- [`docs/cortexkit-credentials-contract.md`](docs/cortexkit-credentials-contract.md)
  — the normative security contract.
- [`docs/operator-runbook.md`](docs/operator-runbook.md) — provisioning, wiring a
  consumer, and the forensic queries worth knowing before you need them.

## Development

All published CortexKit crates come from crates.io; normal locked builds need
no sibling checkout. Check out [`subconscious`](https://github.com/cortexkit/subconscious)
alongside this repo only for the real-daemon e2e tests and the gate's
push-envelope specification check.

```
cargo check --workspace --locked
./scripts/gate.sh          # everything CI runs, on the working tree
```

The gate is exact rather than approximate: it asserts test counts per suite, so a
suite that silently stops running fails the gate instead of passing quietly.

### The TypeScript packages need a build before they can be imported

```
bun install
bun run build               # REQUIRED -- packages/client/dist is gitignored
```

`@cortexkit/claustrum-client` is a workspace package whose `main` points into
`dist/`, and `dist/` is not committed. So on a fresh clone `bun install` succeeds,
reports no changes, and leaves the package unresolvable — any import of it fails
with `Cannot find package '@cortexkit/claustrum-client'`, which reads like a
missing dependency rather than a missing build.

Worth stating plainly because the error points away from the cause: `bun install`
is not enough, and running it again will not help. This is the wall behind
[issue #39](https://github.com/cortexkit/claustrum/issues/39), and it is reachable
from inside the repo too — a `git worktree` of this project is a fresh checkout by
the same definition, so the same three commands fail there while the main checkout
works.

## Mutation proofs

A passing safety test proves little until it has been seen to fail. [`mutations.toml`](mutations.toml) is the checked-in catalogue of exact-once source edits and the full test names that must catch them. The shared `ck-mutate` runner saves and restores source bytes and verifies `Cargo.lock`; compilation errors, missing anchors or tests, timeouts and unrelated failures are not catches. Install the reviewed immutable revision:

```sh
cargo install --locked --git https://github.com/cortexkit/commons --rev 22648cd29230aea9e815bab872ee71de9879ef6d cortexkit-mutate
mkdir -p target/mutations
ck-mutate check
ck-mutate run --only refresh-intent-before-provider --report target/mutations/one.json
ck-mutate run --all --report target/mutations/all.json
ck-mutate run --diff origin/master --report target/mutations/diff.json
ck-mutate run --all --broad --report target/mutations/broad.json
```

Run from a clean tree, with no external test-binary overrides. Never check out an edited file while a replay is running. A successful full replay reports every executable row `CAUGHT`; the real-SIGKILL row runs on Linux and macOS only. Reports live under gitignored `target/mutations/` and CI uploads them as artifacts. PR CI selects rows touched by the committed diff against `origin/master`; master and train pushes replay all rows in isolated shards. The nightly scheduled run audits Cargo rows with `--broad`, against every test target in the package. Reviewed HUB rows name the shared property and only the other targets asserting it; a new cross-target catch still requires review. Diff selection cannot see helpers or fixtures absent from an edit target and `test_file`, so full replay remains necessary.

Build and test deadlines are 3600 seconds and 600 seconds, respectively, not measurements of a developer's loaded machine. Core tests require the non-default `test-support` feature, so core rows declare `features = ["test-support"]` (the crash-cut row adds `kill9-test-seam`); the runner applies a row's features to every cargo invocation, including the baseline listing and `--broad`. Every Rust row is a Cargo row and observes all tests in its target (`only = false`). Script rows invoke one hermetic unittest with a required executed-test count.

To add a row, first resolve the full test name with `cargo test -p <package> --test <target> --locked -- --list` (include `--features test-support` for core tests). Read the current production source and prove an exact-once edit. This existing control illustrates the shape; choose a new ID and mechanism for a new row:

```sh
ck-mutate prove --id scoped-private-key-proof \
  --guards 'scoped get cannot serve vault-held private keys' \
  --file crates/credentials-module/src/read_surface.rs \
  --old '                if record.kind.is_vault_held_key() {
                    // The caller'"'"'s read grant already authorized this record, so this is' \
  --new '                if false { // NON-VACUITY BREAK
                    // The caller'"'"'s read grant already authorized this record, so this is' \
  --test-file crates/credentials-module/src/main.rs \
  --package credentials-module --target='--bin ck-claustrum' \
  --expect-red tests::scoped_get_reveals_signing_kind_only_after_read_grant \
  --expect-message 'a granted caller must learn to use the signing verb' \
  --build-timeout-s 3600 --timeout-s 600 --report target/mutations/proof.json
```

`prove` appends only a caught row. Use `expect_message` to distinguish the intended assertion from unrelated failures, inspect the appended row, run `check`, and commit the catalogue with its guarded behavior. For a core row, add `--features test-support`. See the [pinned runner README](https://github.com/cortexkit/commons/blob/22648cd29230aea9e815bab872ee71de9879ef6d/crates/cortexkit-mutate/README.md) for multi-file catalogue edits, command rows and HUB review. [`docs/mutation-proofs.md`](docs/mutation-proofs.md) records the adoption evidence, survivors and scan-guard boundaries.

The local gate and release build run only `ck-mutate check`. The full replay is the CI landing gate; release-build's ancestor check requires a landed revision, so replaying every mutant there would repeat CI on the same sources. An explicit unlanded-release override also bypasses that assurance.

## License

MIT — see [LICENSE](LICENSE).
