# Mutation testing

A passing safety test proves little until it has been seen to fail. This repository keeps a
checked-in catalogue of source mutations, each paired with the tests that must catch it, and
replays the catalogue in CI.

## 1. The catalogue

[`mutations.toml`](../mutations.toml) is the catalogue of exact-once source edits and the full
test names that must catch them. Each row names the property it guards (`guards`), the edit
(`file`, `old`, `new`), the package and target, and `expect_red`: the tests that must fail. The
shared `ckdev-mutate` runner (the `cortexkit-mutate` crate from the commons repository) applies one
edit at a time, saves and restores source bytes, and verifies `Cargo.lock`. Compilation errors,
missing anchors or tests, timeouts and unrelated failures are not catches.

Core tests need the non-default `test-support` feature, so core rows declare
`features = ["test-support"]` (the crash-cut row adds `kill9-test-seam`); the runner applies a
row's features to every cargo invocation, including the baseline listing and `--broad`. Every
Rust row is a Cargo row and observes all tests in its target (`only = false`). Script rows invoke
one hermetic unittest with a required executed-test count.

## 2. Install and run

Install the reviewed, immutable runner revision:

```sh
cargo install --locked --git https://github.com/cortexkit/commons --rev 0c99c7e16d8ae22b6e114136b6b7b68be6f1394e cortexkit-mutate
```

Then, from a clean tree with no external test-binary overrides:

```sh
mkdir -p target/mutations
ckdev-mutate check                                                        # validate the catalogue
ckdev-mutate run --only refresh-intent-before-provider --report target/mutations/one.json
ckdev-mutate run --all --report target/mutations/all.json
ckdev-mutate run --diff origin/master --report target/mutations/diff.json
ckdev-mutate run --all --broad --report target/mutations/broad.json
```

Never check out an edited file while a replay is running. A successful full replay reports every
executable row `CAUGHT`; the real-SIGKILL row runs on Linux and macOS only. Reports go to the
gitignored `target/mutations/`. Build and test deadlines are 3600 and 600 seconds.

## 3. Where it runs

| where | what runs |
|---|---|
| `./scripts/gate.sh` and `release-build.sh` | `ckdev-mutate check` only |
| PR CI | rows touched by the committed diff against `origin/master` |
| master and train pushes | every row, in isolated Linux shards |
| nightly schedule | every row with `--broad`, against every test target in the package |

CI uploads the reports as artifacts, even on failure. The full replay is the landing gate;
release-build's ancestor check requires a landed revision, so replaying there would repeat CI on
the same sources, and an explicit unlanded-release override forfeits that assurance. Diff
selection cannot see helpers or fixtures absent from an edit target and `test_file`, so a full
replay remains necessary. Reviewed HUB rows name a shared property and only the other targets
asserting it; a new cross-target catch still requires review.

## 4. Adding a row

Resolve the full test name first:

```sh
cargo test -p <package> --test <target> --locked -- --list    # add --features test-support for core tests
```

Read the current production source and prove an exact-once edit. A proof has this shape (the
catalogue's `scoped-get-keeps-private-keys-sealed` row guards the same fence); choose a new id and
mechanism for a new row:

```sh
ckdev-mutate prove --id scoped-private-key-proof \
  --guards 'scoped get cannot serve vault-held private keys' \
  --file crates/credentials-module/src/read_surface.rs \
  --old '                if record.kind.is_vault_held_key() {
                    // The caller'"'"'s read grant already authorized this record, so this is' \
  --new '                if false { // mutant: skip the private-key fence
                    // The caller'"'"'s read grant already authorized this record, so this is' \
  --test-file crates/credentials-module/src/main.rs \
  --package credentials-module --target='--bin ck-claustrum' \
  --expect-red tests::scoped_get_reveals_signing_kind_only_after_read_grant \
  --expect-message 'a granted caller must learn to use the signing verb' \
  --build-timeout-s 3600 --timeout-s 600 --report target/mutations/proof.json
```

`prove` appends only a caught row. Use `--expect-message` to tell the intended assertion from an
unrelated failure, inspect the appended row, run `ckdev-mutate check`, and commit the catalogue
together with the behaviour it guards. For a core row, add `--features test-support`. The
[pinned runner README](https://github.com/cortexkit/commons/blob/0c99c7e16d8ae22b6e114136b6b7b68be6f1394e/crates/cortexkit-mutate/README.md)
covers multi-file edits, command rows and HUB review.

## 5. Scan checks carry their own planted controls

The repository's scan-style checks (`scripts/check-doc-status.py`, `scripts/endpoint-hosts.py`,
`scripts/threshold-controls.py`, `scripts/check-fixture-line-endings.py`,
`scripts/check-path-rendering.py`, `scripts/check-inbound-contracts.sh` and others) run a planted
violation through their real decision path before believing a live scan, because a scan that
reports zero findings reads the same whether the tree is clean or the matcher stopped matching.
The planted controls are hermetic unittests in `scripts/tests/test_script_contracts.py`, and the
`scan-*` rows in the catalogue prove each refusal goes red when neutralized.
