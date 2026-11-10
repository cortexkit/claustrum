# Working in claustrum

Standing rules for workers in this repository. They answer the questions workers ask most,
so you can act without waiting for a reply. If your brief contradicts this file, follow the
brief.

## Building and testing

- Build and test on the build server: use the bash tool with `runon: "linux,8c"`. Don't
  run cargo on the Mac. Keep the normal build directory; a separate `CARGO_TARGET_DIR`
  forces a cold build every run. If a job is refused for capacity (`runner_full`), nothing
  ran: resubmit at `linux,4c`, then `linux,2c`, one job at a time, without asking.
- A change that adds a store migration also changes two tests that pin the whole schema:
  the newest-migration literal and the per-table column lists in `store.rs`. Run
  `cargo test --locked -p credentials-core --features test-support --lib store::` before
  reporting, even when your own filter is narrower.
- Run only the tests for what you changed, by name or module filter, for example
  `cargo test --locked -p credentials-core --features test-support <filter>`. Never run a
  whole crate's suite, the workspace suite, `scripts/fast-check.sh` or `scripts/gate.sh`:
  the head runs the full suite once, over several merged deliveries. If a test outside your
  change fails, rerun that one test by name on your base commit, never the suite.
- Before you deliver, also run: `cargo fmt --all -- --check`; clippy with
  `--features credentials-core/test-support --all-targets -- -D warnings` for every crate
  you touched; `python3 scripts/endpoint-hosts.py`; the script tests in
  `scripts/tests` for any script you touched; and `bun test` on the test files you changed
  plus `bun run typecheck` if you touched `packages/`. Report which checks ran and their
  results.
- A filtered test run that takes more than about 15 minutes means the filter is too broad.
  Don't wait on it in a loop; narrow it.
- Run a sidekick comment review on your changes before delivering, and fix what it flags.
- A bug fix ships with a test that fails without the fix. Say how you showed it failing.
- No mutation-testing work: the `ckdev-mutate` catalogue (`mutations.toml`) was removed
  from this repository.

## Pre-approved: do these without asking

- **Test-only hosts.** A new test that names a host fails `scripts/endpoint-hosts.py`. Run
  `python3 scripts/endpoint-hosts.py --update` locally (it needs no cargo), check the diff
  adds only your test file's rows, and commit it.
- **Schema pins.** A new migration moves the tests that pin the newest migration number.
  Advance those pins. Never rewrite a historical schema snapshot or an old migration.
- **Generated files.** `docs/endpoint-hosts.txt` and `docs/domain-separators.txt` are
  written by `scripts/endpoint-hosts.py`, never by hand.
- **Vector files** that a test generates and pins (rerun the test with
  `CK_EMIT_SECRET_VECTORS=1`): regenerate them with their generator when the change is the
  one your brief asked for, and list each changed case in your report. Never hand-edit one.
  Build-server Linux jobs can't write tracked files, so name each regenerated file in the
  bash tool's `return_paths`; that's the only way the new bytes reach your checkout.
- **Line endings.** Files whose exact bytes are tested go under a `-text` rule in
  `.gitattributes` (fixtures, golden and vectors directories are already covered).
- **Limits.** A new numeric limit needs a test on both sides of its boundary (the last
  accepted value and the first refused one), registered in `docs/threshold-controls.txt`,
  which `scripts/threshold-controls.py` checks.
- **Help pages.** A new or changed `ck auth` verb updates its help page and the verb table,
  and keeps every help line within 80 columns.
- **Test timing.** Tests check order and outcome, not duration. Wait on explicit signals.
  Federation tests use `crates/credentials-module/tests/federation/support.rs`
  (`wait_for_signal`, `wait_until`, `resolved_after_advance`). Never add a real-time sleep.

## Ask first

- Any change to a wire shape: request or reply fields, error codes or classes, or which
  refusals look alike.
- Authorization, grants, principals, or anything that decides who may read, sign, open or
  seal.
- The audit chain, the master key, record sealing, or anything a restored backup depends on.
- Published sample sets other repos pin, beyond the cases your brief names: anything in a
  `tests/vectors/` directory, and the wire fixtures in
  `crates/credentials-module/tests/fixtures/` (`enrollment_wire_contract.json`,
  `federation_wire_contract.json`, `deposit_cookie_wire_contract.json`).
- `Cargo.lock` changes other than adding the packages your brief allows.
- Editing files outside your assigned paths. Ask, and name the file and why.

## Never

- Commit any `.cortexkit/` file other than this one. Git tracks only `WORKER.md` there.
- Print, log or commit a secret, including test keys outside test-only code.
- Weaken an assertion to make a test pass.
