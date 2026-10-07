# Mutation proof catalogue

The catalogue is replayed by ck-mutate 0.7.0, pinned to commons
`7d08e73722fa3e79bbcc2607753978ab768f1c6b`. Every row was appended by `prove`,
never by inventing a catch. No production source or Rust test was changed.

## Runner boundary

At the pinned revision, `crates/cortexkit-mutate/src/lib.rs::Control::targets`
accepts target selectors only and rejects `--features`. `command` passes targets
for `Scope::Row` and `Scope::Broad`, but **not** `Scope::Package`.
`ReplaySession::baselines_scoped` uses package-wide listing to resolve names;
`prove` also prepares package-wide baseline data. Consequently, core Cargo
proofs fail before mutation: its integration tests import `test_support`, which
is not a default feature. The task reviewer approved feature-explicit command
rows after this behavior was checked in the pinned source. The small
`scripts/mutation-cargo-test.py` wrapper enforces 3600-second builds and
600-second exact-test runs. Core command rows therefore do not audit breadth.
Module Cargo rows do. This is a limitation, not an assertion that core mutants
have no collateral catches.

The original four release arms retain their source sites and named tests. The
online listing proof still edits `read_grants_from_conn`, not the migration
planner or the read-only CLI listing. The scoped key fence remains anchored on
its unique comment, rather than TTL/engine-call plumbing. The stale-marker and
wire-key edits are unchanged mechanisms. The old script was deleted; no test
existed solely for its four arms. The release probe-order test now names the
replacement `ck-mutate check`, preserving its ordering claim.

## Findings deliberately not repaired

| Property | Mutant | Expected guard | Result |
|---|---|---|---|
| No secret at existing daemon output sites | In `read_surface.rs`, add `record.payload.expose()` to the existing KEM error `eprintln!` without adding a macro site | `tests::every_daemon_output_site_is_enumerated` | SURVIVED in the selected module binary and in the runner's package-wide follow-up; no red tests. The test pins the number of sites, not their contents. A separate new-site leak row is caught. |
| Exactly `/usr/bin/security` | In `resolver.rs`, change `SECURITY_BIN` to `/tmp/security` | `resolver::tests::keychain_tool_is_spawned_by_absolute_path` | SURVIVED; one exact test ran and passed. The assertion requires an absolute path, not the particular tool path. The separate bare-`security` mutant is caught. Core command rows cannot perform the runner's package-wide follow-up. |

Neither survivor was appended. Neither needs a new Rust test hidden in this
adoption change; a follow-up decision belongs to the vault maintainer.

## Scan guards

“Every run” below means the executable check runs its planted control before
believing the live scan, not that a one-off historical red run exists. Fixture
controls are temporary input trees; they never mutate shipped Rust source.

| Scan-style check | Before adoption | Every-run planted violation now? |
|---|---|---|
| `check-doc-status.py` | Extractor samples; hermetic falsifier regression in script contracts | Yes: real falsifier decision against an existing symbol through the hermetic test, plus existing extractor samples. The separate shipped-header/body contradiction arm is not yet planted. |
| `check-fixture-line-endings.py` | Matcher samples and population floor | Yes: covered directory passes; a second unexempt fixture directory is discovered and refused by `main`. |
| `endpoint-hosts.py` (endpoint hosts and domain separators) | Population floors and discovery regression, but no comparison control | Yes: real discovery and manifest comparison pass unchanged, then refuse a changed host and changed separator. |
| `threshold-controls.py` | Population floor and hermetic missing/stale manifest tests | Yes: unrecorded constant is refused, fully declared inventory passes, then a stale unchecked row is refused. Does not prove boundary-test quality. |
| `check-outside-path-deps.py` | End-to-end Cargo planted outside dependency and clean graph | Already yes, including real Cargo metadata; script tests also plant an outside patch and a silent checker. Unchanged. |
| `check-path-rendering.py` | Population checks and test exclusion control | Yes: temporary clean Python source passes; a real `str(relative_to(...))` violation is refused by the live sweep. TypeScript slash-component detection has no every-run planted violation yet. |
| `check-inbound-contracts.sh` | Real cross-repo extraction and comparison; missing-key script test | Comparison now has matching, mismatched and missing-value controls on every valid-input run. Extraction of the external spec itself is not planted end-to-end. |
| `main.rs` launch-nonce source scan | Planted direct-read and imported-constant text samples, removal negative sample, source-population floor | Already yes for its matcher on every test run. New catalogue row also plants a compiling direct read in the shipped manifest function, proving the tree walk. No Rust change. |
| `resolver.rs` keychain source scan | Existing allowed call-site population control | No planted forbidden call in every test run. Catalogue catches bare-tool path; exact-path survivor above remains. No Rust change. |
| `main.rs` daemon-output-site inventory | Pinned counts and existing route-log population control | No every-run planted new output site. Catalogue now plants a leaking new site, but the in-place-content survivor remains. No Rust change. |
| `gate.sh` skip-emission scan, passed-test floor, floor ratchet, CI arm-count scan | Hermetic skip, count, missing-floor, and unchecked-platform controls run via script contracts | Partial: those helper regressions run in every full gate; no planted extra CI arm or downward floor change through the complete gate. Listed rather than expanding gate execution here. |
| `lib/workflow-gates.py` workflow/trigger/ref scanner used by train/watch scripts | Hermetic tags/branch/path-filter controls in script contracts | No self-control on standalone scanner invocation; the full local/CI script-contract gate exercises planted trigger restrictions. |
| `audit-signed-payloads.sh` stored-hash/file inventory | Hermetic unreadable store, mismatched approval, and hostile filename controls in script contracts | No standalone every-run planted violation. Requires vault/operator inputs; listed, not changed. |
| `accept-deploy.sh`, `accept-opencode-custody.sh` acceptance output/config/PID scans | Hermetic wrong digest, unsigned/multiple PID/degraded vault and custody controls in script contracts | No standalone every-run fixture before live acceptance. Requires deployed services; listed, not changed. |
| Release/workflow artifact, registry-pin and binary-escape-hatch scans | Hermetic workflow asset/pin controls and release-artifact test | No new every-run planted violation of a real release binary/registry. Full release setup is outside this small scripts-only change. |
| `spikes/opencode-config-fetch.sh` fetch-install/config comparisons | Spike has its own disabled-install mutation arm | Manual spike, not a landing scan. Its stub-startup budget is in script contracts. Unchanged. |

The new script controls invoke exact hermetic unittests from a shared small
helper, and require an executed test count. Importing the checked script bypasses
its executable entry point, so control execution cannot recurse. Six catalogue
rows prove the comparison/refusal logic itself goes red when neutralized.

## Wiring

- CI installs the immutable runner and validates the catalogue in its normal
  platform matrix. Two isolated Linux replay shards select `--diff origin/master`
  on PRs, replay `--all` on master/train pushes and manual/reusable invocations,
  and run `--all --broad` on the existing nightly schedule. Reports are uploaded
  from `target/mutations/`, even on failure.
- The master/train workflow is the landing gate used by `train-push.sh`.
- The local gate adds only `ck-mutate check`, preserving the test-job arm parity
  bound. Runner installation is setup, not an additional local test arm.
- Release removes the bespoke script and checks anchors only. Its ancestor guard
  requires a landed source revision; the explicit unlanded override forfeits
  the CI assurance rather than silently gaining one.

## Replay evidence

The final replay results and the catalogue's row-to-test index are recorded below
once the full clean-tree replay and breadth audit have completed.
