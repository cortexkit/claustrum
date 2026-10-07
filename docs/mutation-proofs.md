# Mutation proof catalogue

The catalogue is replayed by ckdev-mutate 0.8.0 (the `cortexkit-mutate` crate), pinned to commons
`46cc166b0df2edcfd14b3eb54ed6eeac588fed69`. Every row was appended by `prove`,
never by inventing a catch.

## Runner boundary, closed in 0.7.2

The catalogue was first written against 0.7.0, which had no cargo feature field:
`Control::targets` rejected `--features`, and `ReplaySession::baselines_scoped`
listed test names package-wide and dropped the row's target selector. Core
integration tests import `test_support`, a non-default feature, so a core cargo
row stopped at E0432 before any mutation. Those 17 rows ran as `command` rows
through a wrapper with explicit features and had no `--broad` breadth audit.
0.7.2 added `features` to cargo rows (applied to every cargo invocation,
including the baseline listing and `--broad`) and fixed the dropped selector, so
the 17 rows are cargo rows again and the wrapper is gone. The same release
retries an LF anchor in CRLF form on a CRLF checkout, so `ckdev-mutate check` also
runs on the Windows CI job.

The original four release arms retain their source sites and named tests. The
online listing proof still edits `read_grants_from_conn`, not the migration
planner or the read-only CLI listing. The scoped key fence remains anchored on
its unique comment, rather than TTL/engine-call plumbing. The stale-marker and
wire-key edits are unchanged mechanisms. The old script was deleted; no test
existed solely for its four arms. The release probe-order test now names the
replacement `ckdev-mutate check`, preserving its ordering claim.

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
helper, and require an executed, non-skipped test count. Importing the checked script bypasses
its executable entry point, so control execution cannot recurse. Six catalogue
rows prove the comparison/refusal logic itself goes red when neutralized; a
seventh proves that skipping the planted control is not accepted as execution.

## Wiring

- CI installs the immutable runner and validates the catalogue in its normal
  platform matrix. Two isolated Linux replay shards select `--diff origin/master`
  on PRs, replay `--all` on master/train pushes and manual/reusable invocations,
  and run `--all --broad` on the existing nightly schedule. Reports are uploaded
  from `target/mutations/`, even on failure.
- The master/train workflow is the landing gate used by `train-push.sh`.
- The local gate adds only `ckdev-mutate check`, preserving the test-job arm parity
  bound. Runner installation is setup, not an additional local test arm.
- Release removes the bespoke script and checks anchors only. Its ancestor guard
  requires a landed source revision; the explicit unlanded override forfeits
  the CI assurance rather than silently gaining one.

## Replay evidence

The final catalogue has **37 proved rows**: 14 Cargo/module rows, 16
feature-explicit core command rows, and 7 script command rows. Every row names
one guard and supplies `expect_message`. On this macOS worktree, with
`cortexkit-mutate 0.7.0`, the final full replay was:

```text
/usr/bin/time -p ckdev-mutate run --all --report target/mutations/all.json
37 CAUGHT; 0 survivors; 0 errors; 0 platform skips
real 366.56 s
```

The preceding full breadth audit of the original 36 rows ran
`ckdev-mutate run --all --broad --report target/mutations/broad.json` in **491.85 s**.
All 36 were CAUGHT; all observed collateral was in the named daemon target
`ck_claustrum`, so no HUB declaration was warranted. The added self-control row
was then audited with `--only scan-self-control-cannot-skip --broad` (CAUGHT,
0.28 s). All 14 Cargo rows observed package breadth; the 23 command rows did
not. Final type-only fixture annotations were followed by individual successful
replays of the endpoint and path scan rows; no guard behavior changed.

The local `./scripts/gate.sh` passed on the final script behavior in **208.00 s**,
with its workspace floor satisfied, 9 real-daemon tests, 1 kill-9 crash cut,
5 rotation cuts, 2 login cuts, 2 OpenCode custody cuts, 8 picker tests,
3 migration-tool tests, and both release-artifact/compatibility arms. Exact
verdict:

```text
GATE PASSED -- every local CI check, on this working tree (full mutation replay runs in landing CI)
```

Independent checks passed: all 52 hermetic script tests (Python 3.9.6), all six
standalone scan checkers with their controls, Python syntax compilation of eight
changed files, Bash 3.2.57 syntax checks, and `ckdev-mutate check` on 37 rows.
The full gate also ran Bun 1.4.2's frozen install, TypeScript typecheck/build and
hermetic tests, Cargo 1.99.0 formatting/clippy (default and seam features), and
Windows cross type-check. Manifests and lockfiles were not changed.
Fresh inspection reports 16 pre-existing Pyright errors in unchanged dynamic
module-loading/fixture assignments and optional regex accesses in
`test_script_contracts.py`; the new tests' fixture annotations avoid adding to
those errors. The two new Python helpers have no diagnostics.

Proof collection staged the live implementation before each mutant and checked
an empty worktree diff. A local command observer captured non-empty source
`git diff --stat` while the named test ran. The shared runner restored bytes;
only after it exited did collection perform checkout/touch, confirm the source
diff empty, and stage its appended catalogue output before requiring the next
global diff empty. Each named guard was also run in isolation for mutation
evidence: exactly that test red, no other test red. Cargo target-wide collateral
in the shared replay is reported separately, never mislabelled exclusive.
The two survivor controls have caught controls reaching the same files/targets.
Detailed JSON reports and local evidence remain in gitignored
`target/mutations/`; this table is the durable row/test index.

| Row id | Exact named test | Full replay |
|---|---|---|
| `audit-chain-detects-tampered-row` | `audit::tests::tampered_entry_breaks_chain` | CAUGHT |
| `bedrock-short-term-deposit-refused` | `store::tests::operator_deposits_refuse_short_term_bedrock_keys_and_accept_long_term_ones` | CAUGHT |
| `cookie-replace-requires-creator` | `tests::deposit_cookie_creator_refusals_preserve_envelope_and_first_use` | CAUGHT |
| `corrupt-record-invalidate-stays-quarantined` | `store::tests::operator_invalidations_preserve_corrupt_and_audit_only_transitions` | CAUGHT |
| `corrupt-record-report-stays-quarantined` | `store::tests::consumer_reports_only_invalidate_active_records` | CAUGHT |
| `daemon-output-sites-no-new-secret-log` | `tests::every_daemon_output_site_is_enumerated` | CAUGHT |
| `deposit-grant-is-not-a-read-grant` | `tests::deposit_only_denial_on_every_read_and_key_operation_has_positive_controls` | CAUGHT |
| `gmail-never-uses-public-client` | `refresh_adapters::google::tests::gmail_missing_client_fails_closed_without_http` | CAUGHT |
| `grant-list-read-sign-separation` | `store::tests::the_online_grant_listing_keeps_read_and_sign_separate_and_orders_by_prefix` | CAUGHT |
| `keychain-security-absolute-path` | `resolver::tests::keychain_tool_is_spawned_by_absolute_path` | CAUGHT |
| `launch-nonce-no-direct-env-read` | `tests::no_shipped_source_reads_the_launch_nonce_directly` | CAUGHT |
| `list-grant-authorizes-inventory` | `tests::a_list_only_principal_sees_identity_and_adapter_in_list_scoped` | CAUGHT |
| `list-grant-does-not-fetch-tokens` | `tests::a_list_only_principal_is_refused_by_every_other_scoped_surface` | CAUGHT |
| `oauth-debug-redacts-client-secret` | `oauth::tests::debug_redacts_client_secret_and_its_bytes` | CAUGHT |
| `oauth-debug-redacts-tokens` | `oauth::tests::debug_redacts_tokens` | CAUGHT |
| `reclassify-preserves-granted-category` | `store::taxonomy_tests::force_refuses_to_strip_a_category_an_active_grant_selects_on` | CAUGHT |
| `refresh-commit-clears-intent` | `engine_tests::refresh_on_stale_commits_new_tokens_and_bumps_version` | CAUGHT |
| `refresh-intent-before-provider` | `kill9_between_response_and_commit_resolves_to_needs_reauth` | CAUGHT |
| `refresh-preserves-client-secret` | `gmail_engine_two_refreshes_preserve_record_client_secret` | CAUGHT |
| `revoked-enrollment-token-unspendable` | `tests::an_enrollment_token_authorizes_a_scoped_read_until_it_is_revoked` | CAUGHT |
| `revoked-handle-refusal-is-uniform` | `tests::unknown_and_revoked_get_handles_refuse_without_disclosing_a_credential_id` | CAUGHT |
| `route-bind-refuses-flow-scope` | `tests::a_route_bind_under_a_flow_scope_is_refused_and_binds_nothing` | CAUGHT |
| `scan-doc-status-falsifier` | `scripts.tests.test_script_contracts.ScriptContracts.test_doc_status_checks_all_markers_and_identifier_boundaries` | CAUGHT |
| `scan-endpoint-host-manifest-drift` | `scripts.tests.test_script_contracts.ScriptContracts.test_endpoint_host_and_separator_drift_are_refused` | CAUGHT |
| `scan-fixture-directory-coverage` | `scripts.tests.test_script_contracts.ScriptContracts.test_uncovered_fixture_directory_is_refused` | CAUGHT |
| `scan-inbound-wire-comparison` | `scripts.tests.test_script_contracts.ScriptContracts.test_inbound_mismatch_is_refused` | CAUGHT |
| `scan-path-rendering` | `scripts.tests.test_script_contracts.ScriptContracts.test_path_scan_refuses_planted_platform_rendering` | CAUGHT |
| `scan-self-control-cannot-skip` | `scripts.tests.test_script_contracts.ScriptContracts.test_scan_self_control_must_execute_not_skip` | CAUGHT |
| `scan-threshold-missing-control` | `scripts.tests.test_script_contracts.ScriptContracts.test_new_threshold_and_stale_unchecked_row_fail_closed` | CAUGHT |
| `scoped-get-keeps-private-keys-sealed` | `tests::scoped_get_reveals_signing_kind_only_after_read_grant` | CAUGHT |
| `scoped-read-honors-enrollment-token` | `tests::every_scoped_surface_answers_an_enrolled_token_differently_than_no_token` | CAUGHT |
| `scoped-refusal-is-uniform` | `tests::scoped_get_uncovered_and_unknown_ids_have_identical_wire_bodies` | CAUGHT |
| `scoped-status-refusal-is-uniform` | `tests::scoped_status_unknown_and_no_grant_are_indistinguishable_on_the_wire` | CAUGHT |
| `secret-debug-is-redacted` | `secret::tests::a_secret_is_unprintable_and_serialises_transparently` | CAUGHT |
| `stale-report-forces-refresh` | `engine_tests::report_stale_then_invalid_grant_latches_needs_reauth` | CAUGHT |
| `status-wire-stale-pending-key` | `tests::the_status_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement` | CAUGHT |
| `store-ahead-refuses-migration` | `store::tests::a_store_ahead_of_this_binary_refuses_to_migrate` | CAUGHT |

## Development executable-name fence

The fleet's `ck-*` namespace is reserved for production executables in the
operator's bin/staging directories. Test and build-artifact execution uses the
shared Rust or shell `ckdev_binary` helper without renaming shipped artifacts.
`scripts/check-ckdev-execution.py` scans 79 test/example/script/workflow sources
and runs its statement-local planted controls before the live scan. A direct
spawn immediately after a wrapped spawn is refused; helper calls in nearby
statements cannot authorize it. Multiline Rust strings, lifetimes, aliases,
inline workflow commands and the shell's production-only paths have controls.

Two rows were appended by `ckdev-mutate prove` (0.8.0):

| Row | Exact expected red test | Applied mutation |
|---|---|---|
| `scan-ckdev-direct-spawn` | `scripts.tests.test_script_contracts.ScriptContracts.test_repo_ckdev_execution_fence` | Restore `Command::new(env!("CARGO_BIN_EXE_ck-auth"))` in `cli_admin::cli` |
| `scan-ckdev-matcher-control` | `scripts.tests.test_script_contracts.ScriptContracts.test_ckdev_matcher_has_statement_local_controls` | Neutralize the Rust constructor matcher predicate |

Each row caught exactly its one named test, with no unrelated failures. The
first direct-spawn attempt survived because an escaped newline in an existing
Rust message confused the initial lexer. That boundary was fixed and given a
planted regression control; the identical direct-spawn edit was then caught.
Reports are retained under `target/mutations/ckdev-{direct-spawn-caught,matcher-caught}.json`
(the initial survivor is `ckdev-direct-spawn.json`). The proof wrapper prints
the applied one-file `2 +-` diff while the mutant is live. The index held the
implementation first, and each restored source ended with an empty unstaged
diff after checkout/touch.

This is a source fence, not full cross-language dataflow analysis: arbitrary
dynamic Python factories and shell indirection require explicit helper use and
additional planted controls. It proves source-population coverage, not runtime
reachability of every factory. A separate genuine nine-test real-daemon run
sampled `ps -axo pid=,comm=` every 0.5 seconds, positively observed both renamed
daemons, and found zero forbidden paths or residual test processes belonging to
the worktree. The [execution audit](../scripts/ckdev-execution-audit.md) records
every site, exact proofs, the supervisor revision, raw-evidence paths, external
seat sightings and the full gate verdict.
