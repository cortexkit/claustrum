# Development executable-name audit

Only execution is renamed. Cargo artifacts, staged artifacts, signatures,
production process lookups and deployment destinations retain their names.
Rust tests stage each artifact with `cortexkit_test_support::ckdev_binary` (a
content-addressed copy, never a hard link, published once and reused) and spawn
it with `dev_command`. Shell uses `scripts/lib/ckdev-binary.sh`, which copies into
caller-owned scratch space. The table below records the sites as first audited;
where it names `ckdev_command`, read `dev_command(ckdev_binary(...))`.

## Execution sites

| File / symbol or step | Previously executed | Now / no change reason |
|---|---|---|
| `crates/credentials-module/tests/cli_admin.rs` / `cli` (override and default arms) | Staged/override or Cargo `ck-auth` | `ckdev_command` → scratch `ckdev-auth` |
| Same / `both_binaries_report_a_build_revision_without_a_supervisor` | Cargo `ck-claustrum`, plus `cli()` | Scratch `ckdev-claustrum`, `ckdev-auth` |
| Same / `a_temp_dir_connection_file_is_found_and_ambiguity_refuses` (`run` and `boot`) | Cargo `ck-auth` | Scratch `ckdev-auth` |
| Same / `test_escape_hatches_are_absent_from_a_release_build` | Cargo builds `target/release/ck-auth`; test reads bytes | **No change**: builds and byte scans, not execution |
| `crates/credentials-module/tests/cli_opencode.rs` / `cli` | Override or Cargo `ck-auth` | Scratch `ckdev-auth`; covers `MigrationRig` and all stdin/crash-cut CLI commands |
| `crates/credentials-module/tests/gmail_cli.rs` / `login` | Cargo `ck-auth` | Scratch `ckdev-auth` |
| `crates/credentials-module/tests/v012_release_compat.rs` / `current_cli`, `released_cli` | Cargo `ck-auth` and downloaded v0.1.2 `ck-auth` | Scratch `ckdev-auth`; downloading, checksum verification and unpacking remain unchanged |
| `crates/credentials-module/tests/import_picker.rs` / `Fixture::command` | Seam-enabled and shipped `ck-auth` | Fixture-owned scratch `ckdev-auth`; covers all picker calls and the `openpty`/`pre_exec` harness |
| `crates/credentials-module/tests/real_daemon_e2e.rs` / `run_cli_raw`, `fixture_dogfood_import_opencode_round_trips_through_real_daemon` final audit verification | Override/Cargo `ck-auth` | Scratch `ckdev-auth` |
| Same / `start_vault_with_seed`: warm-up loop, supervisor spawn, module config `program` | Sibling `target/debug/ck-subc`, override/Cargo `ck-claustrum` | Rig-owned `ckdev-subc`, `ckdev-claustrum`; config points to the development module path, so the supervised child is renamed too |
| Same / `build_subc_core` | Cargo builds `ck-subc` in supervisor checkout | **No change** to artifact name; test-only `CRED_SUBCONSCIOUS_ROOT` permits an isolated checkout and refuses a missing override |
| `crates/credentials-core/tests/common/mod.rs` / `warmed` | Arbitrary helper passed by crash-cut tests | Shared `ckdev_command` for warm-up; no opaque input can accidentally warm a fleet-named executable |
| `crates/credentials-core/tests/{kill9_mid_refresh,rotate_crash_cut,login_crash_cut}.rs` / child constructors | `kill9_refresh_helper`, `rotate_cut_helper`, `login_cut_helper` | **No change**: filenames have no `ck-` prefix; warm-up now uses shared wrapper above |
| `crates/credentials-core/tests/key_verify_takes_nothing.rs` / verify/move commands | `ck_key_verify`, `ck_key_move` | **No change**: underscore names, not `ck-*` |
| `scripts/release-build.sh` / staged `--version` loop | `target/staged/<rev>/ck-{claustrum,auth}` | `ckdev_binary` → smoke scratch `ckdev-{claustrum,auth}`; signed artifacts and sidecars are unchanged |
| Same / `verify` | Invokes Cargo with staged binary override environment | **No direct binary execution**; overridden binaries are now wrapped in the Rust factories above |
| Same / deployed-revision retention check | `$HOME/.local/share/cortexkit/bin/ck-auth` | **No change**: allowed production executable, whose exact placed image must be checked |
| `scripts/accept-opencode-custody.sh` / `ck_auth` | Worktree `target/release/ck-auth` | Link made after build in the rig's existing scratch root; executes `ckdev-auth` |
| `.github/workflows/release.yml` / packaged revision verification | Unpacked temporary `ck-{claustrum,auth}[.exe]` | Shared shell helper → temporary `ckdev-{claustrum,auth}[.exe]`; packaging/signing/upload names stay unchanged |
| `scripts/accept-deploy.sh` / revision, status, mint/revoke checks | `$HOME/.local/share/cortexkit/bin/ck-*` | **No change**: checks exact production placement; linking would weaken dead-placement diagnosis |
| `scripts/tests/test_script_contracts.py` / acceptance fixtures | Fake `ck-*` shell scripts interpreted by `/bin/bash` | **No change**: no native fleet binary is executed; the interpreter image is Bash. Fixtures must preserve the production acceptance script's name/path/signature assertions |
| `scripts/gate.sh`, `.github/workflows/ci.yml` / shipped CLI export | Set `CK_AUTH_IMPORT_SHIPPED_BINARY` to release artifact | **No direct binary execution**; `Fixture::command` now wraps it |
| `packages/opencode/src/tests/enroll.test.ts` / subprocess | `Bun.spawn(["bun", ...])` | **No change**: executable is Bun, not a fleet binary |
| `packages/client/src/tests/manifest-lock.test.ts` / subprocess | `spawnSync("chmod", ...)` | **No change**: system executable |
| `crates/credentials-module/examples/`, remaining tests/scripts/workflows | Wire probes, system commands, Cargo/Bun/tool runners, data/signature/name checks | **No other `ck-*` execution found** |
| `crates/credentials-module/src/bin/credentials_cli.rs` / test `current_exe` child | Cargo unit-test executable `ck_auth-<hash>` | **No change**: underscore test artifact, not the shipped `ck-auth`; production source untouched |

## Fence and non-vacuity

`python3 scripts/check-ckdev-execution.py` checks 79 Rust, TS/JS, shell,
Python and workflow sources. It is run by the local gate and CI. Rust/TS
constructor arguments are balanced expressions in individual statements, not a
fixed look-back window. Current bindings are examined, and function boundaries
reset them. Shell checks command positions and substitutions, including inline
workflow `run:` commands; signing/checksum arguments are not executable positions.
Python checks executable argv entries, including literal/path bindings. This is
not a complete cross-language compiler: arbitrary dynamic Python factories and
shell indirection cannot be exhaustively resolved statically. New dynamic fleet
spawn factories should use the helper explicitly and extend the planted controls.

The planted controls accept helper-wrapped calls, aliases, system commands,
allowed production paths, comments and fixture strings. They reject direct calls
on the next line after a wrapped call, direct aliases, raw TS spawns, shell/inline
workflow spawns, arbitrary Rust env overrides and Python path bindings. Escaped
multiline Rust strings and lifetimes have explicit lexical controls.

`ckdev-mutate prove` appended two caught catalogue rows:

| Row | Exact expected red test | Observed |
|---|---|---|
| `scan-ckdev-direct-spawn` | `scripts.tests.test_script_contracts.ScriptContracts.test_repo_ckdev_execution_fence` | One red test, naming `cli_admin.rs: Command::new(env!("CARGO_BIN_EXE_ck-auth"))`; no other failures |
| `scan-ckdev-matcher-control` | `scripts.tests.test_script_contracts.ScriptContracts.test_ckdev_matcher_has_statement_local_controls` | One red test: `direct spawn immediately after a wrapped spawn must be refused`; no other failures |

The first direct-spawn proof initially survived: the lexer mishandled a
backslash-newline in an existing Rust message, swallowing the following code.
The lexer was fixed and given multiline/lifetime controls; the identical mutant
then reddened the repository fence. The survivor is retained in
`target/mutations/ckdev-direct-spawn.json`, with successful reports in
`target/mutations/ckdev-direct-spawn-caught.json` and
`target/mutations/ckdev-matcher-caught.json`. Each proof staged the live files,
started with an empty unstaged diff, printed a one-file `2 +-` mutation stat,
and restored via `git checkout -- <path> && touch <path>` to an empty unstaged
diff. No runtime production binary was executed by these source-scan mutants.

## Measured execution

Supervisor checkout: isolated `target/subconscious`, revision
`bbc2087985c6bca718139fe753b3d7b983ab4df7` (approved public shallow clone).

Command:

```sh
CRED_REQUIRE_DAEMON=1 CRED_SUBCONSCIOUS_ROOT="$PWD/target/subconscious" \
  python3 scripts/measure-ckdev-processes.py target/ckdev-ps-final-cadence.json -- \
  cargo test --locked -p credentials-module --test real_daemon_e2e \
  -- --ignored --nocapture --test-threads=1
```

9/9 genuine, non-skipped tests passed in 33.22 seconds. `ps -axo pid=,comm=`
was sampled on fixed 0.5-second deadlines: **70 samples, 16 development executable
paths, zero forbidden `ck-*` paths in this worktree, zero residual test
processes**. Both `ckdev-subc` and `ckdev-claustrum` were positively observed.
Actual mean interval was 0.50005 seconds (min 0.36966, max 0.72125 under host load).
Scratch executables were deliberately placed beneath this worktree, making
ownership distinguishable from concurrent seats' temporary processes.
After-run `pgrep -a -x` found the allowed production `ck-subc` (1266) and
`ck-claustrum` (28880), unrelated supervisors (15421, 20160, 22596), and another
seat's existing `ckdev-subc` (1268); no `ckdev-claustrum` or `ckdev-auth` remained.
The after-run `ps` snapshot confirms none of those PIDs belongs to this run's
scratch tree. No `pgrep -f` or `-v` was used. Raw snapshots and exact queries are
in the JSON report. An earlier scoped run also passed (32 samples, 19 development
paths, zero forbidden paths/residual processes) in `target/ckdev-ps-scoped.json`.

A previous genuine run, including the cold supervisor build, passed 9/9 tests
and collected 1,296 samples. Its global check reported unrelated concurrent
seats, not this run. The reviewer approved a worktree/PID-scoped verdict and
requested the external sightings below; none were stopped or modified.
Counts below are exact executable-path matches in those 1,296 samples, not
substring matches. The later reports separately record their external sightings.

| Full executable path as reported by `ps` | Seat inferred from path | Samples |
|---|---|---:|
| `/Users/ufukaltinok/.cache/broca-claustrum-target/release/ck-claustrum` | BROCA cache; claustrum binary | 3 |
| `/Users/ufukaltinok/.cache/broca-subc-target/debug/ck-subc` | BROCA | 188 |
| `/Users/ufukaltinok/.cache/cortexkit/callosum-test-bins/ck-subc-2a0844a16456ab3e` | callosum | 400 |
| `/Users/ufukaltinok/.cache/prefrontal/sibling-target/subconscious/bbc2087985c6bca718139fe753b3d7b983ab4df7-deps-84eea4544f87481cabdba058e23f7b84fa999072/ck-subc/debug/ck-subc` | prefrontal sibling cache | 956 |
| `/Users/ufukaltinok/.local/share/cortexkit/alfonso/worktrees/76e3d5cb0215146c/bg_8e81fced8793c9a3/target/debug/ck-callosum` | callosum `bg_8e81fced8793c9a3` | 32 |
| `/Users/ufukaltinok/.local/share/cortexkit/alfonso/worktrees/76e3d5cb0215146c/bg_d4ea6fa037c05af9/target/debug/ck-callosum` | callosum `bg_d4ea6fa037c05af9` | 402 |
| `/Users/ufukaltinok/.local/share/cortexkit/alfonso/worktrees/c0c39eea197fcc68/9e09c29b1299fe1375199f0556d08a60e3160822e6787a583c0054270883aec9/bg_fd2aabc490b53eb4/target/debug/ck-prefrontal-core` | prefrontal `bg_fd2aabc490b53eb4` | 951 |
| `/Users/ufukaltinok/.local/share/cortexkit/alfonso/worktrees/cb089079df9ef51b/pool-133/target/debug/deps/ck-599565828f8d40f3` | ck CLI test pool | 32 |
| `/Users/ufukaltinok/Work/Projects/CortexKit/broca-ws/crates/ck-import/../../target/debug/ck-broca` | BROCA | 1 |
| `/Users/ufukaltinok/Work/Projects/CortexKit/broca-ws/target/debug/ck-broca` | BROCA | 193 |
| `/tmp/ckm070/bin/ck-mutate` | mutation-runner rig; owner unknown | 5 |
| `/var/folders/18/257zzylx4h1gbkcvs4cnpqqc0000gn/T/subc-tests/ck-twin-on-path-95970-5/bin/ck-twin` | subconscious test rig | 1 |
| `ck-mutate` (comm-only, no absolute image path) | Unknown; later exact `pgrep` found none, so full image path could not be resolved | 1296 |

The final 70-sample run also observed these external images:

| Full executable path as reported by `ps` | Seat inferred from path | Samples |
|---|---|---:|
| `/Users/ufukaltinok/.cache/prefrontal/sibling-target/subconscious/bbc2087985c6bca718139fe753b3d7b983ab4df7-deps-84eea4544f87481cabdba058e23f7b84fa999072/ck-subc/debug/ck-subc` | prefrontal sibling cache | 70 |
| `/Users/ufukaltinok/.local/share/cortexkit/alfonso/worktrees/c0c39eea197fcc68/9e09c29b1299fe1375199f0556d08a60e3160822e6787a583c0054270883aec9/bg_0bafe99e10fc78b5/target/debug/ck-prefrontal-core` | prefrontal `bg_0bafe99e10fc78b5` | 64 |
| `/Users/ufukaltinok/.local/share/cortexkit/alfonso/worktrees/c0c39eea197fcc68/9e09c29b1299fe1375199f0556d08a60e3160822e6787a583c0054270883aec9/bg_4ee402ff4186180d/target/debug/ck-prefrontal-core` | prefrontal `bg_4ee402ff4186180d` | 70 |
| `/Users/ufukaltinok/.local/share/cortexkit/alfonso/worktrees/c0c39eea197fcc68/9e09c29b1299fe1375199f0556d08a60e3160822e6787a583c0054270883aec9/bg_fb2a8cab821baa48/target/debug/ck-prefrontal-core` | prefrontal `bg_fb2a8cab821baa48` | 59 |

## Gates

Cargo 1.99.0, rustc 1.99.0, Python 3.9.6, Bun 1.4.2, ckdev-mutate 0.8.0.

The first full gate failed at
`multi_account_restore_refuses_before_reading_or_revoking_material` during
parallel workspace tests, at host load 45.77 / 49.23 / 47.54. With no code
changes, that exact test passed (1/1), its entire target passed (104/104), and
the full gate passed on rerun. No existing test expectation was changed.
Logs: `target/ckdev-gate.log`, `target/ckdev-gate-recheck.log`.

Final full gate verdict:

```text
GATE PASSED -- every local CI check, on this working tree (full mutation replay runs in landing CI)
```

The final setup diagnostic was additionally checked with a nonexistent explicit
supervisor override and without `CRED_REQUIRE_DAEMON`/`CI`: the one selected
real-daemon test rejected it by naming `CRED_SUBCONSCIOUS_ROOT` and refusing
fallback. The full nine-test target then passed with the valid isolated checkout.
The final matcher refinements passed all 56 Python tests and both catalogue rows
replayed as CAUGHT. An actual release `ck-auth` was executed via the shell helper
as `ckdev-auth`; three checks verified its filename, `--version` execution and
unchanged original-artifact hash. Bash syntax checking covered four modified
shell files. No production placement or live-vault operation was attempted.

The gate includes formatting, both Clippy feature configurations, Bun typecheck,
build and tests, Rust workspace tests, Windows cross-check, all nine real-daemon
arms, crash-cut suites, all eight picker/real-terminal arms, migration tools,
published-v0.1.2 compatibility and the release seam-absence proof. Production
release-build/deploy/acceptance rigs were not run against the live vault.
