# Shared Rust executable test support

Claustrum uses the crates.io `cortexkit-test-support` 0.1.0 crate as a
workspace dependency inherited only by the `credentials-core` and
`credentials-module` **dev-dependencies**. The registry package's
`.cargo_vcs_info.json` identifies commons commit
`d57fd538de6d81d3726d6089032fa24079772a53`.

## Registry API reviewed before adoption

The published README and `src/lib.rs` reexports expose these API groups:

- Executables (`src/binaries.rs`): `ckdev_binary`, `ckdev_file_name`,
  `stage_test_binary`, `dev_command`, `checked_output`, `describe_exit_status`,
  `is_production_executable_name`, `refuse_production_executable`, and
  `exempt_production_executable`.
- Scratch (`src/scratch.rs`): `scratch_root`, `shared_scratch_root`,
  `wait_until_gone`, `STABLE_BIN_DIR`, and `ScratchDir` with `new`, `path`, and
  `keep` (also `AsRef<Path>` and `Deref<Target = Path>`).
- Daemons (`src/daemon.rs`): `TestDaemonCommand` with `new`, `env`,
  `fenced_root`, `arg`, `args`, `env_remove`, `stdout`, `stderr`, `kill_on_drop`,
  and `spawn`; `TestDaemon` with `id`, `try_wait`, `start_kill`, `wait`, `kill`,
  and `stop`.
- Fences and builds (`src/fence.rs`): `fenced_subc_env_dir`,
  `fenced_subc_daemon_env`, `fenced_command`, `fenced_command_with_roots`,
  `warm_exec_fenced`, `sign_test_binary`, `sibling_cargo_build`,
  `sibling_target_dir`, `sibling_checkout`, and `SubcDaemonBinary` with `build`,
  `try_build`, and `command`.
- Sibling cache (`src/sibling_cache.rs`): `sibling_revision`,
  `sibling_cache_root`, `cached_sibling_binary`,
  `cached_sibling_binary_with_target`, `pinned_sibling_build_revision`,
  `sibling_build_revision`, `build_sibling_binary`, and `CachedSiblingBinary`
  with public `executable` and `target_dir` fields.
- Spawn scanning (`src/spawn_guard.rs`): `assert_test_binary_spawns`.
- Unix-only stable files (`src/stable.rs`): `stable_executable` and
  `stable_executable_dir`.
- Privileged-test opt-in (`src/lib.rs`): `PRIVILEGED_TESTS_ENV` and
  `privileged_tests_enabled`.

Only `ckdev_binary` and `dev_command` are adopted here. There is no exported
`ckdev_command`: the equivalent command factory is
`dev_command(ckdev_binary(source))`. `dev_command` alone does not stage its
argument; it rejects production executable names and returns a standard
`std::process::Command`.

## Executable guarantees

The registry source preserves the four required guarantees for built
production-named artifacts:

1. `copy_executable` uses a **copy, never a hard link** (`src/binaries.rs`,
   lines 426–447). Unix runs a `cp` child; other platforms use `fs::copy`.
   The test harness holds no writable descriptor to the staged executable.
2. `publish` writes into a private staging directory, verifies its contents,
   makes the publication read-only, then atomically renames the directory
   (`src/binaries.rs`, lines 254–294).
3. The address hashes the development filename and artifact bytes. Repeated
   requests for the same build reuse the same published path, including
   across processes; spawning does not create a new executable path.
4. Every request hashes the source bytes, and every reuse verifies the
   publication's digest (`src/binaries.rs`, lines 238–317). A rebuilt artifact
   with different bytes gets a different address, even if its length and
   mtime are unchanged. A source changing during copying is refused rather
   than published under the old digest.

Already `ckdev-*` paths pass through unchanged. On Unix, publications now live
in a private per-user `/tmp/cortexkit-ckdev-<uid>` root, not beside the artifact
or beneath `$TMPDIR`. Windows uses system temporary storage and ensures an
`.exe` suffix. Old publications are pruned after three days when a new build
is published. These paths must not be modified or signed after staging.

## Preserved local contracts

`TestTempDir` stays in `credentials_core::test_support`. `ScratchDir` is not a
drop-in replacement: it generates paths and retries collisions, has no
exact-path constructor, and preserves directories while unwinding a panic.
`TestTempDir::from_path` instead creates exactly the caller's path, refuses an
existing path, supports `keep()`, and otherwise removes the directory on drop,
including panic unwinding. Its ownership tests remain local; the deleted
executable-copy test belongs to the shared crate.

The `cli_admin` vault helper still checks Unix signals explicitly. Neither
`dev_command` nor plain `.output()` reports failed exits as errors, and these
CLI tests intentionally inspect ordinary nonzero exits. Replacing them with
`checked_output` would change those refusal tests' contract.

The Rust-only crate does not replace `scripts/lib/ckdev-binary.sh` or its copy
contract test. `scripts/check-ckdev-execution.py` remains the lexical spawn
fence; it recognizes both `Command::new(ckdev_binary(...))` and
`dev_command(ckdev_binary(...))`, including qualified helpers and staged
bindings, while refusing raw arguments. Argument-local positive and negative
controls cover the new command helper.

## Dependencies and CI requirements

The lockfile adds `cortexkit-test-support` 0.1.0, which depends on the already
present `rustix`, `sha2`, and `tokio`, and exactly `subc-os` 0.1.10. Cargo unifies
that version with the workspace's compatible `subc-os` requirement, upgrading
the existing 0.1.6 lock entry to 0.1.10 for the entire graph, including production
consumers. No other package version changes or outside path dependencies are
introduced.

The adopted helpers need `cp` on Unix, as the local helper already did. They
need neither Python nor a test daemon. The unused Unix `TestDaemonCommand`
requires `python3` and `ps` for its embedded supervisor; unused
`SubcDaemonBinary` builds the adjacent subconscious checkout. The current
Linux/Windows CI matrix already invokes `python3` checks and builds the sibling
`ck-subc`; real-daemon e2e tests and Python unittests run only on Linux. Python
is not explicitly installed or version-pinned by that workflow. Adoption adds
no unsatisfied daemon/Python requirement, and workflows are unchanged.
