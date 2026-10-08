# Shared Rust executable test support

Rust tests run built binaries through the crates.io `cortexkit-test-support`
crate (a dev-dependency of `credentials-core` and `credentials-module`), using
`dev_command(ckdev_binary(path))`. The crate replaced a local copy of the same
helper that several CortexKit repos had each patched separately.

## Why these guarantees matter

`ckdev_binary` must keep four properties; check them again before moving to a
new major version of the crate:

1. **A copy, never a hard link.** On a loaded macOS host, `ck-auth` spawned
   through a fresh hard link to cargo's binary was killed by signal 9 before it
   printed anything, in 6 of 15 `cli_admin` runs. With a copy, 15 of 15 passed.
2. **Written by a child process on Unix.** A copy written inside the test
   process can be inherited by a parallel test that forks mid-write, and the
   first exec of the copy then fails with ETXTBSY on Linux.
3. **Published once and reused.** The copy is content-addressed and published by
   atomic rename, so spawns don't create a new executable path each time.
4. **Never stale.** A rebuilt artifact has different bytes and gets a different
   address, so a test can't run the previous build.

## What stayed local

- `TestTempDir` (in `credentials_core::test_support`). The crate's `ScratchDir`
  isn't a drop-in replacement: it generates its own path, has no exact-path
  constructor, and keeps the directory when a panic unwinds. `TestTempDir`
  creates exactly the caller's path, refuses an existing one, supports `keep()`,
  and removes the directory on drop.
- The `cli_admin` helper's signal check. It panics naming the signal when
  `ck-auth` dies by one, so a kill can't pass for a refusal. `dev_command` doesn't
  report signals, and the crate's `checked_output` would fail the tests that
  expect ordinary non-zero refusals.
- `scripts/lib/ckdev-binary.sh` for shell scripts (the crate is Rust only).
- `scripts/check-ckdev-execution.py`, the lexical gate that refuses spawning a
  production-named binary. It recognises both `Command::new(...)` and
  `dev_command(...)` and checks the argument is staged.

## Dependency note

The crate requires `subc-os` 0.1.10, so Cargo unified the workspace's `subc-os`
from 0.1.6 to 0.1.10 for every consumer, including the daemon's launch-nonce
reader. That is a production dependency change and ships with the next vault
build.
