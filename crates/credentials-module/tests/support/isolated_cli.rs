//! Keep `ck-auth` test runs away from the developer's real vault.
//!
//! Without `--data-dir`, `ck-auth` finds the vault from HOME (and the XDG directories)
//! and finds a running daemon from TMPDIR. A test that left out `--data-dir` therefore
//! opened the developer's live vault and read its master key from the keychain; it was
//! caught because the vault's `key-source` record appeared before any build that writes
//! it had been deployed. Every command these suites build goes through [`isolate`], so
//! a missing flag now lands in an empty scratch home instead.
//!
//! The scratch home lives in cargo's per-target temp directory, so `cargo clean`
//! removes it and nothing is left in the system temp directory. A test that needs a
//! different location (for example, discovery tests) sets the variables again after
//! calling [`isolate`]; the later value wins.

use std::path::PathBuf;
use std::process::Command;

/// The scratch home every isolated command uses. It never holds a vault unless a test
/// puts one there itself.
pub fn scratch_home() -> PathBuf {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ck-auth-isolated-home");
    std::fs::create_dir_all(home.join("tmp")).expect("create the isolated test home");
    home
}

/// Point every location `ck-auth` discovers on its own at the scratch home, and drop
/// the variables that would select a real master key or a real daemon connection.
pub fn isolate(command: &mut Command) -> &mut Command {
    let home = scratch_home();
    let tmp = home.join("tmp");
    command
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_DATA_HOME", home.join("share"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TMPDIR", &tmp)
        .env("TMP", &tmp)
        .env("TEMP", &tmp)
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("CK_MASTER_KEY_PATH")
        .env_remove("SUBC_CONNECTION_FILE")
}

/// Assert that `command` would not see the real home. Each suite runs this against its
/// own command builder, so dropping [`isolate`] from a builder fails a named test.
pub fn assert_isolated(command: &Command) {
    let home = command
        .get_envs()
        .find(|(key, _)| *key == "HOME")
        .and_then(|(_, value)| value.map(PathBuf::from))
        .expect("the ck-auth test command must set HOME");
    assert_eq!(home, scratch_home(), "ck-auth test command is not isolated");
    for removed in ["CK_MASTER_KEY_PATH", "SUBC_CONNECTION_FILE"] {
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == removed && value.is_none()),
            "ck-auth test command must clear {removed}"
        );
    }
}
