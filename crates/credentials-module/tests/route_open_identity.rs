//! `ck auth` run from a supervised module's shell must not present that module's
//! identity on `route.open`.
//!
//! Such a shell inherits the supervisor's `SUBC_MODULE_ID`, its one-time launch
//! nonce and the nonce descriptor variables. subc's own clients (subc-client-rs, and
//! the TS client unless told `consumerIdentity: null`) fill `route.open`'s
//! `consumer_identity` from those variables when none is given, which would let the
//! CLI open its route as the supervised module. `ck auth`'s route client builds the
//! request itself and never reads them; this proves it with the variables really set.
//!
//! WHY THIS IS A `harness = false` BINARY (see Cargo.toml). Setting environment
//! variables while other threads may read them is a data race, and libtest runs
//! tests on worker threads. With no harness, `main` sets the variables before this
//! process starts any thread, and no other test shares the process. Re-running the
//! test binary as a child process would also work, but this repository's ckdev
//! execution fence (scripts/check-ckdev-execution.py) refuses `Command::new` on
//! anything but its approved executables.
#![forbid(unsafe_code)]
// The CLI modules included below carry functions this test does not call, and unit
// tests whose `#[test]` functions a harness-less binary never runs (their imports and
// helpers then read as unused).
#![allow(dead_code, unused_imports)]

#[path = "../src/bin/cli_support/credential_client.rs"]
mod credential_client;
#[path = "../src/bin/cli_support/route_client.rs"]
mod route_client;

mod common;

use std::sync::{Arc, Mutex};

use common::route_daemon::spawn_route_daemon_recording;
use serde_json::json;

const TEST_NAME: &str = "ck_auth_route_open_carries_no_consumer_identity_from_a_supervised_shell";
const SUPERVISOR_NONCE: &str = "nonce-of-the-supervising-module";

fn main() {
    // Behave like a libtest binary for the two things cargo and the gates ask of one:
    // `--list` names the test, and a name filter that excludes it runs nothing.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--list") {
        println!("{TEST_NAME}: test");
        return;
    }
    let filters: Vec<&String> = args.iter().filter(|arg| !arg.starts_with('-')).collect();
    if !filters.is_empty() && !filters.iter().any(|f| TEST_NAME.contains(f.as_str())) {
        println!("test result: ok. 0 passed; 0 failed; 1 filtered out");
        return;
    }

    // The variables a supervised module's shell inherits, named by subc's constants.
    std::env::set_var(subc_protocol::SUBC_MODULE_ID_ENV, "claustrum");
    std::env::set_var(subc_protocol::SUBC_LAUNCH_NONCE_ENV, SUPERVISOR_NONCE);
    std::env::set_var(subc_os::LAUNCH_NONCE_FD_ENV, "3");
    std::env::set_var(subc_os::LAUNCH_NONCE_PIPE_ENV, "1");

    let root = common::tmp_root("route-open-identity");
    let opened = Arc::new(Mutex::new(None));
    let conn = spawn_route_daemon_recording(
        &root,
        Arc::new(Mutex::new(Vec::new())),
        opened.clone(),
        json!({ "result": { "payload": [1], "record_version": 1 } }),
    );
    credential_client::get_online(&conn, &root, "ckh_owned_capability")
        .expect("capability read succeeds");
    drop(conn);

    let open = opened
        .lock()
        .expect("opened")
        .clone()
        .expect("the fake daemon saw a route.open");
    let mut keys: Vec<&str> = open
        .as_object()
        .expect("route.open body is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["identity", "op", "target"],
        "route.open must carry no consumer identity: {open}"
    );
    let text = open.to_string();
    assert!(!text.contains(SUPERVISOR_NONCE), "nonce leaked: {text}");
    // The call leaves the process environment alone: library code that edits it
    // races every other thread reading it.
    assert_eq!(
        std::env::var(subc_protocol::SUBC_MODULE_ID_ENV).as_deref(),
        Ok("claustrum")
    );
    println!("test {TEST_NAME} ... ok");
    println!("test result: ok. 1 passed; 0 failed");
}
