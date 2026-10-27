//! Federation tests: two vaults, a callosum stand-in, and independent fake clocks.
//!
//! Each file under `tests/federation/` owns one surface, and this entry point carries
//! nothing but the shared harness.
//!
//! WHY THE FILES ARE INCLUDED BY `path` RATHER THAN DECLARED AS MODULES: they are
//! written against the crate's internals (the daemon's own dispatch and the outbound
//! client), and this repository's execution fence refuses spawning a child process
//! from a test, so a test that needs an environment laid out before anything else runs
//! runs in this binary's `main` with no libtest harness (see `Cargo.toml`, `harness =
//! false`). One entry point keeps that a single decision.
#![forbid(unsafe_code)]

#[path = "federation/support.rs"]
mod support;

#[path = "federation/outbound.rs"]
mod outbound;

#[path = "federation/ingress.rs"]
mod ingress;

#[path = "federation/remote_read.rs"]
mod remote_read;

#[path = "federation/transfer.rs"]
mod transfer;

#[path = "federation/admin.rs"]
mod admin;

#[path = "federation/secret_forward.rs"]
mod secret_forward;

#[path = "federation/callosum_vectors.rs"]
mod callosum_vectors;

#[path = "fixtures/federation_producer.rs"]
mod federation_producer;

#[test]
fn federation_timing_tests_use_signals_or_virtual_time() {
    // These suites order requests with signals and measure deadlines on Tokio's
    // paused clock. A wall-clock wait can pass locally and race on a loaded runner.
    for (path, source) in [
        (
            "federation/remote_read.rs",
            include_str!("federation/remote_read.rs"),
        ),
        ("federation/admin.rs", include_str!("federation/admin.rs")),
    ] {
        assert!(
            !source.contains("sleep("),
            "{path} must wait for a request signal, not sleep"
        );
        for line in source.lines().filter(|line| line.contains("std::time::")) {
            assert_eq!(
                line, "use std::time::Duration;",
                "{path} must measure only virtual time"
            );
        }
    }
}
