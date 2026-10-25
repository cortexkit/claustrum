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

#[path = "fixtures/federation_producer.rs"]
mod federation_producer;
