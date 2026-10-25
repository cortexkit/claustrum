//! The one library target in this package, and it exists only for tests.
//!
//! The daemon is a binary (`ck-claustrum`) and so is the admin CLI. The federation
//! test harness needs to drive the daemon's own outbound client, its federation home
//! (the ingress side) and its admin surface (the federation admin ops) in-process,
//! and a test binary can only link a library target, so this library re-exports
//! exactly the `federation` and `admin_surface` modules and nothing else. Moving the
//! daemon's code into a library to satisfy that would rewrite every module declaration
//! in `main.rs` for no other reason, and would make the whole daemon a public API
//! surface.
#![forbid(unsafe_code)]

#[path = "federation/mod.rs"]
pub mod federation;

// Left out of this library's own unit-test build: the module's unit tests need the
// daemon's test helpers, and they already run in the daemon binary's test build.
#[cfg(not(test))]
#[path = "admin_surface.rs"]
pub mod admin_surface;
