//! The one library target in this package, and it exists only for tests.
//!
//! The daemon is a binary (`ck-claustrum`) and so is the admin CLI. The federation
//! test harness needs to drive the daemon's own outbound client in-process, and a test
//! binary can only link a library target, so this library re-exports exactly the
//! `federation` module and nothing else. Moving the daemon's code into a library to
//! satisfy that would rewrite every module declaration in `main.rs` for no other
//! reason, and would make the whole daemon a public API surface.
#![forbid(unsafe_code)]

#[path = "federation/mod.rs"]
pub mod federation;
