//! The cortexkit-credentials subc module binary.
//!
//! Connects out to the subc daemon (reads the connection file, authenticates over
//! loopback TCP), HELLO-registers a reserved `ManagementSurface` (echoing the
//! `SUBC_LAUNCH_NONCE` the supervisor injects so only the spawned process can
//! claim the `cortexkit-credentials` id), and serves two surfaces:
//!   - the anonymous READ surface over the route channel
//!     (credential.get / get_many / status / report_auth_failure), and
//!   - the master-key-gated ADMIN surface, off the runtime channel
//!     (put / import / invalidate / rotate_master_key).
//!
//! See docs/cortexkit-credentials-contract.md (the security contract) and
//! docs/charter.md (the build plan). The wire/frame loop mirrors the proven
//! ai-provider-quota module (quota-module/src/main.rs).

fn main() {
    // Scaffold baseline: the real entry point (connect_to_subc -> HELLO ->
    // frame loop -> surface dispatch) lands over the charter's build steps. This
    // keeps the binary compiling from the first commit.
    eprintln!("cortexkit-credentials module: scaffold; not yet implemented");
    std::process::exit(1);
}
