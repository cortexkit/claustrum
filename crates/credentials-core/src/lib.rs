//! Credential custody logic for the cortexkit-credentials subc module.
//!
//! This crate holds the format/provider-specific weight of the credential vault
//! (the "Acquisition + Custody" side of the thin-core boundary): the typed
//! `VaultRecord`, the canonical `OAuthCredential`, the value-level encryption
//! envelope, the bounded per-provider refresh adapters, the crash-safe refresh
//! state machine, and master-key resolution. It is wire-agnostic — it never
//! speaks the subc protocol; `credentials-module` is the thin binary that does.
//!
//! See docs/cortexkit-credentials-contract.md for the security contract and
//! docs/charter.md for the build plan. Built behind a security-conformance suite
//! (kill -9 mid-refresh, lease-handover mid-write, fail-closed matrix, envelope
//! fuzz) that is a ship gate, not a nice-to-have.

// Scaffold baseline: the modules below are the contract's decomposition. Each is
// filled in over the charter's build steps; this keeps the crate compiling from
// the first commit (the green-build-before-turn-end rule).
