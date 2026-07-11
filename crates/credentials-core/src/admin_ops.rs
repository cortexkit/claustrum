//! The shared admin-op wire contract: the exact op-body shapes the CLI/app signs
//! and the module verifies+executes.
//!
//! Both sides use THESE types, so the bytes the caller MACs are byte-identical to
//! what the module parses (the caller serializes an `AdminOpBody`, MACs those exact
//! bytes, and sends them verbatim; the module verifies those bytes, then decodes
//! them back into an `AdminOpBody`). Keeping the contract in one place is why the
//! transcript's op-body binding cannot silently drift between the two binaries — a
//! field rename breaks both at compile time, not at runtime.
//!
//! The body is treated as OPAQUE bytes during authentication (parse-after-verify);
//! these types are only used to BUILD the bytes (caller) and to INTERPRET them
//! (module) once the MAC has proven possession.

use serde::{Deserialize, Serialize};

use crate::audit::{AuditCtx, AuditOp};
use crate::record::VaultRecord;
use crate::store::{mint_handle, EncryptedStore, StoreOpError};

/// The admin-op schema version. Bumped only on a breaking op-body change; the
/// module refuses any other version rather than best-effort parsing it.
pub const ADMIN_OP_SCHEMA_V1: u32 = 1;

/// One authenticated admin operation. `#[serde(tag = "op")]` so the discriminator
/// is an `op` string inside the same object the transcript covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum AdminOpBody {
    #[serde(rename = "admin.store")]
    Store {
        v: u32,
        id: String,
        // Boxed to keep the enum variants' sizes comparable (a VaultRecord carries
        // token strings); serde flattens the box transparently.
        record: Box<VaultRecord>,
        audit_op: AdminAuditOp,
        mode: StoreMode,
    },
    #[serde(rename = "admin.invalidate")]
    Invalidate { v: u32, id: String },
    #[serde(rename = "admin.mint_handle")]
    MintHandle { v: u32, id: String },
    #[serde(rename = "admin.revoke_handle")]
    RevokeHandle { v: u32, handle: String },
    #[serde(rename = "admin.revoke_all_handles")]
    RevokeAllHandles { v: u32, id: String },
}

impl AdminOpBody {
    /// The schema version this op declares.
    pub fn schema_version(&self) -> u32 {
        match self {
            AdminOpBody::Store { v, .. }
            | AdminOpBody::Invalidate { v, .. }
            | AdminOpBody::MintHandle { v, .. }
            | AdminOpBody::RevokeHandle { v, .. }
            | AdminOpBody::RevokeAllHandles { v, .. } => *v,
        }
    }

    /// The credential id this op serializes against, for per-credential single-flight
    /// locking. `None` for `revoke_handle` (addressed by handle, not credential id),
    /// which therefore takes no per-id lock.
    pub fn lock_id(&self) -> Option<&str> {
        match self {
            AdminOpBody::Store { id, .. }
            | AdminOpBody::Invalidate { id, .. }
            | AdminOpBody::MintHandle { id, .. }
            | AdminOpBody::RevokeAllHandles { id, .. } => Some(id),
            AdminOpBody::RevokeHandle { .. } => None,
        }
    }

    /// Serialize to the exact bytes the caller MACs and the module verifies. The
    /// caller sends THESE bytes verbatim; the module verifies THESE bytes before
    /// decoding — so serialization non-canonicality is irrelevant (the bytes are
    /// the contract, not a re-derived form).
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// The audit op an `admin.store` records: login, import, or put/overwrite. A closed
/// set so a caller cannot inject an arbitrary audit label.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditOp {
    Login,
    Import,
    Put,
    Overwrite,
}

impl AdminAuditOp {
    pub fn to_audit_op(self) -> AuditOp {
        match self {
            AdminAuditOp::Login => AuditOp::Login,
            AdminAuditOp::Import => AuditOp::Import,
            AdminAuditOp::Put => AuditOp::Put,
            AdminAuditOp::Overwrite => AuditOp::Overwrite,
        }
    }
}

/// Apply an admin op to the store, auditing under `actor`. This is the ONE place
/// the mutation is applied — the running module calls it under the engine's
/// per-credential single-flight lock; the offline CLI calls it directly against the
/// leased store. Sharing it means the online and offline admin paths can never drift
/// in what a given op actually does. Returns a small non-secret JSON result (e.g. a
/// freshly minted handle, or a revoked count).
///
/// The schema version is validated by the caller (the module refuses an unknown
/// version before dispatch); this function assumes a v1 body.
pub fn apply(
    store: &EncryptedStore,
    op: AdminOpBody,
    actor: &str,
) -> Result<serde_json::Value, StoreOpError> {
    match op {
        AdminOpBody::Store {
            id,
            record,
            audit_op,
            mode,
            ..
        } => {
            let ctx = AuditCtx::route_admin(audit_op.to_audit_op(), actor);
            match mode {
                StoreMode::Create => store.create_audited(&id, &record, ctx)?,
                StoreMode::ReplaceUnconditional => {
                    store.overwrite_unconditional_audited(&id, &record, ctx)?
                }
                StoreMode::ReplaceCas { expected_hash_hex } => {
                    let expected = decode_hash32(&expected_hash_hex)
                        .ok_or_else(|| StoreOpError::Encode("bad expected hash hex".into()))?;
                    store.overwrite_cas_audited(&id, &record, &expected, ctx)?
                }
            }
            Ok(serde_json::json!({ "stored": true }))
        }
        AdminOpBody::Invalidate { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Invalidate, actor);
            let revoked = store.invalidate_and_revoke_all_audited(&id, ctx)?;
            Ok(serde_json::json!({ "handles_revoked": revoked }))
        }
        AdminOpBody::MintHandle { id, .. } => {
            let handle = mint_handle().map_err(|e| StoreOpError::Encode(format!("csprng: {e}")))?;
            let ctx = AuditCtx::route_admin(AuditOp::MintHandle, actor);
            store.put_handle_hash(&handle.hash, &id, ctx)?;
            // The raw handle is returned ONCE here; only its hash is persisted.
            Ok(serde_json::json!({ "handle": handle.raw }))
        }
        AdminOpBody::RevokeHandle { handle, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            store.revoke_handle(&handle, ctx)?;
            Ok(serde_json::json!({ "revoked": true }))
        }
        AdminOpBody::RevokeAllHandles { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            let n = store.revoke_all_handles(&id, ctx)?;
            Ok(serde_json::json!({ "handles_revoked": n }))
        }
    }
}

fn decode_hash32(s: &str) -> Option<[u8; 32]> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect();
    <[u8; 32]>::try_from(bytes?.as_slice()).ok()
}

/// The write mode for `admin.store`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreMode {
    /// Create-only: fails if the id already exists.
    Create,
    /// Unconditional overwrite (version-guarded internally): the re-login / re-import
    /// replace that keeps the handle.
    ReplaceUnconditional,
    /// CAS overwrite gated on the current payload hash (lowercase hex).
    ReplaceCas { expected_hash_hex: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::CredentialKind;

    #[test]
    fn round_trips_through_bytes() {
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None);
        let op = AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:x".into(),
            record: Box::new(record),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::Create,
        };
        let bytes = op.to_bytes().unwrap();
        let back: AdminOpBody = serde_json::from_slice(&bytes).unwrap();
        // Re-serializing the decoded value yields the same bytes (serde is stable
        // for these types), which is what lets the module verify the caller's exact
        // bytes and then decode them.
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(back.schema_version(), ADMIN_OP_SCHEMA_V1);
    }

    #[test]
    fn op_discriminator_is_present_in_bytes() {
        let op = AdminOpBody::Invalidate {
            v: 1,
            id: "apikey:x".into(),
        };
        let s = String::from_utf8(op.to_bytes().unwrap()).unwrap();
        assert!(s.contains("\"op\":\"admin.invalidate\""));
    }
}
