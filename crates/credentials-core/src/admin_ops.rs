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

use crate::audit::AuditRecord;
use crate::audit::{AuditCtx, AuditOp};
use crate::record::{RecordIdentity, VaultRecord};
use crate::store::{
    mint_handle, EncryptedStore, GrantOperation, ReadGrant, RecordMeta, SelectorKind,
    SetCategoryMode, StoreOpError,
};

/// The admin-op schema version. Bumped only on a breaking op-body change; the
/// module refuses any other version rather than best-effort parsing it.
pub const ADMIN_OP_SCHEMA_V1: u32 = 1;
pub const ADMIN_OP_SCHEMA_V2: u32 = 2;

/// One authenticated admin operation. `#[serde(tag = "op")]` so the discriminator
/// is an `op` string inside the same object the transcript covers.
#[derive(Clone, Serialize, Deserialize)]
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
    /// Identity-aware replacement has its own op discriminator so a daemon that predates
    /// sticky identity rejects it instead of silently treating it as a legacy replace.
    #[serde(rename = "admin.store_with_identity_policy")]
    StoreWithIdentityPolicy {
        v: u32,
        id: String,
        record: Box<VaultRecord>,
        audit_op: AdminAuditOp,
        clear_identity: bool,
    },
    /// Update only the non-secret identity attached to an existing record. The store
    /// re-seals the unchanged credential material and keeps its lifecycle state.
    #[serde(rename = "admin.set_identity")]
    SetIdentity {
        v: u32,
        id: String,
        identity: RecordIdentity,
    },
    #[serde(rename = "admin.invalidate")]
    Invalidate { v: u32, id: String },
    /// Reversibly stop serving a credential because an operator intentionally retired
    /// it. This is the only admin operation that writes `retired`; all discovery paths
    /// continue to use `needs_reauth` or `corrupt`.
    #[serde(rename = "admin.logout")]
    Logout { v: u32, id: String },
    /// Clear `needs_reauth` or `retired` back to active WITHOUT replacing the stored material: the
    /// operator asserting the credential was marked dead in error.
    ///
    /// The counterpart to `Invalidate`, and NOT a substitute for `Store` -- it changes
    /// no secret, only a verdict about one. Exists because a mistaken consumer report
    /// could otherwise strand material the vault holds intact: a GitHub App key is
    /// shredded after deposit by custody rule, so there is no copy to re-put and no
    /// login flow to re-mint, and recovering would need a browser ceremony.
    #[serde(rename = "admin.reactivate")]
    Reactivate { v: u32, id: String },
    /// PERMANENT removal: delete the credential row, its intent, and its handles
    /// (audited; the chain keeps the history). `logout` (invalidate) is the
    /// reversible sibling — remove is for retiring an account or cleaning up a
    /// mistaken id.
    #[serde(rename = "admin.remove")]
    Remove { v: u32, id: String },
    #[serde(rename = "admin.mint_handle")]
    MintHandle { v: u32, id: String },
    #[serde(rename = "admin.revoke_handle")]
    RevokeHandle { v: u32, handle: String },
    // A distinct tag makes older daemons refuse rather than reinterpret a hash as a bearer.
    #[serde(rename = "admin.revoke_handle_by_hash")]
    RevokeHandleByHash { v: u32, handle_hash: String },
    #[serde(rename = "admin.revoke_all_handles")]
    RevokeAllHandles { v: u32, id: String },
    /// Grant a reserved module principal one literal-prefix credential operation.
    #[serde(rename = "admin.grant_create")]
    GrantCreate {
        v: u32,
        principal_id: String,
        credential_prefix: String,
        operation: GrantOperation,
    },
    /// Revoke a reserved module principal literal-prefix credential operation grant.
    #[serde(rename = "admin.grant_revoke")]
    GrantRevoke {
        v: u32,
        principal_id: String,
        credential_prefix: String,
        operation: GrantOperation,
    },
    #[serde(rename = "admin.grant_create_v2")]
    GrantCreateV2 {
        v: u32,
        principal_kind: String,
        principal_id: String,
        selector_kind: SelectorKind,
        selector: String,
        operation: GrantOperation,
    },
    #[serde(rename = "admin.grant_revoke_v2")]
    GrantRevokeV2 {
        v: u32,
        principal_kind: String,
        principal_id: String,
        selector_kind: SelectorKind,
        selector: String,
        operation: GrantOperation,
    },
    #[serde(rename = "admin.set_category")]
    SetCategory {
        v: u32,
        credential_id: String,
        mode: SetCategoryMode,
        categories: Vec<String>,
    },
    #[serde(rename = "admin.reclassify")]
    Reclassify { v: u32, force: bool },
    /// Record that a NAMED APPROVER approved a specific artifact, identified by the
    /// SHA-256 of its exact bytes, before a signing window is opened for it.
    ///
    /// Master-key-gated like every other admin op, and that is the point rather than
    /// uniformity: an approval a route caller could forge would prove nothing about who
    /// approved. The signing itself is NOT gated this way — `credential.sign` needs only
    /// a handle — so the gate is deliberately on the record of intent rather than on the
    /// act, which is the asymmetry the ceremony rests on.
    #[serde(rename = "admin.approval")]
    Approval {
        v: u32,
        /// The signing credential the window will open on, so the entry names WHICH key
        /// was approved for use and not merely that something was approved.
        credential_id: String,
        /// Lowercase hex SHA-256 of the exact artifact bytes. Never a rendering, never a
        /// canonicalized form: the verifier verifies received bytes, so the approver
        /// must approve those same bytes or the two meet at nothing.
        artifact_sha256: String,
        /// Who approved. Free text by design — the vault cannot authenticate a human,
        /// and pretending otherwise by constraining the field would imply a check that
        /// does not exist.
        approver: String,
    },
    /// An authenticated READ: the no-decrypt credential inventory + health summary.
    /// A read, but master-key-gated like every other admin op, because the full
    /// per-credential id/state list is not an anonymous enumeration surface (the
    /// anonymous read plane is capability-handle-scoped by design). Serves `ck creds
    /// status` against a RUNNING daemon.
    #[serde(rename = "admin.status")]
    Status { v: u32 },
}

/// Redacted `Debug`, hand-written rather than derived, and NOT only because of the
/// boxed `VaultRecord` -- that one is fixed transitively now that `VaultRecord` redacts
/// its own payload.
///
/// THE VARIANT THAT MADE THIS NECESSARY IS `RevokeHandle`. Its `handle` is the RAW
/// `ckh_...` bearer, not a hash: `apply` passes it straight to `store.revoke_handle`,
/// which hashes it there (`handle_hash(raw_handle)`). A capability handle in a log is
/// strictly worse than an encrypted payload in one -- it needs no key, no decoding, and
/// no vault access to use. Anyone who can read the line can read the credential it
/// grants, until someone notices and revokes it.
///
/// A MANUAL IMPL RATHER THAN A REDACTING NEWTYPE, deliberately: this enum IS the MAC
/// transcript, verified byte-for-byte on the admin route, so nothing that could perturb
/// its serialization belongs anywhere near it. A `Debug` impl cannot; a serde-adjacent
/// type change could.
///
/// The exhaustive match is the forcing function. A new variant carrying a new secret
/// will not compile until someone has decided how it renders, which is the property a
/// derive gives up.
impl std::fmt::Debug for AdminOpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminOpBody::Store {
                v,
                id,
                record,
                audit_op,
                mode,
            } => f
                .debug_struct("Store")
                .field("v", v)
                .field("id", id)
                // VaultRecord redacts its own payload.
                .field("record", record)
                .field("audit_op", audit_op)
                .field("mode", mode)
                .finish(),
            AdminOpBody::StoreWithIdentityPolicy {
                v,
                id,
                record,
                audit_op,
                clear_identity,
            } => f
                .debug_struct("StoreWithIdentityPolicy")
                .field("v", v)
                .field("id", id)
                .field("record", record)
                .field("audit_op", audit_op)
                .field("clear_identity", clear_identity)
                .finish(),
            AdminOpBody::SetIdentity { v, id, identity } => f
                .debug_struct("SetIdentity")
                .field("v", v)
                .field("id", id)
                .field("identity", identity)
                .finish(),
            AdminOpBody::Invalidate { v, id } => f
                .debug_struct("Invalidate")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Logout { v, id } => f
                .debug_struct("Logout")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Reactivate { v, id } => f
                .debug_struct("Reactivate")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Remove { v, id } => f
                .debug_struct("Remove")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::MintHandle { v, id } => f
                .debug_struct("MintHandle")
                .field("v", v)
                .field("id", id)
                .finish(),
            // The one that matters: a live bearer token.
            AdminOpBody::RevokeHandle { v, .. } => f
                .debug_struct("RevokeHandle")
                .field("v", v)
                .field("handle", &"<redacted>")
                .finish(),
            AdminOpBody::RevokeHandleByHash { v, handle_hash } => f
                .debug_struct("RevokeHandleByHash")
                .field("v", v)
                .field("handle_hash", handle_hash)
                .finish(),
            AdminOpBody::RevokeAllHandles { v, id } => f
                .debug_struct("RevokeAllHandles")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::GrantCreate {
                v,
                principal_id,
                credential_prefix,
                operation,
            } => f
                .debug_struct("GrantCreate")
                .field("v", v)
                .field("principal_id", principal_id)
                .field("credential_prefix", credential_prefix)
                .field("operation", operation)
                .finish(),
            AdminOpBody::GrantRevoke {
                v,
                principal_id,
                credential_prefix,
                operation,
            } => f
                .debug_struct("GrantRevoke")
                .field("v", v)
                .field("principal_id", principal_id)
                .field("credential_prefix", credential_prefix)
                .field("operation", operation)
                .finish(),
            AdminOpBody::GrantCreateV2 {
                v,
                principal_kind,
                principal_id,
                selector_kind,
                selector,
                operation,
            } => f
                .debug_struct("GrantCreateV2")
                .field("v", v)
                .field("principal_kind", principal_kind)
                .field("principal_id", principal_id)
                .field("selector_kind", selector_kind)
                .field("selector", selector)
                .field("operation", operation)
                .finish(),
            AdminOpBody::GrantRevokeV2 {
                v,
                principal_kind,
                principal_id,
                selector_kind,
                selector,
                operation,
            } => f
                .debug_struct("GrantRevokeV2")
                .field("v", v)
                .field("principal_kind", principal_kind)
                .field("principal_id", principal_id)
                .field("selector_kind", selector_kind)
                .field("selector", selector)
                .field("operation", operation)
                .finish(),
            AdminOpBody::SetCategory {
                v,
                credential_id,
                mode,
                categories,
            } => f
                .debug_struct("SetCategory")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("mode", mode)
                .field("categories", categories)
                .finish(),
            AdminOpBody::Reclassify { v, force } => f
                .debug_struct("Reclassify")
                .field("v", v)
                .field("force", force)
                .finish(),
            AdminOpBody::Approval {
                v,
                credential_id,
                artifact_sha256,
                approver,
            } => f
                .debug_struct("Approval")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("artifact_sha256", artifact_sha256)
                .field("approver", approver)
                .finish(),
            AdminOpBody::Status { v } => f.debug_struct("Status").field("v", v).finish(),
        }
    }
}

impl AdminOpBody {
    /// The schema version this op declares.
    pub fn schema_version(&self) -> u32 {
        match self {
            AdminOpBody::Store { v, .. }
            | AdminOpBody::StoreWithIdentityPolicy { v, .. }
            | AdminOpBody::SetIdentity { v, .. }
            | AdminOpBody::Invalidate { v, .. }
            | AdminOpBody::Logout { v, .. }
            | AdminOpBody::Reactivate { v, .. }
            | AdminOpBody::Remove { v, .. }
            | AdminOpBody::MintHandle { v, .. }
            | AdminOpBody::RevokeHandle { v, .. }
            | AdminOpBody::RevokeHandleByHash { v, .. }
            | AdminOpBody::RevokeAllHandles { v, .. }
            | AdminOpBody::GrantCreate { v, .. }
            | AdminOpBody::GrantRevoke { v, .. }
            | AdminOpBody::GrantCreateV2 { v, .. }
            | AdminOpBody::GrantRevokeV2 { v, .. }
            | AdminOpBody::SetCategory { v, .. }
            | AdminOpBody::Reclassify { v, .. }
            | AdminOpBody::Approval { v, .. }
            | AdminOpBody::Status { v } => *v,
        }
    }

    /// Version admitted for this exact variant. The exhaustive match is the pairing
    /// table: adding a variant cannot silently inherit either schema version.
    pub const fn required_schema_version(&self) -> u32 {
        match self {
            AdminOpBody::GrantCreateV2 { .. }
            | AdminOpBody::GrantRevokeV2 { .. }
            | AdminOpBody::SetCategory { .. }
            | AdminOpBody::Reclassify { .. } => ADMIN_OP_SCHEMA_V2,
            AdminOpBody::Store { .. }
            | AdminOpBody::StoreWithIdentityPolicy { .. }
            | AdminOpBody::SetIdentity { .. }
            | AdminOpBody::Invalidate { .. }
            | AdminOpBody::Logout { .. }
            | AdminOpBody::Reactivate { .. }
            | AdminOpBody::Remove { .. }
            | AdminOpBody::MintHandle { .. }
            | AdminOpBody::RevokeHandle { .. }
            | AdminOpBody::RevokeHandleByHash { .. }
            | AdminOpBody::RevokeAllHandles { .. }
            | AdminOpBody::GrantCreate { .. }
            | AdminOpBody::GrantRevoke { .. }
            | AdminOpBody::Approval { .. }
            | AdminOpBody::Status { .. } => ADMIN_OP_SCHEMA_V1,
        }
    }

    pub fn has_valid_schema_version(&self) -> bool {
        matches!(
            self.schema_version(),
            ADMIN_OP_SCHEMA_V1 | ADMIN_OP_SCHEMA_V2
        ) && self.schema_version() == self.required_schema_version()
    }

    /// The credential id this op serializes against, for per-credential single-flight
    /// locking. `None` for `revoke_handle` (addressed by handle, not credential id),
    /// which therefore takes no per-id lock.
    pub fn lock_id(&self) -> Option<&str> {
        match self {
            // An approval takes the signing credential's lock: it is the record whose
            // window is about to open, so an approval racing an admin mutation of that
            // same key should serialize rather than interleave.
            AdminOpBody::Approval {
                credential_id: id, ..
            }
            | AdminOpBody::Store { id, .. }
            | AdminOpBody::StoreWithIdentityPolicy { id, .. }
            | AdminOpBody::SetIdentity { id, .. }
            | AdminOpBody::Invalidate { id, .. }
            | AdminOpBody::Logout { id, .. }
            | AdminOpBody::Reactivate { id, .. }
            | AdminOpBody::Remove { id, .. }
            | AdminOpBody::MintHandle { id, .. }
            | AdminOpBody::RevokeAllHandles { id, .. }
            | AdminOpBody::SetCategory {
                credential_id: id, ..
            } => Some(id),
            AdminOpBody::RevokeHandle { .. }
            | AdminOpBody::RevokeHandleByHash { .. }
            | AdminOpBody::GrantCreate { .. }
            | AdminOpBody::GrantRevoke { .. }
            | AdminOpBody::GrantCreateV2 { .. }
            | AdminOpBody::GrantRevokeV2 { .. }
            | AdminOpBody::Reclassify { .. }
            | AdminOpBody::Status { .. } => None,
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
    if !op.has_valid_schema_version() {
        return Err(StoreOpError::Encode(format!(
            "unsupported admin op schema version/variant pairing {}",
            op.schema_version()
        )));
    }
    match op {
        AdminOpBody::Approval {
            credential_id,
            artifact_sha256,
            approver,
            ..
        } => {
            // The approver is recorded as the ACTOR rather than folded into a message,
            // so the chain answers "who approved" with a field instead of prose a later
            // reader has to parse.
            //
            // The route actor (`route-admin`) is deliberately NOT used here: it names the
            // path, and this entry exists to name the person.
            store.append_audit(&AuditRecord {
                op: AuditOp::Approval,
                credential_id: Some(credential_id.clone()),
                payload_hash: Some(artifact_sha256.clone()),
                actor: approver.clone(),
                alarm: None,
            })?;
            Ok(serde_json::json!({
                "approved": artifact_sha256,
                "credential_id": credential_id,
                "approver": approver,
            }))
        }
        AdminOpBody::Store {
            id,
            record,
            audit_op,
            mode,
            ..
        } => {
            crate::store::validate_deposit_credential_id(&id)?;
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
        AdminOpBody::StoreWithIdentityPolicy {
            id,
            record,
            audit_op,
            clear_identity,
            ..
        } => {
            crate::store::validate_deposit_credential_id(&id)?;
            store.overwrite_unconditional_with_identity_policy_audited(
                &id,
                &record,
                !clear_identity,
                AuditCtx::route_admin(audit_op.to_audit_op(), actor),
            )?;
            Ok(serde_json::json!({ "stored": true }))
        }
        AdminOpBody::SetIdentity { id, identity, .. } => {
            store.set_identity_audited(
                &id,
                identity,
                AuditCtx::route_admin(AuditOp::SetIdentity, actor),
            )?;
            Ok(serde_json::json!({ "identity_updated": true }))
        }
        AdminOpBody::Invalidate { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Invalidate, actor);
            let outcome = store.invalidate_and_revoke_all_audited(&id, ctx)?;
            // `state_changed` rides the wire so the CLI can tell an operator whether
            // this call did anything. `handles_revoked` alone cannot: a credential
            // with no handles reports zero whether it was live or already dead.
            Ok(serde_json::json!({
                "handles_revoked": outcome.handles_revoked,
                "state_changed": outcome.state_changed,
                "intent_cleared": outcome.intent_cleared,
            }))
        }
        AdminOpBody::Logout { id, .. } => {
            // Keep the established `invalidate` audit label. Historic rows are
            // intentionally not reclassified, and the current lifecycle state carries
            // the operator's retirement intent without changing that chain vocabulary.
            let ctx = AuditCtx::route_admin(AuditOp::Invalidate, actor);
            let outcome = store.retire_and_revoke_all_audited(&id, ctx)?;
            Ok(serde_json::json!({
                "handles_revoked": outcome.handles_revoked,
                "state_changed": outcome.state_changed,
                "intent_cleared": outcome.intent_cleared,
            }))
        }
        AdminOpBody::Reactivate { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Reactivate, actor);
            let state_changed = store.reactivate_audited(&id, ctx)?;
            // `state_changed` rides the wire for the same reason it does on invalidate:
            // without it, a no-op (already active, or corrupt and refused) is
            // indistinguishable from a real repair, and an operator would read success
            // as "the credential is back" when nothing happened.
            Ok(serde_json::json!({ "state_changed": state_changed }))
        }
        AdminOpBody::Remove { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Remove, actor);
            let handles_deleted = store.remove_audited(&id, ctx)?;
            // The count rides the wire so the CLI can tell an operator that live
            // capability handles just stopped resolving. Handles are bearer tokens
            // with no record of who holds them, so this is the only warning
            // available and it is only useful at the moment of the removal.
            Ok(serde_json::json!({
                "removed": true,
                "handles_deleted": handles_deleted,
            }))
        }
        AdminOpBody::MintHandle { id, .. } => {
            // The credential must exist before a handle is minted for it (the handles
            // table has no FK, so this guard is the check). meta() is a no-decrypt
            // plaintext read, so it works on any lifecycle state.
            store.meta(&id)?;
            let handle = mint_handle().map_err(|e| StoreOpError::Encode(format!("csprng: {e}")))?;
            let ctx = AuditCtx::route_admin(AuditOp::MintHandle, actor);
            store.put_handle_hash(&handle.hash, &id, ctx)?;
            // The raw handle is returned ONCE here; only its hash is persisted.
            Ok(serde_json::json!({ "handle": handle.raw }))
        }
        AdminOpBody::RevokeHandle { handle, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            // `revoked` stays for wire compatibility; `credential_id` is the new fact and
            // is null when nothing matched, which is the case an operator needs to see.
            let owner = store.revoke_handle(&handle, ctx)?;
            Ok(serde_json::json!({
                "revoked": owner.is_some(),
                "credential_id": owner,
            }))
        }
        AdminOpBody::RevokeHandleByHash { handle_hash, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            let owner = store.revoke_handle_by_hash_audited(&handle_hash, ctx)?;
            Ok(serde_json::json!({
                "revoked": owner.is_some(),
                "credential_id": owner,
            }))
        }
        AdminOpBody::RevokeAllHandles { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            let n = store.revoke_all_handles(&id, ctx)?;
            Ok(serde_json::json!({ "handles_revoked": n }))
        }
        AdminOpBody::GrantCreate {
            principal_id,
            credential_prefix,
            operation,
            ..
        } => {
            let ctx = AuditCtx::route_admin(AuditOp::GrantCreate, actor);
            store.create_read_grant_audited(
                "reserved",
                &principal_id,
                SelectorKind::Exact,
                &credential_prefix,
                operation,
                ctx,
            )?;
            Ok(serde_json::json!({ "grant_created": true }))
        }
        AdminOpBody::GrantRevoke {
            principal_id,
            credential_prefix,
            operation,
            ..
        } => {
            let ctx = AuditCtx::route_admin(AuditOp::GrantRevoke, actor);
            store.revoke_read_grant_audited(
                "reserved",
                &principal_id,
                SelectorKind::Exact,
                &credential_prefix,
                operation,
                ctx,
            )?;
            Ok(serde_json::json!({ "grant_revoked": true }))
        }
        AdminOpBody::GrantCreateV2 {
            principal_kind,
            principal_id,
            selector_kind,
            selector,
            operation,
            ..
        } => {
            let stored_selector = match selector_kind {
                SelectorKind::Exact => selector,
                SelectorKind::Category => {
                    if !crate::catalog::valid_category_name(&selector) {
                        return Err(StoreOpError::InvalidCategoryName);
                    }
                    format!("category:{selector}")
                }
            };
            store.create_read_grant_audited(
                &principal_kind,
                &principal_id,
                selector_kind,
                &stored_selector,
                operation,
                AuditCtx::route_admin(AuditOp::GrantCreate, actor),
            )?;
            Ok(serde_json::json!({ "grant_created": true }))
        }
        AdminOpBody::GrantRevokeV2 {
            principal_kind,
            principal_id,
            selector_kind,
            selector,
            operation,
            ..
        } => {
            let stored_selector = match selector_kind {
                SelectorKind::Exact => selector,
                SelectorKind::Category => {
                    if !crate::catalog::valid_category_name(&selector) {
                        return Err(StoreOpError::InvalidCategoryName);
                    }
                    format!("category:{selector}")
                }
            };
            store.revoke_read_grant_audited(
                &principal_kind,
                &principal_id,
                selector_kind,
                &stored_selector,
                operation,
                AuditCtx::route_admin(AuditOp::GrantRevoke, actor),
            )?;
            Ok(serde_json::json!({ "grant_revoked": true }))
        }
        AdminOpBody::SetCategory {
            credential_id,
            mode,
            categories,
            ..
        } => {
            let changed = store.set_categories_audited(
                &credential_id,
                mode,
                &categories,
                AuditCtx::route_admin(AuditOp::SetCategory, actor),
            )?;
            Ok(serde_json::json!({ "category_changed": changed }))
        }
        AdminOpBody::Reclassify { force, .. } => {
            let changed = store
                .reclassify_audited(force, AuditCtx::route_admin(AuditOp::SetCategory, actor))?;
            Ok(serde_json::json!({ "credentials_reclassified": changed }))
        }
        AdminOpBody::Status { .. } => {
            // A no-decrypt inventory plus the same fail-closed health summary used by
            // the probe, so `ck auth status` explains a degraded health result from one
            // authenticated read. No mutation, no audit.
            let metas = store.list_meta()?;
            let grants = store.list_read_grants()?;
            let open_intents = store.list_intents()?.len();
            Ok(status_result(
                &metas,
                &grants,
                open_intents,
                store.is_fenced_out(),
            ))
        }
    }
}

/// Build the status report shared by the authenticated route and lease-free CLI fallback.
pub fn status_result(
    metas: &[(String, RecordMeta)],
    grants: &[ReadGrant],
    open_intents: usize,
    fenced_out: bool,
) -> serde_json::Value {
    let health = crate::health::VaultHealth::summarize(metas, open_intents, fenced_out);
    let credentials: Vec<serde_json::Value> = metas
        .iter()
        .map(|(id, m)| {
            serde_json::json!({
                "id": id,
                "state": m.state.as_str(),
                "record_version": m.record_version,
                "categories": m.categories,
            })
        })
        .collect();
    // Both source lists are SQL-sorted, and the filter retains credential order.
    // Grants are ordered by principal, prefix, then operation so the complete
    // authority set is stable across repeated status reads. Stable covered-set
    // output makes an added credential under an existing prefix
    // visible in a status diff instead of silently widening access.
    let read_grants: Vec<serde_json::Value> = grants
        .iter()
        .map(|grant| {
            let covered_credential_ids: Vec<&str> = metas
                .iter()
                .filter(|(id, meta)| match grant.selector_kind {
                    SelectorKind::Exact => id.starts_with(&grant.selector),
                    SelectorKind::Category => meta
                        .categories
                        .iter()
                        .any(|category| grant.selector == format!("category:{category}")),
                })
                .map(|(id, _)| id.as_str())
                .collect();
            serde_json::json!({
                "principal_kind": grant.principal_kind,
                "principal_id": grant.principal_id,
                "selector_kind": grant.selector_kind.as_str(),
                "credential_prefix": grant.selector,
                "operation": grant.operation.as_str(),
                "created_at_ms": grant.created_at_ms,
                "covered_credential_ids": covered_credential_ids,
            })
        })
        .collect();
    serde_json::json!({
        "status": health.status.as_str(),
        "credentials_total": health.credentials_total,
        "active": health.active,
        "needs_reauth": health.needs_reauth,
        "retired": health.retired,
        "corrupt": health.corrupt,
        "needs_reauth_ids": health.needs_reauth_ids,
        "retired_ids": health.retired_ids,
        "corrupt_ids": health.corrupt_ids,
        "open_intents": health.open_intents,
        "fenced_out": health.fenced_out,
        "credentials": credentials,
        "read_grants": read_grants,
    })
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
    /// Legacy unconditional overwrite. Its serialized shape remains frozen for old
    /// clients; identity-aware replacements use `admin.store_with_identity_policy`.
    ReplaceUnconditional,
    /// CAS overwrite gated on the current payload hash (lowercase hex).
    ReplaceCas { expected_hash_hex: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::CredentialKind;

    /// A capability handle never reaches a `Debug` rendering.
    ///
    /// `RevokeHandle.handle` is the RAW `ckh_...` bearer -- `apply` hands it to
    /// `store.revoke_handle`, which hashes it there. Unlike an encrypted payload, a
    /// handle in a log needs no key and no vault access: whoever reads the line holds
    /// the credential it grants.
    ///
    /// Asserts the marker is present as well as the secret absent, so an impl that
    /// rendered nothing cannot pass.
    #[test]
    fn debug_never_renders_a_capability_handle() {
        let op = AdminOpBody::RevokeHandle {
            v: 1,
            handle: "ckh_LIVEBEARERTOKENVALUE".to_string(),
        };
        let rendered = format!("{op:?}");
        assert!(
            !rendered.contains("ckh_LIVEBEARERTOKENVALUE"),
            "a live capability handle rendered into Debug output: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "the redaction marker must be present, or an empty rendering would pass: \
             {rendered}"
        );
    }

    /// The boxed record inside `Store` is redacted transitively.
    ///
    /// Pins the delegation rather than assuming it: if `VaultRecord` ever went back to a
    /// derived `Debug`, this enum's careful impl would start leaking through a field it
    /// does not itself redact.
    #[test]
    fn debug_of_store_does_not_render_the_boxed_records_payload() {
        let record = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "operator",
            b"sk-INNER".to_vec(),
            None,
        );
        let op = AdminOpBody::Store {
            v: 1,
            id: "apikey:x".to_string(),
            record: Box::new(record),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::Create,
        };
        let rendered = format!("{op:?}");
        assert!(
            !rendered.contains("sk-INNER"),
            "the boxed record's payload rendered as text: {rendered}"
        );
        assert!(
            !rendered.contains("115, 107, 45, 73"),
            "the boxed record's payload rendered as bytes: {rendered}"
        );
    }

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

    #[test]
    fn legacy_unconditional_store_bytes_remain_compatible() {
        let op = AdminOpBody::Store {
            v: 1,
            id: "apikey:x".into(),
            record: Box::new(VaultRecord::new_static(
                CredentialKind::ApiKey,
                "t",
                b"k".to_vec(),
                None,
            )),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::ReplaceUnconditional,
        };
        assert_eq!(
            String::from_utf8(op.to_bytes().unwrap()).unwrap(),
            "{\"op\":\"admin.store\",\"v\":1,\"id\":\"apikey:x\",\"record\":{\"schema_version\":1,\"kind\":\"api_key\",\"source\":\"t\",\"record_version\":1,\"expires_at_ms\":null,\"refresh_adapter\":null,\"oauth\":null,\"payload\":[107]},\"audit_op\":\"put\",\"mode\":{\"kind\":\"replace_unconditional\"}}"
        );
    }

    #[test]
    fn identity_policy_store_op_round_trips() {
        let raw = b"{\"op\":\"admin.store_with_identity_policy\",\"v\":1,\"id\":\"apikey:x\",\"record\":{\"schema_version\":1,\"kind\":\"api_key\",\"source\":\"t\",\"record_version\":1,\"expires_at_ms\":null,\"refresh_adapter\":null,\"oauth\":null,\"payload\":[107]},\"audit_op\":\"put\",\"clear_identity\":false}";
        let op: AdminOpBody = serde_json::from_slice(raw).expect("new policy op decodes");
        assert_eq!(op.to_bytes().unwrap(), raw);
    }
}

#[cfg(test)]
mod admin_schema_v2_tests {
    use super::*;
    use crate::record::CredentialKind;

    fn record() -> Box<VaultRecord> {
        Box::new(VaultRecord::new_static(
            CredentialKind::ApiKey,
            "test",
            b"key".to_vec(),
            None,
        ))
    }

    #[test]
    fn every_admin_variant_is_listed_in_version_and_lock_tables() {
        let v1 = ADMIN_OP_SCHEMA_V1;
        let v2 = ADMIN_OP_SCHEMA_V2;
        let variants: Vec<(&str, AdminOpBody, u32, Option<&str>)> = vec![
            (
                "Store",
                AdminOpBody::Store {
                    v: v1,
                    id: "id".into(),
                    record: record(),
                    audit_op: AdminAuditOp::Put,
                    mode: StoreMode::Create,
                },
                v1,
                Some("id"),
            ),
            (
                "StoreWithIdentityPolicy",
                AdminOpBody::StoreWithIdentityPolicy {
                    v: v1,
                    id: "id".into(),
                    record: record(),
                    audit_op: AdminAuditOp::Put,
                    clear_identity: false,
                },
                v1,
                Some("id"),
            ),
            (
                "SetIdentity",
                AdminOpBody::SetIdentity {
                    v: v1,
                    id: "id".into(),
                    identity: RecordIdentity::default(),
                },
                v1,
                Some("id"),
            ),
            (
                "Invalidate",
                AdminOpBody::Invalidate {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "Logout",
                AdminOpBody::Logout {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "Reactivate",
                AdminOpBody::Reactivate {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "Remove",
                AdminOpBody::Remove {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "MintHandle",
                AdminOpBody::MintHandle {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "RevokeHandle",
                AdminOpBody::RevokeHandle {
                    v: v1,
                    handle: "secret".into(),
                },
                v1,
                None,
            ),
            (
                "RevokeHandleByHash",
                AdminOpBody::RevokeHandleByHash {
                    v: v1,
                    handle_hash: "hash".into(),
                },
                v1,
                None,
            ),
            (
                "RevokeAllHandles",
                AdminOpBody::RevokeAllHandles {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "GrantCreate",
                AdminOpBody::GrantCreate {
                    v: v1,
                    principal_id: "p".into(),
                    credential_prefix: "a:".into(),
                    operation: GrantOperation::Read,
                },
                v1,
                None,
            ),
            (
                "GrantRevoke",
                AdminOpBody::GrantRevoke {
                    v: v1,
                    principal_id: "p".into(),
                    credential_prefix: "a:".into(),
                    operation: GrantOperation::Read,
                },
                v1,
                None,
            ),
            (
                "Approval",
                AdminOpBody::Approval {
                    v: v1,
                    credential_id: "id".into(),
                    artifact_sha256: "00".repeat(32),
                    approver: "operator".into(),
                },
                v1,
                Some("id"),
            ),
            ("Status", AdminOpBody::Status { v: v1 }, v1, None),
            (
                "GrantCreateV2",
                AdminOpBody::GrantCreateV2 {
                    v: v2,
                    principal_kind: "reserved".into(),
                    principal_id: "p".into(),
                    selector_kind: SelectorKind::Category,
                    selector: "llm-provider".into(),
                    operation: GrantOperation::Read,
                },
                v2,
                None,
            ),
            (
                "GrantRevokeV2",
                AdminOpBody::GrantRevokeV2 {
                    v: v2,
                    principal_kind: "reserved".into(),
                    principal_id: "p".into(),
                    selector_kind: SelectorKind::Category,
                    selector: "llm-provider".into(),
                    operation: GrantOperation::Read,
                },
                v2,
                None,
            ),
            (
                "SetCategory",
                AdminOpBody::SetCategory {
                    v: v2,
                    credential_id: "id".into(),
                    mode: SetCategoryMode::Set,
                    categories: vec!["llm-provider".into()],
                },
                v2,
                Some("id"),
            ),
            (
                "Reclassify",
                AdminOpBody::Reclassify {
                    v: v2,
                    force: false,
                },
                v2,
                None,
            ),
        ];
        for (name, op, version, lock) in variants {
            assert_eq!(op.schema_version(), version, "{name} schema field");
            assert_eq!(op.required_schema_version(), version, "{name} pairing row");
            assert!(op.has_valid_schema_version(), "{name} must be admitted");
            assert_eq!(op.lock_id(), lock, "{name} lock row");
        }

        assert!(!AdminOpBody::Invalidate {
            v: v2,
            id: "id".into()
        }
        .has_valid_schema_version());
        assert!(!AdminOpBody::Reclassify {
            v: v1,
            force: false
        }
        .has_valid_schema_version());
    }
}
