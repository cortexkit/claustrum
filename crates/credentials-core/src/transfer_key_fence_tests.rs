//! The transfer-key fence in core: the one grant `kem:vault-transfer:*` admits, the
//! handle it may never have, and the admin operations it refuses while it is `Active`.
//!
//! Every admin-op test follows the same shape: build the op the CLI sends, assert the
//! typed refusal, and assert that BOTH `record_version` and the stored state are exactly
//! what they were. A test that only asserted the error would pass for a fence placed
//! after the write.

use super::*;
use crate::admin_ops::{
    apply, AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};
use crate::federation::{
    is_vault_transfer_id, transfer_key_admits_grant, TRANSFER_ANNOUNCE_PRINCIPAL, VAULT_TRANSFER_ID,
};
use crate::store::taxonomy_tests::rig;

const ACTOR: &str = "route-admin";

fn transfer_record() -> VaultRecord {
    let pem = crate::kem::generate_key().expect("generate a transfer key");
    VaultRecord::new_static(CredentialKind::KemKey, "operator", pem.into_bytes(), None)
}

/// A vault with its transfer key created exactly as `ck auth transfer init` would: a
/// `KemKey` record at [`VAULT_TRANSFER_ID`], active, version 1.
fn rig_with_transfer_key(
    label: &str,
    seed: u8,
) -> (crate::test_support::TestTempDir, EncryptedStore) {
    let (root, store) = rig(label, seed);
    store
        .create_audited(
            VAULT_TRANSFER_ID,
            &transfer_record(),
            AuditCtx::route_admin(AuditOp::Put, ACTOR),
        )
        .expect("create the transfer key");
    (root, store)
}

/// The version and state of a record, read without decrypting.
fn version_and_state(store: &EncryptedStore, id: &str) -> (u64, RecordState) {
    let meta = store.meta(id).expect("the record must still be there");
    (meta.record_version, meta.state)
}

fn store_body(
    id: &str,
    record: VaultRecord,
    audit_op: AdminAuditOp,
    mode: StoreMode,
) -> AdminOpBody {
    AdminOpBody::Store {
        v: ADMIN_OP_SCHEMA_V1,
        id: id.to_string(),
        record: Box::new(record),
        audit_op,
        mode,
    }
}

fn static_record() -> VaultRecord {
    VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None)
}

/// One case of "this admin op is refused while the key is active, and changes nothing".
fn assert_protected(store: &EncryptedStore, op: AdminOpBody) {
    let before = version_and_state(store, VAULT_TRANSFER_ID);
    let result = apply(store, op, ACTOR);
    assert!(
        matches!(result, Err(StoreOpError::TransferKeyProtected)),
        "an op that would change the active transfer key must be refused by name: {result:?}"
    );
    assert_eq!(
        version_and_state(store, VAULT_TRANSFER_ID),
        before,
        "the refusal must leave both the version and the state untouched"
    );
}

// ---- the grant fence ----------------------------------------------------

/// Exactly one grant is admitted on the transfer key: the `read` that
/// `credential.public_key` needs for callosum to announce the public half.
#[test]
fn the_transfer_key_admits_only_the_callosum_announce_read() {
    for id in [
        VAULT_TRANSFER_ID,
        "kem:vault-transfer:2",
        "kem:vault-transfer:",
    ] {
        assert!(is_vault_transfer_id(id), "{id} is under the prefix");
        transfer_key_admits_grant(id, TRANSFER_ANNOUNCE_PRINCIPAL, GrantOperation::Read)
            .expect("the announce read is the one admitted grant");
        for operation in [
            GrantOperation::Sign,
            GrantOperation::Open,
            GrantOperation::List,
            GrantOperation::Deposit,
            GrantOperation::AccountToken,
            GrantOperation::Seal,
        ] {
            let refused = transfer_key_admits_grant(id, TRANSFER_ANNOUNCE_PRINCIPAL, operation)
                .expect_err("every other operation is refused");
            assert!(
                refused.contains("transfer_key_reserved"),
                "the refusal names the reason: {refused}"
            );
        }
        for principal in ["reserved:broca", "reserved:callosum-self", "callosum"] {
            assert!(
                transfer_key_admits_grant(id, principal, GrantOperation::Read).is_err(),
                "{principal} may not hold even the read on {id}"
            );
        }
    }
    // Ids outside the prefix are not this fence's business: the ordinary grant rules
    // still decide them.
    for id in [
        "kem:push",
        "kem:fleet-group",
        "kem:bus-seal",
        "apikey:vault-transfer:1",
    ] {
        assert!(!is_vault_transfer_id(id), "{id} is not a transfer key");
        transfer_key_admits_grant(id, "reserved:broca", GrantOperation::Open)
            .expect("an ordinary credential id passes the fence");
    }
}

/// The store's `SelectorKind::validate_operation` refuses the transfer key, at both
/// grant writers, and the admitted announce read still commits.
#[test]
fn the_store_refuses_every_transfer_key_grant_but_the_announce_read() {
    let (_root, store) = rig_with_transfer_key("transfer-grant", 220);
    let grant = |principal: &str, operation| {
        store.create_read_grant_audited(
            "reserved",
            principal,
            SelectorKind::Exact,
            VAULT_TRANSFER_ID,
            operation,
            AuditCtx::route_admin(AuditOp::GrantCreate, ACTOR),
        )
    };
    for operation in [
        GrantOperation::Sign,
        GrantOperation::Open,
        GrantOperation::List,
        GrantOperation::Seal,
    ] {
        assert!(
            matches!(
                grant("callosum", operation),
                Err(StoreOpError::TransferKeyReserved)
            ),
            "{operation:?} on the transfer key must be refused as transfer_key_reserved"
        );
    }
    assert!(matches!(
        grant("broca", GrantOperation::Read),
        Err(StoreOpError::TransferKeyReserved)
    ));
    assert!(
        store.list_read_grants().expect("grants").is_empty(),
        "no refused grant may be stored"
    );

    grant("callosum", GrantOperation::Read).expect(
        "the announce read, to reserved:callosum on the announce principal id, is admitted",
    );
    let grants = store.list_read_grants().expect("grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].selector, VAULT_TRANSFER_ID);
    assert_eq!(grants[0].operation, GrantOperation::Read);

    // Revocation applies the same rule, so the vault and a caller cannot disagree about
    // which grants the key may hold; the admitted read can still be revoked.
    for operation in [GrantOperation::Open, GrantOperation::Seal] {
        assert!(matches!(
            store.revoke_read_grant_audited(
                "reserved",
                "callosum",
                SelectorKind::Exact,
                VAULT_TRANSFER_ID,
                operation,
                AuditCtx::route_admin(AuditOp::GrantRevoke, ACTOR),
            ),
            Err(StoreOpError::TransferKeyReserved)
        ));
    }
    store
        .revoke_read_grant_audited(
            "reserved",
            "callosum",
            SelectorKind::Exact,
            VAULT_TRANSFER_ID,
            GrantOperation::Read,
            AuditCtx::route_admin(AuditOp::GrantRevoke, ACTOR),
        )
        .expect("the announce read is revocable");
    assert!(store.list_read_grants().expect("grants").is_empty());
}

/// `apply` runs the same fence for the CLI's grant verbs, so the daemon and the offline
/// lease path cannot disagree about it either.
#[test]
fn apply_refuses_a_transfer_key_grant_through_the_cli_verbs() {
    let (_root, store) = rig_with_transfer_key("transfer-grant-admin", 221);
    let refused = apply(
        &store,
        AdminOpBody::GrantCreateV2 {
            v: ADMIN_OP_SCHEMA_V2,
            principal_kind: "reserved".into(),
            principal_id: "callosum".into(),
            selector_kind: SelectorKind::Exact,
            selector: VAULT_TRANSFER_ID.into(),
            operation: GrantOperation::Open,
        },
        ACTOR,
    );
    assert!(
        matches!(refused, Err(StoreOpError::TransferKeyReserved)),
        "{refused:?}"
    );
    let revoked = apply(
        &store,
        AdminOpBody::GrantRevokeV2 {
            v: ADMIN_OP_SCHEMA_V2,
            principal_kind: "reserved".into(),
            principal_id: "callosum".into(),
            selector_kind: SelectorKind::Exact,
            selector: VAULT_TRANSFER_ID.into(),
            operation: GrantOperation::Seal,
        },
        ACTOR,
    );
    assert!(
        matches!(revoked, Err(StoreOpError::TransferKeyReserved)),
        "{revoked:?}"
    );
    assert!(store.list_read_grants().expect("grants").is_empty());
}

// ---- the handle fence ---------------------------------------------------

/// A handle on the transfer key would let its holder sign federation seals as this
/// vault, so minting one is refused, in every state, and no handle row is written.
#[test]
fn put_handle_hash_refuses_to_mint_a_transfer_key_handle() {
    let (_root, store) = rig_with_transfer_key("transfer-handle", 222);
    for state in [
        RecordState::Active,
        RecordState::NeedsReauth,
        RecordState::Corrupt,
    ] {
        store
            .force_vault_transfer_key_state_for_test(state)
            .expect("force the key's state");
        let raw = format!("ckh_transfer_{}", state.as_str());
        let result = store.put_handle_hash(
            &crate::store::handle_hash(&raw),
            VAULT_TRANSFER_ID,
            AuditCtx::route_admin(AuditOp::MintHandle, ACTOR),
        );
        assert!(
            matches!(result, Err(StoreOpError::TransferKeyReserved)),
            "a transfer-key handle must be refused while {state:?}: {result:?}"
        );
        assert!(
            store.resolve_handle(&raw).is_err(),
            "no handle may resolve after the refusal"
        );
    }
    let mint_rows = store
        .read_audit(None)
        .expect("audit")
        .into_iter()
        .filter(|entry| entry.op == AuditOp::MintHandle.as_str())
        .count();
    assert_eq!(mint_rows, 0, "a refused mint writes no audit entry");

    // An ordinary credential id still mints, so the refusal is the fence and not a
    // blanket disable of handle minting.
    store
        .create_audited(
            "apikey:zai",
            &static_record(),
            AuditCtx::vault(AuditOp::Put),
        )
        .expect("a local key");
    store
        .put_handle_hash(
            &crate::store::handle_hash("ckh_local"),
            "apikey:zai",
            AuditCtx::route_admin(AuditOp::MintHandle, ACTOR),
        )
        .expect("an ordinary handle still mints");
    assert_eq!(
        store.resolve_handle("ckh_local").expect("resolves"),
        "apikey:zai"
    );
}

// ---- the admin-op fence, one test per op --------------------------------

#[test]
fn put_replace_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-put", 230);
    assert_protected(
        &store,
        store_body(
            VAULT_TRANSFER_ID,
            transfer_record(),
            AdminAuditOp::Overwrite,
            StoreMode::ReplaceUnconditional,
        ),
    );
}

#[test]
fn import_replace_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-import", 231);
    assert_protected(
        &store,
        store_body(
            VAULT_TRANSFER_ID,
            transfer_record(),
            AdminAuditOp::Import,
            StoreMode::Create,
        ),
    );
}

#[test]
fn login_replace_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-login", 232);
    assert_protected(
        &store,
        store_body(
            VAULT_TRANSFER_ID,
            transfer_record(),
            AdminAuditOp::Login,
            StoreMode::ReplaceUnconditional,
        ),
    );
}

/// `mint-kem-key --replace` sends exactly this op: a `Put` in unconditional replace
/// mode on a `KemKey` record.
#[test]
fn mint_kem_key_replace_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-mint-kem", 233);
    let pem = crate::kem::generate_key().expect("generate");
    let replacement =
        VaultRecord::new_static(CredentialKind::KemKey, "operator", pem.into_bytes(), None);
    assert_protected(
        &store,
        store_body(
            VAULT_TRANSFER_ID,
            replacement,
            AdminAuditOp::Put,
            StoreMode::ReplaceUnconditional,
        ),
    );
}

/// The identity-policy replace is its own op discriminator and reaches a different
/// store function, so it needs its own case.
#[test]
fn the_identity_policy_replace_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-identity-policy", 234);
    assert_protected(
        &store,
        AdminOpBody::StoreWithIdentityPolicy {
            v: ADMIN_OP_SCHEMA_V1,
            id: VAULT_TRANSFER_ID.into(),
            record: Box::new(transfer_record()),
            audit_op: AdminAuditOp::Put,
            clear_identity: true,
        },
    );
}

/// The compare-and-set overwrite is a third replace contract in the store, and `apply`
/// reaches it through its own mode.
#[test]
fn the_cas_replace_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-cas", 235);
    let payload_hash = crate::store::payload_hash(
        store
            .get(VAULT_TRANSFER_ID)
            .expect("read the transfer key")
            .payload
            .expose(),
    );
    assert_protected(
        &store,
        store_body(
            VAULT_TRANSFER_ID,
            transfer_record(),
            AdminAuditOp::Put,
            StoreMode::ReplaceCas {
                expected_hash_hex: payload_hash
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            },
        ),
    );
}

#[test]
fn set_identity_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-identity", 236);
    assert_protected(
        &store,
        AdminOpBody::SetIdentity {
            v: ADMIN_OP_SCHEMA_V1,
            id: VAULT_TRANSFER_ID.into(),
            identity: RecordIdentity {
                account_id: Some("acct".into()),
                ..Default::default()
            },
        },
    );
}

#[test]
fn invalidate_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-invalidate", 237);
    assert_protected(
        &store,
        AdminOpBody::Invalidate {
            v: ADMIN_OP_SCHEMA_V1,
            id: VAULT_TRANSFER_ID.into(),
        },
    );
}

#[test]
fn logout_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-logout", 238);
    assert_protected(
        &store,
        AdminOpBody::Logout {
            v: ADMIN_OP_SCHEMA_V1,
            id: VAULT_TRANSFER_ID.into(),
        },
    );
}

/// Reactivation is refused on a key already off `Active` too: putting the key back
/// into service is the recovery command's decision, and its own transaction.
#[test]
fn reactivate_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-reactivate", 239);
    // On an `Active` key the operation changes nothing, so it stays a refusal rather
    // than a quiet success: an operator asking for a reactivation on the transfer key
    // must learn that this is not the route.
    let result = apply(
        &store,
        AdminOpBody::Reactivate {
            v: ADMIN_OP_SCHEMA_V1,
            id: VAULT_TRANSFER_ID.into(),
        },
        ACTOR,
    );
    assert!(
        matches!(result, Err(StoreOpError::TransferKeyProtected)),
        "{result:?}"
    );
    assert_eq!(
        version_and_state(&store, VAULT_TRANSFER_ID),
        (1, RecordState::Active)
    );
    store
        .force_vault_transfer_key_state_for_test(RecordState::NeedsReauth)
        .expect("force needs_reauth");
    assert_protected(
        &store,
        AdminOpBody::Reactivate {
            v: ADMIN_OP_SCHEMA_V1,
            id: VAULT_TRANSFER_ID.into(),
        },
    );
}

#[test]
fn remove_is_refused_on_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-remove", 240);
    assert_protected(
        &store,
        AdminOpBody::Remove {
            v: ADMIN_OP_SCHEMA_V1,
            id: VAULT_TRANSFER_ID.into(),
        },
    );
}

/// `transfer init --replace` is that same unconditional replace, and it is refused while
/// the key is active and admitted once a test-only hook puts the key off `Active`. The
/// hook stands in for the store damage that is the only way a live vault reaches
/// `needs_reauth` here, because no operation path may move the key off `Active`.
#[test]
fn transfer_init_replace_is_refused_active_and_admitted_off_active() {
    let (_root, store) = rig_with_transfer_key("transfer-init", 241);
    let replace = || {
        store_body(
            VAULT_TRANSFER_ID,
            transfer_record(),
            AdminAuditOp::Overwrite,
            StoreMode::ReplaceUnconditional,
        )
    };
    assert_protected(&store, replace());

    assert!(
        store
            .force_vault_transfer_key_state_for_test(RecordState::NeedsReauth)
            .expect("the test-only hook forces the key off active"),
        "the hook must have found the transfer key"
    );
    assert_eq!(
        store.vault_transfer_key_state().expect("state"),
        Some(RecordState::NeedsReauth)
    );
    apply(&store, replace(), ACTOR).expect("replace is admitted once the key is off active");
    assert_eq!(version_and_state(&store, VAULT_TRANSFER_ID).0, 2);
    // The replacement is written active again, so the fences come back with it.
    assert_eq!(
        store.vault_transfer_key_state().expect("state"),
        Some(RecordState::Active)
    );
    assert_protected(&store, replace());
}

/// The read surface's quarantine path reaches the internal state writer, so the fence
/// sits there too: no caller-directed report (a consumer's `report_auth_failure`) or
/// integrity flip may move the key off `Active`.
#[test]
fn the_internal_state_writers_cannot_move_the_active_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-quarantine", 242);
    for result in [
        store.quarantine(VAULT_TRANSFER_ID).map(|_| ()),
        store
            .quarantine_if_version(VAULT_TRANSFER_ID, 1)
            .map(|_| ()),
        store.mark_needs_reauth_retaining_intent(VAULT_TRANSFER_ID),
        store
            .mark_stale_if_version_reported(
                VAULT_TRANSFER_ID,
                1,
                AuditCtx::route_admin(AuditOp::ReportAuthFailure, ACTOR),
                AuthObservation {
                    kind: "consumer_report_stale",
                    provider_status: Some(401),
                    detail: None,
                    reporter_source: None,
                    principal: None,
                },
            )
            .map(|_| ()),
        store
            .invalidate_if_version_reported(
                VAULT_TRANSFER_ID,
                1,
                AuditCtx::route_admin(AuditOp::ReportAuthFailure, ACTOR),
                None,
            )
            .map(|_| ()),
        store.invalidate(VAULT_TRANSFER_ID).map(|_| ()),
    ] {
        match result {
            Err(StoreOpError::TransferKeyProtected) => {}
            other => panic!("every state write on the active key is refused by name: {other:?}"),
        }
    }
    assert_eq!(
        version_and_state(&store, VAULT_TRANSFER_ID),
        (1, RecordState::Active)
    );
}

/// A non-kem id under no prefix is unaffected, so the fence is not a blanket refusal of
/// every admin op.
#[test]
fn ordinary_admin_operations_still_apply_around_the_transfer_key() {
    let (_root, store) = rig_with_transfer_key("transfer-ordinary", 243);
    store
        .create_audited(
            "apikey:zai",
            &static_record(),
            AuditCtx::vault(AuditOp::Put),
        )
        .expect("create");
    apply(
        &store,
        AdminOpBody::Invalidate {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:zai".into(),
        },
        ACTOR,
    )
    .expect("an ordinary invalidation still applies");
    assert_eq!(
        version_and_state(&store, "apikey:zai"),
        (1, RecordState::NeedsReauth)
    );
    apply(
        &store,
        AdminOpBody::Reactivate {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:zai".into(),
        },
        ACTOR,
    )
    .expect("an ordinary reactivation still applies");
    assert_eq!(
        version_and_state(&store, "apikey:zai"),
        (1, RecordState::Active)
    );
    assert_eq!(store.verify_audit_chain().expect("chain"), None);
}
