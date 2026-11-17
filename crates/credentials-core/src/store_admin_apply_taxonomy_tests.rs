//! Admin apply taxonomy tests for the encrypted store.

use super::*;
use crate::admin_ops::{apply, AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1};
use crate::store::taxonomy_tests::{api_record, rig};

#[test]
fn every_deposit_arm_refuses_reserved_or_separator_ids_without_writing() {
    let (_root, store) = rig("invalid-deposit", 86);
    for id in ["category:anything", "apikey:bad|id"] {
        let operations = [
            AdminOpBody::Store {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.into(),
                record: Box::new(api_record()),
                audit_op: AdminAuditOp::Put,
                mode: StoreMode::Create,
            },
            AdminOpBody::Store {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.into(),
                record: Box::new(api_record()),
                audit_op: AdminAuditOp::Put,
                mode: StoreMode::ReplaceUnconditional,
            },
            AdminOpBody::Store {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.into(),
                record: Box::new(api_record()),
                audit_op: AdminAuditOp::Put,
                mode: StoreMode::ReplaceCas {
                    expected_hash_hex: "00".repeat(32),
                },
            },
            AdminOpBody::StoreWithIdentityPolicy {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.into(),
                record: Box::new(api_record()),
                audit_op: AdminAuditOp::Put,
                clear_identity: false,
            },
        ];
        for operation in operations {
            let error = apply(&store, operation, "test").expect_err("invalid id");
            assert!(matches!(&error, StoreOpError::InvalidCredentialId));
            assert_eq!(error.wire_code(), Some("invalid_credential_id"));
            assert_eq!(error.wire_class(), Some("permanent"));
        }
        assert!(matches!(store.meta(id), Err(StoreOpError::NotFound)));
    }
    assert!(store.read_audit(None).unwrap().is_empty());
}

#[test]
fn absent_replace_modes_remain_fail_closed_and_only_create_reaches_defaults() {
    let (_root, store) = rig("replace-contract", 87);
    for operation in [
        AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:zai".into(),
            record: Box::new(api_record()),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::ReplaceUnconditional,
        },
        AdminOpBody::StoreWithIdentityPolicy {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:zai".into(),
            record: Box::new(api_record()),
            audit_op: AdminAuditOp::Put,
            clear_identity: false,
        },
    ] {
        assert!(matches!(
            apply(&store, operation, "test"),
            Err(StoreOpError::NotFound)
        ));
    }
    assert!(store.categories("apikey:zai").unwrap().is_empty());
    apply(
        &store,
        AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:zai".into(),
            record: Box::new(api_record()),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::Create,
        },
        "test",
    )
    .unwrap();
    assert_eq!(
        store.categories("apikey:zai").unwrap(),
        ["llm-provider", "web-search"]
    );
    store
        .set_categories_audited(
            "apikey:zai",
            SetCategoryMode::Set,
            &[],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    apply(
        &store,
        AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:zai".into(),
            record: Box::new(api_record()),
            audit_op: AdminAuditOp::Overwrite,
            mode: StoreMode::ReplaceUnconditional,
        },
        "test",
    )
    .unwrap();
    assert!(
        store.categories("apikey:zai").unwrap().is_empty(),
        "re-login and replacement do not refill an intentionally empty set"
    );
}
