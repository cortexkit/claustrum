//! Audit target delimiter tests for the encrypted store.

use super::*;
use crate::store::taxonomy_tests::rig;

#[test]
fn new_audit_targets_split_on_first_separator_and_refuse_ambiguous_ids() {
    let (_root, store) = rig("audit-target-separator", 88);
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "apikey:|tenant",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let target = store
        .read_audit(None)
        .unwrap()
        .last()
        .unwrap()
        .credential_id
        .as_deref()
        .unwrap()
        .to_string();
    let (left, right) = target.split_once('|').expect("new target delimiter");
    assert_eq!(left, "grant:read:reserved:consumer:exact");
    assert_eq!(
        right, "apikey:|tenant",
        "later separators belong to the selector"
    );
    let count = store.read_audit(None).unwrap().len();
    assert!(matches!(
        store.create_read_grant_audited(
            "reserved",
            "bad|principal",
            SelectorKind::Exact,
            "apikey:",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        ),
        Err(StoreOpError::InvalidPrincipal)
    ));
    assert!(matches!(
        store.set_categories_audited(
            "bad|credential",
            SetCategoryMode::Set,
            &["monitoring".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        ),
        Err(StoreOpError::InvalidCredentialId)
    ));
    assert_eq!(store.read_audit(None).unwrap().len(), count);
}
