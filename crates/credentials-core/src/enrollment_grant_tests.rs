use super::*;
use crate::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2};
use crate::enrollment::EnrollmentPoll;

fn enroll(store: &EncryptedStore) -> String {
    let secret = "ad".repeat(32);
    let request = store
        .propose_enrollment("consumer", &enrollment_secret_hash(&secret).unwrap())
        .unwrap();
    store
        .approve_enrollment(&request.request_id, "consumer", "operator")
        .unwrap();
    match store.poll_enrollment(&request.request_id, &secret).unwrap() {
        EnrollmentPoll::Approved { token, .. } => token,
        other => panic!("expected approved, got {other:?}"),
    }
}

fn grant(
    store: &EncryptedStore,
    kind: &str,
    name: &str,
    selector: SelectorKind,
    operation: GrantOperation,
) {
    store
        .create_read_grant_audited(
            kind,
            name,
            selector,
            if selector == SelectorKind::Category {
                "llm-provider"
            } else {
                "apikey:one"
            },
            operation,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
}

#[test]
fn enrollment_revoke_removes_and_audits_every_grant_and_returns_exact_rows() {
    let (_root, store) = super::taxonomy_tests::rig("enrollment-revoke-grants", 163);
    let token = enroll(&store);
    grant(
        &store,
        "enrolled",
        "consumer",
        SelectorKind::Exact,
        GrantOperation::Read,
    );
    grant(
        &store,
        "enrolled",
        "consumer",
        SelectorKind::Exact,
        GrantOperation::Sign,
    );
    grant(
        &store,
        "enrolled",
        "consumer",
        SelectorKind::Category,
        GrantOperation::List,
    );
    grant(
        &store,
        "reserved",
        "consumer",
        SelectorKind::Exact,
        GrantOperation::Read,
    );
    grant(
        &store,
        "enrolled",
        "other",
        SelectorKind::Exact,
        GrantOperation::Read,
    );
    let before_grants = store.list_read_grants().unwrap();
    let removed: Vec<_> = before_grants
        .iter()
        .filter(|g| g.principal_kind == "enrolled" && g.principal_id == "consumer")
        .collect();
    let before_generation = store.grants_generation().unwrap();
    let before_audit = store.read_audit(None).unwrap().len();
    let result = apply(
        &store,
        AdminOpBody::EnrollRevoke {
            v: ADMIN_OP_SCHEMA_V2,
            name: "consumer".into(),
        },
        "operator:revoker",
    )
    .unwrap();
    assert_eq!(
        result,
        serde_json::json!({
            "revoked": true,
            "removed_grants": [
                {"principal_kind":"enrolled", "principal_id":"consumer", "selector_kind":"category", "credential_prefix":"llm-provider", "operation":"list", "created_at_ms":removed[0].created_at_ms},
                {"principal_kind":"enrolled", "principal_id":"consumer", "selector_kind":"exact", "credential_prefix":"apikey:one", "operation":"read", "created_at_ms":removed[1].created_at_ms},
                {"principal_kind":"enrolled", "principal_id":"consumer", "selector_kind":"exact", "credential_prefix":"apikey:one", "operation":"sign", "created_at_ms":removed[2].created_at_ms}
            ]
        })
    );
    assert_eq!(
        store.list_read_grants().unwrap(),
        before_grants
            .into_iter()
            .filter(|g| g.principal_kind != "enrolled" || g.principal_id != "consumer")
            .collect::<Vec<_>>()
    );
    assert_eq!(store.grants_generation().unwrap(), before_generation + 1);
    assert_eq!(store.resolve_enrollment_token(&token).unwrap(), None);
    let audit = store.read_audit(None).unwrap();
    let appended = &audit[before_audit..];
    assert_eq!(appended.len(), 4);
    for (row, target) in appended[..3].iter().zip([
        "grant:list:enrolled:consumer:category|llm-provider",
        "grant:read:enrolled:consumer:exact|apikey:one",
        "grant:sign:enrolled:consumer:exact|apikey:one",
    ]) {
        assert_eq!(row.op, "grant_revoke");
        assert_eq!(row.credential_id.as_deref(), Some(target));
        assert_eq!(row.actor, "operator:revoker");
        assert_eq!(row.payload_hash, None);
    }
    assert_eq!(appended[3].op, "enroll.revoke");
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    // Removing the grants frees the name without handing the replacement any reach.
    enroll(&store);
    assert!(!store
        .list_read_grants()
        .unwrap()
        .iter()
        .any(|g| g.principal_kind == "enrolled" && g.principal_id == "consumer"));
}

#[test]
fn enrollment_approval_requires_explicit_consent_for_retained_or_preprovisioned_grants() {
    let (_root, store) = super::taxonomy_tests::rig("enrollment-retained-grants", 164);
    for had_enrollment in [false, true] {
        if had_enrollment {
            store.revoke_enrollment("consumer", "operator").unwrap();
        }
        // A grant on an unused name represents both preprovisioning and retained
        // grants from older revocations; neither may pass silently to a new consumer.
        grant(
            &store,
            "enrolled",
            "consumer",
            SelectorKind::Category,
            GrantOperation::Read,
        );
        let secret = if had_enrollment { "ae" } else { "af" }.repeat(32);
        let request = store
            .propose_enrollment("consumer", &enrollment_secret_hash(&secret).unwrap())
            .unwrap();
        let body = serde_json::json!({"op":"admin.enroll_approve", "v":2, "request_id":request.request_id, "final_name":"consumer"});
        let before = store.audit_tip().unwrap();
        let grants = store.list_read_grants().unwrap();
        let error = apply(
            &store,
            serde_json::from_value(body.clone()).unwrap(),
            "operator",
        )
        .unwrap_err();
        assert!(error.to_string().contains("--keep-grants"), "{error}");
        assert_eq!(store.audit_tip().unwrap(), before);
        assert_eq!(store.list_read_grants().unwrap(), grants);
        assert!(matches!(
            store.poll_enrollment(&request.request_id, &secret),
            Ok(EnrollmentPoll::Pending)
        ));
        let mut explicit = body;
        explicit["keep_grants"] = true.into();
        apply(
            &store,
            serde_json::from_value(explicit).unwrap(),
            "operator",
        )
        .unwrap();
        assert!(matches!(
            store.poll_enrollment(&request.request_id, &secret),
            Ok(EnrollmentPoll::Approved { .. })
        ));
        assert_eq!(store.list_read_grants().unwrap(), grants);
    }
}

#[test]
fn enrollment_rotation_preserves_grants_and_generation() {
    let (_root, store) = super::taxonomy_tests::rig("enrollment-rotation-grants", 165);
    let token = enroll(&store);
    grant(
        &store,
        "enrolled",
        "consumer",
        SelectorKind::Exact,
        GrantOperation::Read,
    );
    let grants = store.list_read_grants().unwrap();
    let generation = store.grants_generation().unwrap();
    let rotated = store.rotate_enrollment(&token, 1).unwrap();
    assert_eq!(store.resolve_enrollment_token(&token).unwrap(), None);
    assert_eq!(
        store.resolve_enrollment_token(&rotated.token).unwrap(),
        Some(("consumer".into(), 2))
    );
    assert_eq!(store.list_read_grants().unwrap(), grants);
    assert_eq!(store.grants_generation().unwrap(), generation);
}

#[test]
fn enrollment_revoke_rolls_back_grants_token_and_generation_on_audit_failure() {
    let (_root, store) = super::taxonomy_tests::rig("enrollment-revoke-rollback", 166);
    let token = enroll(&store);
    grant(
        &store,
        "enrolled",
        "consumer",
        SelectorKind::Exact,
        GrantOperation::Read,
    );
    let grants = store.list_read_grants().unwrap();
    let generation = store.grants_generation().unwrap();
    let audit = store.audit_tip().unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_enrollment_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op = 'enroll.revoke' BEGIN SELECT RAISE(ABORT, 'audit refused'); END;",
            )
        })
        .unwrap();
    assert!(store.revoke_enrollment("consumer", "operator").is_err());
    assert_eq!(
        store.resolve_enrollment_token(&token).unwrap(),
        Some(("consumer".into(), 1))
    );
    assert_eq!(store.list_read_grants().unwrap(), grants);
    assert_eq!(store.grants_generation().unwrap(), generation);
    assert_eq!(store.audit_tip().unwrap(), audit);
}
