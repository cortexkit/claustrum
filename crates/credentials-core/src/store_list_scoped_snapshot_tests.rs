//! List scoped snapshot tests for the encrypted store.

use super::*;
use crate::record::RecordIdentity;
use crate::store::taxonomy_tests::{api_record, rig};

#[test]
fn list_scoped_keeps_grants_candidates_and_categories_in_one_snapshot() {
    let (root, store) = rig("list-snapshot", 89);
    store
        .create_audited("apikey:zai", &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let path = root.join("store.db");
    let snapshot = store
            .list_scoped_snapshot_with_hook("reserved", "consumer", || {
                let writer = rusqlite::Connection::open(&path)?;
                let tx = writer.unchecked_transaction()?;
                tx.execute(
                    "DELETE FROM credential_categories WHERE credential_id = 'apikey:zai'",
                    [],
                )?;
                tx.execute(
                    "INSERT INTO credential_categories (credential_id, category) VALUES ('apikey:zai', 'monitoring')",
                    [],
                )?;
                tx.commit()
            })
            .expect("snapshot remains readable while a later writer commits");
    assert_eq!(
        snapshot.rows.len(),
        1,
        "the category grant saw the old category set"
    );
    assert_eq!(snapshot.rows[0].categories, ["llm-provider", "web-search"]);
    assert_eq!(store.categories("apikey:zai").unwrap(), ["monitoring"]);
}

#[test]
fn list_scoped_opens_identity_only_for_read_and_fails_the_whole_read_on_bad_material() {
    let (_root, store) = rig("list-open-policy", 90);
    let record = api_record().with_identity(RecordIdentity {
        account_id: Some("account".into()),
        email: Some("account@example.test".into()),
        org_name: None,
    });
    store
        .create_audited("operator:identity", &record, AuditCtx::admin(AuditOp::Put))
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "operator:identity",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let readable = store
        .list_scoped_snapshot(
            "reserved",
            "consumer",
            &crate::store::DeclaredGrantSet::empty(),
        )
        .unwrap();
    assert_eq!(
        readable.rows[0]
            .identity
            .as_ref()
            .unwrap()
            .account_id
            .as_deref(),
        Some("account")
    );
    store
        .revoke_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "operator:identity",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantRevoke),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "operator:identity",
            GrantOperation::Sign,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = X'00' WHERE credential_id = 'operator:identity'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let sign_only = store
        .list_scoped_snapshot(
            "reserved",
            "consumer",
            &crate::store::DeclaredGrantSet::empty(),
        )
        .expect("sign-only rows never open envelopes");
    assert_eq!(sign_only.rows.len(), 1);
    assert_eq!(sign_only.rows[0].identity, None);

    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "operator:identity",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    assert!(
        store
            .list_scoped_snapshot("reserved", "consumer", &DeclaredGrantSet::empty())
            .is_err(),
        "an unreadable row still stored as active fails the whole snapshot"
    );

    // Once quarantined, the same row lists sealed with state `corrupt`, and the
    // other rows the caller reaches still list.
    store
        .create_audited(
            "operator:healthy",
            &api_record(),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "operator:healthy",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE credentials SET state = 'corrupt' WHERE credential_id = 'operator:identity'",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
    let listed = store
        .list_scoped_snapshot(
            "reserved",
            "consumer",
            &crate::store::DeclaredGrantSet::empty(),
        )
        .expect("a quarantined row must not fail the listing");
    assert_eq!(listed.rows.len(), 2);
    let quarantined = listed
        .rows
        .iter()
        .find(|row| row.id == "operator:identity")
        .unwrap();
    assert_eq!(quarantined.state, RecordState::Corrupt);
    assert_eq!(quarantined.identity, None);
    assert!(listed
        .rows
        .iter()
        .any(|row| row.id == "operator:healthy" && row.state == RecordState::Active));
}
