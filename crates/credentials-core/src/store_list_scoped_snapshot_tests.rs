//! List scoped snapshot tests for the encrypted store.

use super::*;
use crate::record::RecordIdentity;
use crate::store::taxonomy_tests::{api_record, rig};

#[test]
fn scoped_list_reads_gateway_settings_once_regardless_of_visible_row_count() {
    use super::gateway::GATEWAY_SETTINGS_QUERIES;

    let (_root, store) = rig("scoped-gateway-query-count", 89);
    for count in [2, 6] {
        for index in if count == 2 { 0..2 } else { 2..6 } {
            let id = format!("apikey:gateway-query:{index}");
            store
                .create_audited(&id, &api_record(), AuditCtx::admin(AuditOp::Put))
                .unwrap();
            store
                .create_read_grant_audited(
                    "reserved",
                    "consumer",
                    SelectorKind::Exact,
                    &id,
                    GrantOperation::List,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
        }

        GATEWAY_SETTINGS_QUERIES.with(|queries| queries.set(0));
        let snapshot = store
            .list_scoped_snapshot("reserved", "consumer", &DeclaredGrantSet::empty())
            .unwrap();
        assert_eq!(snapshot.rows.len(), count);
        assert_eq!(
            GATEWAY_SETTINGS_QUERIES.with(std::cell::Cell::get),
            1,
            "visible rows: {count}"
        );
    }
}

#[test]
fn list_scoped_copies_only_covered_envelopes() {
    use super::grants::SCOPED_ENVELOPE_COPIES;

    let (_root, store) = rig("list-copy-count", 89);
    let covered_id = "apikey:zai";
    store
        .create_audited(covered_id, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    let unrelated =
        VaultRecord::new_static(CredentialKind::ApiKey, "test", vec![b'x'; 32 * 1024], None);
    for i in 0..8 {
        store
            .create_audited(
                &format!("operator:unrelated-{i}"),
                &unrelated,
                AuditCtx::admin(AuditOp::Put),
            )
            .unwrap();
    }
    for (kind, selector, operation) in [
        (SelectorKind::Exact, covered_id, GrantOperation::Sign),
        (SelectorKind::Category, "llm-provider", GrantOperation::Read),
    ] {
        store
            .create_read_grant_audited(
                "reserved",
                "consumer",
                kind,
                selector,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }

    SCOPED_ENVELOPE_COPIES.with(|count| count.set(0));
    let listed = store
        .list_scoped_snapshot("reserved", "consumer", &DeclaredGrantSet::empty())
        .unwrap();
    assert_eq!(listed.rows.len(), 1);
    assert_eq!(listed.rows[0].id, covered_id);
    assert_eq!(listed.rows[0].operations.len(), 2);
    assert!(listed.rows[0].operations.contains(&GrantOperation::Read));
    assert!(listed.rows[0].operations.contains(&GrantOperation::Sign));
    assert_eq!(SCOPED_ENVELOPE_COPIES.with(std::cell::Cell::get), 1);
}

#[test]
fn list_scoped_with_only_an_audience_grant_does_not_query_local_rows() {
    let (_root, store) = rig("list-no-local-grants", 89);
    store
        .create_read_grant_audited(
            "reserved",
            "ckbus",
            SelectorKind::Audience,
            "cortexkit-hub",
            GrantOperation::AccountToken,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();

    // With neither local table available, even preparing a local query would fail.
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "ALTER TABLE credentials RENAME TO unused_credentials;
                 ALTER TABLE credential_categories RENAME TO unused_categories;",
            )
        })
        .unwrap();
    let listed = store
        .list_scoped_snapshot("reserved", "ckbus", &DeclaredGrantSet::empty())
        .expect("audience coverage does not require local credential rows");
    assert!(listed.rows.is_empty());
    assert_eq!(listed.grants.len(), 1);
}

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
