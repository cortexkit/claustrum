use super::*;
use crate::audit::AuditOp;
use crate::federation::{
    MemberGrantOperation, MemberGrantSelector, NewRemoteRecord, RemoteHomeState, RemoteWatchRow,
    VAULT_TRANSFER_ID,
};
use crate::record::RecordIdentity;
use crate::store::{
    migrate_through_for_test,
    taxonomy_tests::{rig, sqlite},
    GhManifestSource, GhManifestVersion, HubLoginApply, HubLoginApplyMode,
    HUB_ENTRIES_SCHEMA_VERSION,
};
use crate::{CredentialKind, MasterKey, VaultRecord};

const HOME: &str = "fed-computer:0123456789abcdef0123456789abcdef";
const PEER: &str = "fed-computer:fedcba9876543210fedcba9876543210";
const BOX_1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOX_2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ACTIVATION: AuditCtx<'static> = AuditCtx {
    op: AuditOp::GhManifestActivation,
    actor: "vault",
    alarm: None,
};

fn report(member_id: &str) -> GhManifestActivationReport<'_> {
    GhManifestActivationReport {
        member_id,
        version: 28,
        payload_sha256: HASH,
        verdict: GhManifestVerdict::Valid,
        reason: None,
        reported_at_ms: 100,
    }
}

fn seed_self_and_manifest(store: &EncryptedStore) {
    store
        .set_federation_self_member_audited(HOME, AuditCtx::vault(AuditOp::FederationSelfSet))
        .unwrap();
    store
        .store_gh_manifest(
            &GhManifestVersion {
                version: 28,
                manifest_bytes: b"{}",
                manifest_sha256: HASH,
                key_id: "key",
                signature: &[7; 64],
                signed_at_ms: 7,
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
}

fn grant_peer(store: &EncryptedStore, pairing: &str) {
    assert!(store
        .create_member_grant_audited(
            PEER,
            MemberGrantOperation::SecretUse,
            &MemberGrantSelector::None,
            pairing
        )
        .unwrap());
}

fn sql(store: &EncryptedStore, statement: &str) {
    store
        .with_raw_conn(|conn| conn.execute_batch(statement))
        .unwrap();
}

#[test]
fn hub_migration_clears_self_and_peer_fields_but_keeps_roster_retirement_and_audits() {
    let (_root, sqlite) = sqlite("hub-migration", 181);
    migrate_through_for_test(&sqlite, HUB_ENTRIES_SCHEMA_VERSION - 1).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([181; 32])).unwrap();
    seed_self_and_manifest(&store);
    grant_peer(&store, "pair");
    store
        .seed_gh_manifest_activation_for_tests(&report(HOME), ACTIVATION)
        .unwrap();
    store
        .seed_gh_manifest_activation_for_tests(&report(PEER), ACTIVATION)
        .unwrap();
    store
        .seed_gh_manifest_activation_for_tests(&report("retired"), ACTIVATION)
        .unwrap();
    store
        .retire_gh_manifest_member("retired", 123, AuditCtx::admin(AuditOp::GhManifestRetire))
        .unwrap();
    let audit = store.read_audit(None).unwrap();
    // The status reader also reads the signed-policy table from a later migration, so
    // check the reports that make this version ready directly at this older schema.
    let ready_reports: i64 = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT count(*) FROM gh_manifest_activations \
                 WHERE version = 28 AND verdict = 'valid' AND retired_at_ms IS NULL",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(ready_reports, 2);

    EncryptedStore::migrate(&store.store).unwrap();
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(!status.ready);
    assert_eq!(status.computers.len(), 2);
    let states = store.with_raw_conn(|conn| {
        let mut stmt = conn.prepare("SELECT member_id, retired_at_ms FROM gh_manifest_activations \
            WHERE version IS NULL AND payload_sha256 IS NULL AND verdict IS NULL AND reason IS NULL AND reported_at_ms IS NULL \
            ORDER BY member_id")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>();
        rows
    }).unwrap();
    assert_eq!(
        states,
        [
            (HOME.into(), None),
            (PEER.into(), None),
            ("retired".into(), Some(123))
        ]
    );
    assert!(store.hub_own_report().unwrap().is_none());
    assert!(store.hub_report_task_state().unwrap().is_none());
    assert!(store.list_hub_login_homes().unwrap().is_empty());
    assert!(store.list_hub_login_targets().unwrap().is_empty());
    assert!(store.list_hub_manifest_high_waters().unwrap().is_empty());
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    store
        .record_hub_own_report(&report(HOME), ACTIVATION)
        .unwrap();
    assert_eq!(
        store.read_audit(None).unwrap(),
        audit,
        "dedup rows survive the migration"
    );
    assert!(store
        .with_raw_conn(|conn| conn.execute(
            "UPDATE gh_manifest_activations SET version = 1 WHERE member_id = ?1",
            [PEER]
        ))
        .is_err());
}

#[test]
fn readiness_masks_revoked_peer_fields_in_same_snapshot() {
    let (_root, store) = rig("hub-status-grant", 182);
    seed_self_and_manifest(&store);
    grant_peer(&store, "pair");
    store
        .record_hub_own_report(&report(HOME), ACTIVATION)
        .unwrap();
    store
        .seed_gh_manifest_activation_for_tests(&report(PEER), ACTIVATION)
        .unwrap();
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    // Leave the peer report untouched to isolate the readiness predicate from clear-on-revoke.
    sql(
        &store,
        "DELETE FROM member_grants WHERE operation = 'secret_use';",
    );
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(!status.ready);
    assert_eq!(status.computers.len(), 2);
    assert_eq!(status.computers[0].version, Some(28));
    let peer = &status.computers[1];
    assert_eq!(peer.member_id, PEER);
    assert!(
        peer.version.is_none()
            && peer.payload_sha256.is_none()
            && peer.verdict.is_none()
            && peer.reason.is_none()
            && peer.reported_at_ms.is_none()
    );
}

#[test]
fn hub_target_commits_binding_and_bytes_before_delivery_and_never_wraps_generation() {
    let (_root, store) = rig("hub-target", 183);
    let recipient = HubLoginRecipient {
        member_id: PEER,
        box_id: BOX_1,
        transfer_public_key: &[2; 32],
        pairing_id: "one",
    };
    let first = store
        .commit_hub_login_target(&recipient, HubLoginKind::Snapshot, |generation| {
            assert_eq!(generation, HubGeneration::FIRST);
            Ok(b"first".to_vec())
        })
        .unwrap();
    assert!(!store
        .mark_hub_login_target_delivered(PEER, first, b"wrong")
        .unwrap());
    assert!(store
        .mark_hub_login_target_delivered(PEER, first, b"first")
        .unwrap());
    assert!(store.mark_hub_login_target_stale(PEER, first).unwrap());
    let recipient = HubLoginRecipient {
        box_id: BOX_2,
        transfer_public_key: &[3; 32],
        pairing_id: "two",
        ..recipient
    };
    sql(&store, "CREATE TRIGGER fail_target BEFORE UPDATE ON hub_login_targets BEGIN SELECT RAISE(ABORT, 'target write failed'); END;");
    assert!(store
        .commit_hub_login_target(&recipient, HubLoginKind::Ended, |_| Ok(b"second".to_vec()))
        .is_err());
    let rows = store.list_hub_login_targets().unwrap();
    assert_eq!(
        (
            rows[0].generation,
            rows[0].box_id.as_str(),
            rows[0].pairing_id.as_str(),
            rows[0].transfer_public_key
        ),
        (first, BOX_1, "one", [2; 32])
    );
    assert_eq!(rows[0].sealed_bytes.as_deref(), Some(&b"first"[..]));
    assert!(rows[0].stale && rows[0].delivered);
    sql(&store, "DROP TRIGGER fail_target;");
    let second = store
        .commit_hub_login_target(&recipient, HubLoginKind::Ended, |_| Ok(b"second".to_vec()))
        .unwrap();
    assert_eq!(second.get(), 2);
    assert!(!store
        .mark_hub_login_target_delivered(PEER, first, b"first")
        .unwrap());
    let rows = store.list_hub_login_targets().unwrap();
    assert_eq!(
        (
            rows[0].generation,
            rows[0].box_id.as_str(),
            rows[0].pairing_id.as_str(),
            rows[0].transfer_public_key,
            rows[0].kind
        ),
        (second, BOX_2, "two", [3; 32], HubLoginKind::Ended)
    );
    assert_eq!(rows[0].sealed_bytes.as_deref(), Some(&b"second"[..]));
    assert!(!rows[0].stale && !rows[0].delivered);
    assert!(store.discard_hub_login_target_bytes(PEER, second).unwrap());
    assert!(store.list_hub_login_targets().unwrap()[0]
        .sealed_bytes
        .is_none());
    sql(
        &store,
        "UPDATE hub_login_targets SET generation = 9223372036854775807;",
    );
    assert!(store
        .commit_hub_login_target(&recipient, HubLoginKind::Ended, |_| panic!(
            "no seal at exhausted generation"
        ))
        .is_err());
    assert_eq!(
        store.list_hub_login_targets().unwrap()[0].generation.get(),
        i64::MAX
    );
}

fn row(id: &str) -> RemoteWatchRow {
    RemoteWatchRow {
        credential_id: id.into(),
        state: RemoteHomeState::Active,
        refresh_adapter: None,
        identity: RecordIdentity {
            account_id: None,
            email: None,
            org_name: None,
        },
        categories: vec![],
        provider_ids: None,
        detected_plan: None,
        home_version: 1,
        condition: None,
    }
}

#[test]
fn hub_member_applies_restores_and_ends_atomically_with_stored_generation() {
    let (_root, store) = rig("hub-member", 184);
    store
        .set_federation_self_member_audited(PEER, AuditCtx::vault(AuditOp::FederationSelfSet))
        .unwrap();
    let key = VaultRecord::new_static(
        CredentialKind::KemKey,
        "operator",
        crate::kem::generate_key().unwrap().into_bytes(),
        None,
    );
    store
        .create_audited(VAULT_TRANSFER_ID, &key, AuditCtx::admin(AuditOp::Put))
        .unwrap();
    let meta = store.meta(VAULT_TRANSFER_ID).unwrap();
    let mut apply = HubLoginApply {
        home_member: HOME,
        recipient_member: PEER,
        pairing_id: "pair",
        generation: HubGeneration::FIRST,
        recipient_key_incarnation: meta.incarnation.as_deref().unwrap(),
        recipient_key_record_version: meta.record_version,
    };
    let rows = [row("oauth:auto"), row("oauth:collision")];
    store
        .remote_add_audited(&NewRemoteRecord {
            credential_id: "oauth:collision".into(),
            home_member: HOME.into(),
            refresh_adapter: None,
            detected_plan: None,
            identity: rows[0].identity.clone(),
            home_version: 1,
            categories: vec![],
        })
        .unwrap();
    let snap = || HubLoginApplyMode::NewSnapshot {
        rows: &rows,
        retained_ids: &[],
    };
    store.set_login_sharing_audited(true, "operator").unwrap();
    let before = store.read_audit(None).unwrap();
    sql(&store, "CREATE TRIGGER fail_apply BEFORE INSERT ON hub_login_homes BEGIN SELECT RAISE(ABORT, 'apply write failed'); END;");
    assert!(store
        .apply_hub_login_audited(&apply, snap(), || true)
        .is_err());
    assert!(store.remote_record("oauth:auto").unwrap().is_none());
    assert!(store.hub_login_home_state(HOME).unwrap().is_none());
    assert_eq!(store.read_audit(None).unwrap(), before);
    sql(&store, "DROP TRIGGER fail_apply;");
    assert!(store
        .apply_hub_login_audited(&apply, snap(), || false)
        .unwrap()
        .is_none());
    apply.recipient_key_record_version += 1;
    assert!(store
        .apply_hub_login_audited(&apply, snap(), || true)
        .unwrap()
        .is_none());
    apply.recipient_key_record_version = meta.record_version;
    store
        .set_federation_self_member_audited(HOME, AuditCtx::vault(AuditOp::FederationSelfSet))
        .unwrap();
    let before = store.read_audit(None).unwrap();
    assert!(
        store
            .apply_hub_login_audited(&apply, snap(), || true)
            .unwrap()
            .is_none(),
        "the decoded recipient is no longer this vault's member id"
    );
    assert!(store.hub_login_home_state(HOME).unwrap().is_none());
    assert!(store.remote_record("oauth:auto").unwrap().is_none());
    assert_eq!(store.read_audit(None).unwrap(), before);
    store
        .set_federation_self_member_audited(PEER, AuditCtx::vault(AuditOp::FederationSelfSet))
        .unwrap();
    assert_eq!(
        store
            .apply_hub_login_audited(&apply, snap(), || true)
            .unwrap()
            .unwrap()
            .inserted,
        1
    );
    assert_eq!(
        store
            .hub_login_home_state(HOME)
            .unwrap()
            .unwrap()
            .skipped_ids,
        ["oauth:collision"]
    );
    assert!(store
        .apply_hub_login_audited(&apply, snap(), || true)
        .unwrap()
        .is_none());
    apply.generation = apply.generation.checked_next().unwrap();
    let before = store.read_audit(None).unwrap();
    assert_eq!(
        store
            .apply_hub_login_audited(&apply, snap(), || true)
            .unwrap()
            .unwrap()
            .inserted,
        0
    );
    assert_eq!(store.read_audit(None).unwrap(), before);
    assert_eq!(
        store
            .hub_login_home_state(HOME)
            .unwrap()
            .unwrap()
            .generation,
        apply.generation
    );

    store.set_login_sharing_audited(false, "operator").unwrap();
    assert!(store.remote_record("oauth:auto").unwrap().is_none());
    assert!(store.hub_login_home_state(HOME).unwrap().unwrap().reapply);
    store.set_login_sharing_audited(true, "operator").unwrap();
    assert!(
        store
            .apply_hub_login_audited(&apply, snap(), || true)
            .unwrap()
            .is_none(),
        "ordinary replay cannot restore"
    );
    assert_eq!(
        store
            .apply_hub_login_audited(
                &apply,
                HubLoginApplyMode::RestoreSnapshot {
                    rows: &rows,
                    retained_ids: &[]
                },
                || true
            )
            .unwrap()
            .unwrap()
            .inserted,
        1
    );
    assert!(!store.hub_login_home_state(HOME).unwrap().unwrap().reapply);
    store.remote_remove_audited("oauth:collision").unwrap();
    let extra = [rows[0].clone(), rows[1].clone(), row("oauth:not-skipped")];
    assert_eq!(
        store
            .apply_hub_login_audited(
                &apply,
                HubLoginApplyMode::FillCollisions { rows: &extra },
                || true
            )
            .unwrap()
            .unwrap()
            .inserted,
        1
    );
    assert!(store.remote_record("oauth:not-skipped").unwrap().is_none());
    assert!(store
        .hub_login_home_state(HOME)
        .unwrap()
        .unwrap()
        .skipped_ids
        .is_empty());
    store
        .remote_add_audited(&NewRemoteRecord {
            credential_id: "oauth:operator".into(),
            home_member: HOME.into(),
            refresh_adapter: None,
            detected_plan: None,
            identity: rows[0].identity.clone(),
            home_version: 1,
            categories: vec![],
        })
        .unwrap();

    apply.generation = apply.generation.checked_next().unwrap();
    sql(&store, "CREATE TRIGGER fail_ended BEFORE UPDATE ON hub_login_homes BEGIN SELECT RAISE(ABORT, 'end write failed'); END;");
    let before = store.read_audit(None).unwrap();
    assert!(store
        .apply_hub_login_audited(&apply, HubLoginApplyMode::Ended, || true)
        .is_err());
    assert!(store.remote_record("oauth:auto").unwrap().is_some());
    assert_eq!(store.read_audit(None).unwrap(), before);
    assert!(
        store
            .hub_login_home_state(HOME)
            .unwrap()
            .unwrap()
            .generation
            < apply.generation
    );
    sql(&store, "DROP TRIGGER fail_ended;");
    assert_eq!(
        store
            .apply_hub_login_audited(&apply, HubLoginApplyMode::Ended, || true)
            .unwrap()
            .unwrap()
            .removed,
        2
    );
    assert!(store.remote_record("oauth:operator").unwrap().is_some());
    store
        .remove_hub_login_home_audited(HOME, Some("new-pair"))
        .unwrap();
    let state = store.hub_login_home_state(HOME).unwrap().unwrap();
    assert_eq!(state.generation, apply.generation);
    assert_eq!(state.pairing_id, None);
    assert!(!state.reapply);
    apply.pairing_id = "new-pair";
    assert!(store
        .apply_hub_login_audited(&apply, snap(), || true)
        .unwrap()
        .is_none());
}

#[test]
fn hub_own_report_and_signed_task_state_use_separate_atomic_commits() {
    let (_root, store) = rig("hub-own-report", 185);
    seed_self_and_manifest(&store);
    let audit = store.read_audit(None).unwrap();
    assert!(store
        .record_hub_own_report(&report(PEER), ACTIVATION)
        .is_err());
    sql(&store, "CREATE TRIGGER fail_own BEFORE INSERT ON hub_own_report BEGIN SELECT RAISE(ABORT, 'own write failed'); END;");
    assert!(store
        .record_hub_own_report(&report(HOME), ACTIVATION)
        .is_err());
    assert!(store.hub_own_report().unwrap().is_none());
    assert_eq!(store.read_audit(None).unwrap(), audit);
    assert!(!store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    sql(&store, "DROP TRIGGER fail_own;");
    store
        .record_hub_own_report(&report(HOME), ACTIVATION)
        .unwrap();
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    assert!(
        store.hub_report_task_state().unwrap().is_none(),
        "recording does not sign"
    );
    let own = store.hub_own_report().unwrap().unwrap();
    let first = store
        .commit_hub_report_bytes(&own, |seq| {
            assert_eq!(seq, HubReportSeq::FIRST);
            Ok(b"first".to_vec())
        })
        .unwrap()
        .unwrap();
    assert!(!store.hub_report_task_state().unwrap().unwrap().sent);
    assert!(!store
        .mark_hub_report_sent(&own, first, b"wrong bytes")
        .unwrap());
    assert!(store.mark_hub_report_sent(&own, first, b"first").unwrap());

    let mut invalid = report(HOME);
    invalid.verdict = GhManifestVerdict::Invalid;
    invalid.reason = Some("private reason for local status");
    store.record_hub_own_report(&invalid, ACTIVATION).unwrap();
    assert!(!store.mark_hub_report_sent(&own, first, b"first").unwrap());
    assert_eq!(
        store
            .commit_hub_report_bytes(&own, |_| panic!("stale report cannot sign"))
            .unwrap(),
        None
    );
    let latest = store.hub_own_report().unwrap().unwrap();
    assert_eq!(latest.reason.as_deref(), invalid.reason);
    assert!(!store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    sql(&store, "CREATE TRIGGER fail_sign BEFORE UPDATE ON hub_report_task BEGIN SELECT RAISE(ABORT, 'signed write failed'); END;");
    assert!(store
        .commit_hub_report_bytes(&latest, |_| Ok(b"second".to_vec()))
        .is_err());
    let task = store.hub_report_task_state().unwrap().unwrap();
    assert_eq!(
        (task.seq, task.signed_bytes.as_slice(), task.sent),
        (first, &b"first"[..], true)
    );
    sql(&store, "DROP TRIGGER fail_sign;");
    let second = store
        .commit_hub_report_bytes(&latest, |_| Ok(b"second".to_vec()))
        .unwrap()
        .unwrap();
    assert_eq!(second.get(), 2);
    assert!(!store
        .mark_hub_report_sent(&latest, first, b"first")
        .unwrap());
    let task = store.hub_report_task_state().unwrap().unwrap();
    assert_eq!(
        (task.seq, task.signed_bytes.as_slice(), task.sent),
        (second, &b"second"[..], false)
    );
    sql(&store, "UPDATE hub_report_task SET seq = 9007199254740991;");
    assert!(store
        .commit_hub_report_bytes(&latest, |_| panic!("no signing at exhausted sequence"))
        .is_err());
    assert_eq!(
        store.hub_report_task_state().unwrap().unwrap().seq.get(),
        9_007_199_254_740_991
    );
}

#[test]
fn hub_collector_keeps_per_box_high_water_until_membership_ends() {
    let (_root, store) = rig("hub-collector", 186);
    seed_self_and_manifest(&store);
    store
        .set_secret_home_audited(Some("self"), AuditCtx::admin(AuditOp::SecretHomeSet))
        .unwrap();
    store
        .record_hub_own_report(&report(HOME), ACTIVATION)
        .unwrap();
    let seq = |n| HubReportSeq::new(n).unwrap();
    let record = |box_id, pairing, n| {
        store.record_hub_manifest_report(
            &report(PEER),
            box_id,
            pairing,
            seq(n),
            || true,
            ACTIVATION,
        )
    };
    assert!(record(BOX_1, "pair", 2).unwrap().is_none());
    assert!(store.list_hub_manifest_high_waters().unwrap().is_empty());
    grant_peer(&store, "pair");
    assert!(store
        .record_hub_manifest_report(&report(PEER), BOX_1, "pair", seq(2), || false, ACTIVATION)
        .unwrap()
        .is_none());
    let before = store.read_audit(None).unwrap();
    sql(&store, "CREATE TRIGGER fail_peer_activation BEFORE INSERT ON gh_manifest_activation_audits BEGIN SELECT RAISE(ABORT, 'activation audit failed'); END;");
    assert!(record(BOX_1, "pair", 2).is_err());
    assert!(store.list_hub_manifest_high_waters().unwrap().is_empty());
    assert!(!store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    assert_eq!(store.read_audit(None).unwrap(), before);
    sql(&store, "DROP TRIGGER fail_peer_activation;");
    assert!(record(BOX_1, "pair", 2).unwrap().is_some());
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    assert!(record(BOX_1, "pair", 1).unwrap().is_none());
    assert!(record(BOX_2, "pair", 1).unwrap().is_some());
    assert_eq!(
        store
            .list_hub_manifest_high_waters()
            .unwrap()
            .iter()
            .map(|w| (w.box_id.as_str(), w.seq.get()))
            .collect::<Vec<_>>(),
        [(BOX_1, 2), (BOX_2, 1)]
    );
    assert_eq!(store.clear_peer_hub_manifest_reports().unwrap(), 1);
    let after = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert_eq!(
        (after.computers[0].version, after.computers[1].version),
        (Some(28), None)
    );
    assert!(store.hub_own_report().unwrap().is_some());
    assert!(record(BOX_1, "pair", 2).unwrap().is_none());
    assert!(record(BOX_1, "pair", 3).unwrap().is_some());

    sql(&store, "CREATE TRIGGER fail_revoke BEFORE INSERT ON audit_log WHEN NEW.op = 'member_grant_revoke' BEGIN SELECT RAISE(ABORT, 'revoke audit failed'); END;");
    assert!(store
        .revoke_member_grant_audited(
            PEER,
            MemberGrantOperation::SecretUse,
            &MemberGrantSelector::None
        )
        .is_err());
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    sql(&store, "DROP TRIGGER fail_revoke;");
    store
        .revoke_member_grant_audited(
            PEER,
            MemberGrantOperation::SecretUse,
            &MemberGrantSelector::None,
        )
        .unwrap();
    assert_eq!(store.list_hub_manifest_high_waters().unwrap().len(), 2);
    grant_peer(&store, "pair");
    assert!(
        !store.gh_manifest_active_status(28).unwrap().unwrap().ready,
        "the revoke cleared stored fields, not just the readiness predicate"
    );
    assert!(record(BOX_1, "pair", 3).unwrap().is_none());
    assert!(record(BOX_1, "pair", 4).unwrap().is_some());

    grant_peer(&store, "new-pair");
    assert!(store.list_hub_manifest_high_waters().unwrap().is_empty());
    assert!(!store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    assert!(
        record(BOX_1, "new-pair", 1).unwrap().is_some(),
        "re-pair may restart seq even if the collector did not see it"
    );
    assert_eq!(
        store.list_hub_manifest_high_waters().unwrap(),
        [HubManifestHighWater {
            member_id: PEER.into(),
            box_id: BOX_1.into(),
            pairing_id: "new-pair".into(),
            seq: seq(1)
        }]
    );
    // Model a collector that starts with a different current pairing and a
    // committed grant, but no locally observed transition to that pairing.
    sql(
        &store,
        "UPDATE member_grants SET pairing_id = 'missed-pair' WHERE operation = 'secret_use';",
    );
    assert!(record(BOX_1, "missed-pair", 1).unwrap().is_some());
    assert_eq!(
        store.list_hub_manifest_high_waters().unwrap()[0].pairing_id,
        "missed-pair"
    );
    sql(&store, "CREATE TRIGGER fail_retire BEFORE INSERT ON audit_log WHEN NEW.op = 'gh_manifest_retire' BEGIN SELECT RAISE(ABORT, 'retire audit failed'); END;");
    assert!(store
        .retire_gh_manifest_member(PEER, 120, AuditCtx::admin(AuditOp::GhManifestRetire))
        .is_err());
    assert_eq!(store.list_hub_manifest_high_waters().unwrap().len(), 1);
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    sql(&store, "DROP TRIGGER fail_retire;");
    store
        .retire_gh_manifest_member(PEER, 120, AuditCtx::admin(AuditOp::GhManifestRetire))
        .unwrap();
    assert!(store.list_hub_manifest_high_waters().unwrap().is_empty());
    assert!(record(BOX_1, "missed-pair", 2).unwrap().is_none());
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
}

#[test]
fn hub_collector_refuses_record_if_home_role_changed_before_the_store_fence() {
    let (_root, store) = rig("hub-collector-role", 186);
    seed_self_and_manifest(&store);
    grant_peer(&store, "pair");
    store
        .set_secret_home_audited(Some("self"), AuditCtx::admin(AuditOp::SecretHomeSet))
        .unwrap();
    assert!(matches!(
        store.secret_home_role(),
        crate::store::SecretHomeRole::Home { .. }
    ));
    // The work was queued while Home. The role update wins the writer fence.
    store
        .set_secret_home_audited(None, AuditCtx::admin(AuditOp::SecretHomeSet))
        .unwrap();
    let before = store.read_audit(None).unwrap();
    assert!(store
        .record_hub_manifest_report(
            &report(PEER),
            BOX_1,
            "pair",
            HubReportSeq::FIRST,
            || true,
            ACTIVATION
        )
        .unwrap()
        .is_none());
    assert!(store.list_hub_manifest_high_waters().unwrap().is_empty());
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert_eq!(
        status
            .computers
            .iter()
            .find(|row| row.member_id == PEER)
            .unwrap()
            .version,
        None
    );
    assert_eq!(store.read_audit(None).unwrap(), before);
}
