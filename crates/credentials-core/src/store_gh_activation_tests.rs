use super::*;
use crate::audit::AuditOp;
use crate::store::{taxonomy_tests, GhManifestSource, GhManifestVersion};
use rusqlite::types::Value;

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn store_version(store: &EncryptedStore, version: i64) {
    let bytes =
        format!("{{\n  \"manifest_version\": {version},\n  \"note\": \"café \\\"line\\\"\"\n}}\n");
    store
        .store_gh_manifest(
            &GhManifestVersion {
                version,
                manifest_bytes: bytes.as_bytes(),
                manifest_sha256: HASH,
                key_id: "0123456789abcdef",
                signature: &[251; 64],
                signed_at_ms: 10,
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
}

fn report<'a>(member_id: &'a str) -> GhManifestActivationReport<'a> {
    GhManifestActivationReport {
        member_id,
        version: 28,
        payload_sha256: HASH,
        verdict: GhManifestVerdict::Valid,
        reason: None,
        reported_at_ms: 100,
    }
}

fn record(
    store: &EncryptedStore,
    report: &GhManifestActivationReport<'_>,
) -> GhManifestActivationOutcome {
    store
        .report_gh_manifest_active(report, AuditCtx::vault(AuditOp::GhManifestActivation))
        .unwrap()
}

fn self_member(store: &EncryptedStore, member_id: &str) {
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "INSERT INTO settings (name, value, updated_at_ms) VALUES (?1, ?2, 1) \
         ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                params![crate::federation::SELF_MEMBER_SETTING, member_id],
            )
        })
        .unwrap();
}

fn member_grant(
    store: &EncryptedStore,
    member_id: &str,
    operation: &str,
    kind: &str,
    selector: &str,
) {
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "INSERT INTO member_grants \
         (member_id, operation, selector_kind, selector, pairing_id, created_at_ms, source) \
         VALUES (?1, ?2, ?3, ?4, 'pairing', 1, 'operator')",
                params![member_id, operation, kind, selector],
            )
        })
        .unwrap();
}

fn retirement(store: &EncryptedStore, member_id: &str) -> Option<i64> {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT retired_at_ms FROM gh_manifest_activations WHERE member_id = ?1",
                [member_id],
                |row| row.get(0),
            )
        })
        .unwrap()
}

fn activation_audits(store: &EncryptedStore) -> Vec<(String, i64, String)> {
    store.with_raw_conn(|conn| conn.prepare(
        "SELECT member_id, version, verdict FROM gh_manifest_activation_audits ORDER BY member_id, version, verdict",
    )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?.collect()).unwrap()
}

fn audit_count(store: &EncryptedStore, op: &str) -> i64 {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT count(*) FROM audit_log WHERE op = ?1",
                [op],
                |row| row.get(0),
            )
        })
        .unwrap()
}

fn snapshot(store: &EncryptedStore) -> Vec<Vec<Vec<Value>>> {
    store
        .with_raw_conn(|conn| {
            [
                "gh_manifest_activations",
                "gh_manifest_activation_audits",
                "audit_log",
            ]
            .iter()
            .map(|table| {
                let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
                let columns = stmt.column_count();
                let rows = stmt
                    .query_map([], |row| {
                        (0..columns)
                            .map(|i| row.get(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .collect()
        })
        .unwrap()
}

#[test]
fn reports_audit_each_stored_member_version_verdict_only_once() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-audits", 201);
    store_version(&store, 28);
    let mut report = report("member");
    assert_eq!(record(&store, &report).lower_version_reported, None);
    assert_eq!(audit_count(&store, "gh_manifest_activation"), 1);
    assert_eq!(
        activation_audits(&store),
        vec![("member".into(), 28, "valid".into())]
    );

    report.verdict = GhManifestVerdict::Invalid;
    report.reason = Some("first failure");
    record(&store, &report);
    assert_eq!(audit_count(&store, "gh_manifest_activation"), 2);
    assert_eq!(
        activation_audits(&store),
        vec![
            ("member".into(), 28, "invalid".into()),
            ("member".into(), 28, "valid".into()),
        ]
    );

    for (verdict, reason) in [
        (GhManifestVerdict::Invalid, Some("second failure")),
        (GhManifestVerdict::Valid, None),
        (GhManifestVerdict::Valid, None),
        (GhManifestVerdict::Invalid, Some("third failure")),
        (GhManifestVerdict::Invalid, Some("first failure")),
        (GhManifestVerdict::Valid, None),
    ] {
        report.verdict = verdict;
        report.reason = reason;
        report.payload_sha256 = if report.payload_sha256 == HASH {
            OTHER_HASH
        } else {
            HASH
        };
        report.reported_at_ms += 1;
        record(&store, &report);
        assert_eq!(audit_count(&store, "gh_manifest_activation"), 2);
        assert_eq!(activation_audits(&store).len(), 2);
        let status = store.gh_manifest_active_status(28).unwrap().unwrap();
        assert_eq!(
            status.computers,
            vec![GhManifestComputerStatus {
                member_id: "member".into(),
                version: Some(28),
                payload_sha256: Some(report.payload_sha256.into()),
                verdict: Some(verdict),
                reason: reason.map(str::to_owned),
                reported_at_ms: Some(report.reported_at_ms),
            }]
        );
    }

    report.version = 29;
    report.reported_at_ms = 200;
    record(&store, &report);
    assert_eq!(audit_count(&store, "gh_manifest_activation"), 2);
    assert_eq!(activation_audits(&store).len(), 2);
    assert_eq!(
        store
            .gh_manifest_active_status(28)
            .unwrap()
            .unwrap()
            .computers[0]
            .version,
        Some(29)
    );
    // A report seen before storage must not consume the future version's audit tuple.
    store_version(&store, 29);
    record(&store, &report);
    assert_eq!(audit_count(&store, "gh_manifest_activation"), 3);
    report.member_id = "second-member";
    record(&store, &report);
    assert_eq!(audit_count(&store, "gh_manifest_activation"), 4);
}

#[test]
fn lower_version_report_is_recorded_and_returns_warning_metadata() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-lower", 202);
    store_version(&store, 28);
    let mut report = report("member");
    report.version = 29;
    assert_eq!(record(&store, &report).lower_version_reported, None);
    report.version = 28;
    report.reported_at_ms = 101;
    assert_eq!(
        record(&store, &report).lower_version_reported,
        Some(GhManifestLowerVersionReported {
            reported: 28,
            active: 29
        })
    );
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(status.ready);
    assert_eq!(status.computers[0].version, Some(28));
    assert_eq!(status.computers[0].reported_at_ms, Some(101));
    assert_eq!(record(&store, &report).lower_version_reported, None);
}

#[test]
fn two_expected_computers_need_both_reports_or_retirement_of_the_silent_one() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-ready", 203);
    store_version(&store, 28);
    self_member(&store, "home");
    member_grant(&store, "remote", "secret_use", "none", "");
    record(&store, &report("home"));
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(!status.ready);
    assert_eq!(status.computers.len(), 2);
    assert_eq!(
        serde_json::to_value(&status.computers[1]).unwrap(),
        serde_json::json!({
            "member_id": "remote", "version": null, "payload_sha256": null,
            "verdict": null, "reason": null, "reported_at_ms": null,
        })
    );

    store
        .retire_gh_manifest_member("remote", 110, AuditCtx::admin(AuditOp::GhManifestRetire))
        .unwrap();
    assert_eq!(retirement(&store, "remote"), Some(110));
    let retired: Vec<Value> = store.with_raw_conn(|conn| conn.query_row(
        "SELECT version, payload_sha256, verdict, reason, reported_at_ms FROM gh_manifest_activations WHERE member_id = 'remote'",
        [], |row| (0..5).map(|i| row.get(i)).collect(),
    )).unwrap();
    assert_eq!(retired, vec![Value::Null; 5]);
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(status.ready);
    assert_eq!(status.computers.len(), 1);
    assert_eq!(audit_count(&store, "gh_manifest_retire"), 1);
}

#[test]
fn two_reports_make_ready_and_all_three_report_commitments_must_match() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-match", 204);
    store_version(&store, 28);
    self_member(&store, "home");
    member_grant(&store, "remote", "secret_use", "none", "");
    record(&store, &report("home"));
    record(&store, &report("remote"));
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    let mut wrong = report("remote");
    wrong.version = 29;
    record(&store, &wrong);
    assert!(!store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    wrong.version = 28;
    wrong.payload_sha256 = OTHER_HASH;
    record(&store, &wrong);
    assert!(!store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    wrong.payload_sha256 = HASH;
    wrong.verdict = GhManifestVerdict::Invalid;
    wrong.reason = Some("signature failed");
    record(&store, &wrong);
    assert!(!store.gh_manifest_active_status(28).unwrap().unwrap().ready);
    record(&store, &report("remote"));
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
}

#[test]
fn expected_population_is_the_deduplicated_byte_sorted_union_minus_retired() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-population", 205);
    store_version(&store, 28);
    self_member(&store, "home");
    member_grant(&store, "home", "secret_use", "none", "");
    member_grant(&store, "z-secret", "secret_use", "none", "");
    member_grant(&store, "A-secret", "secret_use", "none", "");
    member_grant(
        &store,
        "ignored-reader",
        "remote_read",
        "exact",
        "credential",
    );
    member_grant(&store, "ignored-transfer", "transfer_deliver", "none", "");
    member_grant(&store, "retired", "secret_use", "none", "");
    record(&store, &report("home"));
    record(&store, &report("é-reported"));
    store
        .retire_gh_manifest_member("retired", 110, AuditCtx::admin(AuditOp::GhManifestRetire))
        .unwrap();
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert_eq!(
        status
            .computers
            .iter()
            .map(|c| c.member_id.as_str())
            .collect::<Vec<_>>(),
        vec!["A-secret", "home", "z-secret", "é-reported"]
    );
    assert!(!status.ready);
    store
        .retire_gh_manifest_member("home", 111, AuditCtx::admin(AuditOp::GhManifestRetire))
        .unwrap();
    assert!(!store
        .gh_manifest_active_status(28)
        .unwrap()
        .unwrap()
        .computers
        .iter()
        .any(|c| c.member_id == "home"));
}

#[test]
fn retired_reports_update_fields_without_unretiring_or_blocking_latest() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-retired-report", 206);
    store_version(&store, 28);
    for (member_id, reported_first) in [("retired-only", false), ("reported-first", true)] {
        if reported_first {
            record(&store, &report(member_id));
        }
        store
            .retire_gh_manifest_member(member_id, 110, AuditCtx::admin(AuditOp::GhManifestRetire))
            .unwrap();
        assert!(store.latest_gh_manifest().unwrap().is_some());
        let mut report = report(member_id);
        report.verdict = GhManifestVerdict::Invalid;
        report.reason = Some("retired but still reporting");
        report.payload_sha256 = OTHER_HASH;
        report.reported_at_ms = 120;
        record(&store, &report);
        let row: (i64, String, String, String, i64, i64) = store.with_raw_conn(|conn| conn.query_row(
            "SELECT version, payload_sha256, verdict, reason, reported_at_ms, retired_at_ms \
             FROM gh_manifest_activations WHERE member_id = ?1", [member_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )).unwrap();
        assert_eq!(
            row,
            (
                28,
                OTHER_HASH.into(),
                "invalid".into(),
                "retired but still reporting".into(),
                120,
                110
            )
        );
        record(&store, &report);
        assert_eq!(retirement(&store, member_id), Some(110));
    }
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(status.computers.is_empty());
    assert!(!status.ready);
    assert_eq!(audit_count(&store, "gh_manifest_retire"), 2);
    assert_eq!(audit_count(&store, "gh_manifest_activation"), 3);
}

#[test]
fn readiness_is_false_for_an_empty_population_and_unknown_versions_are_absent() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-unknown", 207);
    assert_eq!(store.gh_manifest_active_status(28).unwrap(), None);
    store_version(&store, 28);
    self_member(&store, "");
    let status = store.gh_manifest_active_status(28).unwrap().unwrap();
    assert!(!status.ready);
    assert!(status.computers.is_empty());
    record(&store, &report("home"));
    assert_eq!(store.gh_manifest_active_status(29).unwrap(), None);
    assert!(store.gh_manifest_active_status(28).unwrap().unwrap().ready);
}

#[test]
fn report_and_retire_roll_back_on_audit_failure() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-rollback", 208);
    store_version(&store, 28);
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_activation_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op IN ('gh_manifest_activation', 'gh_manifest_retire') \
         BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
            )
        })
        .unwrap();
    let before = snapshot(&store);
    let err = store
        .report_gh_manifest_active(
            &report("member"),
            AuditCtx::vault(AuditOp::GhManifestActivation),
        )
        .unwrap_err();
    assert!(err.to_string().contains("injected audit failure"), "{err}");
    assert_eq!(snapshot(&store), before);
    assert!(store
        .retire_gh_manifest_member("member", 110, AuditCtx::admin(AuditOp::GhManifestRetire))
        .is_err());
    assert_eq!(snapshot(&store), before);
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TRIGGER fail_activation_audit"))
        .unwrap();
    record(&store, &report("member"));
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_activation_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op IN ('gh_manifest_activation', 'gh_manifest_retire') \
         BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
            )
        })
        .unwrap();
    let before = snapshot(&store);
    let mut invalid = report("member");
    invalid.verdict = GhManifestVerdict::Invalid;
    invalid.reason = Some("failure");
    assert!(store
        .report_gh_manifest_active(&invalid, AuditCtx::vault(AuditOp::GhManifestActivation))
        .is_err());
    assert_eq!(snapshot(&store), before);
    assert!(store
        .retire_gh_manifest_member("member", 110, AuditCtx::admin(AuditOp::GhManifestRetire))
        .is_err());
    assert_eq!(snapshot(&store), before);
}

#[test]
fn latest_is_absent_or_newest_with_exact_text_hex_key_and_standard_base64() {
    let (_root, store) = taxonomy_tests::rig("gh-activation-latest", 209);
    assert_eq!(store.latest_gh_manifest().unwrap(), None);
    store_version(&store, 28);
    store_version(&store, 29);
    let latest = store.latest_gh_manifest().unwrap().unwrap();
    assert_eq!(latest.version, 29);
    assert_eq!(latest.envelope.key_id, "0123456789abcdef");
    assert_eq!(
        latest.envelope.manifest_bytes,
        "{\n  \"manifest_version\": 29,\n  \"note\": \"café \\\"line\\\"\"\n}\n"
    );
    assert!(latest.envelope.signature.contains('+'));
    assert!(latest.envelope.signature.contains('/'));
    assert!(latest.envelope.signature.ends_with("=="));
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&latest.envelope.signature)
            .unwrap(),
        vec![251; 64]
    );
    let wire = serde_json::to_value(&latest).unwrap();
    assert_eq!(
        wire.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["envelope", "version"]
    );
    assert_eq!(
        wire["envelope"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["key_id", "manifest_bytes", "signature"]
    );
    assert_eq!(
        wire["envelope"]["manifest_bytes"]
            .as_str()
            .unwrap()
            .as_bytes(),
        latest.envelope.manifest_bytes.as_bytes()
    );
}
