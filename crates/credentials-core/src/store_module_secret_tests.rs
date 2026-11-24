use super::*;
use crate::store::taxonomy_tests::{rig, sqlite};
use rusqlite::types::Value;

fn owner(id: &str) -> ModuleSecretOwner {
    ModuleSecretOwner::new(id).unwrap()
}

fn put(store: &EncryptedStore, module: &str, name: &str) {
    store
        .put_module_secret(&owner(module), name, b"test-private-value", None, None)
        .unwrap();
}

fn rows(store: &SqliteStore, table: &str) -> Vec<Vec<Value>> {
    store
        .with_conn(|conn| {
            let count = conn
                .prepare(&format!("SELECT * FROM \"{table}\""))?
                .column_count();
            let order = (1..=count)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\" ORDER BY {order}"))?;
            let mapped = stmt.query_map([], |r| (0..count).map(|i| r.get(i)).collect())?;
            mapped.collect()
        })
        .unwrap()
}

fn snapshot(store: &EncryptedStore) -> (Vec<Vec<Value>>, Vec<AuditEntry>) {
    (
        rows(&store.store, "module_secrets"),
        store.read_audit(None).unwrap(),
    )
}

fn sql(store: &EncryptedStore, statements: &str) {
    store
        .store
        .with_conn(|conn| conn.execute_batch(statements))
        .unwrap();
}

#[test]
fn module_secret_metadata_lists_do_not_read_envelopes() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    let (_root, store) = rig("module-list-metadata", 201);
    put(&store, "first", "a");
    put(&store, "second", "b");
    store
        .with_raw_conn(|conn| {
            conn.authorizer(Some(|context: AuthContext<'_>| match context.action {
                AuthAction::Read {
                    table_name: "module_secrets",
                    column_name: "envelope",
                } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            Ok(())
        })
        .unwrap();
    assert_eq!(store.list_module_secrets(&owner("first")).unwrap().len(), 1);
    assert_eq!(store.list_all_module_secrets().unwrap().len(), 2);
}

#[test]
fn owner_module_secret_metadata_uses_an_index_seek() {
    let (_root, store) = rig("module-list-owner-seek", 201);
    put(&store, "first", "a");
    put(&store, "second", "b");
    put(&store, "third", "c");
    let result = store.list_module_secrets(&owner("second")).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "b");
    assert_eq!(METADATA_FULL_SCAN_STEPS.get(), 0);
}

#[test]
fn module_secret_bounds_validate_before_store_access() {
    let (_root, store) = rig("module-bounds", 201);
    let max_name = "a".repeat(64);
    let max_owner = owner(&max_name);
    let value = vec![0x5a; 65_536];
    store
        .put_module_secret(&max_owner, &max_name, &value, None, None)
        .unwrap();
    assert_eq!(
        store
            .get_module_secret(&max_owner, &max_name)
            .unwrap()
            .value
            .expose(),
        &value
    );
    store
        .put_module_secret(&owner("small"), "byte", b"x", None, None)
        .unwrap();
    for invalid in [
        "",
        ".first",
        "Upper",
        "pipe|name",
        "space name",
        "é",
        &"a".repeat(65),
    ] {
        assert_eq!(
            ModuleSecretOwner::new(invalid),
            Err(ModuleSecretError::InvalidParams)
        );
        assert_eq!(
            validate_module_secret_name(invalid),
            Err(ModuleSecretError::InvalidParams)
        );
        let before = snapshot(&store);
        assert_eq!(
            store.put_module_secret(&owner("small"), invalid, b"x", None, None),
            Err(ModuleSecretError::InvalidParams)
        );
        assert_eq!(snapshot(&store), before);
    }
    for invalid in [Vec::new(), vec![0; 65_537]] {
        let before = snapshot(&store);
        assert_eq!(
            store.put_module_secret(&owner("small"), "invalid", &invalid, None, None),
            Err(ModuleSecretError::InvalidParams)
        );
        assert_eq!(snapshot(&store), before);
    }
    let before = snapshot(&store);
    assert_eq!(
        store.put_module_secret(&owner("small"), "invalid", b"x", Some(0), None),
        Err(ModuleSecretError::InvalidParams)
    );
    assert_eq!(
        store.delete_module_secret(&owner("small"), "byte", Some(0)),
        Err(ModuleSecretError::InvalidParams)
    );
    assert_eq!(snapshot(&store), before);
}

#[test]
fn module_secret_put_and_delete_precedence_and_audit_are_exact() {
    let (_root, store) = rig("module-precedence", 202);
    let module = owner("callosum");
    let created = store
        .put_module_secret(&module, "locked", b"original", None, Some(true))
        .unwrap();
    assert_eq!(
        created,
        ModuleSecretWritten {
            name: "locked".into(),
            version: 1,
            created: true
        }
    );
    let before = snapshot(&store);
    for expected in [None, Some(1), Some(99)] {
        for protected in [None, Some(false), Some(true)] {
            assert_eq!(
                store.put_module_secret(&module, "locked", b"changed", expected, protected),
                Err(ModuleSecretError::Protected)
            );
        }
        assert_eq!(
            store.delete_module_secret(&module, "locked", expected),
            Err(ModuleSecretError::Protected)
        );
    }
    assert_eq!(snapshot(&store), before);
    put(&store, "callosum", "plain");
    let before = snapshot(&store);
    assert_eq!(
        store.put_module_secret(&module, "plain", b"x", Some(99), Some(true)),
        Err(ModuleSecretError::VersionConflict)
    );
    assert_eq!(
        store.put_module_secret(&module, "plain", b"x", Some(1), Some(true)),
        Err(ModuleSecretError::InvalidParams)
    );
    assert_eq!(
        store.delete_module_secret(&module, "plain", Some(99)),
        Err(ModuleSecretError::VersionConflict)
    );
    assert_eq!(
        store.delete_module_secret(&module, "absent", Some(99)),
        Err(ModuleSecretError::NotFound)
    );
    assert_eq!(
        store.put_module_secret(&module, "absent", b"x", Some(1), None),
        Err(ModuleSecretError::VersionConflict)
    );
    assert_eq!(snapshot(&store), before);
    let replaced = store
        .put_module_secret(&module, "plain", b"replacement", Some(1), Some(false))
        .unwrap();
    assert_eq!(
        replaced,
        ModuleSecretWritten {
            name: "plain".into(),
            version: 2,
            created: false
        }
    );
    let item = store.get_module_secret(&module, "plain").unwrap();
    assert_eq!(item.version, 2);
    assert!(!item.protected);
    assert_eq!(item.value.expose(), b"replacement");
    store
        .delete_module_secret(&module, "plain", Some(2))
        .unwrap();
    assert!(matches!(
        store.get_module_secret(&module, "plain"),
        Err(ModuleSecretError::NotFound)
    ));
    let audit = store.read_audit(None).unwrap();
    assert_eq!(
        audit.iter().map(|a| a.op.as_str()).collect::<Vec<_>>(),
        [
            "module_secret_create",
            "module_secret_create",
            "module_secret_replace",
            "module_secret_delete"
        ]
    );
    for entry in &audit {
        assert_eq!(entry.actor, "reserved:callosum");
        assert!(!entry.alarm);
        assert_eq!(entry.alarm_reason, None);
        assert!(entry
            .credential_id
            .as_deref()
            .unwrap()
            .starts_with("module-secret|callosum|"));
    }
    assert_eq!(
        audit[0].payload_hash,
        Some(hex32(&audit::payload_fingerprint(
            &store.audit_key,
            b"original"
        )))
    );
    assert_ne!(
        audit[0].payload_hash,
        Some(hex32(&payload_hash(b"original")))
    );
    assert_eq!(
        audit[2].payload_hash,
        Some(hex32(&audit::payload_fingerprint(
            &store.audit_key,
            b"replacement"
        )))
    );
    assert_eq!(audit[3].payload_hash, None);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn module_secret_limit_counts_corrupt_and_protected_items_and_allows_replacement() {
    let (_root, store) = rig("module-count", 203);
    let module = owner("callosum");
    for i in 0..64 {
        store
            .put_module_secret(&module, &format!("item-{i:02}"), b"x", None, Some(i == 0))
            .unwrap();
    }
    sql(
        &store,
        "UPDATE module_secrets SET state='corrupt' WHERE name='item-01'",
    );
    assert_eq!(store.list_module_secrets(&module).unwrap().len(), 64);
    let before = snapshot(&store);
    assert_eq!(
        store.put_module_secret(&module, "absent", b"x", Some(1), None),
        Err(ModuleSecretError::VersionConflict)
    );
    assert_eq!(
        store.put_module_secret(&module, "absent", b"x", None, None),
        Err(ModuleSecretError::Limit)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        store
            .put_module_secret(&module, "item-01", b"restored", Some(1), None)
            .unwrap()
            .version,
        2
    );
    assert_eq!(
        store.list_module_secrets(&module).unwrap()[1].state,
        ModuleSecretState::Active
    );
    put(&store, "other", "absent");
    assert_eq!(store.list_all_module_secrets().unwrap().len(), 65);
    store
        .delete_module_secret(&module, "item-01", None)
        .unwrap();
    put(&store, "callosum", "absent");
}

#[test]
fn module_secret_audit_append_failure_rolls_back_create_replace_and_delete() {
    let (_root, store) = rig("module-audit-rollback", 204);
    let module = owner("callosum");
    put(&store, "callosum", "existing");
    let before = snapshot(&store);
    sql(&store, "CREATE TRIGGER refuse_module_audit BEFORE INSERT ON audit_log
        WHEN NEW.op LIKE 'module_secret_%' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;");
    assert_eq!(
        store.put_module_secret(&module, "absent", b"x", None, None),
        Err(ModuleSecretError::Store)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        store.put_module_secret(&module, "existing", b"x", None, None),
        Err(ModuleSecretError::Store)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        store.delete_module_secret(&module, "existing", None),
        Err(ModuleSecretError::Store)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        store.delete_module_secret_as_operator(
            &module,
            "existing",
            AuditCtx::admin(AuditOp::ModuleSecretDelete)
        ),
        Err(ModuleSecretError::Store)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn module_secret_binding_rejects_module_name_version_and_credential_swaps() {
    for (i, change) in [
        "UPDATE module_secrets SET module_id='other'",
        "UPDATE module_secrets SET name='other'",
        "UPDATE module_secrets SET version=2",
    ]
    .iter()
    .enumerate()
    {
        let (_root, store) = rig(&format!("module-binding-{i}"), 205);
        put(&store, "callosum", "token");
        let blob: Vec<u8> = store
            .store
            .with_conn(|conn| {
                conn.query_row("SELECT envelope FROM module_secrets", [], |r| r.get(0))
            })
            .unwrap();
        assert!(envelope::open(
            &store.key,
            &blob,
            &RecordBinding {
                credential_id: "apikey:other",
                record_version: 1,
            }
        )
        .is_err());
        sql(&store, change);
        let module = if i == 0 { "other" } else { "callosum" };
        let name = if i == 1 { "other" } else { "token" };
        assert!(matches!(
            store.get_module_secret(&owner(module), name),
            Err(ModuleSecretError::Corrupt)
        ));
        assert_eq!(
            store.list_all_module_secrets().unwrap()[0].state,
            ModuleSecretState::Corrupt
        );
        assert_eq!(store.read_audit(None).unwrap().len(), 1);
    }
}

#[test]
fn module_secret_get_quarantines_only_active_open_failures_not_key_mismatch() {
    let (_root, store) = rig("module-quarantine", 206);
    let module = owner("callosum");
    put(&store, "callosum", "wrong-key");
    let blob = envelope::seal(
        &MasterKey::from_bytes([7; 32]),
        b"different",
        &RecordBinding {
            credential_id: "module-secret|callosum|wrong-key",
            record_version: 1,
        },
    )
    .unwrap();
    store
        .store
        .with_conn(|conn| conn.execute("UPDATE module_secrets SET envelope=?1", [blob]))
        .unwrap();
    let before = snapshot(&store);
    let writes = store.subscribe_writes();
    assert!(matches!(
        store.get_module_secret(&module, "wrong-key"),
        Err(ModuleSecretError::VaultLocked)
    ));
    assert_eq!(snapshot(&store), before);
    assert!(!writes.has_changed().unwrap());
    sql(&store, "UPDATE module_secrets SET state='corrupt'");
    let before = snapshot(&store);
    assert!(matches!(
        store.get_module_secret(&module, "wrong-key"),
        Err(ModuleSecretError::Corrupt)
    ));
    assert_eq!(snapshot(&store), before);
    assert!(!writes.has_changed().unwrap());
    sql(
        &store,
        "UPDATE module_secrets SET state='active', envelope=x'00'",
    );
    assert!(matches!(
        store.get_module_secret(&module, "wrong-key"),
        Err(ModuleSecretError::Corrupt)
    ));
    assert_eq!(
        store.list_module_secrets(&module).unwrap()[0].state,
        ModuleSecretState::Corrupt
    );
    assert_eq!(store.read_audit(None).unwrap(), before.1);
    store
        .put_module_secret(&module, "wrong-key", b"healthy", None, None)
        .unwrap();
    assert_eq!(
        store
            .get_module_secret(&module, "wrong-key")
            .unwrap()
            .value
            .expose(),
        b"healthy"
    );
    sql(
        &store,
        "UPDATE module_secrets SET envelope=x'00';
        CREATE TRIGGER refuse_quarantine BEFORE UPDATE ON module_secrets
        WHEN NEW.state='corrupt' BEGIN SELECT RAISE(ABORT, 'injected quarantine failure'); END;",
    );
    let before = snapshot(&store);
    assert!(matches!(
        store.get_module_secret(&module, "wrong-key"),
        Err(ModuleSecretError::Store)
    ));
    assert_eq!(snapshot(&store), before);
}

#[test]
fn module_secret_stale_quarantine_matches_the_complete_observed_row() {
    let (_root, store) = rig("module-stale", 207);
    let module = owner("callosum");
    put(&store, "callosum", "token");
    let observed = store
        .store
        .with_conn(|conn| read_item(conn, &module, "token"))
        .unwrap()
        .unwrap();
    sql(&store, "UPDATE module_secrets SET version=2");
    let before = snapshot(&store);
    store.quarantine_module_secret(&observed).unwrap();
    assert_eq!(snapshot(&store), before);
    sql(&store, "UPDATE module_secrets SET version=1");
    store
        .put_module_secret(&module, "token", b"replacement", Some(1), None)
        .unwrap();
    let before = snapshot(&store);
    store.quarantine_module_secret(&observed).unwrap();
    assert_eq!(snapshot(&store), before);
    store.delete_module_secret(&module, "token", None).unwrap();
    put(&store, "callosum", "token");
    let recreated = store
        .store
        .with_conn(|conn| read_item(conn, &module, "token"))
        .unwrap()
        .unwrap();
    assert_eq!(observed.version, recreated.version);
    assert_ne!(observed.envelope, recreated.envelope);
    let before = snapshot(&store);
    store.quarantine_module_secret(&observed).unwrap();
    assert_eq!(snapshot(&store), before);
    put(&store, "other", "token");
    put(&store, "callosum", "other");
    for mut wrong in [
        store
            .store
            .with_conn(|conn| read_item(conn, &module, "token"))
            .unwrap()
            .unwrap(),
        store
            .store
            .with_conn(|conn| read_item(conn, &module, "token"))
            .unwrap()
            .unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        if wrong.0 == 0 {
            wrong.1.module_id = "other".into();
        } else {
            wrong.1.name = "other".into();
        }
        let before = snapshot(&store);
        store.quarantine_module_secret(&wrong.1).unwrap();
        assert_eq!(snapshot(&store), before);
    }
    sql(&store, "UPDATE module_secrets SET state='corrupt'");
    sql(
        &store,
        "CREATE TRIGGER refuse_requarantine BEFORE UPDATE ON module_secrets
        WHEN OLD.state='corrupt' BEGIN SELECT RAISE(ABORT, 'already quarantined'); END;",
    );
    let before = snapshot(&store);
    store.quarantine_module_secret(&recreated).unwrap();
    assert_eq!(snapshot(&store), before);
}

#[test]
fn module_secret_every_write_and_quarantine_is_epoch_fenced() {
    let (_root, mut store) = rig("module-fence", 208);
    let module = owner("callosum");
    put(&store, "callosum", "token");
    sql(
        &store,
        "UPDATE module_secrets SET envelope=x'00'; UPDATE cortexkit_fence SET epoch=999 WHERE id=0",
    );
    let before = snapshot(&store);
    assert_eq!(
        store.put_module_secret(&module, "new", b"x", None, None),
        Err(ModuleSecretError::Store)
    );
    assert_eq!(
        store.delete_module_secret(&module, "token", None),
        Err(ModuleSecretError::Store)
    );
    assert_eq!(
        store.delete_module_secret_as_operator(
            &module,
            "token",
            AuditCtx::admin(AuditOp::ModuleSecretDelete)
        ),
        Err(ModuleSecretError::Store)
    );
    assert_eq!(
        store.move_module_secrets(
            &module,
            &owner("other"),
            AuditCtx::admin(AuditOp::ModuleSecretMove)
        ),
        Err(ModuleSecretError::Store)
    );
    assert!(matches!(
        store.get_module_secret(&module, "token"),
        Err(ModuleSecretError::Store)
    ));
    assert!(store
        .rotate_master_key(MasterKey::from_bytes([209; 32]))
        .is_err());
    assert_eq!(snapshot(&store), before);
    assert!(store.is_fenced_out());
}

#[test]
fn module_secret_move_preserves_metadata_rebinds_and_audits_in_name_order() {
    let (_root, store) = rig("module-move", 209);
    let from = owner("old");
    let to = owner("new");
    put(&store, "old", "z");
    store
        .put_module_secret(&from, "a", b"protected", None, Some(true))
        .unwrap();
    store
        .put_module_secret(&from, "z", b"replaced", None, None)
        .unwrap();
    sql(
        &store,
        "UPDATE module_secrets SET created_at_ms=10,updated_at_ms=11",
    );
    let old_envelopes = rows(&store.store, "module_secrets");
    let before = store.read_audit(None).unwrap().len();
    assert_eq!(
        store.move_module_secrets(
            &from,
            &to,
            AuditCtx::route_admin(AuditOp::ModuleSecretMove, "route-admin/gen-3")
        ),
        Ok(2)
    );
    assert!(store.list_module_secrets(&from).unwrap().is_empty());
    let summaries = store.list_module_secrets(&to).unwrap();
    assert_eq!(
        summaries
            .iter()
            .map(|s| (s.name.as_str(), s.version, s.protected, s.state))
            .collect::<Vec<_>>(),
        [
            ("a", 1, true, ModuleSecretState::Active),
            ("z", 2, false, ModuleSecretState::Active),
        ]
    );
    let new_rows = rows(&store.store, "module_secrets");
    for (new, old) in new_rows.iter().zip(&old_envelopes) {
        assert_eq!(new[7], old[7]);
        assert_ne!(new[6], old[6]);
        assert_ne!(new[8], Value::Integer(11));
    }
    assert_eq!(
        store.get_module_secret(&to, "a").unwrap().value.expose(),
        b"protected"
    );
    assert_eq!(
        store.get_module_secret(&to, "z").unwrap().value.expose(),
        b"replaced"
    );
    let audit = store.read_audit(None).unwrap();
    assert_eq!(
        audit[before..]
            .iter()
            .map(|a| a.credential_id.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["module-secret|new|a", "module-secret|new|z"]
    );
    for a in &audit[before..] {
        assert_eq!(a.op, "module_secret_move");
        assert_eq!(a.actor, "route-admin/gen-3");
        assert!(a.alarm);
        assert_eq!(
            a.alarm_reason.as_deref(),
            Some(AlarmReason::AdminWrite.as_str())
        );
    }
    assert_eq!(
        audit[before].payload_hash,
        Some(hex32(&audit::payload_fingerprint(
            &store.audit_key,
            b"protected"
        )))
    );
    store
        .delete_module_secret_as_operator(&to, "a", AuditCtx::admin(AuditOp::ModuleSecretDelete))
        .unwrap();
    let audit = store.read_audit(None).unwrap();
    let deleted = audit.last().unwrap();
    assert_eq!(deleted.actor, "offline-cli");
    assert!(deleted.alarm);
    assert_eq!(
        deleted.alarm_reason.as_deref(),
        Some(AlarmReason::AdminWrite.as_str())
    );
    assert_eq!(deleted.payload_hash, None);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn module_secret_move_refusals_and_mid_move_failure_leave_every_row_unchanged() {
    for failure in [
        "same",
        "absent",
        "occupied",
        "corrupt",
        "bad-envelope",
        "wrong-key",
        "audit",
    ] {
        let (_root, store) = rig(&format!("module-move-{failure}"), 210);
        let from = owner("old");
        let to = owner("new");
        put(&store, "old", "a");
        put(&store, "old", "b");
        let expected = match failure {
            "same" | "occupied" => ModuleSecretError::InvalidParams,
            "absent" => ModuleSecretError::NotFound,
            "wrong-key" => ModuleSecretError::VaultLocked,
            "audit" => ModuleSecretError::Store,
            _ => ModuleSecretError::Corrupt,
        };
        match failure {
            "occupied" => put(&store, "new", "unrelated"),
            "corrupt" => sql(&store, "UPDATE module_secrets SET state='corrupt' WHERE name='b'"),
            "bad-envelope" => sql(&store, "UPDATE module_secrets SET envelope=x'00' WHERE name='b'"),
            "wrong-key" => {
                let blob = envelope::seal(&MasterKey::from_bytes([9; 32]), b"wrong", &RecordBinding {
                    credential_id: "module-secret|old|b", record_version: 1,
                }).unwrap();
                store.store.with_conn(|conn| conn.execute("UPDATE module_secrets SET envelope=?1 WHERE name='b'", [blob])).unwrap();
            }
            "audit" => sql(&store, "CREATE TRIGGER fail_second_move BEFORE INSERT ON audit_log
                WHEN NEW.op='module_secret_move' AND NEW.credential_id='module-secret|new|b'
                AND EXISTS(SELECT 1 FROM module_secrets WHERE module_id='new' AND name='a')
                AND EXISTS(SELECT 1 FROM audit_log WHERE op='module_secret_move' AND credential_id='module-secret|new|a')
                BEGIN
                SELECT RAISE(ABORT, 'injected second audit failure'); END;"),
            _ => (),
        }
        let before = snapshot(&store);
        let empty = owner("empty");
        let result = store.move_module_secrets(
            if failure == "absent" { &to } else { &from },
            if failure == "same" {
                &from
            } else if failure == "absent" {
                &empty
            } else {
                &to
            },
            AuditCtx::admin(AuditOp::ModuleSecretMove),
        );
        assert_eq!(result, Err(expected), "{failure}");
        assert_eq!(snapshot(&store), before, "{failure}");
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }
}

#[test]
fn rotation_does_not_count_existing_corruption_as_new_quarantine() {
    let (_root, mut store) = rig("rotation-earlier-corruption", 211);
    for name in ["existing", "new"] {
        store
            .create(
                &format!("apikey:{name}"),
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"material".to_vec(),
                    None,
                ),
            )
            .unwrap();
        put(&store, "sample", name);
    }
    sql(
        &store,
        "UPDATE credentials SET envelope = X'00';
         UPDATE credentials SET state = 'corrupt' WHERE credential_id = 'apikey:existing';
         UPDATE module_secrets SET envelope = X'00';
         UPDATE module_secrets SET state = 'corrupt' WHERE name = 'existing';",
    );
    let quarantined = store
        .rotate_master_key(MasterKey::from_bytes([212; 32]))
        .unwrap();
    assert_eq!(quarantined, ["apikey:new", "module-secret|sample|new"]);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    assert!(store
        .rotate_master_key(MasterKey::from_bytes([213; 32]))
        .unwrap()
        .is_empty());
}

#[test]
fn module_secret_rotation_reseals_and_reports_quarantine_with_a_continuous_chain() {
    let (_root, mut store) = rig("module-rotation", 211);
    let module = owner("callosum");
    store
        .create(
            "apikey:example",
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "test",
                b"credential-value".to_vec(),
                None,
            ),
        )
        .unwrap();
    store
        .put_module_secret(&module, "healthy", b"module-value", None, Some(true))
        .unwrap();
    put(&store, "callosum", "broken");
    sql(
        &store,
        "UPDATE module_secrets SET envelope=x'00' WHERE name='broken'",
    );
    let old_key_id = store.key_id;
    let before = store.read_audit(None).unwrap();
    assert_eq!(
        store
            .rotate_master_key(MasterKey::from_bytes([212; 32]))
            .unwrap(),
        ["module-secret|callosum|broken"]
    );
    let healthy = store.get_module_secret(&module, "healthy").unwrap();
    assert_eq!(healthy.value.expose(), b"module-value");
    assert!(healthy.protected);
    assert_eq!(healthy.version, 1);
    assert!(matches!(
        store.get_module_secret(&module, "broken"),
        Err(ModuleSecretError::Corrupt)
    ));
    let row_keys = store
        .store
        .with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT name,key_id,state FROM module_secrets ORDER BY name")?;
            let mapped = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    assert_eq!(
        row_keys,
        [
            ("broken".into(), old_key_id.to_hex(), "corrupt".into()),
            ("healthy".into(), store.key_id.to_hex(), "active".into()),
        ]
    );
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit[..before.len()], before);
    assert_eq!(audit.len(), before.len() + 1);
    assert_eq!(audit.last().unwrap().op, "rotate_master_key");
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    let credential = store.store.with_conn(|conn| conn.query_row(
        "SELECT record_version,envelope,key_id FROM credentials WHERE credential_id='apikey:example'", [],
        |r| Ok((r.get::<_, u64>(0)?,r.get::<_, Vec<u8>>(1)?,r.get::<_, String>(2)?)),
    )).unwrap();
    assert_eq!(credential.2, store.key_id.to_hex());
    assert!(envelope::open(
        &store.key,
        &credential.1,
        &RecordBinding {
            credential_id: "apikey:example",
            record_version: credential.0,
        }
    )
    .is_ok());
}

#[test]
fn module_secret_rotation_audit_failure_rolls_back_envelopes_and_in_memory_key() {
    let (_root, mut store) = rig("module-rotation-rollback", 213);
    put(&store, "callosum", "healthy");
    put(&store, "callosum", "broken");
    sql(
        &store,
        "UPDATE module_secrets SET envelope=x'00' WHERE name='broken';
        CREATE TRIGGER refuse_rotation BEFORE INSERT ON audit_log WHEN NEW.op='rotate_master_key'
        BEGIN SELECT RAISE(ABORT, 'injected rotation audit failure'); END;",
    );
    let before = snapshot(&store);
    let vault_before = rows(&store.store, "vault_secrets");
    let key_before = store.key_id;
    assert!(store
        .rotate_master_key(MasterKey::from_bytes([214; 32]))
        .is_err());
    assert_eq!(snapshot(&store), before);
    assert_eq!(rows(&store.store, "vault_secrets"), vault_before);
    assert_eq!(store.key_id, key_before);
    assert_eq!(
        store
            .get_module_secret(&owner("callosum"), "healthy")
            .unwrap()
            .value
            .expose(),
        b"test-private-value"
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn module_secret_only_store_cannot_regenerate_a_missing_audit_key() {
    let (_root, store) = rig("module-audit-key", 215);
    put(&store, "callosum", "token");
    sql(&store, "DELETE FROM vault_secrets; DELETE FROM audit_log");
    let before = rows(&store.store, "module_secrets");
    assert!(matches!(
        load_or_create_audit_key(&store.store, &store.key),
        Err(StoreOpError::CorruptVault(_))
    ));
    assert!(rows(&store.store, "vault_secrets").is_empty());
    assert!(rows(&store.store, "credentials").is_empty());
    assert_eq!(rows(&store.store, "module_secrets"), before);
}

fn all_tables(store: &SqliteStore) -> BTreeMap<String, Vec<Vec<Value>>> {
    let names = store
        .with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master WHERE type='table'
            AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'cortexkit%' ORDER BY name",
            )?;
            let mapped = stmt.query_map([], |r| r.get::<_, String>(0))?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let data = rows(store, &name);
            (name, data)
        })
        .collect()
}

#[test]
fn module_secret_migration_48_preserves_every_existing_step_47_row() {
    let (_root, sqlite) = sqlite("module-migration", 216);
    migrate_through_for_test(&sqlite, 47).unwrap();
    let key = MasterKey::from_bytes([216; 32]);
    let store = EncryptedStore::open(sqlite, key).unwrap();
    store
        .create(
            "apikey:example",
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "test",
                b"legacy-credential".to_vec(),
                None,
            ),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "callosum",
            SelectorKind::Exact,
            "apikey:example",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let sealed = crate::agent_secret::seal(
        &store.key,
        "00000000000000000000000000000001",
        "legacy",
        &crate::agent_secret::SecretScope::ApiKey {
            host: "localhost".into(),
            path_prefix: None,
            location: "authorization_bearer".into(),
        },
        &crate::agent_secret::SecretMaterial::ApiKey(Secret::new(b"legacy-agent-secret".to_vec())),
    )
    .unwrap();
    store.store.with_conn(|conn| {
        conn.execute("INSERT INTO agent_secrets (name,kind,incarnation,state,host,location,record_version,key_id,envelope,created_at_ms)
            VALUES ('legacy','agent_api_key','00000000000000000000000000000001','active','localhost','authorization_bearer',1,?1,?2,10)",
            rusqlite::params![store.key_id.to_hex(), sealed])?;
        conn.execute_batch("INSERT INTO fleet_epochs VALUES (1,x'1234','legacy','[]',NULL,'current',10);
            INSERT INTO fleet_removals VALUES ('old-member','removal',11);
            INSERT INTO fleet_discards VALUES ('mint',2);
            INSERT INTO declared_grant_sets VALUES ('callosum',NULL,NULL,NULL,'[]',0,12);")
    }).unwrap();
    let before = all_tables(&store.store);
    assert_eq!(store.store.with_conn(read_schema_version).unwrap(), 47);
    migrate_through_for_test(&store.store, 48).unwrap();
    assert_eq!(store.store.with_conn(read_schema_version).unwrap(), 48);
    let mut after = all_tables(&store.store);
    assert_eq!(after.remove("module_secrets"), Some(vec![]));
    assert_eq!(
        after, before,
        "the migration must preserve every pre-existing row byte-for-byte"
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    let pk = store
        .store
        .with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name,pk FROM pragma_table_info('module_secrets') WHERE pk>0 ORDER BY pk",
            )?;
            let mapped =
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    assert_eq!(pk, [("module_id".into(), 1), ("name".into(), 2)]);
}

#[test]
fn module_secrets_are_isolated_from_modules_credentials_grants_watch_and_federation() {
    let (_root, store) = rig("module-isolation", 217);
    let callosum = owner("callosum");
    let other = owner("other");
    put(&store, "callosum", "z");
    put(&store, "callosum", "a");
    assert!(store.list_module_secrets(&other).unwrap().is_empty());
    assert!(matches!(
        store.get_module_secret(&other, "a"),
        Err(ModuleSecretError::NotFound)
    ));
    assert_eq!(
        store.delete_module_secret(&other, "a", None),
        Err(ModuleSecretError::NotFound)
    );
    store
        .put_module_secret(&other, "a", b"other-value", None, None)
        .unwrap();
    assert_eq!(
        store
            .get_module_secret(&callosum, "a")
            .unwrap()
            .value
            .expose(),
        b"test-private-value"
    );
    assert_eq!(
        store.get_module_secret(&other, "a").unwrap().value.expose(),
        b"other-value"
    );
    assert_eq!(
        store
            .list_module_secrets(&callosum)
            .unwrap()
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        ["a", "z"]
    );
    assert!(store.list_meta().unwrap().is_empty());
    assert!(store.home_watch_candidates().unwrap().is_empty());
    assert!(store.remote_inventory().unwrap().is_empty());
    let declared = DeclaredGrantSet::empty();
    for operation in [GrantOperation::Read, GrantOperation::List] {
        store
            .create_read_grant_audited(
                "reserved",
                "other",
                SelectorKind::Category,
                "llm-provider",
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        assert!(!store
            .read_grant_covers(
                "reserved",
                "other",
                "module-secret|callosum|a",
                operation,
                &declared
            )
            .unwrap());
    }
    for id in ["a", "module-secret|callosum|a"] {
        assert!(matches!(store.get(id), Err(StoreOpError::NotFound)));
    }
    assert!(store
        .list_scoped_snapshot("reserved", "other", &declared)
        .unwrap()
        .rows
        .is_empty());
    let (watch, generations) = store
        .watch_scoped_snapshot("reserved", "other", &declared)
        .unwrap();
    assert!(watch.rows.is_empty());
    assert!(generations.is_empty());
    assert!(rows(&store.store, "outgoing_transfers").is_empty());
    assert!(rows(&store.store, "pending_transfers").is_empty());
}
