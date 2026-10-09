//! Store-level behaviour of provider ids: the migration that adds their table, the
//! `admin.set_providers` transition and its checks, the lifecycle paths that keep or
//! delete them, and the readers that return them.

use super::*;
use crate::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2};
use crate::oauth::OAuthCredential;
use crate::provider_ids::{
    ProviderIdRule, MAX_PROVIDER_IDS_PER_CREDENTIAL, MAX_PROVIDER_ID_LEN, MIN_PROVIDER_ID_LEN,
};
use crate::store::taxonomy_tests::{api_record, rig, sqlite};

const ID: &str = "apikey:zai";

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|id| id.to_string()).collect()
}

fn numbered(prefix: &str, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}{i:02}")).collect()
}

fn set(
    store: &EncryptedStore,
    id: &str,
    mode: SetProvidersMode,
    list: &[String],
) -> Result<Vec<String>, StoreOpError> {
    store.set_providers_audited(id, mode, list, AuditCtx::admin(AuditOp::SetProviders))
}

fn created(label: &str, seed: u8) -> (crate::test_support::TestTempDir, EncryptedStore) {
    let (root, store) = rig(label, seed);
    store
        .create_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    (root, store)
}

fn provider_audit(store: &EncryptedStore) -> Vec<String> {
    store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == "set_providers")
        .map(|entry| entry.credential_id.unwrap())
        .collect()
}

fn audit_len(store: &EncryptedStore) -> usize {
    store.read_audit(None).unwrap().len()
}

fn table_rows(store: &EncryptedStore) -> Vec<(String, String)> {
    store
        .with_raw_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT credential_id, provider_id FROM credential_provider_ids ORDER BY credential_id, provider_id",
            )?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>();
            rows
        })
        .unwrap()
}

fn raw_row(store: &EncryptedStore, id: &str) -> (i64, Vec<u8>) {
    store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap()
}

fn refusal(result: Result<Vec<String>, StoreOpError>) -> (ProviderIdRule, String) {
    match result {
        Err(StoreOpError::InvalidProviderId { rule, value }) => (rule, value),
        other => panic!("expected an invalid_provider_id refusal, got {other:?}"),
    }
}

fn oauth_record() -> VaultRecord {
    VaultRecord::new_oauth(
        "opencode",
        "anthropic",
        OAuthCredential {
            access_token: "access".to_string().into(),
            refresh_token: "refresh".to_string().into(),
            expires_at_ms: Some(9_999),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            client_secret: None,
            scopes: vec!["scope-a".into()],
        },
        b"payload-bytes".to_vec(),
    )
}

#[test]
fn migration_15_adds_only_the_provider_id_table_and_conserves_every_row() {
    assert_eq!(PROVIDER_ID_SCHEMA_VERSION, 15);
    assert_eq!(newest_migration_version(), 16);
    let (root, sqlite) = sqlite("provider-migration", 160);
    migrate_through_for_test(&sqlite, PROVIDER_ID_SCHEMA_VERSION - 1).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([160; 32])).unwrap();
    store
        .create_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::List,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();

    let objects = |store: &EncryptedStore| {
        store
            .with_raw_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )?;
                let rows = stmt
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>();
                rows
            })
            .unwrap()
    };
    let rows_of = |store: &EncryptedStore, name: &str| {
        store
            .with_raw_conn(|conn| {
                let mut stmt = conn.prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))?;
                let n = stmt.column_count();
                let rows = stmt
                    .query_map([], |r| {
                        (0..n)
                            .map(|i| r.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>();
                rows
            })
            .unwrap()
    };
    let tables = |store: &EncryptedStore, ddl: &[(String, String, String)]| {
        ddl.iter()
            .filter(|(kind, _, _)| kind == "table")
            .map(|(_, name, _)| (name.clone(), rows_of(store, name)))
            .collect::<BTreeMap<_, _>>()
    };

    // Behind the binary by one migration, the lease-free reader still reads the store
    // and reports no provider ids rather than failing on the missing table.
    let (behind, version) = list_meta_read_only_with_schema(&root.join("store.db")).unwrap();
    assert_eq!(version, PROVIDER_ID_SCHEMA_VERSION - 1);
    assert_eq!(behind[0].1.provider_ids, Vec::<String>::new());

    let before_ddl = objects(&store);
    let mut before_tables = tables(&store, &before_ddl);
    let before_versions = before_tables.remove("cortexkit_schema_version").unwrap();
    migrate_through_for_test(&store.store, PROVIDER_ID_SCHEMA_VERSION).unwrap();
    let after_ddl = objects(&store);

    let added: Vec<_> = after_ddl
        .iter()
        .filter(|object| !before_ddl.contains(object))
        .collect();
    assert_eq!(
        added,
        [&(
            "table".to_string(),
            "credential_provider_ids".to_string(),
            "CREATE TABLE credential_provider_ids (\
             credential_id TEXT NOT NULL, \
             provider_id TEXT NOT NULL, \
             PRIMARY KEY (credential_id, provider_id), \
             FOREIGN KEY (credential_id) REFERENCES credentials(credential_id) ON DELETE CASCADE\
             )"
            .to_string()
        )],
        "exactly one new object, the provider-id table"
    );
    assert_eq!(after_ddl.len(), before_ddl.len() + 1);
    for object in &before_ddl {
        assert!(
            after_ddl.contains(object),
            "{} changed its sql or vanished",
            object.1
        );
    }

    let mut after_tables = tables(&store, &after_ddl);
    let after_versions = after_tables.remove("cortexkit_schema_version").unwrap();
    assert_eq!(
        after_tables.remove("credential_provider_ids").unwrap(),
        Vec::<Vec<rusqlite::types::Value>>::new(),
        "no credential starts with a provider id"
    );
    assert_eq!(
        after_tables, before_tables,
        "every earlier row is unchanged"
    );
    assert_eq!(after_versions[..before_versions.len()], before_versions[..]);
    assert_eq!(after_versions.len(), before_versions.len() + 1);
    assert!(after_versions
        .last()
        .unwrap()
        .contains(&rusqlite::types::Value::Integer(
            PROVIDER_ID_SCHEMA_VERSION as i64
        )));
    let (_, version) = list_meta_read_only_with_schema(&root.join("store.db")).unwrap();
    assert_eq!(version, PROVIDER_ID_SCHEMA_VERSION);
}

#[test]
fn set_add_and_remove_return_the_sorted_set_and_audit_only_transitions() {
    let (_root, store) = created("provider-modes", 161);
    assert_eq!(store.provider_ids(ID).unwrap(), Vec::<String>::new());

    let reply = set(&store, ID, SetProvidersMode::Set, &ids(&["bb", "aa"])).unwrap();
    assert_eq!(reply, ["aa", "bb"]);
    assert_eq!(store.provider_ids(ID).unwrap(), ["aa", "bb"]);
    assert_eq!(provider_audit(&store), ["providers:apikey:zai|aa,bb"]);

    // The same set again is a successful no-op: the reply still carries it, and no
    // audit row is written.
    let count = audit_len(&store);
    assert_eq!(
        set(&store, ID, SetProvidersMode::Set, &ids(&["aa", "bb"])).unwrap(),
        ["aa", "bb"]
    );
    assert_eq!(
        set(&store, ID, SetProvidersMode::Add, &ids(&["bb"])).unwrap(),
        ["aa", "bb"]
    );
    assert_eq!(
        set(&store, ID, SetProvidersMode::Remove, &ids(&["zz"])).unwrap(),
        ["aa", "bb"]
    );
    assert_eq!(
        set(&store, ID, SetProvidersMode::Add, &[]).unwrap(),
        ["aa", "bb"]
    );
    assert_eq!(
        set(&store, ID, SetProvidersMode::Remove, &[]).unwrap(),
        ["aa", "bb"]
    );
    assert_eq!(audit_len(&store), count, "unchanged sets are not audited");

    assert_eq!(
        set(&store, ID, SetProvidersMode::Add, &ids(&["cc"])).unwrap(),
        ["aa", "bb", "cc"]
    );
    assert_eq!(
        set(&store, ID, SetProvidersMode::Remove, &ids(&["aa", "cc"])).unwrap(),
        ["bb"]
    );
    // An empty `set` is the clear, and its target keeps the trailing `|`.
    assert_eq!(
        set(&store, ID, SetProvidersMode::Set, &[]).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        provider_audit(&store),
        [
            "providers:apikey:zai|aa,bb",
            "providers:apikey:zai|aa,bb,cc",
            "providers:apikey:zai|bb",
            "providers:apikey:zai|",
        ]
    );
    assert_eq!(table_rows(&store), Vec::<(String, String)>::new());
}

#[test]
fn checks_run_charset_length_duplicate_not_found_count_and_a_refusal_changes_nothing() {
    let (_root, store) = created("provider-checks", 162);
    set(&store, ID, SetProvidersMode::Set, &ids(&["kept"])).unwrap();
    let before = (table_rows(&store), audit_len(&store), raw_row(&store, ID));
    let unchanged = |store: &EncryptedStore| {
        assert_eq!(
            (table_rows(store), audit_len(store), raw_row(store, ID)),
            before
        );
    };

    for mode in [
        SetProvidersMode::Set,
        SetProvidersMode::Add,
        SetProvidersMode::Remove,
    ] {
        // Each rule, one value each, in every mode.
        for (list, rule, value) in [
            (ids(&[""]), ProviderIdRule::Charset, ""),
            (ids(&["1a"]), ProviderIdRule::Charset, "1a"),
            (ids(&["Ab"]), ProviderIdRule::Charset, "Ab"),
            (ids(&["a"]), ProviderIdRule::Length, "a"),
            (ids(&["aa", "bb", "aa"]), ProviderIdRule::Duplicate, "aa"),
            // Shape before duplicate, wherever they sit in the list.
            (ids(&["aa", "aa", "Zz"]), ProviderIdRule::Charset, "Zz"),
        ] {
            assert_eq!(
                refusal(set(&store, ID, mode, &list)),
                (rule, value.to_string()),
                "{mode:?} {list:?}"
            );
            unchanged(&store);
        }
        // Shape and duplicate checks run before the credential lookup.
        assert_eq!(
            refusal(set(&store, "apikey:missing", mode, &ids(&["B"]))),
            (ProviderIdRule::Charset, "B".to_string())
        );
        // The credential lookup runs before the count, for any list length.
        let too_many = numbered("p", MAX_PROVIDER_IDS_PER_CREDENTIAL + 1);
        for list in [Vec::new(), too_many] {
            assert!(
                matches!(
                    set(&store, "apikey:missing", mode, &list),
                    Err(StoreOpError::NotFound)
                ),
                "{mode:?} with {} ids for a missing credential",
                list.len()
            );
        }
        unchanged(&store);
    }
    assert_eq!(
        StoreOpError::NotFound.to_string(),
        "credential not found",
        "a missing credential refuses exactly as set_category does"
    );
}

#[test]
fn the_vault_accepts_ids_of_the_minimum_and_maximum_length_and_refuses_one_byte_past_either() {
    let (_root, store) = created("provider-length", 169);
    let min = "a".repeat(MIN_PROVIDER_ID_LEN);
    let max = "b".repeat(MAX_PROVIDER_ID_LEN);
    assert_eq!(
        set(
            &store,
            ID,
            SetProvidersMode::Set,
            &[min.clone(), max.clone()]
        )
        .unwrap(),
        [min.clone(), max]
    );
    let before = (table_rows(&store), audit_len(&store));
    let short = "c".repeat(MIN_PROVIDER_ID_LEN - 1);
    let long = "d".repeat(MAX_PROVIDER_ID_LEN + 1);
    for bad in [short, long] {
        assert_eq!(
            refusal(set(
                &store,
                ID,
                SetProvidersMode::Add,
                std::slice::from_ref(&bad)
            )),
            (ProviderIdRule::Length, bad)
        );
    }
    assert_eq!((table_rows(&store), audit_len(&store)), before);
}

#[test]
fn the_cap_applies_to_the_resulting_set_and_names_the_crossing_id() {
    let (_root, store) = created("provider-cap", 163);
    let full = numbered("s", MAX_PROVIDER_IDS_PER_CREDENTIAL);

    // On a credential holding none, 33 distinct ids name the 33rd.
    let thirty_three = numbered("p", MAX_PROVIDER_IDS_PER_CREDENTIAL + 1);
    for mode in [SetProvidersMode::Set, SetProvidersMode::Add] {
        assert_eq!(
            refusal(set(&store, ID, mode, &thirty_three)),
            (ProviderIdRule::Count, thirty_three[32].clone())
        );
    }
    // Removing any number of ids is never a count refusal.
    let count = audit_len(&store);
    assert_eq!(
        set(&store, ID, SetProvidersMode::Remove, &thirty_three).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(audit_len(&store), count, "a no-op remove writes no audit");

    // 31 stored, `add n1 n2` (both new): n2 is the one that crosses.
    set(&store, ID, SetProvidersMode::Set, &full[..31]).unwrap();
    let before = (table_rows(&store), audit_len(&store));
    assert_eq!(
        refusal(set(&store, ID, SetProvidersMode::Add, &ids(&["n1", "n2"]))),
        (ProviderIdRule::Count, "n2".to_string())
    );
    assert_eq!((table_rows(&store), audit_len(&store)), before);

    // Exactly 32 is accepted.
    assert_eq!(
        set(&store, ID, SetProvidersMode::Add, &full[31..]).unwrap(),
        full
    );
    // 32 stored + 1 new names the new id.
    let before = (table_rows(&store), audit_len(&store));
    assert_eq!(
        refusal(set(&store, ID, SetProvidersMode::Add, &ids(&["zz-new"]))),
        (ProviderIdRule::Count, "zz-new".to_string())
    );
    assert_eq!((table_rows(&store), audit_len(&store)), before);
    // Re-adding a stored id at 32 succeeds and writes no audit.
    assert_eq!(
        set(&store, ID, SetProvidersMode::Add, &full[..3]).unwrap(),
        full
    );
    assert_eq!(audit_len(&store), before.1);

    // `set` of a different 32-id set replaces the old one with one audit row.
    let other = numbered("t", MAX_PROVIDER_IDS_PER_CREDENTIAL);
    assert_eq!(
        set(&store, ID, SetProvidersMode::Set, &other).unwrap(),
        other
    );
    assert_eq!(store.provider_ids(ID).unwrap(), other);
    assert_eq!(audit_len(&store), before.1 + 1);
    assert_eq!(
        provider_audit(&store).last().unwrap(),
        &format!("providers:{ID}|{}", other.join(","))
    );
}

#[test]
fn a_direct_set_providers_op_refuses_with_the_labelled_display_and_replies_with_the_set() {
    let (_root, store) = created("provider-admin-op", 164);
    let op = |mode: SetProvidersMode, list: &[&str]| AdminOpBody::SetProviders {
        v: ADMIN_OP_SCHEMA_V2,
        credential_id: ID.to_string(),
        mode,
        provider_ids: ids(list),
    };
    let reply = apply(&store, op(SetProvidersMode::Set, &["bb", "aa"]), "operator").unwrap();
    assert_eq!(reply, serde_json::json!({ "provider_ids": ["aa", "bb"] }));
    let reply = apply(&store, op(SetProvidersMode::Set, &[]), "operator").unwrap();
    assert_eq!(reply, serde_json::json!({ "provider_ids": [] }));

    for (list, expected) in [
        (
            vec!["1a"],
            "invalid_provider_id/permanent: rule=charset value=1a",
        ),
        (
            vec!["a"],
            "invalid_provider_id/permanent: rule=length value=a",
        ),
        (
            vec!["aa", "aa"],
            "invalid_provider_id/permanent: rule=duplicate value=aa",
        ),
    ] {
        let error = apply(&store, op(SetProvidersMode::Add, &list), "operator").unwrap_err();
        assert_eq!(error.to_string(), expected);
    }
    let thirty_three = numbered("p", MAX_PROVIDER_IDS_PER_CREDENTIAL + 1);
    let error = apply(
        &store,
        AdminOpBody::SetProviders {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: ID.to_string(),
            mode: SetProvidersMode::Set,
            provider_ids: thirty_three.clone(),
        },
        "operator",
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "invalid_provider_id/permanent: rule=count value={}",
            thirty_three[32]
        )
    );
    let error = apply(
        &store,
        AdminOpBody::SetProviders {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: "apikey:missing".into(),
            mode: SetProvidersMode::Set,
            provider_ids: thirty_three,
        },
        "operator",
    )
    .unwrap_err();
    assert!(matches!(error, StoreOpError::NotFound));
    assert_eq!(
        provider_audit(&store),
        ["providers:apikey:zai|aa,bb", "providers:apikey:zai|"]
    );
}

#[test]
fn writing_provider_ids_never_touches_the_record_even_when_it_is_retired_or_corrupt() {
    let (_root, store) = created("provider-corrupt", 165);
    store
        .retire_and_revoke_all_audited(ID, AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    let retired = raw_row(&store, ID);
    assert_eq!(
        set(&store, ID, SetProvidersMode::Add, &ids(&["aa"])).unwrap(),
        ["aa"]
    );
    assert_eq!(raw_row(&store, ID), retired);

    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = X'00' WHERE credential_id = ?1",
                [ID],
            )
            .map(|_| ())
        })
        .unwrap();
    let corrupt = raw_row(&store, ID);
    assert_eq!(
        set(&store, ID, SetProvidersMode::Add, &ids(&["bb"])).unwrap(),
        ["aa", "bb"]
    );
    assert_eq!(
        raw_row(&store, ID),
        corrupt,
        "record_version and envelope unchanged"
    );

    // The paths that do not unseal show the ids on the corrupt row.
    let metas = store.list_meta().unwrap();
    assert_eq!(metas[0].1.provider_ids, ["aa", "bb"]);
    store
        .create_read_grant_audited(
            "reserved",
            "signer",
            SelectorKind::Exact,
            ID,
            GrantOperation::Sign,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let sign_only = store
        .list_scoped_snapshot("reserved", "signer")
        .expect("a sign-only row never opens its envelope");
    assert_eq!(sign_only.rows.len(), 1);
    assert_eq!(sign_only.rows[0].provider_ids, ["aa", "bb"]);
    assert_eq!(sign_only.rows[0].auth_method, None);
    assert_eq!(sign_only.rows[0].refresh_adapter, None);
}

#[test]
fn every_lifecycle_path_but_remove_keeps_the_provider_ids() {
    let (_root, store) = created("provider-keep", 166);
    let oauth_id = "oauth:anthropic";
    store
        .create_audited(oauth_id, &oauth_record(), AuditCtx::admin(AuditOp::Login))
        .unwrap();
    for id in [ID, oauth_id] {
        set(&store, id, SetProvidersMode::Set, &ids(&["aa", "bb"])).unwrap();
    }
    let kept = |store: &EncryptedStore, path: &str| {
        for id in [ID, oauth_id] {
            assert_eq!(
                store.provider_ids(id).unwrap(),
                ["aa", "bb"],
                "{path} on {id}"
            );
        }
    };

    // put --replace
    store
        .overwrite_unconditional_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Overwrite))
        .unwrap();
    kept(&store, "put --replace");
    // login --replace
    store
        .overwrite_unconditional_with_identity_policy_audited(
            oauth_id,
            &oauth_record(),
            true,
            AuditCtx::admin(AuditOp::Login),
        )
        .unwrap();
    kept(&store, "login --replace");
    // a token refresh commit
    let version = store.meta(oauth_id).unwrap().record_version;
    store
        .commit_refresh(oauth_id, version, &oauth_record())
        .unwrap();
    kept(&store, "refresh");
    // reclassify, with and without force
    store
        .reclassify_audited(false, AuditCtx::admin(AuditOp::SetCategory))
        .unwrap();
    kept(&store, "reclassify");
    store
        .reclassify_audited(true, AuditCtx::admin(AuditOp::SetCategory))
        .unwrap();
    kept(&store, "reclassify --force");
    // logout
    store
        .retire_and_revoke_all_audited(oauth_id, AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    store
        .retire_and_revoke_all_audited(ID, AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    kept(&store, "logout");
    assert_eq!(
        provider_audit(&store).len(),
        2,
        "no KEEP path audits a provider change"
    );

    // remove deletes the mapping in its own transaction, without a provider audit row.
    // Foreign keys are switched off first: the deployed vault cannot count on the
    // cascade, so the explicit delete must do the work on its own.
    store
        .with_raw_conn(|conn| conn.pragma_update(None, "foreign_keys", "OFF"))
        .unwrap();
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    assert_eq!(
        store.read_audit(None).unwrap().last().unwrap().op,
        AuditOp::Remove.as_str()
    );
    assert_eq!(provider_audit(&store).len(), 2);
    assert_eq!(
        table_rows(&store),
        [
            (oauth_id.to_string(), "aa".to_string()),
            (oauth_id.to_string(), "bb".to_string())
        ],
        "only the removed credential's rows go"
    );
    store
        .create_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    assert_eq!(store.provider_ids(ID).unwrap(), Vec::<String>::new());
}

#[test]
fn readers_return_provider_ids_and_list_scoped_derives_auth_method_only_for_read_and_list() {
    let (root, store) = created("provider-readers", 167);
    let oauth_id = "oauth:anthropic";
    let sign_id = "apikey:signed";
    store
        .create_audited(oauth_id, &oauth_record(), AuditCtx::admin(AuditOp::Login))
        .unwrap();
    store
        .create_audited(sign_id, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    set(&store, ID, SetProvidersMode::Set, &ids(&["zz", "aa"])).unwrap();
    set(
        &store,
        sign_id,
        SetProvidersMode::Set,
        &ids(&["kimi-code-plan"]),
    )
    .unwrap();

    // The admin.status rows, built the same way online and offline.
    let (offline, _) = list_meta_read_only_with_schema(&root.join("store.db")).unwrap();
    assert_eq!(offline, store.list_meta().unwrap());
    let status = crate::admin_ops::status_result(&offline, &[], 0, false);
    let rows = status["credentials"].as_array().unwrap();
    let by_id = |id: &str| {
        rows.iter()
            .find(|row| row["id"] == id)
            .unwrap_or_else(|| panic!("{id} missing from admin.status"))
            .clone()
    };
    assert_eq!(by_id(ID)["provider_ids"], serde_json::json!(["aa", "zz"]));
    assert_eq!(by_id(oauth_id)["provider_ids"], serde_json::json!([]));
    assert_eq!(store.meta(ID).unwrap().provider_ids, ["aa", "zz"]);

    for (id, operation) in [
        (ID, GrantOperation::List),
        (oauth_id, GrantOperation::Read),
        (sign_id, GrantOperation::Sign),
    ] {
        store
            .create_read_grant_audited(
                "reserved",
                "consumer",
                SelectorKind::Exact,
                id,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    let snapshot = store.list_scoped_snapshot("reserved", "consumer").unwrap();
    let row = |id: &str| snapshot.rows.iter().find(|row| row.id == id).unwrap();
    assert_eq!(row(ID).provider_ids, ["aa", "zz"]);
    assert_eq!(
        row(ID).auth_method,
        Some(crate::list_auth_method::ListAuthMethod::Apikey)
    );
    assert_eq!(row(oauth_id).provider_ids, Vec::<String>::new());
    assert_eq!(
        row(oauth_id).auth_method,
        Some(crate::list_auth_method::ListAuthMethod::Oauth)
    );
    assert_eq!(row(sign_id).provider_ids, ["kimi-code-plan"]);
    assert_eq!(
        row(sign_id).auth_method,
        None,
        "a sign-only row stays sealed"
    );
}

#[test]
fn a_store_one_migration_behind_reads_and_removes_without_the_provider_table() {
    let (root, sqlite) = sqlite("provider-behind", 168);
    migrate_through_for_test(&sqlite, PROVIDER_ID_SCHEMA_VERSION - 1).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([168; 32])).unwrap();
    store
        .create_audited(ID, &api_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    let (rows, version) = list_meta_read_only_with_schema(&root.join("store.db")).unwrap();
    assert_eq!(version, PROVIDER_ID_SCHEMA_VERSION - 1);
    assert_eq!(rows[0].1.provider_ids, Vec::<String>::new());
    assert_eq!(store.meta(ID).unwrap().provider_ids, Vec::<String>::new());
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            ID,
            GrantOperation::List,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let snapshot = store.list_scoped_snapshot("reserved", "consumer").unwrap();
    assert_eq!(snapshot.rows[0].provider_ids, Vec::<String>::new());
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
}
