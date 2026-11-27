use super::*;
use credentials_core::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V1};
use credentials_core::federation::{
    NewRemoteRecord, RemoteHomeState, RemoteRecordSource, RemoteWatchApplyMode, RemoteWatchRow,
};
use credentials_core::store::DeclaredGrantSet;
use credentials_core::GrantOperation;

const REMOTE_ID: &str = "oauth:anthropic:shared";
const CATEGORY: &str = "member-logins";
const HOME: &str = "fed-computer:11111111111111111111111111111111";

fn seed_remote(vault: &GrantCliVault, source: RemoteRecordSource) {
    let store = open_leased_store(&vault.data_dir, &vault.key_path);
    match source {
        RemoteRecordSource::HomeWatch => {
            store
                .remote_watch_apply_audited(
                    HOME,
                    "pairing",
                    &[RemoteWatchRow {
                        credential_id: REMOTE_ID.into(),
                        state: RemoteHomeState::Active,
                        refresh_adapter: Some("anthropic".into()),
                        identity: Default::default(),
                        categories: vec![CATEGORY.into()],
                        provider_ids: None,
                        detected_plan: None,
                        home_version: 1,
                        condition: None,
                    }],
                    RemoteWatchApplyMode::Full,
                    &[],
                )
                .unwrap();
        }
        RemoteRecordSource::Operator => {
            store
                .remote_add_audited(&NewRemoteRecord {
                    provider_ids: Vec::new(),
                    credential_id: REMOTE_ID.into(),
                    home_member: HOME.into(),
                    refresh_adapter: Some("anthropic".into()),
                    detected_plan: None,
                    identity: Default::default(),
                    home_version: 1,
                    categories: vec![CATEGORY.into()],
                })
                .unwrap();
        }
    }
    assert!(store.list_meta().unwrap().is_empty());
    assert_eq!(
        store.remote_record(REMOTE_ID).unwrap().unwrap().source,
        source
    );
}

fn assert_grant_reach(
    vault: &GrantCliVault,
    kind: &str,
    selector: &str,
    operation: &str,
    expected: usize,
) {
    let (ok, stdout, stderr) = grant_on(vault, "reserved:broca", kind, selector, operation);
    assert!(ok, "{stderr}");
    let noun = if expected == 1 {
        "credential"
    } else {
        "credentials"
    };
    assert_eq!(
        stdout.lines().nth(1),
        Some(format!("  reaches {expected} {noun}").as_str())
    );
    assert_eq!(stderr.contains("warning:"), expected == 0, "{stderr}");
    if expected == 0 && kind == "exact" {
        assert!(
            stderr.contains(&format!("No credential has the id '{selector}'.")),
            "{stderr}"
        );
    }

    let listed = vault.run(&["grants"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8(listed.stdout).unwrap();
    let row = stdout
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| {
            fields.get(1) == Some(&"broca")
                && fields.get(2) == Some(&kind)
                && fields.get(3) == Some(&selector)
                && fields.get(4) == Some(&operation)
        })
        .unwrap_or_else(|| panic!("missing grant in table:\n{stdout}"));
    assert_eq!(row[5], expected.to_string(), "{stdout}");
}

#[test]
fn remote_grant_reach_home_watch_exact_and_absent_ids() {
    let vault = GrantCliVault::new("reach-home-watch");
    vault.bootstrap();
    seed_remote(&vault, RemoteRecordSource::HomeWatch);
    assert_grant_reach(&vault, "exact", REMOTE_ID, "read", 1);
    assert_grant_reach(&vault, "exact", "oauth:anthropic:absent", "read", 0);
}

#[test]
fn remote_grant_reach_manual_exact_and_absent_ids() {
    let vault = GrantCliVault::new("reach-manual");
    vault.bootstrap();
    seed_remote(&vault, RemoteRecordSource::Operator);
    assert_grant_reach(&vault, "exact", REMOTE_ID, "read", 1);
    assert_grant_reach(&vault, "exact", "oauth:anthropic:absent", "read", 0);
}

#[test]
fn remote_grant_reach_categories_match_member_metadata_for_read_and_list() {
    for source in [RemoteRecordSource::HomeWatch, RemoteRecordSource::Operator] {
        let vault = GrantCliVault::new("reach-remote-categories");
        vault.bootstrap();
        seed_remote(&vault, source);
        // The id's registry defaults are not its assigned member-vault categories.
        for (operation, typed) in [
            ("read", GrantOperation::Read),
            ("list", GrantOperation::List),
        ] {
            assert_grant_reach(&vault, "category", "llm-provider", operation, 0);
            let covered = || {
                open_leased_store(&vault.data_dir, &vault.key_path)
                    .evaluate_scoped_coverage(
                        "reserved",
                        "broca",
                        REMOTE_ID,
                        typed,
                        &DeclaredGrantSet::default(),
                    )
                    .unwrap()
                    .covered
            };
            assert!(
                !covered(),
                "unassigned category must not cover the remote id"
            );
            assert_grant_reach(&vault, "category", CATEGORY, operation, 1);
            assert!(covered(), "member-local category must cover the remote id");
        }
    }
}

#[test]
fn remote_grant_reach_status_is_additive_and_inventory_reads_without_key_or_lease() {
    let vault = GrantCliVault::new("reach-status-additive");
    vault.bootstrap();
    put_on(&vault, "apikey:zai");
    grant_on(&vault, "reserved:broca", "exact", REMOTE_ID, "read");
    let status = |store: &EncryptedStore| {
        apply(
            store,
            AdminOpBody::Status {
                v: ADMIN_OP_SCHEMA_V1,
            },
            "operator",
        )
        .unwrap()
    };
    let mut before = status(&open_leased_store(&vault.data_dir, &vault.key_path));
    // Seed the same manual record `remote add` persists, without requiring a home call.
    let store = open_leased_store(&vault.data_dir, &vault.key_path);
    store
        .remote_add_audited(&NewRemoteRecord {
            provider_ids: Vec::new(),
            credential_id: REMOTE_ID.into(),
            home_member: HOME.into(),
            refresh_adapter: Some("anthropic".into()),
            detected_plan: None,
            identity: Default::default(),
            home_version: 1,
            categories: vec![CATEGORY.into()],
        })
        .unwrap();
    let tip = store.audit_tip().unwrap();
    let mut after = status(&store);
    assert_eq!(
        after["remote_credentials"],
        serde_json::json!([
            { "id": REMOTE_ID, "categories": [CATEGORY] }
        ])
    );
    assert_eq!(
        EncryptedStore::remote_inventory_read_only(&vault.data_dir.join("store.db")).unwrap(),
        store.remote_inventory().unwrap(),
    );
    before.as_object_mut().unwrap().remove("remote_credentials");
    after.as_object_mut().unwrap().remove("remote_credentials");
    assert_eq!(
        serde_json::to_vec(&after).unwrap(),
        serde_json::to_vec(&before).unwrap()
    );
    let listed = cli()
        .args(["grants", "--data-dir"])
        .arg(&vault.data_dir)
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8(listed.stdout).unwrap();
    let row = stdout
        .lines()
        .find(|line| line.contains(REMOTE_ID))
        .unwrap();
    assert_eq!(row.split_whitespace().nth(5), Some("1"), "{stdout}");
    assert_eq!(store.audit_tip().unwrap(), tip);
}
