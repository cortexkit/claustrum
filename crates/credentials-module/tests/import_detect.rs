#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../src/bin/cli_support/import_detect.rs"]
mod import_detect;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::admin_ops::{apply, AdminAuditOp, AdminOpBody, ADMIN_OP_SCHEMA_V1};
use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
use credentials_core::oauth::{
    import_antigravity_account, import_api_key, ImportError, OAuthCredential,
};
use credentials_core::record::{RecordIdentity, VaultRecord};
use credentials_core::secret::SecretBytes;
use credentials_core::store::EncryptedStore;
use import_detect::{
    adapter_is_registered, antigravity_default_auth_path, classify_inventory_row, derive_entry,
    enumerate, enumerate_with_registry, first_selectable_rendered_index,
    gemini_cli_default_auth_path, opencode_default_auth_path, parse_inventory,
    pi_default_auth_path, slice2_contract, DetectionFailure, EntryKind, EntrySelection,
    ImportAction, ImportPaths, ImportSource,
};
use serde_json::{json, Value};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import")
}

fn six_paths() -> ImportPaths {
    let root = fixtures().join("six");
    ImportPaths {
        opencode: root.join("opencode/auth.json"),
        pi: root.join("pi/auth.json"),
        gemini_cli: root.join("gemini-cli/oauth_creds.json"),
        antigravity: root.join("antigravity-accounts.json"),
    }
}

fn missing(name: &str) -> PathBuf {
    fixtures().join("missing").join(name)
}

fn paths_with(
    opencode: impl Into<PathBuf>,
    pi: impl Into<PathBuf>,
    gemini_cli: impl Into<PathBuf>,
    antigravity: impl Into<PathBuf>,
) -> ImportPaths {
    ImportPaths {
        opencode: opencode.into(),
        pi: pi.into(),
        gemini_cli: gemini_cli.into(),
        antigravity: antigravity.into(),
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ck-import-detect-{}-{label}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn env(home: &str, data: Option<&str>, config: Option<&str>) -> BTreeMap<String, OsString> {
    let mut values = BTreeMap::from([("HOME".to_string(), OsString::from(home))]);
    if let Some(data) = data {
        values.insert("XDG_DATA_HOME".to_string(), OsString::from(data));
    }
    if let Some(config) = config {
        values.insert("XDG_CONFIG_HOME".to_string(), OsString::from(config));
    }
    values
}

fn open_test_store(root: &TempDir) -> EncryptedStore {
    let path = root.path().join("store.db");
    let sqlite = open_sqlite(&StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .expect("open test store");
    EncryptedStore::migrate(&sqlite).expect("migrate test store");
    EncryptedStore::open(sqlite, MasterKey::from_bytes([23; MASTER_KEY_LEN]))
        .expect("open encrypted test store")
}

fn oauth_record(source: &str, adapter: &str, oauth: OAuthCredential) -> VaultRecord {
    VaultRecord::new_oauth(source, adapter, oauth, SecretBytes::new(Vec::new()))
}

#[test]
fn default_paths_for_home_h_are_pure_and_exact() {
    let values = env("/h", Some("/d"), Some("/c"));
    assert_eq!(
        opencode_default_auth_path(&values),
        Path::new("/d/opencode/auth.json")
    );
    assert_eq!(
        pi_default_auth_path(&values),
        Path::new("/h/.pi/agent/auth.json")
    );
    assert_eq!(
        gemini_cli_default_auth_path(&values),
        Path::new("/h/.gemini/oauth_creds.json")
    );
    assert_eq!(
        antigravity_default_auth_path(&values),
        Path::new("/c/opencode/antigravity-accounts.json")
    );
    assert_ne!(pi_default_auth_path(&values), Path::new("/h/.pi/auth.json"));
}

#[test]
fn default_paths_for_a_different_home_do_not_share_process_state() {
    let values = env("/other-home", Some("/other-data"), Some("/other-config"));
    assert_eq!(
        opencode_default_auth_path(&values),
        Path::new("/other-data/opencode/auth.json")
    );
    assert_eq!(
        pi_default_auth_path(&values),
        Path::new("/other-home/.pi/agent/auth.json")
    );
    assert_eq!(
        gemini_cli_default_auth_path(&values),
        Path::new("/other-home/.gemini/oauth_creds.json")
    );
    assert_eq!(
        antigravity_default_auth_path(&values),
        Path::new("/other-config/opencode/antigravity-accounts.json")
    );
}

#[test]
fn xdg_decoys_do_not_move_pi_or_gemini_and_unset_xdg_uses_fixed_fallbacks() {
    let root = TempDir::new("xdg-decoys");
    root.write("data/.pi/agent/auth.json", b"decoy");
    root.write("data/.gemini/oauth_creds.json", b"decoy");
    root.write("config/.pi/agent/auth.json", b"decoy");
    root.write("config/.gemini/oauth_creds.json", b"decoy");
    let home = root.path().join("home");
    let data = root.path().join("data");
    let config = root.path().join("config");
    let values = env(
        home.to_str().unwrap(),
        Some(data.to_str().unwrap()),
        Some(config.to_str().unwrap()),
    );
    assert_eq!(
        pi_default_auth_path(&values),
        home.join(".pi/agent/auth.json")
    );
    assert_eq!(
        gemini_cli_default_auth_path(&values),
        home.join(".gemini/oauth_creds.json")
    );

    let fallback = env("/h", None, None);
    assert_eq!(
        opencode_default_auth_path(&fallback),
        Path::new("/h/.local/share/opencode/auth.json")
    );
    assert_eq!(
        antigravity_default_auth_path(&fallback),
        Path::new("/h/.config/opencode/antigravity-accounts.json")
    );
}

#[test]
fn explicit_fixture_set_yields_exactly_six_selectable_literal_ids() {
    let rows = enumerate(&six_paths());
    let ids: Vec<_> = rows
        .iter()
        .filter(|row| row.is_selectable())
        .map(|row| row.metadata.proposed_id.as_deref().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "oauth:anthropic",
            "apikey:openrouter",
            "apikey:deepseek",
            "oauth:google",
            "antigravity:google:a",
            "antigravity:google:b",
        ]
    );
    assert_eq!(first_selectable_rendered_index(&rows), Some(2));
    assert!(rows
        .iter()
        .filter_map(|row| row.metadata.refresh_adapter.as_deref())
        .all(adapter_is_registered));
}

#[test]
fn missing_corrupt_and_unreadable_sources_are_isolated() {
    let six = six_paths();
    let without_gemini = paths_with(
        &six.opencode,
        &six.pi,
        missing("gemini.json"),
        &six.antigravity,
    );
    let rows = enumerate(&without_gemini);
    assert_eq!(rows.iter().filter(|row| row.is_selectable()).count(), 5);
    assert!(rows.iter().all(|row| row.failure.is_none()));

    let corrupt_pi = paths_with(
        &six.opencode,
        fixtures().join("corrupt/pi-auth.json"),
        &six.gemini_cli,
        &six.antigravity,
    );
    let rows = enumerate(&corrupt_pi);
    assert_eq!(rows.iter().filter(|row| row.is_selectable()).count(), 5);
    let failures: Vec<_> = rows
        .iter()
        .filter_map(|row| row.non_selectable_text())
        .collect();
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("pi"));
    assert!(failures[0].contains("parse failure"));
    assert!(failures[0].contains("pi-auth.json"));

    let all_absent = paths_with(
        missing("opencode"),
        missing("pi"),
        missing("gemini"),
        missing("antigravity"),
    );
    assert!(enumerate(&all_absent).is_empty());

    let root = TempDir::new("unreadable-shape");
    let directory_instead_of_file = root.path().join("pi-auth.json");
    std::fs::create_dir(&directory_instead_of_file).unwrap();
    let unreadable = paths_with(
        missing("opencode"),
        &directory_instead_of_file,
        missing("gemini"),
        missing("antigravity"),
    );
    let rows = enumerate(&unreadable);
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].is_selectable());
    let text = rows[0].non_selectable_text().unwrap();
    assert!(text.contains("pi"));
    assert!(text.contains("read failure"));
    assert!(text.contains("pi-auth.json"));
}

#[test]
fn every_source_payload_has_the_exact_reader_wrapper() {
    let paths = six_paths();
    let rows = enumerate(&paths);
    let op_root: Value = serde_json::from_slice(&std::fs::read(&paths.opencode).unwrap()).unwrap();
    let pi_root: Value = serde_json::from_slice(&std::fs::read(&paths.pi).unwrap()).unwrap();
    let op = rows
        .iter()
        .find(|row| row.metadata.harness_provider_key.as_deref() == Some("anthropic"))
        .unwrap();
    let pi = rows
        .iter()
        .find(|row| row.metadata.harness_provider_key.as_deref() == Some("deepseek"))
        .unwrap();
    let gemini = rows
        .iter()
        .find(|row| row.metadata.source == ImportSource::GeminiCli)
        .unwrap();
    assert_eq!(
        op.payload().unwrap().as_bytes(),
        format!(
            "{{\"anthropic\":{}}}",
            serde_json::to_string(&op_root["anthropic"]).unwrap()
        )
        .as_bytes()
    );
    assert_eq!(
        pi.payload().unwrap().as_bytes(),
        format!(
            "{{\"deepseek\":{}}}",
            serde_json::to_string(&pi_root["deepseek"]).unwrap()
        )
        .as_bytes()
    );
    assert_eq!(
        gemini.payload().unwrap().as_bytes(),
        std::fs::read(&paths.gemini_cli).unwrap()
    );
}

#[test]
fn antigravity_invalid_sibling_does_not_take_down_valid_raw_entry() {
    let file = fixtures().join("partial/antigravity-accounts.json");
    let rows = enumerate(&paths_with(
        missing("opencode"),
        missing("pi"),
        missing("gemini"),
        &file,
    ));
    assert_eq!(rows.len(), 2);
    assert!(rows[0].is_selectable());
    assert!(!rows[1].is_selectable());
    assert!(matches!(
        rows[1].failure,
        Some(DetectionFailure::MissingField("refreshToken"))
    ));

    let root: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let valid = &root["accounts"][0];
    let expected = format!(
        "{{\"accounts\":[{}],\"activeIndex\":0}}",
        serde_json::to_string(valid).unwrap()
    );
    assert_eq!(rows[0].payload().unwrap().as_bytes(), expected.as_bytes());

    let imported = import_antigravity_account(rows[0].payload().unwrap().as_bytes(), Some("0"))
        .expect("rebased valid account");
    assert_eq!(
        imported.oauth.refresh_token.expose(),
        "fixture-antigravity-valid|valid-project"
    );
    assert_eq!(imported.email.as_deref(), Some("valid@example.com"));
    assert!(matches!(
        import_antigravity_account(rows[0].payload().unwrap().as_bytes(), Some("1")),
        Err(ImportError::ProviderNotFound(_))
    ));
}

#[test]
fn antigravity_second_account_is_rebased_and_keeps_only_original_index_in_metadata() {
    let file = fixtures().join("second-no-email/antigravity-accounts.json");
    let rows = enumerate(&paths_with(
        missing("opencode"),
        missing("pi"),
        missing("gemini"),
        &file,
    ));
    assert_eq!(rows.len(), 2);
    let second = &rows[1];
    assert_eq!(second.metadata.original_account_index, Some(1));
    assert_eq!(
        second.metadata.entry_selection,
        EntrySelection::AntigravityAccount(0)
    );
    assert_eq!(
        second.metadata.proposed_id.as_deref(),
        Some("antigravity:google:1")
    );
    let imported = import_antigravity_account(second.payload().unwrap().as_bytes(), Some("0"))
        .expect("rebased second account");
    assert_eq!(
        imported.oauth.refresh_token.expose(),
        "fixture-antigravity-second|second-project"
    );
    assert_ne!(
        imported.oauth.refresh_token.expose(),
        "fixture-antigravity-first|first-project"
    );
    let store_root = TempDir::new("second-account-store");
    let store = open_test_store(&store_root);
    store
        .create(
            "antigravity:google:1",
            &oauth_record("antigravity", "antigravity", imported.oauth),
        )
        .expect("commit isolated second account");
    let stored = store
        .get("antigravity:google:1")
        .expect("stored second account");
    assert_eq!(
        stored.oauth.unwrap().refresh_token.expose(),
        "fixture-antigravity-second|second-project"
    );
    assert!(matches!(
        import_antigravity_account(second.payload().unwrap().as_bytes(), Some("1")),
        Err(ImportError::ProviderNotFound(_))
    ));
}

#[test]
fn provider_entry_failure_keeps_valid_sibling_and_exact_isolated_payload() {
    let file = fixtures().join("partial/opencode-auth.json");
    let rows = enumerate(&paths_with(
        &file,
        missing("pi"),
        missing("gemini"),
        missing("antigravity"),
    ));
    assert_eq!(rows.len(), 2);
    let valid = rows
        .iter()
        .find(|row| row.metadata.harness_provider_key.as_deref() == Some("anthropic"))
        .unwrap();
    let invalid = rows
        .iter()
        .find(|row| row.metadata.harness_provider_key.as_deref() == Some("broken"))
        .unwrap();
    assert!(valid.is_selectable());
    assert!(!invalid.is_selectable());
    assert!(matches!(
        invalid.failure,
        Some(DetectionFailure::MissingField("refresh or type=api"))
    ));

    let root: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let expected = format!(
        "{{\"anthropic\":{}}}",
        serde_json::to_string(&root["anthropic"]).unwrap()
    );
    assert_eq!(valid.payload().unwrap().as_bytes(), expected.as_bytes());
    let imported = OAuthCredential::import_provider(
        "opencode",
        valid.payload().unwrap().as_bytes(),
        "anthropic",
    )
    .expect("isolated sibling still imports");
    assert_eq!(
        imported.refresh_token.expose(),
        "fixture-partial-valid-refresh"
    );
    let record = oauth_record("opencode", "anthropic", imported);
    assert_eq!(record.refresh_adapter.as_deref(), Some("anthropic"));
    assert!(record.oauth.is_some());
}

#[test]
fn derivation_and_adapter_table_are_literal_and_selection_is_independent() {
    let cases = [
        (
            ImportSource::Opencode,
            EntryKind::ApiKey,
            Some("k"),
            "apikey:k",
            None,
            EntrySelection::ProviderKey("k".into()),
        ),
        (
            ImportSource::Pi,
            EntryKind::Oauth,
            Some("anthropic"),
            "oauth:anthropic",
            Some("anthropic"),
            EntrySelection::ProviderKey("anthropic".into()),
        ),
        (
            ImportSource::Opencode,
            EntryKind::Oauth,
            Some("openai"),
            "chatgpt:openai",
            Some("openai"),
            EntrySelection::ProviderKey("openai".into()),
        ),
        (
            ImportSource::Opencode,
            EntryKind::Oauth,
            Some("github-copilot"),
            "copilot:github",
            Some("github-copilot"),
            EntrySelection::ProviderKey("github-copilot".into()),
        ),
        (
            ImportSource::GeminiCli,
            EntryKind::Oauth,
            None,
            "oauth:google",
            Some("google"),
            EntrySelection::None,
        ),
        (
            ImportSource::Antigravity,
            EntryKind::Oauth,
            None,
            "antigravity:google",
            Some("antigravity"),
            EntrySelection::AntigravityAccount(0),
        ),
    ];
    for (source, kind, key, id, adapter, selection) in cases {
        let derived = derive_entry(source, kind, key).unwrap();
        assert_eq!(derived.base_id, id);
        assert_eq!(derived.refresh_adapter.as_deref(), adapter);
        assert_eq!(derived.entry_selection, selection);
    }
}

#[test]
fn copilot_uses_harness_key_not_id_provider_token_to_select_payload() {
    let file = fixtures().join("special-providers/opencode-auth.json");
    let rows = enumerate(&paths_with(
        &file,
        missing("pi"),
        missing("gemini"),
        missing("antigravity"),
    ));
    let ids: Vec<_> = rows
        .iter()
        .map(|row| row.metadata.proposed_id.as_deref().unwrap())
        .collect();
    assert_eq!(ids, ["copilot:github", "chatgpt:openai"]);
    let copilot = rows
        .iter()
        .find(|row| row.metadata.proposed_id.as_deref() == Some("copilot:github"))
        .unwrap();
    assert_eq!(
        copilot.metadata.entry_selection,
        EntrySelection::ProviderKey("github-copilot".into())
    );
    let imported = OAuthCredential::import_provider(
        "opencode",
        copilot.payload().unwrap().as_bytes(),
        "github-copilot",
    )
    .expect("correct harness key");
    assert_eq!(imported.refresh_token.expose(), "fixture-copilot-refresh");
    assert!(matches!(
        OAuthCredential::import_provider(
            "opencode",
            copilot.payload().unwrap().as_bytes(),
            "github"
        ),
        Err(ImportError::ProviderNotFound(provider)) if provider == "github"
    ));
}

#[test]
fn derivation_is_not_registration_and_api_keys_need_no_adapter() {
    let file = fixtures().join("unregistered/opencode-auth.json");
    let rows = enumerate(&paths_with(
        &file,
        missing("pi"),
        missing("gemini"),
        missing("antigravity"),
    ));
    let oauth = rows
        .iter()
        .find(|row| row.metadata.harness_provider_key.as_deref() == Some("not-installed"))
        .unwrap();
    assert_eq!(
        oauth.metadata.refresh_adapter.as_deref(),
        Some("not-installed")
    );
    assert!(!oauth.is_selectable());
    let text = oauth.non_selectable_text().unwrap();
    assert!(text.contains("missing adapter 'not-installed'"));
    assert!(text.contains("ck auth import --adapter not-installed"));

    let api = rows
        .iter()
        .find(|row| row.metadata.harness_provider_key.as_deref() == Some("static-control"))
        .unwrap();
    assert!(api.is_selectable());
    assert_eq!(api.metadata.refresh_adapter, None);
    assert_eq!(
        api.metadata.proposed_id.as_deref(),
        Some("apikey:static-control")
    );
    assert_eq!(
        import_api_key(
            "opencode",
            api.payload().unwrap().as_bytes(),
            "static-control"
        )
        .unwrap(),
        b"fixture-static-control-key"
    );

    let forced_missing = enumerate_with_registry(
        &paths_with(
            &file,
            missing("pi"),
            missing("gemini"),
            missing("antigravity"),
        ),
        |_| false,
    );
    assert!(forced_missing
        .iter()
        .find(|row| row.metadata.harness_provider_key.as_deref() == Some("static-control"))
        .unwrap()
        .is_selectable());
}

#[test]
fn labels_are_scoped_across_sources_and_single_rows_remain_bare() {
    let root = TempDir::new("cross-source-labels");
    let op = root.write(
        "opencode.json",
        br#"{"anthropic":{"refresh":"op-r","email":"op@example.com"},"google":{"refresh":"g-r"}}"#,
    );
    let pi = root.write(
        "pi.json",
        br#"{"anthropic":{"refresh":"pi-r","email":"pi@example.com"}}"#,
    );
    let gemini = root.write(
        "gemini.json",
        br#"{"refresh_token":"gem-r","access_token":"gem-a"}"#,
    );
    let rows = enumerate(&paths_with(&op, &pi, &gemini, missing("antigravity")));
    let ids: Vec<_> = rows
        .iter()
        .map(|row| row.metadata.proposed_id.as_deref().unwrap())
        .collect();
    assert!(ids.contains(&"oauth:anthropic:op"));
    assert!(ids.contains(&"oauth:anthropic:pi"));
    assert!(ids.contains(&"oauth:google:opencode"));
    assert!(ids.contains(&"oauth:google:gemini-cli"));

    let single = root.write(
        "single-antigravity.json",
        br#"{"accounts":[{"refreshToken":"only-r"}],"activeIndex":0}"#,
    );
    let single_rows = enumerate(&paths_with(
        missing("opencode-single"),
        missing("pi-single"),
        missing("gemini-single"),
        &single,
    ));
    assert_eq!(
        single_rows[0].metadata.proposed_id.as_deref(),
        Some("antigravity:google")
    );

    let unique_api = root.write(
        "single-opencode.json",
        br#"{"solo":{"type":"api","key":"solo-key"}}"#,
    );
    let single_rows = enumerate(&paths_with(
        &unique_api,
        missing("pi-single-api"),
        missing("gemini-single-api"),
        missing("antigravity-single-api"),
    ));
    assert_eq!(
        single_rows[0].metadata.proposed_id.as_deref(),
        Some("apikey:solo")
    );
}

#[test]
fn labels_use_original_antigravity_index_and_residual_ties_get_no_suffix() {
    let rows = enumerate(&paths_with(
        missing("opencode"),
        missing("pi"),
        missing("gemini"),
        fixtures().join("second-no-email/antigravity-accounts.json"),
    ));
    let ids: Vec<_> = rows
        .iter()
        .map(|row| row.metadata.proposed_id.as_deref().unwrap())
        .collect();
    assert_eq!(ids, ["antigravity:google:first", "antigravity:google:1"]);

    let root = TempDir::new("residual-label-tie");
    let tie = root.write(
        "antigravity.json",
        br#"{"accounts":[{"email":"same@one.example","refreshToken":"one"},{"email":"same@two.example","refreshToken":"two"}]}"#,
    );
    let rows = enumerate(&paths_with(
        missing("opencode-tie"),
        missing("pi-tie"),
        missing("gemini-tie"),
        &tie,
    ));
    assert_eq!(
        rows.iter()
            .map(|row| row.metadata.proposed_id.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["antigravity:google:same", "antigravity:google:same"]
    );
}

#[test]
fn non_selectable_text_never_reproduces_fixture_values_or_serde_text() {
    let file = fixtures().join("partial/antigravity-accounts.json");
    let raw = std::fs::read(&file).unwrap();
    let root: Value = serde_json::from_slice(&raw).unwrap();
    let token = root["accounts"][1]["refreshToken"]["offending"]
        .as_str()
        .unwrap();
    assert!(!token.is_empty());
    let serde_text = import_antigravity_account(&raw, Some("1"))
        .unwrap_err()
        .to_string();
    assert!(!serde_text.is_empty());
    assert_ne!(token, serde_text);

    let rows = enumerate(&paths_with(
        missing("opencode"),
        missing("pi"),
        missing("gemini"),
        &file,
    ));
    let invalid = rows
        .iter()
        .find(|row| row.metadata.original_account_index == Some(1))
        .unwrap();
    let text = invalid.non_selectable_text().unwrap();
    assert!(text.contains("missing field 'refreshToken'"));
    assert!(text.contains("antigravity-accounts.json"));
    assert!(text.contains("account 1"));
    assert!(!text.contains(token));
    assert!(!text.contains(&serde_text));
}

#[test]
fn offline_inventory_exposes_versions_and_picker_antigravity_replace_does_not_mismatch() {
    let root = TempDir::new("offline-version-and-g5");
    let store = open_test_store(&root);
    let fixture_rows = enumerate(&six_paths());
    let first = fixture_rows
        .iter()
        .find(|row| row.metadata.original_account_index == Some(0))
        .unwrap();
    let second = fixture_rows
        .iter()
        .find(|row| row.metadata.original_account_index == Some(1))
        .unwrap();
    let first_import = import_antigravity_account(first.payload().unwrap().as_bytes(), Some("0"))
        .expect("first antigravity account");
    let first_email = first_import.email.clone().unwrap();
    let first_record = oauth_record("antigravity", "antigravity", first_import.oauth)
        .with_identity(RecordIdentity {
            account_id: Some(first_email.clone()),
            email: Some(first_email),
            org_name: None,
        });
    store
        .create("antigravity:google:replace", &first_record)
        .expect("seed replacement target");

    let offline = credentials_core::store::list_meta_read_only(&root.path().join("store.db"))
        .expect("offline metadata read");
    assert_eq!(offline.len(), 1);
    assert_eq!(offline[0].0, "antigravity:google:replace");
    assert_eq!(offline[0].1.record_version, 1);

    let second_import = import_antigravity_account(second.payload().unwrap().as_bytes(), Some("0"))
        .expect("second antigravity account");
    let second_email = second_import.email.clone().unwrap();
    let second_record = oauth_record("antigravity", "antigravity", second_import.oauth)
        .with_identity(RecordIdentity {
            account_id: Some(second_email.clone()),
            email: Some(second_email.clone()),
            org_name: None,
        });
    apply(
        &store,
        AdminOpBody::StoreWithIdentityPolicy {
            v: ADMIN_OP_SCHEMA_V1,
            id: "antigravity:google:replace".into(),
            record: Box::new(second_record),
            audit_op: AdminAuditOp::Import,
            clear_identity: false,
        },
        "import-detect-test",
    )
    .expect("picker-shaped antigravity replace is an ordinary replace");
    let stored = store
        .get("antigravity:google:replace")
        .expect("read replaced account");
    assert_eq!(stored.record_version, 2);
    assert_eq!(
        stored.identity.account_id.as_deref(),
        Some(second_email.as_str())
    );
}

#[test]
fn inventory_tuple_order_and_create_replace_classification_are_named() {
    let inventory = parse_inventory(&json!({
        "credentials": [{
            "state": "active",
            "record_version": 7,
            "id": "oauth:anthropic"
        }]
    }))
    .unwrap();
    let (state, record_version, id) = inventory[0].clone();
    assert_eq!(state, "active");
    assert_eq!(record_version, 7);
    assert_eq!(id, "oauth:anthropic");
    assert_eq!(
        classify_inventory_row(&inventory, "oauth:anthropic"),
        ImportAction::Replace { record_version: 7 }
    );
    assert_eq!(
        classify_inventory_row(&inventory, "oauth:google"),
        ImportAction::Create
    );
}

#[test]
fn slice_two_seams_have_ordering_exhaustion_precedence_and_attempt_contracts() {
    assert_eq!(slice2_contract::FEATURE_NAME, "import-prompt-seam");
    assert_eq!(
        slice2_contract::PROMPT_SCRIPT_ENV,
        "CK_AUTH_IMPORT_PROMPT_SCRIPT"
    );
    assert_eq!(
        slice2_contract::COMMIT_SCRIPT_ENV,
        "CK_AUTH_IMPORT_COMMIT_SCRIPT"
    );
    assert_eq!(
        slice2_contract::SHIPPED_BINARY_ENV,
        "CK_AUTH_IMPORT_SHIPPED_BINARY"
    );
    assert_eq!(slice2_contract::ID_PROMPT_OPEN_LIMIT_PER_ROW, 3);
    assert_eq!(
        slice2_contract::prompt_source(true, true, false, false),
        slice2_contract::PromptSource::InjectedScript
    );
    assert_eq!(
        slice2_contract::prompt_source(false, true, false, false),
        slice2_contract::PromptSource::RefuseNoTty
    );
    assert_eq!(
        slice2_contract::prompt_source(false, false, true, true),
        slice2_contract::PromptSource::Terminal
    );
    assert_eq!(
        slice2_contract::ScriptExhausted { seam: "prompt" }.to_string(),
        "prompt script exhausted before the next ordered response"
    );

    fn prompt_typechecks<T: slice2_contract::PromptSeam>() {}
    fn commit_typechecks<T: slice2_contract::CommitSeam>() {}
    let _ = prompt_typechecks::<NeverPrompt>;
    let _ = commit_typechecks::<NeverCommit>;
}

struct NeverPrompt;

impl slice2_contract::PromptSeam for NeverPrompt {
    type Error = slice2_contract::ScriptExhausted;

    fn prompt(
        &mut self,
        _request: slice2_contract::PromptRequest,
    ) -> Result<slice2_contract::PromptResponse, Self::Error> {
        Err(slice2_contract::ScriptExhausted { seam: "prompt" })
    }
}

struct NeverCommit;

impl slice2_contract::CommitSeam for NeverCommit {
    type Error = slice2_contract::ScriptExhausted;

    fn commit(
        &mut self,
        _final_id: &str,
        _record: credentials_core::record::VaultRecord,
        _action: slice2_contract::CommitAction,
    ) -> Result<Value, Self::Error> {
        Err(slice2_contract::ScriptExhausted { seam: "commit" })
    }
}

#[allow(dead_code)]
fn dialoguer_capability_compile_probe() {
    let multi = dialoguer::MultiSelect::new();
    let _: dialoguer::Result<Option<Vec<usize>>> = multi.interact_opt();
    let input = dialoguer::Input::<String>::new();
    let _: dialoguer::Result<String> = input.interact_text();
}

#[test]
fn dialoguer_multiselect_cancellable_capability_and_amendment_are_compiled() {
    let _compiled_probe: fn() = dialoguer_capability_compile_probe;
    assert!(import_detect::SLICE_1_AMENDMENT
        .contains("MultiSelect and its cancellable interact_opt method are reachable"));
    assert!(import_detect::SLICE_1_AMENDMENT
        .contains("Input has no interact_text_opt-shaped cancellable method"));
    for gate in ["G1 —", "G2 —", "G3 —", "G4 —", "G5 —", "G6 —", "G7 —"] {
        assert!(import_detect::SLICE_1_AMENDMENT.contains(gate));
    }
}
