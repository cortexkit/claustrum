use super::*;
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    record::VaultRecord,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{json, Value};

const ROOT_KEY: &str = credentials_core::store::GH_MANIFEST_ROOT_KEY_ID;
const V28: &str = include_str!("../../../credentials-core/tests/fixtures/gh-manifest-v28.json");

fn setup(tag: &str) -> (GrantCliVault, Ed25519KeyPair) {
    let vault = GrantCliVault::new(tag);
    vault.bootstrap();
    let der = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_ref())
    );
    let store = open_leased_store(&vault.data_dir, &vault.key_path);
    store
        .create_audited(
            ROOT_KEY,
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                pem.into_bytes(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    drop(store);
    (vault, pair)
}

fn result(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn manifest_file(vault: &GrantCliVault, version: i64) -> PathBuf {
    let path = vault.root.join(format!("manifest-v{version}.json"));
    std::fs::write(
        &path,
        V28.replace(
            "\"manifest_version\": 28",
            &format!("\"manifest_version\": {version}"),
        ),
    )
    .unwrap();
    path
}

fn sign(vault: &GrantCliVault, version: i64) -> std::process::Output {
    let path = manifest_file(vault, version);
    vault.run(&[
        "manifest",
        "sign",
        "--file",
        path.to_str().unwrap(),
        "--approver",
        "test-operator",
    ])
}

fn count(vault: &GrantCliVault, query: &str) -> i64 {
    rusqlite::Connection::open(vault.data_dir.join("store.db"))
        .unwrap()
        .query_row(query, [], |r| r.get(0))
        .unwrap()
}

fn audit_count(vault: &GrantCliVault, op: &str) -> i64 {
    count(
        vault,
        &format!("SELECT COUNT(*) FROM audit_log WHERE op='{op}'"),
    )
}

fn assert_private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(path.is_file());
}

#[test]
fn manifest_cli_import_list_retire_and_one_tap_dispatch_admin_ops() {
    let (vault, pair) = setup("manifest-cli-admin");
    let envelope = json!({
        "key_id":credentials_core::signing::key_id_for_public(pair.public_key().as_ref()),
        "manifest_bytes":V28,
        "signature":base64::engine::general_purpose::STANDARD.encode(pair.sign(V28.as_bytes()).as_ref()),
    });
    let path = vault.root.join("import.json");
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert_eq!(
        result(vault.run(&["manifest", "one-tap", "status"]))["one_tap"],
        "off"
    );
    for (action, expected_audits) in [
        ("off", 1),
        ("off", 1),
        ("on", 2),
        ("on", 2),
        ("off", 3),
        ("off", 3),
    ] {
        result(vault.run(&["manifest", "one-tap", action]));
        assert_eq!(
            audit_count(&vault, "gh_manifest_one_tap_set"),
            expected_audits
        );
    }
    assert_eq!(
        result(vault.run(&["manifest", "one-tap", "status"]))["one_tap"],
        "off"
    );
    let imported = result(vault.run(&["manifest", "import", "--envelope", path.to_str().unwrap()]));
    assert_eq!(imported["version"], 28);
    let signed = result(sign(&vault, 29));
    assert_eq!(signed["version"], 29);
    let member = "fed-computer:33333333333333333333333333333333";
    result(vault.run(&["manifest", "retire-machine", "--member", member]));
    let listed = result(vault.run(&["manifest", "list"]));
    assert_eq!(listed["versions"][0]["source"], "import");
    assert_eq!(listed["versions"][1]["source"], "ceremony");
    assert_eq!(
        listed["versions"][1]["manifest_sha256"],
        signed["manifest_sha256"]
    );
    assert!(listed["versions"][1]["signed_at_ms"].as_i64().unwrap() > 0);
    assert_eq!(listed["computers"][0]["member_id"], member);
    assert_eq!(listed["computers"][0]["expected"], false);
    assert!(listed["computers"][0]["retired_at_ms"].as_i64().unwrap() > 0);
    assert_eq!(audit_count(&vault, "gh_manifest_retire"), 1);
    assert!(!vault.data_dir.join("signed-payloads").exists());
}

#[test]
fn manifest_cli_failed_commit_leaves_no_row_or_file() {
    let (vault, _) = setup("manifest-cli-commit-failure");
    rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap().execute_batch(
        "CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
         CREATE TABLE commit_child(id INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER fail_manifest_commit AFTER INSERT ON gh_manifests
         BEGIN INSERT INTO commit_child VALUES(1); END;"
    ).unwrap();
    let before = count(&vault, "SELECT COUNT(*) FROM audit_log");
    let output = sign(&vault, 28);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("FOREIGN KEY constraint failed"));
    assert_eq!(count(&vault, "SELECT COUNT(*) FROM gh_manifests"), 0);
    assert_eq!(count(&vault, "SELECT COUNT(*) FROM audit_log"), before);
    assert!(!vault.data_dir.join("signed-envelopes").exists());
}

#[test]
fn manifest_cli_file_failure_keeps_committed_version_for_export_after_restart() {
    let (vault, _) = setup("manifest-cli-file-failure");
    let destination = vault.data_dir.join("signed-envelopes/v28-envelope.json");
    std::fs::create_dir_all(&destination).unwrap();
    let output = sign(&vault, 28);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("version 28 is stored"), "{error}");
    assert!(
        error.contains("ck auth manifest export --version 28"),
        "{error}"
    );
    assert_eq!(
        count(&vault, "SELECT COUNT(*) FROM gh_manifests WHERE version=28"),
        1
    );
    assert_eq!(audit_count(&vault, "approval"), 1);
    assert_eq!(audit_count(&vault, "gh_manifest_sign"), 1);
    assert_eq!(
        std::fs::read_dir(destination.parent().unwrap())
            .unwrap()
            .count(),
        1,
        "failed temp is removed"
    );
    std::fs::remove_dir(&destination).unwrap();
    let before = count(&vault, "SELECT COUNT(*) FROM audit_log");
    let exported = result(vault.run(&["manifest", "export", "--version", "28"]));
    assert_eq!(exported["manifest_bytes"], V28);
    assert_private(&destination);
    assert_eq!(count(&vault, "SELECT COUNT(*) FROM audit_log"), before);
}

#[test]
fn manifest_cli_export_after_restart_is_byte_identical_and_replaces_permissions() {
    let (vault, pair) = setup("manifest-cli-export");
    let signed = result(sign(&vault, 28));
    let destination = vault.data_dir.join("signed-envelopes/v28-envelope.json");
    assert_private(&destination);
    let original = std::fs::read(&destination).unwrap();
    let envelope: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(envelope, signed["envelope"]);
    let signature = base64::engine::general_purpose::STANDARD
        .decode(envelope["signature"].as_str().unwrap())
        .unwrap();
    UnparsedPublicKey::new(&ED25519, pair.public_key().as_ref())
        .verify(V28.as_bytes(), &signature)
        .unwrap();
    let before = count(&vault, "SELECT COUNT(*) FROM audit_log");
    std::fs::write(&destination, "broken derived file").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let exported = result(vault.run(&["manifest", "export", "--version", "28"]));
    assert_eq!(exported, envelope);
    assert_eq!(std::fs::read(&destination).unwrap(), original);
    assert_private(&destination);
    assert_eq!(
        std::fs::read_dir(destination.parent().unwrap())
            .unwrap()
            .count(),
        1
    );
    assert_eq!(count(&vault, "SELECT COUNT(*) FROM audit_log"), before);
}

#[test]
fn manifest_cli_help_and_bad_arguments_are_safe_without_a_key() {
    for verb in [
        "import",
        "sign",
        "export",
        "list",
        "retire-machine",
        "one-tap",
    ] {
        let help = cli().args(["help", "manifest", verb]).output().unwrap();
        let flag = cli().args(["manifest", verb, "--help"]).output().unwrap();
        assert!(help.status.success());
        assert!(flag.status.success());
        assert_eq!(help.stdout, flag.stdout);
        let text = String::from_utf8(help.stdout).unwrap();
        assert!(
            text.starts_with(&format!("ck auth manifest {verb}")),
            "{text}"
        );
        assert!(
            text.lines().all(|line| line.chars().count() <= 80),
            "{text}"
        );
    }
    let vault = GrantCliVault::new("manifest-cli-grammar");
    for args in [
        vec!["manifest"],
        vec!["manifest", "sign"],
        vec!["manifest", "list", "--file", "ignored"],
        vec!["manifest", "one-tap", "on", "off"],
        vec!["manifest", "one-tap", "unknown"],
        vec!["manifest", "export", "--version", "0"],
        vec!["manifest", "export", "--version", "-1"],
        vec!["manifest", "export", "--version", "1.5"],
        vec!["manifest", "export", "--version", "1", "--version", "2"],
        vec!["manifest", "retire-machine", "--member"],
        vec!["manifest", "import", "--envelope", "--file"],
    ] {
        let out = vault.run(&args);
        assert!(!out.status.success(), "{args:?}");
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("master key"));
    }
    assert!(!vault.data_dir.join("store.db").exists());
}

#[test]
fn manifest_root_signer_has_exactly_the_two_production_call_sites() {
    fn scan(directory: &std::path::Path, sites: &mut Vec<(PathBuf, usize)>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().unwrap() != "tests" {
                    scan(&path, sites);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let name = path.file_name().unwrap().to_str().unwrap();
                if name.ends_with("_tests.rs") || name == "tests.rs" {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
                let count = compact.matches("sign_gh_manifest(").count()
                    - compact.matches("fnsign_gh_manifest(").count();
                if count > 0 {
                    sites.push((path, count));
                }
            }
        }
    }
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let mut sites = Vec::new();
    scan(&crates, &mut sites);
    sites.sort();
    assert_eq!(
        sites,
        vec![
            (crates.join("credentials-core/src/store_gh_admin.rs"), 1),
            (crates.join("credentials-core/src/store_gh_approval.rs"), 1),
        ],
        "only the sign admin op and manifest.approve may use the root signer"
    );
}
