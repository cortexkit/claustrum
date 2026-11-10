#![cfg(unix)]

#[path = "support/isolated_cli.rs"]
mod isolated_cli;
#[path = "support/terminal_cli.rs"]
mod terminal_cli;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use cortexkit_test_support::ckdev_binary;
use credentials_core::record::CredentialKind;
use credentials_core::store::EncryptedStore;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const VALUE: &str = "interactive-put-canary-83d9";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ck-put-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let fixture = Self(root);
        let output = fixture.command(&["bootstrap"]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(ckdev_binary(env!("CARGO_BIN_EXE_ck-auth")));
        isolated_cli::isolate(&mut command);
        isolated_cli::assert_isolated(&command);
        command
            .args(args)
            .arg("--data-dir")
            .arg(self.0.join("vault"))
            .arg("--key-path")
            .arg(self.0.join("master.key"));
        command
    }

    fn store(&self) -> EncryptedStore {
        let data = self.0.join("vault");
        let key = credentials_core::resolver::resolve(
            &credentials_core::resolver::ResolverConfig {
                data_dir: data.clone(),
                source: credentials_core::resolver::KeySource::OperatorPath {
                    path: self.0.join("master.key"),
                },
            },
            None,
        )
        .unwrap();
        let descriptor = StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let sqlite = open_sqlite(&descriptor).unwrap();
        EncryptedStore::migrate_with_key(&sqlite, &key).unwrap();
        EncryptedStore::open(sqlite, key).unwrap()
    }

    fn terminal(&self, args: &[&str], steps: &[(&str, &[u8], bool)]) -> String {
        let (status, screen) = terminal_cli::run(self.command(args), steps);
        assert!(
            !screen.contains(VALUE),
            "the hidden value appeared in terminal output"
        );
        assert!(status.success(), "terminal command failed: {screen}");
        screen
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn plain_put_stores_a_hidden_api_key_and_default_no_preserves_the_existing_record() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["put"],
        &[
            ("Credential kind", b"\r", false),
            ("Provider name", b"probe:one\r", false),
            ("Groups for this provider", b"\r", false),
            ("Routing provider ids (", b"\r", false),
            ("Save these provider defaults", b"y\r", false),
            ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    assert!(screen.contains("created apikey:probe:one"), "{screen}");
    assert!(screen.contains("ck auth grant"), "{screen}");
    // The secret value is checked for absence before printing the transcript.
    println!("Create transcript (value redacted):\n{screen}");
    let (version, tip) = {
        let store = fixture.store();
        let record = store.get("apikey:probe:one").unwrap();
        assert_eq!(record.kind, CredentialKind::ApiKey);
        assert_eq!(record.payload.expose(), VALUE.as_bytes());
        (
            store.meta("apikey:probe:one").unwrap().record_version,
            store.audit_tip().unwrap(),
        )
    };
    let screen = fixture.terminal(
        &["put"],
        &[
            ("Credential kind", b"\r", false),
            ("Provider name", b"probe:one\r", false),
            ("Replace it?", b"\r", false),
        ],
    );
    assert!(screen.contains("no"), "{screen}");
    assert!(!screen.contains("Value (hidden)"), "{screen}");
    let store = fixture.store();
    assert_eq!(
        store.get("apikey:probe:one").unwrap().payload.expose(),
        VALUE.as_bytes()
    );
    assert_eq!(
        store.meta("apikey:probe:one").unwrap().record_version,
        version
    );
    assert_eq!(store.audit_tip().unwrap(), tip);
    println!("Declined replacement transcript:\n{screen}");
}

#[test]
fn explicit_id_prompts_only_for_value_trims_it_and_reprompts_after_empty_input() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["put", "--id", "apikey:probe:trim"],
        &[
            ("Groups for this provider", b"\r", false),
            ("Routing provider ids (", b"\r", false),
            ("Save these provider defaults", b"y\r", false),
            ("Value (hidden)", b"  \r", true),
            ("Value (hidden)", format!("  {VALUE}  \r").as_bytes(), true),
        ],
    );
    assert!(screen.contains("Value must not be empty."), "{screen}");
    assert!(!screen.contains("Credential kind"), "{screen}");
    assert!(!screen.contains("Provider name"), "{screen}");
    assert_eq!(
        fixture
            .store()
            .get("apikey:probe:trim")
            .unwrap()
            .payload
            .expose(),
        VALUE.as_bytes()
    );
}

#[test]
fn confirming_replace_uses_the_existing_unconditional_rotation_path() {
    let fixture = Fixture::new();
    fixture.terminal(
        &["put", "--id", "apikey:probe:rotate"],
        &[
            ("Groups for this provider", b"\r", false),
            ("Routing provider ids (", b"\r", false),
            ("Save these provider defaults", b"y\r", false),
            ("Value (hidden)", b"initial-test-value\r", true),
        ],
    );
    let screen = fixture.terminal(
        &["put", "--id", "apikey:probe:rotate"],
        &[
            ("Replace it?", b"y\r", false),
            ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    assert!(
        screen.contains("replaced apikey:probe:rotate (unconditional)"),
        "{screen}"
    );
    let store = fixture.store();
    assert_eq!(store.meta("apikey:probe:rotate").unwrap().record_version, 2);
    assert_eq!(
        store.get("apikey:probe:rotate").unwrap().payload.expose(),
        VALUE.as_bytes()
    );
}

#[test]
fn known_api_key_provider_defaults_to_the_checked_login_suggestion() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    let screen = fixture.terminal(
        &["put"],
        &[
            ("Credential kind", b"\r", false),
            ("Provider name", b"groq\r", false),
            ("Continue storing it unchecked?", b"\r", false),
        ],
    );
    assert!(screen.contains("ck auth login --provider groq"), "{screen}");
    assert!(!screen.contains("Value (hidden)"), "{screen}");
    let store = fixture.store();
    assert!(store.get("apikey:groq").is_err());
    assert_eq!(store.audit_tip().unwrap(), before);
}

#[test]
fn unchecked_provider_opt_in_and_explicit_replace_skip_their_resolved_prompts() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["put", "--kind", "api_key"],
        &[
            ("Provider name", b"groq\r", false),
            ("Continue storing it unchecked?", b"y\r", false),
            ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    assert!(!screen.contains("Credential kind"), "{screen}");
    assert_eq!(
        fixture.store().get("apikey:groq").unwrap().kind,
        CredentialKind::ApiKey
    );
    let screen = fixture.terminal(
        &["put", "--id", "apikey:groq", "--replace"],
        &[("Value (hidden)", format!("{VALUE}\r").as_bytes(), true)],
    );
    for skipped in [
        "Credential kind",
        "Provider name",
        "Replace it?",
        "Continue storing",
    ] {
        assert!(!screen.contains(skipped), "{screen}");
    }
    assert!(
        screen.contains("replaced apikey:groq (unconditional)"),
        "{screen}"
    );
}

#[test]
fn cookie_picker_builds_domain_and_account_and_explicit_kinds_skip_the_picker() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["put"],
        &[
            ("Credential kind", b"\x1b[B\r", false),
            ("Site domain", b"example.com\r", false),
            ("Account label", b"work\r", false),
            ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    assert!(
        screen.contains("created cookie:example.com:work"),
        "{screen}"
    );
    assert_eq!(
        fixture.store().get("cookie:example.com:work").unwrap().kind,
        CredentialKind::Cookie
    );
    for (kind, id, expected) in [
        ("dsn", "database", CredentialKind::Dsn),
        ("opaque", "deploy", CredentialKind::Opaque),
    ] {
        let screen = fixture.terminal(
            &["put", "--kind", kind],
            &[
                ("Credential id", format!("{id}\r").as_bytes(), false),
                ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
            ],
        );
        assert!(!screen.contains("Credential kind"), "{screen}");
        assert_eq!(fixture.store().get(id).unwrap().kind, expected);
    }
}

#[test]
fn nonterminal_missing_flags_keep_the_existing_usage_refusals() {
    let fixture = Fixture::new();
    for (args, reason) in [
        (vec!["put"], "--id is required"),
        (
            vec!["put", "--id", "apikey:probe"],
            "--payload-file <path> is required without a terminal for the hidden interactive prompt",
        ),
    ] {
        let output = fixture
            .command(&args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(reason));
    }
}

#[test]
fn registered_provider_prompt_saves_groups_routes_and_a_second_key_reuses_them() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["put", "--id", "apikey:customvendor:first"],
        &[
            ("Groups for this provider", b" \x1b[B\x1b[B\x1b[B \r", false),
            ("Routing provider ids (", b"custom-route\r", false),
            ("Save these provider defaults", b"y\r", false),
            ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    assert!(
        screen.contains("keys reach only modules granted"),
        "{screen}"
    );
    assert!(screen.contains("empty is the safe answer"), "{screen}");
    let answer = fixture.store().registered_providers().unwrap();
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].service, "customvendor");
    assert_eq!(answer[0].categories, ["llm-provider", "web-search"]);
    assert_eq!(answer[0].provider_ids, ["custom-route"]);
    assert!(answer[0].created_at_ms > 0);
    let screen = fixture.terminal(
        &["put", "--id", "apikey:customvendor:second"],
        &[("Value (hidden)", format!("{VALUE}\r").as_bytes(), true)],
    );
    assert!(!screen.contains("Groups for this provider"), "{screen}");
    let store = fixture.store();
    assert_eq!(store.registered_providers().unwrap(), answer);
    for id in ["apikey:customvendor:first", "apikey:customvendor:second"] {
        assert_eq!(
            store.categories(id).unwrap(),
            ["llm-provider", "web-search"]
        );
        assert_eq!(store.provider_ids(id).unwrap(), ["custom-route"]);
    }
}

#[test]
fn registered_provider_default_no_stores_nothing_and_never_reads_the_value() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    let screen = fixture.terminal(
        &["put", "--id", "apikey:declined"],
        &[
            ("Groups for this provider", b" \r", false),
            ("Routing provider ids (", b"\r", false),
            ("Save these provider defaults", b"\r", false),
        ],
    );
    assert!(!screen.contains("Value (hidden)"), "{screen}");
    let store = fixture.store();
    assert!(store.registered_providers().unwrap().is_empty());
    assert!(store.list_meta().unwrap().is_empty());
    assert_eq!(store.audit_tip().unwrap(), before);
}

#[test]
fn registered_provider_empty_answer_is_remembered_and_nonterminal_put_prints_a_hint() {
    let fixture = Fixture::new();
    fixture.terminal(
        &["put", "--id", "apikey:emptyanswer:first"],
        &[
            ("Groups for this provider", b"\r", false),
            ("Routing provider ids (", b"\r", false),
            ("Save these provider defaults", b"y\r", false),
            ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    let screen = fixture.terminal(
        &["put", "--id", "apikey:emptyanswer:second"],
        &[("Value (hidden)", format!("{VALUE}\r").as_bytes(), true)],
    );
    assert!(!screen.contains("Groups for this provider"));
    let answer = fixture.store().registered_providers().unwrap();
    assert_eq!(answer.len(), 1);
    assert!(answer[0].categories.is_empty());
    assert!(answer[0].provider_ids.is_empty());

    let path = fixture.0.join("value");
    std::fs::write(&path, VALUE).unwrap();
    let output = fixture
        .command(&[
            "put",
            "--id",
            "apikey:nonterminal",
            "--payload-file",
            path.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.contains("ck auth provider set --service nonterminal"))
            .count(),
        1,
        "{stderr}"
    );
    let store = fixture.store();
    assert_eq!(store.registered_providers().unwrap(), answer);
    assert_eq!(
        store.get("apikey:nonterminal").unwrap().payload.expose(),
        VALUE.as_bytes()
    );
}

#[test]
fn registered_provider_verbs_are_audited_idempotent_and_never_rewrite_existing_records() {
    let fixture = Fixture::new();
    let path = fixture.0.join("value");
    std::fs::write(&path, VALUE).unwrap();
    let run = |args: &[&str]| {
        let output = fixture.command(args).stdin(Stdio::null()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let put = |id| run(&["put", "--id", id, "--payload-file", path.to_str().unwrap()]);
    put("apikey:registered:old");
    let (old_record, old_meta, audit_len) = {
        let store = fixture.store();
        (
            store
                .get("apikey:registered:old")
                .unwrap()
                .encode()
                .unwrap(),
            store.meta("apikey:registered:old").unwrap(),
            store.read_audit(None).unwrap().len(),
        )
    };
    let set = [
        "provider",
        "set",
        "--service",
        "registered",
        "--category",
        "web-search",
        "--provider-id",
        "registered-route",
    ];
    run(&set);
    let answer = fixture.store().registered_providers().unwrap();
    assert_eq!(
        fixture.store().read_audit(None).unwrap().len(),
        audit_len + 1
    );
    run(&set);
    {
        let store = fixture.store();
        assert_eq!(store.read_audit(None).unwrap().len(), audit_len + 1);
        assert_eq!(store.registered_providers().unwrap(), answer);
        assert_eq!(
            store
                .get("apikey:registered:old")
                .unwrap()
                .encode()
                .unwrap(),
            old_record
        );
        assert_eq!(store.meta("apikey:registered:old").unwrap(), old_meta);
    }
    let output = run(&["provider", "list"]);
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("registered\t[\"web-search\"]\t[\"registered-route\"]"));
    put("apikey:registered:new");
    let output = run(&["list", "--json"]);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rows = rows["credentials"].as_array().unwrap();
    assert!(rows.iter().all(|row| row["provider"] == "registered"));
    let (new_record, new_meta) = {
        let store = fixture.store();
        assert_eq!(
            store.categories("apikey:registered:new").unwrap(),
            ["web-search"]
        );
        assert_eq!(
            store.provider_ids("apikey:registered:new").unwrap(),
            ["registered-route"]
        );
        (
            store
                .get("apikey:registered:new")
                .unwrap()
                .encode()
                .unwrap(),
            store.meta("apikey:registered:new").unwrap(),
        )
    };
    run(&[
        "provider",
        "set",
        "--service",
        "registered",
        "--category",
        "media-provider",
    ]);
    {
        let store = fixture.store();
        assert_eq!(store.meta("apikey:registered:new").unwrap(), new_meta);
        assert_eq!(store.meta("apikey:registered:old").unwrap(), old_meta);
    }
    run(&["provider", "remove", "--service", "registered"]);
    let store = fixture.store();
    assert!(store.registered_providers().unwrap().is_empty());
    assert_eq!(store.meta("apikey:registered:old").unwrap(), old_meta);
    assert_eq!(store.meta("apikey:registered:new").unwrap(), new_meta);
    assert_eq!(
        store
            .get("apikey:registered:old")
            .unwrap()
            .encode()
            .unwrap(),
        old_record
    );
    assert_eq!(
        store
            .get("apikey:registered:new")
            .unwrap()
            .encode()
            .unwrap(),
        new_record
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn registered_provider_explicit_flags_win_and_replace_keeps_the_stored_sets() {
    let fixture = Fixture::new();
    let path = fixture.0.join("value");
    std::fs::write(&path, VALUE).unwrap();
    let run = |args: &[&str]| {
        let output = fixture.command(args).stdin(Stdio::null()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&[
        "provider",
        "set",
        "--service",
        "custom",
        "--category",
        "web-search",
        "--provider-id",
        "default-route",
    ]);
    let answer = fixture.store().registered_providers().unwrap();
    run(&[
        "put",
        "--id",
        "apikey:custom:overridden",
        "--payload-file",
        path.to_str().unwrap(),
        "--provider-id",
        "explicit-route",
    ]);
    assert_eq!(
        fixture
            .store()
            .categories("apikey:custom:overridden")
            .unwrap(),
        ["web-search"]
    );
    run(&[
        "set-category",
        "apikey:custom:overridden",
        "--set",
        "media-provider",
    ]);
    {
        let store = fixture.store();
        assert_eq!(
            store.categories("apikey:custom:overridden").unwrap(),
            ["media-provider"]
        );
        assert_eq!(
            store.provider_ids("apikey:custom:overridden").unwrap(),
            ["explicit-route"]
        );
    }
    run(&[
        "put",
        "--id",
        "apikey:custom:overridden",
        "--replace",
        "--payload-file",
        path.to_str().unwrap(),
    ]);
    let store = fixture.store();
    assert_eq!(
        store.categories("apikey:custom:overridden").unwrap(),
        ["media-provider"]
    );
    assert_eq!(
        store.provider_ids("apikey:custom:overridden").unwrap(),
        ["explicit-route"]
    );
    assert_eq!(store.registered_providers().unwrap(), answer);
}

#[test]
fn registered_provider_catalog_services_are_refused_without_audit() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    let output = fixture
        .command(&[
            "provider",
            "set",
            "--service",
            "groq",
            "--category",
            "web-search",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("fixed provider catalog"));
    let store = fixture.store();
    assert!(store.registered_providers().unwrap().is_empty());
    assert_eq!(store.audit_tip().unwrap(), before);
}

#[test]
fn registered_provider_help_lists_each_action_and_stays_within_eighty_columns() {
    let fixture = Fixture::new();
    let output = fixture.command(&["help"]).output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("provider            list, set or remove")
    );
    let output = fixture.command(&["help", "provider"]).output().unwrap();
    assert!(output.status.success());
    let page = String::from_utf8(output.stdout).unwrap();
    for action in ["list", "set", "remove"] {
        for args in [
            vec!["help", "provider", action],
            vec!["provider", action, "--help"],
        ] {
            let output = fixture.command(&args).output().unwrap();
            assert!(output.status.success());
            let action_page = String::from_utf8(output.stdout).unwrap();
            assert!(
                action_page.starts_with(&format!("ck auth provider {action}\n"))
                    || action_page.starts_with(&format!("ck auth provider {action} --")),
                "{action_page}"
            );
            assert!(
                action_page.lines().all(|line| line.chars().count() <= 80),
                "{action_page}"
            );
        }
        assert!(
            page.contains(&format!("ck auth provider {action}")),
            "{page}"
        );
    }
    assert!(
        page.lines().all(|line| line.chars().count() <= 80),
        "{page}"
    );
}
