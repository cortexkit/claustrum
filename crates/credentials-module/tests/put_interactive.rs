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
fn gateway_put_existing_id_never_offers_replacement_or_provider_registration() {
    let fixture = Fixture::new();
    let args = [
        "put",
        "--id",
        "apikey:anthropic-gw-acme",
        "--gateway-base-url",
        "http://localhost:4000",
        "--gateway-auth-header",
        "authorization",
        "--gateway-auth-scheme",
        "bearer",
        "--provider-id",
        "anthropic-gw-acme",
    ];
    let screen = fixture.terminal(
        &args,
        &[("Value (hidden)", format!("{VALUE}\r").as_bytes(), true)],
    );
    assert!(!screen.contains("Provider "), "{screen}");
    assert!(!screen.contains("Groups for this provider"), "{screen}");
    let before = {
        let store = fixture.store();
        (
            store.meta(args[2]).unwrap(),
            store.gateway_settings(args[2]).unwrap(),
            store.audit_tip().unwrap(),
        )
    };
    let (status, screen) = terminal_cli::run(
        fixture.command(&args),
        &[("Value (hidden)", b"replacement-canary\r", true)],
    );
    assert_eq!(status.code(), Some(1), "{screen}");
    assert!(screen.contains("already exists"), "{screen}");
    assert!(!screen.contains("Replace it?"), "{screen}");
    assert!(!screen.contains("Groups for this provider"), "{screen}");
    assert!(!screen.contains("replacement-canary"), "{screen}");
    let store = fixture.store();
    assert_eq!(
        store.get(args[2]).unwrap().payload.expose(),
        VALUE.as_bytes()
    );
    assert_eq!(
        store.meta(args[2]).unwrap().record_version,
        before.0.record_version
    );
    assert_eq!(
        store.meta(args[2]).unwrap().incarnation,
        before.0.incarnation
    );
    assert_eq!(store.gateway_settings(args[2]).unwrap(), before.1);
    assert_eq!(store.audit_tip().unwrap(), before.2);
}

#[test]
fn gateway_put_usage_errors_precede_all_terminal_prompts() {
    let fixture = Fixture::new();
    for id in ["apikey:anthropic-gw-acme", "apikey:unknown-provider"] {
        for invalid in [
            vec!["--gateway-auth-header", "authorization"],
            vec!["--gateway-auth-scheme", "bearer"],
            vec!["--gateway-header", "x-route=team"],
            vec!["--gateway-base-url", "http://localhost:4000", "--replace"],
            vec![
                "--gateway-base-url",
                "http://localhost:4000",
                "--expected-hash",
                "00",
            ],
        ] {
            let mut args = vec!["put", "--id", id];
            args.extend(invalid);
            let (status, screen) = terminal_cli::run(fixture.command(&args), &[]);
            assert_eq!(status.code(), Some(1), "{args:?}: {screen}");
            for prompt in ["Replace it?", "Groups for this provider", "Value (hidden)"] {
                assert!(!screen.contains(prompt), "{screen}");
            }
        }
    }
    let store = fixture.store();
    assert!(store.list_meta().unwrap().is_empty());
}

#[test]
fn ordinary_put_gateway_service_skips_provider_prompt_and_notice() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["put", "--id", "apikey:anthropic-gw-ordinary"],
        &[("Value (hidden)", format!("{VALUE}\r").as_bytes(), true)],
    );
    assert!(!screen.contains("Provider "), "{screen}");
    assert!(!screen.contains("provider set"), "{screen}");
    assert!(!screen.contains("Groups for this provider"), "{screen}");
    let store = fixture.store();
    assert_eq!(
        store
            .get("apikey:anthropic-gw-ordinary")
            .unwrap()
            .payload
            .expose(),
        VALUE.as_bytes()
    );
    assert!(store
        .gateway_settings("apikey:anthropic-gw-ordinary")
        .unwrap()
        .is_none());
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
            ("Which models may this key run? Leave empty if unsure.", b"\r", false),
            ("Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.", b"\r", false),
            ("Which provider is this in Fusiform's list? Leave empty if unsure.", b"\r", false),
            ("Save these provider settings and continue?", b"y\r", false),
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
            ("Which models may this key run? Leave empty if unsure.", b"\r", false),
            ("Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.", b"\r", false),
            ("Which provider is this in Fusiform's list? Leave empty if unsure.", b"\r", false),
            ("Save these provider settings and continue?", b"y\r", false),
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
            ("Which models may this key run? Leave empty if unsure.", b"\r", false),
            ("Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.", b"\r", false),
            ("Which provider is this in Fusiform's list? Leave empty if unsure.", b"\r", false),
            ("Save these provider settings and continue?", b"y\r", false),
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
            ("Which models may this key run? Leave empty if unsure.", b"custom-route\r", false),
            ("Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.", b"\r", false),
            ("Which provider is this in Fusiform's list? Leave empty if unsure.", b"openai\r", false),
            ("Save these provider settings and continue?", b"y\r", false),
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
    assert_eq!(answer[0].fusiform_provider_id.as_deref(), Some("openai"));
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
fn ordinary_deposit_preflight_uses_defaults_registered_at_the_terminal_prompt() {
    let fixture = Fixture::new();
    let file = fixture.0.join("preflight-key");
    std::fs::write(&file, VALUE).unwrap();
    let screen = fixture.terminal(
        &[
            "put",
            "--id",
            "apikey:preflightvendor:work",
            "--payload-file",
            file.to_str().unwrap(),
        ],
        &[
            ("Groups for this provider", b"\r", false),
            (MODELS, b"prompt-route\r", false),
            (ADDRESSES, b"\r", false),
            (
                "Which provider is this in Fusiform's list? Leave empty if unsure.",
                b"\r",
                false,
            ),
            ("Save these provider settings and continue?", b"y\r", false),
        ],
    );
    assert!(
        screen.contains("created apikey:preflightvendor:work"),
        "{screen}"
    );
    let store = fixture.store();
    assert_eq!(
        store.registered_providers().unwrap()[0].provider_ids,
        ["prompt-route"]
    );
    assert_eq!(
        store.provider_ids("apikey:preflightvendor:work").unwrap(),
        ["prompt-route"]
    );
    assert_eq!(
        store
            .get("apikey:preflightvendor:work")
            .unwrap()
            .payload
            .expose(),
        VALUE.as_bytes()
    );
}

#[test]
fn ordinary_deposit_preflight_usage_errors_precede_terminal_provider_and_value_prompts() {
    let fixture = Fixture::new();
    let tip = fixture.store().audit_tip().unwrap();
    for (id, provider, reason) in [
        ("apikey:unregistered", "anthropic-gw-x", "rule=reserved"),
        (
            "apikey:anthropic-gw-ordinary",
            "openai",
            "ck auth set-providers",
        ),
    ] {
        let (status, screen) = terminal_cli::run(
            fixture.command(&["put", "--id", id, "--provider-id", provider]),
            &[],
        );
        assert_eq!(status.code(), Some(1), "{screen}");
        assert!(screen.contains(reason), "{screen}");
        for prompt in [
            "Groups for this provider",
            "Value (hidden)",
            "Unknown provider",
        ] {
            assert!(!screen.contains(prompt), "{screen}");
        }
    }
    let store = fixture.store();
    assert!(store.list_meta().unwrap().is_empty());
    assert_eq!(store.audit_tip().unwrap(), tip);
}

#[test]
fn registered_provider_default_no_stores_nothing_and_never_reads_the_value() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    let screen = fixture.terminal(
        &["put", "--id", "apikey:declined"],
        &[
            ("Groups for this provider", b" \r", false),
            ("Which models may this key run? Leave empty if unsure.", b"\r", false),
            ("Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.", b"\r", false),
            ("Which provider is this in Fusiform's list? Leave empty if unsure.", b"\r", false),
            ("Save these provider settings and continue?", b"\r", false),
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
    let first_screen = fixture.terminal(
        &["put", "--id", "apikey:emptyanswer:first"],
        &[
            ("Groups for this provider", b"\r", false),
            ("Which models may this key run? Leave empty if unsure.", b"\r", false),
            ("Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.", b"\r", false),
            ("Which provider is this in Fusiform's list? Leave empty if unsure.", b"\r", false),
            ("Save these provider settings and continue?", b"y\r", false),
            ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    for prompt in [
        "Which request header carries the key?",
        "Is the key sent as 'Bearer <key>' or by itself?",
    ] {
        assert!(!first_screen.contains(prompt), "{first_screen}");
    }
    let screen = fixture.terminal(
        &["put", "--id", "apikey:emptyanswer:second"],
        &[("Value (hidden)", format!("{VALUE}\r").as_bytes(), true)],
    );
    assert!(!screen.contains("Groups for this provider"));
    let answer = fixture.store().registered_providers().unwrap();
    assert_eq!(answer.len(), 1);
    assert!(answer[0].categories.is_empty());
    assert!(answer[0].provider_ids.is_empty());
    assert!(answer[0].hosts.is_empty());
    assert_eq!(answer[0].auth_header, None);
    assert_eq!(answer[0].auth_scheme, None);
    assert_eq!(answer[0].fusiform_provider_id, None);

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
fn registered_provider_prompt_pins_descriptor_questions_and_canonicalizes_answers() {
    for (service, choice, scheme) in [
        ("prompt-bearer", b"\r".as_slice(), "bearer"),
        ("prompt-raw", b"\x1b[B\r".as_slice(), "raw"),
    ] {
        let fixture = Fixture::new();
        let id = format!("apikey:{service}");
        let screen = fixture.terminal(
            &["put", "--id", &id],
            &[
                ("Groups for this provider", b"\r", false),
                ("Which models may this key run? Leave empty if unsure.", b"\r", false),
                ("Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.", b" B.example.com, a.example.com, b.example.com \r", false),
                ("Which request header carries the key?", b"X-API-Key\r", false),
                ("Is the key sent as 'Bearer <key>' or by itself?", choice, false),
                ("Which provider is this in Fusiform's list? Leave empty if unsure.", b"openai\r", false),
                ("Save these provider settings and continue?", b"y\r", false),
                ("Value (hidden)", format!("{VALUE}\r").as_bytes(), true),
            ],
        );
        for choice in ["Bearer <key>", "The key by itself"] {
            assert!(screen.contains(choice), "{screen}");
        }
        let mut position = 0;
        for prompt in [
            "Groups for this provider",
            "Which models may this key run? Leave empty if unsure.",
            "Which addresses may receive this key?",
            "Which request header carries the key?",
            "Is the key sent as 'Bearer <key>' or by itself?",
            "Which provider is this in Fusiform's list? Leave empty if unsure.",
            "Save these provider settings and continue?",
            "Value (hidden)",
        ] {
            position += screen[position..]
                .find(prompt)
                .unwrap_or_else(|| panic!("missing ordered prompt {prompt}: {screen}"))
                + prompt.len();
        }
        let rows = fixture.store().registered_providers().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hosts, ["a.example.com", "b.example.com"]);
        assert_eq!(rows[0].auth_header.as_deref(), Some("x-api-key"));
        assert_eq!(rows[0].auth_scheme.as_deref(), Some(scheme));
        assert_eq!(rows[0].fusiform_provider_id.as_deref(), Some("openai"));
    }
}

#[test]
fn registered_provider_descriptor_flags_round_trip_and_omission_clears_settings() {
    let fixture = Fixture::new();
    let run = |args: &[&str]| {
        let output = fixture.command(args).stdin(Stdio::null()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    for scheme in ["bearer", "raw"] {
        run(&[
            "provider",
            "set",
            "--service",
            "custom-descriptor",
            "--category",
            "llm-provider",
            "--provider-id",
            "custom-route",
            "--host",
            " B.example.com, a.example.com ",
            "--host",
            "b.example.com",
            "--auth-header",
            "X-API-Key",
            "--auth-scheme",
            scheme,
            "--fusiform-id",
            "openai",
        ]);
        assert_eq!(run(&["provider", "list"]), format!(
            "SERVICE\tGROUPS\tPROVIDER IDS\tHOSTS\tAUTH\tFUSIFORM ID\ncustom-descriptor\t[\"llm-provider\"]\t[\"custom-route\"]\t[\"a.example.com\",\"b.example.com\"]\t{{\"header\":\"x-api-key\",\"scheme\":\"{scheme}\"}}\t\"openai\"\n"
        ));
    }
    run(&["provider", "set", "--service", "custom-descriptor"]);
    assert_eq!(run(&["provider", "list"]),
        "SERVICE\tGROUPS\tPROVIDER IDS\tHOSTS\tAUTH\tFUSIFORM ID\ncustom-descriptor\t[]\t[]\t[]\tnull\tnull\n");
}

#[test]
fn registered_provider_bad_descriptor_flags_are_refused_before_preflight_or_writes() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    let key_path = fixture.0.join("master.key");
    let saved_key = fixture.0.join("saved.key");
    std::fs::rename(&key_path, &saved_key).unwrap();
    let cases: &[(&[&str], &str)] = &[
        (&["--fusiform-id", "unknown-provider"], "unknown-provider"),
        (
            &[
                "--host",
                "https://bad.example.com",
                "--auth-header",
                "authorization",
                "--auth-scheme",
                "bearer",
            ],
            "https://bad.example.com",
        ),
        (
            &[
                "--host",
                "bad.example.com:443",
                "--auth-header",
                "authorization",
                "--auth-scheme",
                "bearer",
            ],
            "bad.example.com:443",
        ),
        (
            &[
                "--host",
                "*.example.com",
                "--auth-header",
                "authorization",
                "--auth-scheme",
                "bearer",
            ],
            "*.example.com",
        ),
        (
            &[
                "--host",
                "a.example.com",
                "--auth-header",
                "Bad Header",
                "--auth-scheme",
                "bearer",
            ],
            "bad header",
        ),
        (
            &[
                "--host",
                "a.example.com",
                "--auth-header",
                "authorization",
                "--auth-scheme",
                "Basic",
            ],
            "Basic",
        ),
        (
            &["--host", "a.example.com"],
            "hosts/auth (must be given together)",
        ),
        (
            &["--auth-header", "authorization", "--auth-scheme", "bearer"],
            "hosts/auth (must be given together)",
        ),
        (
            &["--host", "a.example.com", "--auth-header", "authorization"],
            "hosts/auth (must be given together)",
        ),
        (
            &["--host", "a.example.com", "--auth-scheme", "bearer"],
            "hosts/auth (must be given together)",
        ),
    ];
    for (flags, bad_value) in cases {
        let mut args = vec!["provider", "set", "--service", "invalid-descriptor"];
        args.extend_from_slice(flags);
        let output = fixture
            .command(&args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("invalid provider") && stderr.contains(bad_value),
            "{stderr}"
        );
        assert!(
            !key_path.exists(),
            "validation reached master-key preflight"
        );
    }
    std::fs::rename(saved_key, key_path).unwrap();
    let store = fixture.store();
    assert!(store.registered_providers().unwrap().is_empty());
    assert_eq!(store.audit_tip().unwrap(), before);
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
    assert_eq!(String::from_utf8_lossy(&output.stdout),
        "SERVICE\tGROUPS\tPROVIDER IDS\tHOSTS\tAUTH\tFUSIFORM ID\nregistered\t[\"web-search\"]\t[\"registered-route\"]\t[]\tnull\tnull\n");
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Provider service \"groq\""), "{stderr}");
    assert!(!stderr.contains("storage error"), "{stderr}");
    let store = fixture.store();
    assert!(store.registered_providers().unwrap().is_empty());
    assert_eq!(store.audit_tip().unwrap(), before);
}

#[test]
fn registered_provider_invalid_services_are_plain_refusals_without_audit() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    for service in [
        "",
        "has space",
        "has:label",
        "has|separator",
        "has\nnewline",
        "has\u{1b}control",
    ] {
        let output = fixture
            .command(&["provider", "set", "--service", service])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("Provider service {service:?} is invalid")),
            "{stderr}"
        );
        assert!(!stderr.contains("storage error"), "{stderr}");
    }
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

const LOGIN_PICKER: &str = "Select provider to login (type to search)";
const PROVIDER_NAME: &str = "Provider name (optionally provider:label)";
const NO_FREE_CHECK: &str = "This provider has no free check; the key is checked when first used.";
const MODELS: &str = "Which models may this key run? Leave empty if unsure.";
const ADDRESSES: &str = "Which addresses may receive this key? Host names only, like api.example.com, separated by commas. Leave empty if unsure.";

fn seed_login_key(fixture: &Fixture, id: &str) {
    let path = fixture.0.join("key-input");
    std::fs::write(&path, "initial-login-test-value").unwrap();
    let output = fixture
        .command(&["put", "--kind", "api_key", "--id", id, "--payload-file"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn login_other_new_provider_stores_registration_defaults_like_put_and_reuses_them() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["login"],
        &[
            (LOGIN_PICKER, b"Other API key provider\r", false),
            (PROVIDER_NAME, b"loginvendor:work\r", false),
            ("Groups for this provider", b" \x1b[B\x1b[B\x1b[B \r", false),
            (MODELS, b"custom-route\r", false),
            (ADDRESSES, b"\r", false),
            (
                "Which provider is this in Fusiform's list? Leave empty if unsure.",
                b"\r",
                false,
            ),
            ("Save these provider settings and continue?", b"y\r", false),
            (
                "Enter API key for loginvendor:work",
                format!("{VALUE}\r").as_bytes(),
                true,
            ),
        ],
    );
    let mut position = 0;
    for prompt in [
        LOGIN_PICKER,
        PROVIDER_NAME,
        "Groups for this provider",
        MODELS,
        ADDRESSES,
        "Which provider is this in Fusiform's list? Leave empty if unsure.",
        "Save these provider settings and continue?",
        NO_FREE_CHECK,
        "Enter API key for loginvendor:work",
        "logged in and stored apikey:loginvendor:work",
    ] {
        position += screen[position..]
            .find(prompt)
            .unwrap_or_else(|| panic!("missing ordered prompt {prompt}: {screen}"))
            + prompt.len();
    }
    assert!(!screen.contains("Validating API key"), "{screen}");
    let registration = fixture.store().registered_providers().unwrap();
    assert_eq!(registration.len(), 1);
    assert_eq!(registration[0].service, "loginvendor");
    assert_eq!(registration[0].categories, ["llm-provider", "web-search"]);
    assert_eq!(registration[0].provider_ids, ["custom-route"]);
    seed_login_key(&fixture, "apikey:loginvendor:put");
    {
        let store = fixture.store();
        let record = store.get("apikey:loginvendor:work").unwrap();
        assert_eq!(record.kind, CredentialKind::ApiKey);
        assert_eq!(record.payload.expose(), VALUE.as_bytes());
        for id in ["apikey:loginvendor:work", "apikey:loginvendor:put"] {
            assert_eq!(store.categories(id).unwrap(), registration[0].categories);
            assert_eq!(
                store.provider_ids(id).unwrap(),
                registration[0].provider_ids
            );
        }
    }
    let screen = fixture.terminal(
        &["login"],
        &[
            (LOGIN_PICKER, b"Other API key provider\r", false),
            (PROVIDER_NAME, b"loginvendor:work\r", false),
            ("Replace it?", b"y\r", false),
            (
                "Enter API key for loginvendor:work",
                b"rotated-login-test-value\r",
                true,
            ),
        ],
    );
    assert!(!screen.contains("Groups for this provider"), "{screen}");
    assert!(!screen.contains("Save these provider settings"), "{screen}");
    assert!(!screen.contains("rotated-login-test-value"));
    assert!(
        screen.contains("logged in and replaced apikey:loginvendor:work"),
        "{screen}"
    );
    let store = fixture.store();
    assert_eq!(store.registered_providers().unwrap(), registration);
    assert_eq!(
        store
            .meta("apikey:loginvendor:work")
            .unwrap()
            .record_version,
        2
    );
    assert_eq!(
        store
            .get("apikey:loginvendor:work")
            .unwrap()
            .payload
            .expose(),
        b"rotated-login-test-value"
    );
}

#[test]
fn login_other_default_no_preserves_unregistered_and_catalog_credentials_before_any_questions() {
    for (name, id) in [
        ("unregistered:work", "apikey:unregistered:work"),
        ("zai", "apikey:zai"),
    ] {
        let fixture = Fixture::new();
        seed_login_key(&fixture, id);
        let (record, categories, ids, registry, tip, version) = {
            let store = fixture.store();
            (
                store.get(id).unwrap(),
                store.categories(id).unwrap(),
                store.provider_ids(id).unwrap(),
                store.registered_providers().unwrap(),
                store.audit_tip().unwrap(),
                store.meta(id).unwrap().record_version,
            )
        };
        assert!(registry.is_empty());
        let screen = fixture.terminal(
            &["login"],
            &[
                (LOGIN_PICKER, b"Other API key provider\r", false),
                (PROVIDER_NAME, format!("{name}\r").as_bytes(), false),
                ("Replace it?", b"\r", false),
            ],
        );
        assert!(
            screen.contains(&format!("{id} already holds a credential.")),
            "{screen}"
        );
        for absent in [
            "Groups for this provider",
            MODELS,
            ADDRESSES,
            "Enter API key",
            "Validating API key",
            NO_FREE_CHECK,
            "--replace",
        ] {
            assert!(!screen.contains(absent), "unexpected {absent}: {screen}");
        }
        let store = fixture.store();
        assert_eq!(
            store.get(id).unwrap().payload.expose(),
            record.payload.expose()
        );
        assert_eq!(store.categories(id).unwrap(), categories);
        assert_eq!(store.provider_ids(id).unwrap(), ids);
        assert_eq!(store.meta(id).unwrap().record_version, version);
        assert_eq!(store.registered_providers().unwrap(), registry);
        assert_eq!(store.audit_tip().unwrap(), tip);
    }
}

#[test]
fn login_other_declining_registration_writes_neither_registration_nor_key() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    let screen = fixture.terminal(
        &["login"],
        &[
            (LOGIN_PICKER, b"Other API key provider\r", false),
            (PROVIDER_NAME, b"declinedlogin\r", false),
            ("Groups for this provider", b" \r", false),
            (MODELS, b"\r", false),
            (ADDRESSES, b"\r", false),
            (
                "Which provider is this in Fusiform's list? Leave empty if unsure.",
                b"\r",
                false,
            ),
            ("Save these provider settings and continue?", b"\r", false),
        ],
    );
    assert!(!screen.contains("Enter API key"), "{screen}");
    assert!(!screen.contains(NO_FREE_CHECK), "{screen}");
    let store = fixture.store();
    assert!(store.registered_providers().unwrap().is_empty());
    assert!(store.list_meta().unwrap().is_empty());
    assert_eq!(store.audit_tip().unwrap(), before);
}

#[test]
fn login_other_catalog_replacement_uses_the_rows_probe_without_replace_advice() {
    let fixture = Fixture::new();
    seed_login_key(&fixture, "apikey:zai:work");
    let mut command = fixture.command(&["login"]);
    command.env("CORTEXKIT_TEST_BYPASS_VALIDATION", "1");
    let (status, screen) = terminal_cli::run(
        command,
        &[
            (LOGIN_PICKER, b"Other API key provider\r", false),
            (PROVIDER_NAME, b"zai:work\r", false),
            ("Replace it?", b"y\r", false),
            ("Enter API key for", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    assert!(!screen.contains(VALUE));
    assert!(status.success(), "{screen}");
    assert!(screen.contains("Validating API key..."), "{screen}");
    assert!(screen.contains("API key is valid."), "{screen}");
    assert!(
        screen.contains("logged in and replaced apikey:zai:work"),
        "{screen}"
    );
    for absent in ["--replace", "Groups for this provider", NO_FREE_CHECK] {
        assert!(!screen.contains(absent), "{screen}");
    }
    let store = fixture.store();
    assert_eq!(store.meta("apikey:zai:work").unwrap().record_version, 2);
    assert_eq!(
        store.get("apikey:zai:work").unwrap().payload.expose(),
        VALUE.as_bytes()
    );
    assert!(store.registered_providers().unwrap().is_empty());
}

#[test]
fn login_other_unvalidated_catalog_row_warns_before_the_key_and_keeps_the_note_after_it() {
    let fixture = Fixture::new();
    let screen = fixture.terminal(
        &["login"],
        &[
            (LOGIN_PICKER, b"Other API key provider\r", false),
            (PROVIDER_NAME, b"searxng:work\r", false),
            ("Enter API key for", format!("{VALUE}\r").as_bytes(), true),
        ],
    );
    let warning = screen.find(NO_FREE_CHECK).unwrap();
    let prompt = screen.find("Enter API key for").unwrap();
    let note = screen
        .find("NOTE: storing this API key without checking it:")
        .unwrap();
    assert!(warning < prompt && prompt < note, "{screen}");
    assert!(!screen.contains("Validating API key"), "{screen}");
    assert!(
        screen.contains("logged in and stored apikey:searxng:work"),
        "{screen}"
    );
    assert!(fixture.store().registered_providers().unwrap().is_empty());
}

#[test]
fn login_other_picker_lists_every_existing_row_before_other() {
    let fixture = Fixture::new();
    let names: Vec<_> = [
        "Anthropic (Claude Pro/Max)",
        "ChatGPT (Codex subscription)",
        "xAI (Grok)",
        "GitHub Copilot",
        "Kimi Code",
        "Meta Muse (coding subscription)",
        "Google Gemini CLI (Code Assist)",
        "Gmail (send as you)",
        "Antigravity (Gemini 3)",
        "Cursor",
        "Devin",
        "Snowflake Cortex",
        "DigitalOcean GenAI",
    ]
    .into_iter()
    .chain(
        credentials_core::catalog::API_KEY_PROVIDERS
            .iter()
            .map(|row| row.display_name),
    )
    .collect();
    let mut steps: Vec<(&str, &[u8], bool)> = names
        .iter()
        .map(|name| (*name, b"\x1b[B".as_slice(), false))
        .collect();
    steps.extend([
        ("Other API key provider…", b"\r".as_slice(), false),
        (PROVIDER_NAME, b"pickeronly\r".as_slice(), false),
        ("Groups for this provider", b"\r".as_slice(), false),
        (MODELS, b"\r".as_slice(), false),
        (ADDRESSES, b"\r".as_slice(), false),
        (
            "Which provider is this in Fusiform's list? Leave empty if unsure.",
            b"\r".as_slice(),
            false,
        ),
        (
            "Save these provider settings and continue?",
            b"\r".as_slice(),
            false,
        ),
    ]);
    let screen = fixture.terminal(&["login"], &steps);
    for name in names.into_iter().chain(["Other API key provider…"]) {
        assert!(screen.contains(name), "missing picker row {name}: {screen}");
    }
    assert!(fixture.store().list_meta().unwrap().is_empty());
}

#[test]
fn login_other_help_names_login_as_the_provider_key_entry_point() {
    let fixture = Fixture::new();
    for (verb, expected) in [
        ("put", "Use ck auth login to add a provider key"),
        ("login", "Other API key provider…"),
    ] {
        let output = fixture.command(&[verb, "--help"]).output().unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains(expected), "{help}");
        assert!(
            help.lines().all(|line| line.chars().count() <= 80),
            "{help}"
        );
    }
}
