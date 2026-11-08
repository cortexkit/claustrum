#![cfg(unix)]

#[path = "support/isolated_cli.rs"]
mod isolated_cli;
#[path = "support/terminal_cli.rs"]
mod terminal_cli;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use cortexkit_test_support::ckdev_binary;
use credentials_core::record::RecordState;
use credentials_core::store::{EncryptedStore, StoreOpError};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const PICKER: &str = "Select a credential to log out (type to search)";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ck-logout-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let fixture = Self(root);
        fixture.success(&["bootstrap"]);
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

    fn success(&self, args: &[&str]) -> String {
        let output = self.command(args).stdin(Stdio::null()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn put(&self, id: &str) {
        let payload = self.0.join("payload");
        std::fs::write(&payload, b"logout-test-value").unwrap();
        self.success(&[
            "put",
            "--id",
            id,
            "--payload-file",
            payload.to_str().unwrap(),
        ]);
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
        assert!(status.success(), "terminal command failed: {screen}");
        screen
    }

    fn excluded_records(&self) {
        self.put("apikey:retired");
        self.success(&["logout", "--id", "apikey:retired"]);
        self.put("apikey:corrupt");
        self.store().quarantine("apikey:corrupt").unwrap();
        self.success(&["mint-signing-key", "--id", "signing:logout-test"]);
        self.success(&["mint-kem-key", "--id", "kem:logout-test"]);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn logout_picker_lists_only_eligible_ids_and_states_in_id_order() {
    let fixture = Fixture::new();
    fixture.put("apikey:zulu");
    fixture.put("apikey:alpha");
    fixture.store().invalidate("apikey:zulu").unwrap();
    fixture.excluded_records();
    let before = fixture.store().audit_tip().unwrap();
    let screen = fixture.terminal(
        &["logout"],
        &[
            ("apikey:zulu  (needs_reauth)", b"\r", false),
            ("Log out apikey:alpha?", b"\r", false),
        ],
    );
    assert!(screen.contains(PICKER), "{screen}");
    let alpha = screen.find("apikey:alpha  (active)").expect(&screen);
    let zulu = screen.find("apikey:zulu  (needs_reauth)").expect(&screen);
    assert!(alpha < zulu, "ids must be sorted: {screen}");
    for excluded in [
        "apikey:retired",
        "apikey:corrupt",
        "signing:logout-test",
        "kem:logout-test",
    ] {
        assert!(!screen.contains(excluded), "{screen}");
    }
    assert_eq!(fixture.store().audit_tip().unwrap(), before);
}

#[test]
fn confirming_logout_retires_only_the_searched_id_and_matches_flag_audit() {
    let interactive = Fixture::new();
    let flagged = Fixture::new();
    let mut handles = Vec::new();
    for fixture in [&interactive, &flagged] {
        fixture.put("apikey:alpha");
        fixture.put("apikey:zulu");
        fixture.store().invalidate("apikey:zulu").unwrap();
        for _ in 0..2 {
            handles.push(fixture.success(&["mint-handle", "--id", "apikey:zulu"]));
            assert_eq!(
                fixture
                    .store()
                    .resolve_handle(handles.last().unwrap().trim())
                    .unwrap(),
                "apikey:zulu"
            );
        }
    }
    let before = interactive.store().audit_tip().unwrap().unwrap().0;
    let screen = interactive.terminal(
        &["logout"],
        &[
            (PICKER, b"zulu\r", false),
            ("Log out apikey:zulu?", b"y\r", false),
        ],
    );
    let output = flagged.success(&["logout", "--id", "apikey:zulu"]);
    assert!(screen.contains(output.lines().next().unwrap()), "{screen}");
    let warning = screen.find("stops it serving now").expect(&screen);
    let recovery = screen
        .find("ck auth reactivate --id apikey:zulu")
        .expect(&screen);
    let irreversible = screen
        .find("but revoked handles stay revoked.")
        .expect(&screen);
    let confirm = screen.find("Log out apikey:zulu?").expect(&screen);
    let acted = screen.find("logged out apikey:zulu:").expect(&screen);
    assert!(
        warning < recovery && recovery < irreversible && irreversible < confirm && confirm < acted
    );
    assert!(
        screen.contains("revokes all its capability handles"),
        "{screen}"
    );
    assert!(screen.contains("revoked 2 handle(s)"), "{screen}");
    let store = interactive.store();
    assert_eq!(
        store.meta("apikey:zulu").unwrap().state,
        RecordState::Retired
    );
    assert_eq!(
        store.meta("apikey:alpha").unwrap().state,
        RecordState::Active
    );
    for handle in &handles[..2] {
        assert!(matches!(
            store.resolve_handle(handle.trim()),
            Err(StoreOpError::NotFound)
        ));
    }
    assert_eq!(store.audit_tip().unwrap().unwrap().0, before + 2);
    let actual = store.read_audit(Some(2)).unwrap();
    let expected = flagged.store().read_audit(Some(2)).unwrap();
    assert_eq!(actual[0].op, "invalidate");
    assert_eq!(actual[1].op, "revoke_handle");
    // Compare the operation fields, not vault-specific timestamps or chain authentication codes.
    for (actual, expected) in actual.iter().zip(&expected) {
        assert_eq!(actual.op, expected.op);
        assert_eq!(actual.credential_id, expected.credential_id);
        assert_eq!(actual.payload_hash, expected.payload_hash);
        assert_eq!(actual.actor, expected.actor);
        assert_eq!(actual.alarm, expected.alarm);
        assert_eq!(actual.alarm_reason, expected.alarm_reason);
    }
}

#[test]
fn declining_logout_preserves_state_handles_and_audit_tip() {
    let fixture = Fixture::new();
    fixture.put("apikey:keep");
    let handle = fixture.success(&["mint-handle", "--id", "apikey:keep"]);
    let (version, tip) = {
        let store = fixture.store();
        (
            store.meta("apikey:keep").unwrap().record_version,
            store.audit_tip().unwrap(),
        )
    };
    for answer in [b"\r".as_slice(), b"n\r".as_slice()] {
        let screen = fixture.terminal(
            &["logout"],
            &[
                (PICKER, b"\r", false),
                ("Log out apikey:keep?", answer, false),
            ],
        );
        assert!(
            screen.contains("Logout cancelled; nothing changed."),
            "{screen}"
        );
        assert!(!screen.contains("logged out apikey:keep:"), "{screen}");
        let store = fixture.store();
        let meta = store.meta("apikey:keep").unwrap();
        assert_eq!(meta.state, RecordState::Active);
        assert_eq!(meta.record_version, version);
        assert_eq!(store.resolve_handle(handle.trim()).unwrap(), "apikey:keep");
        assert_eq!(store.audit_tip().unwrap(), tip);
    }
}

#[test]
fn explicit_logout_targets_at_a_terminal_never_prompt() {
    let fixture = Fixture::new();
    fixture.put("apikey:probe");
    fixture.put("oauth:xai");
    fixture.success(&["mint-signing-key", "--id", "signing:explicit"]);
    for (flag, target, id) in [
        ("--id", "apikey:probe", "apikey:probe"),
        ("--provider", "xai", "oauth:xai"),
        ("--id", "signing:explicit", "signing:explicit"),
    ] {
        let screen = fixture.terminal(&["logout", flag, target], &[]);
        assert!(!screen.contains(PICKER), "{screen}");
        assert!(!screen.contains("Log out "), "{screen}");
        assert!(screen.contains(&format!("logged out {id}:")), "{screen}");
        assert_eq!(
            fixture.store().meta(id).unwrap().state,
            RecordState::Retired
        );
    }
}

#[test]
fn nonterminal_logout_without_a_target_keeps_usage_error_and_offers_picker_hint() {
    let fixture = Fixture::new();
    let before = fixture.store().audit_tip().unwrap();
    let output = fixture
        .command(&["logout"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    let usage = stderr
        .find("--provider <p> or --id <id> is required")
        .expect(&stderr);
    let hint = stderr
        .find("Run `ck auth logout` in a terminal to choose a credential from a picker.")
        .expect(&stderr);
    assert!(usage < hint, "{stderr}");
    assert!(output.stdout.is_empty());
    assert_eq!(fixture.store().audit_tip().unwrap(), before);
}

#[test]
fn logout_with_nothing_eligible_exits_successfully_without_prompts_or_writes() {
    let fixture = Fixture::new();
    for seed_exclusions in [false, true] {
        if seed_exclusions {
            fixture.excluded_records();
        }
        let before = fixture.store().audit_tip().unwrap();
        let screen = fixture.terminal(&["logout"], &[]);
        assert!(
            screen.contains("No credentials are eligible for interactive logout."),
            "{screen}"
        );
        assert!(!screen.contains(PICKER), "{screen}");
        assert!(!screen.contains("Log out "), "{screen}");
        let store = fixture.store();
        assert_eq!(store.audit_tip().unwrap(), before);
        if seed_exclusions {
            assert_eq!(
                store.meta("apikey:retired").unwrap().state,
                RecordState::Retired
            );
            assert_eq!(
                store.meta("apikey:corrupt").unwrap().state,
                RecordState::Corrupt
            );
            assert_eq!(
                store.meta("signing:logout-test").unwrap().state,
                RecordState::Active
            );
            assert_eq!(
                store.meta("kem:logout-test").unwrap().state,
                RecordState::Active
            );
        }
    }
}

#[test]
fn logout_help_and_verb_table_describe_terminal_picker_and_explicit_targets() {
    let fixture = Fixture::new();
    let help = fixture.success(&["logout", "--help"]);
    for text in [
        "ck auth logout [--provider <p> | --id <id>]",
        "With no flags at a terminal",
        "default No",
        "--id or --provider never prompts",
        "vault-held key",
        "revoked handles stay",
    ] {
        assert!(help.contains(text), "missing {text}: {help}");
    }
    for line in help.lines() {
        assert!(line.chars().count() <= 80, "help line too wide: {line}");
    }
    let summary = fixture.success(&["--help"]);
    assert!(
        summary
            .lines()
            .any(|line| line.contains("logout")
                && line.contains("picker with no flags at a terminal")),
        "{summary}"
    );
}
