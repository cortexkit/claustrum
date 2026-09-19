#![cfg(feature = "import-prompt-seam")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const PROMPT_ENV: &str = "CK_AUTH_IMPORT_PROMPT_SCRIPT";
const COMMIT_ENV: &str = "CK_AUTH_IMPORT_COMMIT_SCRIPT";
const SHIPPED_ENV: &str = "CK_AUTH_IMPORT_SHIPPED_BINARY";

struct Fixture {
    root: PathBuf,
    data_dir: PathBuf,
    key_path: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ck-import-picker-{}-{label}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("data/opencode")).unwrap();
        std::fs::create_dir_all(root.join("home/.pi/agent")).unwrap();
        std::fs::create_dir_all(root.join("home/.gemini")).unwrap();
        std::fs::create_dir_all(root.join("config/opencode")).unwrap();
        std::fs::write(
            root.join("data/opencode/auth.json"),
            br#"{
              "anthropic":{"type":"oauth","access":"anthropic-access-fixture","refresh":"anthropic-refresh-fixture","expires":4102444800000},
              "openrouter":{"type":"api","key":"openrouter-key-fixture"},
              "broken":{"type":"api","key":42}
            }"#,
        )
        .unwrap();
        Self {
            data_dir: root.join("vault"),
            key_path: root.join("master.key"),
            root,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn command(&self, binary: impl AsRef<Path>) -> Command {
        let mut command = Command::new(binary.as_ref());
        command
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("HOME", self.root.join("home"));
        command
    }

    fn global(&self, command: &mut Command) {
        command
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--key-path")
            .arg(&self.key_path);
    }

    fn bootstrap(&self) {
        let mut command = self.command(env!("CARGO_BIN_EXE_ck-auth"));
        command.arg("bootstrap");
        self.global(&mut command);
        let output = command.output().expect("bootstrap picker vault");
        assert!(
            output.status.success(),
            "bootstrap failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_script(&self, name: &str, json: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, json).unwrap();
        path
    }

    fn picker(&self, script: &Path) -> Output {
        let mut command = self.command(env!("CARGO_BIN_EXE_ck-auth"));
        command.arg("import");
        self.global(&mut command);
        command
            .env(PROMPT_ENV, script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run picker")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn injected_prompts_outrank_missing_tty_and_batch_commit_uses_final_ids() {
    let fixture = Fixture::new("driver");
    fixture.bootstrap();
    let script = fixture.write_script(
        "prompts.json",
        r#"[
          {"pick":["oauth:anthropic","apikey:openrouter"]},
          {"id":"oauth:anthropic"},
          {"id":"apikey:openrouter:work"},
          {"confirm":true}
        ]"#,
    );
    let output = fixture.picker(&script);
    assert!(
        output.status.success(),
        "picker failed: {}",
        combined(&output)
    );
    let text = combined(&output);
    assert!(text.contains("oauth:anthropic: stored"), "{text}");
    assert!(text.contains("apikey:openrouter:work: stored"), "{text}");
    assert!(!text.contains("anthropic-access-fixture"), "{text}");
    assert!(!text.contains("openrouter-key-fixture"), "{text}");

    let mut list = fixture.command(env!("CARGO_BIN_EXE_ck-auth"));
    list.arg("list");
    fixture.global(&mut list);
    let listed = list.output().unwrap();
    assert!(
        listed.status.success(),
        "list failed: {}",
        combined(&listed)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("oauth:anthropic"), "{listing}");
    assert!(listing.contains("apikey:openrouter:work"), "{listing}");
    assert!(!listing.contains("apikey:openrouter "), "{listing}");
}

#[test]
fn pseudo_rows_and_submit_time_drops_have_distinct_exit_semantics() {
    let fixture = Fixture::new("pseudo");
    fixture.bootstrap();

    let none = fixture.write_script("none.json", r#"[{"pick":["[none]","oauth:anthropic"]}]"#);
    let output = fixture.picker(&none);
    assert!(
        output.status.success(),
        "[none] must be quiet: {}",
        combined(&output)
    );
    assert!(output.stdout.is_empty(), "[none] printed a report");

    let both = fixture.write_script(
        "both.json",
        r#"[
          {"pick":["[all]","[none]"]},
          {"pick":["[none]"]}
        ]"#,
    );
    let output = fixture.picker(&both);
    assert!(
        output.status.success(),
        "both-checked retry failed: {}",
        combined(&output)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot both be checked"));

    let malformed_label = format!(
        "opencode: opencode file '{}' provider 'broken': missing field 'key' — not importable",
        fixture.root.join("data/opencode/auth.json").display()
    );
    let script_text = format!(r#"[{{"pick":["{malformed_label}"]}}]"#);
    let malformed = fixture.write_script("malformed.json", &script_text);
    let output = fixture.picker(&malformed);
    assert!(!output.status.success());
    assert!(combined(&output).contains("not importable"));
}

#[test]
fn invalid_id_edits_share_one_bounded_attempt_counter() {
    let fixture = Fixture::new("attempts");
    fixture.bootstrap();
    let script = fixture.write_script(
        "attempts.json",
        r#"[
          {"pick":["oauth:anthropic"]},
          {"id":"oauth:google"},
          {"id":"oauth:anthropic:a:b"},
          {"id":"oauth:anthropic"},
          {"confirm":true}
        ]"#,
    );
    let output = fixture.picker(&script);
    assert!(
        output.status.success(),
        "third open should commit: {}",
        combined(&output)
    );
    assert_eq!(
        combined(&output).matches("invalid credential id").count(),
        2
    );

    let repeated = fixture.write_script(
        "exhausted.json",
        r#"[
          {"pick":["apikey:openrouter"]},
          {"id":"apikey:other"},
          {"id":"apikey:other"},
          {"id":"apikey:other"},
          {"id":"apikey:openrouter"}
        ]"#,
    );
    let output = fixture.picker(&repeated);
    assert!(!output.status.success());
    assert!(combined(&output).contains("id prompt exhausted"));
}

#[test]
fn declared_commit_seam_continues_after_a_refused_row_without_leaking_material() {
    let fixture = Fixture::new("commit-seam");
    fixture.bootstrap();
    let prompts = fixture.write_script(
        "prompts.json",
        r#"[
          {"pick":["oauth:anthropic","apikey:openrouter"]},
          {"id":"oauth:anthropic"},
          {"id":"apikey:openrouter"},
          {"confirm":true}
        ]"#,
    );
    let commits = fixture.write_script("commits.json", r#"[{"stored":true},{"refused":true}]"#);
    let mut command = fixture.command(env!("CARGO_BIN_EXE_ck-auth"));
    command.arg("import");
    fixture.global(&mut command);
    let output = command
        .env(PROMPT_ENV, prompts)
        .env(COMMIT_ENV, commits)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = combined(&output);
    assert!(text.contains("oauth:anthropic: stored"), "{text}");
    assert!(text.contains("apikey:openrouter: refused"), "{text}");
    assert!(!text.contains("anthropic-access-fixture"), "{text}");
    assert!(!text.contains("openrouter-key-fixture"), "{text}");

    let mut list = fixture.command(env!("CARGO_BIN_EXE_ck-auth"));
    list.arg("list");
    fixture.global(&mut list);
    let listed = list.output().unwrap();
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("oauth:anthropic"), "{listing}");
    assert!(!listing.contains("apikey:openrouter"), "{listing}");
}

#[test]
fn shipped_binary_probe_requires_the_gate_export_and_distinguishes_the_seam_binary() {
    let shipped = std::env::var_os(SHIPPED_ENV).unwrap_or_else(|| {
        panic!("{SHIPPED_ENV} must name the default-feature binary built by scripts/gate.sh")
    });
    let fixture = Fixture::new("shipped");
    fixture.bootstrap();
    let marker = fixture.path("consumed-marker");
    let script = fixture.write_script(
        "probe.json",
        &format!(r#"[{{"pick":["{}"]}}]"#, marker.to_string_lossy()),
    );

    let run = |binary: &Path| {
        let mut command = fixture.command(binary);
        command.arg("import");
        fixture.global(&mut command);
        command
            .env(PROMPT_ENV, &script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap()
    };
    let shipped_bytes = std::fs::read(&shipped).expect("read shipped ck-auth binary");
    let contains = |needle: &str| {
        shipped_bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    };
    assert!(
        !contains(PROMPT_ENV),
        "the prompt-script seam name is present in the default-feature binary"
    );
    assert!(
        !contains(COMMIT_ENV),
        "the commit-script seam name is present in the default-feature binary"
    );
    assert!(
        contains("unlock-keychain"),
        "release-binary string scan missed its positive control"
    );

    let production = run(Path::new(&shipped));
    assert!(!production.status.success());
    assert!(combined(&production).contains("use the flag form"));
    assert!(!marker.exists());

    let seam = run(Path::new(env!("CARGO_BIN_EXE_ck-auth")));
    assert!(
        !combined(&seam).contains("use the flag form"),
        "negative control did not distinguish seam-enabled binary"
    );
}

#[test]
fn first_use_without_a_store_is_empty_inventory_but_broken_preflight_never_prompts() {
    let fixture = Fixture::new("first-use");
    fixture.bootstrap();
    std::fs::remove_file(fixture.data_dir.join("store.db")).unwrap();
    let script = fixture.write_script(
        "first-use.json",
        r#"[
          {"pick":["oauth:anthropic"]},
          {"id":"oauth:anthropic"},
          {"confirm":true}
        ]"#,
    );
    let output = fixture.picker(&script);
    assert!(
        output.status.success(),
        "first use failed: {}",
        combined(&output)
    );
    assert!(combined(&output).contains("oauth:anthropic: create"));
    assert!(fixture.data_dir.join("store.db").is_file());

    let broken = Fixture::new("broken-key");
    broken.bootstrap();
    std::fs::remove_file(&broken.key_path).unwrap();
    let marker = broken.path("marker");
    let impossible = broken.write_script(
        "must-not-open.json",
        &format!(r#"[{{"pick":["{}"]}}]"#, marker.display()),
    );
    let output = broken.picker(&impossible);
    assert!(!output.status.success());
    assert!(
        !combined(&output).contains(marker.to_str().unwrap()),
        "the prompt seam was invoked after key resolution failed"
    );
}

#[test]
fn flag_shaped_imports_never_open_the_picker_and_keep_validation_errors() {
    let fixture = Fixture::new("flag-drift");
    let marker = fixture.path("marker");
    let script = fixture.write_script(
        "must-not-open.json",
        &format!(r#"[{{"pick":["{}"]}}]"#, marker.display()),
    );
    for tail in [
        vec!["import", "--replace"],
        vec!["import", "--adapter", "x"],
        vec!["import", "--account-id", "y"],
        vec!["import", "--bogus"],
        vec!["import", "--store", "/tmp/nope"],
    ] {
        let mut command = fixture.command(env!("CARGO_BIN_EXE_ck-auth"));
        command
            .args(tail)
            .env(PROMPT_ENV, &script)
            .stdin(Stdio::null());
        let output = command.output().unwrap();
        assert!(!output.status.success(), "flag form unexpectedly succeeded");
        assert!(
            !combined(&output).contains(marker.to_str().unwrap()),
            "a flag-shaped invocation opened the picker"
        );
    }
}

#[cfg(unix)]
fn run_terminal_picker(fixture: &Fixture, input: &[u8]) -> (std::process::ExitStatus, String) {
    use std::io::{Read, Write};
    use std::thread;
    use std::time::{Duration, Instant};

    let mut command = Command::new("script");
    command
        .arg("-q")
        .arg("/dev/null")
        .arg(env!("CARGO_BIN_EXE_ck-auth"))
        .arg("import");
    fixture.global(&mut command);
    command
        .env("XDG_DATA_HOME", fixture.root.join("data"))
        .env("XDG_CONFIG_HOME", fixture.root.join("config"))
        .env("HOME", fixture.root.join("home"))
        .env_remove(PROMPT_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn picker under script(1) pty");
    child.stdin.take().unwrap().write_all(input).unwrap();

    let deadline = Instant::now() + Duration::from_secs(8);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            // libc is the test-only PTY dependency; script(1) supplies the controlling
            // terminal and this signal keeps a broken widget from hanging the gate.
            // SAFETY: the pid belongs to the child spawned immediately above.
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGKILL);
            }
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(25));
    };
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(unix)]
#[test]
fn real_terminal_adapter_exercises_submit_controls_drop_and_attempt_bound() {
    let all = Fixture::new("pty-all");
    all.bootstrap();
    let (status, screen) = run_terminal_picker(&all, b" \r\r\ry\r");
    assert!(status.success(), "pty [all] failed:\n{screen}");
    assert!(
        screen.contains("[all]"),
        "pseudo-row was not rendered:\n{screen}"
    );
    assert!(
        screen.contains("[none]"),
        "pseudo-row was not rendered:\n{screen}"
    );
    assert!(screen.contains("oauth:anthropic: stored"), "{screen}");
    assert!(screen.contains("apikey:openrouter: stored"), "{screen}");
    assert!(!screen.contains("anthropic-access-fixture"), "{screen}");
    assert!(!screen.contains("openrouter-key-fixture"), "{screen}");

    let none = Fixture::new("pty-none");
    none.bootstrap();
    let (status, screen) = run_terminal_picker(&none, b"\x1b[B \r");
    assert!(status.success(), "pty [none] failed:\n{screen}");
    assert!(!screen.contains("Import summary"), "{screen}");

    let both = Fixture::new("pty-both");
    both.bootstrap();
    let (status, screen) = run_terminal_picker(&both, b" \x1b[B \r\x1b");
    assert!(status.success(), "pty both-checked retry failed:\n{screen}");
    assert!(screen.contains("cannot both be checked"), "{screen}");

    let dropped = Fixture::new("pty-drop");
    dropped.bootstrap();
    let (status, screen) = run_terminal_picker(&dropped, b"\x1b[B\x1b[B \x1b[B \x1b[B \r");
    assert!(
        !status.success(),
        "non-importable-only submit succeeded:\n{screen}"
    );
    assert!(screen.contains("not importable"), "{screen}");

    let exhausted = Fixture::new("pty-bound");
    exhausted.bootstrap();
    let (status, screen) = run_terminal_picker(
        &exhausted,
        b"\x1b[B\x1b[B\x1b[B\x1b[B \roauth:google\roauth:google\roauth:google\r",
    );
    assert!(
        !status.success(),
        "fourth id-prompt open was allowed:\n{screen}"
    );
    assert!(screen.contains("id prompt exhausted"), "{screen}");
}
