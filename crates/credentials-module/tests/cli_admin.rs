//! End-to-end tests of the offline admin CLI binary.
//!
//! Drives the real `ck-auth` process against a temp vault dir with an
//! operator key path (so no keychain is touched), exercising the structural
//! master-key proof and the audit chain end-to-end: bootstrap a key, put a
//! credential, mint a handle, list + verify the audit chain. Also proves the
//! single-writer lease makes admin writes mutually exclusive with a held lease.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use base64::Engine;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::key::MasterKey;
use credentials_core::record::CredentialKind;
use credentials_core::store::EncryptedStore;
use ring::signature::{UnparsedPublicKey, ED25519};

mod common;
use common::tmp_root;

/// Point this suite at a specific `ck-auth` instead of the one cargo just built.
///
/// `CARGO_BIN_EXE_*` resolves per-profile and cargo rebuilds before running, so
/// `cargo test` -- with or without `--release` -- always drives a binary produced for
/// the test run, never a staged one. A green suite is therefore evidence about the
/// SOURCE and none at all about the bytes being shipped.
///
/// That matters most for THIS binary. `ck-auth` is what an operator reaches for during
/// an incident and the only thing that takes the single-writer lease to mutate the
/// vault, so a broken artifact is discovered while trying to repair something else.
/// `scripts/release-build.sh` sets this after staging.
const CLI_BIN_ENV: &str = "CRED_CLI_BIN";

fn cli() -> Command {
    // REFUSES a bad override rather than falling back: a typo that silently tested the
    // cargo-built binary would report exactly the green the caller was hoping for.
    match std::env::var_os(CLI_BIN_ENV) {
        Some(raw) => {
            let path = PathBuf::from(raw);
            assert!(
                path.is_file(),
                "{CLI_BIN_ENV} points at {} which is not a file — refusing to fall back \
                 to the cargo-built binary, because a silent fallback would report the \
                 staged artifact as verified when it was never run",
                path.display()
            );
            Command::new(path)
        }
        None => Command::new(env!("CARGO_BIN_EXE_ck-auth")),
    }
}

/// Both documented orders of a global flag must reach the same vault.
///
/// The verb is positional and is read before the flags, so a flag written BEFORE it
/// would be taken as the verb itself and produce "unexpected argument '<path>' for
/// '--data-dir'" -- a message naming the flag as a verb, from an invocation the help
/// text presents as correct. Nothing about the parser is visible to a caller, so the
/// two orders have to be equivalent rather than one of them being a rule to learn.
///
/// Driven through the real binary, because the ordering fix lives in argv handling
/// before dispatch: a unit test calling the helper directly passes whether or not
/// anything invokes it.
/// A github_app deposit must NOT land as a static record.
///
/// Static is what `put` builds for every other kind, and it is precisely wrong here:
/// `credential.get` would serve the PEM verbatim, and a consumer putting newline-laden
/// key material into an HTTP header fails before the wire. That is the failure plexus
/// hit on 2026-08-17, and this asserts the SHAPE that prevents it rather than the CLI's
/// success message -- "created" printed identically for the broken shape.
/// Bootstrap is idempotent, and a real key-store failure is still a failure.
///
/// THE SECOND ARM IS THE POINT. Making a rerun succeed is easy and would be actively
/// dangerous on its own: `CliError::MasterKey(_)` maps all 13 MasterKeyError variants to
/// exit 4, so an installer that learns to tolerate 4 tolerates a LOCKED KEYCHAIN too and
/// enables the module with no key. That is not hypothetical -- it was proposed as a
/// repair on a fresh macOS VM over SSH, 2026-09-03, where the login keychain was locked.
///
/// So this pins the pair: rerun exits 0 AND names the same key_id (proving it is the
/// existing key rather than a silently reprovisioned one), while an unusable key path
/// still exits non-zero.
/// The `ck` dispatcher's opt-in probe, all four clauses.
///
/// Until this answers, `ck auth …` refuses as "not a command" and this binary vanishes
/// from `ck --help` — so the contract is load-bearing in a way nothing local reveals,
/// and every clause below is enforced by a consumer in another repo.
///
/// It must also answer WITHOUT touching config, a vault or the network: a headline that
/// needed the store to be readable would fail the probe on exactly the hosts where an
/// operator most needs `ck auth` to exist. Asserted by running it with a data-dir that
/// does not exist.
#[test]
fn the_ck_domain_probe_answers_with_one_line_and_needs_nothing() {
    let mut c = cli();
    c.arg("--ck-domain");
    let out = c.output().expect("run ck-auth --ck-domain");
    assert!(
        out.status.success(),
        "the probe must exit 0 or `ck auth` stops being a command: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one non-empty line is the contract; got {lines:?}"
    );
    assert!(
        !lines[0].trim().is_empty(),
        "the single line is the headline shown beside the domain in `ck --help`"
    );

    // STRICT MATCH IS INTENTIONAL: the dispatcher invokes exactly `ck-auth --ck-domain`
    // and nothing else, so `--ck-domain` appearing ANYWHERE in a longer command line
    // must NOT be treated as a probe. Loosening it would let the flag shadow a real verb
    // and silently print a headline where an operator asked for work.
    //
    // My first version of this test asserted the opposite -- that the probe survives an
    // extra `--data-dir` -- and failed. The test was wrong, not the code.
    let mut c2 = cli();
    c2.arg("--ck-domain")
        .arg("--data-dir")
        .arg("/definitely/not/a/dir");
    let out2 = c2
        .output()
        .expect("run ck-auth with --ck-domain plus another flag");
    assert!(
        !String::from_utf8_lossy(&out2.stdout).contains(lines[0]),
        "a longer command line must not answer the probe: {}",
        String::from_utf8_lossy(&out2.stdout)
    );

    // AND IT NEEDS NOTHING: the arm above ran with no vault, no config and no lease in
    // the ambient environment, which is the property that matters -- a headline
    // requiring a readable store would fail the probe on exactly the hosts where an
    // operator most needs `ck auth` to exist.
}

#[test]
fn bootstrap_is_idempotent_but_a_real_key_store_failure_is_not() {
    let root = tmp_root("bootstrap-idem");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |dir: &std::path::Path, key: &std::path::Path| {
        let mut c = cli();
        c.arg("bootstrap")
            .arg("--data-dir")
            .arg(dir)
            .arg("--key-path")
            .arg(key);
        c.output().expect("run ck-auth bootstrap")
    };

    let first = run(&data_dir, &key_path);
    assert!(
        first.status.success(),
        "first bootstrap failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_out = String::from_utf8_lossy(&first.stdout).to_string();
    let id = first_out
        .split("key_id ")
        .nth(1)
        .and_then(|t| t.split(')').next())
        .expect("first bootstrap names a key_id")
        .to_string();

    let second = run(&data_dir, &key_path);
    let second_out = String::from_utf8_lossy(&second.stdout).to_string();
    assert!(
        second.status.success(),
        "a rerun must succeed -- an already-provisioned vault IS bootstrap's \
         postcondition: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        second_out.contains("already provisioned"),
        "the rerun must say it changed nothing: {second_out}"
    );
    assert!(
        second_out.contains(&id),
        "the rerun must name the SAME key_id ({id}), or it may have reprovisioned: \
         {second_out}"
    );

    // The control: tolerance must not extend past the already-provisioned case.
    let broken = run(
        &root.join("v2"),
        std::path::Path::new("/definitely/not/a/dir/key"),
    );
    assert!(
        !broken.status.success(),
        "an unusable key store must STILL fail; if this passes, an installer that \
         tolerates bootstrap's exit code will enable a vault with no key: {}",
        String::from_utf8_lossy(&broken.stdout)
    );
}

#[test]
fn a_github_app_deposit_lands_oauth_shaped_rather_than_static() {
    let rig = tmp_root("github-app-put");
    std::fs::create_dir_all(&rig).unwrap();
    let key = rig.join("master.key");
    std::fs::write(&key, "11".repeat(32)).unwrap();
    let data_dir = rig.join("vault");
    let pem = rig.join("app.pem");
    // Shape only -- this test never signs, so PEM-looking text is enough.
    std::fs::write(
        &pem,
        "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----",
    )
    .unwrap();

    let run = |args: &[&str]| {
        let out = cli()
            .args([
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--key-path",
                key.to_str().unwrap(),
            ])
            .args(args)
            .output()
            .expect("cli runs");
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    run(&["bootstrap"]);
    let (stdout, stderr) = run(&[
        "put",
        "--id",
        "github_app:probe",
        "--payload-file",
        pem.to_str().unwrap(),
        "--client-id",
        "Iv23TESTCLIENT",
    ]);
    assert!(
        stdout.contains("created"),
        "deposit failed: {stdout}{stderr}"
    );

    // `usable` renders the record KIND, which is the observable separating the two
    // shapes: an oauth row mints on get, a static row serves its bytes forever.
    let (listed, _) = run(&["usable"]);
    let row = listed
        .lines()
        .find(|l| l.contains("github_app:probe"))
        .unwrap_or_else(|| panic!("no github_app row in:\n{listed}"));
    assert!(
        row.contains("oauth"),
        "a github_app deposit must be oauth-shaped so it can mint; got: {row}"
    );

    // Both refusals: a github_app record with no client_id could never mint, so it must
    // not be creatable at all, and client_id is meaningless on a static kind.
    let (_, e1) = run(&[
        "put",
        "--id",
        "apikey:x",
        "--payload",
        "y",
        "--client-id",
        "z",
    ]);
    assert!(e1.contains("only to a github_app"), "got: {e1}");
    let (_, e2) = run(&[
        "put",
        "--id",
        "github_app:y",
        "--payload-file",
        pem.to_str().unwrap(),
    ]);
    assert!(e2.contains("needs --client-id"), "got: {e2}");

    let _ = std::fs::remove_dir_all(&rig);
}

#[test]
fn a_global_flag_before_the_verb_reaches_the_same_vault_as_one_after_it() {
    let root = tmp_root("flag-order");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let mut boot = cli();
    boot.arg("bootstrap")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path);
    assert!(boot.output().expect("bootstrap").status.success());

    // Flags AFTER the verb: the form that has always worked.
    let mut after = cli();
    after
        .arg("list")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path);
    let after = after.output().expect("list, flags after verb");

    // Flags BEFORE the verb: the form the help text documents.
    let mut before = cli();
    before
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path)
        .arg("list");
    let before = before.output().expect("list, flags before verb");

    assert!(
        before.status.success(),
        "a global flag before the verb must not be read as the verb; got: {}",
        String::from_utf8_lossy(&before.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&after.stdout),
        "both orders must address the same vault and print the same inventory"
    );

    let _ = std::fs::remove_dir_all(&root);
}

struct GrantCliVault {
    root: credentials_core::test_support::TestTempDir,
    data_dir: PathBuf,
    key_path: PathBuf,
}

impl GrantCliVault {
    fn new(tag: &str) -> Self {
        let root = tmp_root(tag);
        let data_dir = root.join("vault");
        let key_path = root.join("master.key");
        std::fs::create_dir_all(&data_dir).expect("vault directory");
        Self {
            root,
            data_dir,
            key_path,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--key-path")
            .arg(&self.key_path)
            .output()
            .expect("run ck-auth")
    }

    fn bootstrap(&self) {
        let out = self.run(&["bootstrap"]);
        assert!(
            out.status.success(),
            "bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Drop for GrantCliVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn grant_row_fields<'a>(stdout: &'a str, credential_prefix: &str) -> Vec<&'a str> {
    stdout
        .lines()
        .find(|line| line.contains(credential_prefix))
        .unwrap_or_else(|| panic!("grant row for {credential_prefix} missing from:\n{stdout}"))
        .split_whitespace()
        .collect()
}

// BOTH ARMS, because the fix and the defect it replaced are each correct for one of them.
// The restatement exists so a refusal buried under a verb's help page still reads as a
// refusal in a tailed transcript. It was firing unconditionally, so a one-line refusal
// printed the same sentence twice with a blank line between. Assert the buried form KEEPS
// its restatement and the short form does not grow one -- with only the second arm,
// restoring the unconditional version passes.
#[test]
fn a_one_line_refusal_says_it_once_and_a_buried_one_is_restated() {
    let short = cli()
        .args(["mint-handle"])
        .output()
        .expect("run mint-handle");
    assert!(
        !short.status.success(),
        "mint-handle with no --id must refuse"
    );
    let short_err = String::from_utf8_lossy(&short.stderr);
    assert_eq!(
        short_err.matches("--id is required").count(),
        1,
        "a one-line refusal must say it once; twice reads as two failures:\n{short_err}"
    );
    assert!(
        !short_err.contains("nothing ran, nothing changed"),
        "nothing buried this refusal, so the restatement is pure echo:\n{short_err}"
    );

    // The arm the restatement was written for: a usage error that prints the verb's whole
    // help page, so the first line is scrolled away by the time the reader reaches the end.
    let buried = cli()
        .args(["list", "--nonsense"])
        .output()
        .expect("run list with a bad flag");
    assert!(!buried.status.success(), "an unknown flag must refuse");
    let buried_err = String::from_utf8_lossy(&buried.stderr);
    assert!(
        buried_err.lines().count() > 3,
        "precondition: this arm only means something if a help page follows:\n{buried_err}"
    );
    assert!(
        buried_err.contains("nothing ran, nothing changed"),
        "a refusal buried under a help page must be restated at the end:\n{buried_err}"
    );
}

// THE DEFECT THIS DEFENDS was a fixed `{:<24}` prefix column against a real 26-character
// prefix: that one row's last two columns shifted right while every other row stayed put.
// A table with one offset row reads as a fault in the VALUE rather than in the layout --
// it cost a false "this prefix is truncated" alarm before the store settled it.
//
// Asserted as EQUAL COLUMN STARTS rather than equal line lengths: the trailing column is
// deliberately unpadded, so line length legitimately varies with its content.
#[test]
fn grants_columns_hold_their_positions_when_a_prefix_is_wider_than_the_others() {
    let home = tmp_root("grants_wide_prefix");
    let data_dir = home.join("vault");
    let key = home.join("master.key");
    std::fs::create_dir_all(&data_dir).expect("data dir");

    let run = |args: &[&str]| -> (bool, String, String) {
        let out = cli()
            .args([
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--key-path",
                key.to_str().unwrap(),
            ])
            .args(args)
            .output()
            .expect("cli runs");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    let (ok, _, err) = run(&["bootstrap"]);
    assert!(ok, "bootstrap failed: {err}");

    // One short prefix and one deliberately wider than the fixed width this replaced.
    for (principal, prefix) in [
        ("short-p", "apikey:x"),
        ("long-p", "apikey:artificial-analysis"),
    ] {
        let (ok, _, err) = run(&[
            "grant",
            "--principal",
            principal,
            "--selector-kind",
            "exact",
            "--selector",
            prefix,
            "--operation",
            "read",
        ]);
        assert!(ok, "grant for {principal} failed: {err}");
    }

    let (ok, stdout, err) = run(&["grants"]);
    assert!(ok, "grants failed: {err}");
    let rows: Vec<&str> = stdout.lines().filter(|l| l.contains("apikey:")).collect();
    assert_eq!(rows.len(), 2, "expected both grants to render:\n{stdout}");

    // The operation column starts at the same offset in both rows, or the wide prefix
    // pushed it. Measured on the rendered line, which is what a reader sees.
    let op_at: Vec<usize> = rows
        .iter()
        .map(|r| r.rfind("read").expect("every row carries its operation"))
        .collect();
    assert_eq!(
        op_at[0], op_at[1],
        "a wider prefix shifted the columns after it:\n{stdout}"
    );

    let header = stdout.lines().next().unwrap_or("");
    assert!(
        header.contains("SELECTOR KIND") && header.contains("SELECTOR") && header.contains("OP"),
        "the table needs a header; two short lowercase columns are otherwise unlabelled:\n{stdout}"
    );
}

// `invalidate` MUST NOT CLAIM IT STOPPED A CREDENTIAL IT DID NOT TOUCH.
//
// The admin op has always sent `state_changed`, with a comment at the site saying it rides
// the wire so the CLI can tell an operator whether the call did anything. The CLI read only
// `handles_revoked` -- which cannot stand in, because a credential with no handles reports
// zero whether it was live or already dead. So `invalidate --id apikey:does-not-exist`
// printed "invalidated apikey:does-not-exist".
//
// Same false-assurance shape as revoke-handle, and the sibling verb `logout` already
// reported it correctly. The data was provided for exactly this purpose and never consumed.
#[test]
fn invalidate_does_not_claim_success_when_nothing_changed() {
    let root = tmp_root("invalidate-noop");
    let data_dir = root.join("vault");
    let key_path = root.join("master.key");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let base = |c: &mut std::process::Command| {
        c.args(["--data-dir", data_dir.to_str().unwrap()])
            .args(["--key-path", key_path.to_str().unwrap()]);
    };

    let mut boot = cli();
    base(&mut boot);
    assert!(
        boot.arg("bootstrap")
            .output()
            .expect("bootstrap")
            .status
            .success(),
        "bootstrap failed"
    );

    // A credential that never existed: the verb succeeds (invalidation is idempotent by
    // design) but must SAY that nothing changed.
    let mut ghost = cli();
    base(&mut ghost);
    let out = ghost
        .arg("invalidate")
        .args(["--id", "apikey:does-not-exist"])
        .output()
        .expect("invalidate ghost");
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.contains("nothing changed"),
        "invalidate claimed success on a credential that does not exist:\n{said}"
    );
    assert!(
        !said.contains("invalidated apikey:does-not-exist;"),
        "invalidate printed its success line for a no-op:\n{said}"
    );
}

// A KIND-PREFIXED `--principal` IS REFUSED, BECAUSE THE GRANT IT WOULD CREATE IS DEAD.
//
// The daemon looks a grant up by ("reserved", module_id) with the BARE id from the route
// bind. A grant stored as `reserved:broca` can never match a bind whose module_id is
// `broca`, so every scoped read from that consumer is refused -- as the anti-enumeration
// `not_found`, which is indistinguishable from the credential not existing. Meanwhile
// `ck auth grants` shows a row that looks entirely correct.
//
// Found by exercising the mutating verbs on a scratch vault: the confirmation line read
// `granted reserved:reserved:probe-consumer`, and the doubling was the only tell.
//
// Both verbs are checked. revoke-grant takes the same flag and would otherwise accept a
// spelling that can never match the row it means to remove -- reporting success while
// leaving the grant in place, which is the worse direction for a revocation.
#[test]
fn grant_verbs_accept_the_canonical_reserved_spelling_and_refuse_other_kinds() {
    let root = tmp_root("grant-principal");
    let data_dir = root.join("vault");
    let key_path = root.join("master.key");
    std::fs::create_dir_all(&data_dir).expect("data dir");

    let boot = cli()
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--key-path", key_path.to_str().unwrap()])
        .arg("bootstrap")
        .output()
        .expect("bootstrap");
    assert!(boot.status.success(), "bootstrap failed");

    for verb in ["grant", "revoke-grant"] {
        let accepted = cli()
            .args(["--data-dir", data_dir.to_str().unwrap()])
            .args(["--key-path", key_path.to_str().unwrap()])
            .arg(verb)
            .args(["--principal", "reserved:probe"])
            .args(["--selector-kind", "exact", "--selector", "apikey:"])
            .args(["--operation", "read"])
            .output()
            .expect("run canonical verb");
        assert!(accepted.status.success(), "{verb} rejected reserved:<id>");

        for principal in ["direct:probe", "reserved:bad|principal"] {
            let refused = cli()
                .args(["--data-dir", data_dir.to_str().unwrap()])
                .args(["--key-path", key_path.to_str().unwrap()])
                .arg(verb)
                .args(["--principal", principal])
                .args(["--selector-kind", "exact", "--selector", "apikey:"])
                .args(["--operation", "read"])
                .output()
                .expect("run refused verb");
            assert!(!refused.status.success(), "{verb} accepted {principal}");
        }
    }
}

/// Flags the parser KNOWS but deliberately does not advertise, because knowing them is
/// how the operator gets a useful refusal instead of a generic one.
///
/// `--prefix` is the only member. It is refused with a message naming its replacement
/// and explaining why a former prefix is a category rather than an exact selector; that
/// message is only reachable if the flag is in the accept-list, since an unknown
/// argument dies earlier with text that says nothing about the migration.
///
/// This list must stay SHORT and each entry must be genuinely refused. A flag parked
/// here that still WORKS is an undocumented working flag, which is the exact defect the
/// caller of this function exists to catch.
const KNOWN_BUT_UNADVERTISED: &[(&str, &str)] =
    &[("grant", "--prefix"), ("revoke-grant", "--prefix")];

/// A VERB WITH POSITIONAL SUBCOMMANDS IS ACTUALLY INVOCABLE.
///
/// `reject_unknown_args` runs BEFORE dispatch and refuses any argument that is not a
/// declared flag, so a verb whose first argument is a bare subcommand is unusable unless
/// that subcommand is named in its exemption. `enroll` shipped exactly that way and the
/// entire suite stayed green: every help and flag test drives FLAGS, and nothing invoked
/// `ck auth enroll list`. It failed on the live daemon at the first probe of a migration
/// window.
///
/// Asserts the argument check ACCEPTS the subcommand — not that the command succeeds,
/// which needs a vault. A refusal naming the subcommand as unexpected is the defect.
#[test]
fn verbs_with_positional_subcommands_accept_them_before_dispatch() {
    for (verb, subs) in [
        (
            "enroll",
            &["list", "approve", "deny", "revoke", "reissue"][..],
        ),
        ("opencode-account", &["add", "remove", "list"][..]),
    ] {
        for sub in subs {
            let output = cli().args([verb, sub]).output().expect("run");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains(&format!("unexpected argument '{sub}'")),
                "{verb} {sub}: the argument check ate the subcommand, so the verb cannot \
                 be invoked at all: {stderr}"
            );
        }
    }
}

/// EVERY DISPATCHABLE VERB IS IN THE TOP-LEVEL VERB TABLE.
///
/// This exists because `enroll` shipped dispatchable and undiscoverable, and the whole
/// existing battery of help checks stayed green: they iterate HAND-KEPT verb lists, so a
/// new verb joins no check by being written. It was reachable by anyone who already knew
/// the word, which is the population that does not need a table.
///
/// The verb list here is derived from the DISPATCHER, not typed, so the next verb cannot
/// repeat it. The extractor's own floor guards the derivation: a broken scan yields few
/// verbs and fails rather than passing on an empty set.
#[test]
fn every_dispatchable_verb_appears_in_the_top_level_verb_table() {
    let src = include_str!("../src/bin/credentials_cli.rs");
    // Anchored on the dispatcher, whose arms ARE the dispatchable set. Reading the
    // source rather than a list is the point: a hand-kept list is what let `enroll` ship
    // undiscoverable while every help check stayed green.
    let start = src
        .find("match command.as_str() {")
        .expect("the dispatcher match must be findable");
    let body = &src[start..];
    let end = body
        .find("\n    }")
        .expect("dispatcher match must terminate");
    let mut verbs: Vec<String> = Vec::new();
    for line in body[..end].lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('"') else {
            continue;
        };
        let Some((verb, tail)) = rest.split_once('"') else {
            continue;
        };
        if tail.trim_start().starts_with("=>")
            && !verb.is_empty()
            && !verbs.contains(&verb.to_string())
        {
            verbs.push(verb.to_string());
        }
    }
    assert!(
        verbs.len() >= 20,
        "extractor found only {} verbs; a broken scan would pass this vacuously",
        verbs.len()
    );

    let rendered = cli().arg("help").output().expect("top-level help");
    let table = String::from_utf8_lossy(&rendered.stdout).to_string();
    let missing: Vec<&String> = verbs
        .iter()
        .filter(|verb| {
            !table
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{verb} ")))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "dispatchable but absent from the verb table, so only someone who already knows \
         the word can find them: {missing:?}"
    );
}

fn accepted_help_flags(verb: &str) -> Vec<String> {
    let src = include_str!("../src/bin/credentials_cli.rs");
    let mut out: Vec<String> = Vec::new();
    for (idx, _) in src.match_indices("=> &[") {
        // The arm pattern is everything from the previous newline up to the fat arrow.
        let line_start = src[..idx].rfind('\n').map(|n| n + 1).unwrap_or(0);
        let pattern = &src[line_start..idx];
        if !pattern.contains(&format!("\"{verb}\"")) {
            continue;
        }
        let rest = &src[idx + "=> &[".len()..];
        let to = rest.find(']').expect("unterminated accept-list");
        for token in rest[..to].split('"') {
            if token.starts_with("--") && !out.contains(&token.to_string()) {
                out.push(token.to_string());
            }
        }
    }
    out.retain(|flag| !KNOWN_BUT_UNADVERTISED.contains(&(verb, flag.as_str())));
    out
}

/// `--prefix` is REFUSED with a message that names its replacement, and the refusal is
/// only reachable because the flag stays in the parser's accept-list.
///
/// Both halves matter and they pull against each other: drop it from the accept-list and
/// an operator typing the old flag gets a generic unknown-argument error that says
/// nothing about the migration; alias it to `exact` and the command SUCCEEDS while
/// granting nothing, because `apikey:` reached seventeen credentials as a prefix and
/// names none of them exactly. Refusing-but-known is the only arrangement where the
/// operator's belief and the stored row cannot diverge.
#[test]
fn the_retired_prefix_flag_refuses_with_a_message_that_routes_to_its_replacement() {
    let vault = GrantCliVault::new("retired-prefix-flag");
    vault.bootstrap();
    for verb in ["grant", "revoke-grant"] {
        let output = vault.run(&[
            verb,
            "--principal",
            "reserved:probe",
            "--prefix",
            "apikey:",
            "--operation",
            "read",
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{verb} must refuse --prefix, not accept it"
        );
        assert!(
            stderr.contains("--prefix is gone"),
            "{verb}: the refusal must name the retired flag: {stderr}"
        );
        assert!(
            stderr.contains("--selector-kind category"),
            "{verb}: and must route a former family to a category, since aliasing it to \
             exact would grant nothing: {stderr}"
        );
    }
}

// EVERY FLAG THE PARSER ACCEPTS IS NAMED ON ITS HELP PAGE. This is the defence for the
// help-page reformat: a page can be rewritten for shape without silently dropping a flag,
// because a dropped flag is undiscoverable -- the parser still takes it, so nothing fails,
// and the operator simply never learns it exists.
//
// Drives the real binary rather than reading source strings, because the defect is in what
// RENDERS. The flag table is read from the parser's own accept-list, so this cannot drift
// the way a hand-kept list would.
#[test]
fn every_verb_names_on_its_help_page_each_flag_its_parser_accepts() {
    // Read the accept-lists from the CLI source rather than keeping a second copy here.
    //
    // TWO SHAPES AND TWO LISTS, both found by this test failing on its own first draft:
    //   "import" => &[...]                        value-taking flags
    //   "import" => &["--replace", ...]           boolean flags, a SEPARATE arm
    //   "grant" | "revoke-grant" => &[...]        one arm serving two verbs
    // A `find()` for a single `"verb" => &[` takes the first list and silently ignores the
    // second, which is how the first draft reported "8 of 8 named" while checking only the
    // value flags. Collect from EVERY arm whose pattern names the verb.
    let accepted = accepted_help_flags;

    assert!(
        accepted("login").iter().any(|flag| flag == "--no-browser"),
        "login's headless browser control must stay in the parser accept-list"
    );

    let verbs = [
        "import",
        "put",
        "login",
        "grant",
        "set-identity",
        "set-category",
        "reclassify",
        "revoke-handle",
    ];
    let mut total = 0usize;

    for verb in verbs {
        let flags = accepted(verb);
        assert!(
            flags.len() >= 2,
            "extractor found {} flags for {verb}; a broken scan passes this vacuously",
            flags.len()
        );

        let help = cli().args(["help", verb]).output().expect("run help");
        assert!(help.status.success(), "help {verb} failed");
        let page = String::from_utf8_lossy(&help.stdout);

        let missing: Vec<&String> = flags
            .iter()
            .filter(|f| !page.contains(f.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "`ck auth help {verb}` never names {missing:?}. The parser accepts them, so a \
             dropped flag fails nothing and is simply undiscoverable:\n{page}"
        );
        total += flags.len();
    }

    // ANCHOR against the extractor narrowing. The first draft matched one arm per verb and
    // reached 24; both arms reach more. A future refactor that splits an arm must not
    // quietly reduce coverage.
    assert!(
        total >= 30,
        "only {total} flags checked across {} verbs; the extractor has narrowed",
        verbs.len()
    );

    // *** AND THE OTHER DIRECTION: NO USAGE BLOCK NAMES A FLAG THE PARSER REFUSES. ***
    //
    // The arm above catches a flag that EXISTS and is undocumented -- invisible, because
    // nothing fails and the operator simply never learns it. This one catches a flag that is
    // DOCUMENTED AND DOES NOT EXIST, which fails loudly in the worst possible place: the
    // operator reads the page, types what it says, and is refused by the tool that just told
    // them to.
    //
    // SCOPED TO THE USAGE BLOCK (everything before the first blank line), which is a real
    // boundary rather than a heuristic. Prose below it legitimately names OTHER verbs' flags:
    // `ck auth help logout` suggests `ck auth login --provider <p> --replace`, and --replace
    // is genuinely not a logout flag. Measured: that line is the ONLY false positive a
    // whole-page scan produces today, and scoping removes it without having to reason about
    // which verb a mention belongs to.
    //
    // Global flags are excluded -- every page may name them, and no per-verb list holds them.
    let global = [
        "--data-dir",
        "--subc",
        "--key-path",
        "--version",
        "--help",
        "--yes",
    ];
    let mut usage_blocks = 0usize;

    for verb in verbs {
        let flags = accepted(verb);
        let help = cli().args(["help", verb]).output().expect("run help");
        let page = String::from_utf8_lossy(&help.stdout);
        let usage = page.split("\n\n").next().unwrap_or("");
        usage_blocks += 1;

        let mut phantom: Vec<String> = Vec::new();
        for token in usage.split_whitespace() {
            let flag: String = token
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .to_string();
            if !flag.starts_with("--") || flag.len() < 4 {
                continue;
            }
            if flags.contains(&flag) || global.contains(&flag.as_str()) {
                continue;
            }
            if !phantom.contains(&flag) {
                phantom.push(flag);
            }
        }
        assert!(
            phantom.is_empty(),
            "`ck auth help {verb}` usage block names {phantom:?}, which the parser REFUSES. \
             An operator typing what the page says gets an unexpected-argument error:\n{usage}"
        );
    }

    assert_eq!(
        usage_blocks,
        verbs.len(),
        "the phantom-flag arm did not reach every verb"
    );
}

// THE RUNBOOK'S SAMPLE OUTPUT MUST MATCH WHAT THE BINARY PRINTS. A sample block in a
// document is a claim about behaviour, and it goes stale silently: I changed the `events`
// renderer and the runbook's example kept its old column layout with nothing failing. An
// operator reading a stale sample learns a column order that no longer exists.
//
// Pins the HEADER only, not the rows. Widths are measured from the data, so row alignment
// legitimately differs between a documented example and any real vault -- but the column
// NAMES and their order are the contract a reader relies on.
#[test]
fn the_runbook_events_sample_names_the_columns_the_binary_prints() {
    // READ THE HEADER FROM SOURCE, NOT BY RUNNING THE BINARY.
    //
    // My first version ran `ck auth events` and searched its stdout. It passed locally and
    // failed on CI, and the reason is the worse of the two: with no `--data-dir` it read
    // the AMBIENT vault -- a real credential store with real rows -- so it found a header
    // because this machine happens to have events. CI has no store, so no header.
    //
    // Building a fixture instead does not work either, and the two refusals are worth
    // recording: a fresh vault has no `auth_events` TABLE (it arrives with a migration the
    // daemon applies), and a vault with the table but no rows prints an explanatory block
    // rather than a header. The header appears only when rows exist, and a row requires a
    // consumer report over the route plane -- daemon territory, for a test about whether
    // two strings agree.
    //
    // So pin the two strings. The header lives in one format-string literal in the CLI and
    // one sample block in the runbook; this asserts the runbook names every column the
    // literal prints, which is the whole claim.
    let cli_src = include_str!("../src/bin/credentials_cli.rs");
    let runbook = include_str!("../../../docs/operator-runbook.md");

    let header_line = cli_src
        .lines()
        .find(|l| l.contains("\"WHEN\", \"CREDENTIAL\""))
        .unwrap_or_else(|| panic!("no events header literal in the CLI source"));

    let columns: Vec<&str> = header_line
        .split('"')
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_uppercase()))
        .collect();
    assert!(
        columns.len() >= 6,
        "extracted {} columns from the header literal; the extractor has narrowed:\n{header_line}",
        columns.len()
    );

    let sample = runbook
        .lines()
        .find(|l| l.trim_start().starts_with("WHEN") && l.contains("CREDENTIAL"))
        .unwrap_or_else(|| panic!("the runbook's events sample carries no header row"));

    for column in &columns {
        assert!(
            sample.contains(column),
            "the runbook's events sample never names the `{column}` column the CLI prints, \
             so the documented layout is stale:\n  cli:     {header_line}\n  runbook: {sample}"
        );
    }
}

#[test]
fn grants_help_describes_the_read_only_inventory() {
    let out = cli()
        .args(["help", "grants"])
        .output()
        .expect("run grants help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ck auth grants"));
    assert!(stdout.contains("principal kind"));
    assert!(stdout.contains("creation time"));
    assert!(stdout.contains("no grants"));
}

#[test]
fn offline_grants_lists_a_newly_minted_grant_with_creation_time() {
    let vault = GrantCliVault::new("grants-created");
    vault.bootstrap();

    let created = vault.run(&[
        "grant",
        "--principal",
        "agent",
        "--selector-kind",
        "exact",
        "--selector",
        "operator:",
        "--operation",
        "read",
    ]);
    assert!(
        created.status.success(),
        "grant failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let listed = vault.run(&["grants"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.status.success(), "grants failed: {stdout}");
    let fields = grant_row_fields(&stdout, "operator:");
    assert_eq!(
        &fields[..5],
        &["reserved", "agent", "exact", "operator:", "read"],
        "grant rows must expose each requested column: {stdout}"
    );
    // 8 = the five above + REACHES + the timestamp's two columns. The reach column was
    // added after a grant naming a category no credential carried rendered identically
    // to a working one; this count is what stops it being dropped by a tidy-up.
    assert_eq!(
        fields.len(),
        8,
        "expected five identity columns, REACHES, and a two-column timestamp: {stdout}"
    );
    // 0, and correctly: this fixture grants the selector `operator:`, and no credential
    // in the scratch vault is literally named that. It is prefix-SHAPED, which under
    // byte-equality `exact` reaches nothing — so the fixture is itself an instance of the
    // defect the column exists to expose, and asserting 1 here would have been me
    // expecting the old prefix semantics.
    assert_eq!(
        fields[5], "0",
        "a prefix-shaped exact selector matching no credential id reaches nothing: {stdout}"
    );
    assert!(
        fields[6].len() == 10 && fields[6].as_bytes()[4] == b'-' && fields[6].as_bytes()[7] == b'-',
        "creation date must use the CLI time-column format: {stdout}"
    );
    assert!(
        fields[7].len() == 8 && fields[7].as_bytes()[2] == b':' && fields[7].as_bytes()[5] == b':',
        "creation time must use the CLI time-column format: {stdout}"
    );
}

#[test]
fn grants_keep_read_and_sign_rows_separate_and_sort_by_prefix_then_operation() {
    let vault = GrantCliVault::new("grants-operations");
    vault.bootstrap();

    for (prefix, operation) in [("z:", "sign"), ("z:", "read"), ("a:", "sign")] {
        let created = vault.run(&[
            "grant",
            "--principal",
            "agent",
            "--selector-kind",
            "exact",
            "--selector",
            prefix,
            "--operation",
            operation,
        ]);
        assert!(
            created.status.success(),
            "grant {prefix} {operation} failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
    }

    let listed = vault.run(&["grants"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.status.success(), "grants failed: {stdout}");
    let rows: Vec<Vec<&str>> = stdout
        .lines()
        .filter(|line| line.contains("reserved"))
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 3, "every grant needs its own row: {stdout}");
    assert_eq!(&rows[0][..5], &["reserved", "agent", "exact", "a:", "sign"]);
    assert_eq!(&rows[1][..5], &["reserved", "agent", "exact", "z:", "read"]);
    assert_eq!(&rows[2][..5], &["reserved", "agent", "exact", "z:", "sign"]);
}

/// One principal holding BOTH selector kinds and all three operations must still list.
///
/// The CLI refuses a grant inventory that does not arrive in stable order, and it checks
/// that order on the TEXT of each field. A store that sorted by enum declaration order
/// instead (exact before category, open after sign) passed every single-kind test and
/// took `ck auth grants` and `ck auth status` down on the live vault, where one module
/// holds exact and category grants side by side. The producer's order and the
/// consumer's check only meet when both kinds and a non-alphabetical operation are
/// present in one listing, so this test puts them there.
#[test]
fn grants_list_when_one_principal_holds_both_selector_kinds_and_every_operation() {
    let vault = GrantCliVault::new("grants-mixed-kinds");
    vault.bootstrap();

    for (kind, selector, operation) in [
        ("exact", "z:", "read"),
        ("category", "llm-provider", "read"),
        ("exact", "a:", "open"),
        ("exact", "a:", "sign"),
    ] {
        let created = vault.run(&[
            "grant",
            "--principal",
            "agent",
            "--selector-kind",
            kind,
            "--selector",
            selector,
            "--operation",
            operation,
        ]);
        assert!(
            created.status.success(),
            "grant {kind} {selector} {operation} failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
    }

    let listed = vault.run(&["grants"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.status.success(),
        "grants refused a mixed inventory: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let rows = stdout
        .lines()
        .filter(|line| line.contains("reserved"))
        .count();
    assert_eq!(rows, 4, "every grant needs its own row: {stdout}");
}

#[test]
fn revoked_grant_disappears_from_the_grants_listing() {
    let vault = GrantCliVault::new("grants-revoked");
    vault.bootstrap();
    let created = vault.run(&[
        "grant",
        "--principal",
        "agent",
        "--selector-kind",
        "exact",
        "--selector",
        "operator:",
        "--operation",
        "read",
    ]);
    assert!(created.status.success());
    assert!(String::from_utf8_lossy(&vault.run(&["grants"]).stdout).contains("operator:"));

    let revoked = vault.run(&[
        "revoke-grant",
        "--principal",
        "agent",
        "--selector-kind",
        "exact",
        "--selector",
        "operator:",
        "--operation",
        "read",
    ]);
    assert!(
        revoked.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let listed = vault.run(&["grants"]);
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        "no grants",
        "a revoked grant must no longer be listed"
    );
}

#[test]
fn empty_grants_prints_an_explicit_no_grants_line() {
    let vault = GrantCliVault::new("grants-empty");
    vault.bootstrap();

    let listed = vault.run(&["grants"]);
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        "no grants",
        "an empty grant table must not be silent"
    );
}

#[test]
fn bootstrap_put_mint_audit_end_to_end() {
    let root = tmp_root("e2e");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap a master key.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    let out = c.output().expect("run bootstrap");
    assert!(
        out.status.success(),
        "bootstrap: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // put an api_key credential.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("operator:db")
        .arg("--payload")
        .arg("sk-secret");
    global(&mut c);
    let out = c.output().expect("run put");
    assert!(
        out.status.success(),
        "put: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // mint a handle for it: stdout is the raw handle.
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("operator:db");
    global(&mut c);
    let out = c.output().expect("run mint-handle");
    assert!(
        out.status.success(),
        "mint: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let handle = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(handle.starts_with("ckh_"), "raw handle on stdout: {handle}");

    // verify-audit: the chain (put + mint_handle entries) must be intact.
    let mut c = cli();
    c.arg("verify-audit");
    global(&mut c);
    let out = c.output().expect("run verify-audit");
    assert!(
        out.status.success(),
        "verify-audit: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("intact"));

    // audit list shows the operations with the offline-cli actor.
    let mut c = cli();
    c.arg("audit");
    global(&mut c);
    let out = c.output().expect("run audit");
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains("put"), "audit lists the put: {listing}");
    assert!(
        listing.contains("mint_handle"),
        "audit lists the mint: {listing}"
    );
    assert!(listing.contains("offline-cli"), "actor recorded: {listing}");

    // list shows the credential id + its active state (no secrets, no decrypt).
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list");
    assert!(
        out.status.success(),
        "list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = String::from_utf8_lossy(&out.stdout);
    assert!(rows.contains("operator:db"), "list names the id: {rows}");
    assert!(rows.contains("active"), "list shows state: {rows}");
    assert!(
        !rows.contains("sk-secret"),
        "list must never print the payload: {rows}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A minted signing key is stored under the signing kind, can sign, and publishes the
/// matching public key. Inspecting the decrypted record and verifying the signature
/// proves the command's output is tied to the stored key rather than only its text.
#[test]
fn mint_signing_key_custodies_a_usable_key_and_prints_its_public_half() {
    let root = tmp_root("mint-signing-key");
    let data_dir = root.join("vault");
    let key_path = root.join("master.key");
    std::fs::write(&key_path, "11".repeat(32)).expect("write operator master key");

    let run = |args: &[&str]| {
        cli()
            .args([
                "--data-dir",
                data_dir.to_str().expect("data dir utf8"),
                "--key-path",
                key_path.to_str().expect("key path utf8"),
            ])
            .args(args)
            .output()
            .expect("run CLI")
    };

    let first = run(&["mint-signing-key", "--id", "signing:agent-assertion:7"]);
    assert!(
        first.status.success(),
        "first mint: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    let first_public = first_stdout
        .lines()
        .find_map(|line| line.strip_prefix("public_key_hex "))
        .expect("mint must print public key hex")
        .to_string();
    let first_key_id = first_stdout
        .lines()
        .find_map(|line| line.strip_prefix("key_id "))
        .expect("mint must print key id")
        .to_string();
    assert_eq!(first_public.len(), 64, "Ed25519 public keys are 32 bytes");
    assert_eq!(first_key_id.len(), 16, "key_id is eight digest bytes");
    assert!(
        !first_stdout.contains("PRIVATE KEY"),
        "the private PEM must never reach command output"
    );

    // Create-only is the safe default: an operator must explicitly acknowledge an
    // overwrite because an existing generation may already have signed artifacts.
    let duplicate = run(&["mint-signing-key", "--id", "signing:agent-assertion:7"]);
    assert!(
        !duplicate.status.success(),
        "minting an existing id without --replace must refuse"
    );

    let replacement = run(&[
        "mint-signing-key",
        "--id",
        "signing:agent-assertion:7",
        "--replace",
    ]);
    assert!(
        replacement.status.success(),
        "replacement mint: {}",
        String::from_utf8_lossy(&replacement.stderr)
    );
    let replacement_stdout = String::from_utf8_lossy(&replacement.stdout);
    let public_hex = replacement_stdout
        .lines()
        .find_map(|line| line.strip_prefix("public_key_hex "))
        .expect("replacement must print public key hex");
    let key_id = replacement_stdout
        .lines()
        .find_map(|line| line.strip_prefix("key_id "))
        .expect("replacement must print key id");
    assert_ne!(
        first_public, public_hex,
        "a replacement must generate a fresh key pair, not reprint the old public key"
    );

    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).expect("open minted vault");
    EncryptedStore::migrate(&sqlite).expect("migrate minted vault");
    let vault = EncryptedStore::open(sqlite, MasterKey::from_bytes([0x11; 32]))
        .expect("open minted vault with operator key");
    let record = vault
        .get("signing:agent-assertion:7")
        .expect("read minted signing record");
    assert_eq!(record.kind, CredentialKind::SigningKey);

    let payload = b"canonical JSON bytes";
    let signature = credentials_core::signing::sign_ed25519(
        std::str::from_utf8(record.payload.expose()).expect("mint stores PEM"),
        payload,
    )
    .expect("the minted record must be usable by credential.sign");
    let public: Vec<u8> = (0..public_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&public_hex[i..i + 2], 16).expect("public hex"))
        .collect();
    let raw_signature = base64::engine::general_purpose::STANDARD
        .decode(signature.signature_b64)
        .expect("signature base64");
    UnparsedPublicKey::new(&ED25519, &public)
        .verify(payload, &raw_signature)
        .expect("printed public key must verify the stored key's signature");
    assert_eq!(
        signature.key_id, key_id,
        "key id derives from the public key"
    );

    let wrong_method = run(&["mint-signing-key", "--id", "apikey:cannot-sign"]);
    assert!(
        !wrong_method.status.success()
            && String::from_utf8_lossy(&wrong_method.stderr).contains("requires an id beginning"),
        "minting under a non-signing method must refuse"
    );
    let bypass = run(&[
        "put",
        "--id",
        "signing:agent-assertion:unsafe",
        "--payload",
        "not-a-key",
    ]);
    assert!(
        !bypass.status.success()
            && String::from_utf8_lossy(&bypass.stderr).contains("mint-signing-key"),
        "generic put must not create a signing id with a non-signing record kind"
    );

    drop(vault);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn version_reports_the_built_cli_without_configuration() {
    let out = cli()
        .arg("--version")
        .output()
        .expect("run ck-auth --version");
    assert!(
        out.status.success(),
        "version: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The package version alone was the WHOLE assertion here, which is what let the
    // flag ship answering "is this ck-auth" rather than "which ck-auth": the constant
    // it pinned has not moved in the project's lifetime, so the test passed no matter
    // what code was inside. Now it must also carry the revision field.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stdout = stdout.trim();

    // Shape, not value. The revision is a property of the BINARY UNDER TEST, and under
    // CRED_CLI_BIN that is a staged artifact stamped with a real commit while this test
    // was compiled unstamped -- so asserting equality with the test's own BUILD_REV
    // would fail on exactly the artifact the override exists to verify, and would be
    // asserting the test's build rather than the binary's.
    let rest = stdout
        .strip_prefix(&format!("ck-auth {} (", env!("CARGO_PKG_VERSION")))
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("unexpected --version shape: {stdout}"));
    assert!(
        !rest.is_empty(),
        "the revision field must carry a value, even if it is `unknown`: {stdout}"
    );
    // Without an override this IS the test's own build, so the exact value is still
    // pinned in the ordinary run -- which is what keeps the field from silently
    // becoming a constant again.
    if std::env::var_os(CLI_BIN_ENV).is_none() {
        assert_eq!(rest, credentials_core::contract::BUILD_REV);
    }
}

/// `logout` stops serving reversibly (retire + revoke handles, row + audit kept).
/// `list` and `status` keep the parked row visible without turning it into a health
/// alarm.
#[test]
fn logout_retires_reversibly_without_degrading_health() {
    let root = tmp_root("logout");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap + put + mint a handle.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:x")
        .arg("--payload")
        .arg("sk-x");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("apikey:x");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // status before: ok, 1/1 serving.
    let mut c = cli();
    c.arg("status");
    global(&mut c);
    let out = c.output().expect("run status");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vault: ok (1/1 serving)"), "pre-logout: {s}");

    // logout by --id (apikey:x is not a login provider).
    let mut c = cli();
    c.arg("logout").arg("--id").arg("apikey:x");
    global(&mut c);
    let out = c.output().expect("run logout");
    assert!(
        out.status.success(),
        "logout: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("revoked 1 handle(s)"),
        "logout revokes the handle: {s}"
    );

    // status after: ok, the id is named as retired, and the ROW SURVIVES (not
    // deleted) — logout is reversible by design.
    let mut c = cli();
    c.arg("status");
    global(&mut c);
    let out = c.output().expect("run status after");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vault: ok (0/1 serving)"), "post-logout: {s}");
    assert!(
        s.contains("retired") && s.contains("apikey:x"),
        "the logged-out row survives as retired: {s}"
    );
    assert!(
        s.contains("retired: apikey:x"),
        "status names the intentionally parked id: {s}"
    );

    // `list` renders the retirement distinctly as well as `status`.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list after logout");
    let list = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        list.contains("retired") && list.contains("apikey:x"),
        "list distinguishes the retired row: {list}"
    );

    // The audit chain survives and stays intact (logout appended, destroyed nothing).
    let mut c = cli();
    c.arg("verify-audit");
    global(&mut c);
    let out = c.output().expect("run verify-audit");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("intact"));

    let _ = std::fs::remove_dir_all(&root);
}

/// An antigravity import stores an identity a consumer can actually resolve.
///
/// The importer parses the account's email out of the plugin store and, before this
/// was fixed, dropped it. That is invisible from inside the vault: the record stores
/// and serves normally, and the only symptom is downstream, where a consumer joining
/// on `account_id` cannot distinguish two antigravity accounts and collapses them
/// into one unlabelled entry.
///
/// So the assertion is on `account_id`, not `email`. Populating `email` alone would
/// look like a fix, render a value, and leave the symptom exactly as it was --
/// antigravity access tokens are opaque, so there is no live claim to fall back on.
///
/// Driven through the real binary, because the capture happens at the CLI call site:
/// a core-level test of the parser passes whether or not anything stores what it
/// returns.
#[test]
fn an_antigravity_import_stores_a_resolvable_account_identity() {
    use credentials_core::resolver::{KeySource, ResolverConfig};
    use credentials_core::store::EncryptedStore;

    let root = tmp_root("ag-import");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    // The plugin's on-disk shape, with two accounts so the selected one is not also
    // the first -- a capture that always took accounts[0] would otherwise pass.
    let store_json = root.join("antigravity-accounts.json");
    std::fs::write(
        &store_json,
        br#"{"version":4,"activeIndex":1,"accounts":[
              {"email":"first@x.com","refreshToken":"1//0-aaa","projectId":"proj-a"},
              {"email":"active@x.com","refreshToken":"1//0-bbb","projectId":"proj-b"}
            ]}"#,
    )
    .unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };
    let mut boot = cli();
    boot.arg("bootstrap");
    global(&mut boot);
    assert!(boot.output().unwrap().status.success(), "bootstrap");

    let mut imp = cli();
    imp.arg("import")
        .arg("--source")
        .arg("antigravity")
        .arg("--id")
        .arg("antigravity:google")
        .arg("--json")
        .arg(&store_json);
    global(&mut imp);
    let out = imp.output().expect("run import");
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Read the stored record back through the real decrypt path.
    let config = ResolverConfig {
        data_dir: data_dir.clone(),
        source: KeySource::OperatorPath {
            path: key_path.clone(),
        },
    };
    let key = credentials_core::resolver::resolve(&config, None).expect("resolve key");
    let sqlite = open_sqlite(&StorageDescriptor {
        // Same shape the other tests in this file use: the module id is imported
        // rather than spelled so a rename cannot silently point this at a different
        // store than the CLI just wrote to.
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .expect("open store");
    EncryptedStore::migrate(&sqlite).expect("migrate");
    let store = EncryptedStore::open(sqlite, key).expect("open vault");
    let record = store.get("antigravity:google").expect("read the record");

    assert_eq!(
        record.identity.account_id.as_deref(),
        Some("active@x.com"),
        "account_id is the field a consumer resolves identity from; without it the \
         record renders an email and still labels nothing"
    );
    assert_eq!(
        record.identity.email.as_deref(),
        Some("active@x.com"),
        "and the display field agrees with it"
    );
    assert!(
        record.identity.is_servable(),
        "the stored identity must satisfy the servable predicate"
    );
    // The identity must track the SELECTED account, not the store's first.
    assert!(
        record
            .oauth
            .as_ref()
            .unwrap()
            .refresh_token
            .expose()
            .starts_with("1//0-bbb"),
        "sanity: the active account's credential was the one imported"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn antigravity_import_prefers_explicit_account_id_and_only_overrides_source_email_when_requested() {
    use credentials_core::resolver::{KeySource, ResolverConfig};

    let root = tmp_root("ag-import-explicit-identity");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).expect("vault dir");
    std::fs::create_dir_all(key_path.parent().expect("key dir")).expect("key dir");
    let source = root.join("antigravity-accounts.json");
    std::fs::write(
        &source,
        br#"{"version":4,"activeIndex":0,"accounts":[{"email":"source@example.com","refreshToken":"1//0-source","projectId":"project"}]}"#,
    )
    .expect("write source");
    let run = |args: &[&str]| -> std::process::Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .output()
            .expect("run ck-auth")
    };
    let open_store = || {
        let key = credentials_core::resolver::resolve(
            &ResolverConfig {
                data_dir: data_dir.clone(),
                source: KeySource::OperatorPath {
                    path: key_path.clone(),
                },
            },
            None,
        )
        .expect("resolve key");
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        })
        .expect("open store");
        EncryptedStore::migrate(&sqlite).expect("migrate");
        EncryptedStore::open(sqlite, key).expect("open vault")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");
    assert!(
        run(&[
            "import",
            "--source",
            "antigravity",
            "--id",
            "antigravity:google:source-email",
            "--json",
            source.to_str().expect("source path"),
            "--account-id",
            "acct-explicit",
        ])
        .status
        .success(),
        "explicit account import"
    );
    let store = open_store();
    let source_email = store
        .get("antigravity:google:source-email")
        .expect("record");
    assert_eq!(
        source_email.identity.account_id.as_deref(),
        Some("acct-explicit")
    );
    assert_eq!(
        source_email.identity.email.as_deref(),
        Some("source@example.com"),
        "the source email remains useful display metadata unless an operator overrides it"
    );
    drop(store);

    assert!(
        run(&[
            "import",
            "--source",
            "antigravity",
            "--id",
            "antigravity:google:operator-email",
            "--json",
            source.to_str().expect("source path"),
            "--account-id",
            "acct-operator",
            "--email",
            "operator@example.com",
        ])
        .status
        .success(),
        "operator email import"
    );
    let operator_email = open_store()
        .get("antigravity:google:operator-email")
        .expect("record");
    assert_eq!(
        operator_email.identity.account_id.as_deref(),
        Some("acct-operator")
    );
    assert_eq!(
        operator_email.identity.email.as_deref(),
        Some("operator@example.com")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_and_set_identity_attach_sticky_account_metadata_without_replacing_secret_material() {
    use credentials_core::resolver::{KeySource, ResolverConfig};

    let root = tmp_root("import-identity");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).expect("vault dir");
    std::fs::create_dir_all(key_path.parent().expect("key dir")).expect("key dir");
    let source = root.join("auth.json");
    std::fs::write(
        &source,
        r#"{"refresh":"refresh-original","access":"opaque-original","expires":4102444800000}"#,
    )
    .expect("write source");

    let run = |args: &[&str]| -> std::process::Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .output()
            .expect("run ck-auth")
    };
    let open_record = || {
        let config = ResolverConfig {
            data_dir: data_dir.clone(),
            source: KeySource::OperatorPath {
                path: key_path.clone(),
            },
        };
        let key = credentials_core::resolver::resolve(&config, None).expect("resolve key");
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        })
        .expect("open store");
        EncryptedStore::migrate(&sqlite).expect("migrate");
        EncryptedStore::open(sqlite, key).expect("open vault")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");
    let imported = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:anthropic",
        "--json",
        source.to_str().expect("source path"),
        "--account-id",
        "acct-import",
        "--email",
        "import@example.com",
        "--org-name",
        "Import Organization",
    ]);
    assert!(
        imported.status.success(),
        "import: {}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let store = open_record();
    let imported_record = store.get("oauth:anthropic").expect("imported record");
    assert_eq!(
        imported_record.identity.account_id.as_deref(),
        Some("acct-import"),
        "the import flag must land in the identity field consumers resolve"
    );
    drop(store);

    let mut legacy = imported_record;
    legacy.identity.account_id = Some("acct\ncontrol".to_string());
    let key = credentials_core::resolver::resolve(
        &ResolverConfig {
            data_dir: data_dir.clone(),
            source: KeySource::OperatorPath {
                path: key_path.clone(),
            },
        },
        None,
    )
    .expect("resolve key for legacy envelope");
    let envelope = credentials_core::envelope::seal(
        &key,
        &legacy.encode().expect("encode legacy record"),
        &credentials_core::envelope::RecordBinding {
            credential_id: "oauth:anthropic",
            record_version: 1,
        },
    )
    .expect("seal legacy record");
    let conn = rusqlite::Connection::open(data_dir.join("store.db")).expect("open raw store");
    conn.execute(
        "UPDATE credentials SET envelope = ?1 WHERE credential_id = 'oauth:anthropic'",
        rusqlite::params![envelope],
    )
    .expect("seed legacy identity");
    let usable_legacy = run(&["usable"]);
    let usable_legacy_stdout = String::from_utf8_lossy(&usable_legacy.stdout);
    assert!(usable_legacy.status.success());
    assert!(usable_legacy_stdout.contains("account=<invalid>"));
    assert!(!usable_legacy_stdout.contains("acct\ncontrol"));
    assert!(usable_legacy_stdout.contains("unservable identity: 1"));

    let store = open_record();
    let material_fixture = credentials_core::record::VaultRecord::new_oauth(
        "fixture",
        "anthropic",
        credentials_core::oauth::OAuthCredential {
            access_token: "opaque-fixture-access".to_string().into(),
            refresh_token: "fixture-refresh-secret".to_string().into(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://fixture.invalid/token".to_string(),
            client_id: Some("fixture-client".to_string()),
            scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
        },
        b"opaque-fixture-access".to_vec(),
    );
    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &material_fixture,
            credentials_core::audit::AuditCtx::admin(credentials_core::audit::AuditOp::Import),
        )
        .expect("replace with field-complete OAuth fixture");
    let before_set = store.get("oauth:anthropic").expect("before set");
    drop(store);
    let set = run(&[
        "set-identity",
        "oauth:anthropic",
        "--account-id",
        "acct-set",
        "--email",
        "set@example.com",
    ]);
    assert!(
        set.status.success(),
        "set-identity: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    let store = open_record();
    let after_set = store.get("oauth:anthropic").expect("after set");
    assert_eq!(
        after_set.payload, before_set.payload,
        "set-identity must not rotate payload"
    );
    assert_eq!(
        after_set.oauth, before_set.oauth,
        "set-identity must not replace OAuth material"
    );
    assert_eq!(after_set.identity.account_id.as_deref(), Some("acct-set"));
    assert!(
        store
            .read_audit(None)
            .expect("audit")
            .iter()
            .any(|entry| entry.op == "set_identity"),
        "identity-only writes must leave an audit entry"
    );
    drop(store);

    let usable = run(&["usable"]);
    let usable_stdout = String::from_utf8_lossy(&usable.stdout);
    assert!(
        usable.status.success(),
        "usable: {}",
        String::from_utf8_lossy(&usable.stderr)
    );
    assert!(
        usable_stdout
            .lines()
            .any(|line| line.contains("oauth:anthropic") && line.contains("account=acct-set")),
        "usable must show non-secret account identity presence: {usable_stdout}"
    );

    std::fs::write(
        &source,
        r#"{"refresh":"refresh-rotated","access":"opaque-rotated","expires":4102444800000}"#,
    )
    .expect("rotate source");
    let replacement = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:anthropic",
        "--json",
        source.to_str().expect("source path"),
        "--replace",
    ]);
    assert!(
        replacement.status.success(),
        "replace: {}",
        String::from_utf8_lossy(&replacement.stderr)
    );
    let sticky = open_record()
        .get("oauth:anthropic")
        .expect("sticky identity");
    assert_eq!(sticky.identity.account_id.as_deref(), Some("acct-set"));
    assert_eq!(
        sticky.oauth.as_ref().expect("OAuth").refresh_token.expose(),
        "refresh-rotated"
    );
    assert_eq!(
        sticky.oauth.as_ref().expect("OAuth").access_token.expose(),
        "opaque-rotated"
    );

    let cleared = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:anthropic",
        "--json",
        source.to_str().expect("source path"),
        "--replace",
        "--clear-identity",
    ]);
    assert!(
        cleared.status.success(),
        "clear identity: {}",
        String::from_utf8_lossy(&cleared.stderr)
    );
    let cleared_record = open_record()
        .get("oauth:anthropic")
        .expect("cleared identity");
    assert!(
        cleared_record.identity.is_empty(),
        "--clear-identity must override sticky preservation"
    );
    assert_eq!(
        cleared_record
            .oauth
            .as_ref()
            .expect("OAuth")
            .refresh_token
            .expose(),
        "refresh-rotated"
    );
    assert_eq!(
        cleared_record
            .oauth
            .as_ref()
            .expect("OAuth")
            .access_token
            .expose(),
        "opaque-rotated"
    );

    assert!(
        run(&[
            "set-identity",
            "oauth:anthropic",
            "--account-id",
            "acct-to-clear",
        ])
        .status
        .success(),
        "set identity before clear"
    );
    assert!(
        run(&["set-identity", "oauth:anthropic", "--clear"])
            .status
            .success(),
        "set-identity --clear"
    );
    assert!(
        open_record()
            .get("oauth:anthropic")
            .expect("cleared by set-identity")
            .identity
            .is_empty(),
        "set-identity --clear must drop metadata without a source re-import"
    );

    let email_only = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:other",
        "--json",
        source.to_str().expect("source path"),
        "--email",
        "missing-account@example.com",
    ]);
    assert!(
        !email_only.status.success(),
        "email without account_id must refuse"
    );
    assert!(
        String::from_utf8_lossy(&email_only.stderr).contains("--account-id is required"),
        "email-only refusal must name the missing field"
    );

    for invalid_value in ["", "account\ncontrol", &"x".repeat(257)] {
        let invalid_output = run(&[
            "set-identity",
            "oauth:anthropic",
            "--account-id",
            invalid_value,
        ]);
        assert!(
            !invalid_output.status.success(),
            "invalid account id {invalid_value:?} must refuse"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// `events` separates three outcomes an operator must not confuse.
///
/// "no events" and "this store cannot record events" would otherwise render the same,
/// and they call for different responses: the first means nothing has gone wrong, the
/// second means the recorder is not installed yet and an incident would leave no trace.
///
/// Also pins that the verb takes NO LEASE. The rows exist to explain a credential that
/// just failed, so requiring the daemon stopped would make the diagnostic unavailable
/// exactly when it is wanted.
#[test]
fn events_distinguishes_no_events_from_no_table_and_takes_no_lease() {
    let root = tmp_root("events");
    let data_dir = root.join("data");
    let key_path = root.join("secrets").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    // A write, so the schema (and with it the events table) is actually created.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:e")
        .arg("--payload")
        .arg("k");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    let mut c = cli();
    c.arg("events");
    global(&mut c);
    let out = c.output().expect("run events");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "events on a migrated vault must succeed"
    );
    assert!(
        text.contains("no authentication events recorded"),
        "an empty table must say so plainly; got: {text}"
    );

    // A store WITHOUT the table: the same command must say something different, because
    // "nothing recorded" and "nothing can be recorded" are different facts.
    let old = root.join("old");
    std::fs::create_dir_all(&old).unwrap();
    let conn = open_sqlite(&StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: old.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .expect("open a bare store");
    drop(conn);

    let mut c = cli();
    c.arg("events").arg("--data-dir").arg(&old);
    let out = c.output().expect("run events on a pre-migration store");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "an absent table is a reportable state, not a failure"
    );
    assert!(
        text.contains("no authentication-event table yet"),
        "an absent table must be distinguishable from an empty one; got: {text}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `invalidate` reports what it actually did, and reaches the state it claims.
///
/// The verb exits 0 for a credential that does not exist -- measured -- printing
/// "invalidated <id>; revoked 0 handle(s)". So an exit status says nothing here, and
/// the observable that separates a real invalidation from a no-op is the reported
/// handle count together with the resulting lifecycle state.
///
/// The store layer's own test covers `invalidate_audited`. This covers the verb: that
/// the CLI reaches that path, that its count comes from the transaction rather than
/// being printed unconditionally, and that a consumer's handle stops resolving.
#[test]
fn invalidate_reports_the_handles_it_revoked_and_leaves_the_row_needing_reauth() {
    let root = tmp_root("invalidate");
    let data_dir = root.join("data");
    let key_path = root.join("secrets").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:inv")
        .arg("--payload")
        .arg("k");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    for _ in 0..2 {
        let mut c = cli();
        c.arg("mint-handle").arg("--id").arg("apikey:inv");
        global(&mut c);
        assert!(c.output().unwrap().status.success());
    }

    let mut c = cli();
    c.arg("invalidate").arg("--id").arg("apikey:inv");
    global(&mut c);
    let out = c.output().expect("run invalidate");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "invalidate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        report.contains("revoked 2 handle(s)"),
        "the count must come from the transaction, not be printed regardless; got: {report}"
    );

    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("needs_reauth") && rows.contains("apikey:inv"),
        "the row must be left needing reauth: {rows}"
    );

    // The negative arm, and the reason the count above is the assertion rather than
    // the exit status: the same verb on an absent credential also succeeds.
    let mut c = cli();
    c.arg("invalidate").arg("--id").arg("apikey:never-existed");
    global(&mut c);
    let out = c.output().expect("run invalidate on an absent id");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "an absent id still exits 0");
    assert!(
        report.contains("revoked 0 handle(s)"),
        "a no-op must report zero, which is what makes the positive count meaningful; \
         got: {report}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `put --replace` is the routine static-key rotation path: it bumps
/// `record_version` (the consumer cache-invalidation signal) and keeps the
/// existing handle, exactly like `login --replace` does for an OAuth record.
///
/// Note the property under test belongs to the REPLACE APPLIER, not to `put`.
///
/// `put --replace` and `login --replace` both build an `AdminOpBody::Store` carrying
/// `StoreMode::ReplaceUnconditional`, which dispatches to
/// `overwrite_unconditional_audited` — that updates the credential row and never
/// touches the handles table. So a consumer's handle surviving an operator's re-login
/// is this same guarantee, reached through the same code.
///
/// Worth saying because the name says `put`, so someone asking "does a re-login keep
/// my handle?" would not find it here. The OAuth login arm is not driven instead
/// because it needs a real provider exchange; this arm reaches the shared applier
/// offline.
#[test]
fn put_replace_rotates_a_static_key_bumping_version_and_keeping_the_handle() {
    let root = tmp_root("put-replace");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap + create the key + mint a handle for it.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("old-key");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("apikey:vast");
    global(&mut c);
    let handle = String::from_utf8_lossy(&c.output().unwrap().stdout)
        .trim()
        .to_string();
    assert!(handle.starts_with("ckh_"));

    // The created record is at v1.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("v1") && rows.contains("apikey:vast"),
        "created at v1: {rows}"
    );

    // A create-mode put on the SAME id must be refused (create-only default) — this
    // is why a dedicated rotation verb is needed at all.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("new-key");
    global(&mut c);
    assert!(
        !c.output().unwrap().status.success(),
        "a plain put on an existing id must fail (create-only)"
    );

    // put --replace rotates it: new payload, version bumps to v2, id stays active.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("new-key")
        .arg("--replace");
    global(&mut c);
    let out = c.output().expect("run put --replace");
    assert!(
        out.status.success(),
        "put --replace: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("active         v2    apikey:vast"),
        "replace bumped the version and kept it active: {rows}"
    );

    // The handle SURVIVES the rotation, asserted on a COUNT rather than on an exit
    // status.
    //
    // `revoke-handle` succeeds for an unknown handle too -- measured: revoking a
    // never-minted string prints "revoked handle" and exits 0, deliberately, since
    // revocation is idempotent and must not confirm whether a handle exists. So
    // asserting that it succeeds proves nothing about the row surviving; it passes
    // just as well against a replace that orphaned every handle.
    //
    // `revoke-all-handles` reports the number it revoked, which is the signal that
    // distinguishes those cases: 1 if the replace kept the row, 0 if it did not.
    let mut c = cli();
    c.arg("revoke-all-handles").arg("--id").arg("apikey:vast");
    global(&mut c);
    let out = c.output().expect("run revoke-all-handles");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "revoke-all-handles: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        report.contains("revoked 1 handle"),
        "the pre-rotation handle must still be live after the replace, so exactly one \
         is revoked here; got: {report}"
    );

    // --replace and --expected-hash are mutually exclusive.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("z")
        .arg("--replace")
        .arg("--expected-hash")
        .arg("00");
    global(&mut c);
    assert!(
        !c.output().unwrap().status.success(),
        "--replace and --expected-hash cannot be combined"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Cookie repair uses the same replacement machinery as static-key rotation, but the
/// captured header comes from a file and must remain a Cookie record with no expiry.
#[test]
fn cookie_put_replace_bumps_version_and_keeps_the_handle_live() {
    let root = tmp_root("cookie-replace");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");
    let global = |command: &mut Command| {
        command
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut bootstrap = cli();
    bootstrap.arg("bootstrap");
    global(&mut bootstrap);
    assert!(bootstrap.output().expect("bootstrap").status.success());

    let payload_file = root.join("cookie.txt");
    std::fs::write(
        &payload_file,
        b" session=old=1; preference=space value; ending=%",
    )
    .expect("write captured cookie");
    let mut put = cli();
    put.arg("put")
        .arg("--id")
        .arg("cookie:qwencloud.com:work")
        .arg("--payload-file")
        .arg(&payload_file);
    global(&mut put);
    let output = put.output().expect("put cookie");
    assert!(
        output.status.success(),
        "cookie deposit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut mint = cli();
    mint.arg("mint-handle")
        .arg("--id")
        .arg("cookie:qwencloud.com:work");
    global(&mut mint);
    assert!(mint.output().expect("mint handle").status.success());

    std::fs::write(
        &payload_file,
        b" session=new=2; preference=space value; ending=%",
    )
    .expect("write replacement cookie");
    let mut replace = cli();
    replace
        .arg("put")
        .arg("--id")
        .arg("cookie:qwencloud.com:work")
        .arg("--payload-file")
        .arg(&payload_file)
        .arg("--replace");
    global(&mut replace);
    let output = replace.output().expect("replace cookie");
    assert!(
        output.status.success(),
        "cookie replace: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut list = cli();
    list.arg("list");
    global(&mut list);
    let rows = String::from_utf8_lossy(&list.output().expect("list").stdout).into_owned();
    assert!(
        rows.contains("active         v2    cookie:qwencloud.com:work"),
        "replacement must bump the record version: {rows}"
    );

    // A cookie has no declarable expiry: the raw request header holds no Set-Cookie
    // attributes, so a timestamp here would be invented rather than captured.
    let mut expired = cli();
    expired
        .arg("put")
        .arg("--id")
        .arg("cookie:qwencloud.com:work")
        .arg("--payload-file")
        .arg(&payload_file)
        .arg("--expires-ms")
        .arg("1")
        .arg("--replace");
    global(&mut expired);
    let output = expired.output().expect("reject cookie expiry");
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("do not carry an expiry"),
        "cookie expiry must be refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // `revoke-all-handles` reports the real count, unlike idempotent `revoke-handle`.
    // Revoking the original handle proves replacement kept that handle live.
    let mut revoke = cli();
    revoke
        .arg("revoke-all-handles")
        .arg("--id")
        .arg("cookie:qwencloud.com:work");
    global(&mut revoke);
    let output = revoke.output().expect("revoke handles");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("revoked 1 handle"),
        "replacement must retain the minted handle"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// An empty manual capture must fail during the `put` operation rather than being
/// stored as a successful-but-useless credential response.
#[test]
fn cookie_put_refuses_a_zero_byte_payload_file() {
    let root = tmp_root("cookie-empty");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");
    let global = |command: &mut Command| {
        command
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut bootstrap = cli();
    bootstrap.arg("bootstrap");
    global(&mut bootstrap);
    assert!(bootstrap.output().expect("bootstrap").status.success());
    let payload_file = root.join("empty-cookie.txt");
    std::fs::write(&payload_file, []).expect("write empty capture");

    let mut put = cli();
    put.arg("put")
        .arg("--id")
        .arg("cookie:cursor.com")
        .arg("--payload-file")
        .arg(&payload_file);
    global(&mut put);
    let output = put.output().expect("put empty cookie");
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("payload must not be empty"),
        "zero-byte capture must be refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn admin_write_refused_while_lease_held() {
    // The structural "while stopped" proof: hold the single-writer lease (as the
    // daemon would) and confirm an admin CLI write is refused with the
    // daemon-running exit code (3), not applied.
    let root = tmp_root("lease");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap first (no lease held yet).
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // Now hold the lease (simulating the running daemon). The namespace MUST match
    // the CLI's ("default", what subc delivers) — the lease key is
    // (module_id, backend, namespace), so a mismatched namespace would take a
    // DIFFERENT lock and the admin write would (wrongly) not be refused.
    let descriptor = StorageDescriptor {
        // Imported rather than spelled: this store must take the SAME lease lock the
        // CLI takes, and the lease key is (module_id, backend, namespace). A literal
        // here drifts silently on a module rename — the two sides then take DIFFERENT
        // locks, the admin write is no longer refused, and this test stops proving
        // mutual exclusion while still passing on its other assertions.
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _held = open_sqlite(&descriptor).expect("hold the lease");

    // An admin put must now be refused with exit code 3 (daemon running).
    let mut c = cli();
    c.arg("put").arg("--id").arg("x").arg("--payload").arg("y");
    global(&mut c);
    let out = c.output().expect("run put while leased");
    assert!(
        !out.status.success(),
        "put must fail while the lease is held"
    );
    assert_eq!(out.status.code(), Some(3), "daemon-running exit code");

    // AND THE REFUSAL NAMES THE NO-DOWNTIME FIX. A caller hitting this has no reason
    // to know --subc exists: it lives under `help overrides`, which is exactly where
    // someone who does not know the flag's name will not look. A refusal that names
    // only "stop the daemon" pushes every routine repair through an outage, so the
    // remedy has to travel with the refusal rather than be findable from it.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--subc"),
        "the refusal must name the flag that makes the write succeed; got: {stderr}"
    );
    assert!(
        stderr.contains("stop the daemon"),
        "and must still offer the offline path; got: {stderr}"
    );

    drop(_held);
    let _ = std::fs::remove_dir_all(&root);
}

/// Inventory reads must not contend with the daemon's single-writer lease.
///
/// Holding the real store lease reproduces the boot collision: these verbs have no live
/// module to answer, so each must fall back to plaintext read-only metadata rather than
/// trying to become a second writer. Comparing with the unlocked output also pins that
/// changing the transport does not change the report.
#[test]
fn read_only_inventory_verbs_succeed_while_exclusive_lease_is_held() {
    let vault = GrantCliVault::new("read-verbs-leased");
    vault.bootstrap();

    let put = vault.run(&["put", "--id", "apikey:lease-reader", "--payload", "secret"]);
    assert!(
        put.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&put.stderr)
    );
    let grant = vault.run(&[
        "grant",
        "--principal",
        "agent",
        "--selector-kind",
        "exact",
        "--selector",
        "apikey:",
        "--operation",
        "read",
    ]);
    assert!(
        grant.status.success(),
        "grant failed: {}",
        String::from_utf8_lossy(&grant.stderr)
    );

    let unlocked: Vec<(&str, std::process::Output)> = ["list", "grants", "status"]
        .into_iter()
        .map(|verb| (verb, vault.run(&[verb])))
        .collect();
    assert!(
        String::from_utf8_lossy(&unlocked[0].1.stdout).contains("apikey:lease-reader"),
        "list must render the seeded credential"
    );
    assert!(
        String::from_utf8_lossy(&unlocked[1].1.stdout).contains("reserved"),
        "grants must render the seeded grant"
    );
    assert!(
        String::from_utf8_lossy(&unlocked[2].1.stdout).contains("vault: ok (1/1 serving)"),
        "status must render the seeded vault health"
    );

    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: vault
                .data_dir
                .join("store.db")
                .to_string_lossy()
                .into_owned(),
        },
    };
    let held = open_sqlite(&descriptor).expect("hold the daemon's exclusive lease");

    for (verb, expected) in unlocked {
        let actual = vault.run(&[verb]);
        assert!(
            actual.status.success(),
            "{verb} must remain usable while the writer lease is held: {}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(
            actual.stdout, expected.stdout,
            "{verb} output changed when the writer lease was held"
        );
        assert_eq!(
            actual.stderr, expected.stderr,
            "{verb} diagnostics changed when the writer lease was held"
        );
    }

    drop(held);
}

/// The validation bypass must not exist in a shipped binary.
///
/// Test-only environment hatches must be compiled out of the operator binary. Some
/// simulate failed persistence and cleanup; one turns an invalid API key into a stored
/// credential while printing "API key is valid." Shipping any of them would put an
/// environment-controlled fault or validation bypass in the custody path.
///
/// Asserted against a real release build rather than by reading the `#[cfg]`, because
/// the claim is about the artifact: a later edit could move the gate, widen it, or add
/// a second read of the same var, and every one of those still reads correctly at the
/// source while shipping the hole.
///
/// The positive control is what makes the absence a measurement: a string known to be
/// present must be found by the identical pipeline, so a scan that silently finds
/// nothing (wrong path, unreadable file, broken pipe) fails here rather than passing as
/// a clean result.
#[test]
#[ignore = "builds the release profile; run explicitly or in the release gate"]
fn test_escape_hatches_are_absent_from_a_release_build() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let built = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "credentials-module",
            "--bin",
            "ck-auth",
        ])
        .current_dir(&manifest)
        .output()
        .expect("run cargo build");
    assert!(
        built.status.success(),
        "release build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let exe = workspace.join("target/release/ck-auth");
    let bytes = std::fs::read(&exe).expect("read the release ck-auth");

    let find = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());

    // Positive control first: if this fails the scan is broken, not the binary clean.
    assert!(
        find("API key validation failed"),
        "positive control absent -- the scan cannot see strings it should find, so the \
         escape-hatch checks below would pass vacuously"
    );

    // THE POPULATION IS DERIVED FROM SOURCE, NOT LISTED HERE. A hardcoded list is a
    // guard that reads as covering what it has never looked at: it stays green for
    // every hatch added after it was written, and the day it matters is the day
    // someone added one. Reviewing a contributor's branch that introduced FOUR new
    // seam env vars against this test's ONE asserted string is what exposed the
    // shape -- the scan would have passed while shipping all four.
    //
    // The point is that the population follows source additions instead of relying on
    // a reviewer to remember a second hardcoded list.
    let hatches = shipped_test_hatch_env_names();

    // Floor: an extractor that silently matches nothing would make every assertion
    // below vacuous, and "zero hatches found" is indistinguishable from "scan broken".
    // The repo has had at least one since 2026-08-08 (c380352).
    assert!(
        !hatches.is_empty(),
        "derived zero test-hatch env names from source -- the extractor is broken, not \
         the source clean; this repo has carried at least one since c380352"
    );
    // Anchors: prove the extractor finds known instances from both the established
    // TEST convention and the SCRIPT convention used by interactive test drivers.
    for known in [
        "CORTEXKIT_TEST_BYPASS_VALIDATION",
        "CK_AUTH_IMPORT_PROMPT_SCRIPT",
    ] {
        assert!(
            hatches.iter().any(|h| h == known),
            "the extractor missed the known hatch {known}; it is reading something other \
             than the shipped source. Derived: {hatches:?}"
        );
    }

    for hatch in &hatches {
        assert!(
            !find(hatch),
            "test hatch {hatch} is present in the release ck-auth binary; it must be \
             compiled out under #[cfg(debug_assertions)] rather than gated at runtime"
        );
    }
}

/// Every test-hatch env name in the SHIPPED source of the two crates.
///
/// WHAT THIS CAN AND CANNOT CLAIM, stated because a guard that implies completeness is
/// worse than none: it finds every hatch whose name carries `TEST`, `BYPASS`, `SEAM`,
/// or `SCRIPT`, which is this repo's convention. A hatch outside it is invisible
/// to it. The convention is therefore load-bearing, not cosmetic.
///
/// The scan is SHAPE-FREE -- it matches SCREAMING_CASE string literals rather than
/// `env::var(...)` call sites. An earlier env-var census here was written call-shaped
/// and returned a plausible six-name list that omitted `SUBC_LAUNCH_NONCE`, a name I had
/// been writing about all week; the shape-free pass found the real thirteen. A scan that
/// only sees one syntax reports honestly about that syntax and says nothing about the
/// rest.
///
/// `src/` only: a hatch named in `tests/` is test code and never reaches a binary.
fn shipped_test_hatch_env_names() -> Vec<String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for token in text.split('"') {
                    let looks_like_a_name = token.len() >= 4
                        && token
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                        && token.starts_with(|c: char| c.is_ascii_uppercase());
                    if looks_like_a_name
                        && ["TEST", "BYPASS", "SEAM", "SCRIPT"]
                            .iter()
                            .any(|keyword| token.contains(keyword))
                        && !out.iter().any(|existing| existing == token)
                    {
                        out.push(token.to_string());
                    }
                }
            }
        }
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();
    let mut out = Vec::new();
    walk(&workspace.join("crates/credentials-module/src"), &mut out);
    walk(&workspace.join("crates/credentials-core/src"), &mut out);
    out
}

/// The valid-key arm makes absence of the URL a meaningful ordering signal rather than
/// a flow that never reached URL construction for an unrelated reason.
#[test]
fn login_key_preflight_refuses_before_printing_the_authorize_url() {
    let root = tmp_root("login-key-preflight");
    let data_dir = root.join("vault");
    let key_dir = root.join("keys");
    std::fs::create_dir_all(&data_dir).expect("create vault dir");
    std::fs::create_dir_all(&key_dir).expect("create key dir");
    let missing_key_path = key_dir.join("missing-master.key");

    let run = |key_path: &std::path::Path| {
        let mut command = cli();
        command
            .arg("login")
            .arg("--provider")
            .arg("anthropic")
            .arg("--no-listener")
            .arg("--no-browser")
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(key_path)
            .stdin(Stdio::null());
        command.output().expect("run anthropic login")
    };

    let refused = run(&missing_key_path);
    assert!(
        !refused.status.success(),
        "a missing master key must refuse"
    );
    let refused_stdout = String::from_utf8_lossy(&refused.stdout);
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused_stdout.contains("Open this URL"),
        "the browser flow must not start before the master key resolves: {refused_stdout}"
    );
    assert!(
        refused_stderr.contains("--key-path"),
        "the refusal must name the operator-key remedy: {refused_stderr}"
    );

    // Control: the same flow reaches the URL when only the key-resolution failure is
    // removed. Closed stdin then makes callback parsing fail without making a network call.
    let valid_key_path = key_dir.join("master.key");
    std::fs::write(&valid_key_path, "17".repeat(32)).expect("write operator key");
    let reached_browser_flow = run(&valid_key_path);
    assert!(
        !reached_browser_flow.status.success(),
        "empty callback input must stop before token exchange"
    );
    let control_stdout = String::from_utf8_lossy(&reached_browser_flow.stdout);
    assert!(
        control_stdout.contains("Open this URL"),
        "a valid key must reach the browser flow, or the negative assertion proves nothing: {control_stdout}"
    );
}

/// The operator who reported this had the browser on a SECOND computer, signed into
/// the account they wanted to custody. With `--no-listener` nothing holds
/// localhost:54545, so sending the browser there can only produce a failed page, and
/// the address bar of a failed page was all they had to carry back. Anthropic
/// registers a second redirect on the same OAuth app that renders the result as a
/// short `code#state`, so the no-listener authorize URL must ask for that one.
///
/// Asserted on the REAL process's stdout rather than on the builder, because the URL
/// the operator opens is the only thing the provider sees.
#[test]
fn login_without_a_listener_sends_anthropic_the_code_display_redirect() {
    let root = tmp_root("login-no-listener-redirect");
    let data_dir = root.join("vault");
    let key_dir = root.join("keys");
    std::fs::create_dir_all(&data_dir).expect("create vault dir");
    std::fs::create_dir_all(&key_dir).expect("create key dir");
    let key_path = key_dir.join("master.key");
    std::fs::write(&key_path, "17".repeat(32)).expect("write operator key");

    let mut command = cli();
    command
        .arg("login")
        .arg("--provider")
        .arg("anthropic")
        .arg("--no-listener")
        .arg("--no-browser")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path)
        .stdin(Stdio::null());
    // Closed stdin makes the pasted callback empty, so the flow stops at parsing
    // without making a network call — after printing everything under test here.
    let printed = String::from_utf8_lossy(&command.output().expect("run anthropic login").stdout)
        .into_owned();

    assert!(
        printed.contains("Open this URL"),
        "the flow must reach the browser step, or the assertions below prove nothing: {printed}"
    );
    assert!(
        printed
            .contains("redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"),
        "with no listener the authorize URL must carry the code-display redirect: {printed}"
    );
    assert!(
        !printed.contains("54545"),
        "nothing is holding the loopback socket, so neither the URL nor the prompt may \
         send the operator there: {printed}"
    );
    assert!(
        printed.contains("code#state"),
        "the prompt must describe the artifact the page actually shows: {printed}"
    );
    assert!(
        !printed.contains("THIS machine"),
        "the listener wait banner belongs to the path where a listener bound: {printed}"
    );
}

#[test]
fn login_existence_preflight_refuses_before_printing_the_authorize_url() {
    let root = tmp_root("login-existence-preflight");
    let data_dir = root.join("vault");
    let key_dir = root.join("keys");
    std::fs::create_dir_all(&data_dir).expect("create vault dir");
    std::fs::create_dir_all(&key_dir).expect("create key dir");
    let key_path = key_dir.join("master.key");

    let global = |command: &mut Command| {
        command
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut bootstrap = cli();
    bootstrap.arg("bootstrap");
    global(&mut bootstrap);
    let bootstrapped = bootstrap.output().expect("bootstrap vault");
    assert!(
        bootstrapped.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&bootstrapped.stderr)
    );

    let mut put = cli();
    put.arg("put")
        .arg("--id")
        .arg("oauth:anthropic")
        .arg("--payload")
        .arg("existing-credential");
    global(&mut put);
    let deposited = put.output().expect("deposit existing target");
    assert!(
        deposited.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&deposited.stderr)
    );

    let run_login = |id: Option<&str>, replace: bool| {
        let mut command = cli();
        command
            .arg("login")
            .arg("--provider")
            .arg("anthropic")
            .arg("--no-listener")
            .arg("--no-browser");
        if let Some(id) = id {
            command.arg("--id").arg(id);
        }
        if replace {
            command.arg("--replace");
        }
        global(&mut command);
        command
            .stdin(Stdio::null())
            .output()
            .expect("run anthropic login")
    };

    let refused = run_login(None, false);
    assert!(
        !refused.status.success(),
        "create mode must refuse an existing id"
    );
    let refused_stdout = String::from_utf8_lossy(&refused.stdout);
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused_stdout.contains("Open this URL"),
        "the browser flow must not start for a known collision: {refused_stdout}"
    );
    assert!(
        refused_stderr.contains("already holds a credential"),
        "the established collision advice must be preserved: {refused_stderr}"
    );

    let replacing = run_login(None, true);
    assert!(
        !replacing.status.success(),
        "empty callback input must stop the replacement before token exchange"
    );
    let control_stdout = String::from_utf8_lossy(&replacing.stdout);
    assert!(
        control_stdout.contains("Open this URL"),
        "replace on an existing id must reach the browser flow: {control_stdout}"
    );

    // ReplaceUnconditional is an update, not an upsert. Preserve its NotFound refusal
    // before asking the operator to authorize a credential the store cannot create.
    let missing_replace = run_login(Some("oauth:anthropic:missing"), true);
    assert!(!missing_replace.status.success());
    assert!(!String::from_utf8_lossy(&missing_replace.stdout).contains("Open this URL"));
    assert!(
        String::from_utf8_lossy(&missing_replace.stderr).contains("credential not found"),
        "replace on a nonexistent id must keep the store's established refusal: {}",
        String::from_utf8_lossy(&missing_replace.stderr)
    );
}

/// NOT RUNNABLE AGAINST A STAGED RELEASE ARTIFACT, deliberately on both sides.
///
/// This drives a real `login --provider zai`, which validates the key against the
/// provider's live endpoint. A debug build short-circuits that through
/// `CORTEXKIT_TEST_BYPASS_VALIDATION`; a release build COMPILES THE BYPASS OUT, so the
/// staged binary would attempt a genuine network call and fail.
///
/// Both halves are correct and the conflict is real, so it is skipped under
/// `CRED_CLI_BIN` rather than resolved by weakening either: shipping a validation
/// bypass in a release binary is the worse outcome by a wide margin, and a test that
/// silently passed by reaching a provider would be worse still.
///
/// This is the honest boundary of artifact verification: an arm that depends on a
/// debug-only seam verifies the SOURCE and cannot verify the SHIPPED BYTES. Recorded
/// here so the skip reads as a known limit rather than as flakiness.
#[test]
fn api_key_login_flow_integration() {
    if std::env::var_os(CLI_BIN_ENV).is_some() {
        eprintln!(
            "SKIPPING api_key_login_flow_integration: {CLI_BIN_ENV} is set, and this arm \
             needs the debug-only validation bypass that release builds omit"
        );
        return;
    }
    let root = tmp_root("api-key-login");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .env("CORTEXKIT_TEST_BYPASS_VALIDATION", "1");
    };

    // bootstrap first.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // Create a temp file with a dummy key.
    let key_file = root.join("dummy.key");
    std::fs::write(&key_file, "sk-dummy-key\n").unwrap();

    // Run login --provider zai --payload-file <key_file>
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--no-browser")
        .arg("--payload-file")
        .arg(&key_file);
    global(&mut c);
    let out = c.output().expect("run login");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "login failed: stdout: {}, stderr: {}",
        stdout,
        stderr
    );
    assert!(stdout.contains("logged in and stored apikey:zai"));

    // Verify it is stored by listing.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list");
    let rows = String::from_utf8_lossy(&out.stdout);
    assert!(rows.contains("apikey:zai"));

    // Test that login --id apikey:zai:work passes the id rail
    let key_file2 = root.join("dummy2.key");
    std::fs::write(&key_file2, "sk-dummy-key-2\n").unwrap();
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--no-browser")
        .arg("--id")
        .arg("apikey:zai:work")
        .arg("--payload-file")
        .arg(&key_file2);
    global(&mut c);
    let out = c.output().expect("run login with labeled id");
    assert!(
        out.status.success(),
        "labeled id login failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Test that login --id zai fails the id rail
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--no-browser")
        .arg("--id")
        .arg("zai")
        .arg("--payload-file")
        .arg(&key_file2);
    global(&mut c);
    let out = c.output().expect("run login with invalid id");
    assert!(!out.status.success(), "invalid id login should have failed");
    assert!(String::from_utf8_lossy(&out.stderr).contains("login --id must be"));

    let _ = std::fs::remove_dir_all(&root);
}

/// The rotate verb's HAPPY PATH, end to end through the real binary.
///
/// The crash-cut suite proves the two-slot handover survives a SIGKILL at each cut,
/// but it drives a helper that re-implements the sequence -- parking between steps
/// requires them separated. So the sequence the CLI actually runs (heal, stage,
/// rewrap, promote, in that order) had no test at all: a verb nobody runs casually,
/// because it needs the daemon stopped, and whose first real exercise would be during
/// a key-compromise incident.
///
/// Asserts the four things an operator is relying on when they type it, each of which
/// can fail independently of the printed "rotated master key to ..." line:
///   1. records still decrypt (a rewrap that half-failed prints success too),
///   2. the audit chain still verifies ACROSS the re-seal,
///   3. handles survive, so consumers are not silently cut off,
///   4. a SECOND rotation works on the slot state the first one left behind.
///
/// WHAT PASS 2 DOES NOT PROVE, measured rather than assumed: it does not exercise the
/// heal. Deleting `heal_pending_rotation` leaves this test green, because after a
/// SUCCESSFUL rotation `promote` has already cleared `next`, so the heal is a no-op --
/// it only does work when a PRIOR rotation crashed between rewrap and promote. That
/// state needs a real SIGKILL to produce, and the crash-cut suite's
/// `double-heal-staged` cut is where it is proven. Deleting `promote` also leaves this
/// green, and correctly so: the next rotation's heal recovers exactly that state, which
/// is why the code calls promote hygiene rather than a safety step.
///
/// Recorded because the obvious reading of a two-pass loop is that it covers the
/// second-rotation guards, and it does not.
#[test]
fn the_rotate_verb_leaves_the_vault_usable_and_can_run_twice() {
    let root = tmp_root("rotate-happy");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success());
    assert!(
        run(&["put", "--id", "apikey:one", "--payload", "secret-one"])
            .status
            .success()
    );
    let minted = run(&["mint-handle", "--id", "apikey:one"]);
    assert!(minted.status.success());
    let handle = String::from_utf8_lossy(&minted.stdout).trim().to_string();
    assert!(handle.starts_with("ckh_"), "minted: {handle}");

    for pass in 1..=2 {
        let out = run(&["rotate-master-key"]);
        assert!(
            out.status.success(),
            "rotation {pass} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("rotated master key to key_id"),
            "rotation {pass} printed no new fingerprint"
        );

        // The record must still decrypt UNDER THE NEW KEY. `usable` is the only verb
        // that opens an envelope, so it is the one that can tell a real rewrap from a
        // rotation that reported success and left rows sealed under a key nobody holds.
        let scan = run(&["usable"]);
        let scan_out = String::from_utf8_lossy(&scan.stdout);
        assert!(scan.status.success(), "usable failed after rotation {pass}");
        assert!(
            scan_out.contains("serviceable: 1")
                && scan_out.contains("stranded: 0")
                && scan_out.contains("unreadable: 0"),
            "rotation {pass} left the record unreadable:\n{scan_out}"
        );

        // The chain spans the re-seal: the audit key is stored sealed and re-wrapped
        // with everything else, so a rotation that dropped it would break verification
        // of entries written before it.
        let verified = run(&["verify-audit"]);
        assert!(
            String::from_utf8_lossy(&verified.stdout).contains("intact"),
            "rotation {pass} broke the audit chain"
        );

        // Consumers hold handles and cannot distinguish a revoked one from an unknown
        // one, so a rotation that dropped them would read as an unexplained outage.
        // `revoke-all-handles` reports its count, which is the available proof the row
        // is still there without a live daemon to resolve against.
        let count = run(&["revoke-all-handles", "--id", "apikey:one"]);
        let count_out = String::from_utf8_lossy(&count.stdout);
        assert!(
            count_out.contains("revoked 1 handle"),
            "rotation {pass} lost the pre-rotation handle: {count_out}"
        );
        // Re-mint for the next pass, so pass 2 tests a handle that has itself crossed
        // a rotation.
        assert!(run(&["mint-handle", "--id", "apikey:one"]).status.success());
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// Both binaries report their source revision, and the daemon does it WITHOUT a
/// supervisor.
///
/// `--version` used to print only the package version -- a constant that has not moved
/// in the project's lifetime, so it answered "is this ck-auth" and never "which one".
/// The daemon had no `--version` at all: asking it what it was required starting it,
/// which needs a connection file and a live supervisor, so the identity check depended
/// on the thing being identified already running correctly.
///
/// The daemon arm is the load-bearing one. Its flag is handled before the `--subc`
/// gate, and that ordering is invisible from the code below it: moving argument parsing
/// earlier, or making the gate stricter, would restore the old behaviour with nothing
/// else failing.
#[test]
fn both_binaries_report_a_build_revision_without_a_supervisor() {
    for label in ["ck-auth", "ck-claustrum"] {
        let mut cmd = match label {
            "ck-auth" => cli(),
            _ => std::process::Command::new(env!("CARGO_BIN_EXE_ck-claustrum")),
        };
        let out = cmd
            .arg("--version")
            .output()
            .unwrap_or_else(|e| panic!("run {label} --version: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{label} --version failed: {}{stdout}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.starts_with(label),
            "{label} --version must name the binary: {stdout}"
        );
        // The revision is present as its own field. An unstamped build says `unknown`,
        // which is the honest answer and still proves the field is wired -- the release
        // script is what fills it, and a missing field would read as a stamped build
        // whose revision happened not to print.
        assert!(
            stdout.contains('(') && stdout.contains(')'),
            "{label} --version must carry a revision field: {stdout}"
        );
    }
}

/// `verify-audit` runs against a vault whose lease is HELD, and discriminates.
///
/// It used to go through `open_for_admin`, which takes the single-writer lease, so the
/// tamper-evidence check required stopping the daemon. That is why it had never run on
/// the live store in six weeks: nobody takes the credential vault down for an integrity
/// check, and a mechanism nobody can afford to invoke provides evidence of nothing.
///
/// The lease arm is the load-bearing one. A regression to the lease-taking form would
/// be invisible in every ordinary test -- they all run against an idle vault -- and
/// would only surface when someone tried to verify a live one, which is exactly the
/// situation that never happens.
#[test]
fn verify_audit_reads_a_leased_vault_and_names_a_broken_chain() {
    let root = tmp_root("verify-leased");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success());
    for i in 0..3 {
        assert!(run(&[
            "put",
            "--id",
            &format!("apikey:t{i}"),
            "--payload",
            "secret"
        ])
        .status
        .success());
    }

    // THE ARM THAT MATTERS: hold the single-writer lease, exactly as the running
    // daemon does, and verify anyway.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _lease = open_sqlite(&descriptor).expect("take the lease as the daemon would");

    let held = run(&["verify-audit"]);
    let held_out = String::from_utf8_lossy(&held.stdout);
    assert!(
        held.status.success(),
        "verify-audit must work while the lease is held: {}{}",
        held_out,
        String::from_utf8_lossy(&held.stderr)
    );
    assert!(
        held_out.contains("intact"),
        "expected an intact chain, got: {held_out}"
    );

    // POSITIVE ARM FOR THE DETECTOR. "Intact" is only worth having if the check can
    // say BROKEN -- an implementation that always reported intact would satisfy every
    // assertion above.
    let db = data_dir.join("store.db");
    let conn = rusqlite::Connection::open(&db).expect("open to tamper");
    conn.execute("UPDATE audit_log SET actor = 'tampered' WHERE seq = 2", [])
        .expect("tamper one row");
    drop(conn);

    let broken = run(&["verify-audit"]);
    let stderr = String::from_utf8_lossy(&broken.stderr);
    assert!(
        !broken.status.success(),
        "a tampered chain must fail: {}",
        String::from_utf8_lossy(&broken.stdout)
    );
    assert!(
        stderr.contains("BROKEN at seq 2"),
        "the refusal must name WHERE the chain broke, so an operator knows what to \
         inspect: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `audit` reads a leased vault, and names WHY a row is flagged.
///
/// Two properties, both invisible until an operator needs them.
///
/// It used to take the single-writer lease, so the forensic log was unreadable while
/// the vault ran -- i.e. whenever anyone actually wanted it. Every column is plaintext,
/// so it needs neither the lease nor a master key.
///
/// And it rendered a bare "ALARM" for any flagged row. The alarm column is set on every
/// admin write BY DESIGN, so admin activity is loud: in the production vault 169 of 172
/// flagged rows are ordinary mints and revokes and 3 are the real detection signal.
/// Collapsing both into one word makes the routine 98% read as faults and buries the
/// thing an operator is scanning for.
#[test]
fn audit_reads_a_leased_vault_and_names_the_alarm_reason() {
    let root = tmp_root("audit-leased");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success());
    assert!(run(&["put", "--id", "apikey:one", "--payload", "secret"])
        .status
        .success());

    // Hold the lease exactly as the running daemon does.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _lease = open_sqlite(&descriptor).expect("take the lease as the daemon would");

    let out = run(&["audit"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "audit must read while the lease is held: {}{}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );

    // The put is an admin write, so it is flagged -- and the row must say WHICH kind of
    // flag, not merely that there is one.
    assert!(
        stdout.contains("[admin_write]"),
        "a flagged row must name its reason, so routine admin activity is \
         distinguishable from a detection signal: {stdout}"
    );
    assert!(
        !stdout.contains(" ALARM"),
        "the bare ALARM marker collapses a routine admin write and a real anomaly into \
         one word: {stdout}"
    );
    // POSITIVE ARM: an implementation printing nothing at all would satisfy the
    // assertions above. The row itself has to be there.
    assert!(
        stdout.contains("apikey:one"),
        "the entry for the credential must be listed: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A refused verb must not advise a remedy that does not exist for it.
///
/// `rotate-master-key` and `bootstrap` have no admin op, so they can only run offline.
/// The lease refusal used to advise `--subc` for every verb -- following it lands on
/// the identical error, and an operator reasonably concludes the vault is broken. For
/// rotate that happens DURING A KEY COMPROMISE, which is the worst possible moment to
/// be sent through a door that is not there.
///
/// The two arms are asserted together because the fix is a discrimination, not a
/// wording change: making both say "offline only" would pass the first assertion and
/// break every mutation, which really can be committed through the running daemon.
#[test]
fn a_lease_refusal_advises_only_a_remedy_that_exists_for_that_verb() {
    let root = tmp_root("refusal-remedy");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };
    assert!(run(&["bootstrap"]).status.success());

    // Hold the lease exactly as the running daemon does.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _lease = open_sqlite(&descriptor).expect("take the lease as the daemon would");

    // NO ROUTE PATH: must say so, and must not point at --subc.
    let rotate = run(&["rotate-master-key"]);
    let rotate_err = String::from_utf8_lossy(&rotate.stderr);
    assert!(!rotate.status.success(), "rotate must refuse under a lease");
    assert!(
        rotate_err.contains("no route path"),
        "rotate has no admin op and must say so: {rotate_err}"
    );
    assert!(
        rotate_err.contains("--subc will NOT help"),
        "the refusal must rule out the remedy an operator would otherwise try: \
         {rotate_err}"
    );

    // ROUTE PATH EXISTS: the mutation arm must still offer --subc. Without this, a
    // "fix" that told every verb to go offline would pass the assertions above while
    // removing the zero-downtime path that 11 of 13 write verbs depend on.
    let put = run(&["put", "--id", "apikey:one", "--payload", "secret"]);
    let put_err = String::from_utf8_lossy(&put.stderr);
    assert!(
        !put.status.success(),
        "an offline put must refuse under a lease"
    );
    assert!(
        put_err.contains("--subc <connection-file>"),
        "a mutation CAN be committed through the running daemon, and the refusal must \
         say so: {put_err}"
    );
    assert!(
        !put_err.contains("no route path"),
        "a mutation must not be described as offline-only: {put_err}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `events` discloses that older rows were discarded, rather than presenting a trimmed
/// window as the whole history.
///
/// The per-credential cap is enforced by a silent DELETE, which is right -- an unbounded
/// diagnostic table on a path a hostile consumer can drive is a disk-exhaustion lever.
/// But it leaves a reader unable to tell "this is everything that happened" from "this
/// is what survived", and those close an investigation in opposite directions: the first
/// says the cause is not here, the second says the evidence is gone.
///
/// A peer hit the same shape tonight in a retention job that pruned 125,000 rows and
/// advanced a tamper-evident seal while logging only on error -- a successful first run
/// and a dead worker were indistinguishable.
#[test]
fn events_discloses_that_the_retention_cap_discarded_older_rows() {
    let root = tmp_root("events-cap");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };
    assert!(run(&["bootstrap"]).status.success());

    // NEGATIVE CONTROL, and it must be a credential WITH events but BELOW the cap.
    //
    // My first version used an EMPTY table, and a mutation that always warns survived
    // it: GROUP BY over zero rows returns nothing whatever the HAVING clause says, so
    // the control could not distinguish a correct check from one that fires
    // unconditionally. An empty-input control tests the input, not the predicate.

    // Flood one credential past the cap directly through the store, which is what a
    // consumer looping on report_auth_failure produces.
    {
        let descriptor = StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let raw = open_sqlite(&descriptor).expect("open");
        // bootstrap provisioned the KEY; the schema arrives on first open by the daemon
        // or CLI, so migrate before opening the vault here.
        credentials_core::store::EncryptedStore::migrate(&raw).expect("migrate");
        let key = credentials_core::resolver::resolve(
            &credentials_core::resolver::ResolverConfig {
                data_dir: data_dir.clone(),
                source: credentials_core::resolver::KeySource::OperatorPath {
                    path: key_path.clone(),
                },
            },
            None,
        )
        .expect("resolve");
        let store = credentials_core::store::EncryptedStore::open(raw, key).expect("vault");
        let rec = credentials_core::record::VaultRecord::new_static(
            credentials_core::record::CredentialKind::ApiKey,
            "test",
            b"secret".to_vec(),
            None,
        );
        store.create("apikey:flooded", &rec).expect("seed");
        // The below-cap sibling: it must NOT appear in the notice.
        store
            .create("apikey:quiet", &rec)
            .expect("seed the quiet one");
        for _ in 0..3 {
            store
                .record_auth_event(
                    "apikey:quiet",
                    credentials_core::store::AuthObservation {
                        kind: "consumer_report",
                        provider_status: Some(401),
                        detail: None,
                        reporter_source: None,
                        principal: None,
                    },
                    Some(1),
                )
                .expect("record a below-cap event");
        }
        for _ in 0..(credentials_core::store::AUTH_EVENTS_PER_CREDENTIAL + 5) {
            store
                .record_auth_event(
                    "apikey:flooded",
                    credentials_core::store::AuthObservation {
                        kind: "consumer_report",
                        provider_status: Some(401),
                        detail: None,
                        reporter_source: None,
                        principal: None,
                    },
                    Some(1),
                )
                .expect("record an event");
        }
    }

    let out = run(&["events"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "events must succeed: {stdout}");
    assert!(
        stdout.contains("retention cap"),
        "a credential at the cap must be disclosed, so a trimmed window is not read as \
         the whole history: {stdout}"
    );
    // THE CONTROL THAT DISCRIMINATES: a credential with events but below the cap must
    // NOT be named. A check that fires unconditionally passes every other assertion.
    assert!(
        !stdout.contains("apikey:quiet"),
        "a credential below the cap must not be reported as having lost history -- a \
         notice that names everything tells an operator nothing: {stdout}"
    );
    assert!(
        stdout.contains("apikey:flooded"),
        "the notice must NAME which credential lost history -- 'some rows were \
         discarded' does not tell an operator whether it was the one they are \
         investigating: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `usable` must not promise a refresh that the state makes unreachable.
///
/// An expired access token on an ACTIVE record genuinely does refresh on the next
/// get -- that is the routine state of a healthy credential. On a NEEDS_REAUTH
/// record the same material is inert: `EncryptedStore::get` refuses at the state
/// check, before decrypting and long before the engine could attempt a refresh.
/// There is no next get.
///
/// The old line said "refreshes on next get" for both, which is true of the MATERIAL
/// and false of the RECORD -- and it invites an operator to wait for a recovery that
/// cannot arrive. Live instance: oauth:anthropic:ufuk3 read that way for five hours
/// while three sibling accounts refreshed normally around it.
///
/// Both arms asserted together, because the fix is a discrimination: making every
/// expired row say "unreachable" would satisfy the first assertion and lie about
/// every healthy credential in the vault.
#[test]
fn usable_does_not_promise_a_refresh_the_state_makes_unreachable() {
    let root = tmp_root("usable-unreachable");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };
    assert!(run(&["bootstrap"]).status.success());

    // Two OAuth records with EXPIRED access tokens and live refresh material. They
    // differ only in state, which is the whole point.
    {
        let descriptor = StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let raw = open_sqlite(&descriptor).expect("open");
        credentials_core::store::EncryptedStore::migrate(&raw).expect("migrate");
        let key = credentials_core::resolver::resolve(
            &credentials_core::resolver::ResolverConfig {
                data_dir: data_dir.clone(),
                source: credentials_core::resolver::KeySource::OperatorPath {
                    path: key_path.clone(),
                },
            },
            None,
        )
        .expect("resolve");
        let store = credentials_core::store::EncryptedStore::open(raw, key).expect("vault");

        let expired_at = chrono_now_ms() - 60_000;
        for id in ["oauth:healthy", "oauth:dead"] {
            let rec = credentials_core::record::VaultRecord::new_oauth(
                "test",
                "anthropic",
                credentials_core::oauth::OAuthCredential {
                    access_token: "stale".to_string().into(),
                    refresh_token: "live-refresh-material".to_string().into(),
                    expires_at_ms: Some(expired_at),
                    token_url: "https://example.invalid/token".into(),
                    client_id: None,
                    scopes: Vec::new(),
                },
                b"stale".to_vec(),
            );
            store.create(id, &rec).expect("seed");
        }
        // Only the second is marked dead, exactly as a consumer report would.
        store
            .invalidate_if_version_audited(
                "oauth:dead",
                1,
                credentials_core::audit::AuditCtx::admin(
                    credentials_core::audit::AuditOp::ReportAuthFailure,
                ),
            )
            .expect("mark needs_reauth");
    }

    let out = run(&["usable"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "usable must succeed: {stdout}");

    let dead_line = stdout
        .lines()
        .find(|l| l.contains("oauth:dead"))
        .unwrap_or_else(|| panic!("no line for the dead credential: {stdout}"));
    assert!(
        dead_line.contains("UNREACHABLE"),
        "a needs_reauth record must not promise a refresh that get() refuses before \
         reaching: {dead_line}"
    );

    // THE ARM THAT KEEPS IT HONEST: an active expired record still promises the
    // refresh, because it genuinely happens.
    let healthy_line = stdout
        .lines()
        .find(|l| l.contains("oauth:healthy"))
        .unwrap_or_else(|| panic!("no line for the healthy credential: {stdout}"));
    assert!(
        healthy_line.contains("refreshes on next get"),
        "an ACTIVE expired record is the routine state of a healthy credential and \
         must still say it refreshes: {healthy_line}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}

/// The temp-dir connection file is discovered, and ambiguity refuses rather than guesses.
///
/// subc writes `<temp>/subc-<user-token>.connection.json` when `XDG_RUNTIME_DIR` is
/// unset -- which is STOCK MACOS, so this is the default arrangement there rather
/// than an edge case. A CLI that misses it does not fail loudly: it concludes no
/// daemon is running, takes the offline path, hits the single-writer lease, and
/// tells the operator to STOP THE DAEMON -- naming the one remedy they should not
/// use, while never mentioning the `--subc` route that would have worked. Reported
/// from a real box (claustrum#3).
///
/// Drives the DEFAULT path deliberately: auto-discovery is scoped to a defaulted
/// `--data-dir`, because an explicit vault dir means "this vault" and a discovered
/// daemon may serve a different one. So the probe overrides HOME/XDG_DATA_HOME to
/// move the default derivation into a throwaway tree rather than passing --data-dir,
/// which would disable the very thing under test.
#[test]
fn a_temp_dir_connection_file_is_found_and_ambiguity_refuses() {
    let root = std::env::temp_dir().join(format!(
        "ck-disco-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let tmp = root.join("tmp");
    let home = root.join("home");
    std::fs::create_dir_all(&tmp).expect("tmp");
    std::fs::create_dir_all(&home).expect("home");

    // std::env::temp_dir() reads TMPDIR on unix and TMP/TEMP on Windows, so all
    // three must be set or the probe silently scans the REAL temp dir -- which
    // finds nothing, attempts no route, and fails for a reason that has nothing to
    // do with the code under test.
    let point_at_probe_dirs = |cmd: &mut std::process::Command| {
        cmd.env("TMPDIR", &tmp)
            .env("TMP", &tmp)
            .env("TEMP", &tmp)
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("share"))
            .env_remove("XDG_RUNTIME_DIR");
    };

    // --key-path, NOT CK_MASTER_KEY_PATH: that env var is the DAEMON's override,
    // and parse_global takes the FLAG only. Passing the env var leaves the CLI on
    // the keychain backend, where the outcome depends on whether the platform has a
    // keychain binary at all rather than on discovery. (--key-path is safe here
    // because only an explicit --data-dir disables auto-discovery.)
    let run = |key: Option<&std::path::Path>| -> String {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ck-auth"));
        cmd.arg("list");
        if let Some(k) = key {
            cmd.arg("--key-path").arg(k);
        }
        point_at_probe_dirs(&mut cmd);
        let out = cmd.output().expect("run list");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    // A REAL vault in the default location, so `list` gets past key resolution and
    // the route attempt is reachable. Without this the one-candidate and
    // no-candidate paths produce byte-identical output ("no master key has been
    // provisioned") and the assertion below proves nothing -- measured, not assumed.
    let key_path = root.join("master.key");
    let mut boot = std::process::Command::new(env!("CARGO_BIN_EXE_ck-auth"));
    boot.arg("bootstrap").arg("--key-path").arg(&key_path);
    point_at_probe_dirs(&mut boot);
    let bootstrap = boot.output().expect("bootstrap");
    assert!(
        bootstrap.status.success(),
        "probe vault must bootstrap: {}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );

    // NO candidate: nothing is discovered, so no route is attempted at all.
    let none_found = run(Some(key_path.as_path()));
    assert!(
        !none_found.contains("no live module"),
        "with no connection file anywhere, the CLI must not attempt a route: {none_found}"
    );

    // ONE candidate: discovered, so a route IS attempted -- and fails, because the
    // file is a stub. The attempt is the observable difference, and it is what the
    // temp-dir arm exists to produce.
    // NON-NUMERIC TOKENS, DELIBERATELY. On unix `user_connection_token` is the real
    // uid, so a numeric fixture name lives in the SAME NAMESPACE as a real one: this
    // test used `subc-1000`/`subc-1001` and went green on macOS (uid 501) while
    // failing on the ubuntu runner, whose uid IS one of them -- the CLI matched its
    // own derived name and correctly stopped refusing. A non-numeric token cannot be
    // a uid, so these two are provably other users on every unix host.
    std::fs::write(tmp.join("subc-otheruser.connection.json"), "{}").expect("write one");
    let single = run(Some(key_path.as_path()));
    assert!(
        single.contains("no live module"),
        "one candidate must be DISCOVERED and routed to (the stub then fails, which \
         is the observable proof the arm ran): {single}"
    );
    assert!(
        !single.contains("not guessing which daemon is yours"),
        "exactly one candidate must be used rather than refused: {single}"
    );

    // TWO candidates: refuse and name them. On a shared temp dir the token exists
    // precisely so different OS users do not collide, so two files mean two users --
    // picking one could point an admin op at another user's daemon.
    std::fs::write(tmp.join("subc-thirduser.connection.json"), "{}").expect("write two");
    let ambiguous = run(Some(key_path.as_path()));
    assert!(
        ambiguous.contains("not guessing which daemon is yours"),
        "two candidates must REFUSE rather than pick one: {ambiguous}"
    );
    assert!(
        ambiguous.contains("subc-otheruser.connection.json")
            && ambiguous.contains("subc-thirduser.connection.json"),
        "the refusal must name both so --subc can be chosen: {ambiguous}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `ck auth usable` reports a static record's AGE from the store's plaintext
/// updated_at_ms, end to end against a real store.
///
/// The failure this exists for is a WRONG COLUMN INDEX in the scan's row mapping.
/// `updated_at_ms` and `record_version` are both i64, so reading the wrong one
/// compiles, runs, and renders a plausible-looking age: version 1 read as a
/// millisecond timestamp is 1970, i.e. "written 20000d ago". No unit test on the
/// predicate can see that, because the predicate never touches the query.
///
/// So a record written seconds ago must report 0 days -- a value only the right column
/// can produce.
#[test]
fn usable_reports_a_static_records_age_from_the_stores_own_timestamp() {
    let root = tmp_root("age-probe");
    let data = root.join("vault");
    let key = root.join("master.key");
    std::fs::create_dir_all(&data).expect("data dir");

    let run = |args: &[&str]| -> std::process::Output {
        let mut cmd = cli();
        cmd.args(args)
            .arg("--data-dir")
            .arg(&data)
            .arg("--key-path")
            .arg(&key)
            .output()
            .expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");

    let payload = root.join("p.txt");
    std::fs::write(&payload, "probe-key").expect("payload");
    let put = run(&[
        "put",
        "--id",
        "apikey:age-probe",
        "--payload-file",
        payload.to_str().unwrap(),
    ]);
    assert!(
        put.status.success(),
        "put: {}",
        String::from_utf8_lossy(&put.stderr)
    );

    let out = run(&["usable"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let line = text
        .lines()
        .find(|l| l.contains("apikey:age-probe"))
        .unwrap_or_else(|| panic!("no row for the probe credential in:\n{text}"));

    assert!(
        line.contains("written 0d ago"),
        "a record written seconds ago must report 0 days. Any other number means the \
         scan read the wrong column -- record_version is also i64, and as a millisecond \
         timestamp it lands in 1970. Got: {line}"
    );
}

/// Equal write ages have opposite operational meanings for an API key and a session
/// cookie. The cookie row must make that staleness interpretation visible without
/// inventing a lifetime threshold.
#[test]
fn usable_distinguishes_a_cookie_age_from_an_api_key_age() {
    let root = tmp_root("cookie-usable");
    let data = root.join("vault");
    let key = root.join("master.key");
    std::fs::create_dir_all(&data).expect("data dir");

    let run = |args: &[&str]| -> std::process::Output {
        let mut command = cli();
        command
            .args(args)
            .arg("--data-dir")
            .arg(&data)
            .arg("--key-path")
            .arg(&key)
            .output()
            .expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");
    assert!(
        run(&["put", "--id", "apikey:age-compare", "--payload", "same-age"])
            .status
            .success(),
        "put API key"
    );
    let cookie_file = root.join("cookie.txt");
    std::fs::write(&cookie_file, b"session=same-age; ending=%").expect("write cookie");
    assert!(
        run(&[
            "put",
            "--id",
            "cookie:cursor.com",
            "--payload-file",
            cookie_file.to_str().expect("utf8 path"),
        ])
        .status
        .success(),
        "put cookie"
    );

    let out = run(&["usable"]);
    assert!(
        out.status.success(),
        "usable: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let api = text
        .lines()
        .find(|line| line.contains("apikey:age-compare"))
        .unwrap_or_else(|| panic!("missing API-key row in:\n{text}"));
    let cookie = text
        .lines()
        .find(|line| line.contains("cookie:cursor.com"))
        .unwrap_or_else(|| panic!("missing cookie row in:\n{text}"));

    assert!(
        api.contains("static") && api.contains("written 0d ago"),
        "API-key age is neutral inventory: {api}"
    );
    assert!(
        cookie.contains("cookie")
            && cookie.contains("session cookie")
            && cookie.contains("captured 0d ago")
            && cookie.contains("staleness signal"),
        "cookie age must be rendered as a staleness signal: {cookie}"
    );
    assert_ne!(
        api, cookie,
        "identical ages must render as different credential kinds"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hash_revoke_cli_stops_a_previously_resolving_handle() {
    use credentials_core::resolver::{KeySource, ResolverConfig};
    let vault = GrantCliVault::new("hash-revoke");
    vault.bootstrap();
    assert!(vault
        .run(&["put", "--id", "apikey:hash", "--payload", "secret"])
        .status
        .success());
    let minted = vault.run(&["mint-handle", "--id", "apikey:hash"]);
    assert!(minted.status.success());
    let raw = String::from_utf8(minted.stdout).unwrap().trim().to_owned();
    assert!(String::from_utf8_lossy(&minted.stderr)
        .lines()
        .any(|line| line == format!("revoke with: ck auth revoke-handle --handle {raw}")));
    let hash = credentials_core::store::handle_hash(&raw);
    let open = || {
        let key = credentials_core::resolver::resolve(
            &ResolverConfig {
                data_dir: vault.data_dir.clone(),
                source: KeySource::OperatorPath {
                    path: vault.key_path.clone(),
                },
            },
            None,
        )
        .unwrap();
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: vault
                    .data_dir
                    .join("store.db")
                    .to_string_lossy()
                    .into_owned(),
            },
        })
        .unwrap();
        EncryptedStore::open(sqlite, key).unwrap()
    };
    assert_eq!(open().resolve_handle(&raw).unwrap(), "apikey:hash");
    let revoked = vault.run(&["revoke-handle", "--hash", &hash]);
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    assert!(String::from_utf8_lossy(&revoked.stdout)
        .contains("revoked handle for apikey:hash via --hash"));
    assert!(matches!(
        open().resolve_handle(&raw),
        Err(credentials_core::store::StoreOpError::NotFound)
    ));
    let repeat = vault.run(&["revoke-handle", "--hash", &hash]);
    assert!(repeat.status.success());
    assert!(String::from_utf8_lossy(&repeat.stdout)
        .contains("no live handle matched that value; nothing changed."));
}

#[test]
fn hash_revoke_cli_refuses_ambiguous_missing_and_malformed_forms_before_opening_vault() {
    let vault = GrantCliVault::new("hash-revoke-usage");
    let hash = "a".repeat(64);
    let short = "a".repeat(63);
    let uppercase = "A".repeat(64);
    for args in [
        vec!["revoke-handle", "--handle", "ckh_raw", "--hash", &hash],
        vec!["revoke-handle"],
        vec!["revoke-handle", "--hash", &short],
        vec!["revoke-handle", "--hash", &uppercase],
    ] {
        let out = vault.run(&args);
        assert!(!out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("exactly one of --handle <raw> or --hash <hex> (64 lowercase hex)"),
            "{err}"
        );
        assert!(!vault.data_dir.join("store.db").exists());
        assert!(!vault.key_path.exists());
    }
}

// Check the rendered pages, not their source literals: Rust string continuations can
// silently eat table indentation. Collect violations so a misplaced flag reports both
// the missing table entry and the prose leak in the same run, with the verb named.
#[test]
fn every_verb_help_uses_a_flags_table_and_notes_layout() {
    let output = cli().arg("help").output().expect("top-level help");
    assert!(output.status.success());
    let top = String::from_utf8(output.stdout).expect("UTF-8 help");
    let verbs: Vec<&str> = top
        .lines()
        .skip_while(|line| *line != "verbs:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().next().expect("verb"))
        .collect();
    // This is an anti-narrowing floor for the rendered verb-table scan, not a
    // budget for verbs. It includes the KEM mint ceremony and the approve verb.
    assert_eq!(
        verbs.len(),
        31,
        "the rendered verb-table scan narrowed; set-category and reclassify are public verbs"
    );
    assert!(accepted_help_flags("login").contains(&"--no-browser".to_string()));
    assert!(accepted_help_flags("revoke-handle").contains(&"--hash".to_string()));
    let mut violations = Vec::new();
    // Derive the value-taking globals from the hoister, where the parser defines
    // which flags may precede the verb. Version exits before that parser runs.
    let src = include_str!("../src/bin/credentials_cli.rs");
    let hoisted = src
        .split_once("const GLOBAL_WITH_VALUE:")
        .expect("global hoist definition")
        .1
        .split_once("= [")
        .expect("global hoist array")
        .1
        .split_once("];")
        .expect("global hoist array end")
        .0;
    let mut globals: Vec<&str> = hoisted.split('"').filter(|s| s.starts_with("--")).collect();
    assert_eq!(globals.len(), 3, "global hoist extraction narrowed");
    globals.push("--version");
    let global_table = top
        .split_once("GLOBAL FLAGS\n")
        .map(|(_, rest)| rest.split("\n\n").next().unwrap_or(""))
        .unwrap_or("");
    for flag in globals {
        let count = global_table
            .lines()
            .filter(|line| {
                line.strip_prefix("  ")
                    .and_then(|rest| rest.split_whitespace().next())
                    == Some(flag)
            })
            .count();
        if count != 1 {
            violations.push(format!(
                "top-level: global table must contain {flag} exactly once"
            ));
        }
    }
    for (i, line) in top.lines().enumerate() {
        if line.chars().count() > 80 {
            violations.push(format!("top-level: line {} exceeds 80 columns", i + 1));
        }
    }
    for verb in verbs {
        let output = cli().args(["help", verb]).output().expect("verb help");
        assert!(output.status.success(), "help {verb} failed");
        let page = String::from_utf8(output.stdout).expect("UTF-8 help");
        let lines: Vec<&str> = page.lines().collect();
        if !lines
            .first()
            .is_some_and(|line| line.starts_with(&format!("ck auth {verb}")))
        {
            violations.push(format!("{verb}: (a) missing synopsis"));
        }
        let synopsis_end = lines
            .iter()
            .position(|line| line.is_empty())
            .unwrap_or(lines.len());
        let table_start = synopsis_end + 1;
        let table_end = lines
            .iter()
            .enumerate()
            .skip(table_start)
            .find(|(_, line)| line.is_empty())
            .map(|(i, _)| i)
            .unwrap_or(lines.len());
        let entries: Vec<&str> = lines
            .iter()
            .take(table_end)
            .skip(table_start)
            .filter_map(|line| line.strip_prefix("  --"))
            .filter(|rest| rest.starts_with(|c: char| c.is_ascii_lowercase()))
            .filter_map(|rest| rest.split_whitespace().next())
            .collect();
        let flags = accepted_help_flags(verb);
        if !flags.is_empty() && entries.is_empty() {
            violations.push(format!("{verb}: (b) missing flags table"));
        }
        for flag in &flags {
            if !entries.contains(&flag.trim_start_matches("--")) {
                violations.push(format!("{verb}: (b) missing table entry {flag}"));
            }
        }
        for entry in &entries {
            if !flags.contains(&format!("--{entry}")) {
                violations.push(format!("{verb}: phantom table entry --{entry}"));
            }
        }
        let mut in_notes = false;
        for (i, line) in lines.iter().enumerate() {
            if line.chars().count() > 80 {
                violations.push(format!("{verb}: (c) line {} exceeds 80 columns", i + 1));
            }
            if !line.is_empty() && line.chars().all(|c| c.is_ascii_uppercase() || c == ' ') {
                in_notes = *line == "NOTES";
            }
            // The synopsis (including its continuations) necessarily names flags.
            // Only a real table's indented rows and continuations are exempt below it.
            let in_table =
                i >= table_start && i < table_end && line.starts_with("  ") && !entries.is_empty();
            if i >= synopsis_end
                && !in_table
                && !in_notes
                && line
                    .match_indices(" --")
                    .any(|(at, _)| line[at + 3..].starts_with(|c: char| c.is_ascii_lowercase()))
            {
                violations.push(format!("{verb}: (d) flag outside table/NOTES: {line}"));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn import_help_page_is_byte_exact_with_the_bare_picker_line() {
    let output = cli()
        .args(["help", "import"])
        .output()
        .expect("import help");
    assert!(output.status.success());
    let expected = r#"ck auth import --source <opencode|pi|gemini-cli|antigravity> --id <id>
ck auth import  pick detected accounts to import (no flags)
               [--json <file>] [--provider <entry>] [--adapter <adapter>]
               [--replace]
               [--account-id <id>] [--email <email>] [--org-name <name>]
               [--clear-identity]

  --source <source>    which harness to read
  --id <id>            vault credential id to create
  --json <file>        read that file instead of the source's default path
  --provider <entry>   opencode/pi: pick one auth.json entry; antigravity: pick
                       an account by email or index; not used for gemini-cli
  --adapter <adapter>  override the refresh adapter the method implies
  --replace            overwrite an existing id, keeping its handles; keeps
                       prior identity only when the incoming token belongs to
                       the same account
  --account-id <id>    attach non-secret account metadata; required with email
                       or org-name
  --email <email>      account email metadata
  --org-name <name>    account organization metadata
  --clear-identity     remove non-secret account metadata

SOURCES
  opencode, pi    auth.json. An apikey:<p> id imports a {type:api,key}
                  entry as a static key; an oauth id imports tokens.
  gemini-cli      ~/.gemini/oauth_creds.json, one credential
  antigravity     antigravity-accounts.json, defaults to activeIndex

NOTES
A detectable account mismatch refuses until you pass identity flags to override
or clear it.
"#;
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn category_cli_lists_mutates_reclassifies_and_renders_category_grants() {
    let vault = GrantCliVault::new("category-cli");
    vault.bootstrap();
    let put = vault.run(&["put", "--id", "apikey:zai", "--payload", "secret"]);
    assert!(
        put.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&put.stderr)
    );
    let listed = vault.run(&["list"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.status.success(), "list failed: {stdout}");
    assert!(stdout.contains("CATEGORIES"));
    assert!(stdout.contains("llm-provider"));

    let set = vault.run(&["set-category", "apikey:zai", "--set", "monitoring"]);
    assert!(
        set.status.success(),
        "set-category failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    let listed = vault.run(&["list"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("monitoring"));

    let clear = vault.run(&["set-category", "apikey:zai", "--set", ""]);
    assert!(clear.status.success(), "clear failed");
    let refill = vault.run(&["reclassify", "--from-registry"]);
    assert!(
        refill.status.success(),
        "reclassify failed: {}",
        String::from_utf8_lossy(&refill.stderr)
    );
    let listed = vault.run(&["list"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("llm-provider"));

    let grant = vault.run(&[
        "grant",
        "--principal",
        "reserved:consumer",
        "--selector-kind",
        "category",
        "--selector",
        "llm-provider",
        "--operation",
        "read",
    ]);
    assert!(
        grant.status.success(),
        "category grant failed: {}",
        String::from_utf8_lossy(&grant.stderr)
    );
    let grants = vault.run(&["grants"]);
    let stdout = String::from_utf8_lossy(&grants.stdout);
    assert!(grants.status.success(), "grants failed: {stdout}");
    assert!(stdout.contains("category"));
    assert!(stdout.contains("llm-provider"));
    assert!(!stdout.contains("category:llm-provider"));
}

/// A store one migration behind the binary must still be readable offline.
///
/// *** THE PLACEMENT WINDOW. *** A CLI-only change is placed first and the daemon,
/// which migrates on boot, is restarted later. Between the two every offline `list`
/// meets a store at schema 8, and before this it failed outright with "no such table:
/// credential_categories" -- so the one verb an operator reaches for during a deploy
/// was broken for the whole window.
///
/// BOTH ARMS IN ONE TEST, because the note is only correct if it is CONDITIONAL: an
/// unconditional note would pass the schema-8 arm alone and then tell every operator
/// on a migrated vault that their categories are missing.
#[test]
fn list_reads_a_store_one_migration_behind_and_says_so_on_stderr_only() {
    let vault = GrantCliVault::new("behind-schema");

    // Build the schema-8 store by running the REAL chain up to version 8, so the
    // fixture cannot drift from the migrations it stands in for.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: vault
                .data_dir
                .join("store.db")
                .to_string_lossy()
                .into_owned(),
        },
    };
    {
        let sqlite = open_sqlite(&descriptor).expect("open schema-8 store");
        credentials_core::store::migrate_through_for_test(&sqlite, 8).expect("migrate to 8");
        sqlite
            .with_conn(|conn| {
                for id in ["apikey:behind-one", "apikey:behind-two"] {
                    conn.execute(
                        "INSERT INTO credentials \
                         (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
                         VALUES (?1, 1, '00', 'active', X'00', 0)",
                        rusqlite::params![id],
                    )?;
                }
                Ok(())
            })
            .expect("seed schema-8 rows");
    }

    let behind = vault.run(&["list"]);
    let stdout = String::from_utf8_lossy(&behind.stdout);
    let stderr = String::from_utf8_lossy(&behind.stderr);
    assert!(
        behind.status.success(),
        "list must exit 0 on a store one migration behind: {stderr}"
    );
    assert!(stdout.contains("apikey:behind-one"), "stdout: {stdout}");
    assert!(stdout.contains("apikey:behind-two"), "stdout: {stdout}");
    // The binary's schema comes from `newest_migration_version()` rather than a typed
    // number, so this expectation follows later migrations instead of breaking on them.
    assert_eq!(
        stderr.trim(),
        format!(
            "note: store schema 8 is behind this binary's {}; categories and category grants \
             appear after the daemon restarts (migration 9)",
            credentials_core::store::newest_migration_version()
        ),
        "the note must be verbatim and on stderr"
    );

    // THE POSITIVE CONTROL: the same verb on a migrated store must carry NO note, or
    // the assertion above would pass for a note printed unconditionally.
    let migrated = GrantCliVault::new("behind-schema-migrated");
    migrated.bootstrap();
    let put = migrated.run(&["put", "--id", "apikey:ahead", "--payload", "secret"]);
    assert!(
        put.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&put.stderr)
    );
    let ahead = migrated.run(&["list"]);
    let ahead_stdout = String::from_utf8_lossy(&ahead.stdout);
    let ahead_stderr = String::from_utf8_lossy(&ahead.stderr);
    assert!(ahead.status.success(), "list failed: {ahead_stderr}");
    assert!(
        ahead_stdout.contains("apikey:ahead"),
        "stdout: {ahead_stdout}"
    );
    assert!(
        !ahead_stderr.contains("is behind this binary's"),
        "a migrated store must carry no behind-note: {ahead_stderr}"
    );
}

/// `enroll list` on a store one migration short of proposers still lists its pending
/// requests, shows `-` for the proposer, and says why on stderr only.
#[test]
fn enroll_list_reads_a_store_without_proposers_and_says_so_on_stderr_only() {
    let vault = GrantCliVault::new("enroll-behind-schema");
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: vault
                .data_dir
                .join("store.db")
                .to_string_lossy()
                .into_owned(),
        },
    };
    let behind = credentials_core::store::ENROLLMENT_PROPOSER_SCHEMA_VERSION - 1;
    {
        let sqlite = open_sqlite(&descriptor).expect("open behind store");
        credentials_core::store::migrate_through_for_test(&sqlite, behind)
            .expect("migrate to the schema before proposers");
        sqlite
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO pending_enrollments \
                     (request_id, proposed_name, request_secret_hash, state, created_at_ms, expires_at_ms) \
                     VALUES ('req-behind', 'behind-consumer', ?1, 'pending', 1, 9999999999999)",
                    ["e".repeat(64)],
                )
            })
            .expect("seed a pending row");
    }

    let out = vault.run(&["enroll", "list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "enroll list failed: {stderr}");
    let row = stdout
        .lines()
        .find(|line| line.starts_with("req-behind "))
        .unwrap_or_else(|| panic!("pending row missing: {stdout}"));
    assert_eq!(
        row.split_whitespace().collect::<Vec<_>>(),
        ["req-behind", "pending", "-", "behind-consumer"],
        "{stdout}"
    );
    assert_eq!(
        stderr.trim(),
        format!(
            "note: store schema {behind} is behind this binary's {}; proposers of pending \
             requests appear after the daemon restarts (migration {})",
            credentials_core::store::newest_migration_version(),
            credentials_core::store::ENROLLMENT_PROPOSER_SCHEMA_VERSION
        ),
        "the note must be verbatim and on stderr"
    );
}
