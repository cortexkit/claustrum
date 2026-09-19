#![cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64")
))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use credentials_core::test_support::TestTempDir;

const TAG: &str = "v0.1.2";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const ASSET: &str = "ck-auth-darwin-arm64.zip";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ASSET: &str = "ck-auth-linux-x64.zip";

fn assert_ok(label: &str, output: Output) -> Output {
    assert!(
        output.status.success(),
        "{label} failed (rc {:?})\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn current_cli(data_dir: &Path, key_path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ck-auth"))
        .args(args)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--key-path")
        .arg(key_path)
        .output()
        .expect("run current ck-auth")
}

fn released_cli(binary: &Path, data_dir: &Path, key_path: &Path, verb: &str) -> Output {
    Command::new(binary)
        .arg(verb)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--key-path")
        .arg(key_path)
        .output()
        .unwrap_or_else(|error| panic!("execute released {TAG} artifact: {error}"))
}

fn download_release(root: &Path) -> PathBuf {
    let archive = root.join(ASSET);
    let sidecar = root.join(format!("{ASSET}.sha256"));
    let base = format!("https://github.com/cortexkit/claustrum/releases/download/{TAG}");
    assert_ok(
        "download released artifact",
        Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error"])
            .arg(format!("{base}/{ASSET}"))
            .args(["--output"])
            .arg(&archive)
            .output()
            .expect("run curl for artifact"),
    );
    assert_ok(
        "download release checksum",
        Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error"])
            .arg(format!("{base}/{ASSET}.sha256"))
            .args(["--output"])
            .arg(&sidecar)
            .output()
            .expect("run curl for checksum"),
    );
    assert_ok(
        "verify published sidecar",
        Command::new("shasum")
            .args(["-a", "256", "-c"])
            .arg(&sidecar)
            .current_dir(root)
            .output()
            .expect("run shasum"),
    );
    assert_ok(
        "unpack released artifact",
        Command::new("unzip")
            .args(["-q", "-o"])
            .arg(&archive)
            .arg("-d")
            .arg(root)
            .output()
            .expect("run unzip"),
    );
    let binary = root.join("ck-auth");
    assert!(binary.is_file(), "released archive did not contain ck-auth");
    binary
}

/// What an operator can still READ with an older artifact against a store this
/// binary has migrated. Not whether they can run on it: the question this answers is
/// inspection, verb by verb.
///
/// Runs only as its own gate arm: it downloads the published v0.1.2 artifact from
/// GitHub, so inside the workspace suite an offline machine would read a network
/// failure as a test regression. The arm fails loudly rather than skipping.
///
/// *** THE THREE REFUSALS BELOW ARE THE CORRECT OUTCOME, NOT A REGRESSION TOLERATED
/// BECAUSE IT WAS AWKWARD TO FIX. *** Migration 10 renamed `read_grants`'s selector
/// column, and that artifact's `read_grants` query names the old one, so every verb
/// that reads the grant table refuses. Keeping a compatibility column would make all
/// three render again -- and render a WRONG ANSWER ABOUT AUTHORIZATION REACH. That
/// artifact's query carries no `selector_kind` column, because the kind did not exist
/// when it shipped, so it would print
///
///     reserved:consumer   operator:compat   read
///
/// which an operator reads as a PREFIX: everything beginning `operator:compat`. After
/// migration 10 that row is an id selector reaching exactly one credential, and
/// nothing in the old binary's output can tell the two apart. A confident, readable,
/// wrong statement about who can read what -- on the surface an operator consults
/// while auditing reach during an incident -- is worse than a refusal naming a column.
/// So do not "repair" this by reinstating the column.
#[test]
#[ignore = "downloads the released v0.1.2 artifact; run explicitly or as the release-compat gate arm"]
fn v012_release_artifact_reads_what_migration_10_did_not_rename() {
    let root = TestTempDir::new(format!("v012-compat-{}", std::process::id()));
    let artifact_dir = root.join("artifact");
    let data_dir = root.join("vault");
    let key_path = root.join("master.key");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    let released = download_release(&artifact_dir);

    assert_ok(
        "bootstrap migration-N store",
        current_cli(&data_dir, &key_path, &["bootstrap"]),
    );
    assert_ok(
        "deposit fixture",
        current_cli(
            &data_dir,
            &key_path,
            &["put", "--id", "operator:compat", "--payload", "secret"],
        ),
    );
    assert_ok(
        "write migration-N selector row",
        current_cli(
            &data_dir,
            &key_path,
            &[
                "grant",
                "--principal",
                "consumer",
                "--selector-kind",
                "exact",
                "--selector",
                "operator:compat",
                "--operation",
                "read",
            ],
        ),
    );

    // The chain is verified over serialized rows and branches on no op vocabulary and
    // no table this migration touched, so this property survives every migration.
    let verify = assert_ok(
        "v0.1.2 verify-audit on a migration-10 store",
        released_cli(&released, &data_dir, &key_path, "verify-audit"),
    );
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("intact"),
        "verify-audit must still report the chain intact: {}",
        String::from_utf8_lossy(&verify.stdout)
    );

    // Inspection that survives, with the row each verb must actually produce: an arm
    // asserting only rc 0 would pass on a binary that printed nothing.
    let audit = assert_ok(
        "v0.1.2 audit on a migration-10 store",
        released_cli(&released, &data_dir, &key_path, "audit"),
    );
    let audit_stdout = String::from_utf8_lossy(&audit.stdout);
    assert!(
        audit_stdout.contains("put operator:compat"),
        "the deposit row must still render: {audit_stdout}"
    );
    assert!(
        audit_stdout.contains("grant:read:reserved:consumer:exact|operator:compat"),
        "an audit target carrying the new selector vocabulary is passed through          verbatim rather than rejected: {audit_stdout}"
    );
    assert_ok(
        "v0.1.2 events on a migration-10 store",
        released_cli(&released, &data_dir, &key_path, "events"),
    );
    let usable = assert_ok(
        "v0.1.2 usable on a migration-10 store",
        released_cli(&released, &data_dir, &key_path, "usable"),
    );
    assert!(
        String::from_utf8_lossy(&usable.stdout).contains("operator:compat"),
        "the credential must still be listed as serviceable: {}",
        String::from_utf8_lossy(&usable.stdout)
    );

    // Every verb whose lease-free path reads the grant table. `list` is in this set
    // and it is easy to miss: it renders an inventory, and its grant read is not
    // visible in what it prints when it succeeds.
    for verb in ["list", "grants", "status"] {
        let refused = released_cli(&released, &data_dir, &key_path, verb);
        assert!(
            !refused.status.success(),
            "{verb} cannot read the renamed selector column, so it must refuse rather              than render: {}",
            String::from_utf8_lossy(&refused.stdout)
        );
        // Assert the REASON, not just the failure: a non-zero exit is also what a
        // crash, a missing store and a permission error produce.
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("no such column: credential_prefix"),
            "{verb} must refuse by naming the column it cannot find, so an operator              reads a schema difference rather than a broken vault: {stderr}"
        );
    }
}
