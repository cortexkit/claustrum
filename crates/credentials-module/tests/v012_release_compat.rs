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

#[test]
fn v012_release_artifact_reads_migration_n_without_a_read_write_open() {
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
                "prefix",
                "--selector",
                "operator:",
                "--operation",
                "read",
            ],
        ),
    );

    let verify = assert_ok(
        "v0.1.2 verify-audit on migration-N store",
        released_cli(&released, &data_dir, &key_path, "verify-audit"),
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("intact"));
    let grants = assert_ok(
        "v0.1.2 grants on migration-N store",
        released_cli(&released, &data_dir, &key_path, "grants"),
    );
    assert!(String::from_utf8_lossy(&grants.stdout).contains("operator:"));
}
