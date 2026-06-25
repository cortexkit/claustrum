#![forbid(unsafe_code)]

//! Real-daemon supervision proof for the credential vault (part of the §13 ship
//! gate).
//!
//! The STANDALONE `subc-core` binary reads a `subc.jsonc` that marks the vault
//! module `reserved: true` and configures a sqlite storage section, spawns +
//! supervises `credentials-module` as a child it owns (injecting `SUBC_MODULE_ID`
//! and the one-time `SUBC_LAUNCH_NONCE` the reserved module echoes), and we drive
//! `credential.get` end-to-end against a credential the admin CLI seeded.
//!
//! Setup uses the real `credentials-cli` binary to bootstrap a master key (an
//! operator key path OUTSIDE the data tree), put a credential, and mint a handle —
//! exactly the operator flow — then the daemon serves a read for that handle. This
//! proves the whole stack: reserved-module launch-nonce registration, the boot
//! gate (resolve key → migrate → reconcile → serve), handle resolution, and the
//! read surface, through a real supervising daemon.
//!
//! `#[ignore]` by default: it builds `subc-core` in the sibling repo and binds
//! loopback ports. Run with
//! `cargo test -p credentials-module --test real_daemon_e2e -- --ignored --nocapture`.

mod common;

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::process::{Child, Command};

use common::{
    connect_consumer, count_alarm_rows, credential_get, credential_get_many, raw_route_request,
    route_open, unique_temp_dir, wait_for_catalog, MODULE_ID, SETUP_TIMEOUT,
};

const SUBCONSCIOUS_REL: &str = "../../../subconscious";

/// A real `subc-core` daemon process plus its isolated rig dir; killed on drop.
struct RealDaemon {
    child: Child,
    rig: PathBuf,
    connection_file: PathBuf,
}

impl Drop for RealDaemon {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.rig);
    }
}

fn subconscious_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SUBCONSCIOUS_REL)
        .canonicalize()
        .expect("sibling ../subconscious repo must exist for the real-daemon test")
}

fn build_subc_core() -> PathBuf {
    let root = subconscious_root();
    let status = std::process::Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--bin", "subc-core"])
        .status()
        .expect("run cargo build for subc-core");
    assert!(status.success(), "building subc-core failed");
    let bin = root.join("target/debug/subc-core");
    assert!(
        bin.exists(),
        "subc-core binary missing at {}",
        bin.display()
    );
    bin
}

/// Run the admin CLI with the given args; panics with stderr on failure. Returns
/// stdout.
fn run_cli(args: &[&str]) -> String {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_credentials-cli"));
    let out = std::process::Command::new(&bin)
        .args(args)
        .output()
        .expect("run credentials-cli");
    assert!(
        out.status.success(),
        "credentials-cli {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The seeded credential's handle and the rig, returned so the test can drive a get.
struct SeededVault {
    daemon: RealDaemon,
    handle: String,
    payload: Vec<u8>,
    /// The vault's sqlite path, for reading durable audit/alarm rows AFTER the
    /// daemon is stopped (it holds the single-writer lease while alive).
    db_path: PathBuf,
}

impl SeededVault {
    /// Stop the supervising daemon (and its child module), releasing the vault's
    /// single-writer lease so the audit_log can be read directly. Waits for the
    /// child to exit so the lease is actually free.
    async fn stop_daemon(&mut self) {
        let _ = self.daemon.child.start_kill();
        let _ = self.daemon.child.wait().await;
        // Give the OS a moment to release the advisory lease the killed tree held.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Bootstrap + seed a vault via the CLI, then spawn a real subc-core supervising the
/// reserved vault module against it.
async fn start_seeded_vault() -> SeededVault {
    let subc_core = build_subc_core();
    let credentials_module = PathBuf::from(env!("CARGO_BIN_EXE_credentials-module"));
    assert!(credentials_module.exists());

    let rig = unique_temp_dir("cred-real-daemon");
    let config_dir = rig.join("config/cortexkit");
    let runtime_dir = rig.join("runtime");
    let data_home = rig.join("data");
    let secrets_dir = rig.join("secrets");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_home).unwrap();
    std::fs::create_dir_all(&secrets_dir).unwrap();

    // subc resolves storage to <data_home>/cortexkit/<module_id>/store.db; the CLI
    // must seed into that SAME data dir. The operator key path lives OUTSIDE it.
    let data_dir = data_home.join("cortexkit").join(MODULE_ID);
    std::fs::create_dir_all(&data_dir).unwrap();
    let key_path = secrets_dir.join("master.key");

    let data_dir_s = data_dir.to_string_lossy().to_string();
    let key_path_s = key_path.to_string_lossy().to_string();

    // Bootstrap a master key, put an api-key credential, mint a handle (the operator
    // flow). The handle's raw value is the CLI's stdout.
    run_cli(&[
        "bootstrap",
        "--data-dir",
        &data_dir_s,
        "--key-path",
        &key_path_s,
    ]);
    run_cli(&[
        "put",
        "--id",
        "operator:test",
        "--payload",
        "the-secret-bytes",
        "--data-dir",
        &data_dir_s,
        "--key-path",
        &key_path_s,
    ]);
    let handle = run_cli(&[
        "mint-handle",
        "--id",
        "operator:test",
        "--data-dir",
        &data_dir_s,
        "--key-path",
        &key_path_s,
    ]);
    assert!(handle.starts_with("ckh_"), "minted handle: {handle}");

    // The subc.jsonc: a storage section + the vault module marked reserved, with the
    // operator key path passed via env so the daemon resolves the same key the CLI
    // provisioned.
    let subc_jsonc = serde_json::json!({
        "version": 1,
        "storage": { "backend": "sqlite", "data_home": data_home },
        "modules": {
            MODULE_ID: {
                "program": credentials_module,
                "args": [],
                "reserved": true,
                "env": { "CK_MASTER_KEY_PATH": key_path }
            }
        }
    });
    std::fs::write(
        config_dir.join("subc.jsonc"),
        serde_json::to_vec_pretty(&subc_jsonc).unwrap(),
    )
    .unwrap();

    let child = Command::new(&subc_core)
        .env("XDG_CONFIG_HOME", rig.join("config"))
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("XDG_DATA_HOME", &data_home)
        .env("SUBC_PORT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn real subc-core daemon");

    let connection_file = runtime_dir.join("subc-connection.json");
    let deadline = tokio::time::Instant::now() + SETUP_TIMEOUT;
    while !connection_file.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "daemon did not publish a connection file within {SETUP_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    SeededVault {
        daemon: RealDaemon {
            child,
            rig,
            connection_file,
        },
        handle,
        payload: b"the-secret-bytes".to_vec(),
        db_path: data_dir.join("store.db"),
    }
}

/// The full supervision proof: a real subc-core supervises the reserved vault
/// module, it boots through the gate and registers, and credential.get on a minted
/// handle returns the seeded payload end-to-end.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_subc_core_supervises_vault_and_serves_credential_get() {
    let seeded = start_seeded_vault().await;
    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;

    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;

    let project_root = unique_temp_dir("cred-real-daemon-project");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;

    let response = credential_get(&mut consumer, route_channel, 2, &seeded.handle).await;
    let result = &response["result"];
    let payload = result["payload"]
        .as_array()
        .expect("credential.get must return a payload byte array");
    let bytes: Vec<u8> = payload.iter().map(|v| v.as_u64().unwrap() as u8).collect();
    assert_eq!(
        bytes, seeded.payload,
        "served the seeded credential payload"
    );

    let _ = std::fs::remove_dir_all(&project_root);
}

/// An UNKNOWN handle returns a fail-closed not_found (no enumeration), through the
/// real daemon.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_daemon_unknown_handle_is_not_found() {
    let seeded = start_seeded_vault().await;
    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;

    let project_root = unique_temp_dir("cred-real-daemon-unknown");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;

    let response = credential_get(&mut consumer, route_channel, 2, "ckh_unknown_handle").await;
    assert_eq!(
        response["result"]["error"]["code"], "not_found",
        "an unknown handle is a uniform not_found"
    );

    let _ = std::fs::remove_dir_all(&project_root);
}

/// Malicious-local-client, on the wire: an over-cap `get_many` is REJECTED (not
/// truncated) by the live daemon over the real connection file.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_daemon_over_cap_get_many_is_rejected() {
    let seeded = start_seeded_vault().await;
    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;

    let project_root = unique_temp_dir("cred-real-daemon-overcap");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;

    // 9 handles in one get_many exceeds the cap of 8: the whole call is rejected
    // with too_many_items, NOT silently truncated to 8.
    let handles: Vec<&str> = (0..9).map(|_| "ckh_whatever").collect();
    let response = credential_get_many(&mut consumer, route_channel, 2, &handles).await;
    let results = response["results"].as_array().expect("results array");
    assert_eq!(
        results.len(),
        1,
        "over-cap returns a single error, not 9 outcomes"
    );
    assert_eq!(
        results[0]["error"]["code"], "too_many_items",
        "over-cap get_many is rejected, not truncated"
    );

    let _ = std::fs::remove_dir_all(&project_root);
}

/// Malicious-local-client, on the wire: a connection that sweeps many distinct
/// credentials fast trips the fetch-rate anomaly detector, which raises a DURABLE
/// audit alarm row — asserted by reading the audit_log after stopping the daemon.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_daemon_fetch_sweep_raises_durable_alarm() {
    let mut seeded = start_seeded_vault().await;
    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;

    let project_root = unique_temp_dir("cred-real-daemon-sweep");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;

    // Sweep many DISTINCT handles fast (the default distinct ceiling is 16). Each is
    // unknown (resolves not_found), but the fetch-rate detector keys on the spread of
    // distinct credential probes on this connection, so > ceiling distinct probes
    // trips the anomaly. The handles must be distinct so the DISTINCT spread climbs.
    for i in 0..40u32 {
        let handle = format!("ckh_sweep_{i}");
        let _ = credential_get(&mut consumer, route_channel, 100 + i as u64, &handle).await;
    }

    // Stop the daemon to release the lease, then read the durable alarm rows.
    seeded.stop_daemon().await;
    let alarms = count_alarm_rows(&seeded.db_path, "fetch_rate_anomaly");
    assert!(
        alarms >= 1,
        "a fetch sweep over the ceiling must raise at least one durable fetch_rate_anomaly alarm row, got {alarms}"
    );

    let _ = std::fs::remove_dir_all(&project_root);
}

/// Malicious-local-client, on the wire: a malformed route request (not a valid
/// method envelope) is answered with a typed wire error, never crashing the daemon
/// (a later valid request still succeeds on a fresh connection).
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_daemon_malformed_request_is_typed_error_not_crash() {
    let seeded = start_seeded_vault().await;
    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;

    let project_root = unique_temp_dir("cred-real-daemon-malformed");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;

    // An unknown method is a typed wire error, not a panic/disconnect.
    let frame = common::raw_route_frame(
        &mut consumer,
        route_channel,
        2,
        serde_json::json!({ "method": "credential.delete_everything", "params": {} }),
    )
    .await;
    assert_eq!(
        frame.header.ty,
        subc_protocol::FrameType::Error,
        "unknown method => typed wire error"
    );

    // The daemon is still alive: a valid status request still succeeds.
    let response = raw_route_request(
        &mut consumer,
        route_channel,
        3,
        serde_json::json!({ "method": "credential.status", "params": {} }),
    )
    .await;
    assert_eq!(
        response["result"]["ready"], true,
        "daemon still serving after malformed input"
    );

    let _ = std::fs::remove_dir_all(&project_root);
}
