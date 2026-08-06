#![forbid(unsafe_code)]

//! Real-daemon supervision proof for the credential vault (part of the §13 ship
//! gate).
//!
//! The STANDALONE `ck-subc` daemon binary (package subc-core) reads a `subc.jsonc` that marks the vault
//! module `reserved: true` and configures a sqlite storage section, spawns +
//! supervises `credentials-module` as a child it owns (injecting `SUBC_MODULE_ID`
//! and the one-time `SUBC_LAUNCH_NONCE` the reserved module echoes), and we drive
//! `credential.get` end-to-end against a credential the admin CLI seeded.
//!
//! Setup uses the real `ck-auth` binary to bootstrap a master key (an
//! operator key path OUTSIDE the data tree), put a credential, and mint a handle —
//! exactly the operator flow — then the daemon serves a read for that handle. This
//! proves the whole stack: reserved-module launch-nonce registration, the boot
//! gate (resolve key → migrate → reconcile → serve), handle resolution, and the
//! read surface, through a real supervising daemon.
//!
//! `#[ignore]` by default: it builds the `ck-subc` daemon in the sibling repo and binds
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

/// A real `ck-subc` daemon process plus its isolated rig dir; killed on drop.
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

/// The anti-masking environment switch. When set (CI sets `CRED_REQUIRE_DAEMON=1`),
/// a missing or unbuildable sibling subc-core is a HARD FAILURE, not a silent skip —
/// so a real-daemon ship-gate test can never silently zero-out in CI (e.g. if the
/// sibling checkout or the subc-core build breaks, CI must go red, not green-by-skip).
/// Unset (a local run without the sibling), the e2e gracefully skips.
const REQUIRE_DAEMON_ENV: &str = "CRED_REQUIRE_DAEMON";

fn require_daemon() -> bool {
    std::env::var_os(REQUIRE_DAEMON_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// Resolve the sibling subconscious checkout, or `None` if it is not present.
/// `None` + `REQUIRE_DAEMON_ENV` set ⇒ panic (CI must not skip silently).
fn subconscious_root() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(SUBCONSCIOUS_REL);
    match path.canonicalize() {
        Ok(root) => Some(root),
        Err(e) => {
            if require_daemon() {
                panic!(
                    "{REQUIRE_DAEMON_ENV} is set but the sibling subconscious checkout is \
                     missing at {} ({e}) — the real-daemon ship-gate test must not be skipped",
                    path.display()
                );
            }
            None
        }
    }
}

/// Build the subc daemon in the sibling and return its binary path, or `None` to
/// skip. A build failure with `REQUIRE_DAEMON_ENV` set is a hard panic (no silent
/// skip). The daemon EXE is `ck-subc` (fleet ck-* naming; the PACKAGE stays
/// subc-core) — building by explicit bin name also guards against silently running
/// a stale binary left under the old name in the sibling's target dir.
fn build_subc_core() -> Option<PathBuf> {
    let root = subconscious_root()?;
    let status = std::process::Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--bin", "ck-subc"])
        .status()
        .expect("run cargo build for ck-subc");
    if !status.success() {
        if require_daemon() {
            panic!("{REQUIRE_DAEMON_ENV} is set but building ck-subc failed");
        }
        return None;
    }
    let bin = root.join("target/debug/ck-subc");
    assert!(bin.exists(), "ck-subc binary missing at {}", bin.display());
    Some(bin)
}

/// Run the admin CLI with the given args; panics with stderr on failure. Returns
/// stdout.
fn run_cli(args: &[&str]) -> String {
    let out = run_cli_raw(args);
    assert!(
        out.status.success(),
        "ck-auth {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Run the admin CLI without asserting success — for tests that need to inspect the
/// exit code / stderr (e.g. the offline path refusing while the daemon is up).
fn run_cli_raw(args: &[&str]) -> std::process::Output {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ck-auth"));
    std::process::Command::new(&bin)
        .args(args)
        .output()
        .expect("run ck-auth")
}

/// The seeded credential's handle and the rig, returned so the test can drive a get.
struct SeededVault {
    daemon: RealDaemon,
    handle: String,
    payload: Vec<u8>,
    /// The vault's sqlite path, for reading durable audit/alarm rows AFTER the
    /// daemon is stopped (it holds the single-writer lease while alive).
    db_path: PathBuf,
    /// The seeded credential id, for admin-path ops that name it.
    credential_id: String,
    /// The data dir + operator key path, so a test can run admin CLI ops (offline or
    /// via `--subc`) against the same vault the daemon supervises.
    data_dir: String,
    key_path: String,
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
/// reserved vault module against it. Returns `None` when the sibling subc-core is
/// unavailable AND the run is not requiring the daemon (a graceful local skip); the
/// anti-masking guard inside `build_subc_core` panics instead when
/// `CRED_REQUIRE_DAEMON` is set, so CI can never skip silently.
async fn start_seeded_vault() -> Option<SeededVault> {
    // Default seeding: the operator `put`s a static api-key credential.
    start_vault_with_seed(|ctx| {
        run_cli(&[
            "put",
            "--id",
            "operator:test",
            "--payload",
            "the-secret-bytes",
            "--data-dir",
            &ctx.data_dir,
            "--key-path",
            &ctx.key_path,
        ]);
        ("operator:test".to_string(), b"the-secret-bytes".to_vec())
    })
    .await
}

/// The operator-flow context handed to a seed closure: the resolved data dir and
/// operator key path (as strings, ready for CLI args). The closure runs the
/// credential-seeding CLI commands (put / import) and returns the credential id it
/// seeded plus the plaintext bytes a `credential.get` should return for it.
struct SeedCtx {
    data_dir: String,
    key_path: String,
}

/// Bootstrap a throwaway master key, run a caller-supplied seeding step (put or
/// import), mint a handle for the seeded credential, then spawn a real subc-core
/// supervising the reserved vault against it. This shared setup is used by both the
/// default `put` flow and the `import --source opencode` test, so neither duplicates
/// the harness.
async fn start_vault_with_seed<F>(seed: F) -> Option<SeededVault>
where
    F: FnOnce(&SeedCtx) -> (String, Vec<u8>),
{
    let subc_core = build_subc_core()?;
    let credentials_module = PathBuf::from(env!("CARGO_BIN_EXE_ck-credentials"));
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

    // Bootstrap a master key, run the caller's seeding step, mint a handle for the
    // seeded credential (the operator flow). The handle's raw value is the CLI stdout.
    run_cli(&[
        "bootstrap",
        "--data-dir",
        &data_dir_s,
        "--key-path",
        &key_path_s,
    ]);
    let (credential_id, payload) = seed(&SeedCtx {
        data_dir: data_dir_s.clone(),
        key_path: key_path_s.clone(),
    });
    let handle = run_cli(&[
        "mint-handle",
        "--id",
        &credential_id,
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

    Some(SeededVault {
        daemon: RealDaemon {
            child,
            rig,
            connection_file,
        },
        handle,
        payload,
        db_path: data_dir.join("store.db"),
        credential_id,
        data_dir: data_dir_s,
        key_path: key_path_s,
    })
}

/// Start a seeded vault or, when the sibling subc-core is unavailable in a non-CI
/// run, return `None` so the test skips gracefully. A macro so the `return` exits
/// the calling test.
macro_rules! seeded_or_skip {
    () => {
        match start_seeded_vault().await {
            Some(v) => v,
            None => {
                eprintln!("skipping real-daemon e2e: sibling subc-core unavailable (set CRED_REQUIRE_DAEMON=1 to require it)");
                return;
            }
        }
    };
}

/// The full supervision proof: a real subc-core supervises the reserved vault
/// module, it boots through the gate and registers, and credential.get on a minted
/// handle returns the seeded payload end-to-end.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_subc_core_supervises_vault_and_serves_credential_get() {
    let seeded = seeded_or_skip!();
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

/// The module-driven admin path end-to-end: while the daemon holds the lease, the
/// OFFLINE CLI access is refused (DaemonRunning, exit 3), while `list --subc` and
/// the same write with `--subc` succeed through the running module (master-key
/// challenge-response over the route plane). The write is then observable via a live
/// `credential.get`.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_daemon_admin_op_over_route_while_offline_refused() {
    let seeded = seeded_or_skip!();
    let conn = seeded.daemon.connection_file.to_string_lossy().to_string();

    // Wait until the vault module is catalog-live BEFORE asserting the offline
    // refusal: the single-writer lease is taken during the module's boot (after the
    // daemon publishes its connection file), so a check that races boot could catch
    // the lease still free. Catalog-live proves the module booted and holds it.
    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;

    // 1) The online list uses authenticated admin.status rather than trying to open
    //    the database itself. If cmd_list regresses to open_for_admin this command exits
    //    3 while the daemon owns the lease, so this is a non-vacuous route-path proof.
    let listed = run_cli(&[
        "list",
        "--data-dir",
        &seeded.data_dir,
        "--key-path",
        &seeded.key_path,
        "--subc",
        &conn,
    ]);
    assert!(
        listed.contains("active") && listed.contains(&seeded.credential_id),
        "online list must print the seeded inventory row, got: {listed}"
    );
    assert!(
        !listed.contains("vault:"),
        "list must retain compact inventory-only output, got: {listed}"
    );

    // 2) The offline path is structurally refused while the daemon holds the lease:
    //    it cannot take the single-writer lease. Exit code 3 (DaemonRunning).
    let offline = run_cli_raw(&[
        "mint-handle",
        "--id",
        &seeded.credential_id,
        "--data-dir",
        &seeded.data_dir,
        "--key-path",
        &seeded.key_path,
    ]);
    assert_eq!(
        offline.status.code(),
        Some(3),
        "offline admin write must be refused (DaemonRunning) while the daemon holds the lease; stderr: {}",
        String::from_utf8_lossy(&offline.stderr)
    );

    // 3) The SAME op with --subc commits through the running module. This exercises
    //    the whole authenticated admin path: direct-principal bind, admin.challenge,
    //    keychain/operator-key resolution by the returned key_id, the op-body MAC,
    //    admin.op, and the fenced+audited store write — with zero downtime.
    let minted = run_cli(&[
        "mint-handle",
        "--id",
        &seeded.credential_id,
        "--data-dir",
        &seeded.data_dir,
        "--key-path",
        &seeded.key_path,
        "--subc",
        &conn,
    ]);
    assert!(
        minted.starts_with("ckh_"),
        "route-committed mint-handle returns a fresh handle, got: {minted}"
    );

    // 4) The route-minted handle is REAL: a live credential.get resolves it to the
    //    seeded payload, proving the write landed in the daemon's own store. Reuse
    //    the consumer connection opened above (already catalog-confirmed).
    let project_root = unique_temp_dir("cred-real-daemon-admin");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;
    let response = credential_get(&mut consumer, route_channel, 2, &minted).await;
    let payload = response["result"]["payload"]
        .as_array()
        .expect("the route-minted handle resolves to a payload");
    let bytes: Vec<u8> = payload.iter().map(|v| v.as_u64().unwrap() as u8).collect();
    assert_eq!(
        bytes, seeded.payload,
        "the route-minted handle serves the seeded credential"
    );

    let _ = std::fs::remove_dir_all(&project_root);
}

/// An UNKNOWN handle returns a fail-closed not_found (no enumeration), through the
/// real daemon.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_daemon_unknown_handle_is_not_found() {
    let seeded = seeded_or_skip!();
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
    let seeded = seeded_or_skip!();
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
    let mut seeded = seeded_or_skip!();
    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;

    let project_root = unique_temp_dir("cred-real-daemon-sweep");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;

    // NEGATIVE CONTROL, on a SEPARATE CONNECTION: a handful of probes is under the
    // distinct ceiling and must raise nothing. The limiter is connection-scoped and
    // alarms once per flagged connection, so this only discriminates from its own
    // connection — probing here on the sweeping one would be masked by that single
    // alarm. Without it, `alarms >= 1` below is equally satisfied by a limiter that
    // flags EVERY probe, which is a permanently-firing detector rather than a working
    // one and looks identical from the sweep alone.
    let mut quiet = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut quiet, MODULE_ID, SETUP_TIMEOUT).await;
    let quiet_root = unique_temp_dir("cred-real-daemon-sweep-quiet");
    std::fs::create_dir_all(&quiet_root).unwrap();
    let quiet_channel = route_open(&mut quiet, &quiet_root, 1).await;
    for i in 0..4u32 {
        let handle = format!("ckh_quiet_{i}");
        let _ = credential_get(&mut quiet, quiet_channel, 900 + i as u64, &handle).await;
    }

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
    // The detector is connection-scoped and fires ONCE per flagged connection, so the
    // under-ceiling connection contributed nothing: exactly one alarm, from the sweep.
    // A flag-everything limiter would have produced one for the quiet connection too.
    assert_eq!(
        alarms, 1,
        "only the sweeping connection may raise an alarm; the under-ceiling one must stay silent"
    );

    let _ = std::fs::remove_dir_all(&project_root);
    let _ = std::fs::remove_dir_all(&quiet_root);
}

/// Malicious-local-client, on the wire: a malformed route request (not a valid
/// method envelope) is answered with a typed wire error, never crashing the daemon
/// (a later valid request still succeeds on a fresh connection).
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn real_daemon_malformed_request_is_typed_error_not_crash() {
    let seeded = seeded_or_skip!();
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

/// Operator dogfood on a DISPOSABLE FIXTURE — the exact real operator flow, but on a
/// fake auth.json (no real credential, throwaway operator-path key, never the
/// keychain). Proves the import path end-to-end: `ck-auth import --source
/// opencode` of an auth.json-shaped fixture, mint a handle, then drive
/// `credential.get` through the REAL supervised daemon and assert the IMPORTED
/// access token round-trips, plus `verify-audit` reports the chain intact. It
/// rehearses the operator flow in docs/operator-runbook.md on a fixture, so the same
/// flow on a real auth.json is known-good before it is ever run.
#[tokio::test]
#[ignore = "builds subc-core in ../subconscious and binds loopback ports"]
async fn fixture_dogfood_import_opencode_round_trips_through_real_daemon() {
    // A fake opencode auth.json entry: the shared {refresh, access, expires} shape
    // the importer parses. Plainly fake values — no real secret.
    const FAKE_ACCESS: &str = "fixture-access-token-NOT-REAL";
    let fixture = serde_json::json!({
        "refresh": "fixture-refresh-token-NOT-REAL",
        "access": FAKE_ACCESS,
        "expires": 1_999_999_999_000i64,
    });

    let mut seeded = match start_vault_with_seed(|ctx| {
        // Write the fixture auth.json into a temp path (alongside the operator key
        // dir's parent — any path works; it is read once by the CLI).
        let json_path = std::path::Path::new(&ctx.key_path)
            .parent()
            .unwrap()
            .join("opencode-auth.json");
        std::fs::write(&json_path, serde_json::to_vec(&fixture).unwrap()).unwrap();
        // The real operator command: import the opencode credential.
        run_cli(&[
            "import",
            "--source",
            "opencode",
            "--id",
            "opencode:anthropic",
            "--json",
            &json_path.to_string_lossy(),
            "--data-dir",
            &ctx.data_dir,
            "--key-path",
            &ctx.key_path,
        ]);
        // credential.get returns the OAuth credential's access token as the payload
        // (VaultRecord::new_oauth stores the access token bytes as the payload).
        (
            "opencode:anthropic".to_string(),
            FAKE_ACCESS.as_bytes().to_vec(),
        )
    })
    .await
    {
        Some(v) => v,
        None => {
            eprintln!("skipping fixture dogfood: sibling subc-core unavailable");
            return;
        }
    };

    let mut consumer = connect_consumer(&seeded.daemon.connection_file).await;
    wait_for_catalog(&mut consumer, MODULE_ID, SETUP_TIMEOUT).await;
    let project_root = unique_temp_dir("cred-dogfood-project");
    std::fs::create_dir_all(&project_root).unwrap();
    let route_channel = route_open(&mut consumer, &project_root, 1).await;

    // The consumer reads the imported credential by its minted handle, over the
    // route channel, through the real supervised daemon.
    let response = credential_get(&mut consumer, route_channel, 2, &seeded.handle).await;
    let payload = response["result"]["payload"]
        .as_array()
        .expect("credential.get returns a payload");
    let bytes: Vec<u8> = payload.iter().map(|v| v.as_u64().unwrap() as u8).collect();
    assert_eq!(
        bytes, seeded.payload,
        "the imported opencode access token round-trips through the real daemon"
    );

    // Stop the daemon, then prove the audit chain is intact via the CLI's
    // verify-audit (the operator's final check; see docs/operator-runbook.md).
    seeded.stop_daemon().await;
    let data_dir = seeded
        .db_path
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let key_path = seeded
        .daemon
        .rig
        .join("secrets/master.key")
        .to_string_lossy()
        .to_string();
    let verify = std::process::Command::new(env!("CARGO_BIN_EXE_ck-auth"))
        .args([
            "verify-audit",
            "--data-dir",
            &data_dir,
            "--key-path",
            &key_path,
        ])
        .output()
        .expect("run verify-audit");
    assert!(
        verify.status.success(),
        "verify-audit must report the chain intact: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("intact"));

    let _ = std::fs::remove_dir_all(&project_root);
}
