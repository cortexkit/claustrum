#![forbid(unsafe_code)]

//! `vault_read_probe` — read a credential from a LIVE vault daemon by handle.
//!
//! A hand-driving consumer for the credential vault: it authenticates as a client
//! over the subc loopback handshake, waits for the vault module to appear in the
//! catalog, opens a route to its ManagementSurface, and issues `credential.get`
//! for a capability handle — printing whether the payload came back, without ever
//! printing the secret itself. It is the operator-facing twin of the e2e harness's
//! consumer driver, useful for verifying a real vault end-to-end.
//!
//! Usage:
//!   cargo run -p credentials-module --example vault_read_probe -- \
//!     --subc <connection-file> --handle <ckh_...> [--root <path>]
//!
//! It deliberately does NOT print the credential payload bytes (only its length and
//! a short fingerprint), so running it against a real credential does not splash the
//! token across a terminal or log.

use std::{path::PathBuf, time::Duration};

use serde_json::{json, Value};
use subc_core::{read_frame, write_frame, Frame};
use subc_protocol::{BindIdentity, Flags, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file};
use tokio::{net::TcpStream, time::Instant};

const MODULE_ID: &str = "claustrum";
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut subc: Option<PathBuf> = None;
    let mut handle: Option<String> = None;
    let mut root = std::env::temp_dir();
    let mut force_refresh = false;
    let mut min_ttl_ms: Option<i64> = None;
    let mut show_account_id = false;
    let mut show_claims = false;
    let mut report_auth_failure = false;
    let mut sign_payload: Option<String> = None;
    let mut sign_payload_bytes: Option<Vec<u8>> = None;
    let mut public_key = false;
    let mut provider_status: u16 = 401;
    let mut record_version: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--subc" => subc = args.next().map(PathBuf::from),
            "--handle" => handle = args.next(),
            "--root" => {
                if let Some(value) = args.next() {
                    root = PathBuf::from(value);
                }
            }
            // Force a refresh-on-read regardless of the token's recorded expiry. This
            // makes the "google's token is dead, the vault refreshes it live" proof
            // DETERMINISTIC: without it, a credential whose auth.json carried no
            // `expires` is treated as not-stale and served as-is (no refresh), so an
            // empty google access token would come back empty and look like a failure.
            "--force-refresh" => force_refresh = true,
            // Refresh if the token has less than this many ms of life left.
            "--min-ttl-ms" => {
                min_ttl_ms = args.next().and_then(|v| v.parse().ok());
            }
            // Decode the served payload AS a JWT client-side and print ONLY the
            // non-secret ChatGPT account-id claim. Useful when the daemon predates
            // the GetResult.account_id field: the payload already carries the claim,
            // so the probe can surface it without printing the token.
            "--show-account-id" => show_account_id = true,
            // Decode the served payload AS a JWT and print its full claims object
            // (pretty JSON). The claims are the token's non-secret self-description
            // (issuer, audience, scopes, account bindings, expiry); the token itself
            // — header+signature, the actual bearer secret — is never printed. For
            // diffing two grants' claim sets during entitlement forensics.
            "--show-claims" => show_claims = true,
            // Send `credential.report_auth_failure` INSTEAD of a get, reporting the
            // given provider status against the given record_version.
            //
            // This exists so the report path can be exercised against a running vault
            // at all. It otherwise has no client: the only way to produce a report is a
            // consumer meeting a real provider 401, so the vault's handling of one was
            // covered by unit tests and by nothing live.
            //
            // Reporting a version the store has already moved past is the SAFE way to
            // drive it: the invalidate is version-gated, so a stale version changes
            // nothing, while the surrounding diagnostics still record the observation.
            // Point it at a disposable credential regardless -- a report at the CURRENT
            // version will mark that credential needs_reauth, which is the whole point
            // of the call.
            "--report-auth-failure" => report_auth_failure = true,
            // Exercise `credential.sign` / `credential.public_key` over the wire.
            //
            // These are route ops with NO CLI verb -- they exist for consumers, so
            // nothing an operator can run proves they answer. That gap is not
            // theoretical: the deploy that shipped them passed every acceptance leg
            // (hashes, identifiers, inode, serving count, fenced write) while these two
            // surfaces had never been called once. `scripts/accept-deploy.sh` says so
            // itself -- it asks whether the right bytes are in the right place, never
            // whether a behaviour is reachable.
            "--sign" => sign_payload = args.next(),
            // SIGN THE FILE'S EXACT BYTES, never a shell-quoted copy of them.
            //
            // `--sign` takes its payload through argv, which is a one-byte mutation
            // channel: quoting, escaping and newline handling all sit between the file an
            // approver hashed and the bytes the vault signs. For a 4872-byte JSON
            // manifest that is not theoretical, and it defeats the SHA gate the ceremony
            // opens with — the approval would bind bytes H while the signature covers
            // something else, and both would look correct.
            "--sign-file" => {
                let path = args.next().expect("--sign-file needs a path");
                let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
                sign_payload_bytes = Some(bytes);
            }
            "--public-key" => public_key = true,
            "--provider-status" => {
                provider_status = args.next().and_then(|v| v.parse().ok()).unwrap_or(401);
            }
            "--record-version" => {
                record_version = args.next().and_then(|v| v.parse().ok());
            }
            other => {
                eprintln!("vault_read_probe: unexpected arg '{other}'");
                std::process::exit(2);
            }
        }
    }

    let subc = subc.unwrap_or_else(|| {
        eprintln!("vault_read_probe: --subc <connection-file> is required");
        std::process::exit(2);
    });
    let handle = handle.unwrap_or_else(|| {
        eprintln!("vault_read_probe: --handle <ckh_...> is required");
        std::process::exit(2);
    });

    let conn = connection_file::read(&subc).expect("read connection file");
    let endpoint = conn
        .endpoints
        .first()
        .expect("connection file has an endpoint");
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .expect("connect to daemon");
    authenticate_client(&mut stream, &conn, Duration::from_secs(2))
        .await
        .expect("client handshake");
    eprintln!(
        "[probe] authenticated to {}:{}",
        endpoint.host, endpoint.port
    );

    wait_for_catalog(&mut stream).await;
    eprintln!("[probe] vault module '{MODULE_ID}' is catalog-live");

    let (route_channel, route_epoch) = route_open(&mut stream, &root).await;
    eprintln!("[probe] route.open -> route_channel={route_channel} route_epoch={route_epoch}");

    if report_auth_failure {
        let version = record_version.unwrap_or_else(|| {
            eprintln!(
                "vault_read_probe: --record-version <n> is required with \
                 --report-auth-failure (the vault refuses a versionless report)"
            );
            std::process::exit(2);
        });
        let body = credential_report_auth_failure(
            &mut stream,
            route_channel,
            route_epoch,
            &handle,
            provider_status,
            version,
        )
        .await;
        let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
        eprintln!(
            "[probe] report_auth_failure status={provider_status} record_version={version} -> {}",
            serde_json::to_string(&parsed).unwrap_or_default()
        );
        return;
    }

    if public_key || sign_payload.is_some() || sign_payload_bytes.is_some() {
        // Both halves in one run when both are asked for, because the useful assertion
        // is that they AGREE: a signature that verifies under the returned key proves
        // the two ops name the same keypair. Either alone proves only that an op
        // answered, which is the weaker claim that let this gap exist.
        if public_key {
            let body =
                credential_public_key(&mut stream, route_channel, route_epoch, &handle).await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            eprintln!(
                "[probe] public_key -> {}",
                serde_json::to_string(&parsed).unwrap_or_default()
            );
        }
        // File bytes take precedence and are used VERBATIM; the argv string keeps its
        // existing behaviour for short ad-hoc payloads.
        let to_sign: Option<Vec<u8>> =
            sign_payload_bytes.or_else(|| sign_payload.map(|p| p.into_bytes()));
        if let Some(payload) = to_sign {
            let body =
                credential_sign(&mut stream, route_channel, route_epoch, &handle, &payload).await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            eprintln!(
                "[probe] sign({} bytes) -> {}",
                payload.len(),
                serde_json::to_string(&parsed).unwrap_or_default()
            );
        }
        return;
    }

    let body = credential_get(
        &mut stream,
        route_channel,
        route_epoch,
        &handle,
        force_refresh,
        min_ttl_ms,
    )
    .await;
    report(&body, show_account_id, show_claims);
}

/// Send `credential.public_key`.
///
/// This op exists precisely BECAUSE `credential.get` returns the record payload
/// verbatim, and for a signing-key record that payload IS the private PKCS#8. A
/// consumer that wants to publish a verifier key must have a route that cannot carry
/// private bytes, and this is it.
async fn credential_public_key(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        11,
        serde_json::to_vec(&json!({
            "method": "credential.public_key",
            "params": { "handle": handle },
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 11
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

/// Send `credential.sign`.
///
/// The payload is base64 on the wire because JSON cannot carry raw bytes, but the
/// vault signs the DECODED bytes. That distinction is load-bearing: signing the
/// encoded text would break the moment a caller re-encoded with different padding,
/// which is the canonicalization mismatch this whole design avoids by carrying exact
/// bytes end to end.
async fn credential_sign(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
    payload: &[u8],
) -> Frame {
    use base64::Engine as _;
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        12,
        serde_json::to_vec(&json!({
            "method": "credential.sign",
            "params": {
                "handle": handle,
                "payload_b64": base64::engine::general_purpose::STANDARD.encode(payload),
            },
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 12
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

async fn control_rpc(stream: &mut TcpStream, corr: u64, body: Value) -> Frame {
    // Channel-0 control frames carry the reserved epoch 0 (wire v2 §3.1).
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.channel == 0
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            && frame.header.corr == corr
        {
            return frame;
        }
    }
}

async fn read_frame_timeout(stream: &mut TcpStream) -> Frame {
    tokio::time::timeout(READ_TIMEOUT, async {
        read_frame(stream)
            .await
            .unwrap()
            .expect("connection should stay open")
    })
    .await
    .expect("timed out waiting for a frame")
}

async fn wait_for_catalog(stream: &mut TcpStream) {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let mut corr = 1000;
    loop {
        let frame = control_rpc(stream, corr, json!({ "op": "catalog.list" })).await;
        let value: Value = serde_json::from_slice(&frame.body).unwrap();
        let present = value["modules"]
            .as_array()
            .map(|ms| ms.iter().any(|m| m["module_id"] == MODULE_ID))
            .unwrap_or(false);
        if present {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "vault module did not appear in catalog within {SETUP_TIMEOUT:?}"
        );
        corr += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn route_open(stream: &mut TcpStream, root: &std::path::Path) -> (u16, u32) {
    let target = RouteTarget::ManagementSurface {
        module_id: MODULE_ID.to_string(),
    };
    let identity = BindIdentity {
        project_root: root.to_path_buf(),
        harness: "vault-read-probe".to_string(),
        session: "probe-1".to_string(),
    };
    let frame = control_rpc(
        stream,
        1,
        json!({ "op": "route.open", "target": target, "identity": identity }),
    )
    .await;
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "route.open should succeed: {}",
        String::from_utf8_lossy(&frame.body)
    );
    let value: Value = serde_json::from_slice(&frame.body).unwrap();
    // Wire v2: route identity is (channel, epoch); both are stamped on every frame.
    (
        value["route_channel"].as_u64().unwrap() as u16,
        value["route_epoch"].as_u64().unwrap() as u32,
    )
}

/// Send `credential.report_auth_failure`. See the `--report-auth-failure` arm for why
/// this exists and why a stale `record_version` is the safe way to drive it.
async fn credential_report_auth_failure(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
    provider_status: u16,
    record_version: u64,
) -> Frame {
    let params = json!({
        "handle": handle,
        "provider_status": provider_status,
        "record_version": record_version,
    });
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        8,
        serde_json::to_vec(&json!({
            "method": "credential.report_auth_failure",
            "params": params,
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 8
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

async fn credential_get(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
    force_refresh: bool,
    min_ttl_ms: Option<i64>,
) -> Frame {
    let mut params = json!({ "handle": handle, "force_refresh": force_refresh });
    if let Some(ttl) = min_ttl_ms {
        params["min_ttl_ms"] = json!(ttl);
    }
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        7,
        serde_json::to_vec(&json!({ "method": "credential.get", "params": params })).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 7
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

/// Decode a JWT access-token payload client-side and pull the non-secret ChatGPT
/// account-id claim (`"https://api.openai.com/auth".chatgpt_account_id`). This is
/// the same claim path the vault's own `account_id_for_adapter` uses; duplicated
/// here because the example must work against a daemon predating that field.
fn chatgpt_account_id_from_payload(payload: &[u8]) -> Option<String> {
    let claims = jwt_claims_from_payload(payload)?;
    claims
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .map(str::to_string)
}

/// Decode a JWT's claims segment (payload part only — never the signature).
fn jwt_claims_from_payload(payload: &[u8]) -> Option<Value> {
    let token = std::str::from_utf8(payload).ok()?;
    let claims_b64 = token.split('.').nth(1)?;
    let claims_json = base64url_decode(claims_b64)?;
    serde_json::from_slice(&claims_json).ok()
}

/// Minimal unpadded base64url decoder (RFC 4648 §5) — dependency-free so the
/// example stays a pure consumer of the wire.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a') as u32 + 26),
            b'0'..=b'9' => Some((b - b'0') as u32 + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            acc |= val(b)? << (18 - 6 * i);
        }
        let n = chunk.len();
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// FNV-1a-64: a stable, dependency-free fingerprint used only to compare two byte
/// strings for equality without revealing either. NOT a cryptographic hash.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Print whether the read succeeded WITHOUT exposing the secret: only the payload
/// length and a one-way fingerprint are shown.
fn report(frame: &Frame, show_account_id: bool, show_claims: bool) {
    match frame.header.ty {
        FrameType::Response => {
            let value: Value = serde_json::from_slice(&frame.body).unwrap_or(Value::Null);
            // The read surface wraps the result as `{ "result": { "payload": [u8...] } }`.
            // Show only the payload length and a one-way fingerprint (FNV-1a-64 hex of
            // the bytes) — never the content. The fingerprint lets an operator compare
            // the served bytes against an expected token's fingerprint WITHOUT either
            // side exposing the secret.
            let payload = value
                .get("result")
                .and_then(|r| r.get("payload"))
                .and_then(|p| p.as_array());
            match payload {
                Some(arr) => {
                    let bytes: Vec<u8> = arr
                        .iter()
                        .filter_map(|b| b.as_u64().map(|n| n as u8))
                        .collect();
                    println!("OK credential.get returned a Response.");
                    println!(
                        "   payload: {} byte(s), fnv1a64={:016x} (content withheld)",
                        bytes.len(),
                        fnv1a64(&bytes)
                    );
                    // Non-secret metadata, printed verbatim: the record revision, the
                    // provider account the token executes under (chatgpt wire), and the
                    // Code-Assist project id (antigravity). These are exactly the fields
                    // a consumer keys routing on, so the probe surfaces them for
                    // operator diagnosis.
                    let result = value.get("result");
                    for key in ["record_version", "account_id", "project_id"] {
                        if let Some(v) = result.and_then(|r| r.get(key)) {
                            println!("   {key}: {v}");
                        }
                    }
                    if show_account_id {
                        match chatgpt_account_id_from_payload(&bytes) {
                            Some(account) => println!("   chatgpt account id (client-side decode): {account}"),
                            None => println!("   chatgpt account id: none (payload is not a JWT carrying the claim)"),
                        }
                    }
                    if show_claims {
                        match jwt_claims_from_payload(&bytes) {
                            Some(claims) => println!(
                                "   claims:\n{}",
                                serde_json::to_string_pretty(&claims).unwrap_or_default()
                            ),
                            None => println!("   claims: payload is not a decodable JWT"),
                        }
                    }
                }
                None => {
                    println!("OK Response, but no result.payload array found.");
                    println!(
                        "   result.error = {}",
                        value
                            .get("result")
                            .and_then(|r| r.get("error"))
                            .cloned()
                            .unwrap_or(Value::Null)
                    );
                }
            }
        }
        FrameType::Error => {
            println!(
                "ERROR credential.get returned an Error frame: {}",
                String::from_utf8_lossy(&frame.body)
            );
            std::process::exit(1);
        }
        ty => {
            println!("UNEXPECTED terminal frame {ty:?}");
            std::process::exit(1);
        }
    }
}
