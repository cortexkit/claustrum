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

const MODULE_ID: &str = "cortexkit-credentials";
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut subc: Option<PathBuf> = None;
    let mut handle: Option<String> = None;
    let mut root = std::env::temp_dir();

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

    let route_channel = route_open(&mut stream, &root).await;
    eprintln!("[probe] route.open -> route_channel={route_channel}");

    let body = credential_get(&mut stream, route_channel, &handle).await;
    report(&body);
}

async fn control_rpc(stream: &mut TcpStream, corr: u64, body: Value) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
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

async fn route_open(stream: &mut TcpStream, root: &std::path::Path) -> u16 {
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
    value["route_channel"].as_u64().unwrap() as u16
}

async fn credential_get(stream: &mut TcpStream, route_channel: u16, handle: &str) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        7,
        serde_json::to_vec(&json!({ "method": "credential.get", "params": { "handle": handle } }))
            .unwrap(),
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
fn report(frame: &Frame) {
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
                }
                None => {
                    println!("OK Response, but no result.payload array found.");
                    println!(
                        "   result keys: {:?}",
                        value
                            .get("result")
                            .and_then(|r| r.as_object())
                            .map(|o| o.keys().collect::<Vec<_>>())
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
