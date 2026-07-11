//! The CLI's route-plane admin client: commit an admin op to the RUNNING module.
//!
//! When the daemon is up it holds the single-writer lease, so the offline path
//! (which takes the lease) cannot write. This client talks to the running module
//! over the subc route plane instead, authenticating each op with a master-key
//! challenge-response (the module's Gate 2). The CLI resolves the SAME master key
//! from the keychain WITHOUT opening the database or taking the lease — the
//! challenge returns the module's `key_id`, and `resolver::resolve` loads the
//! matching keychain slot (rotation is offline-only, so the live key is always the
//! Current slot).
//!
//! Fallback discipline (Oracle finding 10): the caller falls back to the offline
//! lease path ONLY when no live module is reachable. Once an `admin.op` has been
//! sent, a lost response is INDETERMINATE — the op may have committed — so this
//! never silently retries or falls back after dispatch; it returns a distinct error
//! the CLI surfaces as "verify with list/verify-audit before retrying".

use std::time::Duration;

use credentials_core::admin_auth::{AdminMacKey, TranscriptParts, ADMIN_NONCE_LEN, VAULT_ID_LEN};
use credentials_core::admin_ops::AdminOpBody;
use credentials_core::resolver::{self, ResolverConfig};
use credentials_core::{vault_id_for, MODULE_ID};
use serde_json::{json, Value};
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_TIMEOUT: Duration = Duration::from_secs(15);

/// The outcome of attempting a route-plane commit.
pub enum RouteCommit {
    /// The op committed on the running module; carries its JSON result.
    Committed(Value),
    /// No live module was reachable (no connection file, no daemon, or the vault
    /// module is not in the catalog). The caller MAY fall back to the offline path
    /// — nothing was dispatched.
    NoLiveModule(String),
    /// The module refused the op (auth, gate, or a store error). Terminal — do NOT
    /// fall back (the module is alive and said no).
    Refused(String),
    /// The op was dispatched but the outcome is UNKNOWN (connection dropped after
    /// send). Do NOT fall back or retry blindly — the op may have committed.
    Indeterminate(String),
}

/// Try to commit `op` to a running module. `data_dir` locates the vault (for the
/// key resolution and vault-id derivation); `config` is the key-source resolver;
/// `conn_path` is the subc connection file (from `--subc`, or the default probe
/// path). Absence of the file ⇒ no daemon ⇒ the caller may go offline.
pub fn commit(
    data_dir: &std::path::Path,
    config: &ResolverConfig,
    conn_path: &std::path::Path,
    op: &AdminOpBody,
) -> RouteCommit {
    let conn = match connection_file::read(conn_path) {
        Ok(c) => c,
        Err(e) => return RouteCommit::NoLiveModule(format!("no subc connection file: {e}")),
    };
    let vault_id = match vault_id_for(data_dir) {
        Some(v) => v,
        None => return RouteCommit::NoLiveModule("cannot derive vault id".into()),
    };
    let op_bytes = match op.to_bytes() {
        Ok(b) => b,
        Err(e) => return RouteCommit::Refused(format!("encoding op: {e}")),
    };

    run_async(async move { commit_async(&conn, &vault_id, config, &op_bytes).await })
}

fn run_async<F: std::future::Future<Output = RouteCommit>>(fut: F) -> RouteCommit {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return RouteCommit::NoLiveModule(format!("runtime: {e}")),
    };
    rt.block_on(fut)
}

async fn commit_async(
    conn: &connection_file::ConnectionInfo,
    vault_id: &[u8; VAULT_ID_LEN],
    config: &ResolverConfig,
    op_bytes: &[u8],
) -> RouteCommit {
    let Some(endpoint) = conn.endpoints.first() else {
        return RouteCommit::NoLiveModule("connection file has no endpoint".into());
    };
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return RouteCommit::NoLiveModule(format!("connect: {e}")),
        Err(_) => return RouteCommit::NoLiveModule("connect timed out".into()),
    };
    if let Err(e) = authenticate_client(&mut stream, conn, CONNECT_TIMEOUT).await {
        return RouteCommit::NoLiveModule(format!("client handshake: {e}"));
    }

    // The vault module must be catalog-live; otherwise there is no module to admin.
    match catalog_has_vault(&mut stream).await {
        Ok(true) => {}
        Ok(false) => {
            return RouteCommit::NoLiveModule("vault module not in catalog".into());
        }
        Err(e) => return RouteCommit::NoLiveModule(format!("catalog.list: {e}")),
    }

    let route_channel = match route_open(&mut stream, &config.data_dir).await {
        Ok(ch) => ch,
        Err(e) => return RouteCommit::NoLiveModule(format!("route.open: {e}")),
    };

    // admin.challenge: fetch a nonce + the module's key_id (so we resolve the SAME
    // key) + its vault_id (so we confirm we are talking to the intended vault).
    let (nonce, key_id_hex, module_vault_id_hex) = match challenge(&mut stream, route_channel).await
    {
        Ok(v) => v,
        Err(RpcFail::Refused(m)) => return RouteCommit::Refused(m),
        Err(RpcFail::Transport(m)) => return RouteCommit::NoLiveModule(m),
    };

    // Confirm the module's vault identity matches the vault we were pointed at. A
    // mismatch means the connection file points at a DIFFERENT vault's module — do
    // not sign an op for it.
    if module_vault_id_hex != hex(vault_id) {
        return RouteCommit::Refused(
            "the running module is a different vault (vault-id mismatch); not committing".into(),
        );
    }

    // Resolve the master key from the keychain by the module's key_id, WITHOUT
    // opening the DB or taking the lease. Rotation is offline-only, so the live key
    // is the Current slot; `resolve` checks the fingerprint matches.
    let key_id = match credentials_core::key::KeyId::from_hex(&key_id_hex) {
        Some(k) => k,
        None => return RouteCommit::Refused("module returned a malformed key_id".into()),
    };
    let key = match resolver::resolve(config, Some(key_id)) {
        Ok(k) => k,
        Err(e) => {
            return RouteCommit::Refused(format!(
                "cannot resolve the master key to authorize the op: {e}"
            ))
        }
    };
    let mac_key = AdminMacKey::derive(&key);
    let tag = mac_key.sign(&TranscriptParts {
        vault_id,
        key_id,
        nonce: &nonce,
        op_body: op_bytes,
    });

    // admin.op: send the exact op bytes + tag. After THIS send, a lost response is
    // indeterminate (the op may have committed).
    admin_op(&mut stream, route_channel, op_bytes, &hex(&tag)).await
}

enum RpcFail {
    Refused(String),
    Transport(String),
}

async fn challenge(
    stream: &mut TcpStream,
    route_channel: u16,
) -> Result<([u8; ADMIN_NONCE_LEN], String, String), RpcFail> {
    let frame = route_request(route_channel, 100, json!({ "method": "admin.challenge" }));
    if let Err(e) = write_frame(stream, &frame).await {
        return Err(RpcFail::Transport(format!("write admin.challenge: {e}")));
    }
    let resp = read_route_response(stream, 100)
        .await
        .map_err(RpcFail::Transport)?;
    if resp.header.ty == FrameType::Error {
        return Err(RpcFail::Refused(error_reason(&resp.body)));
    }
    let value: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| RpcFail::Transport(format!("decode challenge: {e}")))?;
    let result = &value["result"];
    let nonce_hex = result["nonce_hex"].as_str().unwrap_or_default();
    let nonce_vec =
        decode_hex(nonce_hex).ok_or_else(|| RpcFail::Transport("bad nonce hex".into()))?;
    let nonce: [u8; ADMIN_NONCE_LEN] = nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| RpcFail::Transport("nonce wrong length".into()))?;
    let key_id_hex = result["key_id_hex"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let vault_id_hex = result["vault_id_hex"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Ok((nonce, key_id_hex, vault_id_hex))
}

async fn admin_op(
    stream: &mut TcpStream,
    route_channel: u16,
    op_bytes: &[u8],
    tag_hex: &str,
) -> RouteCommit {
    // The op body rides as a STRING so the exact MAC'd bytes survive the outer
    // envelope verbatim (no JSON re-encoding of the authenticated bytes).
    let op_body_str = match std::str::from_utf8(op_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return RouteCommit::Refused("op body is not valid utf-8".into()),
    };
    let frame = route_request(
        route_channel,
        101,
        json!({
            "method": "admin.op",
            "params": { "op_body": op_body_str, "tag_hex": tag_hex },
        }),
    );
    if let Err(e) = write_frame(stream, &frame).await {
        // Failed BEFORE the bytes left us: safe to treat as not-dispatched.
        return RouteCommit::NoLiveModule(format!("write admin.op: {e}"));
    }
    match read_route_response(stream, 101).await {
        Ok(resp) if resp.header.ty == FrameType::Error => {
            RouteCommit::Refused(error_reason(&resp.body))
        }
        Ok(resp) => match serde_json::from_slice::<Value>(&resp.body) {
            Ok(v) => RouteCommit::Committed(v["result"].clone()),
            Err(e) => RouteCommit::Indeterminate(format!(
                "op was sent but its response did not decode ({e}); verify with `list`/`verify-audit`"
            )),
        },
        // The op was already on the wire; a missing reply is INDETERMINATE.
        Err(e) => RouteCommit::Indeterminate(format!(
            "op was sent but no response arrived ({e}); it may have committed — verify with `list`/`verify-audit` before retrying"
        )),
    }
}

async fn catalog_has_vault(stream: &mut TcpStream) -> Result<bool, String> {
    let frame = control_request(1, json!({ "op": "catalog.list" }));
    write_frame(stream, &frame)
        .await
        .map_err(|e| format!("write catalog.list: {e}"))?;
    let resp = read_control_response(stream, 1).await?;
    let value: Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    Ok(value["modules"]
        .as_array()
        .map(|ms| ms.iter().any(|m| m["module_id"] == MODULE_ID))
        .unwrap_or(false))
}

async fn route_open(stream: &mut TcpStream, root: &std::path::Path) -> Result<u16, String> {
    let target = RouteTarget::ManagementSurface {
        module_id: MODULE_ID.to_string(),
    };
    let identity = BindIdentity {
        project_root: root.to_path_buf(),
        harness: "credentials-cli".to_string(),
        session: "admin".to_string(),
    };
    let frame = control_request(
        2,
        json!({ "op": "route.open", "target": target, "identity": identity }),
    );
    write_frame(stream, &frame)
        .await
        .map_err(|e| format!("write route.open: {e}"))?;
    let resp = read_control_response(stream, 2).await?;
    if resp.header.ty == FrameType::Error {
        return Err(error_reason(&resp.body));
    }
    let value: Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    value["route_channel"]
        .as_u64()
        .map(|c| c as u16)
        .ok_or_else(|| "route.open returned no route_channel".to_string())
}

fn control_request(corr: u64, body: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn route_request(channel: u16, corr: u64, body: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

async fn read_control_response(stream: &mut TcpStream, corr: u64) -> Result<Frame, String> {
    read_matching(stream, 0, corr).await
}

async fn read_route_response(stream: &mut TcpStream, corr: u64) -> Result<Frame, String> {
    // Route responses arrive on the route channel; match by corr only (the channel
    // is whatever route.open returned).
    tokio::time::timeout(RPC_TIMEOUT, async {
        loop {
            let frame = read_frame(stream)
                .await
                .map_err(|e| format!("read: {e}"))?
                .ok_or_else(|| "connection closed".to_string())?;
            if frame.header.corr == corr
                && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            {
                return Ok(frame);
            }
        }
    })
    .await
    .map_err(|_| "response timed out".to_string())?
}

async fn read_matching(stream: &mut TcpStream, channel: u16, corr: u64) -> Result<Frame, String> {
    tokio::time::timeout(RPC_TIMEOUT, async {
        loop {
            let frame = read_frame(stream)
                .await
                .map_err(|e| format!("read: {e}"))?
                .ok_or_else(|| "connection closed".to_string())?;
            if frame.header.channel == channel
                && frame.header.corr == corr
                && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            {
                return Ok(frame);
            }
        }
    })
    .await
    .map_err(|_| "response timed out".to_string())?
}

fn error_reason(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("detail"))
                .and_then(|m| m.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| "module refused the op".to_string())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
