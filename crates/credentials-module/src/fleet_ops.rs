//! Entorhinal's fleet boundary: closed wire grammar and validated Callosum peers.
//! All epoch transitions and membership decisions belong to the encrypted store.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::fleet::{FleetError, FleetPeer, FleetWrap, MAX_BYTES};
use credentials_core::secret::Secret;
use credentials_core::EncryptedStore;
use serde::Deserialize;
use serde_json::{json, Value};
use subc_protocol::Principal;

use crate::federation::ingress::callosum_lookup;
use crate::federation::outbound::{OutboundClient, ADMIN_OP_BUDGET};

pub const OPS: [&str; 8] = [
    "fleet.epoch_seal",
    "fleet.epoch_open",
    "fleet.epoch_status",
    "fleet.epoch_mint",
    "fleet.epoch_commit",
    "fleet.epoch_discard",
    "fleet.epoch_import",
    "fleet.epoch_wrap_for",
];

pub fn is_op(method: &str) -> bool {
    OPS.contains(&method)
}

pub fn admitted(principal: Option<&Principal>) -> bool {
    matches!(principal, Some(Principal::Reserved { module_id }) if module_id == "entorhinal")
}

pub enum Answer {
    Reply(Value),
    InvalidParams,
}

fn body(error: FleetError) -> Value {
    json!({"error": {"code": error.code(), "class": error.class()}})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    aad: String,
    plaintext: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    epoch: u32,
    nonce: String,
    ciphertext: String,
    aad: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mint {
    members: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    epoch: u32,
    mint_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    wrap: FleetWrap,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WrapFor {
    member_id: String,
}

fn parse<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, FleetError> {
    serde_json::from_value(value.clone()).map_err(|_| FleetError::InvalidParams)
}

fn decode(value: &str, max: usize) -> Result<Secret<Vec<u8>>, FleetError> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(FleetError::InvalidParams);
    }
    let bytes = Secret::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| FleetError::InvalidParams)?,
    );
    if bytes.expose().len() > max || URL_SAFE_NO_PAD.encode(bytes.expose()) != value {
        return Err(FleetError::InvalidParams);
    }
    Ok(bytes)
}

/// A malformed snapshot is not an empty fleet. Invalid or absent wrap keys on
/// otherwise valid entries supply no peer, while duplicate fingerprints poison
/// the entire read, even if neither duplicate supplies a usable wrap key.
pub fn decode_peers(body: &Value) -> Result<Vec<FleetPeer>, FleetError> {
    let unavailable = FleetError::PeerKeysUnavailable;
    if body.get("error").is_some() {
        return Err(unavailable);
    }
    let entries = body
        .get("peers")
        .and_then(Value::as_array)
        .ok_or(unavailable)?;
    let mut seen = BTreeSet::new();
    let mut peers = Vec::new();
    for entry in entries {
        let fingerprint = entry
            .get("fingerprint")
            .and_then(Value::as_str)
            .ok_or(unavailable)?;
        if !credentials_core::federation::is_lower_hex_16_bytes(fingerprint)
            || !seen.insert(fingerprint)
        {
            return Err(unavailable);
        }
        if entry.get("class").and_then(Value::as_str) != Some("computer") {
            continue;
        }
        let Some(public) = entry
            .pointer("/key_record/keys/fleet_epoch_wrap_x25519/pub")
            .and_then(Value::as_str)
        else {
            continue;
        };
        if public.len() != 64
            || !public
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        let mut key = [0u8; 32];
        for (byte, pair) in key.iter_mut().zip(public.as_bytes().as_chunks::<2>().0) {
            // The alphabet and width were checked before splitting into pairs.
            *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("validated hex");
        }
        if let Ok(peer) = FleetPeer::new(format!("fed-computer:{fingerprint}"), key) {
            peers.push(peer);
        }
    }
    Ok(peers)
}

async fn peers(client: Option<&OutboundClient>) -> Result<Vec<FleetPeer>, FleetError> {
    let snapshot = callosum_lookup(
        client,
        "callosum.peer_keys_read",
        tokio::time::Instant::now() + ADMIN_OP_BUDGET,
    )
    .await
    .ok_or(FleetError::PeerKeysUnavailable)?;
    decode_peers(&snapshot)
}

// No Debug implementation: requests contain plaintext, ciphertext or wraps.
enum Command {
    Seal(Secret<Vec<u8>>, Secret<Vec<u8>>),
    Open(u32, Secret<Vec<u8>>, Secret<Vec<u8>>, Secret<Vec<u8>>),
    Status,
    Mint(Vec<String>),
    Commit(Transition),
    Discard(Transition),
    Import(FleetWrap),
    WrapFor(String),
}

fn command(method: &str, params: &Value) -> Result<Command, FleetError> {
    Ok(match method {
        "fleet.epoch_seal" => {
            let p: Seal = parse(params)?;
            Command::Seal(decode(&p.aad, MAX_BYTES)?, decode(&p.plaintext, MAX_BYTES)?)
        }
        "fleet.epoch_open" => {
            let p: Open = parse(params)?;
            let nonce = decode(&p.nonce, 24)?;
            let ct = decode(&p.ciphertext, MAX_BYTES + 16)?;
            if p.epoch == 0 || nonce.expose().len() != 24 || ct.expose().len() < 16 {
                return Err(FleetError::InvalidParams);
            }
            Command::Open(p.epoch, nonce, ct, decode(&p.aad, MAX_BYTES)?)
        }
        "fleet.epoch_status" => {
            let _: Empty = parse(params)?;
            Command::Status
        }
        "fleet.epoch_mint" => {
            let p: Mint = parse(params)?;
            if p.members
                .iter()
                .any(|m| !credentials_core::federation::valid_member_id(m))
                || p.members.iter().collect::<BTreeSet<_>>().len() != p.members.len()
            {
                return Err(FleetError::InvalidParams);
            }
            Command::Mint(p.members)
        }
        "fleet.epoch_commit" | "fleet.epoch_discard" => {
            let p: Transition = parse(params)?;
            if p.epoch == 0 || decode(&p.mint_id, 16)?.expose().len() != 16 {
                return Err(FleetError::InvalidParams);
            }
            if method == "fleet.epoch_commit" {
                Command::Commit(p)
            } else {
                Command::Discard(p)
            }
        }
        "fleet.epoch_import" => {
            let p: Import = parse(params)?;
            if decode(&p.wrap.enc, 32)?.expose().len() != 32 {
                return Err(FleetError::InvalidParams);
            }
            decode(&p.wrap.ct, MAX_BYTES + 16)?;
            Command::Import(p.wrap)
        }
        "fleet.epoch_wrap_for" => {
            let p: WrapFor = parse(params)?;
            if !credentials_core::federation::valid_member_id(&p.member_id) {
                return Err(FleetError::InvalidParams);
            }
            Command::WrapFor(p.member_id)
        }
        _ => return Err(FleetError::NotFound),
    })
}

pub async fn serve(
    store: Arc<EncryptedStore>,
    client: Option<&OutboundClient>,
    principal: Option<&Principal>,
    method: &str,
    params: &Value,
) -> Answer {
    if !admitted(principal) {
        return Answer::Reply(body(FleetError::NotFound));
    }
    let result = async {
        let command = command(method, params)?;
        let peers = if matches!(
            &command,
            Command::Mint(_) | Command::Import(_) | Command::WrapFor(_)
        ) {
            peers(client).await?
        } else {
            Vec::new()
        };
        // The store re-reads Self and removals in its transaction after the peer read.
        tokio::task::spawn_blocking(move || execute(&store, command, &peers))
            .await
            .map_err(|_| FleetError::StoreError)?
    }
    .await;
    match result {
        Ok(reply) => Answer::Reply(reply),
        Err(FleetError::InvalidParams) => Answer::InvalidParams,
        Err(error) => Answer::Reply(body(error)),
    }
}

fn execute(
    store: &EncryptedStore,
    command: Command,
    peers: &[FleetPeer],
) -> Result<Value, FleetError> {
    fn wire(value: impl serde::Serialize) -> Result<Value, FleetError> {
        serde_json::to_value(value).map_err(|_| FleetError::StoreError)
    }
    match command {
        Command::Seal(aad, plaintext) => {
            wire(store.fleet_epoch_seal(aad.expose(), plaintext.expose())?)
        }
        Command::Open(epoch, nonce, ct, aad) => {
            let plaintext =
                store.fleet_epoch_open(epoch, nonce.expose(), ct.expose(), aad.expose())?;
            Ok(json!({"plaintext": URL_SAFE_NO_PAD.encode(plaintext.expose())}))
        }
        Command::Status => wire(store.fleet_epoch_status()?),
        Command::Mint(members) => wire(store.fleet_epoch_mint(&members, peers)?),
        Command::Commit(p) => wire(store.fleet_epoch_commit(p.epoch, &p.mint_id)?),
        Command::Discard(p) => wire(store.fleet_epoch_discard(p.epoch, &p.mint_id)?),
        Command::Import(wrap) => wire(store.fleet_epoch_import(&wrap, peers)?),
        Command::WrapFor(member) => {
            Ok(json!({"wrap": store.fleet_epoch_wrap_for(&member, peers)?}))
        }
    }
}
