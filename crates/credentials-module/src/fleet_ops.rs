//! Fleet boundary: attested caller domains, closed grammar and checked Callosum peers.
//! All epoch transitions and membership decisions belong to the encrypted store.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::fleet::{
    validate_batch, FleetError, FleetOpenInput, FleetPeer, FleetSealInput, FleetSealer, FleetWrap,
    MAX_BATCH_ITEMS, MAX_BYTES,
};
use credentials_core::secret::Secret;
use credentials_core::EncryptedStore;
use serde::Deserialize;
use serde_json::{json, Value};
use subc_protocol::Principal;

use crate::federation::ingress::callosum_lookup;
use crate::federation::outbound::{OutboundClient, ADMIN_OP_BUDGET};

pub const OPS: [&str; 10] = [
    "fleet.epoch_seal",
    "fleet.epoch_open",
    "fleet.epoch_seal_batch",
    "fleet.epoch_open_batch",
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

fn sealer(principal: Option<&Principal>) -> Option<FleetSealer> {
    match principal {
        Some(Principal::Reserved { module_id }) if module_id == "entorhinal" => {
            Some(FleetSealer::Entorhinal)
        }
        Some(Principal::Reserved { module_id }) if module_id == "prefrontal" => {
            Some(FleetSealer::Prefrontal)
        }
        Some(Principal::Reserved { module_id }) if module_id == "magic-context" => {
            Some(FleetSealer::MagicContext)
        }
        _ => None,
    }
}

pub fn admitted(principal: Option<&Principal>, method: &str) -> bool {
    match sealer(principal) {
        Some(FleetSealer::Entorhinal) => is_op(method),
        Some(FleetSealer::Prefrontal | FleetSealer::MagicContext) => matches!(
            method,
            "fleet.epoch_seal"
                | "fleet.epoch_open"
                | "fleet.epoch_seal_batch"
                | "fleet.epoch_open_batch"
        ),
        None => false,
    }
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
struct Batch<T> {
    items: Vec<T>,
}

struct SealItem {
    aad: Secret<Vec<u8>>,
    plaintext: Secret<Vec<u8>>,
}
impl SealItem {
    fn input(&self) -> FleetSealInput<'_> {
        FleetSealInput {
            aad: self.aad.expose(),
            plaintext: self.plaintext.expose(),
        }
    }
}
struct OpenItem {
    epoch: u32,
    nonce: Secret<Vec<u8>>,
    ciphertext: Secret<Vec<u8>>,
    aad: Secret<Vec<u8>>,
}
impl OpenItem {
    fn input(&self) -> FleetOpenInput<'_> {
        FleetOpenInput {
            epoch: self.epoch,
            nonce: self.nonce.expose(),
            ciphertext: self.ciphertext.expose(),
            aad: self.aad.expose(),
        }
    }
}

fn seal_item(p: Seal) -> Result<SealItem, FleetError> {
    Ok(SealItem {
        aad: decode(&p.aad, MAX_BYTES)?,
        plaintext: decode(&p.plaintext, MAX_BYTES)?,
    })
}
fn open_item(p: Open) -> Result<OpenItem, FleetError> {
    let item = OpenItem {
        epoch: p.epoch,
        nonce: decode(&p.nonce, 24)?,
        ciphertext: decode(&p.ciphertext, MAX_BYTES + 16)?,
        aad: decode(&p.aad, MAX_BYTES)?,
    };
    item.input().validate()?;
    Ok(item)
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
    Seal(SealItem),
    Open(OpenItem),
    SealBatch(Vec<SealItem>),
    OpenBatch(Vec<OpenItem>),
    Status,
    Mint(Vec<String>),
    Commit(Transition),
    Discard(Transition),
    Import(FleetWrap),
    WrapFor(String),
}

fn command(method: &str, params: &Value) -> Result<Command, FleetError> {
    Ok(match method {
        "fleet.epoch_seal" => Command::Seal(seal_item(parse(params)?)?),
        "fleet.epoch_open" => Command::Open(open_item(parse(params)?)?),
        "fleet.epoch_seal_batch" => {
            let p: Batch<Seal> = parse(params)?;
            if !(1..=MAX_BATCH_ITEMS).contains(&p.items.len()) {
                return Err(FleetError::InvalidParams);
            }
            let items = p
                .items
                .into_iter()
                .map(seal_item)
                .collect::<Result<Vec<_>, _>>()?;
            validate_batch(
                items.len(),
                items.iter().map(|item| item.input().validate()),
            )?;
            Command::SealBatch(items)
        }
        "fleet.epoch_open_batch" => {
            let p: Batch<Open> = parse(params)?;
            if !(1..=MAX_BATCH_ITEMS).contains(&p.items.len()) {
                return Err(FleetError::InvalidParams);
            }
            let items = p
                .items
                .into_iter()
                .map(open_item)
                .collect::<Result<Vec<_>, _>>()?;
            validate_batch(
                items.len(),
                items.iter().map(|item| item.input().validate()),
            )?;
            Command::OpenBatch(items)
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
    // Admission implies a sealer; checking both keeps a caller with no domain out
    // without a panic path, whatever the admission table says.
    let Some(sealer) = sealer(principal).filter(|_| admitted(principal, method)) else {
        return Answer::Reply(body(FleetError::NotFound));
    };
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
        tokio::task::spawn_blocking(move || execute(&store, sealer, command, &peers))
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
    sealer: FleetSealer,
    command: Command,
    peers: &[FleetPeer],
) -> Result<Value, FleetError> {
    fn wire(value: impl serde::Serialize) -> Result<Value, FleetError> {
        serde_json::to_value(value).map_err(|_| FleetError::StoreError)
    }
    match command {
        Command::Seal(item) => {
            wire(store.fleet_epoch_seal(sealer, item.aad.expose(), item.plaintext.expose())?)
        }
        Command::Open(item) => {
            let plaintext = store.fleet_epoch_open(
                sealer,
                item.epoch,
                item.nonce.expose(),
                item.ciphertext.expose(),
                item.aad.expose(),
            )?;
            Ok(json!({"plaintext": URL_SAFE_NO_PAD.encode(plaintext.expose())}))
        }
        Command::SealBatch(items) => {
            let inputs: Vec<_> = items.iter().map(SealItem::input).collect();
            Ok(json!({"items":store.fleet_epoch_seal_batch(sealer, &inputs)?}))
        }
        Command::OpenBatch(items) => {
            let inputs: Vec<_> = items.iter().map(OpenItem::input).collect();
            let replies: Vec<_> = store
                .fleet_epoch_open_batch(sealer, &inputs)?
                .into_iter()
                .map(|result| match result {
                    Ok(plaintext) => {
                        json!({"plaintext": URL_SAFE_NO_PAD.encode(plaintext.expose())})
                    }
                    Err(error) => body(error),
                })
                .collect();
            Ok(json!({"items":replies}))
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
