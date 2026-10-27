//! Federation ingress: how this vault answers another member's vault.
//!
//! A peer vault reaches this one through callosum, which opens the route as itself
//! (`reserved:callosum`) and labels it with a harness naming the member it relays for.
//! Everything that decides what such a call may do lives here, in the order the call
//! meets it:
//!
//! 1. **Harness mapping** ([`map_route_caller`]): which caller a route bind speaks for.
//!    With the member-mapping gate off this is vault release 1's answer exactly; with it
//!    on, `callosum-self` keeps callosum's grants, `fed-computer:<fp>` becomes a
//!    federation channel for that member, and every other harness on callosum's routes
//!    is refused.
//! 2. **The closed op allowlist**: a federation channel answers only the federation
//!    ops on [`FEDERATION_OPS`], and refuses bearer params (handles, enrollment tokens)
//!    so neither can stand in for a member grant. The federation ops answer the uniform
//!    `not_found` on every other channel.
//! 3. **The home-side ops** ([`HomeVault::serve`]): `federation.remote_token`,
//!    `federation.report_auth_failure` and the three `federation.secret_*` ops, each
//!    running its fixed order of checks and stopping at the first refusal.
//!
//! Every credential-shaped refusal is the same `not_found` body a local scoped read
//! answers, byte for byte, so a member cannot tell "no grant" from "no such id" from
//! "not servable".
//!
//! This file is compiled into the daemon and into the test-only library, so it depends
//! on nothing in the daemon outside `federation` and `secret_use`, which the test-only
//! library also contains.

#[cfg(any(test, feature = "test-support"))]
use std::future::Future;
#[cfg(any(test, feature = "test-support"))]
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use credentials_core::agent_secret::SecretSender;
use credentials_core::audit::{AuditCtx, AuditOp, AuthEventKind, ReporterSource};
use credentials_core::engine::{EngineError, GetWithRefreshStatus, RefreshEngine};
use credentials_core::federation::{
    is_vault_transfer_id, valid_member_id, MemberGrantOperation, MemberGrantSelector,
    MEMBER_ID_PREFIX, VAULT_TRANSFER_ID,
};
use credentials_core::plan_detection::DetectedPlan;
use credentials_core::record::{CredentialKind, RecordIdentity, VaultRecord};
use credentials_core::refresh_adapters::RefreshError;
use credentials_core::store::{
    AuthEventPrincipal, AuthObservation, GrantOperation, ReleaseRequest, SealedRelease,
    SecretHomeRole, StoreOpError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subc_protocol::Principal;

use super::outbound::{management_surface, OutboundClient, RouteCall, HOME_OP_DEADLINE};
use crate::secret_use::{ForwardedUseAnswer, UseAnswer};

/// A peer asks the home for a short-lived access token (a `query`: callosum keeps no
/// reply body on disk).
pub const OP_REMOTE_TOKEN: &str = "federation.remote_token";
/// A peer forwards its consumer's report that a token was refused upstream.
pub const OP_REPORT_AUTH_FAILURE: &str = "federation.report_auth_failure";
/// A peer delivers a sealed static-key transfer.
pub const OP_TRANSFER_DELIVER: &str = "federation.transfer_deliver";

/// A peer forwards its local sender's `secret.use` to the secret home (a `query`:
/// callosum keeps no reply body on disk, and the release in it is sealed).
pub const OP_SECRET_USE: &str = "federation.secret_use";
/// A peer forwards its basal's `secret.request_flow_approval` to the secret home.
pub const OP_SECRET_REQUEST_FLOW_APPROVAL: &str = "federation.secret_request_flow_approval";
/// A peer forwards its basal's `secret.revoke_flow_grants` to the secret home.
pub const OP_SECRET_REVOKE_FLOW_GRANTS: &str = "federation.secret_revoke_flow_grants";

/// The closed allowlist of a federation channel. Nothing else is dispatched there.
pub const FEDERATION_OPS: [&str; 6] = [
    OP_REMOTE_TOKEN,
    OP_REPORT_AUTH_FAILURE,
    OP_TRANSFER_DELIVER,
    OP_SECRET_USE,
    OP_SECRET_REQUEST_FLOW_APPROVAL,
    OP_SECRET_REVOKE_FLOW_GRANTS,
];

/// The HPKE `info` of a sealed token reply. A transfer envelope uses a different
/// literal, so a reply can never be opened as a transfer or the other way round.
pub const REMOTE_TOKEN_INFO: &[u8] = b"cortexkit/claustrum/remote-token/v1";

/// The HPKE `info` of a sealed `federation.secret_use` release. Distinct from the token
/// reply's and the transfer envelope's, so none of the three opens as another.
pub const SECRET_RELEASE_INFO: &[u8] = b"cortexkit/claustrum/secret-release/v1";

/// The module id of callosum, which relays other computers' calls on routes it opens
/// as itself.
pub const CALLOSUM_MODULE_ID: &str = "callosum";

/// The harness callosum sets on its own calls: the only harness that keeps callosum's
/// grants once the member-mapping gate is on.
pub const CALLOSUM_SELF_HARNESS: &str = "callosum-self";

/// Every harness callosum sets on a relayed call starts with this, and such a harness
/// never resolves to callosum's own grants, whatever the gate says.
const FORWARDED_HARNESS_PREFIX: &str = "fed-";

/// Callosum's route key in the outbound client's binding cache.
const CALLOSUM_ROUTE_KEY: &str = "callosum";

/// The `auth_events` subject for a refusal that happens before the request names a
/// credential (an unpaired member, a malformed request).
const UNADDRESSED_SUBJECT: &str = "federation.remote_token";

/// True for the federation ops on [`FEDERATION_OPS`].
pub fn is_federation_op(method: &str) -> bool {
    FEDERATION_OPS.contains(&method)
}

// ---------------------------------------------------------------------------------
// Harness mapping
// ---------------------------------------------------------------------------------

/// The member-mapping gate as one federation decision read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingGate {
    /// Release-1 behaviour: callosum keeps its grants unless the harness starts `fed-`.
    Off,
    /// Member mapping: only `callosum-self` keeps callosum's grants.
    On,
    /// The setting could not be read. Treated as the stricter of the two states for
    /// callosum's own routes (only `callosum-self` keeps its grants) and maps no
    /// member, so a store fault can neither widen callosum's reach nor open a
    /// federation channel.
    Unreadable,
}

impl MappingGate {
    /// The gate from the store's live read.
    pub fn from_store(read: Result<bool, StoreOpError>) -> Self {
        match read {
            Ok(true) => Self::On,
            Ok(false) => Self::Off,
            Err(_) => Self::Unreadable,
        }
    }
}

/// Who one route bind speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCaller {
    /// The bind's own principal, or `None` for a caller with none. Served by the read
    /// surface as it always was: scoped ops authorize on the principal, handle reads
    /// on the handle. The federation ops answer the uniform `not_found` here.
    Principal(Option<Principal>),
    /// A federation channel: callosum relaying a call from `member`. Only the
    /// federation ops answer, and only with the member's own grants.
    Member(String),
    /// A callosum-authenticated phone, isolated from credential and federation reads.
    Phone(String),
    /// A refused channel: every op, handle reads included, answers the uniform
    /// `not_found`.
    Refused,
}

impl RouteCaller {
    /// The principal the read surface and the admin plane may use. A federation or
    /// refused channel has none, so even an op that reached them by mistake would be
    /// refused as an unknown caller.
    pub fn principal(&self) -> Option<Principal> {
        match self {
            Self::Principal(principal) => principal.clone(),
            Self::Member(_) | Self::Phone(_) | Self::Refused => None,
        }
    }
}

/// True for a principal the daemon attested as `reserved:callosum`.
pub fn is_callosum(principal: &Principal) -> bool {
    matches!(principal, Principal::Reserved { module_id } if module_id == CALLOSUM_MODULE_ID)
}

/// Map one bind's daemon-stamped principal and opener harness to the caller it
/// speaks for.
///
/// The harness is read only on `reserved:callosum` routes: callosum is the one
/// principal whose harness the daemon passes through from an opener it attested, and
/// any other principal's harness is ignored so no caller can change its own reach by
/// choosing a string. `direct`, unverified and absent principals never map to a
/// member.
pub fn map_route_caller(principal: &Principal, harness: &str, gate: MappingGate) -> RouteCaller {
    map_route_caller_with_phone(principal, harness, gate, MappingGate::Off)
}

pub fn map_route_caller_with_phone(
    principal: &Principal,
    harness: &str,
    gate: MappingGate,
    phone_gate: MappingGate,
) -> RouteCaller {
    if !is_callosum(principal) {
        return RouteCaller::Principal(Some(principal.clone()));
    }
    let keeps_grants = RouteCaller::Principal(Some(principal.clone()));
    if gate == MappingGate::On && phone_gate == MappingGate::On {
        if let Some(fp) = harness.strip_prefix("fed-phone:") {
            if fp.len() == 32
                && fp
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return RouteCaller::Phone(fp.to_owned());
            }
        }
    }
    match gate {
        // Vault release 1, unchanged: a relayed call gets no principal (handle reads
        // still run, which is the documented gate-off residual), and every other
        // harness keeps callosum's grants.
        MappingGate::Off if harness.starts_with(FORWARDED_HARNESS_PREFIX) => {
            RouteCaller::Principal(None)
        }
        MappingGate::Off => keeps_grants,
        MappingGate::On | MappingGate::Unreadable if harness == CALLOSUM_SELF_HARNESS => {
            keeps_grants
        }
        MappingGate::On if valid_member_id(harness) => RouteCaller::Member(harness.to_string()),
        MappingGate::On | MappingGate::Unreadable => RouteCaller::Refused,
    }
}

/// Whether a request's params carry a bearer credential. Enrollment tokens and
/// handles are never resolved on a federation channel: either would authorize the
/// call by something other than the member's own grants.
pub fn carries_bearer(params: &Value) -> bool {
    params.as_object().is_some_and(|params| {
        params.contains_key("handle") || params.contains_key("enrollment_token")
    })
}

// ---------------------------------------------------------------------------------
// Callosum lookups
// ---------------------------------------------------------------------------------

/// The answer to a callosum lookup about one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// Callosum answered and the member has the thing asked for.
    Found(T),
    /// Callosum answered and the member does not: unpaired, or no key announced. A
    /// malformed or unexpected answer also lands here, so the home refuses rather
    /// than guesses.
    Absent,
    /// Callosum could not answer in time or said it was not ready: transient.
    Unavailable,
}

/// A peer's announced transfer key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKey {
    /// The X25519 public half.
    pub public: [u8; 32],
    /// Computed here from `public`, never taken from callosum.
    pub key_id: String,
}

/// The fingerprint part of a member id.
fn member_fingerprint(member_id: &str) -> Option<&str> {
    member_id.strip_prefix(MEMBER_ID_PREFIX)
}

/// The refusal code of a callosum answer that is a refusal rather than a reply: an
/// object with a string `code` and none of `reply_member`. Callosum's refusals arrive
/// as the route's error body, which the outbound client hands back as the value.
fn refusal_code<'a>(body: &'a Value, reply_member: &str) -> Option<&'a str> {
    if body.get(reply_member).is_some() {
        return None;
    }
    body.get("code").and_then(Value::as_str)
}

/// Decode a `callosum.paired_devices_read` reply into `member_id`'s current pairing id.
///
/// The reply shape is callosum's current one, not yet checked against the vector
/// files callosum publishes for it (tag `paired-devices-vectors-v1.3`); once those
/// are vendored, the tests below should read them. The shape:
/// `{"devices":[{"class","fingerprint","pairing_id"}]}`,
/// sorted by fingerprint, with an optional top-level `self` (version 1.3) that this
/// decoder ignores. A device carries no member id: it is `fed-<class>:<fingerprint>`,
/// so only a device of class `computer` can be a member. An unpaired member is simply
/// absent. Extra fields are tolerated everywhere.
///
/// Fails closed: anything malformed, a duplicate entry or an empty `pairing_id` reads
/// as unpaired, and so does any refusal except the two callosum names retryable
/// (`fed_not_ready`, `fed_target_unavailable`), which are transient.
pub fn decode_paired_devices(body: &Value, member_id: &str) -> Lookup<String> {
    if let Some(code) = refusal_code(body, "devices") {
        return match code {
            "fed_not_ready" | "fed_target_unavailable" => Lookup::Unavailable,
            _ => Lookup::Absent,
        };
    }
    let Some(devices) = body.get("devices").and_then(Value::as_array) else {
        return Lookup::Absent;
    };
    let mut found: Option<String> = None;
    for device in devices {
        let class = device.get("class").and_then(Value::as_str);
        let fingerprint = device.get("fingerprint").and_then(Value::as_str);
        let (Some(class), Some(fingerprint)) = (class, fingerprint) else {
            continue;
        };
        if format!("fed-{class}:{fingerprint}") != member_id {
            continue;
        }
        let Some(pairing_id) = device
            .get("pairing_id")
            .and_then(Value::as_str)
            .filter(|pairing_id| !pairing_id.is_empty())
        else {
            return Lookup::Absent;
        };
        if found.is_some() {
            // Two entries for one member: callosum's list is keyed on the fingerprint,
            // so this is damage, and neither pairing id can be trusted.
            return Lookup::Absent;
        }
        found = Some(pairing_id.to_string());
    }
    found.map_or(Lookup::Absent, Lookup::Found)
}

/// Decode a `callosum.peer_keys_read` reply into `member_id`'s announced
/// `vault_transfer_x25519` key.
///
/// The reply shape is callosum's current one, not yet checked against the vector
/// files callosum publishes for it (tag `paired-devices-vectors-v1.3`). The shape:
/// `{"peers":[{"fingerprint", "key_record":{"keys":
/// {"vault_transfer_x25519":{"pub":"<hex>","version":"<n>"}}}}]}`, every admitted
/// peer, no filter, `machine_id`/`key_record`/`registry_platform` optional. The entry
/// carries no class: the caller must already know from `paired_devices_read` that this
/// fingerprint is a `computer` (the home's pairing check does).
///
/// Callosum checks only that `pub` is 1 to 256 hex characters, so this refuses
/// anything but exactly 64 lowercase hex. No key id travels: it is computed here.
/// Fails closed: malformed, duplicate or absent reads as no key; `fed_not_ready` is
/// transient.
pub fn decode_peer_transfer_key(body: &Value, member_id: &str) -> Lookup<PeerKey> {
    if let Some(code) = refusal_code(body, "peers") {
        return match code {
            "fed_not_ready" => Lookup::Unavailable,
            _ => Lookup::Absent,
        };
    }
    let Some(fingerprint) = member_fingerprint(member_id) else {
        return Lookup::Absent;
    };
    let Some(peers) = body.get("peers").and_then(Value::as_array) else {
        return Lookup::Absent;
    };
    let mut matching = peers
        .iter()
        .filter(|peer| peer.get("fingerprint").and_then(Value::as_str) == Some(fingerprint));
    let (Some(peer), None) = (matching.next(), matching.next()) else {
        return Lookup::Absent;
    };
    let Some(public_hex) = peer
        .get("key_record")
        .and_then(|record| record.get("keys"))
        .and_then(|keys| keys.get("vault_transfer_x25519"))
        .and_then(|key| key.get("pub"))
        .and_then(Value::as_str)
    else {
        return Lookup::Absent;
    };
    match decode_x25519_hex(public_hex) {
        Some(public) => Lookup::Found(PeerKey {
            key_id: credentials_core::signing::key_id_for_public(&public),
            public,
        }),
        None => Lookup::Absent,
    }
}

/// The member id callosum gives the computer whose Noise static key is `public`:
/// `fed-computer:` followed by the hex of the first 16 bytes of SHA-256 over the key.
pub fn member_id_for_static_key(public: &[u8; 32]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, public);
    let fingerprint: String = digest.as_ref()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{MEMBER_ID_PREFIX}{fingerprint}")
}

/// This computer's own member id, from the top-level `self` member a version 1.3
/// `callosum.paired_devices_read` reply carries:
/// `"self":{"static_public_key_hex":"<64 lowercase hex>"}`.
///
/// `Absent` when the reply has no usable `self` (a callosum older than 1.3, or a key
/// that is not exactly 64 lowercase hex): the id cannot be checked, and a caller must
/// refuse rather than accept a typed id unchecked. `Unavailable` for any callosum
/// refusal, which says nothing about this computer's id.
pub fn decode_self_member(body: &Value) -> Lookup<String> {
    if refusal_code(body, "devices").is_some() {
        return Lookup::Unavailable;
    }
    body.get("self")
        .and_then(|own| own.get("static_public_key_hex"))
        .and_then(Value::as_str)
        .and_then(decode_x25519_hex)
        .map_or(Lookup::Absent, |public| {
            Lookup::Found(member_id_for_static_key(&public))
        })
}

/// One call to callosum's management surface (`method`, no params) through `client`,
/// within what is left of `budget`. `None` for no client, no time left or no answer,
/// all of which a caller treats as transient. A callosum refusal comes back as the
/// value, for the decoders above to classify.
pub async fn callosum_lookup(
    client: Option<&OutboundClient>,
    method: &str,
    budget: tokio::time::Instant,
) -> Option<Value> {
    let client = client?;
    let left = budget
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|left| !left.is_zero())?;
    client
        .call(
            CALLOSUM_ROUTE_KEY,
            RouteCall {
                target: management_surface(CALLOSUM_MODULE_ID),
                prelude: None,
                request: json!({ "method": method, "params": {} }),
            },
            left,
        )
        .await
        .ok()
}

/// Exactly 64 lowercase hex characters, as 32 bytes.
fn decode_x25519_hex(value: &str) -> Option<[u8; 32]> {
    if !credentials_core::federation::is_lower_hex_sha256(value) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------

/// Why a home-side op refused. Rendered by [`Refusal::body`] in the `{code, class}`
/// shape every read-surface refusal uses, plus `remedy_member` where the spec names one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// The uniform refusal: no grant, stale pairing, unknown id, ungranted category,
    /// ineligible or projection-refused record, or a home id that is not this vault.
    NotFound,
    /// The same answer a local read gives for the record's own condition.
    Local(&'static str, &'static str),
    /// A callosum lookup failed or the work ran past the home's budget: transient.
    HomeUnavailable,
    /// A setup fact about the attested caller or this home, naming who must fix it.
    SetupIncomplete(String),
    /// This vault's own secret-home setting names a member while its self id is unset
    /// or equal to it, so it cannot tell whether it is the home. Names this vault when
    /// its self id is known.
    SecretHomeSetupIncomplete(Option<String>),
    /// A report whose provider status is not evidence of credential death.
    StatusNotCredentialDeath,
    /// The request is malformed. Answered as an `Error` frame, like every other
    /// undecodable request on this wire.
    InvalidParams(String),
}

/// The local read surface's classes for the codes a home read can answer, so a member
/// sees the same code and class a local consumer would.
const NEEDS_REAUTH: Refusal = Refusal::Local("needs_reauth", "auth_required");
const REFRESH_UNSUPPORTED: Refusal = Refusal::Local("refresh_unsupported", "permanent");
const REFRESH_FAILED: Refusal = Refusal::Local("refresh_failed", "transient");
const STORE_ERROR: Refusal = Refusal::Local("store_error", "transient");
const VAULT_LOCKED: Refusal = Refusal::Local("vault_locked", "transient");
const CORRUPT: Refusal = Refusal::Local("corrupt", "permanent");
const TTL_UNSATISFIABLE: Refusal = Refusal::Local("ttl_unsatisfiable", "context_overflow");

#[derive(Serialize)]
struct RefusalBody<'a> {
    code: &'a str,
    class: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remedy_member: Option<&'a str>,
}

impl Refusal {
    fn body(&self) -> Value {
        let (code, class, remedy_member) = match self {
            Self::NotFound => ("not_found", "permanent", None),
            Self::Local(code, class) => (*code, *class, None),
            Self::HomeUnavailable => ("home_unavailable", "transient", None),
            Self::SetupIncomplete(member) => (
                "remote_setup_incomplete",
                "permanent",
                Some(member.as_str()),
            ),
            Self::SecretHomeSetupIncomplete(member) => {
                ("remote_setup_incomplete", "permanent", member.as_deref())
            }
            Self::StatusNotCredentialDeath => {
                ("report_status_not_credential_death", "permanent", None)
            }
            Self::InvalidParams(_) => ("invalid_params", "permanent", None),
        };
        json!(RefusalBody {
            code,
            class,
            remedy_member,
        })
    }
}

/// The same mapping the local read surface applies to a store error
/// (`read_surface::map_store_error`); kept beside it in meaning so a member and a local
/// consumer see one code for one condition.
fn map_store_error(error: &StoreOpError) -> Refusal {
    use credentials_core::envelope::EnvelopeError;
    match error {
        StoreOpError::NotFound => Refusal::NotFound,
        StoreOpError::NeedsReauth => NEEDS_REAUTH,
        StoreOpError::Decrypt(EnvelopeError::KeyMismatch { .. }) => VAULT_LOCKED,
        StoreOpError::Quarantined | StoreOpError::Corrupt(_) | StoreOpError::Decrypt(_) => CORRUPT,
        _ => REFRESH_FAILED,
    }
}

/// The same mapping the local read surface applies to an engine error
/// (`read_surface::map_engine_error`).
fn map_engine_error(error: &EngineError) -> Refusal {
    match error {
        EngineError::Store(error) => map_store_error(error),
        EngineError::UnknownAdapter(_) => REFRESH_UNSUPPORTED,
        EngineError::RefreshFailed(
            RefreshError::InvalidGrant(_) | RefreshError::SubscriptionRequired,
        ) => NEEDS_REAUTH,
        EngineError::RefreshFailed(_) => REFRESH_FAILED,
    }
}

/// The `{code, class}` pair a member receives for a store error, exposed so the daemon
/// can test that it agrees with the local read surface's mapping.
pub fn store_error_wire(error: &StoreOpError) -> (String, String) {
    wire_pair(&map_store_error(error))
}

/// The `{code, class}` pair a member receives for an engine error, exposed so the
/// daemon can test that it agrees with the local read surface's mapping.
pub fn engine_error_wire(error: &EngineError) -> (String, String) {
    wire_pair(&map_engine_error(error))
}

fn wire_pair(refusal: &Refusal) -> (String, String) {
    let body = refusal.body();
    (
        body["code"].as_str().unwrap_or_default().to_string(),
        body["class"].as_str().unwrap_or_default().to_string(),
    )
}

// ---------------------------------------------------------------------------------
// The access-token projection
// ---------------------------------------------------------------------------------

/// The token a home may serve for `record`, or `None` when the record must be refused.
///
/// A rotating login's refresh token must never leave the home, and the record's
/// `payload` is what a get returns. Every production constructor sets the payload to
/// the access token, but the admin store op accepts any client-supplied record and
/// sealing never compares the two, so this checks it: the payload must equal the
/// access token byte for byte, the token must be non-empty, and it must equal none of
/// the non-empty refresh components (`oauth.refresh_token`, its first `|` segment,
/// `oauth.client_secret`, and for adapter `meta` the session's `identity_token` and
/// nested `refresh_token`).
pub fn project_access_token(record: &VaultRecord) -> Option<&str> {
    let oauth = record.oauth.as_ref()?;
    let token = oauth.access_token.expose();
    if token.is_empty() || record.payload.expose() != token.as_bytes() {
        return None;
    }
    let refresh = oauth.refresh_token.expose();
    let mut components: Vec<String> = vec![refresh.to_string()];
    if let Some((first, _)) = refresh.split_once('|') {
        components.push(first.to_string());
    }
    if let Some(secret) = oauth.client_secret.as_ref() {
        components.push(secret.expose().to_string());
    }
    if record.refresh_adapter.as_deref()
        == Some(credentials_core::refresh_adapters::meta::ADAPTER_NAME)
    {
        // The Meta session is JSON in the refresh-token slot. Read loosely: a field
        // that is missing or not a string is simply not a component.
        if let Ok(session) = serde_json::from_str::<Value>(refresh) {
            for field in ["identity_token", "refresh_token"] {
                if let Some(value) = session.get(field).and_then(Value::as_str) {
                    components.push(value.to_string());
                }
            }
        }
    }
    if components
        .iter()
        .any(|component| !component.is_empty() && component == token)
    {
        return None;
    }
    Some(token)
}

/// A known expiry meets a demand only when its remaining lifetime is strictly greater
/// than it, as on the local read surface; an absent expiry cannot prove a short life.
fn meets_min_ttl(record: &VaultRecord, min_ttl_ms: i64) -> bool {
    record
        .expires_at_ms
        .map(|expires_at_ms| wall_now_ms().saturating_add(min_ttl_ms) < expires_at_ms)
        .unwrap_or(true)
}

fn wall_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------
// Wire bodies
// ---------------------------------------------------------------------------------

/// `federation.remote_token` params. Unknown fields are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteTokenParams {
    /// The token `aad` exactly as the requester serialized it. The home seals over
    /// these bytes, never a rebuilt copy, and the credential id comes only from here.
    aad: String,
    /// The requester's demand on the token's remaining lifetime.
    #[serde(default)]
    min_ttl_ms: Option<i64>,
}

/// The token `aad`: `{credential_id, requester, home, nonce, recipient_key_id}`.
/// Unknown, missing and duplicate fields are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenAad {
    credential_id: String,
    requester: String,
    home: String,
    nonce: String,
    recipient_key_id: String,
}

/// `federation.report_auth_failure` params. Unknown fields are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportParams {
    credential_id: String,
    record_version: u64,
    provider_status: u16,
    #[serde(default)]
    reporter_source: Option<String>,
}

/// The sealed plaintext of a token reply. Exactly these fields: no refresh token and
/// no `oauth` struct can be expressed here.
#[derive(Debug, Serialize)]
struct TokenReply<'a> {
    payload: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recheck_in_ms: Option<i64>,
    record_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    identity: &'a RecordIdentity,
    categories: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_adapter: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detected_plan: Option<&'a DetectedPlan>,
}

/// Parse the received aad bytes strictly. Over the seal's aad cap is malformed too.
fn parse_token_aad(bytes: &str) -> Result<TokenAad, Refusal> {
    if bytes.len() > credentials_core::kem::MAX_SEAL_AAD {
        return Err(Refusal::InvalidParams("aad is over its size cap".into()));
    }
    let aad: TokenAad = serde_json::from_str(bytes)
        .map_err(|error| Refusal::InvalidParams(format!("aad: {error}")))?;
    if aad.credential_id.is_empty()
        || !credentials_core::federation::is_lower_hex_16_bytes(&aad.nonce)
        || !valid_member_id(&aad.requester)
        || !valid_member_id(&aad.home)
        || aad.recipient_key_id.is_empty()
    {
        return Err(Refusal::InvalidParams(
            "aad fields are not well formed".into(),
        ));
    }
    Ok(aad)
}

/// `federation.secret_use` params: exactly `{aad, sender, call}`. Unknown fields are
/// refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretUseParams {
    /// The release `aad` exactly as the requester serialized it. The home seals over
    /// these bytes, never a rebuilt copy.
    aad: String,
    /// Which local sender the asking vault authenticated: `aft`, `cerebellum` or `basal`.
    sender: String,
    /// The sender's `secret.use` params, unchanged.
    call: Value,
}

/// The release `aad`: `{secret_name, requester, home, nonce, recipient_key_id,
/// call_sha256}`. Unknown, missing and duplicate fields are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretAad {
    secret_name: String,
    requester: String,
    home: String,
    nonce: String,
    recipient_key_id: String,
    call_sha256: String,
}

/// Parse the received release aad bytes strictly, as [`parse_token_aad`] does.
fn parse_secret_aad(bytes: &str) -> Result<SecretAad, Refusal> {
    if bytes.len() > credentials_core::kem::MAX_SEAL_AAD {
        return Err(Refusal::InvalidParams("aad is over its size cap".into()));
    }
    let aad: SecretAad = serde_json::from_str(bytes)
        .map_err(|error| Refusal::InvalidParams(format!("aad: {error}")))?;
    if aad.secret_name.is_empty()
        || !credentials_core::federation::is_lower_hex_16_bytes(&aad.nonce)
        || !valid_member_id(&aad.requester)
        || !valid_member_id(&aad.home)
        || aad.recipient_key_id.is_empty()
        || !credentials_core::federation::is_lower_hex_sha256(&aad.call_sha256)
    {
        return Err(Refusal::InvalidParams(
            "aad fields are not well formed".into(),
        ));
    }
    Ok(aad)
}

/// The local sender a `federation.secret_use` names. Anything else is malformed.
fn forwarded_sender(sender: &str) -> Option<SecretSender> {
    match sender {
        "aft" => Some(SecretSender::Aft),
        "cerebellum" => Some(SecretSender::Cerebellum),
        "basal" => Some(SecretSender::Basal),
        _ => None,
    }
}

/// The release aad's `call_sha256`: the lower-hex SHA-256 of the RFC 8785 encoding of
/// `{"sender": sender, "call": call}`.
///
/// `None` when `call` holds a number that is not an integer within JSON's exact range
/// (magnitude at most 2^53 - 1): no `secret.use` param is such a number, and leaving
/// them out keeps the encoding here exactly RFC 8785's without its float rules.
pub fn secret_call_sha256(sender: &str, call: &Value) -> Option<String> {
    let mut canonical = Vec::new();
    write_canonical(&json!({ "sender": sender, "call": call }), &mut canonical)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &canonical);
    Some(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

/// Append the RFC 8785 encoding of `value` to `out`: object members sorted by their
/// keys' UTF-16 code units, as the RFC requires; no whitespace; strings in serde_json's
/// minimal escaping, which matches the RFC's; numbers only as exact-range integers.
fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Option<()> {
    const MAX_EXACT: u64 = 9_007_199_254_740_991;
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            out.extend_from_slice(&serde_json::to_vec(value).ok()?);
        }
        Value::Number(number) => {
            let exact = number.as_u64().is_some_and(|n| n <= MAX_EXACT)
                || number
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() <= MAX_EXACT);
            if !exact {
                return None;
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&serde_json::to_vec(key).ok()?);
                out.push(b':');
                write_canonical(&members[key], out)?;
            }
            out.push(b'}');
        }
    }
    Some(())
}

/// The refusal for a failed seal to `member`'s announced key from this home's
/// (`self_id`) transfer key: a bad recipient key is the member's setup to fix, an
/// unusable sender key this home's.
fn seal_refusal(error: credentials_core::kem::SealError, member: &str, self_id: &str) -> Refusal {
    match error {
        credentials_core::kem::SealError::InvalidRecipient => {
            Refusal::SetupIncomplete(member.to_string())
        }
        credentials_core::kem::SealError::TooLarge => CORRUPT,
        credentials_core::kem::SealError::UnusableKey
        | credentials_core::kem::SealError::Failed => Refusal::SetupIncomplete(self_id.to_string()),
    }
}

// ---------------------------------------------------------------------------------
// The home vault
// ---------------------------------------------------------------------------------

/// What [`HomeVault::serve`] hands the route layer.
#[derive(Debug, Clone, PartialEq)]
pub enum HomeAnswer {
    /// The `result` body of an ordinary `Response` frame: a sealed reply, an
    /// acceptance, or a `{code, class}` refusal.
    Reply(Value),
    /// A malformed request, answered as an `invalid_params` `Error` frame.
    InvalidParams(String),
}

/// A future the home awaits between the serving read and the `remote_issue` audit
/// transaction. See [`HomeVault::with_issue_audit_gate`].
#[cfg(any(test, feature = "test-support"))]
pub type IssueAuditGate = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// A stand-in for callosum's management surface: the answer to one lookup by method
/// name, `None` for no answer. See [`HomeVault::with_callosum_stub`].
#[cfg(any(test, feature = "test-support"))]
pub type CallosumStub = Arc<dyn Fn(&str) -> Option<Value> + Send + Sync>;

/// This vault in its role as home: it answers other members' federation ops.
pub struct HomeVault {
    engine: Arc<RefreshEngine>,
    /// The outbound client the home uses to ask callosum about pairings and keys. Set
    /// once at startup; until then every lookup is unavailable (transient).
    callosum: OnceLock<OutboundClient>,
    /// The clock the engine's report cooldown runs on, so `recheck_in_ms` is measured
    /// on the same clock that decided to defer. Real time unless a test replaces both.
    cooldown_clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// The clock forwarded secret ops decide grant, request and receipt expiry on. Real
    /// time unless a test replaces it.
    secret_clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    op_deadline: Duration,
    #[cfg(any(test, feature = "test-support"))]
    issue_audit_gate: Option<IssueAuditGate>,
    #[cfg(any(test, feature = "test-support"))]
    callosum_stub: Option<CallosumStub>,
}

impl std::fmt::Debug for HomeVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeVault")
            .field("callosum", &self.callosum.get())
            .field("op_deadline", &self.op_deadline)
            .finish_non_exhaustive()
    }
}

impl HomeVault {
    pub fn new(engine: Arc<RefreshEngine>) -> Self {
        Self {
            engine,
            callosum: OnceLock::new(),
            cooldown_clock: Arc::new(wall_now_ms),
            secret_clock: Arc::new(wall_now_ms),
            op_deadline: HOME_OP_DEADLINE,
            #[cfg(any(test, feature = "test-support"))]
            issue_audit_gate: None,
            #[cfg(any(test, feature = "test-support"))]
            callosum_stub: None,
        }
    }

    /// Measure `recheck_in_ms` on `clock`. It must be the clock the engine's report
    /// cooldown runs on (`RefreshEngine::with_clock`); only tests change either.
    pub fn with_cooldown_clock(mut self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.cooldown_clock = clock;
        self
    }

    /// Decide forwarded secret ops on `clock` instead of real time. Only tests change it.
    pub fn with_secret_clock(mut self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.secret_clock = clock;
        self
    }

    /// Await `gate` after the serving read and before the `remote_issue` audit
    /// transaction. A test seam with no production caller: it is how a test pauses a
    /// fetch at exactly that point to re-create or refresh the record underneath it
    /// and prove the audit transaction notices.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_issue_audit_gate(mut self, gate: IssueAuditGate) -> Self {
        self.issue_audit_gate = Some(gate);
        self
    }

    /// Answer every callosum lookup from `stub` instead of the outbound client. A test
    /// seam with no production caller: it lets a test drive the home's pairing and
    /// announced-key checks, including callosum timing out or not being ready, without
    /// a callosum.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_callosum_stub(mut self, stub: CallosumStub) -> Self {
        self.callosum_stub = Some(stub);
        self
    }

    /// Attach the outbound client callosum lookups go through. Only the first call
    /// takes effect; returns whether this one did.
    pub fn attach_outbound(&self, client: OutboundClient) -> bool {
        self.callosum.set(client).is_ok()
    }

    /// Whether an outbound client is attached.
    pub fn has_outbound(&self) -> bool {
        self.callosum.get().is_some()
    }

    /// The outbound client attached at startup, shared with this vault's admin ops
    /// (they make their own callosum lookups and deliveries with it). It reaches no
    /// part of [`Self::serve`]: a federation op still goes through every check there.
    pub fn outbound(&self) -> Option<&OutboundClient> {
        self.callosum.get()
    }

    /// Answer one federation op from `member`, the attested harness member of a
    /// federation channel. `method` outside the allowlist answers the uniform
    /// `not_found`; the whole op runs inside the home's 1.5 s budget, and running past
    /// it answers `home_unavailable` (transient).
    pub async fn serve(&self, member: &str, method: &str, params: &Value) -> HomeAnswer {
        // Step 1: the closed allowlist, then the bearer-params refusal it carries.
        if !is_federation_op(method) {
            return HomeAnswer::Reply(json!({ "error": Refusal::NotFound.body() }));
        }
        let budget = tokio::time::Instant::now() + self.op_deadline;
        let outcome = if carries_bearer(params) {
            Err(Refusal::InvalidParams(
                "a federation channel takes no handle or enrollment_token".into(),
            ))
        } else {
            let work = async {
                match method {
                    OP_REMOTE_TOKEN => self.remote_token(member, params, budget).await,
                    OP_REPORT_AUTH_FAILURE => {
                        self.report_auth_failure(member, params, budget).await
                    }
                    // A sealed transfer delivery runs its own order of checks, under
                    // the same member mapping and the same budget as the other ops.
                    OP_TRANSFER_DELIVER => super::transfer::deliver(
                        self.engine.store(),
                        self.callosum.get(),
                        member,
                        params,
                        super::transfer::wall_now_ms(),
                        budget,
                    )
                    .await
                    .map_err(Refusal::InvalidParams),
                    OP_SECRET_USE => self.secret_use(member, params, budget).await,
                    OP_SECRET_REQUEST_FLOW_APPROVAL | OP_SECRET_REVOKE_FLOW_GRANTS => {
                        self.secret_flow_op(member, method, params, budget).await
                    }
                    _ => Err(Refusal::NotFound),
                }
            };
            match tokio::time::timeout_at(budget, work).await {
                Ok(outcome) => outcome,
                Err(_) => Err(Refusal::HomeUnavailable),
            }
        };
        match outcome {
            Ok(reply) => HomeAnswer::Reply(reply),
            Err(Refusal::InvalidParams(detail)) => HomeAnswer::InvalidParams(detail),
            Err(refusal) if method == OP_REPORT_AUTH_FAILURE => HomeAnswer::Reply(json!({
                "accepted": false,
                "error": refusal.body(),
            })),
            Err(refusal) => HomeAnswer::Reply(json!({ "error": refusal.body() })),
        }
    }

    /// `federation.remote_token`: the numbered checks below run in order and the first
    /// refusal ends the call. Step 1, the op allowlist, already ran in [`Self::serve`].
    async fn remote_token(
        &self,
        member: &str,
        params: &Value,
        budget: tokio::time::Instant,
    ) -> Result<Value, Refusal> {
        // 2. The member's current pairing id.
        let pairing_id = self
            .current_pairing(member, UNADDRESSED_SUBJECT, budget)
            .await?;
        // 3. Strict parse.
        let request: RemoteTokenParams = serde_json::from_value(params.clone())
            .map_err(|error| Refusal::InvalidParams(error.to_string()))?;
        let aad = parse_token_aad(&request.aad)?;
        // 4. The requester's own self id must name the attested caller.
        if aad.requester != member {
            return Err(Refusal::SetupIncomplete(member.to_string()));
        }
        // 5. This home's self id and Active transfer key.
        let store = self.engine.store();
        let self_id = match store.federation_self_member() {
            Ok(Some(self_id)) => self_id,
            Ok(None) => return Err(Refusal::SetupIncomplete(aad.home.clone())),
            Err(_) => return Err(STORE_ERROR),
        };
        let sender_pem = self.active_transfer_key(&self_id)?;
        // 6. The request must be meant for this home.
        if aad.home != self_id {
            self.note_refusal(&aad.credential_id, member, "home_mismatch");
            return Err(Refusal::NotFound);
        }
        // 7. A current-pairing `remote_read` grant covering the id.
        self.require_grant(member, &pairing_id, &aad.credential_id)?;
        // 8. Eligibility: local, refreshable, outside the transfer-key fence.
        self.require_eligible(member, &aad.credential_id)?;
        // 9. An announced key for the requester, matching the aad's key id.
        let peer = self.peer_key(member, budget).await?;
        if peer.key_id != aad.recipient_key_id {
            return Err(Refusal::SetupIncomplete(member.to_string()));
        }
        // 10. The local get path, with refresh, then the projection.
        let served = self
            .read_with_refresh(&aad.credential_id, request.min_ttl_ms, budget)
            .await?;
        if served.refreshed_for_min_ttl
            && request
                .min_ttl_ms
                .is_some_and(|min_ttl_ms| !meets_min_ttl(&served.record, min_ttl_ms))
        {
            return Err(TTL_UNSATISFIABLE);
        }
        let plaintext = self.token_reply(member, &aad.credential_id, &served)?;
        #[cfg(any(test, feature = "test-support"))]
        if let Some(gate) = self.issue_audit_gate.as_ref() {
            gate().await;
        }
        // 11. The `remote_issue` audit, rechecking that the material read is still the
        // stored material. Nothing is released unless this commits.
        match store.record_remote_issue_audited(
            member,
            &aad.credential_id,
            served.record.record_version,
            &served.stored_digest_hex,
        ) {
            Ok(_) => {}
            Err(StoreOpError::CasMismatch) => return Err(Refusal::HomeUnavailable),
            Err(_) => return Err(STORE_ERROR),
        }
        // 12. Seal to the requester's announced key, over the received aad bytes.
        let (enc, ciphertext) = credentials_core::kem::seal_auth(
            &sender_pem,
            &peer.public,
            &plaintext,
            REMOTE_TOKEN_INFO,
            request.aad.as_bytes(),
        )
        .map_err(|error| seal_refusal(error, member, &self_id))?;
        // First use is diagnostic, as on local scoped reads. Record it only after the
        // issue audit and sealing succeed, so a refused serve cannot look successful.
        let _ = store.record_scoped_first_use_by(
            &aad.credential_id,
            AuthEventPrincipal::Member(member),
            GrantOperation::Read,
        );
        let b64 = base64::engine::general_purpose::STANDARD;
        Ok(json!({
            "enc": b64.encode(enc),
            "ciphertext": b64.encode(ciphertext),
        }))
    }

    /// `federation.report_auth_failure`: the same pairing, grant and eligibility checks
    /// as `federation.remote_token` (its steps 2, 7 and 8), then the status check, then
    /// the version-fenced stale mark. The store function checks no status itself, so
    /// the check here is what keeps a member from driving the stale latch with a
    /// status that is not credential death.
    async fn report_auth_failure(
        &self,
        member: &str,
        params: &Value,
        budget: tokio::time::Instant,
    ) -> Result<Value, Refusal> {
        let pairing_id = self
            .current_pairing(member, OP_REPORT_AUTH_FAILURE, budget)
            .await?;
        let report: ReportParams = serde_json::from_value(params.clone())
            .map_err(|error| Refusal::InvalidParams(error.to_string()))?;
        if report.credential_id.is_empty() {
            return Err(Refusal::InvalidParams("credential_id is empty".into()));
        }
        self.require_grant(member, &pairing_id, &report.credential_id)?;
        self.require_eligible(member, &report.credential_id)?;
        if !matches!(report.provider_status, 401 | 403) {
            return Err(Refusal::StatusNotCredentialDeath);
        }
        let observation = AuthObservation {
            kind: AuthEventKind::ConsumerReportStale.as_str(),
            provider_status: Some(report.provider_status),
            detail: None,
            reporter_source: report
                .reporter_source
                .as_deref()
                .map(ReporterSource::from_wire),
            principal: Some(AuthEventPrincipal::Member(member)),
        };
        self.engine
            .store()
            .mark_stale_if_version_reported(
                &report.credential_id,
                report.record_version,
                AuditCtx {
                    op: AuditOp::ReportAuthFailure,
                    actor: member,
                    alarm: None,
                },
                observation,
            )
            .map_err(|error| map_store_error(&error))?;
        Ok(json!({ "accepted": true }))
    }

    /// `federation.secret_use`: a paired computer's local sender asks for a secret this
    /// home holds. The checks below run in order and the first refusal ends the call;
    /// the allowlist already ran in [`Self::serve`]. Every check runs again on a retry
    /// of the same request, so a release receipt is replayed only while the pairing,
    /// the `secret_use` member grant and the announced key still hold. A check that
    /// could not be made (callosum unavailable, a store fault) keeps its transient code
    /// and writes no refusal diagnostic.
    async fn secret_use(
        &self,
        member: &str,
        params: &Value,
        budget: tokio::time::Instant,
    ) -> Result<Value, Refusal> {
        // 1. Only a home-role vault serves forwarded secret ops; nothing else falls back
        // to local state or forwards again.
        let self_id = self.secret_home_self()?;
        // 2. The member's current pairing id, and a `secret_use` member grant under it.
        // The grant is checked before anything is parsed, as for the flow ops, so a
        // member without it cannot drive the grammar or binding diagnostics below.
        let pairing_id = self.current_pairing(member, OP_SECRET_USE, budget).await?;
        self.require_secret_use_grant(member, &pairing_id, OP_SECRET_USE)?;
        // 3. Strict parse of the params, the aad and the sender.
        let request: SecretUseParams = serde_json::from_value(params.clone())
            .map_err(|error| Refusal::InvalidParams(error.to_string()))?;
        let aad = parse_secret_aad(&request.aad)?;
        let sender = forwarded_sender(&request.sender).ok_or_else(|| {
            Refusal::InvalidParams("sender is not aft, cerebellum or basal".into())
        })?;
        let call_sha256 = secret_call_sha256(&request.sender, &request.call).ok_or_else(|| {
            Refusal::InvalidParams("call holds a number outside the exact integer range".into())
        })?;
        // 4. The requester's own self id must name the attested caller.
        if aad.requester != member {
            return Err(Refusal::SetupIncomplete(member.to_string()));
        }
        // 5. This home's self id and Active transfer key.
        let Some(self_id) = self_id else {
            return Err(Refusal::SetupIncomplete(aad.home.clone()));
        };
        let sender_pem = self.active_transfer_key(&self_id)?;
        // 6. The aad must be meant for this home and bound to exactly these params.
        let subject = format!("secret|{}", aad.secret_name);
        if aad.home != self_id {
            return Err(self.secret_refusal(&subject, member, "home_mismatch"));
        }
        if aad.call_sha256 != call_sha256 {
            return Err(self.secret_refusal(&subject, member, "call_sha256_mismatch"));
        }
        if request.call.get("name").and_then(Value::as_str) != Some(aad.secret_name.as_str()) {
            return Err(self.secret_refusal(&subject, member, "secret_name_mismatch"));
        }
        // 7. The requester's announced key, matching the aad's key id.
        let peer = match self.peer_key(member, budget).await {
            Ok(peer) => peer,
            Err(Refusal::SetupIncomplete(_)) => {
                return Err(self.secret_refusal(&subject, member, "no_announced_key"));
            }
            Err(refusal) => return Err(refusal),
        };
        if peer.key_id != aad.recipient_key_id {
            return Err(self.secret_refusal(&subject, member, "recipient_key_mismatch"));
        }
        // 8. The local sender's grammar, then the store's grant choice, release receipt
        // and seal, all under the asking member. The seal runs inside the store's
        // transaction, over the received aad bytes.
        let release = ReleaseRequest {
            requester: member,
            nonce: &aad.nonce,
            aad: request.aad.as_bytes(),
        };
        let seal = |released: &Value| -> Result<SealedRelease, Refusal> {
            let plaintext = serde_json::to_vec(released).map_err(|_| CORRUPT)?;
            let (enc, ciphertext) = credentials_core::kem::seal_auth(
                &sender_pem,
                &peer.public,
                &plaintext,
                SECRET_RELEASE_INFO,
                request.aad.as_bytes(),
            )
            .map_err(|error| seal_refusal(error, member, &self_id))?;
            Ok(SealedRelease { enc, ciphertext })
        };
        let clock = Arc::clone(&self.secret_clock);
        let answer = crate::secret_use::serve_forwarded(
            self.engine.store(),
            sender,
            &request.call,
            &release,
            seal,
            move || clock(),
        );
        match answer {
            ForwardedUseAnswer::Sealed(sealed) => {
                let b64 = base64::engine::general_purpose::STANDARD;
                Ok(json!({
                    "status": "sealed",
                    "enc": b64.encode(sealed.enc),
                    "ciphertext": b64.encode(sealed.ciphertext),
                }))
            }
            ForwardedUseAnswer::Reply(reply) => {
                self.note_forwarded_refusal(&subject, member, &reply);
                Ok(reply)
            }
            ForwardedUseAnswer::InvalidParams => {
                Err(Refusal::InvalidParams("invalid secret use call".into()))
            }
            ForwardedUseAnswer::SealFailed(refusal) => Err(refusal),
        }
    }

    /// `federation.secret_request_flow_approval` and
    /// `federation.secret_revoke_flow_grants`: a paired computer's basal asks for, or
    /// gives up, a flow's consent. They carry no sender and no stamp: they are basal's
    /// by their op name, and everything they create or remove belongs to the asking
    /// member only. The home role, pairing and `secret_use` member-grant checks run
    /// before the params are parsed, so a member without the grant cannot drive the
    /// grammar diagnostics either.
    async fn secret_flow_op(
        &self,
        member: &str,
        method: &str,
        params: &Value,
        budget: tokio::time::Instant,
    ) -> Result<Value, Refusal> {
        self.secret_home_self()?;
        let pairing_id = self.current_pairing(member, method, budget).await?;
        self.require_secret_use_grant(member, &pairing_id, method)?;
        let store = self.engine.store();
        let answer = if method == OP_SECRET_REQUEST_FLOW_APPROVAL {
            let clock = Arc::clone(&self.secret_clock);
            crate::secret_use::serve_flow_approval_forwarded(store, member, params, move || clock())
        } else {
            crate::secret_use::serve_revoke_flow_grants_forwarded(store, member, params)
        };
        match answer {
            UseAnswer::Reply(reply) => {
                self.note_forwarded_refusal(method, member, &reply);
                Ok(reply)
            }
            UseAnswer::InvalidParams => Err(Refusal::InvalidParams(
                "invalid flow secret parameters".into(),
            )),
        }
    }

    /// Whether this vault is the secret home, and its self id if it has one. A vault
    /// whose setting is unset (single) or names another member (remote) is not the
    /// home: it answers the uniform `not_found` and writes nothing, so a misrouted call
    /// ends here after one hop. A setting this vault cannot place answers
    /// `remote_setup_incomplete` naming this vault, and an unreadable store
    /// `store_error`.
    fn secret_home_self(&self) -> Result<Option<String>, Refusal> {
        match self.engine.store().secret_home_role() {
            SecretHomeRole::Home { self_member } => Ok(self_member),
            SecretHomeRole::Single | SecretHomeRole::Remote { .. } => Err(Refusal::NotFound),
            SecretHomeRole::RemoteSetupIncomplete { self_member } => {
                Err(Refusal::SecretHomeSetupIncomplete(self_member))
            }
            SecretHomeRole::StoreError => Err(STORE_ERROR),
        }
    }

    /// A selector-free `secret_use` member grant stored under the member's CURRENT
    /// pairing id. A grant recorded under an older pairing is ignored, so re-pairing a
    /// computer stops its forwarded secret calls until the grant is made again.
    fn require_secret_use_grant(
        &self,
        member: &str,
        pairing_id: &str,
        subject: &str,
    ) -> Result<(), Refusal> {
        // A store fault is transient here, not the authoritative `not_found`.
        let grants = self
            .engine
            .store()
            .list_member_grants()
            .map_err(|_| STORE_ERROR)?;
        if grants.iter().any(|grant| {
            grant.member_id == member
                && grant.operation == MemberGrantOperation::SecretUse
                && grant.selector == MemberGrantSelector::None
                && grant.pairing_id == pairing_id
        }) {
            Ok(())
        } else {
            Err(self.secret_refusal(subject, member, "no_secret_use_grant"))
        }
    }

    /// Record a forwarded secret refusal naming the member, and answer the uniform
    /// `not_found`.
    fn secret_refusal(&self, subject: &str, member: &str, reason: &'static str) -> Refusal {
        self.note_secret_event(subject, member, reason);
        Refusal::NotFound
    }

    /// When the store refused a forwarded call, add a diagnostic row naming the
    /// member, beside the store's own row (which names only the local sender), so an
    /// operator can tell which computer was refused. A transient refusal (`store_error`)
    /// decided nothing and is not recorded; neither are releases and approval requests,
    /// whose audit rows and pending requests already carry the member, and which would
    /// otherwise push refusal rows out of the trimmed diagnostics table.
    fn note_forwarded_refusal(&self, subject: &str, member: &str, reply: &Value) {
        let code = reply
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str);
        let reason = match code {
            Some("not_found") => "forwarded_not_found",
            Some("invalid_params") => "forwarded_invalid_params",
            Some("limit_exceeded") => "forwarded_limit_exceeded",
            Some("pending_limit") => "forwarded_pending_limit",
            _ => return,
        };
        self.note_secret_event(subject, member, reason);
    }

    /// One `secret_use_refusal` diagnostic row naming the member. Best effort, like
    /// [`Self::note_refusal`].
    fn note_secret_event(&self, subject: &str, member: &str, reason: &str) {
        let _ = self.engine.store().record_auth_event(
            subject,
            AuthObservation {
                kind: AuthEventKind::SecretUseRefusal.as_str(),
                provider_status: None,
                detail: Some(reason),
                reporter_source: None,
                principal: Some(AuthEventPrincipal::Member(member)),
            },
            None,
        );
    }

    /// Step 2: the member's current pairing id from callosum.
    async fn current_pairing(
        &self,
        member: &str,
        subject: &str,
        budget: tokio::time::Instant,
    ) -> Result<String, Refusal> {
        let body = match self
            .callosum_call("callosum.paired_devices_read", budget)
            .await
        {
            Some(body) => body,
            None => return Err(Refusal::HomeUnavailable),
        };
        match decode_paired_devices(&body, member) {
            Lookup::Found(pairing_id) => Ok(pairing_id),
            Lookup::Absent => {
                self.note_refusal(subject, member, "member_not_paired");
                Err(Refusal::NotFound)
            }
            Lookup::Unavailable => Err(Refusal::HomeUnavailable),
        }
    }

    /// Step 9: the member's announced transfer key from callosum.
    async fn peer_key(
        &self,
        member: &str,
        budget: tokio::time::Instant,
    ) -> Result<PeerKey, Refusal> {
        let body = match self.callosum_call("callosum.peer_keys_read", budget).await {
            Some(body) => body,
            None => return Err(Refusal::HomeUnavailable),
        };
        match decode_peer_transfer_key(&body, member) {
            Lookup::Found(key) => Ok(key),
            Lookup::Absent => Err(Refusal::SetupIncomplete(member.to_string())),
            Lookup::Unavailable => Err(Refusal::HomeUnavailable),
        }
    }

    /// One callosum call within what is left of the home's budget. `None` for no
    /// client, no time or no answer, all of which are transient for the caller.
    async fn callosum_call(&self, method: &str, budget: tokio::time::Instant) -> Option<Value> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(stub) = self.callosum_stub.as_ref() {
            return stub(method);
        }
        callosum_lookup(self.callosum.get(), method, budget).await
    }

    /// Step 5's transfer key: the stored `kem:vault-transfer:1`, readable (so `Active`)
    /// and a KEM key. Anything else is a setup fault of this home.
    fn active_transfer_key(&self, self_id: &str) -> Result<String, Refusal> {
        match self.engine.store().get(VAULT_TRANSFER_ID) {
            Ok(record) if record.kind == CredentialKind::KemKey => {
                std::str::from_utf8(record.payload.expose())
                    .map(str::to_string)
                    .map_err(|_| Refusal::SetupIncomplete(self_id.to_string()))
            }
            Ok(_)
            | Err(StoreOpError::NotFound)
            | Err(StoreOpError::NeedsReauth)
            | Err(StoreOpError::Quarantined)
            | Err(StoreOpError::Corrupt(_))
            | Err(StoreOpError::Decrypt(_)) => Err(Refusal::SetupIncomplete(self_id.to_string())),
            Err(_) => Err(STORE_ERROR),
        }
    }

    /// Step 7: a `remote_read` member grant, stored under the member's CURRENT pairing
    /// id, whose exact or category selector covers `credential_id`. Grants recorded
    /// under an older pairing are ignored, so a re-pair voids every grant made before
    /// it.
    fn require_grant(
        &self,
        member: &str,
        pairing_id: &str,
        credential_id: &str,
    ) -> Result<(), Refusal> {
        let store = self.engine.store();
        // A store fault is transient here, not the authoritative `not_found` a
        // requester would latch as a dead grant.
        let grants = store.list_member_grants().map_err(|_| STORE_ERROR)?;
        let current: Vec<_> = grants
            .into_iter()
            .filter(|grant| {
                grant.member_id == member
                    && grant.operation == MemberGrantOperation::RemoteRead
                    && grant.pairing_id == pairing_id
            })
            .collect();
        let mut covered = current.iter().any(
            |grant| matches!(&grant.selector, MemberGrantSelector::Exact(id) if id == credential_id),
        );
        if !covered
            && current
                .iter()
                .any(|grant| matches!(grant.selector, MemberGrantSelector::Category(_)))
        {
            let categories = store.categories(credential_id).map_err(|_| STORE_ERROR)?;
            covered = current.iter().any(|grant| {
                matches!(&grant.selector, MemberGrantSelector::Category(category)
                    if categories.contains(category))
            });
        }
        if covered {
            Ok(())
        } else {
            self.note_refusal(credential_id, member, "no_grant");
            Err(Refusal::NotFound)
        }
    }

    /// Step 8: the record is a local rotating login (`is_refreshable`) outside the
    /// transfer-key fence. A remote id has no local row, so it reads as not found. A
    /// record whose state refuses a read (`needs_reauth`, quarantined) answers its own
    /// error, as a local read does for a caller already authorized by its grant.
    fn require_eligible(&self, member: &str, credential_id: &str) -> Result<(), Refusal> {
        if is_vault_transfer_id(credential_id) {
            self.note_refusal(credential_id, member, "transfer_key");
            return Err(Refusal::NotFound);
        }
        match self.engine.store().get(credential_id) {
            Ok(record) if record.is_refreshable() => Ok(()),
            Ok(_) => {
                self.note_refusal(credential_id, member, "ineligible");
                Err(Refusal::NotFound)
            }
            Err(StoreOpError::NotFound) => {
                self.note_refusal(credential_id, member, "not_found");
                Err(Refusal::NotFound)
            }
            Err(error) => Err(map_store_error(&error)),
        }
    }

    /// Step 10's read: the engine's get with refresh, on a task of its own. If it runs
    /// past the budget the home answers `home_unavailable` and the task keeps going: a
    /// refresh that has already spent the old refresh token must persist the rotated
    /// one, so it is never cancelled, and the next read is served from it.
    async fn read_with_refresh(
        &self,
        credential_id: &str,
        min_ttl_ms: Option<i64>,
        budget: tokio::time::Instant,
    ) -> Result<GetWithRefreshStatus, Refusal> {
        let engine = Arc::clone(&self.engine);
        let id = credential_id.to_string();
        let read =
            tokio::spawn(
                async move { engine.get_with_refresh_status(&id, min_ttl_ms, false).await },
            );
        match tokio::time::timeout_at(budget, read).await {
            Err(_) => Err(Refusal::HomeUnavailable),
            Ok(Err(_)) => Err(STORE_ERROR),
            Ok(Ok(Err(error))) => Err(map_engine_error(&error)),
            Ok(Ok(Ok(served))) => Ok(served),
        }
    }

    /// The sealed plaintext for `served`, after the projection check.
    fn token_reply(
        &self,
        member: &str,
        credential_id: &str,
        served: &GetWithRefreshStatus,
    ) -> Result<Vec<u8>, Refusal> {
        let record = &served.record;
        let Some(token) = project_access_token(record) else {
            self.note_refusal(credential_id, member, "projection_refused");
            return Err(Refusal::NotFound);
        };
        let oauth = record.oauth.as_ref();
        let expires_at_ms = oauth
            .and_then(|oauth| oauth.expires_at_ms)
            .or(record.expires_at_ms);
        let expires_in_ms = expires_at_ms.map(|at| at.saturating_sub(wall_now_ms()).max(0));
        let recheck_in_ms = served
            .refresh_deferred_until_ms
            .map(|until| until.saturating_sub((self.cooldown_clock)()).max(0));
        // The get projection, computed exactly as the local `get_scoped` computes it.
        let adapter = record.refresh_adapter.as_deref();
        let project_id =
            if adapter == Some(credentials_core::refresh_adapters::antigravity::ADAPTER_NAME) {
                oauth.and_then(|oauth| {
                    credentials_core::refresh_adapters::antigravity::effective_project_id(
                        oauth.refresh_token.expose(),
                    )
                })
            } else {
                None
            };
        let account_id = match (adapter, oauth) {
            (Some(adapter), Some(oauth)) => credentials_core::oauth_login::account_id_for_adapter(
                adapter,
                oauth.access_token.expose(),
            ),
            _ => None,
        }
        .or_else(|| record.identity.account_id.clone());
        let categories = self
            .engine
            .store()
            .categories(credential_id)
            .map_err(|_| STORE_ERROR)?;
        let reply = TokenReply {
            payload: token,
            expires_in_ms,
            recheck_in_ms,
            record_version: record.record_version,
            project_id,
            account_id,
            identity: &record.identity,
            categories,
            refresh_adapter: adapter,
            detected_plan: record.detected_plan.as_ref(),
        };
        serde_json::to_vec(&reply).map_err(|_| CORRUPT)
    }

    /// One diagnostic row naming the member, never `reserved:callosum`. Best effort: a
    /// diagnostic that could fail the call would be worse than the gap it leaves.
    fn note_refusal(&self, subject: &str, member: &str, reason: &str) {
        let _ = self.engine.store().record_auth_event(
            subject,
            AuthObservation {
                kind: AuthEventKind::ScopedReadRefusal.as_str(),
                provider_status: None,
                detail: Some(reason),
                reporter_source: None,
                principal: Some(AuthEventPrincipal::Member(member)),
            },
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    //! The two callosum decoders, fed literal bodies in the shapes callosum sends today.
    //! Callosum publishes vector files for these replies (tag
    //! `paired-devices-vectors-v1.3`); once vendored, they replace these literals.

    use super::*;

    const MEMBER: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";
    const FP: &str = "aa11bb22cc33dd44ee55ff6600112233";
    const KEY_HEX: &str = "0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000";

    #[test]
    fn a_paired_computer_yields_its_pairing_id_and_the_v1_3_self_member_is_ignored() {
        let body = json!({
            "devices": [
                { "class": "computer", "fingerprint": "0000000000000000000000000000000a", "pairing_id": "other" },
                { "class": "computer", "fingerprint": FP, "pairing_id": "pair-7", "extra": 1 },
            ],
            "self": { "static_public_key_hex": KEY_HEX },
        });
        assert_eq!(
            decode_paired_devices(&body, MEMBER),
            Lookup::Found("pair-7".into())
        );
    }

    #[test]
    fn an_absent_or_non_computer_device_is_unpaired() {
        assert_eq!(
            decode_paired_devices(&json!({ "devices": [] }), MEMBER),
            Lookup::Absent
        );
        // The same fingerprint as a phone is `fed-phone:<fp>`, not this member.
        let phone =
            json!({ "devices": [{ "class": "phone", "fingerprint": FP, "pairing_id": "p" }] });
        assert_eq!(decode_paired_devices(&phone, MEMBER), Lookup::Absent);
    }

    #[test]
    fn a_malformed_or_duplicated_paired_devices_answer_fails_closed() {
        for body in [
            json!({}),
            json!({ "devices": "nope" }),
            json!({ "devices": [{ "class": "computer", "fingerprint": FP, "pairing_id": "" }] }),
            json!({ "devices": [{ "class": "computer", "fingerprint": FP }] }),
            json!({ "devices": [
                { "class": "computer", "fingerprint": FP, "pairing_id": "a" },
                { "class": "computer", "fingerprint": FP, "pairing_id": "b" },
            ] }),
        ] {
            assert_eq!(
                decode_paired_devices(&body, MEMBER),
                Lookup::Absent,
                "{body}"
            );
        }
    }

    #[test]
    fn paired_devices_refusals_are_transient_only_when_callosum_says_retryable() {
        for (code, expected) in [
            ("fed_not_ready", Lookup::Unavailable),
            ("fed_target_unavailable", Lookup::Unavailable),
            ("fed_not_authorized", Lookup::Absent),
            ("fed_bad_request", Lookup::Absent),
        ] {
            let body = json!({ "code": code, "message": "refused" });
            assert_eq!(decode_paired_devices(&body, MEMBER), expected, "{code}");
        }
    }

    /// The release aad's `call_sha256` hashes the RFC 8785 bytes of `{sender, call}`:
    /// keys sorted at every level whatever order they arrived in, control characters,
    /// backslash and quote escaped, other text raw UTF-8. The expected digest is of the
    /// canonical bytes written out by hand.
    #[test]
    fn the_call_digest_is_over_the_rfc_8785_bytes_of_sender_and_call() {
        let call: Value = serde_json::from_str(
            "{\"\u{e9}\":{},\"b\":\"\\u001f\\\\\\\"\u{e9}\",\"a\":[1,-2,null,true]}",
        )
        .unwrap();
        assert_eq!(
            secret_call_sha256("aft", &call).as_deref(),
            Some("0590da2688b02f294eff26e009b9dbf898730b710dbab7a96f6ad27d7de85b1a")
        );
        assert_ne!(
            secret_call_sha256("cerebellum", &call),
            secret_call_sha256("aft", &call)
        );
        // Numbers RFC 8785 would print with its float rules are refused, not guessed.
        for number in [
            json!(1.5),
            json!(9_007_199_254_740_992u64),
            json!(-9_007_199_254_740_992i64),
        ] {
            assert_eq!(
                secret_call_sha256("aft", &json!({ "n": number })),
                None,
                "{number}"
            );
        }
        assert!(secret_call_sha256("aft", &json!({ "n": 9_007_199_254_740_991u64 })).is_some());
    }

    /// The release aad is parsed strictly: exactly its six fields, each well formed.
    #[test]
    fn the_release_aad_is_parsed_strictly() {
        let good = json!({
            "secret_name": "key",
            "requester": MEMBER,
            "home": "fed-computer:00000000000000000000000000000001",
            "nonce": "0123456789abcdef0123456789abcdef",
            "recipient_key_id": "kem-1",
            "call_sha256": "ab".repeat(32),
        });
        assert!(parse_secret_aad(&good.to_string()).is_ok());
        let mut cases = Vec::new();
        for field in good.as_object().unwrap().keys() {
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(field);
            cases.push(missing);
        }
        for (field, bad) in [
            ("secret_name", json!("")),
            (
                "requester",
                json!("fed-phone:0123456789abcdef0123456789abcdef"),
            ),
            ("home", json!("self")),
            ("nonce", json!("0123456789ABCDEF0123456789ABCDEF")),
            ("recipient_key_id", json!("")),
            ("call_sha256", json!("AB".repeat(32))),
            ("extra", json!("x")),
        ] {
            let mut case = good.clone();
            case[field] = bad;
            cases.push(case);
        }
        for case in cases {
            assert!(
                matches!(
                    parse_secret_aad(&case.to_string()),
                    Err(Refusal::InvalidParams(_))
                ),
                "{case}"
            );
        }
        // A duplicated field is refused too.
        let duplicated =
            good.to_string()
                .replacen('{', r#"{"nonce":"0123456789abcdef0123456789abcdef","#, 1);
        assert!(parse_secret_aad(&duplicated).is_err());
    }

    fn peers(key: Value) -> Value {
        json!({
            "peers": [
                { "fingerprint": "0000000000000000000000000000000a" },
                {
                    "fingerprint": FP,
                    "machine_id": "m-1",
                    "key_record": { "keys": {
                        "vault_transfer_x25519": key,
                        "seal_x25519": { "pub": "ab", "version": "1" },
                    } },
                    "registry_platform": "macos",
                },
            ]
        })
    }

    #[test]
    fn an_announced_transfer_key_decodes_and_its_key_id_is_computed_here() {
        let body = peers(json!({ "pub": KEY_HEX, "version": "3", "key_id": "forged" }));
        let Lookup::Found(key) = decode_peer_transfer_key(&body, MEMBER) else {
            panic!("the announced key decodes");
        };
        assert_eq!(key.public[0], 0x0f);
        assert_eq!(key.public[31], 0x00);
        assert_eq!(
            key.key_id,
            credentials_core::signing::key_id_for_public(&key.public),
            "the key id is computed from the key, never taken from the reply"
        );
    }

    #[test]
    fn a_missing_or_malformed_transfer_key_is_no_key() {
        let no_record = json!({ "peers": [{ "fingerprint": FP }] });
        assert_eq!(decode_peer_transfer_key(&no_record, MEMBER), Lookup::Absent);
        for key in [
            json!({ "pub": KEY_HEX.to_uppercase(), "version": "3" }),
            json!({ "pub": &KEY_HEX[..62], "version": "3" }),
            json!({ "pub": format!("{KEY_HEX}00"), "version": "3" }),
            json!({ "pub": 7, "version": "3" }),
        ] {
            assert_eq!(
                decode_peer_transfer_key(&peers(key.clone()), MEMBER),
                Lookup::Absent,
                "{key}"
            );
        }
        let no_kind = json!({ "peers": [{ "fingerprint": FP, "key_record": { "keys": {} } }] });
        assert_eq!(decode_peer_transfer_key(&no_kind, MEMBER), Lookup::Absent);
        assert_eq!(
            decode_peer_transfer_key(&json!({ "peers": [] }), MEMBER),
            Lookup::Absent
        );
        assert_eq!(
            decode_peer_transfer_key(&json!({ "code": "fed_not_ready" }), MEMBER),
            Lookup::Unavailable
        );
    }

    #[test]
    fn the_gate_off_mapping_is_release_1() {
        let callosum = Principal::Reserved {
            module_id: "callosum".into(),
        };
        for harness in [
            "fed-computer:aa11bb22cc33dd44ee55ff6600112233",
            "fed-phone:x",
            "fed-",
        ] {
            assert_eq!(
                map_route_caller(&callosum, harness, MappingGate::Off),
                RouteCaller::Principal(None),
                "{harness}"
            );
        }
        for harness in ["callosum-self", "", "opencode", "FED-computer:x"] {
            assert_eq!(
                map_route_caller(&callosum, harness, MappingGate::Off),
                RouteCaller::Principal(Some(callosum.clone())),
                "{harness}"
            );
        }
    }
}
