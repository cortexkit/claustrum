//! Sealed static-key transfers: how a static credential (an API key, a DSN, a cookie,
//! an opaque blob) moves from one member's vault to another's.
//!
//! The sending vault encrypts the record to a key only the receiving vault holds (HPKE
//! Auth mode, sealed with its own transfer key, under [`TRANSFER_INFO`]), both sides
//! audit it, and the operator confirms on both ends. A rotating login never moves
//! this way: [`transfer_eligibility`] is the one allowlist both ends apply.
//!
//! What is here, in the order a transfer meets it:
//!
//! - **Send** ([`Transfers::send`]): look up the receiver's announced key, build and
//!   seal the versioned body once under a fresh transfer id, then commit the outgoing
//!   row and its `transfer_out` audit row in one transaction BEFORE any delivery. A
//!   failed commit sends nothing; a crash after it leaves a row that
//!   [`Transfers::resume`] redelivers byte for byte, never re-sealed.
//! - **Deliver** ([`deliver`], reached only through the home's federation channel):
//!   pairing and grant, then dedup on (sender, SHA-256 over `enc || ciphertext`)
//!   before anything is opened or bounded, then size, then queue, then open and check
//!   the aad, then receive-side validation, then the pending row, indexed by the
//!   transfer id from the authenticated aad.
//! - **Receive, accept, reject** on the receiver: accept opens the envelope again
//!   against the stored sender's announced key and writes the record, its categories,
//!   its provider ids, the accepted marker and `transfer_in` in one transaction.
//! - **Recovery** ([`Transfers::replace_transfer_key`]): replacing a transfer key found
//!   off `Active` rejects every pending transfer and abandons every outgoing one in
//!   the same transaction, because nothing sealed under the old key can open again.
//!
//! This file is compiled into the daemon and into the test-only library, so it depends
//! on nothing in the daemon outside `federation`.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use credentials_core::audit::{AuditCtx, AuditOp, AuthEventKind};
use credentials_core::federation::{
    is_lower_hex_16_bytes, is_vault_transfer_id, valid_member_id, IncomingInsert, IncomingTransfer,
    IncomingTransferState, MemberGrantOperation, NewIncomingTransfer, NewOutgoingTransfer,
    OutgoingTransfer, OutgoingTransferState, SealedTransfer, TransferAcceptOutcome,
    TransferAcceptance, TransferKeyRecovery, REJECT_BODY_INVALID, REJECT_BY_OPERATOR,
    REJECT_REMOTE_SEAL_INVALID, VAULT_TRANSFER_ID,
};
use credentials_core::plan_detection::DetectedPlan;
use credentials_core::record::{CredentialKind, RecordIdentity, VaultRecord};
use credentials_core::store::{AuthEventPrincipal, AuthObservation, EncryptedStore, StoreOpError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::ingress::{
    decode_paired_devices, decode_peer_transfer_key, Lookup, PeerKey, CALLOSUM_MODULE_ID,
    OP_TRANSFER_DELIVER,
};
use super::outbound::{management_surface, OutboundClient, RouteCall, ADMIN_OP_BUDGET};
use super::remote_read::fed_provider_module;

/// The HPKE `info` of a transfer envelope. A token reply uses a different literal, so
/// neither can ever be opened as the other.
pub const TRANSFER_INFO: &[u8] = b"cortexkit/claustrum/transfer/v1";

/// The transfer body's schema version. A body with any other version is refused.
pub const TRANSFER_BODY_VERSION: u32 = 1;

/// The AEAD tag ChaCha20-Poly1305 adds to every ciphertext: a ciphertext longer than
/// the plaintext cap plus this carries a body over the cap.
const AEAD_TAG_LEN: usize = 16;

/// The outbound client's binding-cache key for callosum, shared with the other
/// federation surfaces so they reuse one route.
const CALLOSUM_ROUTE_KEY: &str = "callosum";

/// The `auth_events` subject for a delivery refused before it names a credential.
const DELIVERY_SUBJECT: &str = "federation.transfer_deliver";

/// The longest receiver code this vault repeats in a report or stores on a row. A
/// longer or stranger code is reported as `unrecognised`, so a peer cannot write text
/// here.
const MAX_REPLY_CODE_LEN: usize = 48;

// ---------------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------------

/// Why a record may not be transferred. Each names its reason on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible {
    /// A login (rotating or not) or any record carrying OAuth material or an adapter.
    Oauth,
    /// A signing key the vault exercises and never serves.
    SigningKey,
    /// An HPKE key the vault exercises and never serves.
    KemKey,
    /// A cookie with an expiry, which the store would refuse to seal at accept.
    CookieExpiry,
    /// The vault's own transfer key.
    TransferKey,
    /// A rotating login whose home is another vault: this vault holds no material.
    RemoteRecord,
}

impl Ineligible {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::SigningKey => "signing_key",
            Self::KemKey => "kem_key",
            Self::CookieExpiry => "cookie_expiry",
            Self::TransferKey => "transfer_key",
            Self::RemoteRecord => "remote_record",
        }
    }
}

/// THE eligibility allowlist, applied by `send` and by receive-side validation at
/// delivery and at accept: kind `ApiKey`, `Dsn`, `Cookie` or `Opaque`, with no OAuth
/// struct and no refresh adapter, and a cookie only without an expiry.
///
/// The match is exhaustive on purpose: a new [`CredentialKind`] fails to compile here
/// until someone decides whether it may leave the vault.
pub fn transfer_eligibility(
    kind: CredentialKind,
    has_oauth: bool,
    has_refresh_adapter: bool,
    expires_at_ms: Option<i64>,
) -> Result<(), Ineligible> {
    match kind {
        CredentialKind::ApiKey | CredentialKind::Dsn | CredentialKind::Opaque => {}
        CredentialKind::Cookie => {
            if expires_at_ms.is_some() {
                return Err(Ineligible::CookieExpiry);
            }
        }
        CredentialKind::Oauth => return Err(Ineligible::Oauth),
        CredentialKind::SigningKey => return Err(Ineligible::SigningKey),
        CredentialKind::KemKey => return Err(Ineligible::KemKey),
    }
    if has_oauth || has_refresh_adapter {
        return Err(Ineligible::Oauth);
    }
    Ok(())
}

/// The wire spelling of an eligible kind, as the pending row stores it.
fn kind_str(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Oauth => "oauth",
        CredentialKind::ApiKey => "api_key",
        CredentialKind::Dsn => "dsn",
        CredentialKind::Cookie => "cookie",
        CredentialKind::Opaque => "opaque",
        CredentialKind::SigningKey => "signing_key",
        CredentialKind::KemKey => "kem_key",
    }
}

// ---------------------------------------------------------------------------------
// Wire bodies
// ---------------------------------------------------------------------------------

/// The transfer `aad`: `{transfer_id, credential_id, sender, receiver,
/// recipient_key_id}`, serialized once by the sender in this field order. The exact
/// bytes travel in the envelope; the receiver parses them strictly (unknown, missing
/// and duplicate fields refused) and opens over the received bytes, never a rebuilt
/// copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferAad {
    pub transfer_id: String,
    pub credential_id: String,
    pub sender: String,
    pub receiver: String,
    pub recipient_key_id: String,
}

/// A body's identity. Strict: a field this vault does not know is refused rather
/// than dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    org_name: Option<String>,
}

/// A body's detected plan. Strict, like [`WireIdentity`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePlan {
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    raw: Option<String>,
    observed_at_ms: i64,
}

/// The versioned transfer body: the sealed plaintext. Exactly these fields; anything
/// else (an `oauth` struct, a refresh adapter, a refresh token) is refused, so no
/// rotating login can be expressed here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferBody {
    version: u32,
    credential_id: String,
    kind: CredentialKind,
    /// The record's payload, standard base64.
    payload: String,
    categories: Vec<String>,
    identity: WireIdentity,
    provider_ids: Vec<String>,
    detected_plan: Option<WirePlan>,
    expires_at_ms: Option<i64>,
}

/// `federation.transfer_deliver` params: the envelope, and nothing else. There is no
/// outer transfer id: the only transfer id is the one in the authenticated aad.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverParams {
    /// Standard base64.
    enc: String,
    /// Standard base64.
    ciphertext: String,
    /// The aad exactly as the sender serialized it.
    aad: String,
}

fn deliver_params(sealed: &SealedTransfer) -> Option<Value> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let aad = std::str::from_utf8(&sealed.aad).ok()?;
    Some(json!({
        "enc": b64.encode(&sealed.enc),
        "ciphertext": b64.encode(&sealed.ciphertext),
        "aad": aad,
    }))
}

/// A body that passed receive-side validation, ready to become a pending row or a
/// record.
struct ValidBody {
    record: VaultRecord,
    kind: CredentialKind,
    categories: Vec<String>,
    provider_ids: Vec<String>,
}

impl std::fmt::Debug for ValidBody {
    // The record carries the credential; only its shape belongs in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidBody")
            .field("kind", &self.kind)
            .field("categories", &self.categories)
            .field("provider_ids", &self.provider_ids)
            .finish_non_exhaustive()
    }
}

/// Receive-side validation, run at delivery and again at accept. Every failure is
/// `transfer_body_invalid`; the argument is only for a diagnostic. Requires a body of
/// this version, the eligibility allowlist, a valid id equal to the aad's, a valid
/// identity, plan tier, categories and provider ids, and a non-empty payload.
fn validate_body(body: TransferBody, aad: &TransferAad) -> Result<ValidBody, &'static str> {
    if body.version != TRANSFER_BODY_VERSION {
        return Err("version");
    }
    transfer_eligibility(body.kind, false, false, body.expires_at_ms)
        .map_err(Ineligible::reason)?;
    if body.credential_id != aad.credential_id {
        return Err("credential_id");
    }
    if !valid_transfer_credential_id(&body.credential_id) {
        return Err("credential_id");
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(body.payload.as_bytes())
        .map_err(|_| "payload")?;
    if payload.is_empty() {
        return Err("payload");
    }
    let identity = RecordIdentity {
        account_id: body.identity.account_id,
        email: body.identity.email,
        org_name: body.identity.org_name,
    };
    identity.validate().map_err(|_| "identity")?;
    let detected_plan = body.detected_plan.map(|plan| DetectedPlan {
        tier: plan.tier,
        raw: plan.raw,
        observed_at_ms: plan.observed_at_ms,
    });
    if detected_plan
        .as_ref()
        .and_then(|plan| plan.tier.as_deref())
        .is_some_and(|tier| !credentials_core::plan_tier::valid_plan_tier(tier))
    {
        return Err("plan_tier");
    }
    if body
        .categories
        .iter()
        .any(|category| !credentials_core::catalog::valid_category_name(category))
    {
        return Err("category");
    }
    if credentials_core::provider_ids::check_provider_ids(&body.provider_ids).is_err() {
        return Err("provider_id");
    }
    let mut record = VaultRecord::new_static(body.kind, "transfer", payload, body.expires_at_ms);
    record.identity = identity;
    record.detected_plan = detected_plan;
    let mut categories = body.categories;
    categories.sort();
    categories.dedup();
    Ok(ValidBody {
        record,
        kind: body.kind,
        categories,
        provider_ids: body.provider_ids,
    })
}

/// The store's credential-id rules for a record a transfer may create (non-empty, not a
/// `category:` selector, no `|`), and never an id under the transfer-key prefix.
fn valid_transfer_credential_id(credential_id: &str) -> bool {
    !credential_id.is_empty()
        && !credential_id.starts_with("category:")
        && !credential_id.contains('|')
        && !is_vault_transfer_id(credential_id)
}

/// Parse the received aad bytes strictly, with every field well formed.
fn parse_transfer_aad(bytes: &[u8]) -> Option<TransferAad> {
    if bytes.len() > credentials_core::kem::MAX_SEAL_AAD {
        return None;
    }
    let aad: TransferAad = serde_json::from_slice(bytes).ok()?;
    let well_formed = is_lower_hex_16_bytes(&aad.transfer_id)
        && !aad.credential_id.is_empty()
        && valid_member_id(&aad.sender)
        && valid_member_id(&aad.receiver)
        && !aad.recipient_key_id.is_empty();
    well_formed.then_some(aad)
}

// ---------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------

/// A transfer refusal: the `{code, class}` every refusal on this wire carries, plus
/// `remedy_member` when a setup fault names the member whose operator must fix it and
/// `reason` when a record is ineligible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRefusal {
    pub code: &'static str,
    pub class: &'static str,
    pub remedy_member: Option<String>,
    pub reason: Option<&'static str>,
}

#[derive(Serialize)]
struct RefusalBody<'a> {
    code: &'a str,
    class: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remedy_member: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

impl TransferRefusal {
    const fn new(code: &'static str, class: &'static str) -> Self {
        Self {
            code,
            class,
            remedy_member: None,
            reason: None,
        }
    }

    /// The uniform refusal: no grant, stale pairing, unknown id. The same bytes a local
    /// scoped read answers.
    pub const fn not_found() -> Self {
        Self::new("not_found", "permanent")
    }

    fn callosum_unavailable() -> Self {
        Self::new("callosum_unavailable", "transient")
    }

    fn store_error() -> Self {
        Self::new("store_error", "transient")
    }

    fn too_large() -> Self {
        Self::new("transfer_too_large", "permanent")
    }

    fn queue_full() -> Self {
        Self::new("transfer_queue_full", "transient")
    }

    fn seal_invalid() -> Self {
        Self::new("remote_seal_invalid", "permanent")
    }

    fn conflict() -> Self {
        Self::new("transfer_conflict", "permanent")
    }

    fn body_invalid() -> Self {
        Self::new("transfer_body_invalid", "permanent")
    }

    fn expired() -> Self {
        Self::new("transfer_expired", "permanent")
    }

    fn setup_incomplete(member: Option<String>) -> Self {
        Self {
            remedy_member: member,
            ..Self::new("remote_setup_incomplete", "permanent")
        }
    }

    fn transfer_key_missing(self_id: Option<String>) -> Self {
        Self {
            remedy_member: self_id,
            ..Self::new("transfer_key_missing", "permanent")
        }
    }

    fn ineligible(why: Ineligible) -> Self {
        Self {
            reason: Some(why.reason()),
            ..Self::new("transfer_ineligible", "permanent")
        }
    }

    fn invalid_params() -> Self {
        Self::new("invalid_params", "permanent")
    }

    /// The `error` member of a refusal reply.
    pub fn body(&self) -> Value {
        serde_json::to_value(RefusalBody {
            code: self.code,
            class: self.class,
            remedy_member: self.remedy_member.as_deref(),
            reason: self.reason,
        })
        .unwrap_or_else(|_| json!({ "code": self.code, "class": self.class }))
    }
}

/// The reply a delivery answers for a transfer already recorded in `state`.
fn state_reply(state: IncomingTransferState) -> Value {
    match state {
        IncomingTransferState::Expired => json!({ "error": TransferRefusal::expired().body() }),
        IncomingTransferState::Pending
        | IncomingTransferState::Accepted
        | IncomingTransferState::Rejected => json!({ "state": state.as_str() }),
    }
}

/// Why a delivery stopped.
enum Stop {
    Refused(TransferRefusal),
    /// A malformed request, answered as an `invalid_params` `Error` frame.
    InvalidParams(String),
}

impl From<TransferRefusal> for Stop {
    fn from(refusal: TransferRefusal) -> Self {
        Self::Refused(refusal)
    }
}

// ---------------------------------------------------------------------------------
// Shared lookups
// ---------------------------------------------------------------------------------

/// This vault's own transfer setup: its self id, its transfer key's private half (only
/// while `Active`) and that key's id.
struct OwnKey {
    self_id: String,
    pem: String,
    key_id: String,
}

impl std::fmt::Debug for OwnKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnKey")
            .field("self_id", &self.self_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Read this vault's own setup. `Ok(Err(self_id))` when the self id or a usable,
/// `Active` transfer key is missing (carrying the self id when it is set).
fn own_key(store: &EncryptedStore) -> Result<Result<OwnKey, Option<String>>, StoreOpError> {
    let Some(self_id) = store.federation_self_member()? else {
        return Ok(Err(None));
    };
    let pem = match store.get(VAULT_TRANSFER_ID) {
        Ok(record) if record.kind == CredentialKind::KemKey => {
            match std::str::from_utf8(record.payload.expose()) {
                Ok(pem) => pem.to_string(),
                Err(_) => return Ok(Err(Some(self_id))),
            }
        }
        Ok(_)
        | Err(StoreOpError::NotFound)
        | Err(StoreOpError::NeedsReauth)
        | Err(StoreOpError::Quarantined)
        | Err(StoreOpError::Corrupt(_))
        | Err(StoreOpError::Decrypt(_)) => return Ok(Err(Some(self_id))),
        Err(error) => return Err(error),
    };
    let Ok((_, key_id)) = credentials_core::kem::public_half(&pem) else {
        return Ok(Err(Some(self_id)));
    };
    Ok(Ok(OwnKey {
        self_id,
        pem,
        key_id,
    }))
}

/// One callosum lookup within what is left of `budget`. `None` for no client, no time
/// or no answer, all of which are transient for the caller.
async fn callosum_call(
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

/// `member`'s announced transfer key, looked up for a member this vault fixed itself
/// (the attested harness member, the stored sender or the `--to` member), never for one
/// named in a request.
async fn peer_key(
    client: Option<&OutboundClient>,
    member: &str,
    budget: tokio::time::Instant,
) -> Lookup<PeerKey> {
    match callosum_call(client, "callosum.peer_keys_read", budget).await {
        Some(body) => decode_peer_transfer_key(&body, member),
        None => Lookup::Unavailable,
    }
}

/// One diagnostic row naming the member. Best effort: a diagnostic that could fail the
/// call would be worse than the gap it leaves.
fn note_refusal(store: &EncryptedStore, subject: &str, member: &str, reason: &str) {
    let _ = store.record_auth_event(
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

/// Open `sealed` as a transfer from `sender_public` to this vault, over the received
/// aad bytes, and check the aad: the sender, this vault as receiver, this vault's
/// current key, and (when given) the expected transfer id. Then parse and validate
/// the body; its id must be the aad's. The first failure decides the refusal.
fn open_transfer(
    own: &OwnKey,
    sender: &str,
    sender_public: &[u8],
    sealed: &SealedTransfer,
    expected_transfer_id: Option<&str>,
) -> Result<(TransferAad, ValidBody, usize), TransferRefusal> {
    let aad = parse_transfer_aad(&sealed.aad).ok_or_else(TransferRefusal::seal_invalid)?;
    let plaintext = credentials_core::kem::open_auth(
        &own.pem,
        sender_public,
        &sealed.enc,
        &sealed.ciphertext,
        TRANSFER_INFO,
        &sealed.aad,
    )
    .map_err(|_| TransferRefusal::seal_invalid())?;
    let aad_matches = aad.sender == sender
        && aad.receiver == own.self_id
        && aad.recipient_key_id == own.key_id
        && expected_transfer_id.is_none_or(|expected| aad.transfer_id == expected);
    if !aad_matches {
        return Err(TransferRefusal::seal_invalid());
    }
    let body: TransferBody =
        serde_json::from_slice(&plaintext).map_err(|_| TransferRefusal::body_invalid())?;
    if body.credential_id != aad.credential_id {
        return Err(TransferRefusal::seal_invalid());
    }
    let size = plaintext.len();
    let valid = validate_body(body, &aad).map_err(|_| TransferRefusal::body_invalid())?;
    Ok((aad, valid, size))
}

// ---------------------------------------------------------------------------------
// Delivery (receiver)
// ---------------------------------------------------------------------------------

/// `federation.transfer_deliver`, as the home's federation channel dispatches it for
/// `member`, the attested harness member. Returns the reply body, or the detail of an
/// `invalid_params` refusal. The op allowlist (step 1) already ran.
///
/// Every refusal before the pending row writes nothing, and the dedup answer writes
/// nothing either: no row, no audit.
pub async fn deliver(
    store: &EncryptedStore,
    callosum: Option<&OutboundClient>,
    member: &str,
    params: &Value,
    now_ms: i64,
    budget: tokio::time::Instant,
) -> Result<Value, String> {
    match deliver_inner(store, callosum, member, params, now_ms, budget).await {
        Ok(state) => Ok(state_reply(state)),
        Err(Stop::Refused(refusal)) => Ok(json!({ "error": refusal.body() })),
        Err(Stop::InvalidParams(detail)) => Err(detail),
    }
}

async fn deliver_inner(
    store: &EncryptedStore,
    callosum: Option<&OutboundClient>,
    member: &str,
    params: &Value,
    now_ms: i64,
    budget: tokio::time::Instant,
) -> Result<IncomingTransferState, Stop> {
    // 2. The sender's current pairing, then a `transfer_deliver` grant made under it.
    let Some(devices) = callosum_call(callosum, "callosum.paired_devices_read", budget).await
    else {
        return Err(TransferRefusal::callosum_unavailable().into());
    };
    let pairing_id = match decode_paired_devices(&devices, member) {
        Lookup::Found(pairing_id) => pairing_id,
        Lookup::Absent => {
            note_refusal(store, DELIVERY_SUBJECT, member, "member_not_paired");
            return Err(TransferRefusal::not_found().into());
        }
        Lookup::Unavailable => return Err(TransferRefusal::callosum_unavailable().into()),
    };
    let granted = store
        .list_member_grants()
        .map_err(|_| TransferRefusal::store_error())?
        .into_iter()
        .any(|grant| {
            grant.member_id == member
                && grant.operation == MemberGrantOperation::TransferDeliver
                && grant.pairing_id == pairing_id
        });
    if !granted {
        note_refusal(store, DELIVERY_SUBJECT, member, "no_grant");
        return Err(TransferRefusal::not_found().into());
    }

    let request: DeliverParams = serde_json::from_value(params.clone())
        .map_err(|error| Stop::InvalidParams(error.to_string()))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let (Ok(enc), Ok(ciphertext)) = (
        b64.decode(request.enc.as_bytes()),
        b64.decode(request.ciphertext.as_bytes()),
    ) else {
        return Err(Stop::InvalidParams(
            "enc and ciphertext must be standard base64".into(),
        ));
    };
    if request.aad.len() > credentials_core::kem::MAX_SEAL_AAD {
        return Err(Stop::InvalidParams("aad is over its size cap".into()));
    }
    let sealed = SealedTransfer {
        enc,
        ciphertext,
        aad: request.aad.into_bytes(),
    };

    // 3. Dedup BEFORE anything is opened or bounded: the same bytes from the same
    // sender answer their stored state, whatever the queue or the keys now say.
    store
        .expire_incoming_transfers(now_ms)
        .map_err(|_| TransferRefusal::store_error())?;
    if let Some(known) = store
        .incoming_transfer_by_hash(member, &sealed.body_hash())
        .map_err(|_| TransferRefusal::store_error())?
    {
        return Ok(known.state);
    }

    // 4. Size: a body over the seal's plaintext cap.
    if sealed.ciphertext.len() > credentials_core::kem::MAX_SEAL_PLAINTEXT + AEAD_TAG_LEN {
        return Err(TransferRefusal::too_large().into());
    }

    // 5. Queue bounds.
    if store
        .pending_transfer_counts(member)
        .map_err(|_| TransferRefusal::store_error())?
        .full()
    {
        return Err(TransferRefusal::queue_full().into());
    }

    // 6. Open against the attested sender's announced key, check the aad, and refuse a
    // second envelope under a transfer id this sender already used.
    let own = match own_key(store) {
        Ok(Ok(own)) => own,
        Ok(Err(self_id)) => return Err(TransferRefusal::setup_incomplete(self_id).into()),
        Err(_) => return Err(TransferRefusal::store_error().into()),
    };
    let sender_key = match peer_key(callosum, member, budget).await {
        Lookup::Found(key) => key,
        Lookup::Absent => {
            return Err(TransferRefusal::setup_incomplete(Some(member.to_string())).into())
        }
        Lookup::Unavailable => return Err(TransferRefusal::callosum_unavailable().into()),
    };
    let opened = open_transfer(&own, member, &sender_key.public, &sealed, None);
    // A body that opened but failed validation is reported only after the conflict
    // check, which belongs to the open step; anything that did not open stops here.
    let (aad, valid) = match opened {
        Ok((aad, valid, size)) => (aad, Ok((valid, size))),
        Err(refusal) if refusal.code == TransferRefusal::body_invalid().code => {
            match parse_transfer_aad(&sealed.aad) {
                Some(aad) => (aad, Err(refusal)),
                None => return Err(refusal.into()),
            }
        }
        Err(refusal) => return Err(refusal.into()),
    };
    if store
        .incoming_transfer(member, &aad.transfer_id)
        .map_err(|_| TransferRefusal::store_error())?
        .is_some()
    {
        return Err(TransferRefusal::conflict().into());
    }

    // 7. Receive-side validation, then the pending row, indexed only now by the
    // authenticated transfer id.
    let (valid, size) = valid?;
    let inserted = store
        .insert_incoming_transfer(&NewIncomingTransfer {
            sender_member: member.to_string(),
            transfer_id: aad.transfer_id.clone(),
            credential_id: aad.credential_id.clone(),
            kind: kind_str(valid.kind).to_string(),
            categories: valid.categories,
            size_bytes: size as u64,
            sealed,
            received_at_ms: now_ms,
        })
        .map_err(|_| TransferRefusal::store_error())?;
    match inserted {
        IncomingInsert::Inserted => Ok(IncomingTransferState::Pending),
        IncomingInsert::Known(state) => Ok(state),
        IncomingInsert::QueueFull => Err(TransferRefusal::queue_full().into()),
        IncomingInsert::Conflict => Err(TransferRefusal::conflict().into()),
    }
}

// ---------------------------------------------------------------------------------
// The sender's view of a delivery reply
// ---------------------------------------------------------------------------------

/// What a delivery attempt got back, as the sender acts on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryReply {
    /// The receiver holds the transfer in this state.
    State(IncomingTransferState),
    /// The receiver (or callosum, or the transport) refused. `code` is one this vault
    /// chose or a receiver code of a safe shape.
    Refused { code: String, class: String },
}

impl DeliveryReply {
    /// The code a report prints and the outgoing row records.
    pub fn code(&self) -> &str {
        match self {
            Self::State(state) => state.as_str(),
            Self::Refused { code, .. } => code,
        }
    }

    fn refused(code: &str, class: &str) -> Self {
        Self::Refused {
            code: code.to_string(),
            class: class.to_string(),
        }
    }

    /// Whether the sender keeps its outgoing row for a later `--resume`. A reply that
    /// settles the transfer one way or the other (accepted, rejected, expired, a
    /// permanent refusal, the grant or pairing gone) deletes it; anything that may
    /// succeed on a retry keeps it, including a code this vault does not know.
    pub fn keeps_row(&self) -> bool {
        match self {
            Self::State(IncomingTransferState::Pending) => true,
            Self::State(
                IncomingTransferState::Accepted
                | IncomingTransferState::Rejected
                | IncomingTransferState::Expired,
            ) => false,
            Self::Refused { code, .. } => !matches!(
                code.as_str(),
                "transfer_expired"
                    | "remote_seal_invalid"
                    | "transfer_conflict"
                    | "transfer_too_large"
                    | "transfer_body_invalid"
                    | "federation_setup_invalid"
                    | "not_found"
            ),
        }
    }
}

/// A receiver-chosen code, reduced to something safe to repeat and store.
fn safe_code(code: &str) -> &str {
    let safe = !code.is_empty()
        && code.len() <= MAX_REPLY_CODE_LEN
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if safe {
        code
    } else {
        "unrecognised"
    }
}

/// Classify a delivery's answer. A permanent callosum class means the route itself is
/// misconfigured; every other frame-level answer (a retry-safe callosum class, or an
/// `Error` frame such as `unknown_method` from a receiver that predates transfers) may
/// succeed later and keeps the row.
fn classify_delivery(reply: &Value) -> DeliveryReply {
    if let Some(state) = reply
        .get("state")
        .and_then(Value::as_str)
        .and_then(IncomingTransferState::from_stored)
    {
        if state != IncomingTransferState::Expired {
            return DeliveryReply::State(state);
        }
    }
    if let Some(error) = reply.get("error").filter(|error| error.is_object()) {
        let code = safe_code(error.get("code").and_then(Value::as_str).unwrap_or(""));
        let class = match error.get("class").and_then(Value::as_str) {
            Some("transient") => "transient",
            Some("permanent") => "permanent",
            _ => "unknown",
        };
        return DeliveryReply::refused(code, class);
    }
    if let Some(code) = reply.get("code").and_then(Value::as_str) {
        let permanent_route_fault = matches!(
            code,
            "fed_not_exposed" | "fed_unknown_module" | "fed_bad_call"
        ) || code.starts_with("fed_payload_");
        return if permanent_route_fault {
            DeliveryReply::refused("federation_setup_invalid", "permanent")
        } else if code.starts_with("fed_") {
            DeliveryReply::refused("home_unreachable", "transient")
        } else {
            DeliveryReply::refused("home_unavailable", "transient")
        };
    }
    DeliveryReply::refused("home_unavailable", "transient")
}

// ---------------------------------------------------------------------------------
// The admin side: send, resume, receive, accept, reject, recovery
// ---------------------------------------------------------------------------------

/// What `send` or `send --resume` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReport {
    pub transfer_id: String,
    pub credential_id: String,
    pub receiver: String,
    /// The receiver's reply to this attempt.
    pub reply: DeliveryReply,
    /// Whether the outgoing row is still stored for a later `--resume`.
    pub row_kept: bool,
}

/// What `accept` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptReport {
    /// The record was written at this version.
    Accepted {
        credential_id: String,
        record_version: u64,
    },
    /// The transfer was already decided; nothing was written.
    AlreadyDecided(IncomingTransferState),
}

/// A wall clock in milliseconds since the epoch.
pub type TransferClock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A test seam: when it returns true, the send's commit fails between the outgoing row
/// and its audit row. No production caller sets one.
pub type CommitFault = Arc<dyn Fn() -> bool + Send + Sync>;

fn real_wall() -> TransferClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as i64)
            .unwrap_or(0)
    })
}

/// The wall clock in milliseconds, for callers outside [`Transfers`] (the home's
/// delivery arm).
pub fn wall_now_ms() -> i64 {
    real_wall()()
}

/// 16 random bytes as 32 lowercase hex: a fresh transfer id.
fn random_transfer_id() -> Option<String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The outbound client's binding-cache key for one receiver's route.
fn receiver_route_key(receiver: &str) -> String {
    format!("transfer:{receiver}")
}

/// This vault's transfer admin ops. Each is one operator action; nothing here runs on
/// its own.
pub struct Transfers {
    store: Arc<EncryptedStore>,
    outbound: OnceLock<OutboundClient>,
    wall: TransferClock,
    budget: Duration,
    commit_fault: Option<CommitFault>,
}

impl std::fmt::Debug for Transfers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transfers")
            .field("outbound", &self.outbound.get())
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl Transfers {
    pub fn new(store: Arc<EncryptedStore>) -> Self {
        Self {
            store,
            outbound: OnceLock::new(),
            wall: real_wall(),
            budget: ADMIN_OP_BUDGET,
            commit_fault: None,
        }
    }

    /// Date rows and expire them on `wall` instead of the machine's clock. Only tests
    /// change it.
    pub fn with_clock(mut self, wall: TransferClock) -> Self {
        self.wall = wall;
        self
    }

    /// Give each admin op `budget` for all its outbound calls together instead of
    /// [`ADMIN_OP_BUDGET`]. Only tests shorten it.
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// Fail `send`'s commit between the outgoing row and its audit row whenever `fault`
    /// returns true. A test seam with no production caller: it is how a test proves the
    /// two commit together or not at all, and that nothing is sent after a failed
    /// commit.
    pub fn with_commit_fault(mut self, fault: CommitFault) -> Self {
        self.commit_fault = Some(fault);
        self
    }

    /// Attach the outbound client key lookups and deliveries go through. Only the first
    /// call takes effect; returns whether this one did.
    pub fn attach_outbound(&self, client: OutboundClient) -> bool {
        self.outbound.set(client).is_ok()
    }

    fn now(&self) -> i64 {
        (self.wall)()
    }

    /// `ck auth transfer send --id <credential> --to <member>`.
    ///
    /// Reads the receiver's announced key first (none: `remote_setup_incomplete`,
    /// naming the receiver; a failed lookup: `callosum_unavailable`), with nothing
    /// committed either way. Then it seals the body once, commits the outgoing row and
    /// `transfer_out` together, and only then delivers. A delivery that fails or runs
    /// out of budget still reports the committed row, which `--resume` redelivers.
    pub async fn send(&self, credential_id: &str, to: &str) -> Result<SendReport, TransferRefusal> {
        if !valid_member_id(to) || credential_id.is_empty() {
            return Err(TransferRefusal::invalid_params());
        }
        let budget = tokio::time::Instant::now() + self.budget;
        let now = self.now();
        let _ = self.store.expire_outgoing_transfers(now);
        let own = match own_key(&self.store) {
            Ok(Ok(own)) => own,
            Ok(Err(self_id)) => return Err(TransferRefusal::transfer_key_missing(self_id)),
            Err(_) => return Err(TransferRefusal::store_error()),
        };
        let body = self.outgoing_body(credential_id)?;
        let receiver_key = match peer_key(self.outbound.get(), to, budget).await {
            Lookup::Found(key) => key,
            Lookup::Absent => return Err(TransferRefusal::setup_incomplete(Some(to.to_string()))),
            Lookup::Unavailable => return Err(TransferRefusal::callosum_unavailable()),
        };
        let transfer_id = random_transfer_id().ok_or_else(TransferRefusal::store_error)?;
        let aad = serde_json::to_string(&TransferAad {
            transfer_id: transfer_id.clone(),
            credential_id: credential_id.to_string(),
            sender: own.self_id.clone(),
            receiver: to.to_string(),
            recipient_key_id: receiver_key.key_id.clone(),
        })
        .map_err(|_| TransferRefusal::store_error())?;
        let plaintext = serde_json::to_vec(&body).map_err(|_| TransferRefusal::store_error())?;
        let (enc, ciphertext) = credentials_core::kem::seal_auth(
            &own.pem,
            &receiver_key.public,
            &plaintext,
            TRANSFER_INFO,
            aad.as_bytes(),
        )
        .map_err(|error| match error {
            credentials_core::kem::SealError::TooLarge => TransferRefusal::too_large(),
            credentials_core::kem::SealError::InvalidRecipient => {
                TransferRefusal::setup_incomplete(Some(to.to_string()))
            }
            credentials_core::kem::SealError::UnusableKey
            | credentials_core::kem::SealError::Failed => {
                TransferRefusal::transfer_key_missing(Some(own.self_id.clone()))
            }
        })?;
        let fault = self.commit_fault.clone();
        let fault_hook = move || fault.as_ref().is_some_and(|fault| fault());
        let row = self
            .store
            .commit_outgoing_transfer_audited(
                &NewOutgoingTransfer {
                    transfer_id,
                    receiver_member: to.to_string(),
                    credential_id: credential_id.to_string(),
                    sealed: SealedTransfer {
                        enc,
                        ciphertext,
                        aad: aad.into_bytes(),
                    },
                    created_at_ms: now,
                },
                Some(&fault_hook),
            )
            .map_err(|_| TransferRefusal::store_error())?;
        Ok(self.deliver_row(&row, budget).await)
    }

    /// `ck auth transfer send --resume <transfer-id>`: redeliver the stored envelope,
    /// byte for byte. It never re-seals and writes no second `transfer_out`. A row
    /// already deleted (a terminal reply, or seven days) answers `transfer_gone`; a row
    /// abandoned by a key replacement answers `transfer_abandoned` and sends nothing.
    pub async fn resume(&self, transfer_id: &str) -> Result<SendReport, TransferRefusal> {
        if !is_lower_hex_16_bytes(transfer_id) {
            return Err(TransferRefusal::invalid_params());
        }
        let budget = tokio::time::Instant::now() + self.budget;
        let _ = self.store.expire_outgoing_transfers(self.now());
        let row = self
            .store
            .outgoing_transfer(transfer_id)
            .map_err(|_| TransferRefusal::store_error())?
            .ok_or(TransferRefusal::new("transfer_gone", "permanent"))?;
        if row.state == OutgoingTransferState::Abandoned {
            return Err(TransferRefusal::new("transfer_abandoned", "permanent"));
        }
        Ok(self.deliver_row(&row, budget).await)
    }

    /// The versioned body for `credential_id`, refused unless the record may leave.
    fn outgoing_body(&self, credential_id: &str) -> Result<TransferBody, TransferRefusal> {
        if is_vault_transfer_id(credential_id) {
            return Err(TransferRefusal::ineligible(Ineligible::TransferKey));
        }
        if self
            .store
            .remote_record(credential_id)
            .map_err(|_| TransferRefusal::store_error())?
            .is_some()
        {
            return Err(TransferRefusal::ineligible(Ineligible::RemoteRecord));
        }
        let record = match self.store.get(credential_id) {
            Ok(record) => record,
            Err(StoreOpError::NotFound) => return Err(TransferRefusal::not_found()),
            Err(StoreOpError::NeedsReauth) => {
                return Err(TransferRefusal::new("needs_reauth", "auth_required"))
            }
            Err(_) => return Err(TransferRefusal::store_error()),
        };
        transfer_eligibility(
            record.kind,
            record.oauth.is_some(),
            record.refresh_adapter.is_some(),
            record.expires_at_ms,
        )
        .map_err(TransferRefusal::ineligible)?;
        let categories = self
            .store
            .categories(credential_id)
            .map_err(|_| TransferRefusal::store_error())?;
        let provider_ids = self
            .store
            .provider_ids(credential_id)
            .map_err(|_| TransferRefusal::store_error())?;
        Ok(TransferBody {
            version: TRANSFER_BODY_VERSION,
            credential_id: credential_id.to_string(),
            kind: record.kind,
            payload: base64::engine::general_purpose::STANDARD.encode(record.payload.expose()),
            categories,
            identity: WireIdentity {
                account_id: record.identity.account_id.clone(),
                email: record.identity.email.clone(),
                org_name: record.identity.org_name.clone(),
            },
            provider_ids,
            detected_plan: record.detected_plan.as_ref().map(|plan| WirePlan {
                tier: plan.tier.clone(),
                raw: plan.raw.clone(),
                observed_at_ms: plan.observed_at_ms,
            }),
            expires_at_ms: record.expires_at_ms,
        })
    }

    /// Deliver one committed row's stored bytes and apply the sender's action for the
    /// reply: keep the row (and note the reply) or delete it.
    async fn deliver_row(
        &self,
        row: &OutgoingTransfer,
        budget: tokio::time::Instant,
    ) -> SendReport {
        let reply = self.deliver_once(row, budget).await;
        let row_kept = if reply.keeps_row() {
            let _ = self.store.note_outgoing_transfer_attempt(
                &row.transfer_id,
                safe_code(reply.code()),
                self.now(),
            );
            true
        } else {
            let _ = self.store.delete_outgoing_transfer(&row.transfer_id);
            false
        };
        SendReport {
            transfer_id: row.transfer_id.clone(),
            credential_id: row.credential_id.clone(),
            receiver: row.receiver_member.clone(),
            reply,
            row_kept,
        }
    }

    async fn deliver_once(
        &self,
        row: &OutgoingTransfer,
        budget: tokio::time::Instant,
    ) -> DeliveryReply {
        let unreachable = || DeliveryReply::refused("home_unreachable", "transient");
        let Some(client) = self.outbound.get() else {
            return unreachable();
        };
        let Some(params) = deliver_params(&row.sealed) else {
            return DeliveryReply::refused("store_error", "transient");
        };
        let Some(left) = budget
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|left| !left.is_zero())
        else {
            return unreachable();
        };
        match client
            .call(
                &receiver_route_key(&row.receiver_member),
                RouteCall {
                    target: management_surface(&fed_provider_module(&row.receiver_member)),
                    prelude: None,
                    request: json!({ "method": OP_TRANSFER_DELIVER, "params": params }),
                },
                left,
            )
            .await
        {
            Ok(reply) => classify_delivery(&reply),
            Err(_) => unreachable(),
        }
    }

    /// `ck auth transfer receive`: every transfer waiting for this operator, after
    /// expiring those past their retention.
    pub fn receive(&self) -> Result<Vec<IncomingTransfer>, TransferRefusal> {
        self.store
            .expire_incoming_transfers(self.now())
            .map_err(|_| TransferRefusal::store_error())?;
        Ok(self
            .store
            .list_incoming_transfers()
            .map_err(|_| TransferRefusal::store_error())?
            .into_iter()
            .filter(|row| row.state == IncomingTransferState::Pending)
            .collect())
    }

    /// Expire, at this vault's clock, pending incoming transfers and outgoing rows past
    /// their retention. Returns how many of each.
    pub fn expire(&self) -> Result<(usize, usize), TransferRefusal> {
        let now = self.now();
        let incoming = self
            .store
            .expire_incoming_transfers(now)
            .map_err(|_| TransferRefusal::store_error())?;
        let outgoing = self
            .store
            .expire_outgoing_transfers(now)
            .map_err(|_| TransferRefusal::store_error())?;
        Ok((incoming, outgoing))
    }

    /// `ck auth transfer accept <transfer-id> --from <member> [--replace]`.
    ///
    /// Reads the STORED sender's announced key (a failed lookup is
    /// `callosum_unavailable`: transient, the row stays pending, nothing is written),
    /// opens the envelope again and validates the body again. An envelope that does
    /// not open against a key actually obtained marks the row rejected
    /// (`remote_seal_invalid`, with a `transfer_reject` row), and so does a body that
    /// fails validation. Otherwise the record, its categories, its provider ids, the
    /// accepted marker and `transfer_in` commit in one transaction.
    pub async fn accept(
        &self,
        transfer_id: &str,
        from: &str,
        replace: bool,
    ) -> Result<AcceptReport, TransferRefusal> {
        if !is_lower_hex_16_bytes(transfer_id) || !valid_member_id(from) {
            return Err(TransferRefusal::invalid_params());
        }
        let budget = tokio::time::Instant::now() + self.budget;
        self.store
            .expire_incoming_transfers(self.now())
            .map_err(|_| TransferRefusal::store_error())?;
        let row = self
            .store
            .incoming_transfer(from, transfer_id)
            .map_err(|_| TransferRefusal::store_error())?
            .ok_or_else(TransferRefusal::not_found)?;
        if row.state != IncomingTransferState::Pending {
            return Ok(AcceptReport::AlreadyDecided(row.state));
        }
        let Some(sealed) = row.sealed.clone() else {
            return Err(TransferRefusal::store_error());
        };
        let own = match own_key(&self.store) {
            Ok(Ok(own)) => own,
            Ok(Err(self_id)) => return Err(TransferRefusal::transfer_key_missing(self_id)),
            Err(_) => return Err(TransferRefusal::store_error()),
        };
        let sender_key = match peer_key(self.outbound.get(), &row.sender_member, budget).await {
            Lookup::Found(key) => key,
            Lookup::Absent => {
                return Err(TransferRefusal::setup_incomplete(Some(
                    row.sender_member.clone(),
                )))
            }
            Lookup::Unavailable => return Err(TransferRefusal::callosum_unavailable()),
        };
        let (aad, valid) = match open_transfer(
            &own,
            &row.sender_member,
            &sender_key.public,
            &sealed,
            Some(&row.transfer_id),
        ) {
            Ok((aad, valid, _)) => (aad, valid),
            Err(refusal) => {
                let reason = if refusal.code == TransferRefusal::body_invalid().code {
                    REJECT_BODY_INVALID
                } else {
                    REJECT_REMOTE_SEAL_INVALID
                };
                self.store
                    .reject_incoming_transfer_audited(&row.sender_member, &row.transfer_id, reason)
                    .map_err(|_| TransferRefusal::store_error())?;
                return Err(refusal);
            }
        };
        let outcome = self
            .store
            .accept_incoming_transfer_audited(&TransferAcceptance {
                sender_member: row.sender_member.clone(),
                transfer_id: row.transfer_id.clone(),
                body_hash: row.body_hash.clone(),
                credential_id: aad.credential_id.clone(),
                record: valid.record,
                categories: valid.categories,
                provider_ids: valid.provider_ids,
                replace,
            })
            .map_err(|error| match error {
                StoreOpError::AlreadyExists => {
                    TransferRefusal::new("credential_exists", "permanent")
                }
                StoreOpError::CredentialIdIsRemote => {
                    TransferRefusal::new("credential_id_is_remote", "permanent")
                }
                StoreOpError::Encode(message)
                    if message.starts_with("transfer_replace_refused") =>
                {
                    TransferRefusal::new("transfer_replace_refused", "permanent")
                }
                StoreOpError::NotFound => TransferRefusal::not_found(),
                _ => TransferRefusal::store_error(),
            })?;
        Ok(match outcome {
            TransferAcceptOutcome::Accepted { record_version } => AcceptReport::Accepted {
                credential_id: aad.credential_id,
                record_version,
            },
            TransferAcceptOutcome::AlreadyDecided(state) => AcceptReport::AlreadyDecided(state),
        })
    }

    /// `ck auth transfer reject <transfer-id> --from <member>`: the row's sealed bytes are
    /// dropped and its id kept as rejected, with a `transfer_reject` row.
    pub fn reject(
        &self,
        transfer_id: &str,
        from: &str,
    ) -> Result<IncomingTransferState, TransferRefusal> {
        if !is_lower_hex_16_bytes(transfer_id) || !valid_member_id(from) {
            return Err(TransferRefusal::invalid_params());
        }
        self.store
            .reject_incoming_transfer_audited(from, transfer_id, REJECT_BY_OPERATOR)
            .map_err(|error| match error {
                StoreOpError::NotFound => TransferRefusal::not_found(),
                _ => TransferRefusal::store_error(),
            })
    }

    /// `ck auth transfer init --replace`: replace a transfer key found off `Active`
    /// with a fresh one, rejecting every pending transfer and abandoning every outgoing
    /// one in the same transaction. Refused with `transfer_key_protected` while the key
    /// is `Active`. The returned ids are what the operator re-sends with a fresh `send`.
    /// `actor` is the admin actor the key replacement is audited under.
    pub fn replace_transfer_key(
        &self,
        actor: &str,
    ) -> Result<TransferKeyRecovery, TransferRefusal> {
        let pem =
            credentials_core::kem::generate_key().map_err(|_| TransferRefusal::store_error())?;
        let record =
            VaultRecord::new_static(CredentialKind::KemKey, "operator", pem.into_bytes(), None);
        self.store
            .recover_vault_transfer_key_audited(
                &record,
                AuditCtx::route_admin(AuditOp::Overwrite, actor),
            )
            .map_err(|error| match error {
                StoreOpError::TransferKeyProtected => {
                    TransferRefusal::new("transfer_key_protected", "permanent")
                }
                StoreOpError::NotFound => TransferRefusal::transfer_key_missing(None),
                _ => TransferRefusal::store_error(),
            })
    }
}
