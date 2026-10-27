//! Shared vocabulary for home-vault federation: member ids, member-grant operations,
//! the store settings that govern federation, and the `payload_hash` encodings of the
//! federation audit ops.
//!
//! A "member" is another computer's vault, named everywhere by one canonical string,
//! `fed-computer:<fp>`, where `<fp>` is 32 lowercase hex: the first 16 bytes of
//! SHA-256 over the member's Noise static key, as callosum derives it. The same string
//! is the CLI argument, the grant principal, the remote record's home, the audit actor
//! and the value carried in authenticated `aad` fields, so one validator serves all of
//! them.
//!
//! The payload hashes are pinned here, beside their field lists, because the audit
//! chain stores only the hash: a verifier recomputes it from the fields, so the field
//! order and each field's encoding are part of the chain's meaning. Every hash is
//! lowercase-hex SHA-256 over the compact JSON of one object whose fields appear in
//! the order listed on each function.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plan_detection::DetectedPlan;
use crate::record::RecordIdentity;
use crate::store::{GrantOperation, StoreOpError};

/// The prefix of every member id.
pub const MEMBER_ID_PREFIX: &str = "fed-computer:";

/// The settings row holding the member-mapping gate (`true`/`false`). Absent means off.
pub const MEMBER_MAPPING_SETTING: &str = "federation.member_mapping";

/// The settings row holding this vault's own member id. Absent means unset.
pub const SELF_MEMBER_SETTING: &str = "federation.self_member";

/// The credential-id prefix of the vault transfer key: a `KemKey` that signs the
/// federation seals (token replies, transfer envelopes) and nothing else. Every rule
/// that keeps it out of ordinary credential reach matches on this prefix rather than
/// on the exact id, so a second transfer key of another generation is fenced the same
/// way.
pub const VAULT_TRANSFER_ID_PREFIX: &str = "kem:vault-transfer:";

/// The one id `ck auth transfer init` creates.
pub const VAULT_TRANSFER_ID: &str = "kem:vault-transfer:1";

/// The principal that may hold the announce `read` grant on the transfer key: that
/// grant is how callosum announces the key's public half.
pub const TRANSFER_ANNOUNCE_PRINCIPAL: &str = "reserved:callosum";

/// True for any id starting [`VAULT_TRANSFER_ID_PREFIX`].
pub fn is_vault_transfer_id(credential_id: &str) -> bool {
    credential_id.starts_with(VAULT_TRANSFER_ID_PREFIX)
}

/// Whether `principal` may hold `operation` on the transfer key `credential_id` at
/// all. Exactly one grant is admitted: the `read` that `credential.public_key` needs,
/// to the announce principal. Every other grant is refused with
/// `transfer_key_reserved`, because a grant of `open`, `seal`, `sign` or `list` over
/// the transfer key would hand a caller the federation key or let it sign as this
/// vault. Ids outside the prefix are not this fence's business and pass.
///
/// Callers pass the id and the full principal (`reserved:callosum`), which is the form
/// a grant row and an operator both use. Shared by the store (both grant writers) and
/// the CLI `grant`/`revoke-grant` verbs, so the refusal text and the admitted case are
/// defined once.
pub fn transfer_key_admits_grant(
    credential_id: &str,
    principal: &str,
    operation: GrantOperation,
) -> Result<(), String> {
    if !is_vault_transfer_id(credential_id) {
        return Ok(());
    }
    if operation == GrantOperation::Read && principal == TRANSFER_ANNOUNCE_PRINCIPAL {
        return Ok(());
    }
    Err(format!(
        "transfer_key_reserved: {credential_id} is the vault transfer key; its only \
         grant is read to {TRANSFER_ANNOUNCE_PRINCIPAL} for the public-key announce"
    ))
}

/// True for exactly `fed-computer:` followed by 32 lowercase hex characters.
pub fn valid_member_id(value: &str) -> bool {
    value
        .strip_prefix(MEMBER_ID_PREFIX)
        .is_some_and(is_lower_hex_16_bytes)
}

/// Refuse anything but a canonical member id with [`StoreOpError::InvalidMemberId`].
pub fn check_member_id(value: &str) -> Result<(), StoreOpError> {
    if valid_member_id(value) {
        Ok(())
    } else {
        Err(StoreOpError::InvalidMemberId)
    }
}

/// True for exactly 32 lowercase hex characters: the encoding of a transfer id, an
/// incarnation, a token nonce and a member fingerprint.
pub fn is_lower_hex_16_bytes(value: &str) -> bool {
    is_lower_hex_of_len(value, 32)
}

/// True for exactly 64 lowercase hex characters: the encoding of a SHA-256 digest.
pub fn is_lower_hex_sha256(value: &str) -> bool {
    is_lower_hex_of_len(value, 64)
}

fn is_lower_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// What a member grant lets another member's vault do here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberGrantOperation {
    /// Fetch short-lived access tokens for a rotating login homed in this vault.
    RemoteRead,
    /// Deliver sealed static-key transfers to this vault.
    TransferDeliver,
    /// Forward agent-secret calls (`secret.use` and the flow-grant calls) to this vault,
    /// which holds the account's secrets. Takes no selector: the secret grants made
    /// here, not the member grant, decide which secret a call may use.
    SecretUse,
}

impl MemberGrantOperation {
    /// The stored and audited spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RemoteRead => "remote_read",
            Self::TransferDeliver => "transfer_deliver",
            Self::SecretUse => "secret_use",
        }
    }

    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "remote_read" => Some(Self::RemoteRead),
            "transfer_deliver" => Some(Self::TransferDeliver),
            "secret_use" => Some(Self::SecretUse),
            _ => None,
        }
    }
}

/// Which credentials a member grant reaches. `remote_read` takes an exact id or a
/// category; `transfer_deliver` and `secret_use` take no selector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "selector", rename_all = "snake_case")]
pub enum MemberGrantSelector {
    Exact(String),
    Category(String),
    None,
}

impl MemberGrantSelector {
    /// The stored `selector_kind` column.
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Exact(_) => "exact",
            Self::Category(_) => "category",
            Self::None => "none",
        }
    }

    /// The stored `selector` column: empty for [`Self::None`].
    pub fn selector_str(&self) -> &str {
        match self {
            Self::Exact(selector) | Self::Category(selector) => selector,
            Self::None => "",
        }
    }

    pub(crate) fn from_stored(kind: &str, selector: String) -> Option<Self> {
        match kind {
            "exact" => Some(Self::Exact(selector)),
            "category" => Some(Self::Category(selector)),
            "none" if selector.is_empty() => Some(Self::None),
            _ => None,
        }
    }
}

/// One stored member grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberGrant {
    pub member_id: String,
    pub operation: MemberGrantOperation,
    pub selector: MemberGrantSelector,
    /// The member's pairing id when the grant was made. The grant counts only while
    /// it equals the member's current pairing id.
    pub pairing_id: String,
    pub created_at_ms: i64,
}

/// The state of a remote record as the home last reported it authoritatively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteHomeState {
    Active,
    NeedsReauth,
    Corrupt,
}

impl RemoteHomeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::NeedsReauth => "needs_reauth",
            Self::Corrupt => "corrupt",
        }
    }

    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "needs_reauth" => Some(Self::NeedsReauth),
            "corrupt" => Some(Self::Corrupt),
            _ => None,
        }
    }
}

/// What `remote add` stores: the home's non-secret description of a rotating login,
/// copied from one validated home reply. The token in that reply is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRemoteRecord {
    pub credential_id: String,
    pub home_member: String,
    pub refresh_adapter: Option<String>,
    pub detected_plan: Option<DetectedPlan>,
    pub identity: RecordIdentity,
    /// The home's `record_version` in the reply `add` fetched.
    pub home_version: u64,
    /// The home's categories, which seed this vault's own category set once.
    pub categories: Vec<String>,
}

/// One `remote_records` row. Nothing in it is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRecord {
    pub credential_id: String,
    pub home_member: String,
    /// 32 lowercase hex, new on every `remote add`.
    pub incarnation: String,
    pub refresh_adapter: Option<String>,
    pub detected_plan: Option<DetectedPlan>,
    pub identity: RecordIdentity,
    pub last_home_version: u64,
    pub last_home_state: RemoteHomeState,
    pub last_home_error: Option<String>,
    pub last_fetch_outcome: Option<String>,
    pub last_fetch_at_ms: Option<i64>,
    pub reported_version: Option<u64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// What one conditional write to a remote record did.
///
/// Every write after a fetch is conditioned on the record's `incarnation`, so a reply
/// fetched for an earlier `remote add` of the same id (removed, then added again with
/// another home) can never land on the new record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteRecordWrite {
    /// The row changed.
    Changed,
    /// The row already held these values, so nothing was written.
    Unchanged,
    /// No row has this id and incarnation: the record was removed, or removed and added
    /// again. The caller must discard the reply it was applying.
    StaleIncarnation,
}

/// The home-owned description carried by one validated home reply that this vault
/// applies as authoritative. Nothing in it is secret: the token in the same reply is
/// never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteHomeSuccess {
    /// The home's `record_version` in the reply.
    pub home_version: u64,
    pub refresh_adapter: Option<String>,
    pub detected_plan: Option<DetectedPlan>,
    pub identity: RecordIdentity,
    /// The reply carried `recheck_in_ms`: the home held back a reported refresh for
    /// its cooldown, so a forwarded report at this version is still unresolved.
    pub recheck_pending: bool,
}

/// One remote record together with this vault's own metadata for it (categories,
/// provider ids, operator plan tier), read from one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteInventoryRow {
    pub record: RemoteRecord,
    pub categories: Vec<String>,
    pub provider_ids: Vec<String>,
    pub plan_tier: Option<String>,
}

// ---------------------------------------------------------------------------------
// Sealed static-key transfers
// ---------------------------------------------------------------------------------

/// How many transfers one sender may have waiting for the operator here at once.
pub const TRANSFER_PENDING_PER_SENDER_CAP: u32 = 8;

/// How many transfers may wait for the operator here at once, across all senders.
pub const TRANSFER_PENDING_TOTAL_CAP: u32 = 64;

/// How long an unaccepted transfer waits on the receiver, and how long the sender keeps
/// an outgoing transfer it has not had a terminal reply for: seven days.
pub const TRANSFER_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// The `transfer_reject` reason when a pending transfer's envelope did not open
/// against a key actually obtained, or the receiver replaced its own key.
pub const REJECT_REMOTE_SEAL_INVALID: &str = "remote_seal_invalid";

/// The `transfer_reject` reason when the opened body failed receive-side validation.
pub const REJECT_BODY_INVALID: &str = "transfer_body_invalid";

/// The `transfer_reject` reason when the receiving operator refused the transfer.
pub const REJECT_BY_OPERATOR: &str = "rejected_by_operator";

/// The `transfer_reject` reason written on the SENDER for an outgoing transfer sealed
/// under a transfer key this vault has since replaced.
pub const REJECT_SENDER_KEY_REPLACED: &str = "sender_key_replaced";

/// One sealed transfer envelope exactly as it travels: the HPKE encapsulation, the
/// ciphertext and the authenticated `aad` bytes. Nothing in it is plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedTransfer {
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

impl std::fmt::Debug for SealedTransfer {
    // Sealed bytes are not secret, but they are long and say nothing to a reader.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedTransfer")
            .field("enc_len", &self.enc.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .field("aad_len", &self.aad.len())
            .finish()
    }
}

impl SealedTransfer {
    /// The dedup key: SHA-256 over `enc || ciphertext`, as 64 lowercase hex. The aad is
    /// left out because it is bound into the ciphertext already.
    pub fn body_hash(&self) -> String {
        transfer_body_hash(&self.enc, &self.ciphertext)
    }
}

/// SHA-256 over `enc || ciphertext`, as 64 lowercase hex.
pub fn transfer_body_hash(enc: &[u8], ciphertext: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(enc);
    hasher.update(ciphertext);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Where a received transfer stands. Every state but `Pending` is terminal and is kept
/// forever with its id and hash, so a resend of the same bytes answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncomingTransferState {
    Pending,
    Accepted,
    Rejected,
    Expired,
}

impl IncomingTransferState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "accepted" => Some(Self::Accepted),
            "rejected" => Some(Self::Rejected),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// A transfer to record as pending, after its envelope opened and its body validated.
/// Only non-secret metadata travels beside the sealed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIncomingTransfer {
    pub sender_member: String,
    /// The transfer id from the authenticated `aad`, never from an outer field.
    pub transfer_id: String,
    pub credential_id: String,
    /// The body's kind, in its wire spelling (`api_key`, `dsn`, `cookie`, `opaque`).
    pub kind: String,
    pub categories: Vec<String>,
    /// The plaintext body's length in bytes.
    pub size_bytes: u64,
    pub sealed: SealedTransfer,
    pub received_at_ms: i64,
}

/// One `pending_transfers` row. The sealed bytes are present only while pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingTransfer {
    pub sender_member: String,
    pub transfer_id: String,
    pub body_hash: String,
    pub state: IncomingTransferState,
    pub credential_id: String,
    pub kind: String,
    pub categories: Vec<String>,
    pub size_bytes: u64,
    pub sealed: Option<SealedTransfer>,
    pub reject_reason: Option<String>,
    pub received_at_ms: i64,
    pub expires_at_ms: i64,
    pub decided_at_ms: Option<i64>,
}

/// What recording a delivered transfer did. Decided in one write transaction that
/// rechecks the dedup and the queue bounds, so concurrent deliveries cannot overfill
/// the queue or record one envelope twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingInsert {
    /// The transfer is now pending.
    Inserted,
    /// The same bytes from the same sender are already recorded, in this state.
    Known(IncomingTransferState),
    /// The sender already has a different transfer under this transfer id.
    Conflict,
    /// The sender's queue or the whole queue is full.
    QueueFull,
}

/// How many transfers are pending: from one sender, and in total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingTransferCounts {
    pub from_sender: u32,
    pub total: u32,
}

impl PendingTransferCounts {
    /// Whether one more pending transfer from this sender would overfill a queue.
    pub fn full(self) -> bool {
        self.from_sender >= TRANSFER_PENDING_PER_SENDER_CAP
            || self.total >= TRANSFER_PENDING_TOTAL_CAP
    }
}

/// Where an outgoing transfer stands on the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutgoingTransferState {
    /// Waiting for a terminal reply from the receiver.
    Pending,
    /// Sealed under a transfer key this vault has since replaced: it can only fail at
    /// the receiver, so it is never delivered again.
    Abandoned,
}

impl OutgoingTransferState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Abandoned => "abandoned",
        }
    }

    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }
}

/// An outgoing transfer to commit before its first delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOutgoingTransfer {
    pub transfer_id: String,
    pub receiver_member: String,
    pub credential_id: String,
    pub sealed: SealedTransfer,
    pub created_at_ms: i64,
}

/// One `outgoing_transfers` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingTransfer {
    pub transfer_id: String,
    pub receiver_member: String,
    pub credential_id: String,
    pub body_hash: String,
    pub sealed: SealedTransfer,
    pub state: OutgoingTransferState,
    pub last_reply_code: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub last_attempt_at_ms: Option<i64>,
}

/// What accepting one pending transfer writes, all in one transaction.
#[derive(Debug, Clone)]
pub struct TransferAcceptance {
    pub sender_member: String,
    pub transfer_id: String,
    /// The hash of the envelope the caller opened. The accept is refused if the stored
    /// row no longer holds these bytes.
    pub body_hash: String,
    pub credential_id: String,
    /// The record built from the opened body. The store assigns its version.
    pub record: crate::record::VaultRecord,
    /// The body's categories. They replace the catalog defaults a new record gets.
    pub categories: Vec<String>,
    pub provider_ids: Vec<String>,
    /// Replace an existing record of the same eligible kind instead of refusing it.
    pub replace: bool,
}

/// What an accept did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferAcceptOutcome {
    /// The record was written at this version and the transfer is now accepted.
    Accepted { record_version: u64 },
    /// The transfer was already decided (another accept won, or it was rejected or
    /// expired); nothing was written.
    AlreadyDecided(IncomingTransferState),
}

/// One pending transfer the transfer-key recovery marked rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredIncoming {
    pub sender_member: String,
    pub transfer_id: String,
    pub credential_id: String,
}

/// One outgoing transfer the transfer-key recovery marked abandoned. The operator
/// sends the credential again with a fresh `send`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredOutgoing {
    pub transfer_id: String,
    pub credential_id: String,
    pub receiver_member: String,
}

/// What `transfer init --replace` did besides replacing the key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferKeyRecovery {
    pub rejected_incoming: Vec<RecoveredIncoming>,
    pub abandoned_outgoing: Vec<RecoveredOutgoing>,
}

fn sha256_hex_of_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("audit payload objects always serialize");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(field: &str, expected: &str) -> StoreOpError {
    StoreOpError::Encode(format!("{field} must be {expected}"))
}

/// `remote_issue`: `{credential_id, record_version}`, the version as a JSON number.
pub fn remote_issue_payload_hash(credential_id: &str, record_version: u64) -> String {
    #[derive(Serialize)]
    struct Payload<'a> {
        credential_id: &'a str,
        record_version: u64,
    }
    sha256_hex_of_json(&Payload {
        credential_id,
        record_version,
    })
}

/// `transfer_out` and `transfer_in`: `{transfer_id, body_hash}`. The transfer id is 32
/// lowercase hex; the body hash is SHA-256(`enc || ciphertext`) as 64 lowercase hex.
pub fn transfer_payload_hash(transfer_id: &str, body_hash: &str) -> Result<String, StoreOpError> {
    if !is_lower_hex_16_bytes(transfer_id) {
        return Err(invalid("transfer_id", "32 lowercase hex characters"));
    }
    if !is_lower_hex_sha256(body_hash) {
        return Err(invalid("body_hash", "64 lowercase hex characters"));
    }
    #[derive(Serialize)]
    struct Payload<'a> {
        transfer_id: &'a str,
        body_hash: &'a str,
    }
    Ok(sha256_hex_of_json(&Payload {
        transfer_id,
        body_hash,
    }))
}

/// `transfer_reject`: `{transfer_id, reason}`, the reason being the refusal code.
pub fn transfer_reject_payload_hash(
    transfer_id: &str,
    reason: &str,
) -> Result<String, StoreOpError> {
    if !is_lower_hex_16_bytes(transfer_id) {
        return Err(invalid("transfer_id", "32 lowercase hex characters"));
    }
    if reason.is_empty() {
        return Err(invalid("reason", "a refusal code"));
    }
    #[derive(Serialize)]
    struct Payload<'a> {
        transfer_id: &'a str,
        reason: &'a str,
    }
    Ok(sha256_hex_of_json(&Payload {
        transfer_id,
        reason,
    }))
}

/// `member_grant_create` and `member_grant_revoke`: `{operation, selector_kind,
/// selector, pairing_id}`, each the stored string (`selector` is empty for kind `none`).
pub fn member_grant_payload_hash(
    operation: MemberGrantOperation,
    selector: &MemberGrantSelector,
    pairing_id: &str,
) -> String {
    #[derive(Serialize)]
    struct Payload<'a> {
        operation: &'a str,
        selector_kind: &'a str,
        selector: &'a str,
        pairing_id: &'a str,
    }
    sha256_hex_of_json(&Payload {
        operation: operation.as_str(),
        selector_kind: selector.kind_str(),
        selector: selector.selector_str(),
        pairing_id,
    })
}

/// `remote_add` and `remote_remove`: `{incarnation}`, 32 lowercase hex.
pub fn remote_membership_payload_hash(incarnation: &str) -> Result<String, StoreOpError> {
    if !is_lower_hex_16_bytes(incarnation) {
        return Err(invalid("incarnation", "32 lowercase hex characters"));
    }
    #[derive(Serialize)]
    struct Payload<'a> {
        incarnation: &'a str,
    }
    Ok(sha256_hex_of_json(&Payload { incarnation }))
}

/// `federation_gate_set`: `{value}`, the new gate as a JSON boolean.
pub fn federation_gate_payload_hash(value: bool) -> String {
    #[derive(Serialize)]
    struct Payload {
        value: bool,
    }
    sha256_hex_of_json(&Payload { value })
}

/// `federation_self_set`: `{member}`, the new self member id.
pub fn federation_self_payload_hash(member: &str) -> String {
    #[derive(Serialize)]
    struct Payload<'a> {
        member: &'a str,
    }
    sha256_hex_of_json(&Payload { member })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0123456789abcdef0123456789abcdef";

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn member_ids_are_exactly_the_prefix_and_32_lowercase_hex() {
        assert!(valid_member_id(&format!("fed-computer:{FP}")));
        for bad in [
            String::new(),
            FP.to_string(),
            format!("fed-computer:{}", &FP[..31]),
            format!("fed-computer:{FP}0"),
            format!("fed-computer:{}", FP.to_uppercase()),
            format!("fed-phone:{FP}"),
            format!("Fed-computer:{FP}"),
            format!("fed-computer:{}g", &FP[..31]),
            format!("fed-computer: {}", &FP[..31]),
        ] {
            assert!(!valid_member_id(&bad), "{bad:?} must be refused");
        }
        assert!(matches!(
            check_member_id("fed-sim:x"),
            Err(StoreOpError::InvalidMemberId)
        ));
    }

    /// Each hash is pinned to the exact JSON bytes the constraints table lists, so a
    /// field reordered, renamed or re-encoded (a version as a string, a hash in
    /// uppercase) reddens here instead of silently changing what the chain commits to.
    #[test]
    fn payload_hashes_cover_the_listed_fields_in_order_with_the_listed_encodings() {
        let transfer_id = "00112233445566778899aabbccddeeff";
        let body_hash = "ab".repeat(32);
        assert_eq!(
            remote_issue_payload_hash("oauth:anthropic", 7),
            sha256_hex(br#"{"credential_id":"oauth:anthropic","record_version":7}"#)
        );
        assert_eq!(
            transfer_payload_hash(transfer_id, &body_hash).unwrap(),
            sha256_hex(
                format!(r#"{{"transfer_id":"{transfer_id}","body_hash":"{body_hash}"}}"#)
                    .as_bytes()
            )
        );
        assert_eq!(
            transfer_reject_payload_hash(transfer_id, "remote_seal_invalid").unwrap(),
            sha256_hex(
                format!(r#"{{"transfer_id":"{transfer_id}","reason":"remote_seal_invalid"}}"#)
                    .as_bytes()
            )
        );
        assert_eq!(
            member_grant_payload_hash(
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Category("llm-provider".into()),
                "pair-1",
            ),
            sha256_hex(
                br#"{"operation":"remote_read","selector_kind":"category","selector":"llm-provider","pairing_id":"pair-1"}"#
            )
        );
        assert_eq!(
            member_grant_payload_hash(
                MemberGrantOperation::TransferDeliver,
                &MemberGrantSelector::None,
                "pair-1",
            ),
            sha256_hex(
                br#"{"operation":"transfer_deliver","selector_kind":"none","selector":"","pairing_id":"pair-1"}"#
            )
        );
        assert_eq!(
            remote_membership_payload_hash(transfer_id).unwrap(),
            sha256_hex(format!(r#"{{"incarnation":"{transfer_id}"}}"#).as_bytes())
        );
        assert_eq!(
            federation_gate_payload_hash(true),
            sha256_hex(br#"{"value":true}"#)
        );
        assert_eq!(
            federation_gate_payload_hash(false),
            sha256_hex(br#"{"value":false}"#)
        );
        let member = format!("fed-computer:{FP}");
        assert_eq!(
            federation_self_payload_hash(&member),
            sha256_hex(format!(r#"{{"member":"{member}"}}"#).as_bytes())
        );
    }

    #[test]
    fn payload_hash_builders_refuse_malformed_hex_fields() {
        let good_id = "00112233445566778899aabbccddeeff";
        let good_hash = "ab".repeat(32);
        assert!(transfer_payload_hash(&good_id.to_uppercase(), &good_hash).is_err());
        assert!(transfer_payload_hash(good_id, &good_hash[..63]).is_err());
        assert!(transfer_reject_payload_hash(&good_id[..31], "x").is_err());
        assert!(transfer_reject_payload_hash(good_id, "").is_err());
        assert!(remote_membership_payload_hash("not-hex").is_err());
    }
}
