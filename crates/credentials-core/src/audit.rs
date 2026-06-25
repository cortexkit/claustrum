//! The tamper-evident, HMAC-keyed audit chain for vault mutations.
//!
//! Every durable mutation appends one [`AuditEntry`] in the same fenced transaction
//! as the mutation itself. Each entry carries an `entry_mac` computed over the
//! previous entry's mac plus this entry's fields, so the log is a hash chain: any
//! edit to a past entry invalidates every later mac.
//!
//! The chain is HMAC-keyed (not a plain hash) with a key DERIVED from the master
//! key, so the audit log cannot be forged or silently repaired without the master
//! key. A key-less attacker who rewrites the whole `audit_log` table could
//! recompute a plain SHA-256 chain and erase their tracks; they cannot recompute
//! the HMACs without the audit key, so the forensic record's tamper-evidence rests
//! on the SAME trust boundary as the record encryption. (An attacker who HAS the
//! master key would write through the admin CLI anyway, so this is the right
//! boundary.)

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::key::MasterKey;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label for deriving the audit-chain key from the master key.
const AUDIT_KEY_DOMAIN: &[u8] = b"cortexkit-credentials/audit-chain/v1";

/// The genesis predecessor mac for the first chain entry (a fixed, non-secret
/// constant — the chain's anchor).
pub const GENESIS_MAC: &str = "genesis";

/// What kind of mutation an audit entry records. Op-typed so the chain accounts for
/// every record-version change and an unexplained bump is a detectable gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOp {
    /// A create-only `put` (a new credential).
    Put,
    /// An import of a credential from a source format.
    Import,
    /// An overwrite under a compare-and-set.
    Overwrite,
    /// An authoritative invalidate (revoke).
    Invalidate,
    /// A master-key rotation (rewrap).
    RotateMasterKey,
    /// A vault-owned refresh that committed new tokens.
    RefreshCommit,
    /// A consumer-reported auth failure that marked the credential needs_reauth.
    ReportAuthFailure,
    /// A capability handle was minted.
    MintHandle,
    /// A capability handle (or all for a credential) was revoked.
    RevokeHandle,
}

impl AuditOp {
    /// The stable wire/storage string for this op.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOp::Put => "put",
            AuditOp::Import => "import",
            AuditOp::Overwrite => "overwrite",
            AuditOp::Invalidate => "invalidate",
            AuditOp::RotateMasterKey => "rotate_master_key",
            AuditOp::RefreshCommit => "refresh_commit",
            AuditOp::ReportAuthFailure => "report_auth_failure",
            AuditOp::MintHandle => "mint_handle",
            AuditOp::RevokeHandle => "revoke_handle",
        }
    }
}

/// Why an audit entry is flagged as an alarm (a detected anomaly). `None` for a
/// normal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmReason {
    /// An existing credential was overwritten without a compare-and-set guard.
    OverwriteWithoutCas,
    /// A connection's credential-fetch rate/spread crossed the anomaly threshold.
    FetchRateAnomaly,
    /// An administrative write occurred (always flagged so admin activity is loud).
    AdminWrite,
}

impl AlarmReason {
    pub fn as_str(self) -> &'static str {
        match self {
            AlarmReason::OverwriteWithoutCas => "overwrite_without_cas",
            AlarmReason::FetchRateAnomaly => "fetch_rate_anomaly",
            AlarmReason::AdminWrite => "admin_write",
        }
    }
}

/// The data of one audit entry, BEFORE it is sequenced and chained. The store
/// assigns `seq`/`prev_mac` and computes `entry_mac` at append time.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// The mutation kind.
    pub op: AuditOp,
    /// The credential affected, if the op is credential-scoped.
    pub credential_id: Option<String>,
    /// Hex hash of the affected payload (for substitution detection), if applicable.
    pub payload_hash: Option<String>,
    /// Who performed it: a connection id (daemon read-surface action) or
    /// `"offline-cli"` (an admin CLI write).
    pub actor: String,
    /// An alarm reason when this entry records a detected anomaly.
    pub alarm: Option<AlarmReason>,
}

/// A fully chained audit entry as stored/read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: i64,
    pub ts_ms: i64,
    pub op: String,
    pub credential_id: Option<String>,
    pub payload_hash: Option<String>,
    pub actor: String,
    pub alarm: bool,
    pub alarm_reason: Option<String>,
    pub prev_mac: String,
    pub entry_mac: String,
}

/// Derive the audit-chain HMAC key from the master key (domain-separated), so the
/// chain key is bound to the same secret as record encryption but is not the master
/// key itself.
pub fn derive_audit_key(master: &MasterKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AUDIT_KEY_DOMAIN);
    h.update(master.as_bytes());
    h.finalize().into()
}

/// The MAC-covered content of one audit entry (everything the chain authenticates
/// except the audit key and the predecessor mac). Grouped so the mac computation
/// takes a single content view rather than a long positional argument list.
#[derive(Debug, Clone, Copy)]
pub struct MacFields<'a> {
    pub seq: i64,
    pub ts_ms: i64,
    pub op: &'a str,
    pub credential_id: Option<&'a str>,
    pub payload_hash: Option<&'a str>,
    pub actor: &'a str,
    pub alarm: bool,
    pub alarm_reason: Option<&'a str>,
}

/// Compute an entry's mac over its predecessor's mac and its own fields. The field
/// order and separators are fixed so the mac is reproducible for verification.
/// Optional fields use a fixed sentinel when absent so a missing value can never be
/// confused with an empty one.
pub fn compute_entry_mac(audit_key: &[u8; 32], prev_mac: &str, fields: &MacFields<'_>) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(audit_key).expect("HMAC accepts a 32-byte key");
    // Length-prefixed, sentinel-tagged field feed so no crafted field value can
    // shift a boundary or alias a missing value.
    feed(&mut mac, prev_mac.as_bytes());
    feed(&mut mac, &fields.seq.to_le_bytes());
    feed(&mut mac, &fields.ts_ms.to_le_bytes());
    feed(&mut mac, fields.op.as_bytes());
    feed_opt(&mut mac, fields.credential_id.map(str::as_bytes));
    feed_opt(&mut mac, fields.payload_hash.map(str::as_bytes));
    feed(&mut mac, fields.actor.as_bytes());
    feed(&mut mac, &[fields.alarm as u8]);
    feed_opt(&mut mac, fields.alarm_reason.map(str::as_bytes));
    let bytes = mac.finalize().into_bytes();
    hex(&bytes)
}

/// Verify a chain segment: each entry's mac recomputes from its predecessor and its
/// fields, and `prev_mac` links to the prior entry's `entry_mac`. The first entry's
/// `prev_mac` must be [`GENESIS_MAC`]. Returns the seq of the first broken entry, or
/// `None` if the whole segment verifies.
pub fn verify_chain(audit_key: &[u8; 32], entries: &[AuditEntry]) -> Option<i64> {
    let mut expected_prev = GENESIS_MAC.to_string();
    for e in entries {
        if e.prev_mac != expected_prev {
            return Some(e.seq);
        }
        let recomputed = compute_entry_mac(
            audit_key,
            &e.prev_mac,
            &MacFields {
                seq: e.seq,
                ts_ms: e.ts_ms,
                op: &e.op,
                credential_id: e.credential_id.as_deref(),
                payload_hash: e.payload_hash.as_deref(),
                actor: &e.actor,
                alarm: e.alarm,
                alarm_reason: e.alarm_reason.as_deref(),
            },
        );
        if recomputed != e.entry_mac {
            return Some(e.seq);
        }
        expected_prev = e.entry_mac.clone();
    }
    None
}

fn feed(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_le_bytes());
    mac.update(field);
}

/// Feed an optional field: a leading tag byte (0 = absent, 1 = present) so a
/// missing value is distinct from an empty one.
fn feed_opt(mac: &mut HmacSha256, field: Option<&[u8]>) {
    match field {
        Some(bytes) => {
            mac.update(&[1u8]);
            feed(mac, bytes);
        }
        None => mac.update(&[0u8]),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;

    fn key() -> MasterKey {
        MasterKey::from_bytes([3u8; MASTER_KEY_LEN])
    }

    fn entry(seq: i64, prev: &str, ak: &[u8; 32]) -> AuditEntry {
        let op = "put";
        let cid = Some("opencode:anthropic");
        let ph = Some("abcd");
        let actor = "offline-cli";
        let mac = compute_entry_mac(
            ak,
            prev,
            &MacFields {
                seq,
                ts_ms: 1000 + seq,
                op,
                credential_id: cid,
                payload_hash: ph,
                actor,
                alarm: false,
                alarm_reason: None,
            },
        );
        AuditEntry {
            seq,
            ts_ms: 1000 + seq,
            op: op.into(),
            credential_id: cid.map(String::from),
            payload_hash: ph.map(String::from),
            actor: actor.into(),
            alarm: false,
            alarm_reason: None,
            prev_mac: prev.into(),
            entry_mac: mac,
        }
    }

    #[test]
    fn audit_key_is_deterministic_and_domain_separated() {
        let k = key();
        assert_eq!(derive_audit_key(&k), derive_audit_key(&k));
        // Not the bare master key bytes, not a bare SHA of them.
        let bare: [u8; 32] = Sha256::digest([3u8; MASTER_KEY_LEN]).into();
        assert_ne!(derive_audit_key(&k), bare);
    }

    #[test]
    fn valid_chain_verifies() {
        let ak = derive_audit_key(&key());
        let e1 = entry(1, GENESIS_MAC, &ak);
        let e2 = entry(2, &e1.entry_mac, &ak);
        let e3 = entry(3, &e2.entry_mac, &ak);
        assert_eq!(verify_chain(&ak, &[e1, e2, e3]), None);
    }

    #[test]
    fn tampered_entry_breaks_chain() {
        let ak = derive_audit_key(&key());
        let e1 = entry(1, GENESIS_MAC, &ak);
        let mut e2 = entry(2, &e1.entry_mac, &ak);
        let e3 = entry(3, &e2.entry_mac, &ak);
        // Tamper with e2's payload_hash but keep its (now-stale) mac.
        e2.payload_hash = Some("deadbeef".into());
        assert_eq!(verify_chain(&ak, &[e1, e2, e3]), Some(2), "broken at e2");
    }

    #[test]
    fn reordered_entries_break_chain() {
        let ak = derive_audit_key(&key());
        let e1 = entry(1, GENESIS_MAC, &ak);
        let e2 = entry(2, &e1.entry_mac, &ak);
        // e2 before e1: e2.prev_mac (e1's mac) != genesis.
        assert_eq!(verify_chain(&ak, &[e2, e1]), Some(2));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let ak = derive_audit_key(&key());
        let e1 = entry(1, GENESIS_MAC, &ak);
        let other = derive_audit_key(&MasterKey::from_bytes([9u8; MASTER_KEY_LEN]));
        // A different audit key cannot reproduce the mac.
        assert_eq!(verify_chain(&other, &[e1]), Some(1));
    }

    #[test]
    fn optional_field_presence_changes_mac() {
        let ak = derive_audit_key(&key());
        let base = MacFields {
            seq: 1,
            ts_ms: 1,
            op: "put",
            credential_id: None,
            payload_hash: None,
            actor: "a",
            alarm: false,
            alarm_reason: None,
        };
        let with = compute_entry_mac(
            &ak,
            "p",
            &MacFields {
                credential_id: Some(""),
                ..base
            },
        );
        let without = compute_entry_mac(&ak, "p", &base);
        assert_ne!(with, without, "absent != empty-present");
    }
}
