//! Domain health snapshot for the subc continuous-health probe (L3).
//!
//! The daemon probes this on a cadence (default 30s) with a short deadline, so
//! the report MUST be cheap: in-memory / no-decrypt state only, never a network
//! call, an envelope decrypt, an audit-chain HMAC recompute, or a lease write.
//!
//! The vault keeps no decrypted state in memory (the daemon never caches
//! payloads — every serve reads SQLite), so the honest cheap source of truth is
//! a single no-decrypt metadata scan (`list_meta`): the same read every `get`
//! does before decryption. That read IS the vault's real serving dependency
//! (SQLite reachable under the resolved master key), so probing it proves the
//! path consumers use without paying to decrypt every record.
//!
//! Fail-closed status ladder (deliberately never restart-flaps a serving vault):
//! - `Failing` — the daemon cannot correctly serve. Two triggers: the store is
//!   unreadable (a gone/corrupt store surfaces as a read error), OR the store has
//!   been fenced out (a newer writer took the single-writer lease, so this
//!   superseded daemon has lost write authority — it can still return stale reads
//!   but must not keep serving as the authority). The detail distinguishes them
//!   because the operator action differs: unreadable ⇒ check disk/lease; fenced
//!   ⇒ find the newer writer.
//! - `Degraded` — the store serves, but ≥1 credential needs operator action
//!   (`needs_reauth` or `corrupt`). An expired token is a degraded DETAIL, never
//!   `failing`: we must not let one credential needing re-auth trigger a daemon
//!   restart of an otherwise-healthy vault.
//! - `Ok` — the store is readable, not fenced out, and every record is Active.

use crate::store::{RecordMeta, RecordState};

/// Cap on how many affected credential ids the snapshot carries per bucket. The
/// counts (`needs_reauth`/`corrupt`) remain the true totals; the id lists are a
/// bounded sample so the health metrics stay well under the prober's 16 KiB cap
/// even on a pathologically large vault. For a real credential vault (dozens of
/// records) this always lists every affected id.
const MAX_LISTED_IDS: usize = 32;

/// The wire-agnostic domain health status. The module maps this onto the subc
/// protocol `HealthStatus`; core never depends on the protocol crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultHealthStatus {
    Ok,
    Degraded,
    Failing,
}

impl VaultHealthStatus {
    /// The stable lowercase display form (matches the subc health table's wording).
    pub fn as_str(self) -> &'static str {
        match self {
            VaultHealthStatus::Ok => "ok",
            VaultHealthStatus::Degraded => "degraded",
            VaultHealthStatus::Failing => "failing",
        }
    }
}

/// A cheap, no-decrypt health snapshot of the vault's serveable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHealth {
    pub status: VaultHealthStatus,
    /// Whether the no-decrypt metadata scan succeeded. `false` ⇒ `Failing`.
    pub store_readable: bool,
    /// Whether a fenced write has ever been rejected because a newer writer took
    /// the lease. `true` ⇒ `Failing` (this daemon has lost write authority).
    pub fenced_out: bool,
    /// Whether the background health refresher has stopped updating this snapshot
    /// (wedged on a blocking scan, or dead from a panic). Set LIVE by the probe path
    /// when the last-refresh age exceeds the stale limit — it is NOT a stored age
    /// (which would violate the cheap-in-memory / QTA rule by letting a frozen snapshot
    /// mask its own staleness), it is a boolean the probe computes from a live clock at
    /// read time. `true` ⇒ `Failing`: a snapshot no one is refreshing cannot be trusted
    /// as current, so serving it as healthy would hide a real failure.
    pub refresher_stalled: bool,
    pub credentials_total: usize,
    pub active: usize,
    pub needs_reauth: usize,
    pub corrupt: usize,
    /// The ids of credentials in `needs_reauth` (capped at [`MAX_LISTED_IDS`]) so
    /// the report NAMES which credential to re-import, not just how many. Credential
    /// ids are non-secret metadata (`<method>:<provider>[:<account>]`) and the
    /// health lane is authenticated-clients-only, so listing them turns an alert
    /// into a one-read action.
    pub needs_reauth_ids: Vec<String>,
    /// The ids of `corrupt` (quarantined) credentials, same cap and rationale.
    pub corrupt_ids: Vec<String>,
    /// Open refresh-intent rows at snapshot time. Carried as an opaque metric
    /// only — a nonzero count is NOT a status input because a legitimately
    /// in-flight refresh holds an intent open transiently (txn1 opens it, txn2
    /// clears it), so it would false-positive a degraded state on every serve.
    pub open_intents: usize,
}

impl VaultHealth {
    /// The `Failing` snapshot for an unreadable store — the one cheap signal of
    /// real serving inability.
    pub fn unreadable() -> Self {
        VaultHealth {
            status: VaultHealthStatus::Failing,
            store_readable: false,
            fenced_out: false,
            refresher_stalled: false,
            credentials_total: 0,
            active: 0,
            needs_reauth: 0,
            corrupt: 0,
            needs_reauth_ids: Vec::new(),
            corrupt_ids: Vec::new(),
            open_intents: 0,
        }
    }

    /// Force the snapshot to `Failing` because the background refresher has stalled
    /// (last successful refresh is older than the daemon's stale limit). Called live on
    /// the probe path over a clone, never on the stored snapshot, so it reflects the
    /// refresher's liveness AT PROBE TIME rather than freezing an age into the content.
    pub fn mark_refresher_stalled(&mut self) {
        self.refresher_stalled = true;
        self.status = VaultHealthStatus::Failing;
    }

    /// Summarize the no-decrypt metadata histogram into the fail-closed ladder.
    /// Pure over the scan result so the ladder is unit-testable without a store.
    /// `fenced_out` reflects whether this store instance has lost the lease to a
    /// newer writer (a `Failing` trigger that outranks per-record state, since a
    /// fenced-out daemon must not keep serving as the authority even if every row
    /// it can still read looks Active).
    pub fn summarize(
        metas: &[(String, RecordMeta)],
        open_intents: usize,
        fenced_out: bool,
    ) -> Self {
        let mut active = 0;
        let mut needs_reauth = 0;
        let mut corrupt = 0;
        let mut needs_reauth_ids = Vec::new();
        let mut corrupt_ids = Vec::new();
        for (id, meta) in metas {
            match meta.state {
                RecordState::Active => active += 1,
                RecordState::NeedsReauth => {
                    needs_reauth += 1;
                    if needs_reauth_ids.len() < MAX_LISTED_IDS {
                        needs_reauth_ids.push(id.clone());
                    }
                }
                RecordState::Corrupt => {
                    corrupt += 1;
                    if corrupt_ids.len() < MAX_LISTED_IDS {
                        corrupt_ids.push(id.clone());
                    }
                }
            }
        }
        // Fenced out outranks everything: this daemon lost write authority, so it
        // is Failing even though its stale reads still succeed. Otherwise degraded
        // on any credential needing operator action; else ok (the store is
        // readable and this writer still holds the lease).
        let status = if fenced_out {
            VaultHealthStatus::Failing
        } else if needs_reauth > 0 || corrupt > 0 {
            VaultHealthStatus::Degraded
        } else {
            VaultHealthStatus::Ok
        };
        VaultHealth {
            status,
            store_readable: true,
            fenced_out,
            refresher_stalled: false,
            credentials_total: metas.len(),
            active,
            needs_reauth,
            corrupt,
            needs_reauth_ids,
            corrupt_ids,
            open_intents,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(state: RecordState) -> (String, RecordMeta) {
        meta_id("id", state)
    }

    fn meta_id(id: &str, state: RecordState) -> (String, RecordMeta) {
        (
            id.to_string(),
            RecordMeta {
                record_version: 1,
                key_id_hex: "deadbeef".to_string(),
                state,
                stale_pending: false,
            },
        )
    }

    #[test]
    fn empty_vault_is_ok() {
        let h = VaultHealth::summarize(&[], 0, false);
        assert_eq!(h.status, VaultHealthStatus::Ok);
        assert_eq!(h.credentials_total, 0);
        assert!(h.store_readable);
    }

    #[test]
    fn all_active_is_ok() {
        let metas = vec![meta(RecordState::Active), meta(RecordState::Active)];
        let h = VaultHealth::summarize(&metas, 0, false);
        assert_eq!(h.status, VaultHealthStatus::Ok);
        assert_eq!(h.active, 2);
    }

    #[test]
    fn a_needs_reauth_credential_is_degraded_never_failing() {
        let metas = vec![
            meta_id("apikey:openai", RecordState::Active),
            meta_id("oauth:google", RecordState::NeedsReauth),
        ];
        let h = VaultHealth::summarize(&metas, 0, false);
        // The load-bearing invariant: one credential needing re-auth must NOT
        // escalate to `failing` (which would restart-flap a serving vault).
        assert_eq!(h.status, VaultHealthStatus::Degraded);
        assert_eq!(h.active, 1);
        assert_eq!(h.needs_reauth, 1);
        // And it NAMES which credential, so the alert is actionable in one read.
        assert_eq!(h.needs_reauth_ids, vec!["oauth:google".to_string()]);
        assert!(h.corrupt_ids.is_empty());
    }

    #[test]
    fn a_corrupt_record_is_degraded() {
        let metas = vec![meta(RecordState::Active), meta(RecordState::Corrupt)];
        let h = VaultHealth::summarize(&metas, 0, false);
        assert_eq!(h.status, VaultHealthStatus::Degraded);
        assert_eq!(h.corrupt, 1);
    }

    #[test]
    fn open_intents_are_carried_but_do_not_change_status() {
        // An in-flight refresh holds an intent open; that alone is healthy.
        let metas = vec![meta(RecordState::Active)];
        let h = VaultHealth::summarize(&metas, 3, false);
        assert_eq!(h.status, VaultHealthStatus::Ok);
        assert_eq!(h.open_intents, 3);
    }

    #[test]
    fn fenced_out_is_failing_even_when_readable_rows_look_active() {
        // A superseded daemon still reads its stale rows fine (all Active), but it
        // lost the lease — it must report Failing, outranking the healthy-looking
        // per-record state.
        let metas = vec![meta(RecordState::Active), meta(RecordState::Active)];
        let h = VaultHealth::summarize(&metas, 0, true);
        assert_eq!(h.status, VaultHealthStatus::Failing);
        assert!(h.fenced_out);
        assert!(h.store_readable);
    }

    #[test]
    fn unreadable_store_is_failing() {
        let h = VaultHealth::unreadable();
        assert_eq!(h.status, VaultHealthStatus::Failing);
        assert!(!h.store_readable);
    }
}
