//! Manifest report grammar and the shared committed-report path for every transport.

use credentials_core::{
    audit::{AuditCtx, AuditOp},
    store::{
        EncryptedStore, GhManifestActivationOutcome, GhManifestActivationReport, GhManifestVerdict,
    },
};
use serde::Deserialize;
use serde_json::{json, Value};

const REPORT_REASON_LIMIT: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportParams {
    version: i64,
    payload_sha256: String,
    verdict: GhManifestVerdict,
    reason: Value,
}

impl ReportParams {
    fn valid(&self) -> bool {
        self.version > 0
            && valid_manifest_hash(&self.payload_sha256)
            && match self.verdict {
                GhManifestVerdict::Valid => self.reason.is_null(),
                GhManifestVerdict::Invalid => self
                    .reason
                    .as_str()
                    .is_some_and(|s| s.chars().count() <= REPORT_REASON_LIMIT),
            }
    }
}

pub(crate) fn valid_manifest_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parse_active_report(params: &Value) -> Option<ReportParams> {
    serde_json::from_value::<ReportParams>(params.clone())
        .ok()
        .filter(ReportParams::valid)
}

/// The legacy federation route does not commit the caller's report as this vault's own.
pub fn record_manifest_active_report(
    store: &EncryptedStore,
    member_id: &str,
    params: &ReportParams,
) -> Value {
    record(store, member_id, params, false)
}

#[allow(
    dead_code,
    reason = "the library probe does not serve the local manifest route"
)]
pub(crate) fn record_own_manifest_active_report(
    store: &EncryptedStore,
    member_id: &str,
    params: &ReportParams,
) -> Value {
    record(store, member_id, params, true)
}

pub(crate) fn report_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(crate) fn warn_on_downgrade(member_id: &str, outcome: GhManifestActivationOutcome) {
    if let Some(lower) = outcome.lower_version_reported {
        tracing::warn!(
            member_id,
            reported = lower.reported,
            active = lower.active,
            "lower manifest version reported"
        );
    }
}

fn record(store: &EncryptedStore, member_id: &str, params: &ReportParams, own: bool) -> Value {
    let report = GhManifestActivationReport {
        member_id,
        version: params.version,
        payload_sha256: &params.payload_sha256,
        verdict: params.verdict,
        reason: params.reason.as_str(),
        reported_at_ms: report_time_ms(),
    };
    let ctx = AuditCtx {
        actor: member_id,
        op: AuditOp::GhManifestActivation,
        alarm: None,
    };
    let outcome = if own {
        store.record_hub_own_report(&report, ctx)
    } else {
        store.report_gh_manifest_active(&report, ctx)
    };
    match outcome {
        Ok(outcome) => {
            warn_on_downgrade(member_id, outcome);
            json!({"status":"recorded", "member_id":member_id, "version":params.version})
        }
        Err(_) => json!({"error":{"code":"store_error","class":"transient"}}),
    }
}
