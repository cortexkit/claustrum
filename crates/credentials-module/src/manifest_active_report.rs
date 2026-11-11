//! Manifest report grammar and the shared committed-report path for every transport.

use credentials_core::{
    audit::{AuditCtx, AuditOp},
    store::{EncryptedStore, GhManifestActivationReport, GhManifestVerdict},
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
            && self.payload_sha256.len() == 64
            && self
                .payload_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && match self.verdict {
                GhManifestVerdict::Valid => self.reason.is_null(),
                GhManifestVerdict::Invalid => self
                    .reason
                    .as_str()
                    .is_some_and(|s| s.chars().count() <= REPORT_REASON_LIMIT),
            }
    }
}

pub fn parse_active_report(params: &Value) -> Option<ReportParams> {
    serde_json::from_value::<ReportParams>(params.clone())
        .ok()
        .filter(ReportParams::valid)
}

/// Shared by local and federation report routes after each has derived the member id.
/// Only committed downgrade metadata reaches the warning; payload and reason never do.
pub fn record_manifest_active_report(
    store: &EncryptedStore,
    member_id: &str,
    params: &ReportParams,
) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let report = GhManifestActivationReport {
        member_id,
        version: params.version,
        payload_sha256: &params.payload_sha256,
        verdict: params.verdict,
        reason: params.reason.as_str(),
        reported_at_ms: now,
    };
    match store.report_gh_manifest_active(
        &report,
        AuditCtx {
            actor: member_id,
            op: AuditOp::GhManifestActivation,
            alarm: None,
        },
    ) {
        Ok(outcome) => {
            if let Some(lower) = outcome.lower_version_reported {
                tracing::warn!(
                    member_id,
                    reported = lower.reported,
                    active = lower.active,
                    "lower manifest version reported"
                );
            }
            json!({"status":"recorded", "member_id":member_id, "version":params.version})
        }
        Err(_) => json!({"error":{"code":"store_error","class":"transient"}}),
    }
}
