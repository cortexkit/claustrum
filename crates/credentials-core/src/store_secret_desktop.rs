//! Temporary unsigned desktop approvals. Remove before the next public release.
use super::*;
use crate::agent_secret::{ApprovalEnvelope, SecretError, SECRET_ISSUE_SKEW_LIMIT_MS};
use crate::broker_action::BrokerActionEnvelope;
use crate::gh_manifest::ManifestBindingEnvelope;
use serde_json::Value;

pub const DEV_DESKTOP_FINGERPRINT: &str = "00000000000000000000000000000000";

pub(in crate::store) enum ApprovalAuthority<'a> {
    Phone {
        public_key: &'a [u8],
        signature: &'a [u8],
    },
    DevelopmentDesktop,
}

impl ApprovalAuthority<'_> {
    pub(in crate::store) fn secret(
        &self,
        bytes: &[u8],
        fingerprint: &str,
    ) -> Result<ApprovalEnvelope, SecretError> {
        match self {
            Self::Phone {
                public_key,
                signature,
            } => ApprovalEnvelope::verify(bytes, signature, public_key, fingerprint),
            Self::DevelopmentDesktop => {
                ApprovalEnvelope::parse_canonical(bytes, DEV_DESKTOP_FINGERPRINT)
            }
        }
    }

    pub(in crate::store) fn manifest(
        &self,
        bytes: &[u8],
        fingerprint: &str,
        now: i64,
    ) -> Result<ManifestBindingEnvelope, SecretError> {
        match self {
            Self::Phone {
                public_key,
                signature,
            } => ManifestBindingEnvelope::verify(bytes, signature, public_key, fingerprint, now),
            Self::DevelopmentDesktop => {
                let envelope =
                    ManifestBindingEnvelope::parse_canonical(bytes, DEV_DESKTOP_FINGERPRINT)?;
                if now.abs_diff(envelope.issued_at_ms as i64) > SECRET_ISSUE_SKEW_LIMIT_MS as u64 {
                    return Err(SecretError::ApprovalInvalid);
                }
                Ok(envelope)
            }
        }
    }

    pub(in crate::store) fn broker_action(
        &self,
        bytes: &[u8],
        fingerprint: &str,
        now: i64,
    ) -> Result<BrokerActionEnvelope, SecretError> {
        match self {
            Self::Phone {
                public_key,
                signature,
            } => BrokerActionEnvelope::verify(bytes, signature, public_key, fingerprint, now),
            Self::DevelopmentDesktop => {
                BrokerActionEnvelope::parse_canonical(bytes, DEV_DESKTOP_FINGERPRINT, now)
            }
        }
    }

    pub(in crate::store) fn actor(&self, fingerprint: &str, manifest: bool) -> String {
        match self {
            Self::Phone { .. } if manifest => {
                format!("fed-phone:{fingerprint}/approver:fed-phone:{fingerprint}")
            }
            Self::Phone { .. } => format!("fed-phone:{fingerprint}"),
            Self::DevelopmentDesktop => "desktop-development".to_owned(),
        }
    }
}

impl EncryptedStore {
    /// The caller must be an unscoped direct development route. Check the switch again
    /// inside the transaction so a queued request cannot outlive its admission.
    pub fn broker_action_dev_desktop_approval(
        &self,
        bytes: &[u8],
        clock: impl FnOnce() -> i64,
    ) -> Result<Value, SecretError> {
        self.fenced_write(|tx| {
            if !phone::setting_enabled(tx, phone::DEV_DESKTOP_APPROVALS_SETTING) {
                return Ok(Err(SecretError::NotFound));
            }
            if super::super::policy_token::serving_role(tx).is_err() {
                return Ok(Err(SecretError::ApprovalInvalid));
            }
            self.broker_action_approval_tx(
                tx,
                DEV_DESKTOP_FINGERPRINT,
                ApprovalAuthority::DevelopmentDesktop,
                bytes,
                clock(),
            )
        })
        .map_err(|_| SecretError::ApprovalInvalid)?
    }

    pub fn secret_dev_desktop_approvals_status_read_only(
        path: &std::path::Path,
    ) -> Result<String, StoreOpError> {
        phone::feature_status_read_only(path, phone::DEV_DESKTOP_APPROVALS_SETTING)
    }

    pub fn secret_dev_desktop_approvals_enabled(&self) -> Result<bool, SecretError> {
        self.store
            .with_conn(|conn| {
                Ok(phone::setting_enabled(
                    conn,
                    phone::DEV_DESKTOP_APPROVALS_SETTING,
                ))
            })
            .map_err(|_| SecretError::StoreError)
    }

    pub fn set_secret_dev_desktop_approvals_audited(
        &self,
        enabled: bool,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.set_secret_feature_audited(
            phone::DEV_DESKTOP_APPROVALS_SETTING,
            AuditOp::SecretDevDesktopApprovalsSet,
            enabled,
            ctx,
        )
    }

    /// The module admits only an unscoped direct development route. Repeat the live
    /// switch check under the writer so disabling it fences off queued approvals.
    pub fn secret_dev_desktop_approval(
        &self,
        bytes: &[u8],
        card_ref: Option<&str>,
        manifest: bool,
        clock: impl FnOnce() -> i64,
    ) -> Result<Value, SecretError> {
        self.fenced_write(|tx| {
            if !phone::setting_enabled(tx, phone::DEV_DESKTOP_APPROVALS_SETTING) {
                return Ok(Err(SecretError::NotFound));
            }
            if let Some(refusal) = operator::secret_home_role_conn(tx).phone_deposit_refusal() {
                return Ok(refusal);
            }
            let now = clock();
            let authority = ApprovalAuthority::DevelopmentDesktop;
            if manifest {
                self.gh_manifest_approval_tx(tx, DEV_DESKTOP_FINGERPRINT, authority, bytes, now)
            } else {
                self.secret_approval_tx(
                    tx,
                    DEV_DESKTOP_FINGERPRINT,
                    authority,
                    bytes,
                    card_ref,
                    false,
                    now,
                )
            }
        })
        .map_err(|_| SecretError::StoreError)?
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    #[test]
    fn desktop_dev_vector_inventory_is_generated_and_byte_pinned() {
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/desktop-dev-approval-vectors-v1");
        let readme = b"# Development desktop approval vectors v1\n\nDevelopment only; remove before the next public release. No desktop signing key\nis used. The device fingerprint is 32 zeros. Agent, flow and manifest requests\nand replies are produced by the real vault approval transactions. Refusals are\nproduced by the real daemon route dispatcher, without changing audit, pending\nrequest, grant, replay, phone-observation or manifest tables.\nThe fixed timestamps are test inputs, not valid approval times today.\n\nRegenerate agent.json and flow.json with the core test\n`desktop_dev_agent_and_flow_approvals_share_phone_grants_and_emit_vectors`,\nmanifest.json with `desktop_dev_manifest_approval_uses_shared_commitments_and_emits_vector`,\nand refusals.json with the module test\n`desktop_dev_route_refusals_write_nothing_and_emit_vectors`. Set\n`CK_EMIT_SECRET_VECTORS=1`, then run\n`desktop_dev_vector_inventory_is_generated_and_byte_pinned` last with the same\nsetting to generate this README and SHA256SUMS. Normal runs byte-compare samples.\n\nSHA256SUMS covers this README and every JSON sample. Existing phone vectors are\nunchanged. No production keys, secret material or grant bearer values are stored.\n";
        let emit = std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some();
        if emit {
            std::fs::write(folder.join("README.md"), readme).unwrap();
        } else {
            assert_eq!(std::fs::read(folder.join("README.md")).unwrap(), readme);
        }
        let mut sums = String::new();
        for name in [
            "README.md",
            "agent.json",
            "flow.json",
            "manifest.json",
            "refusals.json",
        ] {
            let bytes = std::fs::read(folder.join(name)).unwrap();
            sums.push_str(&format!("{:x}  {name}\n", Sha256::digest(bytes)));
        }
        if emit {
            std::fs::write(folder.join("SHA256SUMS"), sums).unwrap();
        } else {
            assert_eq!(
                std::fs::read_to_string(folder.join("SHA256SUMS")).unwrap(),
                sums
            );
        }
    }
}
