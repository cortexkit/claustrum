use super::{
    append_audit_tx, now_ms, AuditCtx, AuditOp, AuditRecord, EncryptedStore,
    GhManifestHandoffEnvelope, GhManifestSource, GhManifestVersion, StoreOpError,
    GH_MANIFEST_ROOT_KEY_ID,
};
use crate::gh_manifest::GhManifest;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rusqlite::OptionalExtension;
use serde_json::{json, Value};

fn sql(error: rusqlite::Error) -> StoreOpError {
    StoreOpError::Store(error.to_string())
}

fn validate_version(
    tx: &rusqlite::Transaction<'_>,
    bytes: &[u8],
) -> Result<GhManifest, StoreOpError> {
    let manifest = GhManifest::parse_reproducible(bytes)
        .map_err(|error| StoreOpError::Encode(error.to_string()))?;
    let newest: Option<i64> = tx
        .query_row("SELECT MAX(version) FROM gh_manifests", [], |row| {
            row.get(0)
        })
        .map_err(sql)?;
    if newest.is_some_and(|newest| manifest.version() <= newest) {
        return Err(StoreOpError::Encode(
            "invalid_manifest_version: version must exceed the newest stored version".into(),
        ));
    }
    Ok(manifest)
}

impl EncryptedStore {
    // Preserve domain errors while making every error abort the transaction, even
    // when approval or signature audit rows have already been appended.
    fn manifest_admin_transaction<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, StoreOpError>,
    ) -> Result<T, StoreOpError> {
        let mut operation_error = None;
        let result = self.fenced_write(|tx| match f(tx) {
            Ok(value) => Ok(value),
            Err(error) => {
                operation_error = Some(error);
                Err(rusqlite::Error::InvalidQuery)
            }
        });
        result.map_err(|error| operation_error.unwrap_or_else(|| error.into()))
    }

    pub(crate) fn import_gh_manifest_admin(
        &self,
        envelope: &GhManifestHandoffEnvelope,
        actor: &str,
    ) -> Result<Value, StoreOpError> {
        self.manifest_admin_transaction(|tx| {
            let manifest = validate_version(tx, envelope.manifest_bytes.as_bytes())?;
            // Imports become trusted bases; a withdrawn root cannot restore trust.
            let root = self
                .gh_manifest_root_in_tx(tx)
                .map_err(manifest_root_error)?;
            let corrupt = || StoreOpError::Corrupt("unusable manifest signing key".into());
            let pem = std::str::from_utf8(root.payload.expose()).map_err(|_| corrupt())?;
            let public = crate::signing::public_key_ed25519(pem).map_err(|_| corrupt())?;
            let public_bytes = public
                .public_key_hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|hex| {
                    let text = std::str::from_utf8(hex).map_err(|_| corrupt())?;
                    u8::from_str_radix(text, 16).map_err(|_| corrupt())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if envelope.key_id != crate::signing::key_id_for_public(&public_bytes) {
                return Err(StoreOpError::Encode("key_id_mismatch".into()));
            }
            let invalid_signature = || StoreOpError::Encode("invalid_manifest_signature".into());
            let raw: [u8; 64] = STANDARD
                .decode(&envelope.signature)
                .map_err(|_| invalid_signature())?
                .try_into()
                .map_err(|_| invalid_signature())?;
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public_bytes)
                .verify(envelope.manifest_bytes.as_bytes(), &raw)
                .map_err(|_| invalid_signature())?;
            let signed_at_ms = manifest
                .issued_at_unix_secs()
                .checked_mul(1000)
                .ok_or_else(|| {
                    StoreOpError::Encode("issued_at_unix_secs overflows milliseconds".into())
                })?;
            let hash = manifest.manifest_sha256();
            self.store_gh_manifest_in_tx(
                tx,
                &GhManifestVersion {
                    version: manifest.version(),
                    manifest_bytes: envelope.manifest_bytes.as_bytes(),
                    manifest_sha256: &hash,
                    key_id: &envelope.key_id,
                    signature: &raw,
                    signed_at_ms,
                    source: GhManifestSource::Import,
                    approval_audit_seq: None,
                },
                AuditCtx::route_admin(AuditOp::GhManifestStore, actor),
            )
            .map_err(sql)?;
            Ok(json!({"version": manifest.version(), "manifest_sha256": hash}))
        })
    }

    pub(crate) fn sign_gh_manifest_admin(
        &self,
        manifest_bytes: &str,
        approver: &str,
        actor: &str,
    ) -> Result<Value, StoreOpError> {
        self.manifest_admin_transaction(|tx| {
            let manifest = validate_version(tx, manifest_bytes.as_bytes())?;
            self.gh_manifest_root_in_tx(tx)
                .map_err(manifest_root_error)?;
            let hash = manifest.manifest_sha256();
            let actor = format!("{actor}/approver:{approver}");
            let approval = append_audit_tx(
                tx,
                &self.audit_key,
                &AuditRecord {
                    op: AuditOp::Approval,
                    credential_id: Some(GH_MANIFEST_ROOT_KEY_ID.into()),
                    payload_hash: Some(hash.clone()),
                    actor: actor.clone(),
                    alarm: None,
                },
            )
            .map_err(sql)?;
            let signed = self.sign_gh_manifest(
                tx,
                manifest_bytes.as_bytes(),
                AuditCtx::route_admin(AuditOp::GhManifestSign, &actor),
            )?;
            let raw: [u8; 64] = STANDARD
                .decode(&signed.signature_b64)
                .ok()
                .and_then(|raw| raw.try_into().ok())
                .ok_or_else(|| StoreOpError::Corrupt("unusable manifest signature".into()))?;
            self.store_gh_manifest_in_tx(
                tx,
                &GhManifestVersion {
                    version: manifest.version(),
                    manifest_bytes: manifest_bytes.as_bytes(),
                    manifest_sha256: &hash,
                    key_id: &signed.key_id,
                    signature: &raw,
                    signed_at_ms: now_ms(),
                    source: GhManifestSource::Ceremony,
                    approval_audit_seq: Some(approval.seq),
                },
                AuditCtx::route_admin(AuditOp::GhManifestStore, &actor),
            )
            .map_err(sql)?;
            // The fenced transaction publishes this envelope only after COMMIT.
            Ok(
                json!({"version": manifest.version(), "manifest_sha256": hash,
                "envelope": GhManifestHandoffEnvelope {
                    key_id: signed.key_id,
                    manifest_bytes: manifest_bytes.into(),
                    signature: signed.signature_b64,
                }}),
            )
        })
    }
}

fn manifest_root_error(error: StoreOpError) -> StoreOpError {
    match error {
        StoreOpError::NotFound => StoreOpError::Encode("manifest_setup_incomplete".into()),
        error => error,
    }
}

impl EncryptedStore {
    pub(crate) fn export_gh_manifest_admin(
        &self,
        version: i64,
    ) -> Result<GhManifestHandoffEnvelope, StoreOpError> {
        let row =
            self.store
                .with_conn(|conn| {
                    conn.query_row(
            "SELECT key_id, manifest_bytes, signature FROM gh_manifests WHERE version = ?1",
            [version], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?)),
        ).optional()
                })?
                .ok_or(StoreOpError::NotFound)?;
        Ok(GhManifestHandoffEnvelope {
            key_id: row.0,
            manifest_bytes: String::from_utf8(row.1)
                .map_err(|_| StoreOpError::Corrupt("manifest is not UTF-8".into()))?,
            signature: STANDARD.encode(row.2),
        })
    }

    pub(crate) fn list_gh_manifests_admin(&self) -> Result<Value, StoreOpError> {
        self.store.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let versions = tx.prepare(
                "SELECT version, source, manifest_sha256, signed_at_ms FROM gh_manifests ORDER BY version",
            )?.query_map([], |row| Ok(json!({
                "version": row.get::<_, i64>(0)?,
                "source": row.get::<_, String>(1)?,
                "manifest_sha256": row.get::<_, String>(2)?,
                "signed_at_ms": row.get::<_, i64>(3)?,
            })))?.collect::<rusqlite::Result<Vec<_>>>()?;
            // As in gh_manifest_active_status, self, secret-use grant holders and
            // report senders are expected unless retired. Keep retired rows visible
            // to the operator.
            let computers = tx.prepare(
                "SELECT population.member_id, a.version, a.payload_sha256, a.verdict, a.reason, \
                 a.reported_at_ms, a.retired_at_ms \
                 FROM (SELECT value AS member_id FROM settings WHERE name = ?1 AND value != '' \
                       UNION SELECT member_id FROM member_grants WHERE operation = 'secret_use' \
                       UNION SELECT member_id FROM gh_manifest_activations) AS population \
                 LEFT JOIN gh_manifest_activations AS a ON a.member_id = population.member_id \
                 ORDER BY population.member_id COLLATE BINARY",
            )?.query_map([crate::federation::SELF_MEMBER_SETTING], |row| {
                let retired = row.get::<_, Option<i64>>(6)?;
                Ok(json!({
                    "member_id": row.get::<_, String>(0)?,
                    "version": row.get::<_, Option<i64>>(1)?,
                    "payload_sha256": row.get::<_, Option<String>>(2)?,
                    "verdict": row.get::<_, Option<String>>(3)?,
                    "reason": row.get::<_, Option<String>>(4)?,
                    "reported_at_ms": row.get::<_, Option<i64>>(5)?,
                    "retired_at_ms": retired,
                    "expected": retired.is_none(),
                }))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            tx.commit()?;
            Ok(json!({"versions": versions, "computers": computers}))
        }).map_err(StoreOpError::from)
    }
}

#[cfg(test)]
#[path = "store_gh_admin_tests.rs"]
mod tests;
