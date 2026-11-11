use super::*;
use crate::gateway::{
    gateway_settings_digest, validate_gateway_settings, GatewaySettings, GatewaySettingsRule,
};

pub(super) fn has_settings(
    conn: &rusqlite::Connection,
    credential_id: &str,
) -> rusqlite::Result<bool> {
    if read_schema_version(conn)? < GATEWAY_SETTINGS_SCHEMA_VERSION {
        return Ok(false);
    }
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credential_gateway_settings WHERE credential_id = ?1)",
        [credential_id],
        |row| row.get(0),
    )
}

impl EncryptedStore {
    /// Create a gateway key and its fixed metadata atomically under the writer lease,
    /// refusing a writer superseded by a newer lease holder.
    /// Unlike an ordinary deposit, catalog and registry category defaults do not apply.
    pub fn gateway_create_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        settings: &GatewaySettings,
        provider_ids: &[String],
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        validate_gateway_settings(credential_id, settings, provider_ids)?;
        if record.kind != CredentialKind::ApiKey || record.refresh_adapter.is_some() {
            return Err(StoreOpError::InvalidGatewaySettings {
                rule: GatewaySettingsRule::Kind,
            });
        }
        validate_deposit_credential_id(credential_id)?;
        self.check_vault_transfer_key_writable(credential_id)?;
        refuse_short_term_bedrock_key(record)?;
        let mut record = normalize_record_identity(record.clone());
        if let Some(derived_account_id) = derived_account_id(&record) {
            match record.identity.account_id.as_deref() {
                Some(supplied_account_id) if supplied_account_id != derived_account_id => {
                    return Err(StoreOpError::SuppliedIdentityContradictsClaim {
                        credential_id: credential_id.to_string(),
                        supplied_account_id: supplied_account_id.to_string(),
                        derived_account_id,
                    });
                }
                None => record.identity.account_id = Some(derived_account_id),
                Some(_) => {}
            }
        }
        validate_record_identity(&record)?;
        record.record_version = 1;
        retain_detected_plan(&mut record, None);
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&audit::payload_fingerprint(
            &audit_key,
            record.payload.expose(),
        ));
        let digest = gateway_settings_digest(settings);
        let headers_json = serde_json::to_string(&settings.headers)
            .map_err(|error| StoreOpError::Encode(error.to_string()))?;

        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "INSERT INTO credentials \
                 (credential_id, record_version, key_id, state, envelope, updated_at_ms, created_at_ms, created_by) \
                 VALUES (?1, 1, ?2, 'active', ?3, ?4, ?4, 'operator') \
                 ON CONFLICT(credential_id) DO NOTHING",
                rusqlite::params![credential_id, key_id_hex, blob, now],
            )?;
            if n == 0 {
                return Ok(0);
            }
            tx.execute(
                "INSERT INTO credential_gateway_settings \
                 (credential_id, incarnation, base_url, auth_header, auth_scheme, headers_json) \
                 SELECT credential_id, incarnation, ?2, ?3, ?4, ?5 FROM credentials \
                 WHERE credential_id = ?1",
                rusqlite::params![
                    credential_id,
                    settings.base_url,
                    settings.auth.header,
                    settings.auth.scheme,
                    headers_json
                ],
            )?;
            tx.execute(
                "INSERT INTO credential_categories (credential_id, category) VALUES (?1, 'llm-gateway')",
                [credential_id],
            )?;
            tx.execute(
                "INSERT INTO credential_provider_ids (credential_id, provider_id) VALUES (?1, ?2)",
                rusqlite::params![credential_id, provider_ids[0]],
            )?;
            // This tail belongs to create-only: a conflict must not clear an intent,
            // advance grants, or append either audit row for the existing record.
            bump_grants_generation_tx(tx)?;
            clear_intent_tx(tx, credential_id)?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: Some(payload_hash_hex),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::GatewayCreate,
                    credential_id: Some(format!("gateway:{credential_id}|{digest}")),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::AlreadyExists);
        }
        Ok(())
    }
}
