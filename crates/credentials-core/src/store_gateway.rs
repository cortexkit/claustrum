use super::*;
use crate::gateway::{
    gateway_settings_digest, validate_gateway_settings, GatewayAuth, GatewaySettings,
    GatewaySettingsRule,
};

/// Plaintext gateway metadata with the identity of the record it was written for.
/// Readers must compare `incarnation` with the record they serve, not a later lookup
/// of the same credential id: removal and recreation can change all settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGatewaySettings {
    pub incarnation: String,
    pub settings: GatewaySettings,
    /// Exact base-URL host, without a port and with IPv6 brackets preserved.
    pub host: String,
    /// Derived from the stored provider id's prefix, never from a catalog offering.
    pub vendor: crate::catalog::ModelVendor,
}

pub(super) fn from_conn(
    conn: &rusqlite::Connection,
    credential_id: &str,
    schema_version: u32,
) -> rusqlite::Result<Option<StoredGatewaySettings>> {
    if schema_version < GATEWAY_SETTINGS_SCHEMA_VERSION {
        return Ok(None);
    }
    conn.query_row(
        "SELECT incarnation, base_url, auth_header, auth_scheme, headers_json, \
         COALESCE((SELECT group_concat(provider_id, ',') FROM (\
             SELECT provider_id FROM credential_provider_ids WHERE credential_id = ?1 ORDER BY provider_id\
         )), '') FROM credential_gateway_settings WHERE credential_id = ?1",
        [credential_id],
        |row| {
            let invalid = || {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid stored gateway settings",
                    )),
                )
            };
            let settings = GatewaySettings {
                base_url: row.get(1)?,
                auth: GatewayAuth {
                    header: row.get(2)?,
                    scheme: row.get(3)?,
                },
                headers: serde_json::from_str(&row.get::<_, String>(4)?).map_err(|_| invalid())?,
            };
            let providers = split_provider_ids(row.get(5)?);
            let validated = validate_gateway_settings(credential_id, &settings, &providers)
                .map_err(|_| invalid())?;
            Ok(StoredGatewaySettings {
                incarnation: row.get(0)?,
                settings,
                host: validated.host,
                vendor: validated.vendor,
            })
        },
    )
    .optional()
}

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
    /// Read gateway metadata without unsealing the key. `None` means no settings row
    /// (including stores predating the gateway migration). The stored incarnation is
    /// returned unchanged so a read surface can refuse a removed-and-recreated id.
    pub fn gateway_settings(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredGatewaySettings>, StoreOpError> {
        self.store
            .with_conn(|conn| from_conn(conn, credential_id, read_schema_version(conn)?))
            .map_err(StoreOpError::from)
    }

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
