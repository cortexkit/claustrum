use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use super::store_agent_secrets::secret_home_role_conn;
use super::{
    append_audit_tx, hex32, now_ms, AuditOp, AuditRecord, EncryptedStore, StoreOpError, StoredRead,
};
use crate::agent_policy::{valid_app_slug, valid_github_app_agent};
use crate::oauth::OAuthCredential;
use crate::record::{CredentialKind, VaultRecord};
use crate::refresh_adapters::github_app::ADAPTER_NAME;
use crate::secret::SecretString;

pub(super) const AGENT_EXISTS: &str = "github_app_agent_exists: an App already holds this agent";

pub(super) fn github_app_agent_exists_conn(
    conn: &Connection,
    agent: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE github_app_agent = ?1)",
        [agent],
        |row| row.get(0),
    )
}

pub(super) fn github_app_attested_agent(
    conn: &Connection,
    credential_id: &str,
) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT github_app_agent FROM credentials WHERE credential_id = ?1",
        [credential_id],
        |row| row.get::<_, Option<String>>(0),
    )
    .optional()
    .map(Option::flatten)
}

/// Material from a validated GitHub manifest conversion. The relay slot and the
/// webhook secret, when present, belong to the same conversion.
pub struct GitHubAppCreation<'a> {
    pub slug: &'a str,
    pub app_id: u64,
    pub agent: &'a str,
    pub pem: &'a SecretString,
    pub client_id: &'a str,
    pub relay: Option<(&'a str, &'a SecretString)>,
}

impl EncryptedStore {
    /// Check all states, including invalidated Apps, before consuming a GitHub code.
    pub fn github_app_agent_exists(&self, agent: &str) -> Result<bool, StoreOpError> {
        Ok(self
            .store
            .with_conn(|conn| github_app_agent_exists_conn(conn, agent))?)
    }

    /// Create the OAuth record, its agent association and optional webhook companion together.
    /// The caller holds the App lock through this write and the initial relay PUT.
    pub fn create_github_app_audited(
        &self,
        app: GitHubAppCreation<'_>,
        actor: &str,
    ) -> Result<(), StoreOpError> {
        let GitHubAppCreation {
            slug,
            app_id,
            agent,
            pem,
            client_id,
            relay,
        } = app;
        if !valid_app_slug(slug)
            || !valid_github_app_agent(agent)
            || app_id == 0
            || client_id.is_empty()
        {
            return Err(StoreOpError::Encode(
                "invalid GitHub App conversion material".into(),
            ));
        }
        let id = format!("github_app:{slug}");
        let companion_id = format!("opaque:github-app-webhook:{slug}");
        let oauth = OAuthCredential {
            access_token: String::new().into(),
            refresh_token: pem.clone(),
            expires_at_ms: None,
            token_url: String::new(),
            client_id: Some(client_id.into()),
            client_secret: None,
            scopes: Vec::new(),
        };
        let record = VaultRecord::new_oauth("operator", ADAPTER_NAME, oauth, Vec::new());
        let slot = relay.map(|(slot, _)| slot);
        let unencodable = |_| StoreOpError::Encode("could not encode GitHub App material".into());
        let companion = relay
            .map(|(_, secret)| {
                serde_json::to_vec(&WebhookRecord {
                    current: secret.clone(),
                    pending: None,
                    pending_put_confirmed: false,
                })
                .map(|payload| {
                    VaultRecord::new_static(CredentialKind::Opaque, "operator", payload, None)
                })
            })
            .transpose()
            .map_err(unencodable)?;
        let audit_input = Zeroizing::new(
            serde_json::to_vec(&(
                app_id,
                slug,
                agent,
                client_id,
                pem.expose(),
                slot,
                relay.map(|(_, secret)| secret.expose()),
            ))
            .map_err(unencodable)?,
        );
        let payload_hash = hex32(&crate::audit::payload_fingerprint(
            &self.audit_key,
            &audit_input,
        ));

        self.fenced_write_or_refuse(|tx| {
            use super::SecretHomeRole;
            match secret_home_role_conn(tx) {
                SecretHomeRole::Single | SecretHomeRole::Home { .. } => {}
                SecretHomeRole::Remote { home_member } => {
                    return Ok(Err(StoreOpError::SecretHomeElsewhere { home_member }))
                }
                SecretHomeRole::RemoteSetupIncomplete { self_member } => {
                    return Ok(Err(StoreOpError::SecretRemoteSetupIncomplete {
                        remedy_member: self_member,
                    }))
                }
                SecretHomeRole::StoreError => return Err(rusqlite::Error::InvalidQuery),
            }
            let id_taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id IN (?1, ?2)) \
                 OR EXISTS(SELECT 1 FROM remote_records WHERE credential_id IN (?1, ?2))",
                params![id, companion_id],
                |row| row.get(0),
            )?;
            if id_taken {
                return Ok(Err(StoreOpError::AlreadyExists));
            }
            // This read and the insert share one write transaction.
            // The unique index also prevents any other writer from duplicating an agent.
            if github_app_agent_exists_conn(tx, agent)? {
                return Ok(Err(StoreOpError::Encode(AGENT_EXISTS.into())));
            }
            let now = now_ms();
            if let Err(error) = self.insert_new_record_in_tx(tx, &id, &record, now)? {
                return Ok(Err(error));
            }
            tx.execute(
                "UPDATE credentials SET github_app_id = ?2, github_app_slug = ?3, \
                 github_app_created_at_ms = ?4, github_app_agent = ?5, github_app_relay_slot = ?6 \
                 WHERE credential_id = ?1",
                params![id, app_id.to_string(), slug, now, agent, slot],
            )?;
            if let Some(companion) = &companion {
                if let Err(error) =
                    self.insert_new_record_in_tx(tx, &companion_id, companion, now)?
                {
                    return Ok(Err(error));
                }
            }
            append_audit_tx(
                tx,
                &self.audit_key,
                &AuditRecord {
                    op: AuditOp::GitHubAppCreateComplete,
                    credential_id: Some(id),
                    payload_hash: Some(payload_hash),
                    actor: actor.into(),
                    alarm: None,
                },
            )?;
            Ok(Ok(()))
        })
    }

    pub fn github_app_relay(&self, slug: &str) -> Result<GitHubAppRelay, GitHubAppRelayError> {
        use GitHubAppRelayError::{Inactive, NoRelay, NotFound, Store};
        let app = format!("github_app:{slug}");
        let companion_id = format!("opaque:github-app-webhook:{slug}");
        let (state, app_incarnation, attested, slot, app_id) = self
            .store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT state, incarnation, github_app_agent IS NOT NULL, \
                     github_app_relay_slot, github_app_id FROM credentials WHERE credential_id = ?1",
                    [&app],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, bool>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )
                .optional()
            })
            .map_err(|error| Store(error.into()))?
            .ok_or(NotFound)?;
        if state != "active" {
            return Err(Inactive);
        }
        let slot = slot.filter(|_| attested).ok_or(NoRelay)?;
        let app_id = app_id
            .filter(|id| {
                id.parse::<u64>()
                    .is_ok_and(|n| n > 0 && n.to_string() == *id)
            })
            .ok_or_else(|| Store(invalid_webhook_record()))?;
        // The App state is checked before opening either of the sealed records.
        let companion = self
            .get_with_stale_pending_and_digest(&companion_id)
            .map_err(Store)?;
        let webhook: WebhookRecord = serde_json::from_slice(companion.record.payload.expose())
            .map_err(|_| Store(invalid_webhook_record()))?;
        if companion.record.kind != CredentialKind::Opaque
            || webhook.current.expose().is_empty()
            || webhook.pending_put_confirmed && webhook.pending.is_none()
            || webhook
                .pending
                .as_ref()
                .is_some_and(|secret| secret.expose().is_empty())
        {
            return Err(Store(invalid_webhook_record()));
        }
        Ok(GitHubAppRelay {
            app,
            app_incarnation,
            app_id,
            slot,
            companion_id,
            companion,
            webhook,
        })
    }

    pub fn github_app_relay_oauth(
        &self,
        relay: &GitHubAppRelay,
    ) -> Result<OAuthCredential, StoreOpError> {
        let record = self
            .get_snapshot(&relay.app, &relay.app_incarnation)?
            .record;
        if record.refresh_adapter.as_deref() != Some(ADAPTER_NAME) {
            return Err(invalid_webhook_record());
        }
        record.oauth.ok_or_else(invalid_webhook_record)
    }

    pub fn audit_github_app_relay_retry(
        &self,
        relay: &GitHubAppRelay,
        actor: &str,
    ) -> Result<(), StoreOpError> {
        let input = Zeroizing::new(
            serde_json::to_vec(&(&relay.app_id, &relay.slot, relay.current()))
                .map_err(|_| invalid_webhook_record())?,
        );
        self.append_audit(&AuditRecord {
            op: AuditOp::GitHubAppRelayRetry,
            credential_id: Some(relay.app.clone()),
            payload_hash: Some(hex32(&crate::audit::payload_fingerprint(
                &self.audit_key,
                &input,
            ))),
            actor: actor.into(),
            alarm: None,
        })?;
        Ok(())
    }

    pub fn rotate_github_app_webhook_audited(
        &self,
        relay: &mut GitHubAppRelay,
        step: WebhookRotation,
        actor: &str,
    ) -> Result<(), StoreOpError> {
        let mut webhook = relay.webhook.clone();
        match step {
            WebhookRotation::Stage(secret) if webhook.pending.is_none() => {
                webhook.pending = Some(secret);
            }
            WebhookRotation::ConfirmPut
                if webhook.pending.is_some() && !webhook.pending_put_confirmed =>
            {
                webhook.pending_put_confirmed = true;
            }
            WebhookRotation::Promote if webhook.pending_put_confirmed => {
                webhook.current = webhook.pending.take().ok_or_else(invalid_webhook_record)?;
                webhook.pending_put_confirmed = false;
            }
            _ => return Err(invalid_webhook_record()),
        }
        let mut record = relay.companion.record.clone();
        let previous_version = record.record_version;
        record.record_version = previous_version
            .checked_add(1)
            .ok_or_else(invalid_webhook_record)?;
        record.payload = serde_json::to_vec(&webhook)
            .map_err(|_| invalid_webhook_record())?
            .into();
        let blob = self.seal_record(&relay.companion_id, &record)?;
        let digest = hex32(&crate::audit::payload_fingerprint(
            &self.audit_key,
            record.payload.expose(),
        ));
        self.fenced_write_or_refuse(|tx| {
            let changed = tx.execute(
                "UPDATE credentials SET record_version = ?2, key_id = ?3, envelope = ?4, updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6 AND incarnation = ?7 AND state = 'active' \
                 AND EXISTS (SELECT 1 FROM credentials WHERE credential_id = ?8 AND incarnation = ?9 \
                             AND state = 'active' AND github_app_relay_slot = ?10)",
                params![
                    relay.companion_id, record.record_version, self.key_id.to_hex(), blob, now_ms(),
                    previous_version, relay.companion.incarnation, relay.app, relay.app_incarnation, relay.slot,
                ],
            )?;
            if changed != 1 {
                return Ok(Err(StoreOpError::CasMismatch));
            }
            append_audit_tx(tx, &self.audit_key, &AuditRecord {
                op: AuditOp::GitHubAppWebhookRotate,
                credential_id: Some(relay.app.clone()),
                payload_hash: Some(digest),
                actor: actor.into(),
                alarm: None,
            })?;
            Ok(Ok(()))
        })?;
        relay.companion.record = record;
        relay.webhook = webhook;
        Ok(())
    }
}

fn invalid_webhook_record() -> StoreOpError {
    StoreOpError::Encode("invalid GitHub App webhook state".into())
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct WebhookRecord {
    current: SecretString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<SecretString>,
    #[serde(default, skip_serializing_if = "is_false")]
    pending_put_confirmed: bool,
}

/// Relay state read under the full App ID's admin lock. Hold that lock until
/// the outbound operation and any corresponding audit or state write finish.
pub struct GitHubAppRelay {
    app: String,
    app_incarnation: String,
    pub app_id: String,
    pub slot: String,
    companion_id: String,
    companion: StoredRead,
    webhook: WebhookRecord,
}

impl GitHubAppRelay {
    pub fn current(&self) -> &SecretString {
        &self.webhook.current
    }

    pub fn pending(&self) -> Option<&SecretString> {
        self.webhook.pending.as_ref()
    }

    pub fn pending_put_confirmed(&self) -> bool {
        self.webhook.pending_put_confirmed
    }
}

pub enum GitHubAppRelayError {
    NotFound,
    Inactive,
    NoRelay,
    Store(StoreOpError),
}

/// Each transition replaces the sealed payload and appends its audit row together.
pub enum WebhookRotation {
    Stage(SecretString),
    ConfirmPut,
    Promote,
}
