use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use super::store_agent_secrets::secret_home_role_conn;
use super::{append_audit_tx, hex32, now_ms, AuditOp, AuditRecord, EncryptedStore, StoreOpError};
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
        let companion = relay.map(|(_, secret)| {
            let payload = serde_json::to_vec(&WebhookRecord {
                current: secret.expose(),
            })
            .expect("a string field always serializes");
            VaultRecord::new_static(CredentialKind::Opaque, "operator", payload, None)
        });
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
            .expect("strings, bytes and an App id always serialize"),
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
}

#[derive(serde::Serialize)]
struct WebhookRecord<'a> {
    current: &'a str,
}
