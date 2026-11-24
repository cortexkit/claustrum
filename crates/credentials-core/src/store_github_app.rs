use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use super::store_agent_secrets::secret_home_role_conn;
use super::{
    append_audit_tx, hex32, now_ms, AuditOp, AuditRecord, EncryptedStore, StoreOpError, StoredRead,
};
use crate::agent_policy::{valid_app_slug, valid_github_app_agent};
use crate::oauth::OAuthCredential;
use crate::record::{CredentialKind, VaultRecord};
use crate::refresh_adapters::github_app::{GithubAppAdapter, ADAPTER_NAME};
use crate::secret::SecretString;

pub(super) const AGENT_EXISTS: &str = "github_app_agent_exists: an App already holds this agent";
const COMPANION_PREFIX: &str = "opaque:github-app-webhook:";

pub fn is_github_app_companion_id(id: &str) -> bool {
    id.starts_with(COMPANION_PREFIX)
}

pub fn check_github_app_companion_id(id: &str) -> Result<(), StoreOpError> {
    if is_github_app_companion_id(id) {
        return Err(StoreOpError::GitHubAppCompanionProtected);
    }
    Ok(())
}

/// The locally recorded App identity a read or list grant can disclose.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ListedGitHubApp {
    pub app_id: String,
    pub slug: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<GitHubAppAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "created_by")]
pub enum GitHubAppAttestation {
    #[serde(rename = "vault")]
    Vault { created_at_ms: i64, agent: String },
}

/// Read this before clearing an App's attestation in the same transaction.
/// A matching id alone is not evidence that a legacy record belongs to the App.
pub(super) fn managed_github_app_companion(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
) -> rusqlite::Result<Option<String>> {
    let Some(slug) = id.strip_prefix("github_app:") else {
        return Ok(None);
    };
    if super::read_schema_version(tx)? < super::POLICY_ROOT_SCHEMA_VERSION {
        return Ok(None);
    }
    let managed = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = ?1 \
                        AND github_app_created_at_ms IS NOT NULL AND github_app_relay_slot IS NOT NULL)",
        [id],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(managed.then(|| format!("{COMPANION_PREFIX}{slug}")))
}

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
    /// Open only the material needed to sign an App JWT. A vault-created App has
    /// no installation token yet, and a failed open must not quarantine the row.
    pub(super) fn open_github_app_material(
        &self,
        id: &str,
        version: u64,
        blob: &[u8],
    ) -> Result<Option<OAuthCredential>, StoreOpError> {
        let bytes = super::envelope::open(
            &self.key,
            blob,
            &super::RecordBinding {
                credential_id: id,
                record_version: version,
            },
        )
        .map_err(StoreOpError::Decrypt)?;
        let record = VaultRecord::decode(&bytes)
            .map_err(|error| StoreOpError::Corrupt(error.to_string()))?;
        if record.kind != CredentialKind::Oauth
            || record.refresh_adapter.as_deref() != Some(ADAPTER_NAME)
        {
            return Ok(None);
        }
        Ok(record.oauth.filter(|oauth| {
            oauth.client_id.as_ref().is_some_and(|id| !id.is_empty())
                && GithubAppAdapter::valid_private_key_pem(oauth.refresh_token.expose())
        }))
    }

    /// Model a row deposited before the webhook companion namespace was reserved.
    #[cfg(any(test, feature = "test-support"))]
    pub fn put_legacy_github_app_companion_for_tests(
        &self,
        id: &str,
        record: &VaultRecord,
    ) -> Result<(), StoreOpError> {
        assert!(is_github_app_companion_id(id));
        self.fenced_write_or_refuse(|tx| {
            self.create_audited_in_tx(
                tx,
                id,
                record,
                crate::audit::AuditCtx::admin(AuditOp::Put),
                now_ms(),
            )
        })
    }

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
        let companion_id = format!("{COMPANION_PREFIX}{slug}");
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
        let companion_id = format!("{COMPANION_PREFIX}{slug}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::github_app::GithubAppIdentity;
    use crate::store::taxonomy_tests::rig;

    #[test]
    fn github_app_refresh_keeps_attested_identity_but_updates_hand_added_identity() {
        let (_dir, store) = rig("github-app-refresh-identity", 212);
        let id = "github_app:created-app";
        let agent = "agent_0123456789abcdef";
        let slot = "test-slot";
        store
            .create_github_app_audited(
                GitHubAppCreation {
                    slug: "created-app",
                    app_id: 9007199254740993,
                    agent,
                    pem: &"test-pem".to_owned().into(),
                    client_id: "test-client",
                    relay: Some((slot, &"webhook-test-secret".to_owned().into())),
                },
                "test",
            )
            .unwrap();
        let attestation = || {
            store
                .store
                .with_conn(|conn| {
                    conn.query_row(
                        "SELECT github_app_id, github_app_slug, github_app_created_at_ms, \
                                github_app_agent, github_app_relay_slot FROM credentials \
                         WHERE credential_id = ?1",
                        [id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, String>(4)?,
                            ))
                        },
                    )
                })
                .unwrap()
        };
        let alleged_identity = GithubAppIdentity {
            app_id: "17".into(),
            slug: "other-app".into(),
        };
        let before = attestation();
        assert_eq!(before.0, "9007199254740993");
        assert_eq!(before.1, "created-app");
        assert_eq!(before.3, agent);
        assert_eq!(before.4, slot);

        let refresh = |credential_id: &str, identity: Option<&GithubAppIdentity>| {
            let mut record = store.get(credential_id).unwrap();
            let version = record.record_version;
            record.oauth.as_mut().unwrap().access_token = "new-test-token".to_owned().into();
            assert_eq!(
                store
                    .commit_refresh(
                        credential_id,
                        version,
                        &store.credential_incarnation(credential_id).unwrap(),
                        &record,
                        identity,
                    )
                    .unwrap(),
                version + 1,
            );
        };
        let different_id_only = GithubAppIdentity {
            app_id: alleged_identity.app_id.clone(),
            slug: "created-app".into(),
        };
        for identity in [None, Some(&different_id_only), Some(&alleged_identity)] {
            refresh(id, identity);
            assert_eq!(attestation(), before);
        }
        let hand_added = "github_app:hand-added";
        store.create(hand_added, &store.get(id).unwrap()).unwrap();
        let hand_added_report = GithubAppIdentity {
            slug: "hand-added".into(),
            ..alleged_identity
        };
        refresh(hand_added, Some(&hand_added_report));
        let hand_added_identity = store
            .store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT github_app_id, github_app_slug FROM credentials WHERE credential_id = ?1",
                    [hand_added],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
            })
            .unwrap();
        assert_eq!(hand_added_identity, ("17".into(), "hand-added".into()));
    }
}
