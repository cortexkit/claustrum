use super::{
    append_audit_tx, hex32, now_ms, payload_hash, EncryptedStore, StoreOpError,
    GH_MANIFEST_ROOT_KEY_ID,
};
use crate::audit::{AuditCtx, AuditOp, AuditRecord, GhManifestAudit};
use crate::gh_manifest::{GhManifest, ManifestBindingStatement, ManifestValue};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;

pub const MANIFEST_ONE_TAP_SETTING: &str = "manifest.one_tap";
pub const GH_MANIFEST_PROPOSAL_LIFETIME_LIMIT_MS: i64 = 24 * 60 * 60 * 1000;

fn one_tap_status(conn: &Connection) -> &'static str {
    match conn
        .query_row(
            "SELECT value FROM settings WHERE name=?1",
            [MANIFEST_ONE_TAP_SETTING],
            |row| row.get::<_, String>(0),
        )
        .optional()
    {
        Ok(None) => "off",
        Ok(Some(value)) if value == "true" => "on",
        Ok(Some(value)) if value == "false" => "off",
        _ => "unreadable",
    }
}

/// Show the gate without loading secrets or acquiring the writer lease.
pub fn manifest_one_tap_status_read_only(path: &std::path::Path) -> Result<String, StoreOpError> {
    let store_error = |error: rusqlite::Error| StoreOpError::Store(error.to_string());
    if !path
        .try_exists()
        .map_err(|error| StoreOpError::Store(error.to_string()))?
    {
        return Ok("off".into());
    }
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(store_error)?;
    let has_settings: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='settings')",
            [],
            |row| row.get(0),
        )
        .map_err(store_error)?;
    Ok(if has_settings {
        one_tap_status(&conn)
    } else {
        "off"
    }
    .into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhManifestProposalError {
    ManifestSetupIncomplete,
    AlreadyBound {
        version: i64,
        manifest_sha256: String,
    },
    BoundToOtherAgent,
    StaleBase,
    NotReproducible,
    GithubUnavailable,
    StoreError,
}

/// Identity and installation checks belong to the caller. The repository spelling
/// and permissions here must be the installation check's full_name and permission map.
#[derive(Debug, Clone)]
pub struct GhManifestProposalInput {
    pub agent_id: String,
    pub app_id: i64,
    pub app_slug: String,
    pub repo: String,
    pub installation_permissions: BTreeMap<String, String>,
}

/// An immutable checked base. Only the store can construct one; the write path
/// rechecks its version after acquiring the writer.
#[derive(Debug, Clone)]
pub struct PreparedGhManifestProposal {
    input: GhManifestProposalInput,
    prior: GhManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhManifestProposal {
    pub proposal_id: String,
    pub agent_id: String,
    pub app_id: i64,
    pub app_slug: String,
    pub repo: String,
    pub installation_permissions: Vec<u8>,
    pub base_version: i64,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: String,
    pub statement_bytes: Vec<u8>,
    pub statement_sha256: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

fn setup_complete(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id=?1 AND state='active') \
         AND EXISTS(SELECT 1 FROM gh_manifests) \
         AND EXISTS(SELECT 1 FROM settings WHERE name=?2 AND value != '')",
        params![
            GH_MANIFEST_ROOT_KEY_ID,
            crate::federation::SELF_MEMBER_SETTING
        ],
        |row| row.get(0),
    )
}

impl EncryptedStore {
    /// Malformed or unreadable values never enable statement creation.
    pub fn manifest_one_tap_enabled(&self) -> bool {
        self.store
            .with_conn(|conn| Ok(one_tap_status(conn) == "on"))
            .unwrap_or(false)
    }

    pub fn set_manifest_one_tap_audited(
        &self,
        enabled: bool,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.fenced_write(|tx| {
            let wanted = if enabled { "true" } else { "false" };
            let old: Option<rusqlite::types::Value> = tx
                .query_row("SELECT value FROM settings WHERE name=?1", [MANIFEST_ONE_TAP_SETTING], |row| row.get(0))
                .optional()?;
            if old == Some(rusqlite::types::Value::Text(wanted.into())) {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO settings (name,value,updated_at_ms) VALUES (?1,?2,?3) \
                 ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated_at_ms=excluded.updated_at_ms",
                params![MANIFEST_ONE_TAP_SETTING, wanted, now_ms()],
            )?;
            let mut payload = Vec::new();
            crate::agent_secret::push_field(&mut payload, wanted.as_bytes());
            append_audit_tx(tx, &self.audit_key, &AuditRecord {
                op: AuditOp::GhManifestOneTapSet,
                credential_id: None,
                payload_hash: Some(hex32(&payload_hash(&payload))),
                actor: ctx.actor.to_owned(),
                alarm: ctx.alarm,
            })?;
            Ok(true)
        }).map_err(StoreOpError::from)
    }

    /// Propose and approve require an active signing root, a stored base and this
    /// vault's own federation member id. Without that id, the local manifest
    /// consumer (AFT) cannot report activation of the resulting version.
    pub fn check_gh_manifest_setup(&self) -> Result<(), GhManifestProposalError> {
        match self.store.with_conn(setup_complete) {
            Ok(true) => Ok(()),
            Ok(false) => Err(GhManifestProposalError::ManifestSetupIncomplete),
            Err(_) => Err(GhManifestProposalError::StoreError),
        }
    }

    /// Run the local checks after identity and installation discovery, without
    /// writing anything. Binding and activation refusals precede reproducibility.
    pub fn prepare_gh_manifest_proposal(
        &self,
        input: GhManifestProposalInput,
    ) -> Result<PreparedGhManifestProposal, GhManifestProposalError> {
        self.store.with_conn(|conn| {
            use GhManifestProposalError as Error;
            if !setup_complete(conn)? {
                return Ok(Err(Error::ManifestSetupIncomplete));
            }
            let (version, bytes, hash): (i64, Vec<u8>, String) = conn.query_row(
                "SELECT version,manifest_bytes,manifest_sha256 FROM gh_manifests ORDER BY version DESC LIMIT 1",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            // This decode is only for the binding lookup. The ordered parser below
            // separately proves that the original bytes can be reproduced exactly.
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(bindings) = value.get("bindings").and_then(|value| value.as_object()) {
                    if let Some((_, agent)) = bindings.iter().find(|(repo, _)| repo.eq_ignore_ascii_case(&input.repo)) {
                        return Ok(Err(if agent.as_str() == Some(&input.agent_id) {
                            Error::AlreadyBound { version, manifest_sha256: hash }
                        } else { Error::BoundToOtherAgent }));
                    }
                }
            }
            let ahead: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM gh_manifest_activations WHERE retired_at_ms IS NULL AND version > ?1)",
                [version], |row| row.get(0),
            )?;
            if ahead { return Ok(Err(Error::StaleBase)); }
            let prior = match GhManifest::parse_reproducible(&bytes) {
                Ok(prior) if prior.version() == version && prior.manifest_sha256() == hash => prior,
                _ => return Ok(Err(Error::NotReproducible)),
            };
            Ok(Ok(PreparedGhManifestProposal { input, prior }))
        }).map_err(|_| GhManifestProposalError::StoreError)?
    }

    /// Check admission only after holding the writer. Once admitted, the operation
    /// completes without rechecking the deadline; callers must await its result.
    pub fn propose_gh_manifest_binding(
        &self,
        prepared: &PreparedGhManifestProposal,
        actor: &str,
        before_deadline: impl FnOnce() -> bool,
        clock: impl FnOnce() -> i64,
    ) -> Result<GhManifestProposal, GhManifestProposalError> {
        self.fenced_write(|tx| {
            use GhManifestProposalError as Error;
            if !before_deadline() { return Ok(Err(Error::GithubUnavailable)); }
            let now = clock();
            let newest: Option<i64> = tx.query_row("SELECT MAX(version) FROM gh_manifests", [], |row| row.get(0))?;
            if newest != Some(prepared.prior.version()) { return Ok(Err(Error::StaleBase)); }
            let input = &prepared.input;
            let pending = tx.query_row(
                "SELECT proposal_id,agent_id,app_id,app_slug,repo,installation_permissions,base_version, \
                 manifest_bytes,manifest_sha256,statement_bytes,statement_sha256,created_at_ms,expires_at_ms \
                 FROM gh_manifest_proposals WHERE agent_id=?1 AND lower(repo)=lower(?2) AND state='pending'",
                params![input.agent_id, input.repo], proposal_row,
            ).optional()?;
            if let Some(pending) = &pending {
                if now < pending.expires_at_ms { return Ok(Ok(pending.clone())); }
            }
            // Build before changing an expired row: every refusal must leave all
            // manifest tables and the audit chain unchanged.
            let proposal = match build_proposal(prepared, now) {
                Ok(proposal) => proposal,
                Err(error) => return Ok(Err(error)),
            };
            if let Some(pending) = pending {
                tx.execute("UPDATE gh_manifest_proposals SET state='expired' WHERE proposal_id=?1", [&pending.proposal_id])?;
                append_audit_tx(tx, &self.audit_key, &GhManifestAudit::ProposalState {
                    proposal_id: &pending.proposal_id, from: "pending", to: "expired",
                }.record(actor, None))?;
            }
            tx.execute(
                "INSERT INTO gh_manifest_proposals \
                 (proposal_id,agent_id,app_id,app_slug,repo,installation_permissions,base_version, \
                  manifest_bytes,manifest_sha256,statement_bytes,statement_sha256,created_at_ms,expires_at_ms,state) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending')",
                params![proposal.proposal_id, proposal.agent_id, proposal.app_id, proposal.app_slug,
                    proposal.repo, proposal.installation_permissions, proposal.base_version,
                    proposal.manifest_bytes, proposal.manifest_sha256, proposal.statement_bytes,
                    proposal.statement_sha256, proposal.created_at_ms, proposal.expires_at_ms],
            )?;
            append_audit_tx(tx, &self.audit_key, &GhManifestAudit::Propose {
                proposal_id: &proposal.proposal_id, agent_id: &proposal.agent_id, repo: &proposal.repo,
                base_version: proposal.base_version, manifest_sha256: &proposal.manifest_sha256,
                statement_sha256: &proposal.statement_sha256,
            }.record(actor, None))?;
            Ok(Ok(proposal))
        }).map_err(|_| GhManifestProposalError::StoreError)?
    }
}

fn build_proposal(
    prepared: &PreparedGhManifestProposal,
    now: i64,
) -> Result<GhManifestProposal, GhManifestProposalError> {
    let error = |_| GhManifestProposalError::StoreError;
    let input = &prepared.input;
    let proposal_id = crate::agent_secret::request_id(now).map_err(error)?;
    let expires_at_ms = now
        .checked_add(GH_MANIFEST_PROPOSAL_LIFETIME_LIMIT_MS)
        .ok_or(GhManifestProposalError::StoreError)?;
    let manifest = prepared
        .prior
        .build_next(&input.repo, &input.agent_id, now / 1000)
        .map_err(|_| GhManifestProposalError::NotReproducible)?;
    let statement = ManifestBindingStatement::new(
        proposal_id.clone(),
        input.agent_id.clone(),
        input.app_slug.clone(),
        input.repo.clone(),
        input.installation_permissions.clone(),
        &manifest,
        &prepared.prior,
        expires_at_ms,
    )
    .map_err(|_| GhManifestProposalError::NotReproducible)?;
    let statement_bytes = statement
        .canonical_bytes()
        .map_err(|_| GhManifestProposalError::NotReproducible)?;
    // Extract from the canonical statement so permission keys retain JCS's UTF-16
    // order, rather than the map's native string ordering.
    let canonical: ManifestValue = serde_json::from_slice(&statement_bytes)
        .map_err(|_| GhManifestProposalError::StoreError)?;
    let installation_permissions = serde_json::to_vec(
        canonical
            .get("installation_permissions")
            .expect("statement permissions"),
    )
    .map_err(|_| GhManifestProposalError::StoreError)?;
    Ok(GhManifestProposal {
        proposal_id,
        agent_id: input.agent_id.clone(),
        app_id: input.app_id,
        app_slug: input.app_slug.clone(),
        repo: input.repo.clone(),
        installation_permissions,
        base_version: prepared.prior.version(),
        manifest_bytes: manifest.to_bytes(),
        manifest_sha256: statement.manifest_sha256,
        statement_sha256: hex32(&payload_hash(&statement_bytes)),
        statement_bytes,
        created_at_ms: now,
        expires_at_ms,
    })
}

fn proposal_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GhManifestProposal> {
    Ok(GhManifestProposal {
        proposal_id: row.get(0)?,
        agent_id: row.get(1)?,
        app_id: row.get(2)?,
        app_slug: row.get(3)?,
        repo: row.get(4)?,
        installation_permissions: row.get(5)?,
        base_version: row.get(6)?,
        manifest_bytes: row.get(7)?,
        manifest_sha256: row.get(8)?,
        statement_bytes: row.get(9)?,
        statement_sha256: row.get(10)?,
        created_at_ms: row.get(11)?,
        expires_at_ms: row.get(12)?,
    })
}

#[cfg(test)]
#[path = "store_gh_proposal_tests.rs"]
mod tests;
