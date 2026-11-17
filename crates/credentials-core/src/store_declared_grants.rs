//! Approved declarations are route authority; persisted sets are only a last-seen inventory.

use super::*;

/// Account-token audiences accepted by both the exchange and declaration parser.
pub const ACCOUNT_TOKEN_AUDIENCES: [&str; 4] = [
    "cortexkit-runners",
    "cortexkit-account",
    "cortexkit-webhook-relay",
    "cortexkit-hub",
];

pub const MAX_DECLARED_GRANTS: usize = 32;

/// Field order is the canonical persisted JSON order, independent of JSON map ordering.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredGrant {
    pub selector_kind: SelectorKind,
    pub selector: String,
    pub operation: GrantOperation,
}

const CATEGORY_READ_APPROVAL_TEMPLATE: &str = "Read your <category name> logins and keys";
const CATEGORY_LIST_APPROVAL_TEMPLATE: &str =
    "See which <category name> logins and keys exist (no secrets)";
const CATEGORY_DEPOSIT_APPROVAL_TEMPLATE: &str =
    "Save browser sign-ins into the vault (<category name>)";
const AUDIENCE_ACCOUNT_TOKEN_APPROVAL_TEMPLATE: &str =
    "Get short-lived CortexKit account tokens for <audience>";

/// Desktop approval templates in the order used by the wire contract.
pub const DECLARED_GRANT_APPROVAL_TEMPLATES: &[(&str, &str)] = &[
    ("Category `read`", CATEGORY_READ_APPROVAL_TEMPLATE),
    ("Category `list`", CATEGORY_LIST_APPROVAL_TEMPLATE),
    ("Category `deposit`", CATEGORY_DEPOSIT_APPROVAL_TEMPLATE),
    (
        "Audience `account_token`",
        AUDIENCE_ACCOUNT_TOKEN_APPROVAL_TEMPLATE,
    ),
];

/// Category plain names in wire-contract order; unlisted categories keep their raw name.
pub const DECLARED_GRANT_CATEGORY_NAMES: &[(&str, &str)] = &[
    ("llm-provider", "model provider"),
    ("llm-gateway", "company AI gateway"),
    ("data-warehouse", "data warehouse"),
    ("cloud-infrastructure", "cloud infrastructure"),
    ("web-search", "web search"),
    ("media-provider", "speech and media"),
    ("embedding-provider", "embedding models"),
    ("browser-session", "browser sign-in"),
    ("antigravity-native", "Antigravity"),
    ("anthropic-native", "Anthropic"),
    ("cursor-native", "Cursor"),
    ("devin-native", "Devin"),
    ("digitalocean-native", "DigitalOcean"),
    ("github-app-native", "GitHub bot"),
    ("github-copilot-native", "GitHub Copilot"),
    ("gmail-native", "Gmail"),
    ("google-native", "Google"),
    ("kimi-native", "Kimi"),
    ("meta-native", "Meta AI"),
    ("openai-native", "OpenAI"),
    ("snowflake-native", "Snowflake"),
    ("xai-native", "xAI"),
];

/// Format a parser-admitted grant for a desktop approval screen, not an admission check.
/// Unsupported selector/operation pairs return `None` so callers can show raw JSON.
pub fn declared_grant_approval_sentence(grant: &DeclaredGrant) -> Option<String> {
    let template = match (grant.selector_kind, grant.operation) {
        (SelectorKind::Category, GrantOperation::Read) => CATEGORY_READ_APPROVAL_TEMPLATE,
        (SelectorKind::Category, GrantOperation::List) => CATEGORY_LIST_APPROVAL_TEMPLATE,
        (SelectorKind::Category, GrantOperation::Deposit) => CATEGORY_DEPOSIT_APPROVAL_TEMPLATE,
        (SelectorKind::Audience, GrantOperation::AccountToken) => {
            return Some(
                AUDIENCE_ACCOUNT_TOKEN_APPROVAL_TEMPLATE.replace("<audience>", &grant.selector),
            );
        }
        _ => return None,
    };
    let name = DECLARED_GRANT_CATEGORY_NAMES
        .iter()
        .find_map(|(category, name)| (*category == grant.selector).then_some(*name))
        .unwrap_or(&grant.selector);
    Some(template.replace("<category name>", name))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclaredGrantSet {
    module_id: Option<String>,
    grants: Vec<DeclaredGrant>,
}

impl DeclaredGrantSet {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn grants(&self) -> &[DeclaredGrant] {
        &self.grants
    }

    pub fn grants_json(&self) -> String {
        // DeclaredGrant contains only strings and string enums, which cannot fail JSON encoding.
        serde_json::to_string(&self.grants).expect("declared grant JSON")
    }

    /// Decode an inventory row without treating arbitrary stored tuples as authority.
    pub fn from_grants_json(module_id: &str, json: &str) -> Result<Self, String> {
        let grants: Vec<DeclaredGrant> = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if grants
            .iter()
            .any(|grant| validate_declared_grant(module_id, grant).is_err())
        {
            return Err("invalid declared grant tuple".into());
        }
        Ok(Self::canonical(module_id, grants))
    }

    fn canonical(module_id: &str, mut grants: Vec<DeclaredGrant>) -> Self {
        grants.sort_by(|a, b| {
            (
                a.selector_kind.as_str(),
                a.selector.as_str(),
                a.operation.as_str(),
            )
                .cmp(&(
                    b.selector_kind.as_str(),
                    b.selector.as_str(),
                    b.operation.as_str(),
                ))
        });
        grants.dedup();
        Self {
            module_id: Some(module_id.into()),
            grants,
        }
    }

    pub(super) fn union_into(&self, kind: &str, id: &str, hand: &mut Vec<ReadGrant>) {
        if kind != "reserved" || self.module_id.as_deref() != Some(id) {
            return;
        }
        for grant in &self.grants {
            if !hand.iter().any(|row| {
                row.selector_kind == grant.selector_kind
                    && row.selector == grant.selector
                    && row.operation == grant.operation
            }) {
                hand.push(ReadGrant {
                    principal_kind: kind.into(),
                    principal_id: id.into(),
                    selector_kind: grant.selector_kind,
                    selector: grant.selector.clone(),
                    operation: grant.operation,
                    created_at_ms: 0,
                });
            }
        }
        hand.sort_by(|a, b| {
            (
                a.selector_kind.as_str(),
                a.selector.as_str(),
                a.operation.as_str(),
            )
                .cmp(&(
                    b.selector_kind.as_str(),
                    b.selector.as_str(),
                    b.operation.as_str(),
                ))
        });
    }
}

/// Reasons contain no unvalidated declaration values, so callers can log them safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedDeclaredGrant {
    pub index: usize,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclarationDiagnostics {
    pub skipped: Vec<SkippedDeclaredGrant>,
    pub whole_reason: Option<&'static str>,
    pub skipped_count: usize,
}

fn validate_declared_grant(module_id: &str, grant: &DeclaredGrant) -> Result<(), &'static str> {
    // Check the closed string vocabulary before the broader hand-grant validator.
    match (grant.selector_kind, grant.operation.as_str()) {
        (SelectorKind::Category, "read" | "list" | "deposit")
        | (SelectorKind::Audience, "account_token") => {}
        _ => return Err("operation"),
    }
    validate_read_grant(
        "reserved",
        module_id,
        grant.selector_kind,
        &grant.selector,
        grant.operation,
    )
    .map_err(|error| match error {
        StoreOpError::HubAudienceReserved => {
            "cortexkit-hub audience is reserved for reserved:ckbus"
        }
        _ => "tuple",
    })?;
    if grant.selector_kind == SelectorKind::Audience
        && !ACCOUNT_TOKEN_AUDIENCES.contains(&grant.selector.as_str())
    {
        return Err("audience");
    }
    Ok(())
}

fn parse_entry(module_id: &str, value: &serde_json::Value) -> Result<DeclaredGrant, &'static str> {
    let entry = value.as_object().ok_or("entry")?;
    let (selector_kind, selector_key) = if entry.contains_key("category") {
        (SelectorKind::Category, "category")
    } else if entry.contains_key("audience") {
        (SelectorKind::Audience, "audience")
    } else {
        return Err("selector");
    };
    let operation = entry
        .get("operation")
        .and_then(|v| v.as_str())
        .ok_or("operation")?;
    // Never deserialize a declaration operation into the wider GrantOperation vocabulary first.
    let operation = match (selector_kind, operation) {
        (SelectorKind::Category, "read") => GrantOperation::Read,
        (SelectorKind::Category, "list") => GrantOperation::List,
        (SelectorKind::Category, "deposit") => GrantOperation::Deposit,
        (SelectorKind::Audience, "account_token") => GrantOperation::AccountToken,
        _ => return Err("operation"),
    };
    if entry
        .keys()
        .any(|key| key != selector_key && key != "operation")
    {
        return Err("field");
    }
    let selector = entry
        .get(selector_key)
        .and_then(|v| v.as_str())
        .ok_or("selector")?;
    let grant = DeclaredGrant {
        selector_kind,
        selector: selector.into(),
        operation,
    };
    validate_declared_grant(module_id, &grant)?;
    Ok(grant)
}

/// Parse the already-selected claustrum declaration. Admission and warning deduplication
/// belong to the bind handler; malformed declarations never fail a bind.
pub fn parse_declared_grants(
    module_id: &str,
    declaration: &serde_json::Value,
) -> (DeclaredGrantSet, DeclarationDiagnostics) {
    let entries = declaration.get("grants").and_then(|v| v.as_array());
    let rejected = if declaration.get("v").and_then(|v| v.as_u64()) != Some(1) {
        Some("version")
    } else if entries.is_none() {
        Some("grants")
    } else if entries.is_some_and(|entries| entries.len() > MAX_DECLARED_GRANTS) {
        Some("entry_count")
    } else {
        None
    };
    if let Some(reason) = rejected {
        return (
            DeclaredGrantSet::canonical(module_id, vec![]),
            DeclarationDiagnostics {
                whole_reason: Some(reason),
                skipped_count: entries.map_or(0, Vec::len),
                ..Default::default()
            },
        );
    }
    let mut diagnostics = DeclarationDiagnostics::default();
    let mut grants = Vec::new();
    for (index, entry) in entries.expect("validated array").iter().enumerate() {
        match parse_entry(module_id, entry) {
            Ok(grant) => grants.push(grant),
            Err(reason) => diagnostics
                .skipped
                .push(SkippedDeclaredGrant { index, reason }),
        }
    }
    diagnostics.skipped_count = diagnostics.skipped.len();
    (DeclaredGrantSet::canonical(module_id, grants), diagnostics)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredGrantRecord {
    pub module_id: String,
    pub declaration_digest: Option<String>,
    pub approved_declarations_digest: Option<String>,
    pub origin: Option<String>,
    pub grants: DeclaredGrantSet,
    pub skipped_count: usize,
    pub first_seen_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclaredGrantListing {
    pub rows: Vec<DeclaredGrantRecord>,
    pub incomplete: bool,
}

impl EncryptedStore {
    /// Persist a last-seen change and its audit evidence atomically. The caller must
    /// establish bind admission before invoking this method; stored rows confer no authority.
    #[allow(clippy::too_many_arguments)]
    pub fn record_declared_grants_seen(
        &self,
        module_id: &str,
        declaration_digest: Option<&str>,
        approved_declarations_digest: Option<&str>,
        origin: Option<&str>,
        grants: &DeclaredGrantSet,
        skipped_count: usize,
    ) -> Result<bool, StoreOpError> {
        if module_id.is_empty()
            || module_id.contains('|')
            || declaration_digest == Some("")
            || (declaration_digest.is_some()
                && !grants.grants.is_empty()
                && grants.module_id.as_deref() != Some(module_id))
        {
            return Err(StoreOpError::InvalidPrincipal);
        }
        let grants_json = if declaration_digest.is_some() {
            grants.grants_json()
        } else {
            "[]".into()
        };
        let skipped_count = if declaration_digest.is_some() {
            skipped_count
        } else {
            0
        };
        let skipped_count = i64::try_from(skipped_count)
            .map_err(|_| StoreOpError::Store("skipped count overflow".into()))?;
        Ok(self.fenced_write(|tx| {
            let previous: Option<(Option<String>, String)> = tx.query_row(
                "SELECT declaration_digest, grants_json FROM declared_grant_sets WHERE module_id = ?1",
                [module_id], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            if declaration_digest.is_none() {
                if previous.as_ref().is_none_or(|(digest, _)| digest.is_none()) {
                    return Ok(false);
                }
            } else if previous.as_ref().is_some_and(|(digest, json)| {
                digest.as_deref() == declaration_digest && json == &grants_json
            }) {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO declared_grant_sets \
                 (module_id, declaration_digest, approved_declarations_digest, origin, grants_json, skipped_count, first_seen_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(module_id) DO UPDATE SET \
                 declaration_digest = excluded.declaration_digest, approved_declarations_digest = excluded.approved_declarations_digest, \
                 origin = excluded.origin, grants_json = excluded.grants_json, skipped_count = excluded.skipped_count, first_seen_ms = excluded.first_seen_ms",
                rusqlite::params![module_id, declaration_digest, approved_declarations_digest, origin, grants_json, skipped_count, now_ms()],
            )?;
            append_audit_tx(tx, &self.audit_key, &AuditRecord {
                op: AuditOp::DeclarationSeen,
                credential_id: Some(format!("declaration|{}", declaration_digest.unwrap_or("none"))),
                payload_hash: Some(sha256_hex_of_bytes(grants_json.as_bytes())),
                actor: format!("reserved:{module_id}"), alarm: None,
            })?;
            Ok(true)
        })?)
    }

    pub fn list_declared_grant_sets(&self) -> Result<DeclaredGrantListing, StoreOpError> {
        self.store
            .with_conn(declared_sets_from_conn)
            .map_err(StoreOpError::from)
    }
}

fn declared_sets_from_conn(conn: &rusqlite::Connection) -> rusqlite::Result<DeclaredGrantListing> {
    if read_schema_version(conn)? < DECLARED_GRANTS_SCHEMA_VERSION {
        return Ok(DeclaredGrantListing::default());
    }
    let mut stmt = conn.prepare(
        "SELECT module_id, declaration_digest, approved_declarations_digest, origin, grants_json, skipped_count, first_seen_ms \
         FROM declared_grant_sets ORDER BY module_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    let mut listing = DeclaredGrantListing::default();
    for row in rows {
        let (
            module_id,
            declaration_digest,
            approved_declarations_digest,
            origin,
            json,
            skipped_count,
            first_seen_ms,
        ) = row?;
        let Ok(grants) = DeclaredGrantSet::from_grants_json(&module_id, &json) else {
            listing.incomplete = true;
            continue;
        };
        let Ok(skipped_count) = usize::try_from(skipped_count) else {
            listing.incomplete = true;
            continue;
        };
        listing.rows.push(DeclaredGrantRecord {
            module_id,
            declaration_digest,
            approved_declarations_digest,
            origin,
            grants,
            skipped_count,
            first_seen_ms,
        });
    }
    Ok(listing)
}

/// Read the declared-grant inventory through a read-only connection, without the store's
/// writer lease. An older store has no declared inventory to display.
pub fn declared_grant_sets_read_only(
    path: &std::path::Path,
) -> Result<DeclaredGrantListing, String> {
    if !path.exists() {
        return Ok(DeclaredGrantListing::default());
    }
    // `mode=ro` through a URI, as `list_read_grants_read_only_with_schema` opens it, so
    // closing this connection can never checkpoint or truncate the daemon's WAL.
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|error| error.to_string())?;
    declared_sets_from_conn(&conn).map_err(|error| error.to_string())
}
