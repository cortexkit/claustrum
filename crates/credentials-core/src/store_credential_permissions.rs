use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The category an operator puts on a stored secret that a module needs in order to run
/// at all, such as Broca's session-storage key. Grants on such a record are left out of
/// the apps' permission list, like grants on vault-held keys: one tap there would stop
/// the module, and that's not something to offer next to ordinary access.
pub const MODULE_RUNTIME_CATEGORY: &str = "module-runtime";

fn visible_grants(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<ReadGrant>> {
    let runtime: std::collections::BTreeSet<String> = conn
        .prepare("SELECT credential_id FROM credential_categories WHERE category=?1")?
        .query_map([MODULE_RUNTIME_CATEGORY], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(
        read_grants_from_conn(conn, None, None, read_schema_version(conn)?)?
            .into_iter()
            .filter(|grant| {
                matches!(grant.principal_kind.as_str(), "reserved" | "enrolled")
                    && !(grant.selector_kind == SelectorKind::Exact
                        && (grant.selector.starts_with("signing:")
                            || grant.selector.starts_with("kem:")
                            || runtime.contains(&grant.selector)))
            })
            .collect(),
    )
}

fn grant_id(grant: &ReadGrant) -> String {
    credential_permission_id([
        &grant.principal_kind,
        &grant.principal_id,
        grant.selector_kind.as_str(),
        &grant.selector,
        grant.operation.as_str(),
    ])
}

pub(super) fn permission_rows(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<Value>> {
    visible_grants(conn)?
        .into_iter()
        .map(|grant| {
            let mut holder = if grant.principal_kind == "reserved" {
                json!({"kind":"module", "module_id":grant.principal_id})
            } else {
                json!({"kind":"enrolled", "name":grant.principal_id})
            };
            if grant.principal_kind == "enrolled" {
                let label: Option<String> = conn
                    .query_row(
                        "SELECT display_name FROM enrolled_consumers WHERE name=?1 AND revoked_at_ms IS NULL",
                        [&grant.principal_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .flatten();
                if let Some(label) = label {
                    holder["label"] = json!(label);
                }
            }
            let reach = if grant.selector_kind == SelectorKind::Category {
                conn.query_row(
                    "SELECT COUNT(*) FROM credential_categories cc JOIN credentials c \
                     ON c.credential_id=cc.credential_id WHERE cc.category=?1",
                    [&grant.selector],
                    |row| row.get::<_, usize>(0),
                )?
            } else {
                0
            };
            Ok(json!({
                "id":grant_id(&grant),
                "holder":holder,
                "module":"claustrum",
                "subject_label":credential_subject_label(grant.selector_kind.as_str(), &grant.selector),
                "scope":grant.operation.as_str(),
                "scope_label":credential_scope_label(grant.selector_kind.as_str(), &grant.selector, grant.operation.as_str(), reach),
                "granted_at_ms":grant.created_at_ms,
            }))
        })
        .collect()
}

pub(super) fn revoke(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    id: &str,
    actor: &str,
) -> rusqlite::Result<Value> {
    let Some(grant) = visible_grants(tx)?
        .into_iter()
        .find(|grant| grant_id(grant) == id)
    else {
        return Ok(json!({"outcome":"not_found"}));
    };
    // Resolve the opaque id and remove the grant within the same transaction. The CLI
    // and provider share the deletion, audit record and grant-generation update.
    let changed = revoke_read_grant_audited_tx(
        tx,
        key,
        &grant.principal_kind,
        &grant.principal_id,
        grant.selector_kind,
        &grant.selector,
        grant.operation,
        AuditCtx {
            actor,
            op: AuditOp::GrantRevoke,
            alarm: None,
        },
    )?;
    Ok(json!({"outcome":if changed > 0 {"revoked"} else {"not_found"}}))
}

fn credential_permission_id(columns: [&str; 5]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"claustrum-credential-permission/v1\0");
    for column in columns {
        hash.update((column.len() as u64).to_be_bytes());
        hash.update(column.as_bytes());
    }
    format!("cg_{:x}", hash.finalize())
}

fn credential_subject_label(selector_kind: &str, selector: &str) -> String {
    match selector_kind {
        "category" => match selector {
            "llm-provider" => "Model provider logins and keys".into(),
            "web-search" => "Web search keys".into(),
            "media-provider" => "Speech and media keys".into(),
            "browser-session" => "Browser sign-ins".into(),
            "github-app-native" => "GitHub App keys".into(),
            "anthropic-native" => "Claude logins".into(),
            "openai-native" => "ChatGPT logins".into(),
            "antigravity-native" => "Antigravity logins".into(),
            other => format!("Credentials in the {other} group"),
        },
        "audience" => format!("CortexKit account tokens for {selector}"),
        _ => selector.into(),
    }
}

fn credential_scope_label(
    selector_kind: &str,
    selector: &str,
    operation: &str,
    reach: usize,
) -> String {
    if selector_kind == "audience" {
        return format!("can get CortexKit account tokens for {selector}");
    }
    if selector_kind == "category" {
        let credentials = if reach == 1 {
            "1 credential".to_owned()
        } else {
            format!("{reach} credentials")
        };
        return match operation {
            "read" => format!("can read the secrets of {credentials} in this group"),
            "list" => format!(
                "can see the accounts and plans of {credentials} in this group, but not their secrets"
            ),
            "deposit" => format!(
                "can store browser sign-ins in this group, which currently contains {credentials}"
            ),
            "sign" => format!("can sign with {credentials} in this group"),
            "open" => format!("can decrypt messages with {credentials} in this group"),
            "seal" => format!("can encrypt messages with {credentials} in this group"),
            _ => format!("can get account tokens with {credentials} in this group"),
        };
    }
    match operation {
        "read" => "can read the secret of this credential",
        "list" => "can see this account and its plan, but not its secret",
        "deposit" => "can store browser sign-ins for this credential",
        "sign" => "can sign with this credential",
        "open" => "can decrypt messages with this credential",
        "seal" => "can encrypt messages with this credential",
        _ => "can get account tokens with this credential",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_permission_ids_are_framed_and_stable() {
        assert_eq!(
            credential_permission_id(["reserved", "broca", "category", "llm-provider", "read"]),
            "cg_0b27e0d58a8329b15f72cc8765399faba1656d3b263a93cb2f567b3c3a2d9955"
        );
        assert_ne!(
            credential_permission_id(["ab", "c", "exact", "key", "read"]),
            credential_permission_id(["a", "bc", "exact", "key", "read"])
        );
        assert_ne!(
            credential_permission_id(["reserved", "broca", "category", "llm-provider", "read"]),
            credential_permission_id(["reserved", "broca", "category", "llm-provider", "list"])
        );
    }

    #[test]
    fn credential_permission_labels_cover_groups_and_operations() {
        for (category, expected) in [
            ("llm-provider", "Model provider logins and keys"),
            ("web-search", "Web search keys"),
            ("media-provider", "Speech and media keys"),
            ("browser-session", "Browser sign-ins"),
            ("github-app-native", "GitHub App keys"),
            ("anthropic-native", "Claude logins"),
            ("openai-native", "ChatGPT logins"),
            ("antigravity-native", "Antigravity logins"),
            ("custom", "Credentials in the custom group"),
        ] {
            assert_eq!(credential_subject_label("category", category), expected);
        }
        assert_eq!(credential_subject_label("exact", "key-1"), "key-1");
        assert_eq!(
            credential_subject_label("audience", "cortexkit-runners"),
            "CortexKit account tokens for cortexkit-runners"
        );
        for operation in [
            "read",
            "list",
            "sign",
            "open",
            "seal",
            "deposit",
            "account_token",
        ] {
            let empty = credential_scope_label("category", "custom", operation, 0);
            let populated = credential_scope_label("category", "custom", operation, 37);
            assert!(empty.contains("0 credentials"), "{empty}");
            assert!(populated.contains("37 credentials"), "{populated}");
            assert!(credential_scope_label("exact", "key-1", operation, 1).starts_with("can "));
        }
    }
}
