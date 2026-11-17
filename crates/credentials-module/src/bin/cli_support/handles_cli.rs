//! Credential handle minting and revocation commands.

use super::{
    commit_admin, format_ts_ms, optional, required, store_path, AdminOpBody, CliError, GlobalArgs,
    ADMIN_OP_SCHEMA_V1,
};

pub(super) fn cmd_mint_handle(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::MintHandle {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let handle = result["handle"]
        .as_str()
        .ok_or_else(|| CliError::Io("mint did not return a handle".into()))?;
    // Keep stdout machine-readable for consumers capturing the bearer token.
    println!("{handle}");
    eprintln!("revoke with: ck auth revoke-handle --handle <handle>");
    eprintln!("(minted handle for {id}; store it now — it is not recoverable)");
    warn_about_predecessors(global, &id, handle);
    Ok(())
}

/// Ask the operator about a predecessor, because this is the only moment anyone can.
///
/// A fresh handle either REPLACES one the operator already holds or joins a set held by
/// different consumers, and the vault cannot tell which: there is no holder column. What
/// it can do is say that other live doors exist and name them by hash, while the person
/// who knows whether one of them is theirs is still standing here holding both values.
///
/// After this returns, nothing holds the predecessor. A consumer config keyed on
/// credential id loses it on the next save; the audit chain records that a handle was
/// minted and (only since 2026-09-19) which one. That asymmetry is how this vault reached
/// 16 live handles on four credentials with 12 unattributable to any holder -- resolved
/// by canvassing three seats, which is an hour of work this advisory would have saved.
///
/// FAILS OPEN AND SILENT. The mint already succeeded and its handle is on stdout; an
/// advisory that turned a completed mint into a visible error would teach operators that
/// minting is unreliable. A hash is not spendable, so naming them costs nothing.
fn warn_about_predecessors(global: &GlobalArgs, id: &str, handle: &str) {
    let hash = credentials_core::handle_hash(handle);
    let Ok(others) =
        credentials_core::store::other_live_handles_read_only(&store_path(global), id, &hash)
    else {
        return;
    };
    for line in render_predecessor_note(id, &others) {
        eprintln!("{line}");
    }
}

/// The predecessor note's text, or nothing when no other live handle exists.
///
/// THE OTHER HANDLES ARE LISTED AS BARE HASHES, NEVER AS COMMANDS. Most of them belong to
/// other consumers, and printing each as a ready-to-run `ck auth revoke-handle --hash ...`
/// line made them indistinguishable from the one revoke command the operator DOES want
/// (the `revoke with:` line for the handle just minted). A cleanup script that took the
/// first line matching the command came within a shell syntax error of revoking two
/// other consumers' handles. So the verb appears once, as prose, and no line here
/// contains `ck auth`.
fn render_predecessor_note(id: &str, others: &[(String, i64)]) -> Vec<String> {
    if others.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "note: {id} now has {} live handles. The vault cannot tell holders apart, so if\n\
         \x20     this one REPLACES a handle you already hold, revoke that one by its hash\n\
         \x20     (revoke-handle --hash <hash>). Other live handles, NOT this one:",
        others.len() + 1
    )];
    for (other, minted_at) in others {
        lines.push(format!("    {other}  minted {}", format_ts_ms(*minted_at)));
    }
    lines
}

pub(super) fn cmd_revoke_handle(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let usage =
        "revoke-handle requires exactly one of --handle <raw> or --hash <hex> (64 lowercase hex)";
    let (op, form) = match (optional(args, "--handle"), optional(args, "--hash")) {
        (Some(handle), None) => (
            AdminOpBody::RevokeHandle {
                v: ADMIN_OP_SCHEMA_V1,
                handle,
            },
            "--handle",
        ),
        (None, Some(handle_hash)) => {
            if handle_hash.len() != 64
                || !handle_hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(CliError::Usage(usage.into()));
            }
            (
                AdminOpBody::RevokeHandleByHash {
                    v: ADMIN_OP_SCHEMA_V1,
                    handle_hash,
                },
                "--hash",
            )
        }
        _ => return Err(CliError::Usage(usage.into())),
    };
    let result = commit_admin(global, op)?;
    // NAME WHAT WAS REVOKED, OR SAY NOTHING MATCHED. The old line said "revoked handle"
    // for a live handle, an already-revoked one, AND one that never existed -- so an
    // operator who pasted a truncated value was told a bearer credential was dead while
    // it kept serving. That is the one direction this tool must never be wrong in.
    //
    // Falls back to the old wording against a daemon too old to send the field, rather
    // than claiming nothing matched: absent and null mean different things here.
    //
    // And FAIL when nothing matched: a script that read success here went on to delete the
    // handle from its consumer's file while the handle kept serving.
    match result.get("credential_id") {
        Some(serde_json::Value::String(id)) => println!("revoked handle for {id} via {form}"),
        Some(serde_json::Value::Null) => {
            return Err(CliError::NothingRevoked(
                "no live handle matched that value; nothing changed.\n  \
                 check for a truncated paste — a handle is one unbroken ckh_ token. \
                 --hash takes the handle_hash column, not the sha256 of the raw token."
                    .into(),
            ))
        }
        _ => println!("revoked handle"),
    }
    Ok(())
}

pub(super) fn cmd_revoke_all_handles(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::RevokeAllHandles {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let n = result["handles_revoked"].as_u64().unwrap_or(0);
    println!("revoked {n} handle(s) for {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Only the handle just minted may appear as a runnable revoke command; the other
    /// holders' handles are listed as bare hashes so a script grepping for the command
    /// can never pick one of them.
    #[test]
    fn the_predecessor_note_names_other_handles_without_a_runnable_command() {
        let others = vec![
            ("a".repeat(64), 1_758_000_000_000_i64),
            ("b".repeat(64), 1_758_000_100_000_i64),
        ];
        let lines = super::render_predecessor_note("oauth:anthropic", &others);
        let text = lines.join("\n");
        assert!(text.contains(&"a".repeat(64)), "{text}");
        assert!(text.contains(&"b".repeat(64)), "{text}");
        assert!(
            !text.contains("ck auth"),
            "no line may be a runnable command: {text}"
        );
        assert!(super::render_predecessor_note("oauth:anthropic", &[]).is_empty());
    }
}
