//! Enrollment commands, pending-request checks, and enrollment rendering.

use super::{
    commit_admin, has_flag, optional, parse_grants, render_grant_reach,
    request_admin_status_with_schema, required, store_path, AdminOpBody, CliError, GlobalArgs,
    ADMIN_OP_SCHEMA_V2,
};
#[cfg(test)]
use super::{enrollment_admin_error, reject_unknown_args, StoreOpError};

/// `ck auth enroll <list|approve|label|deny|revoke|reissue>` — the operator half of consumer
/// enrollment.
///
/// WITHOUT THIS THE CEREMONY IS UNREACHABLE. A consumer can propose, and the store can
/// approve, deny, revoke and reissue — but nothing could CALL those, so a pending
/// request sat in the queue forever and the vault admitted nobody. The consumer-facing
/// routes shipped first because they are what a plugin builds against; this is the half
/// that makes them mean something.
///
/// Every mutating subcommand is master-key gated through `commit_admin`: the module
/// checks the admin plane's MAC over the exact operation bytes.
/// `list` is not: it reads the pending queue and the live roster, both plaintext, so it
/// works against a running daemon without the key and without taking the write lease.
pub(super) fn cmd_enroll(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let sub = args
        .first()
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| {
            CliError::Usage(
                "enroll requires a subcommand: list|approve|label|deny|revoke|reissue".into(),
            )
        })?
        .clone();
    let rest = &args[1..];
    if sub != "approve" && has_flag(rest, "--keep-grants") {
        return Err(CliError::Usage(
            "--keep-grants is only valid for enroll approve".into(),
        ));
    }
    if sub != "approve" && (has_flag(rest, "--grant-requested") || has_flag(rest, "--no-grants")) {
        return Err(CliError::Usage(
            "--grant-requested and --no-grants are only valid for enroll approve".into(),
        ));
    }
    if sub != "approve" && sub != "label" && optional(rest, "--display-name").is_some() {
        return Err(CliError::Usage(
            "--display-name is only valid for enroll approve or label".into(),
        ));
    }
    if sub != "label" && has_flag(rest, "--clear") {
        return Err(CliError::Usage(
            "--clear is only valid for enroll label".into(),
        ));
    }
    match sub.as_str() {
        "list" => cmd_enroll_list(global),
        "label" => {
            let name = required(rest, "--name")?;
            let display_name = optional(rest, "--display-name");
            if display_name.is_some() == has_flag(rest, "--clear") {
                return Err(CliError::Usage(
                    "enroll label requires exactly one of --display-name or --clear".into(),
                ));
            }
            let display_name = display_name
                .map(|label| {
                    credentials_core::display_name::validate_display_name(&label)
                        .map_err(|error| CliError::Usage(format!("invalid_params: {error}")))
                })
                .transpose()?;
            require_live_enrollment(global, &name)?;
            let reply = commit_admin(
                global,
                AdminOpBody::EnrollLabel {
                    v: ADMIN_OP_SCHEMA_V2,
                    name: name.clone(),
                    display_name: display_name.clone(),
                },
            )?;
            if reply.get("changed").and_then(serde_json::Value::as_bool) == Some(false) {
                println!("enrolled:{}: nothing changed", name.escape_debug());
            }
            match display_name {
                Some(label) => println!(
                    "enrolled:{} display name: \"{}\"",
                    name.escape_debug(),
                    label.escape_debug()
                ),
                None => println!("enrolled:{} display name cleared", name.escape_debug()),
            }
            Ok(())
        }
        "approve" => {
            let grant_requested = has_flag(rest, "--grant-requested");
            let no_grants = has_flag(rest, "--no-grants");
            if grant_requested && no_grants {
                return Err(CliError::Usage(
                    "--grant-requested and --no-grants are mutually exclusive".into(),
                ));
            }
            let request_id = required(rest, "--request-id")?;
            let display_name = optional(rest, "--display-name")
                .map(|name| {
                    credentials_core::display_name::validate_display_name(&name)
                        .map_err(|error| CliError::Usage(format!("invalid_params: {error}")))
                })
                .transpose()?;
            let proposed_name = pending_proposed_name(global, &request_id)?;
            // The name defaults to what was proposed, and `--name` is how an operator
            // corrects it. A name a stranger chose is a claim, not a fact.
            let final_name = optional(rest, "--name").unwrap_or(proposed_name);
            let keep_grants = has_flag(rest, "--keep-grants");
            let rows = credentials_core::store::list_enrollments_read_only(&store_path(global))
                .map_err(|error| CliError::Usage(format!("read enrollments: {error}")))?;
            let requested = rows
                .iter()
                .find(|row| row.key == request_id && row.state == "pending")
                .and_then(|row| row.requested_grants.as_deref());
            let grant_requested = if let Some(grants) = requested {
                print_requested_grants(global, &request_id, grants)?;
                if grant_requested || no_grants {
                    grant_requested
                } else {
                    use std::io::IsTerminal;
                    if !std::io::stdin().is_terminal() {
                        return Err(CliError::Usage(
                            "this request carries grants; pass --grant-requested or --no-grants"
                                .into(),
                        ));
                    }
                    eprint!("Approve and grant these? [y/N] ");
                    std::io::Write::flush(&mut std::io::stderr())
                        .map_err(|error| CliError::Usage(error.to_string()))?;
                    let mut answer = String::new();
                    std::io::stdin()
                        .read_line(&mut answer)
                        .map_err(|error| CliError::Usage(error.to_string()))?;
                    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                        return Err(CliError::Usage(
                            "approval cancelled; nothing changed".into(),
                        ));
                    }
                    true
                }
            } else {
                false
            };
            if !live_enrollment_named(&rows, &final_name) {
                let grants =
                    credentials_core::store::list_read_grants_read_only(&store_path(global))
                        .map_err(|error| CliError::Usage(format!("read grants: {error}")))?;
                let retained: Vec<_> = grants
                    .iter()
                    .filter(|grant| {
                        grant.principal_kind == "enrolled" && grant.principal_id == final_name
                    })
                    .collect();
                for grant in &retained {
                    eprintln!(
                        "existing grant enrolled:{final_name} {} {}:{}",
                        grant.operation.as_str(),
                        grant.selector_kind.as_str(),
                        grant.selector
                    );
                }
                if !retained.is_empty() && !keep_grants {
                    return Err(CliError::Usage(format!(
                        "enrolled:{final_name} has existing grants; revoke them with \
                         ck auth revoke-grant, or approve with --keep-grants to explicitly inherit them"
                    )));
                }
            }
            let reply = commit_admin(
                global,
                AdminOpBody::EnrollApprove {
                    v: ADMIN_OP_SCHEMA_V2,
                    request_id: request_id.clone(),
                    final_name: final_name.clone(),
                    keep_grants,
                    display_name,
                    grant_requested,
                },
            )?;
            println!("approved {request_id} as enrolled:{final_name}");
            if let Some(name) = reply
                .get("display_name")
                .and_then(serde_json::Value::as_str)
            {
                println!("display name: \"{}\"", name.escape_debug());
            }
            eprintln!(
                "(no token was minted here: the consumer's own poll mints it, \
                 authenticated by the request secret it holds)"
            );
            Ok(())
        }
        "deny" => {
            let request_id = required(rest, "--request-id")?;
            commit_admin(
                global,
                AdminOpBody::EnrollDeny {
                    v: ADMIN_OP_SCHEMA_V2,
                    request_id: request_id.clone(),
                },
            )?;
            println!("denied {request_id}");
            Ok(())
        }
        "revoke" => {
            let name = required(rest, "--name")?;
            require_live_enrollment(global, &name)?;
            let reply = commit_admin(
                global,
                AdminOpBody::EnrollRevoke {
                    v: ADMIN_OP_SCHEMA_V2,
                    name: name.clone(),
                },
            )?;
            println!("revoked enrolled:{name}");
            let grants = parse_grants(&serde_json::json!({
                "read_grants": reply.get("removed_grants")
            }))?;
            for grant in grants {
                println!(
                    "removed grant {}:{} {} {}:{}",
                    grant.principal_kind,
                    grant.principal_id,
                    grant.operation,
                    grant.selector_kind,
                    grant.credential_prefix
                );
            }
            Ok(())
        }
        "reissue" => {
            let name = required(rest, "--name")?;
            require_live_enrollment(global, &name)?;
            let reply = commit_admin(
                global,
                AdminOpBody::EnrollReissue {
                    v: ADMIN_OP_SCHEMA_V2,
                    name: name.clone(),
                },
            )?;
            let token = reply
                .get("token")
                .and_then(|value| value.as_str())
                .ok_or_else(|| CliError::Usage("reissue returned no token".into()))?;
            // Stdout carries the token ALONE so it can be piped into a 0600 file
            // without a shell dance; everything else goes to stderr.
            println!("{token}");
            eprintln!(
                "reissued enrolled:{name} at generation {}. The previous token stopped \
                 working the moment this one was minted.",
                reply
                    .get("token_generation")
                    .and_then(|value| value.as_u64())
                    .unwrap_or_default()
            );
            Ok(())
        }
        other => Err(CliError::Usage(format!(
            "unknown enroll subcommand {other}: expected list|approve|label|deny|revoke|reissue"
        ))),
    }
}

/// Render pending requests and live enrollments, lease-free.
fn cmd_enroll_list(global: &GlobalArgs) -> Result<(), CliError> {
    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run `ck auth bootstrap` first)",
            db.display()
        )));
    }
    let (rows, schema) = credentials_core::store::list_enrollments_read_only_with_schema(&db)
        .map_err(|error| CliError::Usage(format!("read enrollments: {error}")))?;
    for line in render_enroll_list(&rows) {
        println!("{line}");
    }
    for row in &rows {
        if let Some(grants) = &row.requested_grants {
            print_requested_grants(global, &row.key, grants)?;
        }
    }
    print_enroll_store_behind_note(schema);
    Ok(())
}

fn print_requested_grants(
    global: &GlobalArgs,
    request_id: &str,
    grants: &[credentials_core::enrollment::RequestedGrant],
) -> Result<(), CliError> {
    let (status, _) = request_admin_status_with_schema(global)?;
    println!("requested grants for {request_id}:");
    for grant in grants {
        let (kind, selector) = grant.selector.parts();
        println!(
            "  {} {}:{}",
            grant.operation.as_str(),
            kind.as_str(),
            selector.escape_debug()
        );
        let report = render_grant_reach(&status, kind, selector, grant.operation);
        for line in report.stdout {
            println!("{line}");
        }
        for line in report.stderr {
            eprintln!("{line}");
        }
    }
    Ok(())
}

/// Say, once and on stderr, that this listing cannot show proposers because the store
/// has not reached the migration that records them.
///
/// The same placement window as [`print_store_behind_note`]: a newer CLI reads the store
/// before the daemon that migrates it restarts. Without the note every pending row
/// showing `-` reads as "nobody knows who proposed this", when the truth is that the
/// column does not exist yet. Stdout is untouched so a script parsing the table keeps
/// working.
fn print_enroll_store_behind_note(store_schema: u32) {
    let proposer_schema = credentials_core::store::ENROLLMENT_PROPOSER_SCHEMA_VERSION;
    if store_schema >= proposer_schema {
        return;
    }
    let binary_schema = credentials_core::store::newest_migration_version();
    eprintln!(
        "note: store schema {store_schema} is behind this binary's {binary_schema}; \
         proposers of pending requests appear after the daemon restarts (migration {proposer_schema})"
    );
}

/// How the enrollment listing names a request's proposer: `kind:id`, the bare kind when
/// the kind carries no id (`direct`), and `-` when no proposer is recorded (live
/// enrollments, and requests proposed before the store recorded proposers).
fn enroll_proposer_label(row: &credentials_core::store::EnrollmentRow) -> String {
    match (&row.proposer_kind, &row.proposer_id) {
        (Some(kind), Some(id)) => format!("{kind}:{id}"),
        (Some(kind), None) => kind.clone(),
        (None, _) => "-".to_string(),
    }
}

/// Render the enrollment ledger, flagging pending requests whose name is already taken.
///
/// THE VAULT ACCEPTS THOSE REQUESTS ON PURPOSE. A proposal is anonymous and inert until
/// the operator approves it, so refusing one adds no safety, and a refusal on that route
/// would tell any caller which names are enrolled. It would also block a real case: a
/// second install of a plugin that proposes the same fixed name, which `approve --name`
/// admits under a different one.
///
/// What the operator needs instead is to see the collision BEFORE approving, because a
/// plain `approve` on that request is refused (a name with a live enrollment cannot be
/// admitted twice). So the row names the collision and both ways out.
///
/// A pure function over the rows so the flag can be tested without a vault.
fn render_enroll_list(rows: &[credentials_core::store::EnrollmentRow]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["no pending requests and no live enrollments".to_string()];
    }
    // Every non-pending row the ledger returns is an unrevoked enrollment, which is the
    // set approval checks against.
    let enrolled: std::collections::BTreeSet<&str> = rows
        .iter()
        .filter(|row| row.state != "pending")
        .map(|row| row.name.as_str())
        .collect();
    let width = rows
        .iter()
        .map(|row| row.key.chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    let proposers: Vec<String> = rows.iter().map(enroll_proposer_label).collect();
    let proposer_width = proposers
        .iter()
        .map(|label| label.chars().count())
        .max()
        .unwrap_or(0)
        .max("PROPOSER".len());
    let mut lines = vec![format!(
        "{:<width$}  {:<13}  {:<proposer_width$}  NAME",
        "KEY",
        "STATE",
        "PROPOSER",
        width = width,
        proposer_width = proposer_width
    )];
    let mut collisions = Vec::new();
    for (row, proposer) in rows.iter().zip(&proposers) {
        let suffix = if row.token_generation > 0 {
            format!("  (generation {})", row.token_generation)
        } else if row.state == "pending" && enrolled.contains(row.name.as_str()) {
            collisions.push(row.key.as_str());
            "  (name already enrolled)".to_string()
        } else {
            String::new()
        };
        lines.push(format!(
            "{:<width$}  {:<13}  {:<proposer_width$}  {}{suffix}{}",
            row.key,
            row.state,
            proposer,
            row.name,
            row.effective_display_name()
                .map(|name| format!("  display name: \"{}\"", name.escape_debug()))
                .unwrap_or_default(),
            width = width,
            proposer_width = proposer_width
        ));
    }
    for key in collisions {
        lines.push(String::new());
        lines.push(format!(
            "{key} asks for a name that is already enrolled; a plain approve is refused."
        ));
        lines.push(format!(
            "  admit it under another name:  ck auth enroll approve --request-id {key} --name <new-name>"
        ));
        lines.push(format!(
            "  or refuse it:                 ck auth enroll deny --request-id {key}"
        ));
    }
    lines
}

/// Require a pending request on this vault and read its proposed name for `approve`.
///
/// Reading it here rather than defaulting inside the store keeps the DECISION visible:
/// the operator sees the name in the success line and can override it with `--name`.
/// A store-side default would admit whatever a stranger proposed with nothing printed.
fn pending_proposed_name(global: &GlobalArgs, request_id: &str) -> Result<String, CliError> {
    let db = store_path(global);
    let rows = credentials_core::store::list_enrollments_read_only(&db)
        .map_err(|error| CliError::Usage(format!("read enrollments: {error}")))?;
    rows.into_iter()
        .find(|row| row.key == request_id && row.state == "pending")
        .map(|row| row.name)
        .ok_or_else(|| CliError::Usage(missing_pending_request(request_id)))
}

pub(super) fn missing_pending_request(request_id: &str) -> String {
    let ttl_minutes = credentials_core::enrollment::ENROLLMENT_PENDING_TTL_MS / 60_000;
    format!(
        "no pending request with id {request_id} on this vault. A request lapses \
         {ttl_minutes} minutes after it is proposed. It is held by the vault on the \
         computer where the consumer ran its setup; approve on that computer. \
         `ck auth enroll list` shows the pending ones."
    )
}

/// Refuse `label`, `revoke` or `reissue` for a name with no live enrollment.
///
/// Without this the op reaches the store, which finds no row and reports it as a storage
/// failure, so the operator reads "the running module refused the op: store error" for
/// what is really a typo or an already-revoked name. Checked here, the same way `approve`
/// reads the pending request first. A name revoked between this read and the op still
/// fails closed in the store.
fn require_live_enrollment(global: &GlobalArgs, name: &str) -> Result<(), CliError> {
    let rows = credentials_core::store::list_enrollments_read_only(&store_path(global))
        .map_err(|error| CliError::Usage(format!("read enrollments: {error}")))?;
    if live_enrollment_named(&rows, name) {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "no live enrollment named {name} (list them with `ck auth enroll list`)"
        )))
    }
}

/// Whether the ledger holds an unrevoked enrollment under `name`. The read-only ledger
/// returns pending requests and unrevoked enrollments only, so any non-pending row is live.
pub(super) fn live_enrollment_named(
    rows: &[credentials_core::store::EnrollmentRow],
    name: &str,
) -> bool {
    rows.iter()
        .any(|row| row.state != "pending" && row.name == name)
}

#[cfg(test)]
mod tests {
    #[test]
    fn enrollment_regression_raced_not_found_is_a_usage_error() {
        use super::{enrollment_admin_error, CliError, StoreOpError};

        for error in [
            CliError::Store(StoreOpError::NotFound),
            CliError::RouteRefused("credential not found".into()),
        ] {
            let mapped =
                enrollment_admin_error(error, Some("no pending request on this vault".into()));
            assert!(
                matches!(&mapped, CliError::Usage(message) if message == "no pending request on this vault")
            );
            assert_eq!(mapped.exit_code(), std::process::ExitCode::FAILURE);
        }
        let unrelated =
            enrollment_admin_error(CliError::RouteRefused("credential not found".into()), None);
        assert!(matches!(unrelated, CliError::RouteRefused(_)));
        let other_refusal = enrollment_admin_error(
            CliError::RouteRefused("store error: storage backend unavailable".into()),
            Some("no pending request on this vault".into()),
        );
        assert!(matches!(other_refusal, CliError::RouteRefused(_)));
    }

    fn enrollment_row(
        key: &str,
        name: &str,
        state: &str,
        generation: i64,
    ) -> credentials_core::store::EnrollmentRow {
        credentials_core::store::EnrollmentRow {
            key: key.to_string(),
            name: name.to_string(),
            display_name: None,
            requested_grants: None,
            state: state.to_string(),
            created_at_ms: 0,
            token_generation: generation,
            proposer_kind: None,
            proposer_id: None,
        }
    }

    #[test]
    fn enrollment_display_name_listing_escapes_terminal_text() {
        let mut row = enrollment_row("request", "consumer", "pending", 0);
        row.display_name = Some("Pi\n\u{1b}[31m\"\\".into());
        let lines = super::render_enroll_list(&[row]);
        assert_eq!(lines.len(), 2);
        assert!(
            lines[1].contains("Pi\\n\\u{1b}[31m\\\"\\\\"),
            "{}",
            lines[1]
        );
        assert!(!lines[1].contains('\n'));
        assert!(!lines[1].contains('\u{1b}'));
    }

    /// A pending request under a name is not a live enrollment, so revoke and reissue
    /// must refuse it as well as a name that is absent altogether.
    #[test]
    fn only_an_unrevoked_enrollment_counts_as_live() {
        let rows = vec![
            enrollment_row("enr-1", "anthropic-auth-opencode", "live", 1),
            enrollment_row("req-1", "cookie-list-probe", "pending", 0),
        ];
        assert!(super::live_enrollment_named(
            &rows,
            "anthropic-auth-opencode"
        ));
        assert!(!super::live_enrollment_named(&rows, "cookie-list-probe"));
        assert!(!super::live_enrollment_named(&rows, "no-such-consumer"));
    }

    /// The proposer column names who asked, and `-` where nothing is recorded, with the
    /// column wide enough for the longest label so NAME still lines up.
    #[test]
    fn enroll_list_shows_the_proposer_and_a_dash_when_none_is_recorded() {
        let mut reserved = enrollment_row("req-module", "module-consumer", "pending", 0);
        reserved.proposer_kind = Some("reserved".to_string());
        reserved.proposer_id = Some("insula".to_string());
        let mut direct = enrollment_row("req-host", "host-consumer", "pending", 0);
        direct.proposer_kind = Some("direct".to_string());
        let unknown = enrollment_row("req-older", "older-consumer", "pending", 0);
        let lines = super::render_enroll_list(&[reserved, direct, unknown]);
        let text = lines.join("\n");
        assert_eq!(
            lines[0], "KEY         STATE          PROPOSER         NAME",
            "{text}"
        );
        assert_eq!(
            lines[1], "req-module  pending        reserved:insula  module-consumer",
            "{text}"
        );
        assert_eq!(
            lines[2], "req-host    pending        direct           host-consumer",
            "{text}"
        );
        assert_eq!(
            lines[3], "req-older   pending        -                older-consumer",
            "{text}"
        );
    }

    /// A pending request for an enrolled name is shown with both remedies; one for a free
    /// name is not. Both arms matter: a flag on every pending row would be noise an
    /// operator learns to skip, and a missing flag sends them into a refused approve.
    #[test]
    fn enroll_list_flags_only_pending_requests_for_an_enrolled_name() {
        let rows = [
            enrollment_row("req-taken", "anthropic-auth-opencode", "pending", 0),
            enrollment_row("req-free", "fresh-consumer", "pending", 0),
            enrollment_row(
                "anthropic-auth-opencode",
                "anthropic-auth-opencode",
                "live",
                1,
            ),
        ];
        let lines = super::render_enroll_list(&rows);
        let text = lines.join("\n");

        let taken = lines
            .iter()
            .find(|line| line.starts_with("req-taken "))
            .unwrap();
        assert!(taken.ends_with("(name already enrolled)"), "{text}");
        let free = lines
            .iter()
            .find(|line| line.starts_with("req-free "))
            .unwrap();
        assert!(!free.contains("already enrolled"), "{text}");

        assert!(
            text.contains("approve --request-id req-taken --name"),
            "{text}"
        );
        assert!(text.contains("deny --request-id req-taken"), "{text}");
        assert!(!text.contains("req-free --name"), "{text}");
    }

    /// Every command the listing prints must be one the CLI accepts.
    ///
    /// Checking the printed strings against expected strings cannot catch a wrong
    /// command: both come from the same author, so a wrong argument shape passes. That
    /// happened: this listing first printed `enroll deny <id>` with a positional id,
    /// and its test asserted exactly that, while the parser only takes `--request-id`.
    /// Found only by running the printed command against the live vault. So each line
    /// goes through the dispatcher's own argument check.
    #[test]
    fn every_command_enroll_list_prints_passes_the_argument_check() {
        let rows = [
            enrollment_row("req-taken", "anthropic-auth-opencode", "pending", 0),
            enrollment_row(
                "anthropic-auth-opencode",
                "anthropic-auth-opencode",
                "live",
                1,
            ),
        ];
        let commands: Vec<Vec<String>> = super::render_enroll_list(&rows)
            .iter()
            .filter_map(|line| line.split_once("ck auth ").map(|(_, command)| command))
            .map(|command| {
                command
                    .split_whitespace()
                    .map(|word| word.replace("<new-name>", "second-install"))
                    .collect()
            })
            .collect();
        assert_eq!(commands.len(), 2, "expected the approve and deny lines");
        for words in commands {
            let (verb, args) = words.split_first().unwrap();
            super::reject_unknown_args(verb, args).unwrap_or_else(|error| {
                panic!(
                    "printed command `ck auth {}` is refused: {error:?}",
                    words.join(" ")
                )
            });
        }
    }
}
