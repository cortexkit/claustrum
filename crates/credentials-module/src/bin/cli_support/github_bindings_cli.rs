use credentials_core::{
    admin_ops::{AdminOpBody, GitHubBindingChange, GitHubBindingPreview, ADMIN_OP_SCHEMA_V2},
    agent_policy::AgentPolicyEnvelope,
};
use dialoguer::Confirm;
use serde_json::Value;

use super::manifest_cli::{publish_envelope, value, write_envelope};
use crate::{commit_admin, CliError, GlobalArgs};

fn parse(args: &[String]) -> Result<GitHubBindingChange, CliError> {
    let [group, action, rest @ ..] = args else {
        return Err(CliError::Usage(help_text(None)));
    };
    let flags: &[&str] = match (group.as_str(), action.as_str()) {
        ("bindings", "remove") => &["--repo"],
        ("bindings", "move") => &["--repo", "--to"],
        ("bindings", "app") => &["--agent", "--app"],
        _ => return Err(CliError::Usage(help_text(None))),
    };
    let (pairs, extra) = rest.as_chunks::<2>();
    if pairs.len() != flags.len()
        || !extra.is_empty()
        || !flags
            .iter()
            .all(|flag| pairs.iter().any(|pair| pair[0] == *flag))
        || pairs
            .iter()
            .any(|pair| pair[1].is_empty() || pair[1].starts_with('-'))
    {
        return Err(CliError::Usage(help_text(Some(action))));
    }
    Ok(match action.as_str() {
        "remove" => GitHubBindingChange::Remove {
            repo: value(rest, "--repo"),
        },
        "move" => GitHubBindingChange::Move {
            repo: value(rest, "--repo"),
            to: value(rest, "--to"),
        },
        "app" => GitHubBindingChange::App {
            agent: value(rest, "--agent"),
            slug: value(rest, "--app"),
        },
        _ => unreachable!(),
    })
}

pub fn guard_args(args: &[String]) -> Result<(), CliError> {
    parse(args).map(drop)
}

pub fn cmd_github(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let change = parse(args)?;
    let v = ADMIN_OP_SCHEMA_V2;
    let preview_json = commit_admin(
        global,
        AdminOpBody::GitHubBindingPreview {
            v,
            change: change.clone(),
        },
    )?;
    let preview: GitHubBindingPreview = serde_json::from_value(preview_json)
        .map_err(|error| CliError::Io(format!("invalid GitHub binding preview: {error}")))?;
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&preview).expect("JSON binding preview")
    );
    if !Confirm::new()
        .with_prompt("Sign and store both documents?")
        .default(false)
        .interact()
        .map_err(|error| CliError::Io(format!("could not confirm binding change: {error}")))?
    {
        eprintln!("No GitHub binding change was made.");
        return Ok(());
    }
    let result = commit_admin(
        global,
        AdminOpBody::GitHubBindingCommit {
            v,
            change,
            base: preview.base,
        },
    )?;
    publish(global, &result)?;
    println!(
        "{}",
        serde_json::to_string(&result).expect("JSON signed binding result")
    );
    Ok(())
}

fn publish(global: &GlobalArgs, result: &Value) -> Result<(), CliError> {
    let manifest = result["manifest"]["version"].as_i64();
    let policy = result["policy"]["version"].as_i64();
    let recovery = || {
        match (manifest, policy) {
        (Some(m), Some(p)) => format!("recover with ck auth manifest export --version {m} and ck auth policy export --version {p}"),
        _ => "recover via ck auth manifest list and ck auth policy list, then export".into(),
    }
    };
    let (Some(m), Some(p)) = (manifest, policy) else {
        return Err(CliError::Io(format!(
            "signed pair reply is missing a version; {}",
            recovery()
        )));
    };
    // Both files are derived from the committed rows. Try both even if one write fails.
    let manifest_write = write_envelope(global, m, &result["manifest"]["envelope"]);
    let policy_write =
        serde_json::from_value::<AgentPolicyEnvelope>(result["policy"]["envelope"].clone())
            .map_err(std::io::Error::from)
            .and_then(|envelope| {
                publish_envelope(&global.data_dir.join("signed-policies"), p, &envelope)
            });
    manifest_write.and(policy_write).map_err(|error| {
        CliError::Io(format!(
            "the signed pair is stored, but an envelope file could not be written: {error}; {}",
            recovery()
        ))
    })
}

pub fn help_text(action: Option<&str>) -> String {
    let page = match action {
        Some("remove") => "ck auth github bindings remove --repo <owner/name>\n\n  --repo <owner/name>  repository to unbind",
        Some("move") => "ck auth github bindings move --repo <owner/name> --to <agent>\n\n  --repo <owner/name>  repository to move\n  --to <agent>        destination with an existing GitHub binding",
        Some("app") => "ck auth github bindings app --agent <agent> --app <slug>\n\n  --agent <agent>     agent with an existing GitHub binding\n  --app <slug>        slug of the replacement GitHub App record",
        _ => "ck auth github bindings remove --repo <owner/name>\nck auth github bindings move --repo <owner/name> --to <agent>\nck auth github bindings app --agent <agent> --app <slug>\n\n  --repo <owner/name>  repository to remove or move\n  --to <agent>        destination with an existing GitHub binding (move)\n  --agent <agent>     agent with an existing GitHub binding (app)\n  --app <slug>        slug of the replacement GitHub App record (app)",
    };
    format!("{page}\n\nNOTES\nReview the complete old and new bindings, then confirm (default No).\nSigns and stores both documents together, online or under the offline lease.\nIf the signed pair changes after preview, start again. A move destination\nneeds its first repository through one-tap approval before receiving a move.\nRecover envelope files with ck auth manifest export and ck auth policy export.")
}
