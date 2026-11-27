//! Generate and publish agent policies through the master-key admin surface.
use crate::{commit_admin, CliError, GlobalArgs};
use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2, ADMIN_OP_SCHEMA_V3};
use credentials_core::agent_policy::AgentPolicyEnvelope;
use credentials_core::gh_manifest::ManifestValue;
use std::path::Path;

use super::manifest_cli::{positive_version, publish_envelope, value, write_private_file};

pub(crate) fn value_flags(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "sign" => &["--file", "--manifest-version", "--approver"],
        "list" => &[],
        "export" => &["--version"],
        "derive" => &[
            "--manifest-version",
            "--identities",
            "--out",
            "--rules-release",
        ],
        _ => return None,
    })
}

pub fn guard_args(args: &[String]) -> Result<(), CliError> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(CliError::Usage(help_text(None)));
    };
    let flags = value_flags(verb).ok_or_else(|| CliError::Usage(help_text(None)))?;
    let mut seen = std::collections::HashSet::new();
    for pair in rest.chunks(2) {
        let flag = &pair[0];
        if !flags.contains(&flag.as_str()) || !seen.insert(flag.as_str()) {
            return Err(CliError::Usage(format!(
                "unexpected or repeated argument '{flag}'\n\n{}",
                help_text(Some(verb))
            )));
        }
        if pair.len() != 2 || pair[1].is_empty() || pair[1].starts_with("--") {
            return Err(CliError::Usage(format!("{flag} requires a value")));
        }
    }
    for flag in flags {
        if *flag != "--rules-release" && !seen.contains(flag) {
            return Err(CliError::Usage(format!(
                "missing {flag}\n\n{}",
                help_text(Some(verb))
            )));
        }
    }
    if flags.contains(&"--manifest-version") {
        positive_version(rest, "--manifest-version")?;
    }
    if flags.contains(&"--version") {
        positive_version(rest, "--version")?;
    }
    Ok(())
}

pub fn cmd_policy(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    guard_args(args)?;
    let (verb, rest) = args.split_first().unwrap();
    let v = ADMIN_OP_SCHEMA_V2;
    let op = match verb.as_str() {
        "sign" => AdminOpBody::AgentPolicySign {
            v,
            policy_bytes: read_text(&value(rest, "--file"))?,
            manifest_version: positive_version(rest, "--manifest-version")?,
            approver: value(rest, "--approver"),
        },
        "list" => AdminOpBody::AgentPolicyList { v },
        "export" => AdminOpBody::AgentPolicyExport {
            v,
            version: positive_version(rest, "--version")?,
        },
        "derive" => {
            let text = read_text(&value(rest, "--identities"))?;
            let invalid = || {
                CliError::Usage(
                    "identities must be a JSON object mapping agents to GitHub App credential IDs"
                        .into(),
                )
            };
            let ManifestValue::Object(entries) =
                serde_json::from_str(&text).map_err(|_| invalid())?
            else {
                return Err(invalid());
            };
            let identities = entries
                .into_iter()
                .map(|(agent, id)| match id {
                    ManifestValue::String(id) => Ok((agent, id)),
                    _ => Err(invalid()),
                })
                .collect::<Result<_, _>>()?;
            let rules_release =
                rest.as_chunks::<2>().0.iter().find_map(|[flag, release]| {
                    (flag == "--rules-release").then(|| release.clone())
                });
            AdminOpBody::AgentPolicyDerive {
                v: if rules_release.is_some() {
                    ADMIN_OP_SCHEMA_V3
                } else {
                    v
                },
                manifest_version: positive_version(rest, "--manifest-version")?,
                identities,
                rules_release,
            }
        }
        _ => unreachable!(),
    };
    let result = commit_admin(global, op)?;
    if verb == "derive" {
        let text = result
            .as_str()
            .ok_or_else(|| CliError::Io("policy derive returned no policy text".into()))?;
        let path = value(rest, "--out");
        // Give a filename without a directory an explicit parent for sync after rename.
        let destination = Path::new(&path);
        let destination = if destination.components().count() == 1 {
            Path::new(".").join(destination)
        } else {
            destination.to_path_buf()
        };
        return write_private_file(&destination, text.as_bytes())
            .map_err(|error| CliError::Io(format!("{path}: {error}")));
    }
    let publication = match verb.as_str() {
        "sign" => Some((
            result["version"].as_i64().ok_or_else(|| {
                CliError::Io(
                    "policy sign returned no stored version; use policy list and export".into(),
                )
            })?,
            &result["envelope"],
        )),
        "export" => Some((positive_version(rest, "--version")?, &result)),
        _ => None,
    };
    if let Some((version, envelope)) = publication {
        let publish = || {
            let envelope: AgentPolicyEnvelope = serde_json::from_value(envelope.clone())?;
            publish_envelope(&global.data_dir.join("signed-policies"), version, &envelope)
        };
        publish().map_err(|error| CliError::Io(format!(
            "policy version {version} is stored, but its envelope file could not be written: {error}; recover with `ck auth policy export --version {version}`"
        )))?;
    }
    println!(
        "{}",
        serde_json::to_string(&result).expect("JSON admin result")
    );
    Ok(())
}

fn read_text(path: &str) -> Result<String, CliError> {
    std::fs::read_to_string(path).map_err(|error| CliError::Io(format!("{path}: {error}")))
}

pub fn help_text(verb: Option<&str>) -> String {
    let page = match verb {
        Some("sign") => "ck auth policy sign --file <policy.json> --manifest-version <M>\n  --approver <name>\n\n  --file <policy.json>    exact canonical policy bytes to approve and sign\n  --manifest-version <M>  newest stored manifest (must be unpaired)\n  --approver <name>       approver recorded in the audit chain\n\nNOTES\nApproval, signing and retention commit before the envelope file is written.",
        Some("list") => "ck auth policy list\n\nNOTES\nPrint JSON policies in ascending order, with the head and active versions.\nThe active policy is paired with the ready manifest.",
        Some("export") => "ck auth policy export --version <P>\n\n  --version <P>  stored policy version whose envelope file is rewritten\n\nNOTES\nExport signs nothing and works for inactive versions.",
        Some("derive") => "ck auth policy derive --manifest-version <M> --identities <file>\n  --out <policy.json> [--rules-release <release>]\n\n  --manifest-version <M>     newest stored manifest (must be unpaired)\n  --identities <file>        JSON map of agent names to github_app:<slug> IDs\n  --out <policy.json>        write the unsigned canonical policy on success\n  --rules-release <release>  use all GitHub rules from an embedded release\n\nNOTES\nWithout this flag, derive keeps the head's rules or uses the default.\nDerive writes no vault or audit row.",
        _ => "ck auth policy <verb> [flags]\n\n  --file <policy.json>    sign: exact canonical policy bytes\n  --manifest-version <M>  sign or derive: newest unpaired manifest\n  --approver <name>       sign: who approves those bytes\n  --version <P>           export: stored policy version to recover\n  --identities <file>     derive: JSON map of agent names to App IDs\n  --out <policy.json>     derive: output file\n  --rules-release <release>  derive: select an embedded GitHub rules release\n\nNOTES\nVerbs: sign, list, export, derive.\nRun ck auth help policy <verb> for that verb's page.",
    };
    format!("{page}\nAll commands use the master-key admin path, online or under the offline lease.\nSign and export write signed-policies/v<P>-envelope.json at mode 0600\nthrough a temporary file and rename. Recover a lost envelope with export.")
}
