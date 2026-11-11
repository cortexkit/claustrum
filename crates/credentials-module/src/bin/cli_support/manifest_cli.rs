//! Master-key-gated manifest administration and recoverable envelope publication.
use crate::{commit_admin, CliError, GlobalArgs};
use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2};
use credentials_core::store::GhManifestHandoffEnvelope;
use serde_json::Value;
use std::{io::Write as _, path::PathBuf};

fn value_flags(verb: &str) -> &'static [&'static str] {
    match verb {
        "import" => &["--envelope"],
        "sign" => &["--file", "--approver"],
        "export" => &["--version"],
        "retire-machine" => &["--member"],
        _ => &[],
    }
}

pub fn guard_args(args: &[String]) -> Result<(), CliError> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(CliError::Usage(help_text(None)));
    };
    if verb == "one-tap" {
        return match rest {
            [action] if matches!(action.as_str(), "on" | "off" | "status") => Ok(()),
            _ => Err(CliError::Usage(help_text(Some("one-tap")))),
        };
    }
    if !matches!(
        verb.as_str(),
        "import" | "sign" | "export" | "list" | "retire-machine"
    ) {
        return Err(CliError::Usage(help_text(None)));
    }
    let mut seen = std::collections::HashSet::new();
    for pair in rest.chunks(2) {
        let flag = &pair[0];
        if !value_flags(verb).contains(&flag.as_str()) || !seen.insert(flag.as_str()) {
            return Err(CliError::Usage(format!(
                "unexpected or repeated argument '{flag}'\n\n{}",
                help_text(Some(verb))
            )));
        }
        if pair.len() != 2 || pair[1].is_empty() || pair[1].starts_with("--") {
            return Err(CliError::Usage(format!("{flag} requires a value")));
        }
    }
    for flag in value_flags(verb) {
        if !seen.contains(flag) {
            return Err(CliError::Usage(format!(
                "missing {flag}\n\n{}",
                help_text(Some(verb))
            )));
        }
    }
    if verb == "export" {
        version(rest)?;
    }
    Ok(())
}

fn value(args: &[String], flag: &str) -> String {
    args.as_chunks::<2>()
        .0
        .iter()
        .find(|pair| pair[0] == flag)
        .unwrap()[1]
        .clone()
}

fn version(args: &[String]) -> Result<i64, CliError> {
    value(args, "--version")
        .parse::<i64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| CliError::Usage("--version must be a positive integer".into()))
}

pub fn cmd_manifest(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    guard_args(args)?;
    let (verb, rest) = args.split_first().unwrap();
    let v = ADMIN_OP_SCHEMA_V2;
    let op = match verb.as_str() {
        "import" => {
            let path = value(rest, "--envelope");
            let bytes = std::fs::read(&path).map_err(|e| CliError::Io(format!("{path}: {e}")))?;
            let envelope = serde_json::from_slice::<GhManifestHandoffEnvelope>(&bytes)
                .map_err(|e| CliError::Usage(format!("invalid manifest envelope: {e}")))?;
            AdminOpBody::ManifestImport { v, envelope }
        }
        "sign" => {
            let path = value(rest, "--file");
            let manifest_bytes =
                std::fs::read_to_string(&path).map_err(|e| CliError::Io(format!("{path}: {e}")))?;
            AdminOpBody::ManifestSign {
                v,
                manifest_bytes,
                approver: value(rest, "--approver"),
            }
        }
        "export" => AdminOpBody::ManifestExport {
            v,
            version: version(rest)?,
        },
        "list" => AdminOpBody::ManifestList { v },
        "retire-machine" => AdminOpBody::ManifestRetireMachine {
            v,
            member_id: value(rest, "--member"),
        },
        "one-tap" => match rest[0].as_str() {
            "status" => AdminOpBody::ManifestOneTapStatus { v },
            action => AdminOpBody::ManifestOneTapSet {
                v,
                enabled: action == "on",
            },
        },
        _ => unreachable!(),
    };
    // Nothing is published until the admin path confirms COMMIT. The database row
    // remains the authority if this process stops or cannot write the derived file.
    let result = commit_admin(global, op)?;
    let publication = match verb.as_str() {
        "sign" => Some((
            result["version"].as_i64().ok_or_else(|| {
                CliError::Io(
                    "manifest sign returned no stored version; use manifest list and export".into(),
                )
            })?,
            &result["envelope"],
        )),
        "export" => Some((version(rest)?, &result)),
        _ => None,
    };
    if let Some((version, envelope)) = publication {
        write_envelope(global, version, envelope).map_err(|error| CliError::Io(format!(
            "manifest version {version} is stored, but its envelope file could not be written: {error}; recover with `ck auth manifest export --version {version}`"
        )))?;
    }
    println!(
        "{}",
        serde_json::to_string(&result).expect("JSON admin result")
    );
    Ok(())
}

fn write_envelope(global: &GlobalArgs, version: i64, value: &Value) -> std::io::Result<()> {
    use ring::rand::SecureRandom as _;
    let envelope: GhManifestHandoffEnvelope = serde_json::from_value(value.clone())?;
    let mut bytes = serde_json::to_vec_pretty(&envelope)?;
    bytes.push(b'\n');
    let directory = global.data_dir.join("signed-envelopes");
    std::fs::create_dir_all(&directory)?;
    let destination = directory.join(format!("v{version}-envelope.json"));
    let mut nonce = [0; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| std::io::Error::other("temporary filename randomness unavailable"))?;
    let temporary: PathBuf =
        directory.join(format!(".v{version}-{}.tmp", crate::hex_lower(&nonce)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        cortexkit_lease::durable_replace(&temporary, &destination)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn help_text(verb: Option<&str>) -> String {
    let page = match verb {
        Some("import") => "ck auth manifest import --envelope <file>\n\n  --envelope <file>  signed hand-off envelope to verify and store\n\nNOTES\nImport checks the root key, signature, increasing version and exact bytes.",
        Some("sign") => "ck auth manifest sign --file <manifest> --approver <name>\n\n  --file <manifest>  reproducible manifest bytes to approve and sign\n  --approver <name>  approver recorded in the audit chain\n\nNOTES\nApproval, signing and retention commit together before the file is written.",
        Some("export") => "ck auth manifest export --version <N>\n\n  --version <N>  stored version whose envelope file is rewritten\n\nNOTES\nExport signs nothing and writes no database row.",
        Some("list") => "ck auth manifest list\n\nNOTES\nPrint JSON versions (source, SHA-256, signed time), then expected computers\nand activation rows, including retired computers with expected=false.",
        Some("retire-machine") => "ck auth manifest retire-machine --member <member-id>\n\n  --member <member-id>  computer to remove from the readiness population\n\nNOTES\nRetirement is final. It does not revoke the computer's delivery grant.",
        Some("one-tap") => "ck auth manifest one-tap on|off|status\n\nNOTES\nMissing settings are off; unreadable settings are treated as off. Only\nproposing is gated. Pending approvals and all other operations still work.\nA real change writes one audit row; repeating the setting writes none.",
        _ => "ck auth manifest <verb> [flags]\n\n  --envelope <file>  import: signed envelope to verify and retain\n  --file <manifest>  sign: reproducible manifest bytes\n  --approver <name>  sign: who approves those bytes\n  --version <N>      export: stored version to recover\n  --member <id>      retire-machine: computer to retire\n\nNOTES\nVerbs: import, sign, export, list, retire-machine, one-tap on|off|status.\nRun ck auth help manifest <verb> for that verb's page.\nOne-tap defaults off and gates only proposals, not pending approvals.",
    };
    format!("{page}\nAll commands use the master-key admin path, online or under the offline lease.\nSign and export write signed-envelopes/v<N>-envelope.json at mode 0600\nthrough a temporary file and rename. A file-write failure leaves the stored\nversion intact; recover it with ck auth manifest export --version <N>.")
}
