//! Operator controls for the independently opt-in phone channel and for agent secrets.
//!
//! The write verbs (`put`, `delete`, `revoke`, `phone-gate on|off`) all build one admin
//! op and hand it to `commit_admin`, so they run on the same path as every other operator
//! write: through the master-key admin MAC when the daemon is up, and under the
//! single-writer lease when it is not. The read verbs (`list`, `grants`, `phone-gate
//! status`) never call the daemon at all — they open the store file read-only, because an
//! operator asking what exists is usually asking while the vault is serving.
//!
//! MATERIAL HANDLING IS THE RULE THAT SHAPES THIS FILE. `put` reads the secret from a
//! mode-0600 file or from a prompt, never from a flag: an argv value is visible to every
//! process on the machine and lands in shell history, and this command's whole purpose is
//! to place a credential the operator does not want to leak. A refusal names the path and
//! the rule that failed, never a byte of what was read.
use crate::{commit_admin, optional, required, store_path, CliError, GlobalArgs};
use base64::Engine;
use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2};

const BEARER: &str = "authorization_bearer";
const NO_TABLES: &str = "no agent-secret tables yet";
const NO_SECRETS: &str = "no agent secrets stored";
const NO_SECRET_GRANTS: &str = "no agent-secret grants";

pub fn cmd_secret(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(CliError::Usage(help_text().to_string()));
    };
    match verb.as_str() {
        "phone-gate" => phone_gate(global, rest),
        "put" => put(global, rest),
        "list" => list(global, rest),
        "grants" => grants(global, rest),
        "delete" => delete(global, rest),
        "revoke" => revoke(global, rest),
        other => Err(CliError::Usage(format!(
            "unknown secret verb '{other}'\n\n{}",
            help_text()
        ))),
    }
}

/// The flags `secret put` takes, and nothing else. One table serves the guard, the
/// dispatcher's awareness of a flag's value, and the CLI's page-versus-parser check.
fn put_flags() -> &'static [&'static str] {
    &[
        "--kind",
        "--name",
        "--host",
        "--path-prefix",
        "--location",
        "--origin",
        "--material-file",
    ]
}

/// The flags `secret revoke` takes: the grant id.
const REVOKE_FLAGS: &[&str] = &["--grant-id"];

/// The flags `secret delete` takes: the name, as an alternative to the positional operand.
const DELETE_FLAGS: &[&str] = &["--name"];

/// Refuse an unknown or misplaced flag on one `ck auth secret <verb>` invocation.
///
/// The dispatcher's shared argument check sees only the verb name `secret`, and a flag's
/// value may be any word, so it cannot judge a secret invocation. This does, against the
/// table for the verb actually named, and it names the flags that verb takes — a typo such
/// as `secret put --locaton header:X` would otherwise store the key under the bearer
/// default with nothing on screen to say why.
pub fn guard_args(args: &[String]) -> Result<(), CliError> {
    let Some((verb, rest)) = args.split_first() else {
        return Ok(());
    };
    let (value_flags, positional) = match verb.as_str() {
        // `phone-gate` takes one positional operand and no flags.
        "phone-gate" => (&[][..], true),
        // `delete` names the secret positionally or with `--name`, as `secret_name` reads it.
        "delete" => (DELETE_FLAGS, true),
        // `put` names the secret first or with `--name`, then its flags.
        "put" => (put_flags(), true),
        "revoke" => (REVOKE_FLAGS, false),
        "list" | "grants" => (&[][..], false),
        // An unknown verb is diagnosed by `cmd_secret`, which names it.
        _ => return Ok(()),
    };
    // A positional operand, when the verb takes one, is the first token unless that token is
    // a flag: `put --name ops-key ...` names the secret with the flag instead.
    let mut i = usize::from(positional && rest.first().is_some_and(|arg| !arg.starts_with("--")));
    while let Some(arg) = args_or(rest, i) {
        if value_flags.contains(&arg.as_str()) {
            match args_or(rest, i + 1) {
                Some(value) if !value.starts_with("--") => {
                    i += 2;
                    continue;
                }
                _ => {
                    return Err(CliError::Usage(format!(
                        "{arg} needs a value for 'secret {verb}'\n\n{}",
                        help_text()
                    )));
                }
            }
        }
        // A token in a flag position is named only when it looks like a flag, which the
        // operator typed on purpose. Anything else may be a secret that reached the command
        // line by mistake, and repeating it would put it in the terminal, the scrollback
        // and any captured transcript: the same leak as reading it from argv.
        let description = if arg.starts_with("--") {
            format!("unexpected argument '{arg}'")
        } else {
            format!("unexpected argument at position {}", i + 1)
        };
        return Err(CliError::Usage(format!(
            "{description} for 'secret {verb}'; it takes {}\n\n{}",
            if value_flags.is_empty() {
                "no flags".to_string()
            } else {
                format!("only {}", value_flags.join(", "))
            },
            help_text()
        )));
    }
    let _ = rest;
    Ok(())
}

fn args_or(args: &[String], index: usize) -> Option<&String> {
    args.get(index)
}

/// The page `ck auth help secret` prints. Every listed verb and flag is one this module
/// accepts, because a printed shape the parser refuses is worse than no listing.
pub fn help_text() -> &'static str {
    "ck auth secret <verb> [flags]\n\
     \n\
      \x20 --kind <api-key|site-login>  which kind of secret to store\n\
      \x20 --name <name>                secret name; put also takes it first\n\
      \x20 --host <host>                api key: the approved host\n\
      \x20 --path-prefix <path>         api key: an optional path prefix\n\
      \x20 --location <where>           api key: where to put it; the default\n\
      \x20                             is authorization_bearer\n\
      \x20 --origin <https://host>      site login: the approved origin\n\
      \x20 --material-file <path>       read the material from a 0600 file\n\
      \x20 --grant-id <id>              remove one grant by id (revoke)\n\
      \n\
      VERBS\n\
      put creates a secret. list shows secrets, scopes and grants. grants shows one\n\
      row per live grant. delete removes a secret with its grants and pending\n\
      requests. revoke removes one grant. phone-gate turns the phone channel on or\n\
      off, or prints its state.\n\
      \n\
      NOTES\n\
      The material is never read from a flag. Without --material-file, a site login\n\
      is prompted for username, password and an optional otpauth URI, and an api key\n\
      for its key bytes; nothing is echoed. The file holds the same plaintext a\n\
      phone deposit carries: the key bytes, or username, password and otpauth on\n\
      separate lines. A file that is not mode 0600 is refused, naming the path and\n\
      the rule.\n\
      \n\
      Secrets are addressed by name only (1-64 bytes of A-Z a-z 0-9 . _ -) and\n\
      never by a credential id. Names are create-only: a second put of a name is\n\
      refused, and reusing a name means deleting it first. Writes use the admin MAC\n\
      online or the offline lease; list, grants and phone-gate status read the store\n\
      without either. Keep the phone setting off until callosum derives the forwarded\n\
      harness from the authenticated phone peer on every call."
}

fn phone_gate(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let Some(action) = args.first() else {
        return Err(CliError::Usage(
            "secret phone-gate takes on, off or status".into(),
        ));
    };
    if action == "status" {
        let db = store_path(global);
        if !db.exists() {
            println!("member mapping off\nphone setting off");
            return Ok(());
        }
        let [member, phone] = credentials_core::store::secret_phone_gate_status_read_only(&db)
            .map_err(|_| CliError::Usage("cannot read phone gate settings".into()))?;
        println!("member mapping {member}\nphone setting {phone}");
        return Ok(());
    }
    let enabled = match action.as_str() {
        "on" => true,
        "off" => false,
        _ => {
            return Err(CliError::Usage(
                "secret phone-gate takes on, off or status".into(),
            ))
        }
    };
    commit_admin(
        global,
        AdminOpBody::SecretPhoneGateSet {
            v: ADMIN_OP_SCHEMA_V2,
            enabled,
        },
    )?;
    println!("phone setting {}", if enabled { "on" } else { "off" });
    Ok(())
}

/// What the operator supplied, already split into the kind's plaintext fields.
enum Material {
    ApiKey(Vec<u8>),
    SiteLogin {
        username: String,
        password: String,
        otpauth: Option<String>,
    },
}

fn put(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let kind = required(args, "--kind")?;
    let name = secret_name(args)?;
    let optional_plain = |flag: &str| -> Result<Option<String>, CliError> {
        match optional(args, flag) {
            None => Ok(None),
            Some(value) if value.starts_with("--") => Err(CliError::Usage(format!(
                "{flag} needs a value\n\n{}",
                help_text()
            ))),
            Some(value) => Ok(Some(value)),
        }
    };
    let host = optional_plain("--host")?;
    let path_prefix = optional_plain("--path-prefix")?;
    let origin = optional_plain("--origin")?;
    let location = optional_plain("--location")?.unwrap_or_else(|| BEARER.to_owned());

    // Refuse a scope the kind cannot carry before reading anything at all, so a bad
    // invocation never touches the material or the terminal.
    match kind.as_str() {
        "api-key" => {
            if origin.is_some() {
                return Err(CliError::Usage(
                    "an api key names a host, never an origin".into(),
                ));
            }
            if host.is_none() {
                return Err(CliError::Usage("an api key requires the host flag".into()));
            }
        }
        "site-login" => {
            if host.is_some() || path_prefix.is_some() || optional(args, "--location").is_some() {
                return Err(CliError::Usage(
                    "a site login takes only the origin flag, never the host, prefix or location"
                        .into(),
                ));
            }
            if origin.is_none() {
                return Err(CliError::Usage(
                    "a site login requires the origin flag".into(),
                ));
            }
        }
        other => {
            return Err(CliError::Usage(format!(
                "the kind must be api-key or site-login, not '{other}'"
            )))
        }
    }

    let material = match optional(args, "--material-file") {
        Some(path) => read_material_file(&path, &kind)?,
        None => prompt_material(&kind)?,
    };
    let (op_kind, host, origin) = match kind.as_str() {
        "api-key" => ("agent_api_key", host, None),
        _ => ("site_login", None, origin),
    };
    let reply = commit_admin(
        global,
        AdminOpBody::SecretPut {
            v: ADMIN_OP_SCHEMA_V2,
            kind: op_kind.to_owned(),
            name: name.clone(),
            host,
            path_prefix,
            location: (op_kind == "agent_api_key").then_some(location),
            origin,
            material_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(frame_plaintext(&material).expose()),
        },
    )?;
    // Only the incarnation is reported: it is a random id, and comparing it with
    // `secret list` tells the operator which record this put created.
    println!(
        "stored secret {name} (incarnation {})",
        reply["incarnation"].as_str().unwrap_or("unknown")
    );
    Ok(())
}

/// Read the material file, refusing a mode other than 0600 or a body that is not the kind's
/// plaintext. Every message names the path and the rule and never the content.
fn read_material_file(path: &str, kind: &str) -> Result<Material, CliError> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| CliError::Usage(format!("cannot read material file {path}")))?;
    if !metadata.is_file() {
        return Err(CliError::Usage(format!(
            "material file {path} is not a regular file"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(CliError::Usage(format!(
                "material file {path} is mode {:04o}; it must be 0600 so no other user can read it",
                metadata.mode() & 0o777
            )));
        }
    }
    let text = std::fs::read_to_string(path)
        .map_err(|_| CliError::Usage(format!("material file {path} is not readable UTF-8 text")))?;
    // A trailing newline is the editor's, not the operator's; anything else is content.
    let text = text.strip_suffix('\n').unwrap_or(&text);
    parse_material(text, kind).map_err(|rule| {
        CliError::Usage(format!(
            "material file {path} does not hold a {kind} payload: {rule}"
        ))
    })
}

/// The file layout: one field per line for a site login (username, password, and an
/// optional `otpauth://` line), or the whole trimmed body as the api key.
fn parse_material(text: &str, kind: &str) -> Result<Material, &'static str> {
    match kind {
        "api-key" => {
            if text.is_empty() {
                return Err("the key is empty");
            }
            Ok(Material::ApiKey(text.as_bytes().to_vec()))
        }
        _ => {
            let mut lines = text.split('\n');
            let username = lines.next().unwrap_or_default();
            let password = lines.next().unwrap_or_default();
            if username.is_empty() || password.is_empty() {
                return Err("expected a username line, then a password line");
            }
            let otpauth = lines.next().filter(|line| !line.is_empty());
            if lines.next().is_some() {
                return Err("expected at most three lines: username, password, otpauth://");
            }
            Ok(Material::SiteLogin {
                username: username.to_owned(),
                password: password.to_owned(),
                otpauth: otpauth.map(str::to_owned),
            })
        }
    }
}

fn prompt_material(kind: &str) -> Result<Material, CliError> {
    let prompt = |label: &str| -> Result<String, CliError> {
        eprint!("{label}: ");
        use std::io::{BufRead, Write};
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|_| CliError::Usage("cannot read from stdin".into()))?;
        Ok(line.trim_end_matches('\n').to_owned())
    };
    match kind {
        "api-key" => {
            let key = prompt("API key")?;
            if key.is_empty() {
                return Err(CliError::Usage("the key is empty".into()));
            }
            Ok(Material::ApiKey(key.into_bytes()))
        }
        _ => {
            let username = prompt("Username")?;
            let password = prompt("Password")?;
            let otpauth = prompt("otpauth:// URI (optional)")?;
            if username.is_empty() || password.is_empty() {
                return Err(CliError::Usage(
                    "a site login needs a username and a password".into(),
                ));
            }
            Ok(Material::SiteLogin {
                username,
                password,
                otpauth: (!otpauth.is_empty()).then_some(otpauth),
            })
        }
    }
}

/// Encode the same u64-length-prefixed plaintext a phone deposit carries, so one validator
/// (`decode_deposit_plaintext`) checks both doors.
fn frame_plaintext(material: &Material) -> credentials_core::secret::Secret<Vec<u8>> {
    use credentials_core::agent_secret::push_field;
    let mut out = Vec::new();
    push_field(
        &mut out,
        credentials_core::agent_secret::DEPOSIT_PLAINTEXT_TAG,
    );
    match material {
        Material::ApiKey(key) => push_field(&mut out, key),
        Material::SiteLogin {
            username,
            password,
            otpauth,
        } => {
            for field in [
                username.as_bytes(),
                password.as_bytes(),
                otpauth.as_deref().unwrap_or("").as_bytes(),
            ] {
                push_field(&mut out, field);
            }
        }
    }
    credentials_core::secret::Secret::new(out)
}

/// The secret name: positional for `put` and `delete`, or `--name`. Both at once is a
/// mistake worth naming, because the two could differ.
fn secret_name(args: &[String]) -> Result<String, CliError> {
    let positional = args.first().filter(|arg| !arg.starts_with("--")).cloned();
    match (positional, optional(args, "--name")) {
        (Some(name), None) => Ok(name),
        (None, Some(name)) => Ok(name),
        (Some(_), Some(_)) => Err(CliError::Usage(
            "name the secret once, positionally or with --name".into(),
        )),
        (None, None) => Err(CliError::Usage(format!(
            "the secret name is required\n\n{}",
            help_text()
        ))),
    }
}

fn list(global: &GlobalArgs, _args: &[String]) -> Result<(), CliError> {
    let Some(listing) = read_listing(global)? else {
        println!("{NO_TABLES}");
        return Ok(());
    };
    let stamp = |at_ms: i64| match chrono::DateTime::from_timestamp_millis(at_ms) {
        Some(at) => at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => at_ms.to_string(),
    };
    // Say so when nothing is stored: silent output would look the same as a verb that
    // failed to read the store, and the pre-migration case already prints its own line.
    if listing.secrets.is_empty() && listing.phones.is_empty() {
        println!("{NO_SECRETS}");
    }
    for secret in &listing.secrets {
        let scope = match (&secret.host, &secret.origin) {
            (Some(host), _) => format!(
                "host={host} prefix={} location={}",
                secret.path_prefix.as_deref().unwrap_or(""),
                secret.location.as_deref().unwrap_or("")
            ),
            (_, Some(origin)) => format!("origin={origin}"),
            _ => String::new(),
        };
        println!("{} {} {} {scope}", secret.name, secret.kind, secret.state);
        for grant in &secret.grants {
            println!(
                "  grant {} {}/{}:{} {} {}",
                grant.grant_id,
                grant.scope_owner,
                grant.scope_kind,
                grant.scope_ref,
                grant.coverage,
                match grant.expires_at_ms {
                    Some(expiry) => format!("{} until {}", grant.duration, stamp(expiry)),
                    None => grant.duration.clone(),
                }
            );
        }
        for grant in &secret.flow_grants {
            // A flow grant lists the installed version that owns it in place of an asking
            // scope, and prints its approved methods where an agent grant prints coverage.
            // Its duration is always `version`, so it needs no column of its own.
            println!(
                "  grant {} {} version{}",
                grant.grant_id,
                flow_holder(grant),
                match &grant.methods {
                    Some(methods) => format!(" methods={}", methods.join(",")),
                    None => String::new(),
                }
            );
        }
    }
    // Phone keys are reported by their LAST OBSERVED pairing, never by a check made now:
    // this verb does not check the pairing at all, so "superseded" means a lookup saw
    // something else, not that the pairing is known to be dead.
    for phone in &listing.phones {
        let state = match (phone.unobserved, phone.current_since_ms) {
            (true, _) => "unobserved".to_owned(),
            (false, Some(at)) => format!("current as of {}", stamp(at)),
            (false, None) => "superseded".to_owned(),
        };
        println!(
            "phone {} pairing {} {state}",
            phone.fingerprint, phone.pairing_id
        );
    }
    Ok(())
}

/// How the operator names the holder of a flow grant: one installed flow version.
///
/// Written as `flow:<flow_id>@<version>/<install_id>`, the form the install card and
/// basal's own logs use, so an operator can match a grant against the install that runs it.
fn flow_holder(grant: &credentials_core::store::OperatorFlowGrantRow) -> String {
    format!(
        "flow:{}@{}/{}",
        grant.flow_id, grant.flow_version, grant.flow_install_id
    )
}

fn grants(global: &GlobalArgs, _args: &[String]) -> Result<(), CliError> {
    let Some(listing) = read_listing(global)? else {
        println!("{NO_TABLES}");
        return Ok(());
    };
    if listing
        .secrets
        .iter()
        .all(|secret| secret.grants.is_empty())
    {
        println!("{NO_SECRET_GRANTS}");
    }
    for secret in &listing.secrets {
        for grant in &secret.grants {
            println!(
                "{} secret|{} {}/{}:{} {} {} expiry={} last_use={}",
                grant.grant_id,
                secret.name,
                grant.scope_owner,
                grant.scope_kind,
                grant.scope_ref,
                grant.coverage,
                grant.duration,
                grant
                    .expires_at_ms
                    .map(|at| at.to_string())
                    .unwrap_or_else(|| "none".into()),
                grant
                    .last_use_ms
                    .map(|at| at.to_string())
                    .unwrap_or_else(|| "never".into())
            );
        }
        for grant in &secret.flow_grants {
            // A flow grant never expires, so its expiry is the same "none" a permanent
            // agent grant prints, and its methods take the coverage column's place.
            println!(
                "{} secret|{} {} version{} expiry=none last_use={}",
                grant.grant_id,
                secret.name,
                flow_holder(grant),
                match &grant.methods {
                    Some(methods) => format!(" methods={}", methods.join(",")),
                    None => String::new(),
                },
                grant
                    .last_use_ms
                    .map(|at| at.to_string())
                    .unwrap_or_else(|| "never".into())
            );
        }
    }
    Ok(())
}

fn read_listing(
    global: &GlobalArgs,
) -> Result<Option<credentials_core::store::OperatorSecretListing>, CliError> {
    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    credentials_core::store::list_agent_secrets_read_only(&db).map_err(CliError::Store)
}

fn delete(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let name = secret_name(args)?;
    commit_admin(
        global,
        AdminOpBody::SecretDelete {
            v: ADMIN_OP_SCHEMA_V2,
            name: name.clone(),
        },
    )?;
    println!("deleted secret {name}");
    Ok(())
}

fn revoke(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let grant_id = required(args, "--grant-id")?;
    let reply = commit_admin(
        global,
        AdminOpBody::SecretRevokeGrant {
            v: ADMIN_OP_SCHEMA_V2,
            grant_id: grant_id.clone(),
        },
    )?;
    match reply["outcome"].as_str() {
        Some("revoked") => println!("revoked grant {grant_id}"),
        // A grant that is gone is the operator's answer, not a failure: an expired grant
        // and an unknown id mean the same thing to whoever asked.
        _ => println!("no live grant {grant_id}"),
    }
    Ok(())
}
