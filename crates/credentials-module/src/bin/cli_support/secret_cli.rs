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

/// The page `ck auth help secret` prints. Every listed verb and flag is one this module
/// accepts, because a printed shape the parser refuses is worse than no listing.
pub fn help_text() -> &'static str {
    "ck auth secret <verb> [flags]\n\
     \n\
     \x20 put       create an agent secret (create-only)\n\
     \x20 list      secrets, their scopes and their live grants\n\
     \x20 grants    one row per live grant\n\
     \x20 delete    remove a secret, its grants and its pending requests\n\
     \x20 revoke    remove one grant by id\n\
     \x20 phone-gate on|off|status   the phone channel gate\n\
     \n\
     PUT\n\
     \x20 ck auth secret put --kind api-key|site-login --name <name> [scope flags]\n\
     \x20 \x20 \x20 \x20 \x20 \x20 \x20 \x20 \x20 \x20 [--material-file <path> | prompt]\n\
     \x20 --kind api-key     --host <host> [--path-prefix </path>] [--location <where>]\n\
     \x20 --kind site-login   --origin <https://host>\n\
     \x20 --material-file <path>  read the material from a mode-0600 file\n\
     \n\
     The material is never read from a flag. Without --material-file, a site login is\n\
     prompted for its username and password and an api key for its key bytes; neither\n\
     is echoed. --location defaults to authorization_bearer and names where the agent\n\
     puts the key: authorization_bearer, header:<name>, query:<name> or\n\
     json_pointer:<pointer>.\n\
     \n\
     NOTES\n\
     Secrets are addressed by name only (1-64 bytes of A-Z a-z 0-9 . _ -) and never by a\n\
     credential id. Names are create-only: a second put of a name is refused, and reusing\n\
     a name means deleting it first. Writes use the admin MAC online or the offline lease;\n\
     list, grants and phone-gate status read the store without a daemon or a key.\n\
     Keep the phone setting off until callosum derives the forwarded harness from the\n\
     authenticated phone peer on every call."
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

/// What the operator handed us on stdin, already split into the kind's plaintext fields.
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
                    "--origin belongs to --kind site-login; an api key names --host".into(),
                ));
            }
            if host.is_none() {
                return Err(CliError::Usage(
                    "--host is required for --kind api-key".into(),
                ));
            }
        }
        "site-login" => {
            if host.is_some() || path_prefix.is_some() || optional(args, "--location").is_some() {
                return Err(CliError::Usage(
                    "--kind site-login takes --origin only; --host, --path-prefix and --location belong to an api key".into(),
                ));
            }
            if origin.is_none() {
                return Err(CliError::Usage(
                    "--origin is required for --kind site-login".into(),
                ));
            }
        }
        other => {
            return Err(CliError::Usage(format!(
                "--kind must be api-key or site-login, not '{other}'"
            )))
        }
    }

    let material = match optional(args, "--material-file") {
        Some(path) => read_material_file(&path, &kind)?,
        None => prompt_material(&kind)?,
    };
    let framed = frame_plaintext(&material);
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
                .encode(framed.expose()),
        },
    )?;
    // Only the incarnation is reported: it is a random id, and an operator comparing it
    // with `secret list` can confirm which record this put created.
    println!(
        "stored secret {name} (incarnation {})",
        reply["incarnation"].as_str().unwrap_or("unknown")
    );
    Ok(())
}

/// Read the material file, refusing everything about it that the spec makes a rule:
/// a non-0600 mode, an empty file, an unreadable path. Every message names the path and
/// the rule and never the content.
fn read_material_file(path: &str, kind: &str) -> Result<Material, CliError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path)
        .map_err(|_| CliError::Usage(format!("cannot read material file {path}")))?;
    if !metadata.is_file() {
        return Err(CliError::Usage(format!(
            "material file {path} is not a regular file"
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(CliError::Usage(format!(
            "material file {path} is mode {:04o}; it must be 0600 so no other user can read it",
            metadata.mode() & 0o777
        )));
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

/// Encode the same u64-length-prefixed plaintext a phone deposit carries, so one
/// validator (`decode_deposit_plaintext`) checks both doors.
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

/// `put` and `delete` name the secret positionally; `--name` is accepted too, because
/// an operator scanning `ck auth help secret` for a flag is not making a mistake.
fn secret_name(args: &[String]) -> Result<String, CliError> {
    let positional = args.first().filter(|arg| !arg.starts_with("--")).cloned();
    match (positional, optional(args, "--name")) {
        (Some(name), None) => Ok(name),
        (None, Some(name)) => Ok(name),
        (Some(_), Some(_)) => Err(CliError::Usage(
            "name the secret once, positionally or with --name".into(),
        )),
        (None, None) => Err(CliError::Usage(
            "the secret name is required\n\nThe name is the first argument.".into(),
        )),
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
    }
    // Phone keys are reported by their LAST OBSERVED pairing, never by a check made now:
    // this verb makes no callosum call, so "superseded" means a lookup saw something
    // else, not that the pairing is known to be dead.
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

fn grants(global: &GlobalArgs, _args: &[String]) -> Result<(), CliError> {
    let Some(listing) = read_listing(global)? else {
        println!("{NO_TABLES}");
        return Ok(());
    };
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
        // A missing grant is the operator's answer, not a failure: an expired grant and
        // an unknown id are the same thing to whoever asked.
        _ => println!("no live grant {grant_id}"),
    }
    Ok(())
}
