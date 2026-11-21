//! Credential deposit, import, identity, category, and lifecycle commands.

use super::{
    check_deposit_provider_flags, commit_admin, created_id_is_already_reachable, decode_hash,
    default_refresh_adapter, deposit_provider_ids, finish_provider_deposit, github_apps, has_flag,
    hex_lower, import_picker, no_covering_grant_note, optional, parse_credential_id,
    provider_id_flags, provider_id_values, put_prompt, required, store_op, AdminAuditOp,
    AdminOpBody, AuthMethod, CliError, CredentialKind, GlobalArgs, ParsedOptions, RecordIdentity,
    SetCategoryMode, StoreMode, VaultRecord, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};

pub(super) fn has_gateway_flags(options: &ParsedOptions) -> bool {
    [
        "--gateway-base-url",
        "--gateway-auth-header",
        "--gateway-auth-scheme",
        "--gateway-header",
    ]
    .iter()
    .any(|flag| options.optional(flag).is_some())
}

fn put_gateway_settings(
    args: &[String],
    options: &ParsedOptions,
) -> Result<Option<credentials_core::gateway::GatewaySettings>, CliError> {
    use credentials_core::gateway::{GatewayAuth, GatewaySettings};

    if !has_gateway_flags(options) {
        return Ok(None);
    }
    if options.has_flag("--replace") || options.optional("--expected-hash").is_some() {
        return Err(CliError::Usage(
            "gateway flags cannot be used with --replace or --expected-hash".into(),
        ));
    }
    let base_url = options.required("--gateway-base-url")?;
    let auth_header = options.required("--gateway-auth-header")?;
    let auth_scheme = options.required("--gateway-auth-scheme")?;
    let base_url = normalize_gateway_base_url(&base_url);
    let mut headers = Vec::new();
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        if flag == "--replace" {
            continue;
        }
        let value = args.next();
        if flag == "--gateway-header" {
            headers.push(parse_gateway_header(
                value.map(String::as_str).unwrap_or_default(),
            )?);
        }
    }
    headers.sort_by(|a, b| a.name.cmp(&b.name));
    // Do not deduplicate: the shared validator refuses repeated names, including
    // names that become equal after lowercasing.
    Ok(Some(GatewaySettings {
        base_url,
        auth: GatewayAuth {
            header: auth_header.to_ascii_lowercase(),
            scheme: auth_scheme,
        },
        headers,
    }))
}

pub(super) fn parse_gateway_header(
    value: &str,
) -> Result<credentials_core::gateway::GatewayHeader, CliError> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| CliError::Usage("--gateway-header needs name=value".into()))?;
    Ok(credentials_core::gateway::GatewayHeader {
        name: name.to_ascii_lowercase(),
        value: value.trim().to_string(),
    })
}

pub(super) fn normalize_gateway_base_url(base_url: &str) -> String {
    // Preserve the path and explicit port spelling: URL parsers can repair invalid
    // paths or discard default ports before the core validator sees them.
    match base_url.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            let path = if path.is_empty() {
                String::new()
            } else {
                format!("/{path}")
            };
            format!(
                "{}://{}{}",
                scheme.to_ascii_lowercase(),
                authority.to_ascii_lowercase(),
                path
            )
        }
        None => base_url.to_string(),
    }
    .trim_end_matches('/')
    .to_string()
}

pub(super) fn cmd_put(
    global: &GlobalArgs,
    args: &[String],
    mut options: ParsedOptions,
) -> Result<(), CliError> {
    if let Some(id) = options.optional("--id") {
        credentials_core::store::check_github_app_companion_id(&id).map_err(CliError::Store)?;
    }
    let gateway = put_gateway_settings(args, &options)?;
    let explicit_ids = if gateway.is_some() {
        provider_id_values(args)?
    } else {
        let ids = provider_id_flags(args)?;
        check_deposit_provider_flags(options.optional("--id").as_deref(), &ids)?;
        ids
    };
    if !put_prompt::prepare(global, &mut options)? {
        return Ok(());
    }
    let id = options.required("--id")?;
    credentials_core::store::check_github_app_companion_id(&id).map_err(CliError::Store)?;
    if let Some(settings) = &gateway {
        credentials_core::gateway::validate_gateway_settings(&id, settings, &explicit_ids)
            .map_err(CliError::Store)?;
    } else {
        check_deposit_provider_flags(Some(&id), &explicit_ids)?;
    }
    if options
        .optional("--kind")
        .is_none_or(|kind| kind == "api_key")
        && !put_prompt::provider(global, &id)?
    {
        return Ok(());
    }
    // The provider prompt can register defaults. Resolve them after it returns,
    // but before storing the key, so a refused metadata write leaves no key behind.
    let ids = if gateway.is_some() {
        explicit_ids
    } else {
        deposit_provider_ids(global, &id, explicit_ids)?
    };
    let parsed = parse_credential_id(&id);
    if matches!(parsed.method, Some(AuthMethod::Signing)) {
        return Err(CliError::Usage(
            "signing keys must be generated with mint-signing-key, not put".to_string(),
        ));
    }
    // Keep secret bytes out of argv: read a file or use the hidden terminal prompt.
    // Ordinary key files drop their terminal line ending, but a cookie header is sent
    // verbatim upstream, so its file bytes cannot be trimmed or normalized.
    let payload = match options.optional("--payload-file") {
        Some(path) if matches!(parsed.method, Some(AuthMethod::Cookie)) => {
            std::fs::read(&path).map_err(|e| CliError::Io(format!("reading {path}: {e}")))?
        }
        Some(path) => {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| CliError::Io(format!("reading {path}: {e}")))?;
            raw.trim_end().as_bytes().to_vec()
        }
        None if put_prompt::is_terminal() => put_prompt::payload()?,
        None => {
            return Err(CliError::Usage(
                "--payload-file <path> is required without a terminal for the hidden interactive prompt".to_string(),
            ))
        }
    };
    // A GitHub App deposit is the one `put` that must NOT produce a static record.
    //
    // The App private key is a DURABLE credential that mints short-lived installation
    // tokens -- structurally the refresh-token/access-token relationship, so it belongs
    // in the OAuth shape where the engine's single-flight, expiry and version-CAS
    // machinery already lives. Stored static instead, `credential.get` serves the PEM
    // verbatim; a consumer then puts newline-laden key material into an HTTP header and
    // fails before the wire.
    //
    // `--client-id` is what selects the shape, because the adapter cannot mint without
    // it: it is the App JWT's `iss`. Requiring it here means a github_app record cannot
    // be created in a state that can never serve.
    let client_id = options.optional("--client-id");
    let is_github_app = id.starts_with("github_app:");
    match (&client_id, is_github_app) {
        (Some(_), false) => {
            return Err(CliError::Usage(
                "--client-id applies only to a github_app:<slug> id".to_string(),
            ))
        }
        (None, true) => {
            return Err(CliError::Usage(
                "a github_app deposit needs --client-id <app client id> (the App JWT issuer); \
                 without it the record can never mint a token"
                    .to_string(),
            ))
        }
        _ => {}
    }

    let kind = if matches!(parsed.method, Some(AuthMethod::Cookie)) {
        if options.optional("--kind").is_some() {
            return Err(CliError::Usage(
                "cookie:<domain> determines the cookie kind; do not pass --kind".to_string(),
            ));
        }
        CredentialKind::Cookie
    } else {
        match options.optional("--kind").as_deref() {
            None | Some("api_key") => CredentialKind::ApiKey,
            Some("dsn") => CredentialKind::Dsn,
            Some("opaque") => CredentialKind::Opaque,
            Some(other) => {
                return Err(CliError::Usage(format!(
                "--kind must be api_key|dsn|opaque (oauth records come via import), got '{other}'"
            )))
            }
        }
    };
    let expires_at_ms = if matches!(parsed.method, Some(AuthMethod::Cookie)) {
        if options.optional("--expires-ms").is_some() {
            return Err(CliError::Usage(
                "cookie credentials do not carry an expiry; omit --expires-ms".to_string(),
            ));
        }
        None
    } else {
        options
            .optional("--expires-ms")
            .map(|s| s.parse::<i64>())
            .transpose()
            .map_err(|e| CliError::Usage(format!("--expires-ms not an integer: {e}")))?
    };

    let record = match client_id {
        Some(client_id) => {
            // Empty access_token on purpose: `is_stale` short-circuits an empty access
            // token to stale, so the FIRST get mints rather than serving nothing. The
            // empty payload is legal here for the same reason it is legal for a
            // refresh-only OAuth import -- the non-empty-payload invariant guards
            // records that have no way to fill themselves, and this one refreshes.
            //
            // token_url stays empty because this adapter pins GitHub's endpoints as
            // constants rather than reading them off the record.
            let oauth = credentials_core::oauth::OAuthCredential {
                access_token: String::new().into(),
                refresh_token: String::from_utf8(payload)
                    .map_err(|_| {
                        CliError::Usage("the App private key must be UTF-8 PEM text".to_string())
                    })?
                    .into(),
                expires_at_ms: None,
                token_url: String::new(),
                client_id: Some(client_id),
                client_secret: None,
                scopes: Vec::new(),
            };
            github_apps::check_deposit(&id, &oauth)?;
            VaultRecord::new_oauth("operator", "github_app", oauth, Vec::new())
        }
        None if kind == CredentialKind::Cookie => VaultRecord::new_cookie("operator", payload),
        None => VaultRecord::new_static(kind, "operator", payload, expires_at_ms),
    };
    if let Some(settings) = gateway {
        commit_admin(
            global,
            AdminOpBody::GatewayCreate {
                v: ADMIN_OP_SCHEMA_V2,
                id: id.clone(),
                record: Box::new(record),
                audit_op: AdminAuditOp::Put,
                base_url: settings.base_url,
                auth_header: settings.auth.header,
                auth_scheme: settings.auth.scheme,
                headers: settings.headers,
                provider_ids: ids,
            },
        )?;
        println!("created {id}");
        return Ok(());
    }
    // CREATE-ONLY by default. An overwrite is either an explicit --expected-hash CAS
    // (concurrency-safe: fails if the record changed under you) or --replace
    // (unconditional: bumps record_version, keeps existing handles). --replace is the
    // routine rotation path for a static key — the operator pastes the new key from
    // the provider console and the record_version bump invalidates every consumer's
    // cache. The two are mutually exclusive: a CAS is a targeted overwrite, --replace
    // is a deliberate blind one.
    let replace = options.has_flag("--replace");
    match (options.optional("--expected-hash"), replace) {
        (Some(_), true) => {
            return Err(CliError::Usage(
                "pass only one of --expected-hash (CAS) or --replace (unconditional)".to_string(),
            ));
        }
        (Some(hex), false) => {
            let expected = decode_hash(&hex)?;
            commit_admin(
                global,
                store_op(
                    &id,
                    record,
                    AdminAuditOp::Overwrite,
                    StoreMode::ReplaceCas {
                        expected_hash_hex: hex_lower(&expected),
                    },
                ),
            )?;
            println!("overwrote {id} (CAS ok)");
        }
        (None, true) => {
            commit_admin(
                global,
                store_op(
                    &id,
                    record,
                    AdminAuditOp::Overwrite,
                    StoreMode::ReplaceUnconditional,
                ),
            )?;
            println!("replaced {id} (unconditional)");
        }
        (None, false) => {
            commit_admin(
                global,
                store_op(&id, record, AdminAuditOp::Put, StoreMode::Create),
            )?;
            println!("created {id}");
            // SAID ONLY ON THE CREATE ARM, and only when nothing already reaches the id.
            //
            // A deposit is not a delivery. The vault now holds the material and no
            // consumer can ask for it until a grant covers it: modules and enrolled
            // consumers read under a grant, and only the operator can decide who that
            // should be.
            //
            // So the operator is the only party who can close it, and this is the one
            // moment they are standing in the flow.
            //
            // WHY A LINE HERE RATHER THAN A GAUGE IN `list` OR HEALTH: measured on the
            // live vault, 4 of 4 credentials with no handle and no covering grant are
            // DELIBERATELY unreachable -- a signing root whose handle exists only inside
            // a ceremony window, and three deploy-time sources of record consumed by
            // `wrangler secret put` and never over the route plane. A standing alarm
            // would be wrong every time it fired, and the first thing anyone would do is
            // stop reading it. A statement at the moment of the act is honest for those
            // too: depositing the manifest root DOES leave it unreachable until a
            // ceremony mints one.
            //
            // Create-only by construction: `StoreMode::Create` fails if the id exists,
            // so there cannot be a surviving handle from a previous deposit. On the
            // replace arms handles are deliberately kept, and printing this there would
            // be false.
            // ADVICE ON STDERR, VERDICT ON STDOUT -- this file's existing convention,
            // most closely the mint advisory ("(minted handle for …)"), which puts the
            // datum on stdout and the note beside it on stderr.
            //
            // This was on stdout, so the LAST line of a successful put was advice and a
            // caller had to tail past it to find `created <id>`. An operator reads both
            // either way; a script capturing stdout now gets the verdict alone.
            if !created_id_is_already_reachable(global, &id) {
                eprintln!("{}", no_covering_grant_note(&id));
            }
        }
    }
    finish_provider_deposit(global, &id, &ids)?;
    Ok(())
}

#[derive(Default)]
pub(super) struct IdentityFlags {
    clear: bool,
    account_id: Option<String>,
    email: Option<String>,
    org_name: Option<String>,
}

fn identity_flags(
    args: &[String],
    clear_flag: &str,
    require_account_id: bool,
) -> Result<IdentityFlags, CliError> {
    let flags = IdentityFlags {
        clear: has_flag(args, clear_flag),
        account_id: optional(args, "--account-id"),
        email: optional(args, "--email"),
        org_name: optional(args, "--org-name"),
    };
    let has_identity_fields =
        flags.account_id.is_some() || flags.email.is_some() || flags.org_name.is_some();
    if flags.clear && has_identity_fields {
        return Err(CliError::Usage(format!(
            "{clear_flag} is mutually exclusive with --account-id, --email, and --org-name"
        )));
    }
    if flags.clear {
        return Ok(flags);
    }
    let Some(account_id) = flags.account_id.as_deref() else {
        if has_identity_fields || require_account_id {
            return Err(CliError::Usage(
                "--account-id is required when setting identity metadata".to_string(),
            ));
        }
        return Ok(flags);
    };
    if account_id.trim().is_empty() {
        return Err(CliError::Usage(
            "--account-id must not be empty".to_string(),
        ));
    }
    if account_id.chars().any(char::is_control) {
        return Err(CliError::Usage(
            "--account-id must not contain control characters".to_string(),
        ));
    }
    if account_id.len() > 256 {
        return Err(CliError::Usage(
            "--account-id must be at most 256 bytes".to_string(),
        ));
    }
    Ok(flags)
}

/// Convert one isolated harness entry into the vault record used by both import forms.
/// Identity is deliberately returned as metadata so attachment remains a separate step.
pub(super) fn build_import_record(
    source: &str,
    entry_payload: &[u8],
    id: &str,
    provider_selection: Option<&str>,
    adapter_override: Option<String>,
) -> Result<(VaultRecord, Option<String>), CliError> {
    let parsed = parse_credential_id(id);
    if matches!(parsed.method, Some(AuthMethod::Signing)) {
        return Err(CliError::Usage(
            "signing keys must be generated with mint-signing-key, not imported".to_string(),
        ));
    }
    if matches!(parsed.method, Some(AuthMethod::ApiKey)) {
        let provider = provider_selection.unwrap_or(&parsed.provider);
        let key = credentials_core::oauth::import_api_key(source, entry_payload, provider)
            .map_err(|error| CliError::Usage(format!("api-key import: {error}")))?;
        return Ok((
            VaultRecord::new_static(CredentialKind::ApiKey, source, key, None),
            None,
        ));
    }

    let mut imported_email = None;
    let oauth = if source == "antigravity" {
        credentials_core::oauth::import_antigravity_account(entry_payload, provider_selection).map(
            |imported| {
                imported_email = imported.email;
                imported.oauth
            },
        )
    } else {
        match provider_selection {
            Some(provider) => credentials_core::oauth::OAuthCredential::import_provider(
                source,
                entry_payload,
                provider,
            ),
            None => credentials_core::oauth::OAuthCredential::import(source, entry_payload),
        }
    }
    .map_err(|error| CliError::Usage(format!("import parse: {error}")))?;
    let adapter = adapter_override
        .or_else(|| default_refresh_adapter(parsed.method, &parsed.provider))
        .ok_or_else(|| {
            CliError::Usage(format!(
                "no refresh adapter for id '{id}'; pass --adapter <name>"
            ))
        })?;
    let payload =
        credentials_core::secret::SecretBytes::new(oauth.access_token.expose().as_bytes().to_vec());
    Ok((
        VaultRecord::new_oauth(source, adapter, oauth, payload),
        imported_email,
    ))
}

/// Apply the import identity policy after record construction. Keeping this separate
/// ensures the picker and flag form attach antigravity identity in the same order.
pub(super) fn attach_import_identity(
    record: VaultRecord,
    requested_identity: IdentityFlags,
    imported_email: Option<String>,
) -> VaultRecord {
    if requested_identity.clear {
        return record;
    }
    match requested_identity.account_id {
        Some(account_id) => record.with_identity(RecordIdentity {
            account_id: Some(account_id),
            email: requested_identity.email.or(imported_email),
            org_name: requested_identity.org_name,
        }),
        None => match imported_email {
            // THE EMAIL BECOMES THE ACCOUNT ID BECAUSE AN EMAIL-ONLY IDENTITY IS DROPPED.
            // `RecordIdentity::normalized` discards an identity with no account_id, so a
            // harness that gives us an address and no subject would otherwise import with
            // no identity at all, and several such accounts would render as
            // indistinguishable unlabelled rows.
            //
            // The consequence is real and belongs here rather than in a commit message: a
            // consumer's account column then holds an email for this provider and a UUID
            // for every other. That is admissible because `account_id` is contractually
            // the PROVIDER's identifier with the provider's own shape, and for Google an
            // address is a truer account identity than anything else we hold -- but a
            // consumer validating UUID shape breaks on a real value, not a missing one.
            // docs/wire-contract-v1.md states the opacity rule for exactly this reason.
            Some(email) => record.with_identity(RecordIdentity {
                account_id: Some(email.clone()),
                email: Some(email),
                org_name: None,
            }),
            None => record,
        },
    }
}

pub(super) fn cmd_import(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    if args.is_empty() {
        return import_picker::run(global);
    }

    let source = required(args, "--source")?;
    let id = required(args, "--id")?;
    let json_path = required(args, "--json")?;
    let requested_identity = identity_flags(args, "--clear-identity", false)?;
    let clear_identity = requested_identity.clear;
    let raw =
        std::fs::read(&json_path).map_err(|e| CliError::Io(format!("reading {json_path}: {e}")))?;
    let provider_selection = optional(args, "--provider");
    let (record, imported_email) = build_import_record(
        &source,
        &raw,
        &id,
        provider_selection.as_deref(),
        optional(args, "--adapter"),
    )?;
    let record = attach_import_identity(record, requested_identity, imported_email);

    // `--replace` overwrites an existing credential UNCONDITIONALLY (re-seal at
    // version+1, reset to active, keep the handle), for fixing a credential imported
    // from the wrong source. Without it, import is CREATE-ONLY (an existing id is an
    // error), so a fresh credential can never be silently clobbered.
    if has_flag(args, "--replace") {
        commit_admin(
            global,
            AdminOpBody::StoreWithIdentityPolicy {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.clone(),
                record: Box::new(record),
                audit_op: AdminAuditOp::Import,
                clear_identity,
            },
        )?;
        println!("replaced {id}");
    } else {
        commit_admin(
            global,
            store_op(&id, record, AdminAuditOp::Import, StoreMode::Create),
        )?;
        println!("imported {id}");
    }
    Ok(())
}

pub(super) fn cmd_set_identity(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = args
        .first()
        .filter(|arg| !arg.starts_with("--"))
        .cloned()
        .ok_or_else(|| {
            CliError::Usage("set-identity requires a positional <credential-id>".to_string())
        })?;
    let requested = identity_flags(args, "--clear", true)?;
    let identity = if requested.clear {
        RecordIdentity::default()
    } else {
        RecordIdentity {
            account_id: requested.account_id,
            email: requested.email,
            org_name: requested.org_name,
        }
    };
    commit_admin(
        global,
        AdminOpBody::SetIdentity {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
            identity,
        },
    )?;
    println!("updated identity for {id}");
    Ok(())
}

pub(super) fn cmd_set_category(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let credential_id = args
        .first()
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| {
            CliError::Usage("set-category requires a positional <credential-id>".into())
        })?
        .clone();
    let modes = [
        ("--set", SetCategoryMode::Set),
        ("--add", SetCategoryMode::Add),
        ("--remove", SetCategoryMode::Remove),
    ];
    let mode_count = args
        .iter()
        .filter(|value| modes.iter().any(|(flag, _)| value == flag))
        .count();
    let selected: Vec<_> = modes
        .iter()
        .filter_map(|(flag, mode)| optional(args, flag).map(|value| (*mode, value)))
        .collect();
    if mode_count != 1 || selected.len() != 1 {
        return Err(CliError::Usage(
            "set-category requires exactly one of --set, --add, or --remove".into(),
        ));
    }
    let (mode, raw) = &selected[0];
    let categories = if raw.is_empty() {
        Vec::new()
    } else {
        raw.split(',').map(str::to_string).collect()
    };
    commit_admin(
        global,
        AdminOpBody::SetCategory {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: credential_id.clone(),
            mode: *mode,
            categories,
        },
    )?;
    println!("updated categories for {credential_id}");
    Ok(())
}

pub(super) fn cmd_reclassify(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    if !has_flag(args, "--from-registry") {
        return Err(CliError::Usage(
            "reclassify requires --from-registry".into(),
        ));
    }
    let result = commit_admin(
        global,
        AdminOpBody::Reclassify {
            v: ADMIN_OP_SCHEMA_V2,
            force: has_flag(args, "--force"),
        },
    )?;
    let changed = result
        .get("credentials_reclassified")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    println!("reclassified {changed} credential(s)");
    Ok(())
}

pub(super) fn cmd_invalidate(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    // The compound invalidate is atomic: needs_reauth + clear intent + revoke all
    // handles in one fenced transaction (so a live relay can't split the halves).
    let result = commit_admin(
        global,
        AdminOpBody::Invalidate {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let revoked = result["handles_revoked"].as_u64().unwrap_or(0);
    // READ `state_changed`, WHICH THE ADMIN OP SENDS FOR EXACTLY THIS. Without it the
    // line claimed "invalidated <id>" for an id that does not exist, is already
    // needs_reauth, or is retired -- and `handles_revoked` cannot stand in, because a
    // credential with no handles reports zero whether it was live or already dead.
    //
    // Same false-assurance shape as revoke-handle: the operator is told a credential was
    // stopped when nothing was. `logout` already reports this correctly; this is the
    // sibling that did not.
    //
    // Absent (older daemon) falls back to the previous wording rather than claiming
    // nothing changed -- absent and false mean different things.
    match result.get("state_changed") {
        Some(serde_json::Value::Bool(false)) => println!(
            "{id} was already needs_reauth, retired, absent, or corrupt: nothing changed\n  \
             revoked {revoked} handle(s) regardless — revocation is idempotent."
        ),
        _ => println!("invalidated {id}; revoked {revoked} handle(s)"),
    }
    Ok(())
}

/// `reactivate` = clear `needs_reauth` or `retired` back to active WITHOUT replacing
/// the secret.
///
/// The repair is for a wrong lifecycle verdict, not for a credential whose stored
/// material is damaged. It exists because that state was otherwise unrecoverable for
/// material the vault holds
/// the only copy of: a GitHub App key is shredded after deposit by custody rule, so
/// `put --replace` has no PEM to read and no login flow can re-mint one, and a mistaken
/// consumer report could force an operator back to a browser to repair bytes that were
/// never damaged.
///
/// Refuses from `corrupt` by design -- that is a claim about our own bytes, which this
/// vault verified itself, and clearing it would return known-broken material to service.
pub(super) fn cmd_reactivate(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::Reactivate {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    if result["state_changed"].as_bool().unwrap_or(false) {
        println!("reactivated {id}: serving verdict cleared, material untouched");
        println!("  the next use verifies it; if the credential really is dead it returns to");
        println!("  needs_reauth on its own, so a wrong call costs one failed request.");
    } else {
        // A no-op has two causes and the operator needs to know WHICH, because one is
        // benign and the other means they reached for the wrong verb.
        println!("reactivated nothing: {id} was not in needs_reauth or retired");
        println!("  already active, unknown, or corrupt. Corrupt is refused here because the");
        println!("  bytes themselves failed, and only a re-deposit fixes that.");
    }
    Ok(())
}

/// `remove` = PERMANENTLY delete a credential row (+ its intent and handle rows) in
/// one audited fenced transaction. The audit chain keeps the full history — removal
/// deletes serving state, never forensics. The permanent sibling of `logout`: use it
/// to retire an account or clean up a mistakenly created id. Takes `--id` only (no
/// `--provider` shorthand: a permanent delete should name its exact target).
pub(super) fn cmd_remove(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::Remove {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    // Absent on a daemon older than the field: print the old line rather than
    // claiming a count we did not get.
    let handles = result["handles_deleted"].as_u64();
    match handles {
        Some(n) => println!(
            "removed {id}: row, refresh intent, and {n} handle(s) deleted (audit history kept)"
        ),
        None => {
            println!("removed {id}: row, refresh intent, and handles deleted (audit history kept)")
        }
    }
    // NAME THE CONSEQUENCE THE VAULT CANNOT ACT ON. Handles are bearer
    // capabilities: nothing records who holds one, so removal cannot notify the
    // holder and their next fetch gets a bare `not_found`. The operator is the only
    // party who knows which consumers were given one, and this is the last moment
    // that knowledge is actionable. Observed live: a removed credential left a
    // stale entry in a consumer's handle file, and that one dangling entry blinded
    // its three healthy sibling accounts until the consumer noticed independently.
    if handles.is_some_and(|n| n > 0) {
        println!("  those handle(s) no longer resolve for whoever holds them.");
        println!("  the vault cannot tell them: a handle records no holder. if you gave");
        println!("  one to a consumer, drop it from that consumer's config now.");
    }
    Ok(())
}
