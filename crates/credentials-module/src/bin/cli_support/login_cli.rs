//! Interactive, device, API-key, gateway, and browser login and logout commands.

#[cfg(all(test, unix))]
use super::spawn_browser;
use super::{
    api_key_login, browser_login, check_deposit_provider_flags, commit_admin,
    commit_admin_with_key, commit_login_admin, google_login, has_flag, login_listener,
    login_provider, login_wire, normalize_gateway_base_url, optional, parse_credential_id,
    parse_gateway_header, parse_inventory, preflight_login, provider_id_flags, provider_login,
    put_prompt, request_admin_status, store_op, tokio_block_on, AdminAuditOp, AdminOpBody,
    CliError, CredentialKind, DeviceKind, ExchangeWire, GlobalArgs, LoginProvider, RecordIdentity,
    StoreMode, VaultRecord, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};
#[cfg(test)]
use super::{help_verb, parse_plan_since, usage_short, windows_browser_command};

// Vault-native first-party OAuth login uses the shared core catalog so the CLI,
// creation defaults, reclassification, and scoped listings resolve the same entries.

/// The default credential id for a bare `--provider <name>` login (no `--id`, no
/// interactive pick). OAuth/subscription logins WIN for the three names that also
/// have an api-key row (openai → chatgpt:openai, xai → oauth:xai, google →
/// oauth:google): a bare `login --provider <name>` means the subscription login,
/// and that name's api-key credential is reached with an explicit `--id apikey:<name>`.
fn default_login_id(provider: &str) -> String {
    if let Some(wire) = login_provider(provider) {
        return wire.default_id.to_string();
    }
    if let Some(id) = google_login::default_id(provider) {
        return id.to_string();
    }
    if let Some(p) = api_key_login::API_KEY_PROVIDERS
        .iter()
        .find(|p| p.key == provider)
    {
        return p.default_id.to_string();
    }
    // Unknown provider: return it unchanged so the dispatch's final login_provider
    // lookup produces the proper "unknown provider" error.
    provider.to_string()
}

pub(super) use credentials_core::oauth_login::login_id_is_valid;

/// The login providers offered by the interactive picker, in display order. The
/// display name is the subscription the operator recognizes; the key is what
/// `login_provider()` resolves.
const LOGIN_PICKER_ROWS: &[(&str, &str)] = &[
    ("anthropic", "Anthropic (Claude Pro/Max)"),
    ("openai", "ChatGPT (Codex subscription)"),
    ("xai", "xAI (Grok)"),
    ("github-copilot", "GitHub Copilot"),
    ("kimi", "Kimi Code"),
    ("meta", "Meta Muse (coding subscription)"),
    ("google", "Google Gemini CLI (Code Assist)"),
    ("gmail", "Gmail (send as you)"),
    ("antigravity", "Antigravity (Gemini 3)"),
    ("cursor", "Cursor"),
    ("devin", "Devin"),
    ("snowflake", "Snowflake Cortex"),
    ("digitalocean", "DigitalOcean GenAI"),
];

/// What the interactive flow decided beyond the provider: an id override (labeled
/// account) and/or replace mode.
struct InteractiveChoice {
    provider: String,
    id_override: Option<String>,
    replace: bool,
}

/// Best-effort credential inventory for the picker's "logged in" indicators and the
/// add-vs-replace prompt: the authenticated `admin.status` read (running daemon or
/// offline lease). `None` when unavailable (unbootstrapped vault, locked keychain) —
/// the picker then simply shows no indicators; login itself will surface real errors.
fn inventory_for_picker(global: &GlobalArgs) -> Option<Vec<(String, String)>> {
    let result = commit_admin(
        global,
        AdminOpBody::Status {
            v: ADMIN_OP_SCHEMA_V1,
        },
    )
    .ok()?;
    Some(
        result["credentials"]
            .as_array()?
            .iter()
            .filter_map(|row| {
                Some((
                    row["id"].as_str()?.to_string(),
                    row["state"].as_str()?.to_string(),
                ))
            })
            .collect(),
    )
}

/// The ids belonging to one login provider: the default id and its labeled accounts.
fn provider_ids<'a>(inventory: &'a [(String, String)], default_id: &str) -> Vec<&'a str> {
    inventory
        .iter()
        .map(|(id, _)| id.as_str())
        .filter(|id| *id == default_id || id.starts_with(&format!("{default_id}:")))
        .collect()
}

fn login_replace(args: &[String], interactive_replace: bool) -> bool {
    has_flag(args, "--replace") || interactive_replace
}

fn new_login_id(provider: &str, default_id: &str, label: Option<&str>) -> Option<String> {
    // Snowflake ids are derived from the account entered by the operator, not labels.
    if provider == "snowflake" {
        return None;
    }
    Some(label.map_or_else(
        || default_id.to_string(),
        |label| format!("{default_id}:{label}"),
    ))
}

const OTHER_API_KEY_PROVIDER: &str = "__other_api_key__";
const COMPANY_AI_GATEWAY: &str = "__company_ai_gateway__";

/// Every row the interactive login picker offers, as (provider key, display name,
/// default id): OAuth/device logins, API-key catalog rows, gateway, then custom.
fn login_picker_rows() -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for &(key, name) in LOGIN_PICKER_ROWS {
        let wire = login_provider(key).expect("picker rows are valid providers");
        rows.push((
            key.to_string(),
            name.to_string(),
            wire.default_id.to_string(),
        ));
    }
    for provider in api_key_login::API_KEY_PROVIDERS {
        rows.push((
            provider.key.to_string(),
            provider.display_name.to_string(),
            provider.default_id.to_string(),
        ));
    }
    rows.push((
        COMPANY_AI_GATEWAY.to_string(),
        "Company AI gateway (LiteLLM, Portkey, Cloudflare)".to_string(),
        String::new(),
    ));
    rows.push((
        OTHER_API_KEY_PROVIDER.to_string(),
        "Other API key provider…".to_string(),
        String::new(),
    ));
    rows
}

fn pick_login_interactively(
    global: &GlobalArgs,
    args: &[String],
) -> Result<InteractiveChoice, CliError> {
    use dialoguer::{theme::ColorfulTheme, FuzzySelect, Input, Select};

    let inventory = inventory_for_picker(global).unwrap_or_default();
    let combined_rows = login_picker_rows();
    let items: Vec<String> = combined_rows
        .iter()
        .map(|(_key, name, default_id)| {
            let ids = provider_ids(&inventory, default_id);
            match ids.len() {
                0 => name.to_string(),
                1 => format!("{name}  ● logged in"),
                n => format!("{name}  ● {n} accounts"),
            }
        })
        .collect();

    let theme = ColorfulTheme::default();
    let pick = FuzzySelect::with_theme(&theme)
        .with_prompt("Select provider to login (type to search)")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| {
            CliError::Usage(format!(
                "interactive login needs a terminal ({e}); run `ck auth login` with a TTY, \
                 or pass --provider <name>"
            ))
        })?;
    let (provider, _, default_id) = &combined_rows[pick];
    if provider == OTHER_API_KEY_PROVIDER || provider == COMPANY_AI_GATEWAY {
        return Ok(InteractiveChoice {
            provider: provider.clone(),
            id_override: None,
            replace: false,
        });
    }
    google_login::validate_client_flags(args, provider)?;
    let default_id = default_id.as_str();
    let existing = provider_ids(&inventory, default_id);

    if existing.is_empty() {
        // Carry the picked row's default id so the dispatch keys on the credential
        // METHOD, not the provider name: openai/xai/google each name BOTH an OAuth
        // login (chatgpt:openai / oauth:xai / oauth:google) and an api-key row
        // (apikey:*), so the provider string alone cannot say which the operator
        // picked — the resolved id can.
        return Ok(InteractiveChoice {
            provider: provider.clone(),
            id_override: new_login_id(provider, default_id, None),
            replace: false,
        });
    }

    // The account already exists: make the multi-account path a menu, not a flag.
    let mut actions = vec![format!(
        "Add another account (a new labeled id like {}:work)",
        default_id
    )];
    for id in &existing {
        actions.push(format!("Replace {id} (re-login; keeps its handles)"));
    }
    let action = Select::with_theme(&theme)
        .with_prompt("This provider already has a credential")
        .items(&actions)
        .default(0)
        .interact()
        .map_err(|e| CliError::Usage(format!("interactive login cancelled: {e}")))?;

    if action == 0 {
        if provider == "snowflake" {
            return Ok(InteractiveChoice {
                provider: provider.clone(),
                id_override: None,
                replace: false,
            });
        }
        let label: String = Input::with_theme(&theme)
            .with_prompt("Label for the new account (e.g. work, personal, gmail)")
            .validate_with(|s: &String| {
                if s.is_empty() || s.contains(':') || s.contains(char::is_whitespace) {
                    Err("label must be non-empty, without ':' or spaces")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map_err(|e| CliError::Usage(format!("interactive login cancelled: {e}")))?;
        Ok(InteractiveChoice {
            id_override: new_login_id(provider, default_id, Some(&label)),
            provider: provider.clone(),
            replace: false,
        })
    } else {
        Ok(InteractiveChoice {
            id_override: Some(existing[action - 1].to_string()),
            provider: provider.clone(),
            replace: true,
        })
    }
}

/// Whether a login runs the device-code flow instead of the browser authorize flow.
///
/// A provider with no authorize URL can only log in by device code, so it must take
/// this path even without `--device`. Listing device-only providers by name let a new
/// one (Meta) fall through to the browser flow, which then failed building an
/// authorize URL from the empty string.
fn uses_device_login(wire: &LoginProvider, requested_device: bool) -> bool {
    requested_device || (wire.device.is_some() && wire.authorize_url.is_empty())
}

fn cmd_device_login(
    global: &GlobalArgs,
    args: &[String],
    provider: &str,
    id: &str,
    wire: &LoginProvider,
    replace: bool,
) -> Result<(), CliError> {
    use credentials_core::device_flow::{
        run_device_flow, run_openai_device_flow, DeviceBodyEncoding, DeviceFlowConfig,
    };
    use credentials_core::refresh_adapters::{github_copilot, kimi, meta, xai, RefreshAdapter};

    let preflighted_key = preflight_login(
        global,
        id,
        replace,
        format!("'{id}' already holds a credential; use --replace or a labeled id"),
    )?;

    let http =
        credentials_core::http::ReqwestTransport::new().map_err(|e| CliError::Io(e.to_string()))?;
    let print_device_instructions = |auth: &credentials_core::DeviceAuthorization| {
        println!("Enter this code: {}", auth.user_code);
        println!("Verification URL: {}", auth.verification_uri);
        if let Some(complete) = auth.verification_uri_complete.as_deref() {
            println!("Direct verification URL: {complete}");
        }
    };

    let tokens = match wire.device {
        Some(DeviceKind::Meta) => tokio_block_on(run_device_flow(
            &http,
            &meta::device_config(),
            print_device_instructions,
        ))
        .map_err(|e| CliError::Io(e.to_string()))?,
        Some(DeviceKind::GithubCopilot) => {
            let mut cfg = DeviceFlowConfig::new(
                github_copilot::DEVICE_CODE_URL,
                github_copilot::DEVICE_TOKEN_URL,
                github_copilot::CLIENT_ID,
                DeviceBodyEncoding::Json,
            );
            cfg.scope = Some("read:user".into());
            cfg.extra_headers = vec![("Accept".into(), "application/json".into())];
            tokio_block_on(run_device_flow(&http, &cfg, print_device_instructions))
                .map_err(|e| CliError::Io(e.to_string()))?
        }
        Some(DeviceKind::Kimi) => {
            let path = kimi::device_id_path(&global.data_dir);
            let device_id = kimi::ensure_device_id(&path)
                .map_err(|e| CliError::Io(format!("Kimi device id: {e}")))?;
            let mut cfg = DeviceFlowConfig::new(
                kimi::DEVICE_AUTH_URL,
                kimi::TOKEN_URL,
                kimi::CLIENT_ID,
                DeviceBodyEncoding::Form,
            );
            cfg.extra_headers = vec![
                ("Accept".into(), "application/json".into()),
                ("User-Agent".into(), kimi::USER_AGENT.into()),
                ("X-Msh-Platform".into(), kimi::PLATFORM.into()),
                ("X-Msh-Device-Id".into(), device_id),
            ];
            tokio_block_on(run_device_flow(&http, &cfg, print_device_instructions))
                .map_err(|e| CliError::Io(e.to_string()))?
        }
        Some(DeviceKind::Xai) => {
            let mut cfg = DeviceFlowConfig::new(
                xai::DEVICE_CODE_URL,
                xai::DEVICE_TOKEN_URL,
                xai::GROK_CLI_CLIENT_ID,
                DeviceBodyEncoding::Form,
            );
            cfg.scope = Some(xai::DEVICE_SCOPE.into());
            cfg.extra_headers = vec![("Accept".into(), "application/json".into())];
            tokio_block_on(run_device_flow(&http, &cfg, print_device_instructions))
                .map_err(|e| CliError::Io(e.to_string()))?
        }
        Some(DeviceKind::OpenAi) => tokio_block_on(run_openai_device_flow(
            &http,
            credentials_core::refresh_adapters::openai::CODEX_CLIENT_ID,
            print_device_instructions,
        ))
        .map_err(|e| CliError::Io(e.to_string()))?,
        None => {
            return Err(CliError::Usage(format!(
                "provider '{provider}' does not support device login"
            )))
        }
    };

    let record = if matches!(wire.device, Some(DeviceKind::Meta)) {
        let presence = |present| if present { "present" } else { "absent" };
        println!(
            "Meta device-token response: refresh token {}; expiry field {}",
            presence(tokens.refresh_token.is_some()),
            presence(tokens.expiry_field_present)
        );
        let (record, fields) = tokio_block_on(meta::login_record(tokens, &http))
            .map_err(|e| CliError::Io(format!("Meta Muse login failed: {e}")))?;
        println!(
            "Meta key response: expiry field {}",
            presence(fields.key_expiry_field_present)
        );
        record
    } else if matches!(wire.device, Some(DeviceKind::GithubCopilot)) {
        let github_credential = credentials_core::oauth::OAuthCredential {
            access_token: String::new().into(),
            refresh_token: tokens.access_token.into(),
            expires_at_ms: None,
            token_url: github_copilot::TOKEN_URL.into(),
            client_id: Some(github_copilot::CLIENT_ID.into()),
            client_secret: None,
            scopes: vec!["read:user".into()],
        };
        let exchanged = tokio_block_on(
            github_copilot::GithubCopilotAdapter::new().refresh(&github_credential, &http),
        )
        .map_err(|e| CliError::Io(e.to_string()))?;
        let oauth = credentials_core::oauth::OAuthCredential {
            access_token: exchanged.access_token.clone(),
            refresh_token: exchanged.refresh_token,
            expires_at_ms: exchanged.expires_at_ms,
            token_url: github_copilot::TOKEN_URL.into(),
            client_id: Some(github_copilot::CLIENT_ID.into()),
            client_secret: None,
            scopes: vec!["read:user".into()],
        };
        let payload = credentials_core::secret::SecretBytes::new(
            oauth.access_token.expose().as_bytes().to_vec(),
        );
        VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload)
    } else {
        device_oauth_record(wire, tokens)?
    };
    if replace {
        commit_login_admin(
            global,
            store_op(
                id,
                record,
                AdminAuditOp::Login,
                StoreMode::ReplaceUnconditional,
            ),
            preflighted_key,
            args,
        )?;
        println!("logged in and replaced {id}");
    } else {
        let result = commit_login_admin(
            global,
            store_op(id, record, AdminAuditOp::Login, StoreMode::Create),
            preflighted_key,
            args,
        );
        if result.as_ref().is_err_and(CliError::is_already_exists) {
            return Err(CliError::Usage(format!(
                "'{id}' already holds a credential; use --replace or a labeled id"
            )));
        }
        result?;
        println!("logged in and stored {id}");
    }
    Ok(())
}

fn device_oauth_record(
    wire: &LoginProvider,
    tokens: credentials_core::device_flow::DeviceTokens,
) -> Result<VaultRecord, CliError> {
    let refresh_token = tokens.refresh_token.ok_or_else(|| {
        CliError::Io(format!(
            "{} device flow returned no refresh token",
            wire.key
        ))
    })?;
    let tokens = credentials_core::oauth_login::LoginTokens {
        access_token: tokens.access_token,
        refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        id_token: tokens.id_token,
        account: None,
        organization: None,
    };
    let identity = match wire.device {
        Some(DeviceKind::OpenAi | DeviceKind::Xai) => login_identity(wire.key, &tokens),
        _ => RecordIdentity::default(),
    };
    let oauth = credentials_core::oauth::OAuthCredential {
        access_token: tokens.access_token.into(),
        refresh_token: tokens.refresh_token.into(),
        expires_at_ms: tokens.expires_at_ms,
        token_url: wire.token_url.to_string(),
        client_id: Some(wire.client_id.to_string()),
        client_secret: None,
        scopes: wire.scopes.iter().map(|scope| scope.to_string()).collect(),
    };
    let payload =
        credentials_core::secret::SecretBytes::new(oauth.access_token.expose().as_bytes().to_vec());
    Ok(VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload).with_identity(identity))
}

fn login_identity(
    provider: &str,
    tokens: &credentials_core::oauth_login::LoginTokens,
) -> RecordIdentity {
    use credentials_core::oauth_login::{
        account_id_for_adapter, decode_jwt_claims, extract_chatgpt_account_id,
    };

    let account_from_token = if provider == "xai" {
        account_id_for_adapter(provider, &tokens.access_token)
    } else {
        extract_chatgpt_account_id(tokens)
    };
    if provider == "openai" {
        match account_from_token.as_deref() {
            Some(account) => println!("chatgpt account id: {account}"),
            None => println!(
                "WARNING: the minted token carries no chatgpt_account_id claim; \
                 the ChatGPT wire family will refuse it — is this a ChatGPT-subscription account?"
            ),
        }
    }
    // Account identity is display metadata, not used for authorization. Anthropic
    // sends it inline; OIDC providers include it in the identity token.
    let identity = RecordIdentity {
        account_id: tokens
            .account
            .as_ref()
            .and_then(|a| a.uuid.clone())
            .or(account_from_token),
        email: tokens
            .account
            .as_ref()
            .and_then(|a| a.email_address.clone())
            .or_else(|| {
                let claims = decode_jwt_claims(tokens.id_token.as_deref()?)?;
                Some(claims.get("email")?.as_str()?.to_owned())
            }),
        org_name: tokens.organization.as_ref().and_then(|o| o.name.clone()),
    };
    if let Some(email) = identity.email.as_deref() {
        match identity.org_name.as_deref() {
            Some(org) => println!("account: {email} · {org}"),
            None => println!("account: {email}"),
        }
    }
    identity
}

struct OtherApiKeyChoice {
    key: put_prompt::ApiKeyName,
    replace: bool,
}

fn pick_other_api_key(global: &GlobalArgs) -> Result<Option<OtherApiKeyChoice>, CliError> {
    let theme = dialoguer::theme::ColorfulTheme::default();
    let key = put_prompt::api_key_name(&theme)?;
    let inventory = parse_inventory(&request_admin_status(global)?)?;
    let replace = inventory.iter().any(|row| row.2 == key.id());
    if replace && !put_prompt::confirm_replacement(&theme, key.id())? {
        return Ok(None);
    }
    Ok(Some(OtherApiKeyChoice { key, replace }))
}

fn cmd_other_api_key_login(
    global: &GlobalArgs,
    args: &[String],
    choice: &OtherApiKeyChoice,
) -> Result<(), CliError> {
    let id = choice.key.id();
    let replace = choice.replace;
    let preflighted_key = preflight_login(
        global,
        id,
        replace,
        format!("{id} already holds a credential."),
    )?;
    if !put_prompt::provider(global, id)? {
        return Ok(());
    }
    println!("{}", api_key_login::NO_FREE_CHECK_MESSAGE);
    let name = choice.key.name();
    let key = dialoguer::Password::new()
        .with_prompt(format!("Enter API key for {name}"))
        .interact()
        .map_err(|e| CliError::Io(format!("reading API key: {e}")))?;
    let record = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "login",
        key.trim().as_bytes().to_vec(),
        None,
    );
    let (audit_op, store_mode) = if replace {
        (AdminAuditOp::Overwrite, StoreMode::ReplaceUnconditional)
    } else {
        (AdminAuditOp::Put, StoreMode::Create)
    };
    commit_login_admin(
        global,
        store_op(id, record, audit_op, store_mode),
        preflighted_key,
        args,
    )?;
    println!(
        "logged in and {} {id}",
        if replace { "replaced" } else { "stored" }
    );
    Ok(())
}

const GATEWAY_KINDS: &[(&str, &str, &str)] = &[
    ("LiteLLM", "authorization", "bearer"),
    ("Portkey", "x-portkey-api-key", "raw"),
    ("Cloudflare AI Gateway", "cf-aig-authorization", "bearer"),
    ("Other", "", ""),
];

fn print_unchecked_api_key_note(reason: &str) {
    println!("NOTE: storing this API key without checking it: {reason}.");
}

fn gateway_login_vendors() -> Vec<&'static str> {
    let mut ids: Vec<_> = credentials_core::catalog::MODEL_VENDOR_FUSIFORM_IDS
        .iter()
        .map(|(_, id)| *id)
        .collect();
    ids.sort_by_key(|id| (*id != "anthropic", *id));
    ids
}

fn cmd_gateway_login(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    use credentials_core::gateway::{validate_gateway_settings, GatewayAuth, GatewaySettings};
    use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};

    if !args.is_empty() {
        return Err(CliError::Usage(
            "gateway login uses the interactive prompts, not login flags; \
             use `ck auth put` for scripted gateway enrollment"
                .into(),
        ));
    }
    let cancelled = |e| CliError::Usage(format!("interactive gateway login cancelled: {e}"));
    let theme = ColorfulTheme::default();
    let kind = Select::with_theme(&theme)
        .with_prompt("Gateway kind")
        .items(GATEWAY_KINDS.iter().map(|(name, _, _)| *name))
        .default(0)
        .interact()
        .map_err(cancelled)?;
    let (_, header, scheme) = GATEWAY_KINDS[kind];
    let mut settings = GatewaySettings {
        base_url: "http://localhost".into(),
        auth: GatewayAuth {
            header: header.into(),
            scheme: scheme.into(),
        },
        headers: Vec::new(),
    };
    // Use a valid placeholder id until the vendor and name prompts. Every field
    // is checked by the store's validator, including partially collected settings.
    let preview_id = "apikey:anthropic-gw-preview";
    let preview_providers = vec!["anthropic-gw-preview".to_string()];
    if header.is_empty() {
        settings.auth.scheme = "bearer".into();
        let header: String = Input::with_theme(&theme)
            .with_prompt("Key header name")
            .validate_with(|value: &String| {
                let mut candidate = settings.clone();
                candidate.auth.header = value.to_ascii_lowercase();
                validate_gateway_settings(preview_id, &candidate, &preview_providers).map(|_| ())
            })
            .interact_text()
            .map_err(cancelled)?;
        settings.auth.header = header.to_ascii_lowercase();
        let schemes = ["bearer", "raw"];
        let scheme = Select::with_theme(&theme)
            .with_prompt("Key header scheme")
            .items(schemes)
            .default(0)
            .interact()
            .map_err(cancelled)?;
        settings.auth.scheme = schemes[scheme].into();
    }
    let base_url: String = Input::with_theme(&theme)
        .with_prompt("Gateway base URL")
        .validate_with(|value: &String| {
            let mut candidate = settings.clone();
            candidate.base_url = normalize_gateway_base_url(value);
            validate_gateway_settings(preview_id, &candidate, &preview_providers).map(|_| ())
        })
        .interact_text()
        .map_err(cancelled)?;
    settings.base_url = normalize_gateway_base_url(&base_url);
    println!("Fixed headers must be non-secret; enter name=value, or an empty line to finish.");
    loop {
        let mut candidate = settings.clone();
        let line: String = Input::with_theme(&theme)
            .with_prompt("Fixed header (empty to finish)")
            .allow_empty(true)
            .validate_with(|value: &String| {
                if value.is_empty() {
                    return Ok(());
                }
                let mut next = settings.clone();
                next.headers.push(parse_gateway_header(value)?);
                next.headers.sort_by(|a, b| a.name.cmp(&b.name));
                validate_gateway_settings(preview_id, &next, &preview_providers)
                    .map_err(CliError::Store)?;
                candidate = next;
                Ok::<_, CliError>(())
            })
            .interact_text()
            .map_err(cancelled)?;
        if line.is_empty() {
            break;
        }
        settings = candidate;
    }
    let vendors = gateway_login_vendors();
    let vendor = Select::with_theme(&theme)
        .with_prompt("Whose models does the gateway serve?")
        .items(&vendors)
        .default(0)
        .interact()
        .map_err(cancelled)?;
    let (id, provider_ids, preflighted_key) = loop {
        let name: String = Input::with_theme(&theme)
            .with_prompt("Gateway name (lowercase letters, digits, hyphens; starts with a letter)")
            .validate_with(|name: &String| {
                let provider = format!("{}-gw-{name}", vendors[vendor]);
                validate_gateway_settings(&format!("apikey:{provider}"), &settings, &[provider])
                    .map(|_| ())
            })
            .interact_text()
            .map_err(cancelled)?;
        let provider = format!("{}-gw-{name}", vendors[vendor]);
        let id = format!("apikey:{provider}");
        match preflight_login(
            global,
            &id,
            false,
            format!("{id} already exists; choose another name."),
        ) {
            Ok(key) => break (id, vec![provider], key),
            Err(CliError::Usage(message)) => println!("{message}"),
            Err(error) => return Err(error),
        }
    };
    println!("{}", api_key_login::NO_FREE_CHECK_MESSAGE);
    let key = Password::new()
        .with_prompt("Enter gateway API key")
        .interact()
        .map_err(|e| CliError::Io(format!("reading gateway API key: {e}")))?;
    println!("Credential: {id}");
    println!("Base URL: {}", settings.base_url);
    println!(
        "Key auth: {} ({})",
        settings.auth.header, settings.auth.scheme
    );
    println!("Category: llm-gateway");
    for header in &settings.headers {
        println!("Fixed header: {}={}", header.name, header.value);
    }
    if !Confirm::with_theme(&theme)
        .with_prompt("Store this gateway credential?")
        .default(false)
        .interact()
        .map_err(cancelled)?
    {
        println!("Gateway login cancelled; nothing stored.");
        return Ok(());
    }
    let record = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "login",
        key.trim().as_bytes().to_vec(),
        None,
    );
    print_unchecked_api_key_note("company gateways have no shared free key-check endpoint");
    commit_admin_with_key(
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
            provider_ids,
        },
        Some(preflighted_key),
    )?;
    println!("logged in and stored {id}");
    Ok(())
}

pub(super) fn cmd_login(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let explicit_ids = provider_id_flags(args)?;
    let explicit_id = optional(args, "--id");
    check_deposit_provider_flags(explicit_id.as_deref(), &explicit_ids)?;
    use credentials_core::oauth_login::{
        access_token_expiry_ms, exchange_authorization_code, exchange_authorization_code_form,
        generate_pkce, generate_state,
    };

    // With --provider the flow is fully flag-driven (scriptable); without it, the
    // interactive picker owns provider + id + replace selection.
    let interactive = match optional(args, "--provider") {
        Some(provider) => InteractiveChoice {
            provider,
            id_override: None,
            replace: false,
        },
        None if !std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
            return Err(CliError::Usage(
                "login without a terminal needs --provider <name>".into(),
            ));
        }
        None => pick_login_interactively(global, args)?,
    };
    if optional(args, "--provider").is_none() && interactive.provider == COMPANY_AI_GATEWAY {
        return cmd_gateway_login(global, args);
    }
    let from_other =
        optional(args, "--provider").is_none() && interactive.provider == OTHER_API_KEY_PROVIDER;
    let other = if from_other {
        let Some(choice) = pick_other_api_key(global)? else {
            return Ok(());
        };
        Some(choice)
    } else {
        None
    };
    let picked_id = other
        .as_ref()
        .map(|choice| choice.key.id())
        .or(interactive.id_override.as_deref());
    if let (Some(explicit), Some(picked)) = (explicit_id.as_deref(), picked_id) {
        if explicit != picked {
            return Err(CliError::Usage(format!(
                "login picker selected '{picked}', but --id names '{explicit}'"
            )));
        }
    }
    let provider = match &other {
        Some(choice) => parse_credential_id(choice.key.id()).provider.to_string(),
        None => interactive.provider.clone(),
    };
    google_login::validate_client_flags(args, &provider)?;

    // Resolve the target credential id BEFORE routing so the dispatch can key on the
    // credential METHOD, not the bare provider name. openai/xai/google each name both
    // an OAuth login (chatgpt:openai / oauth:xai / oauth:google) and an api-key row
    // (apikey:*). Use the supplied or picked id (which must agree when both are
    // present), or the provider default when neither is set.
    // Route to the api-key branch when the provider has ONLY an
    // api-key login, OR it has both AND the resolved id is explicitly an `apikey:` id.
    // (Gating purely on the id's method would send a malformed `--id zai` for an
    // api-key-only provider to the "unknown provider" path instead of the helpful
    // id-rail error.)
    let target_id = explicit_id
        .as_deref()
        .or(picked_id)
        .map(str::to_owned)
        .unwrap_or_else(|| default_login_id(&provider));
    let has_oauth_login =
        login_provider(&provider).is_some() || google_login::is_provider(&provider);
    let apikey_row = api_key_login::API_KEY_PROVIDERS
        .iter()
        .find(|p| p.key == provider);
    let route_api_key =
        apikey_row.is_some() && (!has_oauth_login || target_id.starts_with("apikey:"));

    // `--account-id` is checked here, before any prompt, preflight or network call, so
    // a script that passes it to the wrong provider, or passes a malformed id, fails
    // without side effects. Only an API-key row with an `account_id_prompt` takes one;
    // every other login (OAuth, device, browser) would otherwise ignore it silently.
    let account_id_flag = optional(args, "--account-id").map(|v| v.trim().to_string());
    if let Some(flag) = account_id_flag.as_deref() {
        match apikey_row.filter(|_| route_api_key) {
            Some(row) => {
                api_key_login::check_account_id(row, Some(flag)).map_err(CliError::Usage)?
            }
            None => {
                return Err(CliError::Usage(format!(
                    "--account-id does not apply to '{provider}': only providers whose login \
                     asks for an account id take one"
                )))
            }
        }
    }

    if let Some(choice) = other.as_ref().filter(|_| apikey_row.is_none()) {
        return cmd_other_api_key_login(global, args, choice);
    }

    if !route_api_key && google_login::is_provider(&provider) {
        return google_login::cmd_login(
            global,
            args,
            &provider,
            interactive.id_override,
            interactive.replace,
        );
    }

    if route_api_key {
        let p = apikey_row.expect("route_api_key implies an api-key row");
        let id = target_id.clone();
        if !login_id_is_valid(p.default_id, &id) {
            return Err(CliError::Usage(format!(
                "login --id must be '{d}' or '{d}:<label>' (a labeled account of the same \
                 provider, e.g. '{d}:work') — got '{id}'",
                d = p.default_id
            )));
        }

        let replace = match &other {
            Some(choice) => choice.replace,
            None => login_replace(args, interactive.replace),
        };
        let preflighted_key = preflight_login(
            global,
            &id,
            replace,
            format!(
                "'{id}' already holds a credential.\n\
                 To add ANOTHER account for this provider:  login --provider {provider} --id {d}:<label>\n\
                 (e.g. --id {d}:work — each labeled id is an independent credential)\n\
                 To REPLACE the existing credential:        login --provider {provider} --replace\n\
                 (keeps the id, its handles, and bumps record_version)",
                d = p.default_id
            ),
        )?;

        if matches!(
            p.validation,
            api_key_login::KeyValidation::Unvalidated { .. }
        ) {
            println!("{}", api_key_login::NO_FREE_CHECK_MESSAGE);
        }
        let key = if let Some(path) = optional(args, "--payload-file") {
            super::credential_cli::read_key_file(&path)?
        } else {
            use dialoguer::Password;
            let prompt = format!(
                "Enter API key for {} ({}; dashboard: {})",
                p.display_name, p.placeholder, p.dashboard_url
            );
            Password::new()
                .with_prompt(prompt)
                .interact()
                .map_err(|e| CliError::Io(format!("reading API key: {e}")))?
                .trim()
                .to_string()
        };

        // The account id is NOT secret, so it is read as visible input, after the key.
        // It is checked against the row's format before the probe below, which builds
        // its URL from it.
        let account_id = match (p.account_id_prompt, account_id_flag) {
            (None, _) => None,
            (Some(_), Some(flag)) => Some(flag),
            (Some(prompt), None) => {
                let value: String = dialoguer::Input::new()
                    .with_prompt(prompt.label)
                    .interact_text()
                    .map_err(|e| {
                        CliError::Usage(format!(
                            "reading the account id: {e}; pass --account-id <id> when \
                             running without a terminal"
                        ))
                    })?;
                Some(value.trim().to_string())
            }
        };
        api_key_login::check_account_id(p, account_id.as_deref()).map_err(CliError::Usage)?;

        if !matches!(
            p.validation,
            api_key_login::KeyValidation::Unvalidated { .. }
        ) {
            println!("Validating API key...");
        }
        let http = credentials_core::http::ReqwestTransport::new()
            .map_err(|e| CliError::Io(e.to_string()))?;
        let outcome = tokio_block_on(api_key_login::check_login_key(
            &http,
            p,
            &key,
            account_id.as_deref(),
        ))
        .map_err(CliError::Usage)?;
        match outcome {
            api_key_login::ValidationOutcome::Valid => {
                println!("API key is valid.");
            }
            api_key_login::ValidationOutcome::Invalid(err) => {
                return Err(CliError::Usage(format!("API key validation failed: {err}")));
            }
            api_key_login::ValidationOutcome::Warning(warn) => {
                println!("WARNING: API key validation could not be completed: {warn}. Storing the key anyway.");
            }
            api_key_login::ValidationOutcome::Unchecked(reason) => {
                print_unchecked_api_key_note(reason);
            }
        }

        let record =
            VaultRecord::new_static(CredentialKind::ApiKey, "login", key.into_bytes(), None);
        // The account id becomes the record's identity, which the read surface serves as
        // `identity.account_id` on `credential.get_scoped` and `credential.list_scoped`:
        // consumers such as Broca need it to build the provider's request URLs.
        let record = match account_id {
            Some(account_id) => record.with_identity(RecordIdentity {
                account_id: Some(account_id),
                email: None,
                org_name: None,
            }),
            None => record,
        };

        let (audit_op, store_mode) = if replace {
            (AdminAuditOp::Overwrite, StoreMode::ReplaceUnconditional)
        } else {
            (AdminAuditOp::Put, StoreMode::Create)
        };

        if replace {
            commit_login_admin(
                global,
                store_op(&id, record, audit_op, store_mode),
                preflighted_key,
                args,
            )?;
            println!("logged in and replaced {id}");
        } else {
            let result = commit_login_admin(
                global,
                store_op(&id, record, audit_op, store_mode),
                preflighted_key,
                args,
            );
            let already_exists = result.as_ref().is_err_and(CliError::is_already_exists);
            if already_exists {
                return Err(CliError::Usage(format!(
                    "'{id}' already holds a credential.\n\
                     To add ANOTHER account for this provider:  login --provider {p} --id {d}:<label>\n\
                     (e.g. --id {d}:work — each labeled id is an independent credential)\n\
                     To REPLACE the existing credential:        login --provider {p} --replace\n\
                     (keeps the id, its handles, and bumps record_version)",
                    p = provider,
                    d = p.default_id
                )));
            }
            result?;
            println!("logged in and stored {id}");
        }

        // No follow-up hint: consumers reach a new key through their category or exact
        // grant, so pointing at `mint-handle` here steered operators to the legacy path.
        return Ok(());
    }

    // The proprietary browser-poll / callback flows (Cursor, Devin, Snowflake,
    // DigitalOcean) run their own driver, which returns None for any other provider.
    let mut special_key = None;
    if let Some(special) = provider_login::run(
        &provider,
        args,
        interactive.id_override.as_deref(),
        interactive.replace,
        &mut |id, replace| {
            special_key = Some(preflight_login(
                global,
                id,
                replace,
                format!("'{id}' already holds a credential; use --replace"),
            )?);
            Ok(())
        },
    )? {
        let mode = if special.replace {
            StoreMode::ReplaceUnconditional
        } else {
            StoreMode::Create
        };
        let receipt = special.receipt();
        commit_login_admin(
            global,
            store_op(&special.id, special.record, AdminAuditOp::Login, mode),
            special_key.expect("special login ran preflight"),
            args,
        )?;
        println!("logged in and {receipt} {}", special.id);
        return Ok(());
    }

    // Each provider's auth-code wire is checked against that provider's own
    // documentation before it is added to login_provider().
    let Some(wire) = login_provider(&provider) else {
        return Err(CliError::Usage(format!(
            "unknown --provider '{provider}'; run `ck auth login` with no flags \
             to pick from the full provider list"
        )));
    };
    // The method-resolved target id (same precedence as the api-key branch).
    let id = target_id;
    // Multi-account rail: --id must be the provider's default id or a labeled
    // sub-account of it (`<default_id>:<label>`). A free-form id here would silently
    // create a mis-keyed credential (wrong method segment ⇒ wrong adapter routing,
    // ugly inventory) — the exact footgun this validation exists to close.
    if !login_id_is_valid(wire.default_id, &id) {
        return Err(CliError::Usage(format!(
            "login --id must be '{d}' or '{d}:<label>' (a labeled account of the same \
             provider, e.g. '{d}:work') — got '{id}'",
            d = wire.default_id
        )));
    }

    let requested_device = has_flag(args, "--device");
    if requested_device && wire.device.is_none() {
        return Err(CliError::Usage(format!(
            "provider '{provider}' has no device login; omit --device"
        )));
    }
    if uses_device_login(wire, requested_device) {
        return cmd_device_login(
            global,
            args,
            &provider,
            &id,
            wire,
            login_replace(args, interactive.replace),
        );
    }

    #[cfg(all(debug_assertions, feature = "test-support"))]
    let wire = &browser_login::test_wire(wire);
    let approve_on = browser_login::approve_on(args)?;
    let replace = login_replace(args, interactive.replace);
    let preflighted_key = preflight_login(
        global,
        &id,
        replace,
        format!(
            "'{id}' already holds a credential.\n\
             To add ANOTHER account for this provider:  login --provider {provider} --id {d}:<label>\n\
             (e.g. --id {d}:work — each labeled id is an independent credential)\n\
             To REPLACE the existing credential:        login --provider {provider} --replace\n\
             (keeps the id, its handles, and bumps record_version)",
            d = wire.default_id
        ),
    )?;

    // Generate the PKCE pair and the random state from the operating system's secure
    // random generator (state is independent of the verifier), pick the wire, build the
    // authorize URL, and present it to the operator.
    let pkce = generate_pkce().map_err(|e| CliError::Io(format!("csprng: {e}")))?;
    let state = generate_state().map_err(|e| CliError::Io(format!("csprng: {e}")))?;
    // An OIDC provider (xAI) requires a fresh per-flow nonce in the authorize request;
    // it is freshly random per login and appended as an extra authorize param. The vault does
    // not consume the id_token, so the nonce is not verified — it only satisfies the
    // provider's authorize contract.
    let nonce = if wire.needs_oidc_nonce {
        Some(generate_state().map_err(|e| CliError::Io(format!("csprng: {e}")))?)
    } else {
        None
    };
    let mut authorize_params: Vec<(&str, &str)> = wire.extra_authorize_params.to_vec();
    if let Some(nonce) = nonce.as_deref() {
        authorize_params.push(("nonce", nonce));
    }

    // Bind before building the URL: providers with a code-display redirect use it
    // when there is no listener. Explicitly choosing this computer overrides the
    // headless default, but --no-listener still disables the socket.
    let listener =
        if approve_on == browser_login::ApproveOn::Other || has_flag(args, "--no-listener") {
            None
        } else {
            login_listener::loopback_bind_addr(wire.redirect_uri)
                .and_then(|addr| login_listener::capture_callback(&addr))
        };
    #[cfg(all(debug_assertions, feature = "test-support"))]
    let wire = &browser_login::test_wire_for_listener(wire, listener.as_ref())?;

    // ONE redirect for the whole flow. The token exchange replays the redirect, and
    // the provider refuses the exchange unless it byte-matches the one in the
    // authorize URL — a refusal that lands AFTER the operator has already approved in
    // the browser, which is the most expensive place to fail. So the authorize URL
    // and both exchange arms below read this plan, and nothing past here works out a
    // redirect of its own.
    let plan = login_wire::plan_login_wire(
        wire,
        listener.is_some(),
        &pkce.challenge,
        &state,
        &authorize_params,
    )
    .map_err(|e| CliError::Io(format!("building authorize url: {e}")))?;

    println!("Open this URL in a browser signed into the account to custody:");
    println!();
    println!("  {}", plan.authorize_url);
    println!();
    browser_login::choose_and_present(args, approve_on, &plan.authorize_url)?;
    let callback = tokio_block_on(browser_login::read_callback(
        listener,
        plan.redirect_uri,
        plan.paste_prompt,
        &state,
    ))?;

    // Exchange the code for tokens over the provider's wire. State is validated
    // inside (before any network call), so a forged/stale callback is refused up
    // front.
    let http =
        credentials_core::http::ReqwestTransport::new().map_err(|e| CliError::Io(e.to_string()))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let tokens = match wire.exchange {
        ExchangeWire::AnthropicJson => tokio_block_on(exchange_authorization_code(
            &http,
            wire.token_url,
            wire.client_id,
            plan.redirect_uri,
            &callback,
            &state,
            &pkce.verifier,
            now_ms,
        )),
        ExchangeWire::RfcForm => {
            // xAI's public-client token endpoint echoes the PKCE challenge in the
            // exchange body (alongside the verifier); OpenAI sends none.
            let extra_body: &[(&str, &str)] = if wire.exchange_echoes_challenge {
                &[
                    ("code_challenge", &pkce.challenge),
                    ("code_challenge_method", "S256"),
                ]
            } else {
                &[]
            };
            tokio_block_on(exchange_authorization_code_form(
                &http,
                wire.token_url,
                wire.client_id,
                plan.redirect_uri,
                &callback,
                &state,
                &pkce.verifier,
                extra_body,
                now_ms,
            ))
        }
    }
    .map_err(|e| CliError::Io(e.to_string()))?;

    // The OpenAI browser-flow exchange returns no expires_in; the access token is a
    // JWT carrying its own `exp` (seconds). Fall back to it so the refresh engine
    // sees the real expiry instead of never-expires (the official codex CLI reads
    // the same claim).
    let expires_at_ms = tokens
        .expires_at_ms
        .or_else(|| access_token_expiry_ms(&tokens.access_token));

    let identity = login_identity(&provider, &tokens);

    // Build the canonical oauth credential + record. token_url and client_id are
    // stored on the record so the refresh path uses the same endpoint/client that
    // minted this token.
    let oauth = credentials_core::oauth::OAuthCredential {
        access_token: tokens.access_token.clone().into(),
        refresh_token: tokens.refresh_token.clone().into(),
        expires_at_ms,
        token_url: wire.token_url.to_string(),
        client_id: Some(wire.client_id.to_string()),
        client_secret: None,
        scopes: wire.scopes.iter().map(|s| s.to_string()).collect(),
    };
    let payload =
        credentials_core::secret::SecretBytes::new(oauth.access_token.expose().as_bytes().to_vec());
    let mut record =
        VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload).with_identity(identity);
    if wire.adapter_name == "anthropic"
        && tokio_block_on(credentials_core::plan_detection::detect_login_plan(
            &http,
            &mut record,
        ))
        .is_err()
    {
        println!(
            "NOTE: subscription profile unavailable; storing login without a newly detected tier."
        );
    }

    // Login records a distinct `Login` audit op (not `Import`) so forensics can tell
    // a native mint from a foreign import. `--replace` overwrites an existing id (the
    // dual-custody migration: swap the imported token for the vault-minted one; the
    // handle survives). With `--subc` the commit rides the RUNNING module, so a
    // re-login needs no daemon stop at all (the zero-downtime path).
    if replace {
        commit_login_admin(
            global,
            store_op(
                &id,
                record,
                AdminAuditOp::Login,
                StoreMode::ReplaceUnconditional,
            ),
            preflighted_key,
            args,
        )?;
        println!("logged in and replaced {id}");
    } else {
        let result = commit_login_admin(
            global,
            store_op(&id, record, AdminAuditOp::Login, StoreMode::Create),
            preflighted_key,
            args,
        );
        // The create-only refusal must not be a dead end: name both ways forward
        // (another account under a label, or swapping this credential). The route
        // path surfaces the same refusal as a RouteRefused string, so match both.
        let already_exists = result.as_ref().is_err_and(CliError::is_already_exists);
        if already_exists {
            return Err(CliError::Usage(format!(
                "'{id}' already holds a credential.\n\
                 To add ANOTHER account for this provider:  login --provider {p} --id {d}:<label>\n\
                 (e.g. --id {d}:work — each labeled id is an independent credential)\n\
                 To REPLACE the existing credential:        login --provider {p} --replace\n\
                 (keeps the id, its handles, and bumps record_version)",
                p = provider,
                d = wire.default_id
            )));
        }
        result?;
        println!("logged in and stored {id}");
    }
    Ok(())
}

/// `logout` = stop serving a credential, reversibly: retire + revoke all its handles
/// (the compound atomic op), keeping the row and its audit chain. Re-login
/// restores it (`login --provider <p> --replace`). Deliberately NOT a delete — a
/// logout must never destroy an audit trail. `--provider <p>` resolves to the same
/// default id `login --provider <p>` writes, except Snowflake, where all account ids
/// are retired. `--id` names any credential directly.
pub(super) fn cmd_logout(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = match (optional(args, "--id"), optional(args, "--provider")) {
        (Some(_), Some(_)) => {
            return Err(CliError::Usage(
                "pass only one of --id or --provider".to_string(),
            ))
        }
        (Some(id), None) => id,
        // Resolve the same way `login` does (OAuth/subscription wins for openai/
        // xai/google, which each also have an api-key row): `logout --provider openai`
        // targets the ChatGPT subscription credential, and the api-key one is reached
        // with `logout --id apikey:openai`. A provider with no known login is rejected.
        (None, Some(provider)) => {
            let id = default_login_id(&provider);
            if id == provider {
                return Err(CliError::Usage(format!(
                    "unknown login provider '{provider}'; pass --id <id> for other credentials"
                )));
            }
            id
        }
        (None, None) => {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                return logout_interactively(global);
            }
            return Err(CliError::Usage(
                "--provider <p> or --id <id> is required\nRun `ck auth logout` in a terminal to choose a credential from a picker.".to_string(),
            ));
        }
    };
    let ids = if optional(args, "--provider").as_deref() == Some("snowflake") {
        let status = request_admin_status(global)?;
        parse_inventory(&status)?
            .into_iter()
            .filter_map(|(_, _, id, _, _)| id.starts_with("oauth:snowflake:").then_some(id))
            .collect::<Vec<_>>()
    } else {
        vec![id]
    };
    if ids.is_empty() {
        println!("no Snowflake credentials are present: nothing changed");
    }
    for id in ids {
        logout_id(global, &id)?;
    }
    Ok(())
}

fn logout_interactively(global: &GlobalArgs) -> Result<(), CliError> {
    use dialoguer::{theme::ColorfulTheme, Confirm, FuzzySelect};

    let status = request_admin_status(global)?;
    let mut credentials: Vec<_> = parse_inventory(&status)?
        .into_iter()
        .filter(|(state, _, id, _, _)| {
            matches!(state.as_str(), "active" | "needs_reauth")
                // Vault-held keys are infrastructure, not login sessions. Require an
                // explicit id so a fuzzy selection cannot retire one by accident.
                && !id.starts_with("signing:")
                && !id.starts_with("kem:")
        })
        .collect();
    credentials.sort_by(|a, b| a.2.cmp(&b.2));
    if credentials.is_empty() {
        println!("No credentials are eligible for interactive logout.");
        return Ok(());
    }

    let items: Vec<_> = credentials
        .iter()
        .map(|(state, _, id, _, _)| format!("{id}  ({state})"))
        .collect();
    let theme = ColorfulTheme::default();
    let prompt_error = |error| CliError::Io(format!("interactive logout cancelled: {error}"));
    let selected = FuzzySelect::with_theme(&theme)
        .with_prompt("Select a credential to log out (type to search)")
        .items(&items)
        .default(0)
        .interact()
        .map_err(prompt_error)?;
    let id = &credentials[selected].2;
    println!("Logging out {id} stops it serving now and revokes all its capability handles.");
    println!("`ck auth reactivate --id {id}` or logging in again restores the credential,");
    println!("but revoked handles stay revoked.");
    if !Confirm::with_theme(&theme)
        .with_prompt(format!("Log out {id}?"))
        .default(false)
        .interact()
        .map_err(prompt_error)?
    {
        println!("Logout cancelled; nothing changed.");
        return Ok(());
    }
    logout_id(global, id)
}

fn logout_id(global: &GlobalArgs, id: &str) -> Result<(), CliError> {
    let result = commit_admin(
        global,
        AdminOpBody::Logout {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.to_string(),
        },
    )?;
    let revoked = result["handles_revoked"].as_u64().unwrap_or(0);
    let state_changed = result["state_changed"].as_bool().unwrap_or(true);
    let intent_cleared = result["intent_cleared"].as_bool().unwrap_or(false);

    if state_changed {
        println!("logged out {id}: retired, stopped serving, revoked {revoked} handle(s)");
        println!(
            "  reversible: `login --provider <p> --replace` or `reactivate --id {id}` restores it."
        );
        println!("  it stays listed as retired, but is not counted as a degraded health signal.");
    } else if intent_cleared || revoked > 0 {
        println!("logged out {id}: stopped serving, revoked {revoked} handle(s)");
        println!("  its lifecycle state did not change; inspect `ck auth status` for the recorded state.");
    } else {
        println!("{id} was already retired, absent, or corrupt: nothing changed");
        println!(
            "  retired rows stay listed because logout is reversible; remove deletes the row."
        );
    }
    Ok(())
}

#[cfg(test)]
mod login_regressions {
    use super::*;

    #[test]
    fn snowflake_new_accounts_defer_id_until_account_is_known() {
        assert_eq!(new_login_id("snowflake", "oauth:snowflake", None), None);
        assert_eq!(
            new_login_id("snowflake", "oauth:snowflake", Some("work")),
            None
        );
        assert_eq!(
            new_login_id("openai", "apikey:openai", None).as_deref(),
            Some("apikey:openai")
        );
    }

    #[test]
    fn interactive_replace_is_forwarded_to_login_drivers() {
        assert!(login_replace(&[], true));
        assert!(!login_replace(&[], false));
        assert!(login_replace(&["--replace".into()], false));
    }

    #[test]
    fn gateway_login_vendor_menu_and_kind_presets_match_the_contract() {
        assert_eq!(
            gateway_login_vendors(),
            [
                "anthropic",
                "alibaba",
                "deepseek",
                "google",
                "inception",
                "meta",
                "minimax",
                "mistral",
                "moonshotai",
                "nvidia",
                "openai",
                "perplexity",
                "stepfun-ai",
                "xai",
                "xiaomi",
                "zhipuai",
            ]
        );
        assert_eq!(
            GATEWAY_KINDS,
            [
                ("LiteLLM", "authorization", "bearer"),
                ("Portkey", "x-portkey-api-key", "raw"),
                ("Cloudflare AI Gateway", "cf-aig-authorization", "bearer"),
                ("Other", "", ""),
            ]
        );
        let help = help_verb("login");
        assert!(help.contains("Gateway enrollment is picker-only"));
        assert!(usage_short().contains("picker also enrolls gateways"));
    }

    #[test]
    fn set_plan_help_and_verb_row_describe_the_optional_start_date() {
        let help = help_verb("set-plan");
        for text in [
            "--since",
            "YYYY-MM-DD",
            "RFC 3339",
            "epoch ms",
            "midnight UTC",
            "omitting it clears",
        ] {
            assert!(help.contains(text), "missing {text}: {help}");
        }
        assert!(help.lines().all(|line| line.len() <= 80), "{help}");
        assert!(usage_short()
            .lines()
            .any(|line| line.contains("set-plan") && line.contains("start date")));
    }

    #[test]
    fn set_plan_since_parses_dates_offsets_and_epoch_milliseconds() {
        for value in [
            "2025-01-01",
            "2025-01-01T00:00:00Z",
            "2025-01-01T01:00:00+01:00",
            "1735689600000",
        ] {
            assert_eq!(parse_plan_since(value).unwrap(), 1_735_689_600_000);
        }
        for value in [
            "",
            "0",
            "-1",
            "1.5",
            "2025-02-30",
            "2025-01-01T00:00:00",
            "9999-01-01",
            "9007199254740992",
        ] {
            assert!(parse_plan_since(value).is_err(), "{value}");
        }
    }

    /// The picker is the only way an operator who runs a bare `ck auth login` reaches a
    /// provider, so a catalog row it does not list is unreachable interactively.
    #[test]
    fn the_login_picker_offers_cloudflare_workers_ai() {
        let rows = login_picker_rows();
        assert!(
            rows.iter()
                .any(|(key, name, default_id)| key == "cloudflare-workers-ai"
                    && name == "Cloudflare Workers AI"
                    && default_id == "apikey:cloudflare-workers-ai"),
            "picker rows: {rows:?}"
        );
    }

    #[test]
    fn the_login_picker_keeps_all_rows_and_appends_other_api_key_provider() {
        let rows = login_picker_rows();
        let expected: Vec<_> = LOGIN_PICKER_ROWS
            .iter()
            .map(|(key, name)| {
                (
                    key.to_string(),
                    name.to_string(),
                    login_provider(key).unwrap().default_id.to_string(),
                )
            })
            .chain(api_key_login::API_KEY_PROVIDERS.iter().map(|row| {
                (
                    row.key.to_string(),
                    row.display_name.to_string(),
                    row.default_id.to_string(),
                )
            }))
            .collect();
        assert_eq!(&rows[..rows.len() - 2], expected);
        assert_eq!(
            rows[rows.len() - 2],
            (
                COMPANY_AI_GATEWAY.to_string(),
                "Company AI gateway (LiteLLM, Portkey, Cloudflare)".to_string(),
                String::new(),
            )
        );
        assert!(rows.contains(&(
            "elevenlabs".into(),
            "ElevenLabs".into(),
            "apikey:elevenlabs".into(),
        )));
        for (key, name) in [
            ("iteracompute", "IteraCompute"),
            ("kilo", "Kilo Gateway"),
            ("minimax-cn", "MiniMax (minimax.cn)"),
            ("mixlayer", "Mixlayer"),
            ("moark", "Moark"),
            ("model-oracle-ai", "Model Oracle AI"),
            ("modular", "Modular"),
            ("moonshotai-cn", "Moonshot AI (China)"),
            ("morph", "Morph"),
            ("munito", "Munito AI"),
            ("munito-eu", "Munito AI (EU)"),
            ("nan", "NaN"),
            ("nearai", "NEAR AI Cloud"),
            ("nebius", "Nebius Token Factory"),
            ("neuralwatt", "Neuralwatt"),
            ("ofox", "Ofox"),
            ("opper", "Opper"),
            ("orcarouter", "OrcaRouter"),
            ("ovhcloud", "OVHcloud AI Endpoints"),
            ("pareto", "Pareto Inference"),
            ("pendra", "Pendra"),
            ("perplexity-agent", "Perplexity Agent"),
            ("pioneer", "Pioneer"),
            ("poe", "Poe"),
            ("prime", "Prime Inference"),
            ("privatemode-ai", "Privatemode AI"),
            ("qiniu-ai", "Qiniu"),
            ("reflection", "Reflection"),
            ("requesty", "Requesty"),
            ("runinfra", "RunInfra"),
            ("salad-cloud", "SaladCloud AI Gateway"),
            ("sambanova", "SambaNova"),
            ("sarvam", "Sarvam AI"),
            ("standardcompute", "Standard Compute"),
            ("stepfun-cn", "StepFun (China)"),
            ("stepfun-ai-step-plan", "StepFun Step Plan (Global)"),
            ("stepfun-step-plan", "StepFun Step Plan (China)"),
            ("subconscious", "Subconscious"),
            ("submodel", "submodel"),
            ("tempr", "Tempr Gateway"),
            ("tensorx", "TensorX"),
            ("the-grid-ai", "The Grid AI"),
            ("thinkingmachines", "Thinking Machines"),
            ("tinfoil", "Tinfoil"),
            ("tokengo", "TokenGo"),
            ("trustedrouter", "TrustedRouter"),
            ("unorouter", "UnoRouter"),
            ("upstage", "Upstage"),
            ("vivgrid", "Vivgrid"),
            ("volcengine", "Volcengine Ark"),
            ("vultr", "Vultr"),
            ("wallaby", "Wallaby"),
            ("wally", "Wally"),
            ("wandb", "CoreWeave"),
            ("xiaomi", "Xiaomi (Standard API)"),
            ("xpersona", "Xpersona"),
            ("zai-api", "Z.AI (Standard API)"),
            ("zeldoc", "Zeldoc"),
            ("zenifra", "Zenifra"),
            ("zhipuai", "Zhipu AI (Standard API)"),
            ("modelis", "Modelis"),
            ("modelscope", "ModelScope"),
            ("poolside", "Poolside"),
            ("regolo-ai", "Regolo AI"),
            ("scaleway", "Scaleway"),
            ("sensenova", "SenseNova (China)"),
            ("stackit", "STACKIT"),
            ("vancine", "Vancine"),
            ("volcengine-coding-plan", "Volcengine Ark Coding Plan"),
            ("byteplus", "BytePlus ModelArk"),
        ] {
            assert!(rows.contains(&(key.into(), name.into(), format!("apikey:{key}"),)));
        }
        assert_eq!(
            rows.last().unwrap(),
            &(
                OTHER_API_KEY_PROVIDER.to_string(),
                "Other API key provider…".to_string(),
                String::new(),
            )
        );
    }

    #[test]
    fn windows_browser_argv_preserves_the_entire_url() {
        let url = "https://example.com/authorize?client_id=public&state=test&redirect_uri=http%3A%2F%2Flocalhost";
        let command = windows_browser_command(url);
        assert_eq!(command.get_program(), "rundll32");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["url.dll,FileProtocolHandler", url]
        );
    }

    #[cfg(unix)]
    #[test]
    fn browser_launcher_returns_without_waiting_for_exit() {
        let start = std::time::Instant::now();
        let mut command = std::process::Command::new("sleep");
        command.arg("2");
        let mut child = spawn_browser(&mut command).unwrap();
        let elapsed = start.elapsed();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "waited {elapsed:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_and_xai_device_records_keep_account_email() {
        use base64::Engine as _;
        let jwt = |claims: &[u8]| {
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims);
            format!("e30.{body}.sig")
        };
        for (provider, id_claims) in [
            ("openai", br#"{"email":"account@example.invalid","https://api.openai.com/auth":{"chatgpt_account_id":"fixture-account"}}"#.as_slice()),
            ("xai", br#"{"email":"account@example.invalid"}"#.as_slice()),
        ] {
            let record = device_oauth_record(
                login_provider(provider).unwrap(),
                credentials_core::device_flow::DeviceTokens {
                    access_token: jwt(br#"{"sub":"fixture-account"}"#),
                    refresh_token: Some("fixture-refresh".into()),
                    id_token: Some(jwt(id_claims)),
                    expires_at_ms: None,
                    expiry_field_present: false,
                },
            )
            .unwrap();
            assert_eq!(
                record.identity.email.as_deref(),
                Some("account@example.invalid")
            );
            assert_eq!(record.identity.account_id.as_deref(), Some("fixture-account"));
        }
    }

    /// The multi-account rail: a login id is the provider default or one labeled
    /// sub-account — any free-form id (e.g. a bare account name) would create a
    /// mis-keyed credential, so it is refused before any browser or network work.
    #[test]
    fn login_id_validation_accepts_default_and_labels_only() {
        // The default id and labeled accounts pass.
        assert!(login_id_is_valid("oauth:anthropic", "oauth:anthropic"));
        assert!(login_id_is_valid("oauth:anthropic", "oauth:anthropic:work"));
        assert!(login_id_is_valid("chatgpt:openai", "chatgpt:openai:gmail"));
        assert!(login_id_is_valid("copilot:github", "copilot:github:work"));
        assert!(login_id_is_valid("oauth:kimi", "oauth:kimi:personal"));
        // Free-form ids are refused (a bare label is not a credential id).
        assert!(!login_id_is_valid("oauth:anthropic", "wwaxpoetic"));
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:xai"));
        // Empty or nested labels are refused.
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:anthropic:"));
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:anthropic:a:b"));
        // A prefix without the separator is refused (not a label).
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:anthropicx"));
    }

    #[test]
    fn google_login_provider_rows_pin_ids_redirects_and_fallback_ports() {
        let gemini = login_provider("google").expect("Gemini CLI row");
        assert_eq!(gemini.default_id, "oauth:google");
        assert_eq!(gemini.redirect_uri, "http://127.0.0.1:8085/oauth2callback");
        assert!(gemini.paste_prompt.contains("8085"));
        assert_eq!(gemini.scopes, credentials_core::google_login::SCOPES);

        let antigravity = login_provider("antigravity").expect("Antigravity row");
        assert_eq!(antigravity.default_id, "antigravity:google");
        assert_eq!(antigravity.redirect_uri, "http://127.0.0.1:51121/callback");
        assert!(antigravity.paste_prompt.contains("51121"));
        assert!(LOGIN_PICKER_ROWS.contains(&("google", "Google Gemini CLI (Code Assist)")));
        assert!(LOGIN_PICKER_ROWS.contains(&("antigravity", "Antigravity (Gemini 3)")));
    }

    #[test]
    fn test_api_key_registration_and_id_rail() {
        // apikey:zai:work passes the id rail for zai (default_id = apikey:zai)
        assert!(login_id_is_valid("apikey:zai", "apikey:zai:work"));
        // --id zai fails it
        assert!(!login_id_is_valid("apikey:zai", "zai"));

        // Check that zai is in API_KEY_PROVIDERS
        let zai_provider = api_key_login::API_KEY_PROVIDERS
            .iter()
            .find(|p| p.key == "zai");
        assert!(zai_provider.is_some());
        let zai = zai_provider.unwrap();
        assert_eq!(zai.default_id, "apikey:zai");

        let kiro = api_key_login::API_KEY_PROVIDERS
            .iter()
            .find(|p| p.key == "kiro")
            .unwrap();
        assert_eq!(default_login_id("kiro"), "apikey:kiro");
        assert_eq!(kiro.default_id, "apikey:kiro");
        assert!(login_id_is_valid(kiro.default_id, "apikey:kiro:work"));
        assert!(!login_id_is_valid(kiro.default_id, "apikey:openai"));
    }

    #[test]
    fn collision_provider_names_default_to_the_oauth_login() {
        // openai / xai / google each name BOTH an OAuth login and an api-key row.
        // A bare `--provider <name>` login must resolve to the OAuth/subscription
        // credential (the "login" semantic), NOT the api-key row — the regression
        // that shadowed the ChatGPT login behind apikey:openai.
        assert_eq!(default_login_id("openai"), "chatgpt:openai");
        assert_eq!(default_login_id("xai"), "oauth:xai");
        assert_eq!(default_login_id("google"), "oauth:google");
        assert_eq!(default_login_id("antigravity"), "antigravity:google");
        assert_eq!(default_login_id("meta"), "oauth:meta");
    }

    /// A login row with no authorize URL can only log in by device code, so it must
    /// reach the device flow without `--device`. Meta shipped routed to the browser
    /// flow, and `ck auth login` died building an authorize URL from "".
    #[test]
    fn every_device_only_login_row_routes_to_the_device_flow() {
        let mut device_only = Vec::new();
        for row in credentials_core::catalog::LOGIN_PROVIDERS {
            if row.authorize_url.is_empty() {
                assert!(
                    row.device.is_some(),
                    "{}: no authorize URL and no device login, so it cannot log in",
                    row.key
                );
                assert!(uses_device_login(row, false), "{}", row.key);
                device_only.push(row.key);
            } else {
                assert!(!uses_device_login(row, false), "{}", row.key);
                assert!(uses_device_login(row, true), "{}", row.key);
            }
        }
        assert_eq!(device_only, ["github-copilot", "kimi", "meta"]);
        assert!(LOGIN_PICKER_ROWS.contains(&("meta", "Meta Muse (coding subscription)")));
        // anthropic has an api-key row too; the bare name stays the subscription login.
        assert_eq!(default_login_id("anthropic"), "oauth:anthropic");
        // api-key-only providers resolve to their apikey: id.
        assert_eq!(default_login_id("zai"), "apikey:zai");
        assert_eq!(default_login_id("openrouter"), "apikey:openrouter");
        // The routing discriminator: the OAuth defaults are NOT api-key ids, so the
        // dispatch sends them to the OAuth path; the api-key-only ones ARE.
        assert!(!default_login_id("openai").starts_with("apikey:"));
        assert!(!default_login_id("xai").starts_with("apikey:"));
        assert!(default_login_id("zai").starts_with("apikey:"));
        // An unknown provider returns itself unchanged (so the dispatch surfaces the
        // proper "unknown provider" error rather than mis-routing).
        assert_eq!(
            default_login_id("nope-not-a-provider"),
            "nope-not-a-provider"
        );
    }
}
