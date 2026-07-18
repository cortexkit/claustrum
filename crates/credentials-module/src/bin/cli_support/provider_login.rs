//! CLI drivers for login flows that do not fit the ordinary authorization-code table.
//!
//! Keeping these flows here leaves the command router's shared provider table small:
//! Cursor polls a browser challenge, Snowflake needs a dynamic callback port, and
//! DigitalOcean needs an explicit fragment-capture listener.

use std::process::Command;

use credentials_core::oauth::OAuthCredential;
use credentials_core::oauth_login::{generate_pkce, generate_state, parse_callback};
use credentials_core::record::VaultRecord;
use credentials_core::refresh_adapters::{cursor, devin, digitalocean, snowflake};
use credentials_core::ReqwestTransport;

use super::login_listener;

pub(crate) struct SpecialLogin {
    pub id: String,
    pub record: VaultRecord,
    pub replace: bool,
}

/// Run one of the provider-specific CLI flows. `None` means the ordinary login
/// driver should handle the provider.
pub(crate) fn run(
    provider: &str,
    args: &[String],
    selected_id: Option<&str>,
    selected_replace: bool,
) -> Result<Option<SpecialLogin>, String> {
    let result = match provider {
        "cursor" => Some(run_cursor(args, selected_id, selected_replace)?),
        "devin" => Some(run_devin(args, selected_id, selected_replace)?),
        "snowflake" => Some(run_snowflake(args, selected_id, selected_replace)?),
        "digitalocean" => Some(run_digitalocean(args, selected_id, selected_replace)?),
        _ => None,
    };
    Ok(result)
}

fn run_cursor(
    args: &[String],
    selected_id: Option<&str>,
    selected_replace: bool,
) -> Result<SpecialLogin, String> {
    let id = optional(args, "--id")
        .or_else(|| selected_id.map(str::to_string))
        .unwrap_or_else(|| cursor::DEFAULT_ID.to_string());
    if !login_id_is_valid(cursor::DEFAULT_ID, &id) {
        return Err(format!(
            "login --id must be '{}' or a labeled id",
            cursor::DEFAULT_ID
        ));
    }
    let pkce = generate_pkce().map_err(|e| format!("csprng: {e}"))?;
    let start =
        cursor::start_login(&pkce).map_err(|e| format!("building Cursor login URL: {e}"))?;
    println!("Open this URL in a browser signed into the Cursor account:");
    println!();
    println!("  {}", start.authorize_url);
    println!();
    let _ = open_in_browser(&start.authorize_url);
    println!("Waiting for browser sign-in…");
    let poller = cursor::ReqwestCursorPollTransport::new()
        .map_err(|e| format!("starting Cursor login poll: {e}"))?;
    let tokens = block_on(cursor::run_cursor_login(
        &poller,
        &start.uuid,
        &start.verifier,
    ))
    .map_err(|e| e.to_string())?;
    let oauth = OAuthCredential {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        token_url: cursor::TOKEN_URL.to_string(),
        client_id: None,
        scopes: Vec::new(),
    };
    Ok(SpecialLogin {
        id,
        record: VaultRecord::new_oauth(
            "login",
            cursor::ADAPTER_NAME,
            oauth,
            tokens.access_token.into_bytes(),
        ),
        replace: has_flag(args, "--replace") || selected_replace,
    })
}

fn run_devin(
    args: &[String],
    selected_id: Option<&str>,
    selected_replace: bool,
) -> Result<SpecialLogin, String> {
    let id = optional(args, "--id")
        .or_else(|| selected_id.map(str::to_string))
        .unwrap_or_else(|| devin::DEFAULT_ID.to_string());
    if !login_id_is_valid(devin::DEFAULT_ID, &id) {
        return Err(format!(
            "login --id must be '{}' or a labeled id",
            devin::DEFAULT_ID
        ));
    }
    let pkce = generate_pkce().map_err(|e| format!("csprng: {e}"))?;
    let state = generate_state().map_err(|e| format!("csprng: {e}"))?;
    let authorize_url = devin::authorize_url(devin::LOGIN_REDIRECT_URI, &state, &pkce.challenge)
        .map_err(|e| format!("building Devin login URL: {e}"))?;
    let listener = if has_flag(args, "--no-listener") {
        None
    } else {
        login_listener::loopback_bind_addr(devin::LOGIN_REDIRECT_URI)
            .and_then(|addr| login_listener::capture_callback(&addr))
    };
    let callback = open_and_capture(
        &authorize_url,
        listener,
        "After approving Devin, copy the full callback URL from the browser and paste it here:",
    )?;
    let callback =
        parse_callback(&callback).ok_or_else(|| "could not parse Devin callback".to_string())?;
    let http = ReqwestTransport::new().map_err(|e| format!("http: {e}"))?;
    let tokens = block_on(devin::exchange_authorization_code(
        &http,
        &callback,
        &state,
        &pkce.verifier,
        chrono::Utc::now().timestamp_millis(),
    ))
    .map_err(|e| e.to_string())?;
    let oauth = OAuthCredential {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        token_url: devin::TOKEN_URL.to_string(),
        client_id: None,
        scopes: Vec::new(),
    };
    Ok(SpecialLogin {
        id,
        record: VaultRecord::new_oauth(
            "login",
            devin::ADAPTER_NAME,
            oauth,
            tokens.access_token.into_bytes(),
        ),
        replace: has_flag(args, "--replace") || selected_replace,
    })
}

fn run_snowflake(
    args: &[String],
    selected_id: Option<&str>,
    selected_replace: bool,
) -> Result<SpecialLogin, String> {
    let account = match optional(args, "--account") {
        Some(account) => account,
        None => {
            println!("Snowflake account identifier:");
            let mut account = String::new();
            std::io::stdin()
                .read_line(&mut account)
                .map_err(|e| format!("reading Snowflake account: {e}"))?;
            account.trim().to_string()
        }
    };
    snowflake::validate_account(&account)?;
    let default_id = snowflake::default_id(&account)?;
    let id = optional(args, "--id")
        .or_else(|| selected_id.map(str::to_string))
        .unwrap_or_else(|| default_id.clone());
    snowflake::validate_credential_id(&account, &id)?;

    // Snowflake requires the actual callback port in the authorize URL. Reserve it
    // before opening the browser, then keep the listener alive through the redirect.
    let reserved = login_listener::capture_dynamic_callback()
        .ok_or_else(|| "could not bind a loopback callback port for Snowflake".to_string())?;
    let port = reserved
        .local_addr()
        .map_err(|e| format!("reading Snowflake callback port: {e}"))?
        .port();
    let redirect_uri = format!("{}{port}/", snowflake::LOGIN_REDIRECT_PREFIX);
    let pkce = generate_pkce().map_err(|e| format!("csprng: {e}"))?;
    let state = generate_state().map_err(|e| format!("csprng: {e}"))?;
    let authorize_url = snowflake::authorize_url(&account, &redirect_uri, &state, &pkce.challenge)?;
    let listener = if has_flag(args, "--no-listener") {
        // Keep the dynamically selected port in the URL, but intentionally release
        // the socket so this flag has the same paste-only behavior as other providers.
        drop(reserved);
        None
    } else {
        Some(reserved)
    };
    let callback = open_and_capture(
        &authorize_url,
        listener,
        "After approving Snowflake, copy the full callback URL from the browser and paste it here:",
    )?;
    let callback = parse_callback(&callback)
        .ok_or_else(|| "could not parse Snowflake callback".to_string())?;
    let token_url = snowflake::token_url(&account)?;
    let http = ReqwestTransport::new().map_err(|e| format!("http: {e}"))?;
    let tokens = block_on(snowflake::exchange_authorization_code(
        &http,
        &token_url,
        &redirect_uri,
        &callback,
        &state,
        &pkce.verifier,
        chrono::Utc::now().timestamp_millis(),
    ))
    .map_err(|e| e.to_string())?;
    let oauth = OAuthCredential {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        token_url,
        client_id: Some(snowflake::CLIENT_ID.to_string()),
        scopes: Vec::new(),
    };
    Ok(SpecialLogin {
        id,
        record: VaultRecord::new_oauth(
            "login",
            snowflake::ADAPTER_NAME,
            oauth,
            tokens.access_token.into_bytes(),
        ),
        replace: has_flag(args, "--replace") || selected_replace,
    })
}

fn run_digitalocean(
    args: &[String],
    selected_id: Option<&str>,
    selected_replace: bool,
) -> Result<SpecialLogin, String> {
    let id = optional(args, "--id")
        .or_else(|| selected_id.map(str::to_string))
        .unwrap_or_else(|| digitalocean::DEFAULT_ID.to_string());
    if !login_id_is_valid(digitalocean::DEFAULT_ID, &id) {
        return Err(format!(
            "login --id must be '{}' or a labeled id",
            digitalocean::DEFAULT_ID
        ));
    }
    let state = generate_state().map_err(|e| format!("csprng: {e}"))?;
    let authorize_url = digitalocean::authorize_url(&state);
    let listener = if has_flag(args, "--no-listener") {
        None
    } else {
        login_listener::loopback_bind_addr(digitalocean::REDIRECT_URI)
            .and_then(|addr| login_listener::capture_fragment_callback(&addr))
    };
    let raw = open_and_capture(
        &authorize_url,
        listener,
        "After approving DigitalOcean, copy the full callback URL (including the #fragment) and paste it here:",
    )?;
    let tokens =
        digitalocean::parse_fragment_capture(&raw, &state, chrono::Utc::now().timestamp_millis())?;
    let oauth = OAuthCredential {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        token_url: digitalocean::AUTHORIZE_URL.to_string(),
        client_id: Some(digitalocean::CLIENT_ID.to_string()),
        scopes: digitalocean::SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect(),
    };
    Ok(SpecialLogin {
        id,
        record: VaultRecord::new_oauth(
            "login",
            digitalocean::ADAPTER_NAME,
            oauth,
            tokens.access_token.into_bytes(),
        ),
        replace: has_flag(args, "--replace") || selected_replace,
    })
}

fn open_and_capture(
    authorize_url: &str,
    listener: Option<login_listener::CallbackListener>,
    paste_prompt: &str,
) -> Result<String, String> {
    println!("Open this URL in a browser signed into the account to custody:");
    println!();
    println!("  {authorize_url}");
    println!();
    let _ = open_in_browser(authorize_url);
    let captured = match listener {
        Some(listener) => {
            println!("Approve in the browser — the login completes here automatically.");
            listener.wait()
        }
        None => None,
    };
    if let Some(captured) = captured {
        return Ok(captured);
    }
    println!("{paste_prompt}");
    let mut pasted = String::new();
    std::io::stdin()
        .read_line(&mut pasted)
        .map_err(|e| format!("reading callback: {e}"))?;
    Ok(pasted)
}

fn login_id_is_valid(default_id: &str, id: &str) -> bool {
    id == default_id
        || id
            .strip_prefix(default_id)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(|label| !label.is_empty() && !label.contains(':'))
}

fn optional(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn open_in_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).spawn()?.wait()?;
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open").arg(url).spawn()?.wait()?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()?
            .wait()?;
    }
    Ok(())
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("single-thread login runtime")
        .block_on(future)
}
