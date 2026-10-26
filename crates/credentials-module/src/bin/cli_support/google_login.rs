//! CLI driver for the Google-family vault-native login flows.
//!
//! The core crate owns the provider wire helpers; this module owns only the
//! interactive browser/listener and admin-store integration.

use credentials_core::google_login::{
    self as google, GoogleLoginProvider, AUTHORIZE_URL, TOKEN_URL,
};
use credentials_core::oauth_login::{
    build_authorize_url_google, exchange_authorization_code_google, generate_state,
};
use credentials_core::record::{RecordIdentity, VaultRecord};

use super::{
    commit_login_admin, has_flag, login_id_is_valid, optional, preflight_login, CliError,
    GlobalArgs,
};

/// Whether a provider flag belongs to one of the Google-family login flows.
pub fn is_provider(provider: &str) -> bool {
    GoogleLoginProvider::parse(provider).is_some()
}

/// Return the default id used by a Google-family provider, for picker and logout
/// metadata without requiring the PKCE-oriented provider table to own this wire.
pub fn default_id(provider: &str) -> Option<&'static str> {
    GoogleLoginProvider::parse(provider).map(GoogleLoginProvider::default_id)
}

const GMAIL_COMMAND: &str =
    "ck auth login --provider gmail --client-id <id> --client-secret-file <path>";

/// Refuse client flags before touching the vault or opening a browser. The picker
/// uses the same validation so selecting Gmail cannot use a public Google client.
pub fn validate_client_flags(args: &[String], provider: &str) -> Result<(), CliError> {
    if provider != "gmail" {
        if has_flag(args, "--client-id") || has_flag(args, "--client-secret-file") {
            return Err(CliError::Usage(
                "--client-id and --client-secret-file are only supported for --provider gmail"
                    .into(),
            ));
        }
        return Ok(());
    }
    for flag in ["--client-id", "--client-secret-file"] {
        if optional(args, flag).is_none_or(|value| value.trim().is_empty()) {
            return Err(CliError::Usage(format!(
                "gmail requires {flag}; run: {GMAIL_COMMAND}"
            )));
        }
    }
    Ok(())
}

fn client_credentials(
    args: &[String],
    wire: GoogleLoginProvider,
) -> Result<(String, credentials_core::secret::SecretString), CliError> {
    validate_client_flags(args, wire.adapter_name())?;
    if wire != GoogleLoginProvider::Gmail {
        return Ok((wire.client_id(), wire.client_secret().into()));
    }
    let path = optional(args, "--client-secret-file").expect("validated secret file flag");
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| CliError::Io(format!("reading client secret file {path}: {error}")))?;
    let secret = raw.trim_end().to_string();
    if secret.trim().is_empty() {
        return Err(CliError::Usage(
            "gmail --client-secret-file is empty".into(),
        ));
    }
    Ok((
        optional(args, "--client-id").expect("validated client id"),
        secret.into(),
    ))
}

/// Drive a Google authorization-code login and commit the resulting record.
pub fn cmd_login(
    global: &GlobalArgs,
    args: &[String],
    provider: &str,
    id_override: Option<String>,
    replace_override: bool,
) -> Result<(), CliError> {
    let wire = GoogleLoginProvider::parse(provider).expect("caller checked Google provider");
    let (client_id, client_secret) = client_credentials(args, wire)?;
    let id = optional(args, "--id")
        .or(id_override)
        .unwrap_or_else(|| wire.default_id().to_string());
    if !login_id_is_valid(wire.default_id(), &id) {
        return Err(CliError::Usage(format!(
            "login --id must be '{d}' or '{d}:<label>' (a labeled account of the same provider, e.g. '{d}:work') — got '{id}'",
            d = wire.default_id()
        )));
    }

    let approve_on = super::browser_login::approve_on(args)?;
    let replace = has_flag(args, "--replace") || replace_override;
    let preflighted_key = preflight_login(
        global,
        &id,
        replace,
        format!(
            "'{id}' already holds a credential. To replace it, pass --replace (keeps its handles)."
        ),
    )?;

    let state = generate_state().map_err(|error| CliError::Io(format!("csprng: {error}")))?;
    let (authorize_endpoint, token_endpoint, redirect_uri) =
        (AUTHORIZE_URL, TOKEN_URL, wire.redirect_uri());
    #[cfg(all(debug_assertions, feature = "test-support"))]
    let (authorize_endpoint, token_endpoint, redirect_uri) = (
        super::browser_login::test_endpoint("authorize_url", authorize_endpoint),
        super::browser_login::test_endpoint("token_url", token_endpoint),
        super::browser_login::test_endpoint("redirect_uri", redirect_uri),
    );
    let authorize_url = build_authorize_url_google(
        authorize_endpoint,
        &client_id,
        redirect_uri,
        wire.scopes(),
        &state,
        google::AUTHORIZE_EXTRA_PARAMS,
    )
    .map_err(|error| CliError::Io(format!("building authorize url: {error}")))?;

    let listener = if approve_on == super::browser_login::ApproveOn::Other
        || has_flag(args, "--no-listener")
    {
        None
    } else {
        super::login_listener::loopback_bind_addr(redirect_uri)
            .and_then(|address| super::login_listener::capture_callback(&address))
    };

    println!("Open this URL in a browser signed into the account to custody:");
    println!();
    println!("  {authorize_url}");
    println!();
    super::browser_login::choose_and_present(args, approve_on, &authorize_url)?;
    let callback = super::tokio_block_on(super::browser_login::read_callback(
        listener,
        "Copy the full callback URL from the browser's address bar and paste it here, then Enter:",
        &state,
    ))?;

    let http = credentials_core::http::ReqwestTransport::new()
        .map_err(|error| CliError::Io(error.to_string()))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let tokens = super::tokio_block_on(exchange_authorization_code_google(
        &http,
        token_endpoint,
        &client_id,
        client_secret.expose(),
        redirect_uri,
        &callback,
        &state,
        now_ms,
    ))
    .map_err(|error| CliError::Io(error.to_string()))?;

    let project = if wire == GoogleLoginProvider::Antigravity {
        Some(
            super::tokio_block_on(google::discover_antigravity_project(
                &http,
                &tokens.access_token,
            ))
            .map_err(|error| CliError::Io(error.to_string()))?,
        )
    } else {
        None
    };
    let email = super::tokio_block_on(google::google_userinfo_email(&http, &tokens.access_token));
    if let Some(email) = email.as_deref() {
        println!("account: {email}");
    }

    let record = if wire == GoogleLoginProvider::Gmail {
        google::gmail_login_record(tokens, client_id, client_secret, email)
            .map_err(|message| CliError::Usage(message.into()))?
    } else {
        let refresh_token = match project.as_ref() {
            Some(project) => google::pack_antigravity_refresh(&tokens.refresh_token, project),
            None => tokens.refresh_token.clone(),
        };
        let oauth = credentials_core::oauth::OAuthCredential {
            access_token: tokens.access_token.clone().into(),
            refresh_token: refresh_token.into(),
            expires_at_ms: tokens.expires_at_ms,
            token_url: TOKEN_URL.to_string(),
            client_id: Some(client_id),
            client_secret: None,
            scopes: wire
                .scopes()
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
        };
        VaultRecord::new_oauth(
            "login",
            wire.adapter_name(),
            oauth,
            tokens.access_token.into_bytes(),
        )
        .with_identity(RecordIdentity {
            // The email is the identity, not just a label. The read surface serves
            // `account_id` as the field consumers join on and treats `email` as display
            // metadata, so populating only `email` yields a record that renders a value
            // while resolving no identity -- a consumer labelling per account collapses
            // its accounts into one unlabelled entry and the wire looks unchanged. The
            // read surface states the invariant: email never ships without account_id.
            //
            // Google/antigravity access tokens are opaque rather than JWTs, so there is no
            // claim to parse live and no other stable per-account identifier available.
            account_id: email.clone(),
            email,
            org_name: None,
        })
    };

    if replace {
        commit_login_admin(
            global,
            super::store_op(
                &id,
                record,
                credentials_core::admin_ops::AdminAuditOp::Login,
                credentials_core::admin_ops::StoreMode::ReplaceUnconditional,
            ),
            preflighted_key,
            args,
        )?;
        println!("logged in and replaced {id}");
        return Ok(());
    }

    let result = commit_login_admin(
        global,
        super::store_op(
            &id,
            record,
            credentials_core::admin_ops::AdminAuditOp::Login,
            credentials_core::admin_ops::StoreMode::Create,
        ),
        preflighted_key,
        args,
    );
    let already_exists = match &result {
        Err(CliError::Store(credentials_core::store::StoreOpError::AlreadyExists)) => true,
        Err(CliError::RouteRefused(message)) => message.contains("already exists"),
        _ => false,
    };
    if already_exists {
        return Err(CliError::Usage(format!(
            "'{id}' already holds a credential. To replace it, pass --replace (keeps its handles)."
        )));
    }
    result?;
    println!("logged in and stored {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmail_secret_file_trims_only_trailing_whitespace() {
        let dir = credentials_core::test_support::TestTempDir::new(format!(
            "gmail-secret-{}",
            std::process::id()
        ));
        let path = dir.join("secret");
        std::fs::write(&path, " test-client-secret \n\t").unwrap();
        let args = vec![
            "--client-id".into(),
            "test-client-id".into(),
            "--client-secret-file".into(),
            path.to_string_lossy().into_owned(),
        ];
        let (id, secret) = client_credentials(&args, GoogleLoginProvider::Gmail).unwrap();
        assert_eq!(id, "test-client-id");
        assert_eq!(secret.expose(), " test-client-secret");
        std::fs::write(&path, " \n").unwrap();
        assert!(
            matches!(client_credentials(&args, GoogleLoginProvider::Gmail), Err(CliError::Usage(message)) if message == "gmail --client-secret-file is empty")
        );
    }
}
