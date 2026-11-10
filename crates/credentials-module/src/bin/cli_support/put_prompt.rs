//! Terminal-only input for manually deposited credentials. Secret values never
//! enter the argument list; `cmd_put` sends them through its usual store path.

use std::io::IsTerminal;

use credentials_core::deposit_cookie::valid_deposit_cookie_id;
use credentials_core::store::validate_deposit_credential_id;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Password, Select};

use super::{
    api_key_login, login_id_is_valid, parse_inventory, request_admin_status, CliError, GlobalArgs,
    ParsedOptions,
};

const KINDS: [&str; 4] = ["API key", "Cookie", "DSN", "Opaque secret"];

pub(super) fn is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

fn prompt_error(error: dialoguer::Error) -> CliError {
    CliError::Io(format!("interactive put cancelled: {error}"))
}

fn api_key_id(name: &str) -> Result<String, String> {
    let provider = name.split(':').next().unwrap_or_default();
    let label = name.split_once(':').map(|(_, label)| label);
    let id = format!("apikey:{name}");
    if !credentials_core::credential_id::valid_api_key_service_name(provider)
        || label.is_some_and(|label| {
            label.contains(char::is_whitespace) || label.contains(char::is_control)
        })
        || !login_id_is_valid(&format!("apikey:{provider}"), &id)
    {
        return Err(
            "use a provider name and optionally one non-empty :label, without spaces".into(),
        );
    }
    validate_deposit_credential_id(&id).map_err(|error| error.to_string())?;
    Ok(id)
}

fn cookie_id(domain: &str, account: &str) -> Result<String, String> {
    if !valid_deposit_cookie_id(&format!("cookie:{domain}:account")) {
        return Err("use a lowercase site domain, such as example.com (no URL or path)".into());
    }
    let id = format!("cookie:{domain}:{account}");
    if !valid_deposit_cookie_id(&id) {
        return Err(
            "use an account label of 1-64 letters, digits or ._@+- within a valid cookie id".into(),
        );
    }
    validate_deposit_credential_id(&id).map_err(|error| error.to_string())?;
    Ok(id)
}

fn manual_id(id: &str) -> Result<String, String> {
    validate_deposit_credential_id(id).map_err(|error| error.to_string())?;
    Ok(id.to_string())
}

fn name(theme: &ColorfulTheme, kind: usize) -> Result<String, CliError> {
    match kind {
        0 => {
            let value: String = Input::with_theme(theme)
                .with_prompt("Provider name (optionally provider:label)")
                .validate_with(|value: &String| api_key_id(value).map(|_| ()))
                .interact_text()
                .map_err(prompt_error)?;
            api_key_id(&value).map_err(CliError::Usage)
        }
        1 => {
            let domain: String = Input::with_theme(theme)
                .with_prompt("Site domain")
                .validate_with(|value: &String| cookie_id(value, "account").map(|_| ()))
                .interact_text()
                .map_err(prompt_error)?;
            let account: String = Input::with_theme(theme)
                .with_prompt("Account label")
                .validate_with(|value: &String| cookie_id(&domain, value).map(|_| ()))
                .interact_text()
                .map_err(prompt_error)?;
            cookie_id(&domain, &account).map_err(CliError::Usage)
        }
        _ => Input::with_theme(theme)
            .with_prompt("Credential id (no required prefix)")
            .validate_with(|value: &String| manual_id(value).map(|_| ()))
            .interact_text()
            .map_err(prompt_error),
    }
}

/// Resolve only missing metadata. Explicit id and payload sources preserve the
/// noninteractive command, even when a script happens to inherit a terminal.
pub(super) fn prepare(global: &GlobalArgs, options: &mut ParsedOptions) -> Result<bool, CliError> {
    if !is_terminal()
        || (options.optional("--id").is_some() && options.optional("--payload-file").is_some())
    {
        return Ok(true);
    }
    let theme = ColorfulTheme::default();
    let id = match options.optional("--id") {
        Some(id) => id,
        None => {
            let kind = match options.optional("--kind").as_deref() {
                Some("api_key") => 0,
                Some("dsn") => 2,
                Some("opaque") => 3,
                Some(_) => return Err(CliError::Usage("--kind must be api_key|dsn|opaque".into())),
                None => {
                    eprintln!("For generated keys use ck auth mint-signing-key / mint-kem-key; for OAuth use ck auth login.");
                    Select::with_theme(&theme)
                        .with_prompt("Credential kind")
                        .items(KINDS)
                        .default(0)
                        .interact()
                        .map_err(prompt_error)?
                }
            };
            let id = name(&theme, kind)?;
            if kind == 0 {
                let parsed = super::parse_credential_id(&id);
                if api_key_login::API_KEY_PROVIDERS
                    .iter()
                    .any(|row| row.key == parsed.provider)
                {
                    eprintln!("ck auth login checks the key against the provider where a check is available.");
                    if !Confirm::with_theme(&theme)
                        .with_prompt("Continue storing it unchecked?")
                        .default(false)
                        .interact()
                        .map_err(prompt_error)?
                    {
                        println!("ck auth login --provider {}", parsed.provider);
                        return Ok(false);
                    }
                }
            }
            options.values.insert("--id".into(), id.clone());
            if options.optional("--kind").is_none() && kind != 1 {
                options.values.insert(
                    "--kind".into(),
                    ["api_key", "", "dsn", "opaque"][kind].into(),
                );
            }
            id
        }
    };

    if !options.has_flag("--replace") && options.optional("--expected-hash").is_none() {
        let inventory = parse_inventory(&request_admin_status(global)?)?;
        if inventory.iter().any(|row| row.2 == id) {
            eprintln!("{id} already holds a credential.");
            if !Confirm::with_theme(&theme)
                .with_prompt("Replace it?")
                .default(false)
                .interact()
                .map_err(prompt_error)?
            {
                return Ok(false);
            }
            options.bools.insert("--replace".into());
        }
    }
    Ok(true)
}

pub(super) fn payload() -> Result<Vec<u8>, CliError> {
    loop {
        let value = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Value (hidden)")
            .allow_empty_password(true)
            .interact()
            .map_err(prompt_error)?;
        let value = value.trim();
        if !value.is_empty() {
            return Ok(value.as_bytes().to_vec());
        }
        eprintln!("Value must not be empty.");
    }
}

/// Resolve an unknown API-key service before reading any secret bytes.
pub(super) fn provider(global: &GlobalArgs, id: &str) -> Result<bool, CliError> {
    use credentials_core::store::{
        api_key_service, registered_providers_read_only, RegisteredProvider,
    };

    let Some(service) = api_key_service(id) else {
        return Ok(true);
    };
    if credentials_core::catalog::provider(id).is_some() {
        return Ok(true);
    }
    let registered =
        registered_providers_read_only(&super::store_path(global)).map_err(CliError::Store)?;
    if RegisteredProvider::for_id(&registered, id).is_some() {
        return Ok(true);
    }
    if !is_terminal() {
        eprintln!("Unknown provider {service}; use ck auth provider set --service {service} to choose defaults for future keys.");
        return Ok(true);
    }
    let theme = ColorfulTheme::default();
    eprintln!("Provider {service} is unknown. Its keys reach only modules granted the groups you choose now.");
    let groups: Vec<_> = credentials_core::catalog::CredentialCategory::ALL
        .iter()
        .map(|category| category.as_str())
        .collect();
    let selected = MultiSelect::with_theme(&theme)
        .with_prompt("Groups for this provider (space to select, enter to finish)")
        .items(&groups)
        .interact()
        .map_err(prompt_error)?;
    let categories = selected
        .into_iter()
        .map(|index| groups[index].to_string())
        .collect();
    eprintln!("Routing provider ids tell routing which models the key may serve. A wrong id sends work to a key that refuses it; empty is the safe answer.");
    let raw: String = Input::with_theme(&theme)
        .with_prompt("Routing provider ids (comma-separated, empty for none)")
        .allow_empty(true)
        .validate_with(|value: &String| {
            let ids = routing_ids(value);
            super::check_cli_provider_ids(&ids, true).map_err(|error| error.to_string())
        })
        .interact_text()
        .map_err(prompt_error)?;
    if !Confirm::with_theme(&theme)
        .with_prompt("Save these provider defaults and continue?")
        .default(false)
        .interact()
        .map_err(prompt_error)?
    {
        return Ok(false);
    }
    super::commit_admin(
        global,
        credentials_core::admin_ops::AdminOpBody::ProviderSet {
            v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V2,
            service: service.to_string(),
            categories,
            provider_ids: routing_ids(&raw),
            hosts: None,
            auth_header: None,
            auth_scheme: None,
            fusiform_provider_id: None,
        },
    )?;
    Ok(true)
}

fn routing_ids(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() {
        Vec::new()
    } else {
        raw.split(',').map(|id| id.trim().to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_names_follow_the_existing_login_id_shape() {
        assert_eq!(api_key_id("daytona").unwrap(), "apikey:daytona");
        assert_eq!(api_key_id("probe:one").unwrap(), "apikey:probe:one");
        for service in ["CUSTOM", "custom.vendor", "éclair"] {
            assert_eq!(api_key_id(service).unwrap(), format!("apikey:{service}"));
        }
        for bad in [
            "",
            ":work",
            "probe:",
            "probe:one:two",
            "probe one",
            "probe|one",
            "probe\nline",
            "probe\u{1b}control",
        ] {
            assert!(api_key_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cookie_names_use_the_vault_domain_and_account_validator() {
        assert_eq!(
            cookie_id("example.com", "work+one").unwrap(),
            "cookie:example.com:work+one"
        );
        for domain in [
            "",
            "localhost",
            "Example.com",
            "https://example.com",
            "-a.com",
            "a..com",
        ] {
            assert!(cookie_id(domain, "work").is_err(), "{domain}");
        }
        for account in ["", "work:one", "work one", "work/one", "work|one"] {
            assert!(cookie_id("example.com", account).is_err(), "{account}");
        }
        assert!(cookie_id("example.com", &"a".repeat(64)).is_ok());
        assert!(cookie_id("example.com", &"a".repeat(65)).is_err());
    }

    #[test]
    fn dsn_and_opaque_ids_keep_the_existing_deposit_grammar() {
        for id in ["database", "dsn:database", "opaque:deploy"] {
            assert_eq!(manual_id(id).unwrap(), id);
        }
        for id in ["category:llm", "database|other"] {
            assert!(manual_id(id).is_err(), "{id}");
        }
    }
}
