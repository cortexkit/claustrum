//! Normal-form, non-secret settings fixed when a company AI gateway is enrolled.

use crate::catalog::{ModelVendor, MODEL_VENDOR_FUSIFORM_IDS};
use crate::provider_ids::check_provider_ids;
use crate::store::StoreOpError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_GATEWAY_BASE_URL_BYTES: usize = 512;
pub const MAX_GATEWAY_HEADERS: usize = 8;
pub const MAX_GATEWAY_HEADER_NAME_BYTES: usize = 64;
pub const MAX_GATEWAY_HEADER_VALUE_BYTES: usize = 1024;
pub const MAX_GATEWAY_SLUG_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayAuth {
    pub header: String,
    pub scheme: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayHeader {
    pub name: String,
    pub value: String,
}

impl std::fmt::Debug for GatewayHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewaySettings {
    pub base_url: String,
    pub auth: GatewayAuth,
    /// Kept as pairs so duplicate and misordered names reach validation unchanged.
    pub headers: Vec<GatewayHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGateway {
    /// The exact host spelling, including brackets for the IPv6 loopback.
    pub host: String,
    pub vendor: ModelVendor,
}

/// Stable tokens carried in gateway creation refusals as `rule=<token>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySettingsRule {
    CredentialId,
    Kind,
    BaseUrl,
    BaseUrlPath,
    BaseUrlLength,
    Auth,
    HeaderCount,
    HeaderName,
    HeaderValue,
    ProviderId,
}

/// Stable tokens for changes to gateway properties fixed at creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayFixedRule {
    Kind,
    Category,
    ProviderId,
}

impl GatewayFixedRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Category => "category",
            Self::ProviderId => "provider_id",
        }
    }
}

impl std::fmt::Display for GatewayFixedRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl GatewaySettingsRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialId => "credential_id",
            Self::Kind => "kind",
            Self::BaseUrl => "base_url",
            Self::BaseUrlPath => "base_url_path",
            Self::BaseUrlLength => "base_url_length",
            Self::Auth => "auth",
            Self::HeaderCount => "header_count",
            Self::HeaderName => "header_name",
            Self::HeaderValue => "header_value",
            Self::ProviderId => "provider_id",
        }
    }
}

impl std::fmt::Display for GatewaySettingsRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn invalid(rule: GatewaySettingsRule) -> StoreOpError {
    StoreOpError::InvalidGatewaySettings { rule }
}

/// Check signed settings without repairing them, shared by CLI preflight and writes.
///
/// The URL path is empty or `/seg(/seg)*`. Each nonempty segment contains only
/// RFC 3986 `pchar` without `%`: ASCII letters, digits, `-._~`, `!$&'()*+,;=`,
/// `:` and `@`. Empty segments, `.` and `..`, trailing slashes, queries,
/// fragments, Unicode, spaces, controls and backslashes are refused, so URL
/// parsers cannot silently rewrite accepted paths. Scheme and host are lowercase;
/// explicit ports, including default ports, are preserved rather than normalized.
/// Refusals contain no supplied values, because fixed header values may be sensitive.
pub fn validate_gateway_settings(
    credential_id: &str,
    settings: &GatewaySettings,
    provider_ids: &[String],
) -> Result<ValidatedGateway, StoreOpError> {
    let service = credential_service(credential_id)
        .ok_or_else(|| invalid(GatewaySettingsRule::CredentialId))?;
    let host = validate_base_url(&settings.base_url)?;
    if settings.auth.header.len() > MAX_GATEWAY_HEADER_NAME_BYTES
        || !crate::store::valid_provider_header_name(&settings.auth.header)
        || !matches!(settings.auth.scheme.as_str(), "bearer" | "raw")
    {
        return Err(invalid(GatewaySettingsRule::Auth));
    }
    if settings.headers.len() > MAX_GATEWAY_HEADERS {
        return Err(invalid(GatewaySettingsRule::HeaderCount));
    }
    let mut previous: Option<&str> = None;
    for header in &settings.headers {
        if header.name.len() > MAX_GATEWAY_HEADER_NAME_BYTES
            || !crate::store::valid_provider_header_name(&header.name)
            || previous.is_some_and(|name| name >= header.name.as_str())
            || refused_header_name(&header.name)
            || header.name == settings.auth.header
        {
            return Err(invalid(GatewaySettingsRule::HeaderName));
        }
        previous = Some(&header.name);
        if header.value.is_empty()
            || header.value.len() > MAX_GATEWAY_HEADER_VALUE_BYTES
            || !header.value.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || header.value.starts_with(' ')
            || header.value.ends_with(' ')
            || serde_json::from_str::<serde_json::Value>(&header.value)
                .is_ok_and(|value| value.is_object() || value.is_array())
        {
            return Err(invalid(GatewaySettingsRule::HeaderValue));
        }
    }
    if provider_ids.len() != 1 || check_provider_ids(provider_ids).is_err() {
        return Err(invalid(GatewaySettingsRule::ProviderId));
    }
    let provider_id = &provider_ids[0];
    let vendor = gateway_provider_vendor(provider_id)
        .filter(|_| service == provider_id)
        .ok_or_else(|| invalid(GatewaySettingsRule::ProviderId))?;
    Ok(ValidatedGateway { host, vendor })
}

fn credential_service(id: &str) -> Option<&str> {
    let mut parts = id.strip_prefix("apikey:")?.split(':');
    let service = parts.next()?;
    let valid_part = |part: &str| {
        !part.is_empty()
            && !part
                .chars()
                .any(|c| c == '|' || c.is_whitespace() || c.is_control())
    };
    if !valid_part(service) || parts.next().is_some_and(|label| !valid_part(label)) {
        return None;
    }
    parts.next().is_none().then_some(service)
}

/// Resolve the model vendor using the first gateway marker, never a catalog offering.
pub fn gateway_provider_vendor(provider_id: &str) -> Option<ModelVendor> {
    let (prefix, slug) = provider_id.split_once("-gw-")?;
    if slug.is_empty()
        || slug.len() > MAX_GATEWAY_SLUG_BYTES
        || !slug.as_bytes()[0].is_ascii_lowercase()
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    MODEL_VENDOR_FUSIFORM_IDS
        .iter()
        .find_map(|(vendor, id)| (*id == prefix).then_some(*vendor))
}

fn refused_header_name(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "upgrade"
            | "cookie"
            | "authorization"
            | "proxy-authorization"
            | "x-api-key"
    )
}

fn validate_base_url(base_url: &str) -> Result<String, StoreOpError> {
    if base_url.len() > MAX_GATEWAY_BASE_URL_BYTES {
        return Err(invalid(GatewaySettingsRule::BaseUrlLength));
    }
    let (scheme, rest) = base_url
        .split_once("://")
        .filter(|(scheme, _)| matches!(*scheme, "http" | "https"))
        .ok_or_else(|| invalid(GatewaySettingsRule::BaseUrl))?;
    let (authority, path) = rest
        .find('/')
        .map_or((rest, ""), |index| (&rest[..index], &rest[index..]));
    // Inspect the raw authority: URL parsers canonicalize abbreviated IPv4,
    // noncanonical IPv6 and default ports before a caller can reject them.
    let (host, port) = if let Some(suffix) = authority.strip_prefix("[::1]") {
        ("[::1]", suffix.strip_prefix(':'))
    } else {
        authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)))
    };
    if host == "[::1]" && authority != host && !authority.starts_with("[::1]:") {
        return Err(invalid(GatewaySettingsRule::BaseUrl));
    }
    if port.is_some_and(|port| {
        port.is_empty()
            || port.len() > 5
            || port.starts_with('0')
            || !port.bytes().all(|b| b.is_ascii_digit())
            || !port.parse::<u16>().is_ok_and(|value| value > 0)
    }) {
        return Err(invalid(GatewaySettingsRule::BaseUrl));
    }
    let loopback = host == "localhost" || host == "[::1]" || decimal_loopback(host);
    if (!loopback && !dns_name(host)) || (scheme == "http" && !loopback) {
        return Err(invalid(GatewaySettingsRule::BaseUrl));
    }
    if !path.is_empty()
        && !path[1..].split('/').all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b))
        })
    {
        return Err(invalid(GatewaySettingsRule::BaseUrl));
    }
    let lower_path = path.to_ascii_lowercase();
    if lower_path.ends_with("/messages") || lower_path.ends_with("/v1/messages") {
        return Err(invalid(GatewaySettingsRule::BaseUrlPath));
    }
    Ok(host.to_owned())
}

fn decimal_loopback(host: &str) -> bool {
    let parts: Vec<_> = host.split('.').collect();
    parts.len() == 4
        && parts[0] == "127"
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

fn dns_name(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or_default();
    !last.bytes().all(|b| b.is_ascii_digit())
        && !last
            .strip_prefix("0x")
            .is_some_and(|tail| tail.bytes().all(|b| b.is_ascii_hexdigit()))
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && label.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// SHA-256 of compact normal-form settings JSON, not of the pair-list wire shape.
/// Call only after validation; the JSON header object uses ascending byte order.
pub fn gateway_settings_digest(settings: &GatewaySettings) -> String {
    #[derive(Serialize)]
    struct DigestSettings<'a> {
        base_url: &'a str,
        auth: &'a GatewayAuth,
        headers: BTreeMap<&'a str, &'a str>,
    }
    let value = DigestSettings {
        base_url: &settings.base_url,
        auth: &settings.auth,
        headers: settings
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect(),
    };
    let json = serde_json::to_vec(&value).expect("string-only gateway settings serialize");
    format!("{:x}", Sha256::digest(json))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> GatewaySettings {
        GatewaySettings {
            base_url: "https://gateway.example/v1".into(),
            auth: GatewayAuth {
                header: "authorization".into(),
                scheme: "bearer".into(),
            },
            headers: vec![],
        }
    }

    fn header(name: &str, value: &str) -> GatewayHeader {
        GatewayHeader {
            name: name.into(),
            value: value.into(),
        }
    }

    fn validate(settings: &GatewaySettings) -> Result<ValidatedGateway, StoreOpError> {
        validate_gateway_settings(
            "apikey:anthropic-gw-acme",
            settings,
            &["anthropic-gw-acme".into()],
        )
    }

    fn refused(error: StoreOpError, rule: GatewaySettingsRule) {
        assert!(
            matches!(error, StoreOpError::InvalidGatewaySettings { rule: actual } if actual == rule)
        );
        assert_eq!(error.wire_code(), Some("invalid_gateway_settings"));
        assert_eq!(error.wire_class(), Some("permanent"));
        assert_eq!(
            error.to_string(),
            format!("invalid_gateway_settings/permanent: rule={rule}")
        );
    }

    #[test]
    fn gateway_base_url_hosts_and_ports_accept_only_exact_spellings() {
        for (base_url, host) in [
            ("https://gateway.example/v1", "gateway.example"),
            ("https://a-b.c9", "a-b.c9"),
            ("https://localhost", "localhost"),
            ("http://localhost:4000", "localhost"),
            ("http://127.0.0.0", "127.0.0.0"),
            ("http://127.255.255.255:65535", "127.255.255.255"),
            ("http://127.1.2.3:1", "127.1.2.3"),
            ("https://127.0.0.1:443/v1", "127.0.0.1"),
            ("http://[::1]:80", "[::1]"),
            ("https://[::1]:443", "[::1]"),
            ("https://api.localhost", "api.localhost"),
            ("https://gateway.example:443/v1", "gateway.example"),
            ("http://localhost:80/v1", "localhost"),
            ("https://0xg", "0xg"),
        ] {
            let mut s = settings();
            s.base_url = base_url.into();
            let before = s.clone();
            assert_eq!(validate(&s).unwrap().host, host, "{base_url}");
            assert_eq!(s, before, "validation must not normalize an explicit port");
        }
        for base_url in [
            "https://10.1",
            "https://3232235777",
            "https://0x7f.1",
            "https://0x",
            "https://127.1",
            "https://[0:0:0:0:0:0:0:1]",
            "https://192.168.1.1",
            "https://0x7f000001",
            "https://gateway.0xff",
            "https://gateway.0x",
            "https://gateway.123",
            "https://127.0.0.256",
            "https://127.00.0.1",
            "https://0127.0.0.1",
            "https://127.0.0.01",
            "https://[::2]",
            "https://::1",
            "https://[::1]suffix",
            "https://[::1]@gateway.example",
            "http://gateway.example",
            "http://api.localhost",
            "http://localhost.example",
            "https://",
            "https://.example",
            "https://gateway..example",
            "https://gateway.example.",
            "https://-gateway.example",
            "https://gateway-.example",
            "https://gate_way.example",
            "https://Gateway.example",
            "https://é.example",
            "https://%67ateway.example",
            "https://user@gateway.example",
            "https://user:pass@gateway.example",
            "HTTPS://gateway.example",
            "ftp://gateway.example",
            "https:gateway.example",
            "https://gateway.example:",
            "https://gateway.example:0",
            "https://gateway.example:01",
            "https://gateway.example:65536",
            "https://gateway.example:123456",
            "https://gateway.example:+80",
            "https://gateway.example:80:90",
            "https://[::1]:",
            "https://[::1]:080",
            "https://[::1]:65536",
            "https://gateway.example?x=1",
            "https://gateway.example#fragment",
            "https://gateway.example\\path",
            " https://gateway.example",
        ] {
            let mut s = settings();
            s.base_url = base_url.into();
            let result = validate(&s);
            assert!(result.is_err(), "{base_url} must be refused");
            refused(result.unwrap_err(), GatewaySettingsRule::BaseUrl);
        }
    }

    #[test]
    fn gateway_base_url_paths_cannot_be_rewritten_by_url_parsers() {
        for path in [
            "",
            "/v1",
            "/V1",
            "/messages-next",
            "/a/.-/..x",
            "/aAZ09-._~!$&'()*+,;=:@",
        ] {
            let mut s = settings();
            s.base_url = format!("https://gateway.example{path}");
            assert!(validate(&s).is_ok(), "{path}");
        }
        for path in [
            "/",
            "/v1/",
            "//v1",
            "/v1//x",
            "/.",
            "/..",
            "/./v1",
            "/v1/../x",
            "/%41",
            "/%2e%2e/x",
            "/v1?x=1",
            "/v1#fragment",
            "/é",
            "/a b",
            "/a\tb",
            "/a\nb",
            "/a\u{7f}b",
            "/a\\b",
            "/[x]",
            "/a|b",
            "/a\"b",
        ] {
            let mut s = settings();
            s.base_url = format!("https://gateway.example{path}");
            let result = validate(&s);
            assert!(result.is_err(), "{path:?}");
            refused(result.unwrap_err(), GatewaySettingsRule::BaseUrl);
        }
        for path in [
            "/messages",
            "/v1/messages",
            "/V1/MESSAGES",
            "/prefix/Messages",
        ] {
            let mut s = settings();
            s.base_url = format!("https://gateway.example{path}");
            refused(validate(&s).unwrap_err(), GatewaySettingsRule::BaseUrlPath);
        }
    }

    #[test]
    fn gateway_base_url_accepts_512_bytes_and_refuses_513() {
        let mut s = settings();
        let prefix = "https://gateway.example/";
        s.base_url = format!("{prefix}{}", "a".repeat(512 - prefix.len()));
        assert_eq!(s.base_url.len(), 512);
        assert!(validate(&s).is_ok());
        s.base_url.push('a');
        refused(
            validate(&s).unwrap_err(),
            GatewaySettingsRule::BaseUrlLength,
        );
    }

    #[test]
    fn gateway_auth_accepts_64_bytes_and_refuses_65() {
        let mut s = settings();
        s.auth.header = "a".repeat(64);
        assert!(validate(&s).is_ok());
        s.auth.header.push('a');
        refused(validate(&s).unwrap_err(), GatewaySettingsRule::Auth);
    }

    #[test]
    fn gateway_auth_requires_lowercase_http_token_and_exact_scheme() {
        let mut s = settings();
        s.auth.header = "a09!#$%&'*+-.^_`|~".into();
        s.auth.scheme = "raw".into();
        assert!(validate(&s).is_ok());
        for name in [
            "",
            "Authorization",
            "x api-key",
            "x-api-key:",
            "x-key\n",
            "é",
        ] {
            let mut s = settings();
            s.auth.header = name.into();
            refused(validate(&s).unwrap_err(), GatewaySettingsRule::Auth);
        }
        for scheme in ["", "Bearer", "RAW", "basic", "bearer "] {
            let mut s = settings();
            s.auth.scheme = scheme.into();
            refused(validate(&s).unwrap_err(), GatewaySettingsRule::Auth);
        }
    }

    #[test]
    fn gateway_header_count_accepts_eight_and_refuses_nine() {
        let mut s = settings();
        s.headers = (0..8).map(|i| header(&format!("x-{i}"), "ok")).collect();
        assert!(validate(&s).is_ok());
        s.headers.push(header("x-8", "ok"));
        refused(validate(&s).unwrap_err(), GatewaySettingsRule::HeaderCount);
    }

    #[test]
    fn gateway_header_name_accepts_64_bytes_and_refuses_65() {
        let mut s = settings();
        s.headers = vec![header(&"a".repeat(64), "ok")];
        assert!(validate(&s).is_ok());
        s.headers[0].name.push('a');
        refused(validate(&s).unwrap_err(), GatewaySettingsRule::HeaderName);
    }

    #[test]
    fn gateway_header_name_grammar_order_repeats_and_refused_names() {
        let mut s = settings();
        s.headers = vec![header("a09!#$%&'*+-.^_`|~", "ok")];
        assert!(validate(&s).is_ok());
        for name in [
            "",
            "X-Test",
            "x test",
            "x-test:",
            "x-test\n",
            "é",
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "upgrade",
            "cookie",
            "authorization",
            "proxy-authorization",
            "x-api-key",
        ] {
            s.headers = vec![header(name, "must-not-appear-in-refusal")];
            refused(validate(&s).unwrap_err(), GatewaySettingsRule::HeaderName);
        }
        s.auth.header = "x-custom-auth".into();
        s.headers = vec![header("x-custom-auth", "must-not-appear-in-refusal")];
        refused(validate(&s).unwrap_err(), GatewaySettingsRule::HeaderName);
        for names in [["x-b", "x-a"], ["x-a", "x-a"]] {
            s.headers = names.into_iter().map(|name| header(name, "ok")).collect();
            refused(validate(&s).unwrap_err(), GatewaySettingsRule::HeaderName);
        }
        s.headers = vec![header("x-a", "ok"), header("x-b", "ok")];
        assert!(validate(&s).is_ok());
    }

    #[test]
    fn gateway_header_value_accepts_1024_bytes_and_refuses_1025() {
        let mut s = settings();
        s.headers = vec![header("x-test", &"a".repeat(1024))];
        assert!(validate(&s).is_ok());
        s.headers[0].value.push('a');
        refused(validate(&s).unwrap_err(), GatewaySettingsRule::HeaderValue);
    }

    #[test]
    fn gateway_header_value_bytes_whitespace_and_json_are_refused_without_echo() {
        let mut s = settings();
        for value in ["! ~", "a b", "{bad-json}", "42", "null", "true", "\"text\""] {
            s.headers = vec![header("x-test", value)];
            assert!(validate(&s).is_ok(), "{value}");
        }
        for value in [
            "",
            " leading",
            "trailing ",
            "\tsecret",
            "secret\r",
            "a\nb",
            "a\0b",
            "a\u{1f}b",
            "a\u{7f}b",
            "é",
            "{}",
            "[]",
            "{\"key\":\"secret\"}",
            "[\"secret\"]",
        ] {
            s.headers = vec![header("x-test", value)];
            refused(validate(&s).unwrap_err(), GatewaySettingsRule::HeaderValue);
        }
        // Every printable byte is allowed when the value is neither padded nor JSON.
        let printable: String = (0x20u8..=0x7e).map(char::from).collect();
        s.headers = vec![header("x-test", &format!("a{printable}z"))];
        assert!(validate(&s).is_ok());
    }

    #[test]
    fn gateway_provider_slug_accepts_32_bytes_and_refuses_33() {
        let s = settings();
        let provider_id = format!("stepfun-ai-gw-{}", "a".repeat(32));
        let id = format!("apikey:{provider_id}:eu");
        assert_eq!(
            validate_gateway_settings(&id, &s, std::slice::from_ref(&provider_id))
                .unwrap()
                .vendor,
            ModelVendor::StepFun
        );
        let too_long = format!("{provider_id}a");
        refused(
            validate_gateway_settings(&format!("apikey:{too_long}"), &s, &[too_long]).unwrap_err(),
            GatewaySettingsRule::ProviderId,
        );
    }

    #[test]
    fn gateway_provider_ids_use_first_marker_and_only_model_vendor_ids() {
        let s = settings();
        for (vendor, prefix) in MODEL_VENDOR_FUSIFORM_IDS {
            for slug in ["x", "a1-b2", "x-gw-y", "x-"] {
                let provider_id = format!("{prefix}-gw-{slug}");
                assert!(check_provider_ids(std::slice::from_ref(&provider_id)).is_ok());
                assert_eq!(
                    validate_gateway_settings(&format!("apikey:{provider_id}"), &s, &[provider_id])
                        .unwrap()
                        .vendor,
                    *vendor
                );
            }
        }
        for provider_id in [
            "openrouter-gw-x",
            "unknown-gw-x",
            "moonshot-gw-x",
            "qwen-gw-x",
            "anthropic",
            "anthropic-gw-",
            "anthropic-gw-1x",
            "anthropic-gw--x",
            "anthropic-gw-X",
            "anthropic-gw-x_y",
            "anthropic-gw-x.y",
            "anthropic-gw-é",
        ] {
            refused(
                validate_gateway_settings(
                    &format!("apikey:{provider_id}"),
                    &s,
                    &[provider_id.into()],
                )
                .unwrap_err(),
                GatewaySettingsRule::ProviderId,
            );
        }
        for ids in [
            vec![],
            vec!["anthropic-gw-acme".into(); 2],
            vec!["openai-gw-acme".into()],
        ] {
            refused(
                validate_gateway_settings("apikey:anthropic-gw-acme", &s, &ids).unwrap_err(),
                GatewaySettingsRule::ProviderId,
            );
        }
        assert_eq!(
            gateway_provider_vendor("moonshotai-gw-x"),
            Some(ModelVendor::Moonshot)
        );
        assert_eq!(
            gateway_provider_vendor("alibaba-gw-x"),
            Some(ModelVendor::Qwen)
        );
    }

    #[test]
    fn gateway_credential_id_accepts_only_apikey_service_and_optional_label() {
        let s = settings();
        let ids = ["anthropic-gw-acme".into()];
        for id in ["apikey:anthropic-gw-acme", "apikey:anthropic-gw-acme:eu"] {
            assert!(validate_gateway_settings(id, &s, &ids).is_ok());
        }
        for id in [
            "anthropic-gw-acme",
            "oauth:anthropic-gw-acme",
            "apikey:",
            "apikey:anthropic-gw-acme:",
            "apikey:anthropic-gw-acme:eu:extra",
            "apikey:anthropic-gw-acme:bad|label",
            "apikey:anthropic-gw-acme:bad label",
            "apikey:anthropic-gw-acme:bad\tlabel",
            "apikey:anthropic-gw-acme:bad\u{7f}label",
        ] {
            refused(
                validate_gateway_settings(id, &s, &ids).unwrap_err(),
                GatewaySettingsRule::CredentialId,
            );
        }
        refused(
            validate_gateway_settings("apikey:anthropic-gw-other", &s, &ids).unwrap_err(),
            GatewaySettingsRule::ProviderId,
        );
    }

    #[test]
    fn gateway_settings_digest_pins_compact_json_order_escaping_and_lowercase_sha256() {
        let mut s = settings();
        s.headers = vec![header("x-a", "a\"b\\c"), header("x-z", "2")];
        validate(&s).unwrap();
        // Independently hashed UTF-8 bytes, with JSON fields in the audit contract's order:
        // {"base_url":"https://gateway.example/v1","auth":{"header":"authorization","scheme":"bearer"},"headers":{"x-a":"a\"b\\c","x-z":"2"}}
        let expected = "0f1055b85bc64f6b44355776c91dc3bfc89f504308be3f6174ff180d7d8c2c99";
        let digest = gateway_settings_digest(&s);
        assert_eq!(digest, expected);
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        s.headers[1].value = "3".into();
        assert_ne!(gateway_settings_digest(&s), expected);
    }

    #[test]
    fn gateway_marker_is_absent_from_unique_vendor_ids_and_catalog_defaults() {
        let mut seen = std::collections::BTreeSet::new();
        for (_, id) in MODEL_VENDOR_FUSIFORM_IDS {
            assert!(seen.insert(id), "repeated vendor id {id}");
            assert!(!id.contains("-gw-"), "reserved marker in vendor id {id}");
        }
        for row in crate::catalog::API_KEY_PROVIDERS {
            assert!(
                !row.key.contains("-gw-"),
                "reserved marker in catalog key {}",
                row.key
            );
            for id in row.default_provider_ids {
                assert!(!id.contains("-gw-"), "reserved marker in default id {id}");
            }
        }
    }
}
