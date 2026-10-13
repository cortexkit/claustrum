//! Meta Muse derives inference keys from a vaulted identity token. Like the GitHub
//! App adapter, it preserves minting material and serves only the derived key.
//! The refresh-token slot contains a sealed JSON `MetaSession`, including any OAuth
//! refresh token for custody only: no refresh-token grant has been observed.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens};
use crate::device_flow::{DeviceBodyEncoding, DeviceFlowConfig, DeviceTokens};
use crate::oauth::OAuthCredential;
use crate::record::{RecordIdentity, VaultRecord};
use crate::secret::{SecretBytes, SecretString};

pub const ADAPTER_NAME: &str = "meta";
pub const CLIENT_ID: &str = "1031625952748946";
pub const DEVICE_CODE_URL: &str = "https://auth.meta.com/oidc/device/authorization/";
pub const DEVICE_TOKEN_URL: &str = "https://auth.meta.com/oidc/device/token/";
pub const KEY_URL: &str = "https://api.meta.ai/muse-code/key";

/// Sent on every Meta request. auth.meta.com answers a request with no User-Agent
/// with a 302 to `facebook.com/unsupportedbrowser` (measured on both the device
/// authorization and token endpoints), and our HTTP client sends none by default.
pub const USER_AGENT: &str = concat!("cortexkit-credentials/", env!("CARGO_PKG_VERSION"));
/// The API version header both reference clients send on every Meta request.
pub const API_VERSION: &str = "1.0.0";

/// Assumed key lifetime, following pi-meta-oauth, only when neither the response
/// nor the key's JWT supplies expiry. Replace this assumption once a live response
/// shows the real lifetime; the device identity token's lifetime is unrelated.
pub const ASSUMED_KEY_FRESHNESS_LIMIT_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Serialize, Deserialize)]
struct MetaSession {
    identity_token: SecretString,
    refresh_token: Option<SecretString>,
}

pub fn device_config() -> DeviceFlowConfig {
    let mut cfg = DeviceFlowConfig::new(
        DEVICE_CODE_URL,
        DEVICE_TOKEN_URL,
        CLIENT_ID,
        DeviceBodyEncoding::Form,
    );
    cfg.extra_headers = vec![
        ("User-Agent".into(), USER_AGENT.into()),
        ("Accept".into(), "application/json".into()),
        ("x-api-version".into(), API_VERSION.into()),
    ];
    cfg
}

/// Presence diagnostics only: never render the provider's token or expiry values.
#[derive(Debug)]
pub struct LoginFields {
    pub refresh_token_present: bool,
    pub device_expiry_field_present: bool,
    pub key_expiry_field_present: bool,
}

/// Mint before constructing a login record, so an unusable subscription or dead
/// session cannot overwrite a working credential during `login --replace`.
pub async fn login_record(
    tokens: DeviceTokens,
    http: &dyn HttpTransport,
) -> Result<(VaultRecord, LoginFields), RefreshError> {
    let session = MetaSession {
        identity_token: tokens.access_token.into(),
        refresh_token: tokens.refresh_token.map(Into::into),
    };
    let minted = mint_key(&session.identity_token, http).await?;
    let fields = LoginFields {
        refresh_token_present: session.refresh_token.is_some(),
        device_expiry_field_present: tokens.expiry_field_present,
        key_expiry_field_present: minted.expiry_field_present,
    };
    let oauth = OAuthCredential {
        access_token: minted.key,
        refresh_token: serde_json::to_string(&session)
            .map_err(|_| RefreshError::Decode("could not seal Meta session".into()))?
            .into(),
        expires_at_ms: Some(minted.expires_at_ms),
        token_url: KEY_URL.into(),
        client_id: Some(CLIENT_ID.into()),
        client_secret: None,
        scopes: vec![],
    };
    let payload = SecretBytes::new(oauth.access_token.expose().as_bytes().to_vec());
    let mut record = VaultRecord::new_oauth("login", ADAPTER_NAME, oauth, payload);
    record.identity = minted.identity;
    Ok((record, fields))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AbsoluteExpiry {
    Seconds(i64),
    Text(String),
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    api_key: Option<SecretString>,
    user_id: Option<String>,
    user_email: Option<String>,
    is_subs_active: Option<bool>,
    require_payment: Option<bool>,
    action_url: Option<String>,
    require_payment_action_url: Option<String>,
    // These expiry field names and units are assumed, not confirmed by captured
    // Meta responses. Reject an invalid expiry instead of using the 24-hour fallback.
    expires_in: Option<i64>,
    expires_at: Option<AbsoluteExpiry>,
    expires_at_ms: Option<i64>,
}

impl KeyResponse {
    fn expiry_field_present(&self) -> bool {
        self.expires_in.is_some() || self.expires_at.is_some() || self.expires_at_ms.is_some()
    }

    fn expiry(&self, key: &SecretString, minted_at_ms: i64) -> Result<i64, RefreshError> {
        let invalid = || RefreshError::Decode("Meta key response has an invalid expiry".into());
        if let Some(ms) = self.expires_at_ms {
            return (ms >= 0).then_some(ms).ok_or_else(invalid);
        }
        if let Some(absolute) = &self.expires_at {
            return match absolute {
                AbsoluteExpiry::Seconds(seconds) if *seconds >= 0 => {
                    Ok(seconds.saturating_mul(1000))
                }
                AbsoluteExpiry::Text(text) => chrono::DateTime::parse_from_rfc3339(text)
                    .map(|date| date.timestamp_millis())
                    .map_err(|_| invalid()),
                _ => Err(invalid()),
            };
        }
        if let Some(seconds) = self.expires_in {
            return crate::oauth_login::relative_expiry_ms(minted_at_ms, Some(seconds))
                .ok_or_else(invalid);
        }
        Ok(crate::oauth_login::access_token_expiry_ms(key.expose())
            .unwrap_or_else(|| minted_at_ms.saturating_add(ASSUMED_KEY_FRESHNESS_LIMIT_MS)))
    }

    fn subscription_required(&self) -> bool {
        // Follow the source client's subscription signals: reject explicit inactivity
        // even with a key; payment/action URLs require a missing or blank key.
        self.is_subs_active == Some(false)
            || (self
                .api_key
                .as_ref()
                .is_none_or(|key| key.expose().trim().is_empty())
                && (self.require_payment == Some(true)
                    || self
                        .action_url
                        .as_ref()
                        .is_some_and(|url| !url.trim().is_empty())
                    || self
                        .require_payment_action_url
                        .as_ref()
                        .is_some_and(|url| !url.trim().is_empty())))
    }
}

struct MintedKey {
    key: SecretString,
    expires_at_ms: i64,
    identity: RecordIdentity,
    expiry_field_present: bool,
}

async fn mint_key(
    identity_token: &SecretString,
    http: &dyn HttpTransport,
) -> Result<MintedKey, RefreshError> {
    if identity_token.expose().trim().is_empty() {
        return Err(RefreshError::InvalidGrant(
            "Meta identity token is missing; re-login required".into(),
        ));
    }
    let authorization = SecretString::new(format!("Bearer {}", identity_token.expose()));
    let response = http
        .post(
            KEY_URL,
            &[
                ("Authorization", authorization.expose()),
                ("User-Agent", USER_AGENT),
                ("x-api-version", API_VERSION),
                ("Accept", "application/json"),
            ],
            "application/json",
            br#"{"onboard":true}"#.to_vec(),
        )
        .await?;
    // Rate limits and upstream outages stay retryable, even if their bodies
    // contain subscription fields; they must not invalidate the stored session.
    if response.status == 429 || response.status >= 500 {
        return Err(RefreshError::Status(
            response.status,
            "Meta key mint is temporarily unavailable".into(),
        ));
    }
    if response.status == 402 {
        return Err(RefreshError::SubscriptionRequired);
    }
    let parsed = serde_json::from_slice::<KeyResponse>(&response.body);
    // The source client checks subscription flags on successful responses only.
    // Do not infer a payment problem from arbitrary text or from a session 401/403.
    if (200..300).contains(&response.status)
        && parsed
            .as_ref()
            .is_ok_and(KeyResponse::subscription_required)
    {
        return Err(RefreshError::SubscriptionRequired);
    }
    if response.status == 401 || response.status == 403 {
        return Err(RefreshError::InvalidGrant(
            "Meta session expired; re-login required".into(),
        ));
    }
    if !(200..300).contains(&response.status) {
        return Err(RefreshError::Status(
            response.status,
            "Meta key mint was rejected".into(),
        ));
    }
    // Provider bodies and serde errors may contain secrets, so discard their
    // details and return fixed error messages that are safe for the operator.
    let parsed = parsed
        .map_err(|_| RefreshError::Decode("Meta key response has an unsupported shape".into()))?;
    let key = parsed
        .api_key
        .as_ref()
        .filter(|key| !key.expose().trim().is_empty())
        .ok_or_else(|| {
            RefreshError::Decode("Meta key response contained no inference key".into())
        })?;
    let expires_at_ms = parsed.expiry(key, now_ms())?;
    let identity = RecordIdentity {
        account_id: parsed.user_id.clone().filter(|id| !id.trim().is_empty()),
        email: parsed
            .user_email
            .clone()
            .filter(|email| !email.trim().is_empty()),
        org_name: None,
    };
    if identity.account_id.is_none() || identity.validate().is_err() {
        return Err(RefreshError::Decode(
            "Meta key response contained no valid account identity".into(),
        ));
    }
    Ok(MintedKey {
        key: key.clone(),
        expires_at_ms,
        identity,
        expiry_field_present: parsed.expiry_field_present(),
    })
}

#[derive(Default)]
pub struct MetaAdapter;

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[async_trait]
impl RefreshAdapter for MetaAdapter {
    fn name(&self) -> &str {
        ADAPTER_NAME
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        let session: MetaSession = serde_json::from_str(cred.refresh_token.expose())
            .map_err(|_| RefreshError::Decode("invalid vaulted Meta session".into()))?;
        let minted = mint_key(&session.identity_token, http).await?;
        Ok(RefreshedTokens {
            access_token: minted.key,
            refresh_token: cred.refresh_token.clone(),
            expires_at_ms: Some(minted.expires_at_ms),
            github_app_permissions: None,
        })
    }
}

#[cfg(test)]
#[path = "meta/fixtures.rs"]
pub(crate) mod fixtures;
#[cfg(test)]
#[path = "meta/tests.rs"]
mod tests;
