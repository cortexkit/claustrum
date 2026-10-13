//! Reconstructed HTTP fixtures, NOT captured live exchanges. Based on
//! TheStreamCode/opencode-muse-auth src/auth.ts and BlockedPath/pi-meta-oauth
//! src/meta/oauth.ts and constants.ts (reviewed 2026-10-12).
//!
//! Assumptions: device replies use RFC 8628 fields and JSON pending/slow_down
//! errors at HTTP 400; identity material arrives as access_token. Optional OAuth
//! refresh_token and expires_in fields are hypothetical (neither client models
//! them). Mint success uses api_key, user_id, optional user_email, with boolean
//! is_subs_active/require_payment and action_url/require_payment_action_url as in
//! opencode-muse-auth. Keys below are opaque examples, not real credentials.
//! Mint expiry spellings/units (expires_in seconds, expires_at Unix seconds or
//! RFC3339, expires_at_ms milliseconds) are provisional conventional shapes;
//! JWT exp is Unix seconds. 401/403 are session refusals, 402 is payment-required,
//! 429 is rate limiting, and 503 is transient. Error bodies are illustrative.
//! No identity-token lifetime or OAuth refresh-grant behavior is assumed.

pub const DEVICE_AUTH: &str = r#"{"device_code":"meta-device","user_code":"ABCD-EFGH","verification_uri":"https://auth.meta.com/device","verification_uri_complete":"https://auth.meta.com/device?user_code=ABCD-EFGH","interval":5,"expires_in":900}"#;
pub const PENDING: &str = r#"{"error":"authorization_pending"}"#;
pub const SLOW_DOWN: &str = r#"{"error":"slow_down"}"#;
pub const DEVICE_TOKEN: &str = r#"{"access_token":"meta-identity-token","token_type":"bearer"}"#;
pub const DEVICE_TOKEN_OPTIONALS: &str = r#"{"access_token":"meta-identity-token","refresh_token":"meta-refresh-token","expires_in":3600,"token_type":"bearer"}"#;
pub const KEY: &str = r#"{"api_key":"muse-inference-key","user_id":"meta-account","user_email":"muse@example.invalid","is_subs_active":true}"#;
pub const KEY_EXPIRY: &str =
    r#"{"api_key":"muse-inference-key","user_id":"meta-account","expires_in":3600}"#;
pub const KEY_JWT: &str =
    r#"{"api_key":"e30.eyJleHAiOjIwMDAwMDAwMDB9.sig","user_id":"meta-account"}"#;
pub const UNAUTHORIZED: &str = r#"{"error":"unauthorized"}"#;
pub const FORBIDDEN: &str = r#"{"error":"forbidden"}"#;
pub const INACTIVE: &str =
    r#"{"api_key":"muse-inference-key","user_id":"meta-account","is_subs_active":false}"#;
pub const PAYMENT: &str = r#"{"require_payment":true,"action_url":"https://meta.ai/subscribe"}"#;
pub const PAYMENT_ACTION: &str = r#"{"require_payment_action_url":"https://meta.ai/subscribe"}"#;
pub const TRANSIENT: &str =
    r#"{"error":"temporarily_unavailable","is_subs_active":false,"require_payment":true}"#;
