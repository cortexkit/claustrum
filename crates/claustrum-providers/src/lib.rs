//! Provider catalog, bounded refresh adapters, and provider login and HTTP flows.
#![forbid(unsafe_code)]

pub use claustrum_model::{credential_id, fusiform_providers, oauth, record, secret};

pub mod apns;
pub mod apns_submit;
pub mod bedrock;
pub mod catalog;
pub mod device_flow;
pub mod encoding;
pub mod google_login;
pub mod http;
pub mod list_auth_method;
pub mod oauth_login;
pub mod plan_detection;
pub mod refresh_adapters;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
