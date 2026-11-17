//! Credential record formats, encryption envelopes, and agent-secret validation.
#![forbid(unsafe_code)]

pub mod agent_secret;
pub mod credential_id;
pub mod envelope;
pub mod fusiform_providers;
pub mod key;
pub mod oauth;
pub mod plan_detection;
pub mod record;
pub mod secret;

pub use envelope::{open, seal, EnvelopeError, RecordBinding};
