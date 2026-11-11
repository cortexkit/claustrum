//! Entorhinal's identity check for a proposed GitHub App manifest binding.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use crate::federation::{management_surface, OutboundClient, OutboundError, RouteCall};

/// The identity lookup is separate from proposal storage so tests need no peer daemon.
#[async_trait]
pub trait GithubIdentitySource: Send + Sync {
    async fn github_identity(
        &self,
        agent_id: &str,
        budget: Duration,
    ) -> Result<IdentityReply, IdentityCheckError>;
}

/// The production identity source, sharing the vault's outbound connection.
pub struct EntorhinalIdentity {
    outbound: OutboundClient,
}

impl EntorhinalIdentity {
    pub fn new(outbound: OutboundClient) -> Self {
        Self { outbound }
    }
}

#[async_trait]
impl GithubIdentitySource for EntorhinalIdentity {
    async fn github_identity(
        &self,
        agent_id: &str,
        budget: Duration,
    ) -> Result<IdentityReply, IdentityCheckError> {
        match self
            .outbound
            .call(
                "entorhinal-github-identity",
                RouteCall {
                    target: management_surface("entorhinal"),
                    prelude: None,
                    request: json!({
                        "method": "agent.github_identity",
                        "params": {"agent_id": agent_id},
                    }),
                },
                budget,
            )
            .await
        {
            Ok(reply) => decode_identity_reply(reply).map_err(|_| IdentityCheckError::Unavailable),
            // Channel-zero refusals expose only code and message. Target-channel
            // Error bodies retain their detail and pass through the decoder above.
            Err(OutboundError::Refused { code, .. }) => Err(match code.as_str() {
                "unknown_agent" | "gone" | "invalid_request" => IdentityCheckError::Mismatch,
                _ => IdentityCheckError::Unavailable,
            }),
            Err(OutboundError::Unavailable(_)) => Err(IdentityCheckError::Unavailable),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityReply {
    Success(IdentitySnapshot),
    Refused(IdentityRefusal),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IdentitySnapshot {
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub github_identity: Option<GithubIdentity>,
    pub agent_generation: i64,
    pub generation: i64,
    // Entorhinal changes this metadata on restart; it does not affect App matching.
    pub incarnation: String,
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GithubIdentity {
    App {
        app_id: i64,
        app_slug: String,
        #[serde(default, deserialize_with = "present_optional")]
        installation_id: Option<i64>,
        #[serde(default, deserialize_with = "present_optional")]
        client_id: Option<String>,
        credential_ref: String,
        coauthor_line: String,
    },
    UserToken {
        login: String,
        credential_ref: String,
        #[serde(deserialize_with = "Deserialize::deserialize")]
        coauthor_line: Option<String>,
    },
}

// An absent optional App field is allowed, but a present field must be non-null.
fn present_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum IdentityRefusal {
    UnknownAgent {
        message: String,
        detail: Option<Value>,
    },
    Gone {
        message: String,
        detail: GoneDetail,
    },
    InvalidRequest {
        message: String,
        detail: Option<Value>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GoneDetail {
    pub reason: GoneReason,
    pub at: i64,
    pub into_agent_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoneReason {
    Deleted,
    Merged,
}

/// Accept both the published envelope and OutboundClient's unwrapped result.
/// Error frames have no result envelope and retain their typed refusal details.
pub fn decode_identity_reply(reply: Value) -> Result<IdentityReply, serde_json::Error> {
    let reply = reply.get("result").cloned().unwrap_or(reply);
    if reply.get("code").is_some() {
        serde_json::from_value(reply).map(IdentityReply::Refused)
    } else {
        serde_json::from_value(reply).map(IdentityReply::Success)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCheckError {
    Mismatch,
    Unavailable,
}

impl IdentityCheckError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Mismatch => "identity_mismatch",
            Self::Unavailable => "identity_unavailable",
        }
    }
}

/// Only the App id, slug, and vault credential reference authorize the binding.
pub async fn check_identity(
    source: &(impl GithubIdentitySource + ?Sized),
    agent_id: &str,
    app_id: i64,
    app_slug: &str,
    budget: Duration,
) -> Result<(), IdentityCheckError> {
    let reply = source.github_identity(agent_id, budget).await?;
    match reply {
        IdentityReply::Success(IdentitySnapshot {
            github_identity:
                Some(GithubIdentity::App {
                    app_id: actual_id,
                    app_slug: actual_slug,
                    credential_ref,
                    ..
                }),
            ..
        }) if actual_id == app_id
            && actual_slug == app_slug
            && credential_ref == format!("github_app:{app_slug}") =>
        {
            Ok(())
        }
        _ => Err(IdentityCheckError::Mismatch),
    }
}
