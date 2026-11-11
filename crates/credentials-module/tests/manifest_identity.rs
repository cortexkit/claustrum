//! The Entorhinal contract and the manifest proposal's identity check.

use std::time::Duration;

use async_trait::async_trait;
use claustrum_module_probe::federation::{management_surface, OutboundClient};
use claustrum_module_probe::manifest_identity::{
    check_identity, decode_identity_reply, EntorhinalIdentity, GithubIdentity,
    GithubIdentitySource, GoneReason, IdentityCheckError, IdentityRefusal, IdentityReply,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "federation/support.rs"]
mod support;

const AGENT: &str = "agent_0000000000000001";
const BUDGET: Duration = Duration::from_secs(30);

struct Stub {
    agent_id: String,
    reply: Result<IdentityReply, IdentityCheckError>,
}

impl Stub {
    fn decoded(agent_id: &str, reply: Value) -> Self {
        Self {
            agent_id: agent_id.into(),
            reply: Ok(decode_identity_reply(reply).expect("identity contract reply")),
        }
    }
}

#[async_trait]
impl GithubIdentitySource for Stub {
    async fn github_identity(
        &self,
        agent_id: &str,
        budget: Duration,
    ) -> Result<IdentityReply, IdentityCheckError> {
        assert_eq!(agent_id, self.agent_id);
        assert_eq!(budget, BUDGET);
        self.reply.clone()
    }
}

fn app() -> Value {
    json!({
        "kind": "app",
        "app_id": 314159,
        "app_slug": "fern-bot",
        "credential_ref": "github_app:fern-bot",
        "coauthor_line": "Co-authored-by: synthetic-bot",
    })
}

fn success(identity: Value) -> Value {
    json!({"result": {
        "github_identity": identity,
        "agent_generation": 2,
        "generation": 13,
        "incarnation": "0123456789abcdef",
    }})
}

async fn check(source: &impl GithubIdentitySource) -> Result<(), IdentityCheckError> {
    check_identity(source, AGENT, 314159, "fern-bot", BUDGET).await
}

#[tokio::test]
async fn identity_stub_covers_every_success_and_refusal_shape() {
    let mut full_app = app();
    full_app["installation_id"] = json!(271828);
    full_app["client_id"] = json!("Iv23syntheticFernBot");
    for (name, reply, expected) in [
        ("app_without_optionals", success(app()), Ok(())),
        ("app_with_optionals", success(full_app), Ok(())),
        (
            "user_token_null_coauthor",
            success(json!({
                "kind": "user_token", "login": "fern-gardener",
                "credential_ref": "github_user:fern-gardener", "coauthor_line": null,
            })),
            Err(IdentityCheckError::Mismatch),
        ),
        (
            "user_token_with_coauthor",
            success(json!({
                "kind": "user_token", "login": "fern-gardener",
                "credential_ref": "github_user:fern-gardener", "coauthor_line": "synthetic",
            })),
            Err(IdentityCheckError::Mismatch),
        ),
        (
            "null",
            success(Value::Null),
            Err(IdentityCheckError::Mismatch),
        ),
        (
            "unknown_agent",
            json!({"code":"unknown_agent", "message":"unknown agent"}),
            Err(IdentityCheckError::Mismatch),
        ),
        (
            "gone_deleted",
            json!({"code":"gone", "message":"agent is gone", "detail":{
                "reason":"deleted", "at":700,
            }}),
            Err(IdentityCheckError::Mismatch),
        ),
        (
            "gone_merged",
            json!({"code":"gone", "message":"agent is gone", "detail":{
                "reason":"merged", "at":700, "into_agent_id":"agent_0000000000000602",
            }}),
            Err(IdentityCheckError::Mismatch),
        ),
        (
            "invalid_request",
            json!({"code":"invalid_request", "message":"invalid agent_id", "detail":null}),
            Err(IdentityCheckError::Mismatch),
        ),
    ] {
        assert_eq!(
            check(&Stub::decoded(AGENT, reply)).await,
            expected,
            "{name}"
        );
    }
    let unavailable = Stub {
        agent_id: AGENT.into(),
        reply: Err(IdentityCheckError::Unavailable),
    };
    assert_eq!(
        check(&unavailable).await,
        Err(IdentityCheckError::Unavailable)
    );
    assert_eq!(IdentityCheckError::Mismatch.code(), "identity_mismatch");
    assert_eq!(
        IdentityCheckError::Unavailable.code(),
        "identity_unavailable"
    );
}

#[tokio::test]
async fn identity_stub_rejects_each_mismatched_app_field() {
    for (field, wrong_value) in [
        ("app_id", json!(314160)),
        ("app_slug", json!("Fern-Bot")),
        ("credential_ref", json!("github_app:another-bot")),
        ("credential_ref", json!("github_user:fern-bot")),
    ] {
        let mut identity = app();
        identity[field] = wrong_value;
        assert_eq!(
            check(&Stub::decoded(AGENT, success(identity))).await,
            Err(IdentityCheckError::Mismatch),
            "{field}",
        );
    }
}

#[tokio::test]
async fn identity_incarnation_is_decoded_but_never_fences_a_matching_app() {
    for incarnation in ["0123456789abcdef", "0000000000000000", "ffffffffffffffff"] {
        let mut reply = success(app());
        reply["result"]["incarnation"] = json!(incarnation);
        reply["result"]["projectId"] = json!("pj-synthetic");
        let stub = Stub::decoded(AGENT, reply);
        let IdentityReply::Success(snapshot) = stub.reply.as_ref().unwrap() else {
            panic!("expected identity snapshot");
        };
        assert_eq!(snapshot.incarnation, incarnation);
        assert_eq!(snapshot.agent_generation, 2);
        assert_eq!(snapshot.generation, 13);
        assert_eq!(snapshot.project_id.as_deref(), Some("pj-synthetic"));
        assert_eq!(check(&stub).await, Ok(()));
    }
}

#[test]
fn identity_decoder_preserves_tagged_fields_and_gone_details() {
    let mut identity = app();
    identity["installation_id"] = json!(271828);
    identity["client_id"] = json!("Iv23syntheticFernBot");
    for (body, installation_id, client_id) in [
        (identity, Some(271828), Some("Iv23syntheticFernBot")),
        (app(), None, None),
    ] {
        let IdentityReply::Success(snapshot) = decode_identity_reply(success(body)).unwrap() else {
            panic!("expected app snapshot");
        };
        assert_eq!(snapshot.project_id, None);
        assert_eq!(
            snapshot.github_identity,
            Some(GithubIdentity::App {
                app_id: 314159,
                app_slug: "fern-bot".into(),
                installation_id,
                client_id: client_id.map(String::from),
                credential_ref: "github_app:fern-bot".into(),
                coauthor_line: "Co-authored-by: synthetic-bot".into(),
            })
        );
    }
    for (reason, into_agent_id, expected_reason) in [
        ("deleted", None, GoneReason::Deleted),
        ("merged", Some("agent_0000000000000602"), GoneReason::Merged),
    ] {
        let mut detail = json!({"reason":reason, "at":700});
        if let Some(into) = into_agent_id {
            detail["into_agent_id"] = json!(into);
        }
        let IdentityReply::Refused(IdentityRefusal::Gone { message, detail }) =
            decode_identity_reply(
                json!({"code":"gone", "message":"agent is gone", "detail":detail}),
            )
            .unwrap()
        else {
            panic!("expected gone detail");
        };
        assert_eq!(message, "agent is gone");
        assert_eq!(detail.reason, expected_reason);
        assert_eq!(detail.at, 700);
        assert_eq!(detail.into_agent_id.as_deref(), into_agent_id);
    }
}

#[test]
fn identity_decoder_checks_required_types_and_non_null_app_optionals() {
    for field in ["installation_id", "client_id", "coauthor_line"] {
        let mut identity = app();
        identity[field] = Value::Null;
        assert!(decode_identity_reply(success(identity)).is_err(), "{field}");
    }
    for field in [
        "agent_generation",
        "generation",
        "incarnation",
        "github_identity",
    ] {
        let mut reply = success(app());
        reply["result"].as_object_mut().unwrap().remove(field);
        assert!(decode_identity_reply(reply).is_err(), "missing {field}");
    }
    for field in ["agent_generation", "generation"] {
        let mut reply = success(app());
        reply["result"][field] = json!(1.5);
        assert!(decode_identity_reply(reply).is_err(), "fractional {field}");
    }
    let mut identity = app();
    identity["kind"] = json!("future_kind");
    assert!(decode_identity_reply(success(identity)).is_err());
}

const VECTORS: &[u8] = include_bytes!("vectors/agent-github-identity-v1/github-identity.json");
const VECTOR_README: &[u8] = include_bytes!("vectors/agent-github-identity-v1/README.md");

fn expected_vectors() -> [(&'static str, Result<(), IdentityCheckError>); 7] {
    [
        ("agent_0000000000000001", Ok(())),
        ("agent_0000000000000002", Ok(())),
        ("agent_0000000000000003", Err(IdentityCheckError::Mismatch)),
        ("agent_0000000000000602", Err(IdentityCheckError::Mismatch)),
        ("agent_ffffffffffffffff", Err(IdentityCheckError::Mismatch)),
        ("agent_0000000000000004", Err(IdentityCheckError::Mismatch)),
        ("agent_0000000000000601", Err(IdentityCheckError::Mismatch)),
    ]
}

#[tokio::test]
async fn identity_published_vectors_have_pinned_bytes_and_expected_outcomes() {
    assert_eq!(
        format!("{:x}", Sha256::digest(VECTORS)),
        "5dec4c5a383c69d76a382d02630cf1bd474766daee76c4259522e873427b29fa",
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(VECTOR_README)),
        "66d485ff508f64a7a21a904943edcee5a678b2d091ce8d21bbe4ef9b5c566c1a",
    );
    let records: Vec<Value> = serde_json::from_slice(VECTORS).unwrap();
    assert_eq!(records.len(), 7);
    for (record, (agent_id, expected)) in records.into_iter().zip(expected_vectors()) {
        assert_eq!(record["op"], "agent.github_identity");
        assert_eq!(record["request"], json!({"agent_id":agent_id}));
        assert_eq!(
            record["principal"],
            json!({"kind":"reserved", "moduleId":"claustrum"})
        );
        let source = Stub::decoded(agent_id, record["reply"].clone());
        assert_eq!(
            check_identity(&source, agent_id, 314159, "fern-bot", BUDGET).await,
            expected,
            "{agent_id}",
        );
    }
}

#[tokio::test]
async fn identity_production_calls_entorhinal_and_decodes_real_response_and_error_frames() {
    let root = support::temp_root("manifest-identity-wire");
    let stand_in = support::SharedCallosumStandIn::start(&root).await;
    let source = EntorhinalIdentity::new(OutboundClient::for_daemon(
        stand_in.connection_file(),
        "claustrum",
        Some("identity-nonce"),
    ));
    let records: Vec<Value> = serde_json::from_slice(VECTORS).unwrap();
    for (record, (agent_id, expected)) in records.into_iter().zip(expected_vectors()) {
        let reply = &record["reply"];
        let answer = if let Some(result) = reply.get("result") {
            support::Reply::Ok(result.clone())
        } else {
            support::Reply::SubscriptionError {
                channel_zero: false,
                body: reply.clone(),
            }
        };
        // The stand-in scripts all replies under its fixed target, but records
        // the actual management surface from route.open separately in the ledger.
        stand_in.answer(support::TARGET_MODULE, "agent.github_identity", answer);
        assert_eq!(
            support::wait_for_signal(check_identity(
                &source, agent_id, 314159, "fern-bot", BUDGET
            ))
            .await,
            expected,
            "{agent_id}",
        );
    }
    let requests: Vec<_> = stand_in
        .ledger()
        .into_iter()
        .filter_map(|row| match row {
            support::Ledger::Request {
                target,
                method,
                params,
            } => Some((target, method, params)),
            _ => None,
        })
        .collect();
    let expected_requests: Vec<_> = expected_vectors()
        .into_iter()
        .map(|(agent_id, _)| {
            (
                "entorhinal".to_string(),
                "agent.github_identity".to_string(),
                json!({"agent_id":agent_id}),
            )
        })
        .collect();
    assert_eq!(requests, expected_requests);
    let opens = stand_in.opens("entorhinal");
    assert_eq!(opens.len(), 1);
    assert_eq!(
        opens[0]["target"],
        serde_json::to_value(management_surface("entorhinal")).unwrap()
    );
    assert_eq!(
        opens[0]["consumer_identity"],
        json!({
            "module_id":"claustrum", "launch_nonce":"identity-nonce",
        })
    );
}

#[tokio::test]
async fn identity_production_maps_invalid_request_and_channel_zero_refusals_to_mismatch() {
    let root = support::temp_root("manifest-identity-refusals");
    let stand_in = support::SharedCallosumStandIn::start(&root).await;
    let source = EntorhinalIdentity::new(OutboundClient::for_daemon(
        stand_in.connection_file(),
        "claustrum",
        Some("identity-nonce"),
    ));
    for channel_zero in [false, true] {
        for body in [
            json!({"code":"unknown_agent", "message":"unknown agent"}),
            json!({"code":"gone", "message":"agent is gone", "detail":{"reason":"deleted", "at":700}}),
            json!({"code":"invalid_request", "message":"invalid agent_id"}),
        ] {
            stand_in.answer(
                support::TARGET_MODULE,
                "agent.github_identity",
                support::Reply::SubscriptionError { channel_zero, body },
            );
            assert_eq!(
                support::wait_for_signal(check(&source)).await,
                Err(IdentityCheckError::Mismatch)
            );
        }
    }
}

#[tokio::test]
async fn identity_production_unreachable_or_unusable_replies_are_unavailable() {
    let root = support::temp_root("manifest-identity-unavailable");
    let absent = EntorhinalIdentity::new(OutboundClient::for_daemon(
        root.join("absent-connection.json"),
        "claustrum",
        Some("identity-nonce"),
    ));
    assert_eq!(
        support::wait_for_signal(check(&absent)).await,
        Err(IdentityCheckError::Unavailable)
    );

    let stand_in = support::SharedCallosumStandIn::start(&root).await;
    let source = EntorhinalIdentity::new(OutboundClient::for_daemon(
        stand_in.connection_file(),
        "claustrum",
        Some("identity-nonce"),
    ));
    for answer in [
        support::Reply::Ok(json!({"unexpected":"body"})),
        support::Reply::RouteRefusal("unknown_method".into()),
        support::Reply::Permanent("fed_not_exposed".into()),
        support::Reply::Drop,
    ] {
        stand_in.answer(support::TARGET_MODULE, "agent.github_identity", answer);
        assert_eq!(
            support::wait_for_signal(check(&source)).await,
            Err(IdentityCheckError::Unavailable)
        );
    }
}
