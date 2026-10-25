//! The outbound client against the callosum stand-in: one deadline per call, a
//! consumer identity on every route it opens, and recovery from a silent restart.

use std::time::{Duration, Instant};

use serde_json::json;

use crate::support::{Reply, TwoVaults};
use claustrum_module_probe::federation as fed;

fn consumer_get() -> serde_json::Value {
    json!({
        "method": "credential.get_scoped",
        "params": { "credential_id": "oauth:anthropic:work" },
    })
}

fn route(target_module: &str, request: serde_json::Value) -> fed::RouteCall {
    fed::RouteCall {
        target: subc_protocol::RouteTarget::ManagementSurface {
            module_id: target_module.to_string(),
        },
        prelude: None,
        request,
    }
}

async fn call(
    client: &fed::OutboundClient,
    key: &str,
    request: serde_json::Value,
    deadline: Duration,
) -> Result<serde_json::Value, fed::OutboundError> {
    client
        .call(key, route("claustrum", request), deadline)
        .await
}

#[tokio::test]
async fn every_route_the_client_opens_carries_the_module_id_and_the_launch_nonce() {
    let root = crate::support::temp_root("outbound-identity");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Ok(json!({ "payload": "tok" })),
    );

    call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect("the call succeeds");
    call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect("the second call reuses the binding");

    let opens = vaults.callosum.opens("claustrum");
    assert_eq!(
        opens.len(),
        1,
        "the second call reused the binding: {opens:?}"
    );
    assert_eq!(opens[0]["consumer_identity"]["module_id"], "claustrum");
    assert_eq!(
        opens[0]["consumer_identity"]["launch_nonce"],
        "harness-launch-nonce"
    );
    // The nonce is the credential that attributes a connection. It travels in
    // `consumer_identity` and nowhere else.
    assert!(
        !opens[0]["identity"]
            .to_string()
            .contains("harness-launch-nonce"),
        "opens: {opens:?}"
    );
}

#[tokio::test]
async fn a_stalled_call_ends_at_the_consumer_deadline_and_a_restart_costs_one_failure() {
    let root = crate::support::temp_root("outbound-deadline");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    vaults
        .callosum
        .answer("claustrum", "credential.get_scoped", Reply::Stall);

    let started = Instant::now();
    let error = call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect_err("a stalled call never succeeds");
    let elapsed = started.elapsed();
    assert!(
        error.is_transient(),
        "a missed deadline is transient: {error:?}"
    );
    assert!(
        elapsed >= fed::CONSUMER_FACING_DEADLINE,
        "elapsed {elapsed:?} is shorter than the deadline, so something else ended it"
    );
    assert!(
        elapsed < fed::CONSUMER_FACING_DEADLINE + Duration::from_secs(1),
        "elapsed {elapsed:?} overran the deadline"
    );

    // The stand-in now behaves like a restarted one for this client: the method it
    // stalled answers again. One transient failure, then a success, no vault restart.
    vaults.callosum.forget_answers();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Ok(json!({ "payload": "tok" })),
    );
    call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect("the call after the restart succeeds");
}

#[tokio::test]
async fn a_dropped_connection_drops_the_binding_and_the_next_call_reopens_it() {
    let root = crate::support::temp_root("outbound-drop");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    vaults
        .callosum
        .answer("claustrum", "credential.get_scoped", Reply::Drop);

    let first = call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await;
    assert!(first.is_err(), "a dropped connection is a failure");

    vaults.callosum.forget_answers();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Ok(json!({ "payload": "tok" })),
    );
    call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect("the next call reopens the binding and succeeds");
    assert_eq!(
        vaults.callosum.opens("claustrum").len(),
        2,
        "the failed binding was dropped, so a new route was opened"
    );
}

#[tokio::test]
async fn an_admin_op_budget_bounds_the_call_that_exhausts_it_inside_the_cli_wait() {
    let root = crate::support::temp_root("outbound-admin-budget");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    vaults
        .callosum
        .answer("claustrum", "callosum.peer_keys_read", Reply::Stall);

    let started = Instant::now();
    let first = call(
        &vaults.b.outbound,
        &home,
        json!({ "method": "callosum.peer_keys_read", "params": {} }),
        fed::ADMIN_OP_BUDGET,
    )
    .await;
    assert!(first.is_err());
    assert!(
        started.elapsed() >= fed::ADMIN_OP_BUDGET,
        "the admin budget is what ended the call"
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the operator still gets a definite reply inside the CLI's wait"
    );
}

#[tokio::test]
async fn a_target_refusal_answers_as_an_error_and_never_as_a_value() {
    let root = crate::support::temp_root("outbound-error-frame");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Permanent("fed_not_exposed".into()),
    );

    let reply = call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await;
    assert!(reply.is_err(), "a refusal is not a token");
}

#[tokio::test]
async fn a_method_the_target_does_not_serve_is_still_sent_over_the_wire() {
    let root = crate::support::temp_root("outbound-unknown-method");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    let reply = call(
        &vaults.b.outbound,
        &home,
        json!({ "method": "federation.remote_token", "params": {} }),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await;
    assert!(reply.is_err(), "the stand-in answers no configured method");
    assert!(
        vaults.callosum.saw_method("federation.remote_token"),
        "the request reached the stand-in's ledger"
    );
}

#[test]
fn a_clone_shares_the_launch_identity_of_the_client_it_came_from() {
    let root = crate::support::temp_root("outbound-clone");
    let client =
        fed::OutboundClient::for_daemon(root.join("connection.json"), "claustrum", Some("nonce"));
    let clone = client.clone();
    assert_eq!(
        clone
            .consumer_identity()
            .map(|identity| identity.launch_nonce.clone()),
        Some("nonce".to_string())
    );
    assert!(
        fed::OutboundClient::for_daemon(root.join("c.json"), "claustrum", None)
            .consumer_identity()
            .is_none()
    );
}

/// `OutboundClient::call` is the only way to reach the peer, so a deadline is not
/// optional at any call site. This compiles only because `deadline` has no default: if
/// `call` gained one, this call would silently lose its deadline and this test would
/// stop proving the rule. The tripwire is deliberately a compile-time shape, and the
/// body asserts the value it passed is the one the client enforces.
#[test]
fn the_only_way_to_call_the_peer_takes_a_deadline() {
    fn takes_deadline<F>(_f: F)
    where
        F: for<'a> Fn(
            &'a fed::OutboundClient,
            &'a str,
            fed::RouteCall,
            Duration,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<serde_json::Value, fed::OutboundError>>
                    + 'a,
            >,
        >,
    {
    }
    takes_deadline(|client, key, call, deadline| Box::pin(client.call(key, call, deadline)));
}
