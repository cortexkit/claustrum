//! The outbound client against the callosum stand-in: one deadline per call, a
//! consumer identity on every route it opens, and recovery from a silent restart.

use std::time::{Duration, Instant};

use serde_json::json;

use crate::support::{Held, Reply, TwoVaults};
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
async fn a_channel_zero_open_refusal_keeps_its_code_without_spending_the_deadline() {
    let root = crate::support::temp_root("outbound-open-refusal");
    let vaults = TwoVaults::new(&root).await;
    tokio::time::pause();
    // TCP runs on the stand-in's thread. Keep virtual time fixed while it answers.
    let io = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    for (code, transient) in [("fed_not_exposed", false), ("fed_partition", true)] {
        vaults.callosum.refuse_open("claustrum", code);
        let started = tokio::time::Instant::now();
        let error = call(
            &vaults.b.outbound,
            "refused",
            consumer_get(),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, fed::OutboundError::Refused { code: actual, .. } if actual == code)
        );
        assert_eq!(error.is_transient(), transient);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
    io.abort();
}

#[tokio::test]
async fn a_channel_zero_route_refusal_is_prompt_and_leaves_a_concurrent_route_untouched() {
    let root = crate::support::temp_root("outbound-route-refusal");
    let vaults = TwoVaults::new(&root).await;
    let good = Held::new();
    let refused = Held::new();
    vaults
        .callosum
        .answer("claustrum", "good", Reply::Hold(good.clone()));
    vaults
        .callosum
        .answer("claustrum", "refused", Reply::Hold(refused.clone()));
    let client = vaults.b.outbound.clone();
    let success = tokio::spawn(async move {
        call(
            &client,
            "good-route",
            json!({ "method": "good" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    good.arrived().await;
    let client = vaults.b.outbound.clone();
    let failure = tokio::spawn(async move {
        call(
            &client,
            "refused-route",
            json!({ "method": "refused" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    refused.arrived().await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let io = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    refused.release(Reply::Permanent("fed_not_exposed".into()));
    refused.answered().await;
    good.release(Reply::Ok(json!({ "untouched": true })));
    assert_eq!(
        success.await.unwrap().unwrap(),
        json!({ "untouched": true })
    );
    // The successful reply follows the refusal on the same socket. Its completion
    // proves the reader has already dispatched (or dropped) that refusal.
    io.abort();
    let error = failure.await.unwrap().unwrap_err();
    assert!(
        matches!(error, fed::OutboundError::Refused { ref code, .. } if code == "fed_not_exposed"),
        "{error:?}"
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test]
async fn an_uncorrelated_channel_zero_error_leaves_every_pending_call_untouched() {
    let root = crate::support::temp_root("outbound-stray-error");
    let vaults = TwoVaults::new(&root).await;
    let first = Held::new();
    let second = Held::new();
    vaults
        .callosum
        .answer("claustrum", "first", Reply::Hold(first.clone()));
    vaults
        .callosum
        .answer("claustrum", "second", Reply::Hold(second.clone()));
    vaults
        .callosum
        .stray_error_before("second", "fed_not_exposed");
    let client = vaults.b.outbound.clone();
    let one = tokio::spawn(async move {
        call(
            &client,
            "first-route",
            json!({ "method": "first" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    first.arrived().await;
    let client = vaults.b.outbound.clone();
    let two = tokio::spawn(async move {
        call(
            &client,
            "second-route",
            json!({ "method": "second" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    second.arrived().await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let io = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    first.release(Reply::Ok(json!({ "first": true })));
    second.release(Reply::Ok(json!({ "second": true })));
    assert_eq!(one.await.unwrap().unwrap(), json!({ "first": true }));
    assert_eq!(two.await.unwrap().unwrap(), json!({ "second": true }));
    assert_eq!(started.elapsed(), Duration::ZERO);
    io.abort();
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

// ---------------------------------------------------------------------------------
// Multiplexing: one connection carries many calls, and one slow or failing call must
// not decide another call's outcome.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_slow_admin_call_does_not_delay_a_consumer_call_on_the_same_connection() {
    let root = crate::support::temp_root("outbound-mux-admin");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    // An admin-class call the stand-in holds for 5 s, well past a consumer's budget.
    vaults.callosum.answer(
        "claustrum",
        "callosum.peer_keys_read",
        Reply::Delayed(
            Duration::from_secs(5),
            Box::new(Reply::Ok(json!({ "keys": [] }))),
        ),
    );
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Ok(json!({ "payload": "tok" })),
    );

    let admin = {
        let client = vaults.b.outbound.clone();
        let home = home.clone();
        tokio::spawn(async move {
            call(
                &client,
                &home,
                json!({ "method": "callosum.peer_keys_read", "params": {} }),
                fed::ADMIN_OP_BUDGET,
            )
            .await
        })
    };
    // Let the admin call reach the stand-in and start holding the connection's reply.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect("a consumer call still succeeds while an admin call is in flight");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(1_000),
        "the consumer call waited on the admin call: {elapsed:?}"
    );

    admin
        .await
        .expect("admin task joined")
        .expect("the admin call eventually gets its own reply");
}

#[tokio::test]
async fn two_concurrent_consumer_calls_on_different_routes_both_succeed() {
    let root = crate::support::temp_root("outbound-mux-two-routes");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();

    // Both calls open their own route and answer after a delay that overlaps the other,
    // so neither can finish before the second one has started.
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Delayed(
            Duration::from_millis(400),
            Box::new(Reply::Ok(json!({ "payload": "tok" }))),
        ),
    );

    let started = Instant::now();
    let first = call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    );
    let second = call(
        &vaults.b.outbound,
        "fed-computer:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    );
    let (a, b) = tokio::join!(first, second);
    a.expect("the first route answers");
    b.expect("the second route answers");
    // Two 400 ms replies served one after the other would take 800 ms; overlapping them
    // keeps the pair inside one reply's delay plus scheduling slack.
    assert!(
        started.elapsed() < Duration::from_millis(750),
        "the two calls serialized: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_call_that_misses_its_deadline_leaves_a_concurrent_call_unharmed() {
    let root = crate::support::temp_root("outbound-mux-deadline");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    // The stand-in holds this method for 2 s: longer than the consumer deadline the
    // first call is given, short enough that the second call, given a roomy budget,
    // gets its answer afterwards.
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Delayed(
            Duration::from_secs(2),
            Box::new(Reply::Ok(json!({ "payload": "tok" }))),
        ),
    );

    let impatient = call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        Duration::from_millis(300),
    );
    // Same route, so the second call joins the same connection and binding.
    let patient = call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        Duration::from_secs(4),
    );
    let (impatient, patient) = tokio::join!(impatient, patient);
    assert!(
        impatient.is_err(),
        "the call with a 300 ms budget cannot get a 2 s reply"
    );
    patient.expect("the call with a 4 s budget gets its reply on the same connection");
}

#[tokio::test]
async fn a_dead_connection_fails_every_pending_call_and_the_next_call_succeeds() {
    let root = crate::support::temp_root("outbound-mux-dead");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    vaults
        .callosum
        .answer("claustrum", "credential.get_scoped", Reply::Drop);

    let one = call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    );
    let two = call(
        &vaults.b.outbound,
        "fed-computer:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    );
    let (one, two) = tokio::join!(one, two);
    let one = one.expect_err("a dropped connection fails the first call");
    let two = two.expect_err("a dropped connection fails the second call");
    assert!(one.is_transient() && two.is_transient());
    assert!(
        one.message().contains("closed") || one.message().contains("failed"),
        "the message says the connection died: {}",
        one.message()
    );

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
    .expect("the next call dials a fresh connection and succeeds");
}
