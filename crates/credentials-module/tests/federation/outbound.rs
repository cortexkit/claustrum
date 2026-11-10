//! The outbound client against the callosum stand-in: one deadline per call, a
//! consumer identity on every route it opens, and recovery from a silent restart.

use std::time::Duration;

use serde_json::json;
use tokio::time::Instant;

use crate::support::{
    poll_once, resolved_after_advance, resolved_before_deadline, wait_for_signal, wait_until, Held,
    Reply, TwoVaults,
};
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
async fn subscription_events_distinguish_data_and_clean_end() {
    use fed::outbound::SubscriptionEvent;

    let root = crate::support::temp_root("outbound-subscription-data");
    let vaults = TwoVaults::new(&root).await;
    let snapshot = json!({ "kind": "snapshot", "seq": 1, "logins": [] });
    vaults.callosum.answer(
        "claustrum",
        "federation.remote_watch",
        Reply::Watch(json!({ "result": snapshot })),
    );
    let mut subscription = wait_for_signal(vaults.b.outbound.subscribe(
        "subscription-data",
        route(
            "claustrum",
            json!({ "method": "federation.remote_watch", "params": {} }),
        ),
        fed::HOME_OP_DEADLINE,
    ))
    .await
    .unwrap();
    assert_eq!(
        wait_for_signal(subscription.next_event()).await.unwrap(),
        SubscriptionEvent::Data(snapshot.clone())
    );
    assert_eq!(
        vaults.callosum.watch_snapshot(Some(snapshot.clone())).await,
        1
    );
    assert_eq!(
        wait_for_signal(subscription.next_event()).await.unwrap(),
        SubscriptionEvent::Data(snapshot)
    );
    assert_eq!(vaults.callosum.watch_snapshot(None).await, 1);
    assert_eq!(
        wait_for_signal(subscription.next_event()).await.unwrap(),
        SubscriptionEvent::End
    );
    assert!(matches!(
        wait_for_signal(subscription.next_event()).await,
        Err(fed::OutboundError::Unavailable(_))
    ));
}

#[tokio::test]
async fn subscription_events_unwrap_the_homes_response_result() {
    use fed::outbound::SubscriptionEvent;

    let root = crate::support::temp_root("outbound-subscription-response");
    let vaults = TwoVaults::new(&root).await;
    let refusal = json!({ "error": { "code": "not_found", "class": "permanent" } });
    vaults.callosum.answer(
        "claustrum",
        "federation.remote_watch",
        Reply::Ok(refusal.clone()),
    );
    let mut subscription = wait_for_signal(vaults.b.outbound.subscribe(
        "subscription-response",
        route(
            "claustrum",
            json!({ "method": "federation.remote_watch", "params": {} }),
        ),
        fed::HOME_OP_DEADLINE,
    ))
    .await
    .unwrap();
    assert_eq!(
        wait_for_signal(subscription.next_event()).await.unwrap(),
        SubscriptionEvent::Response(refusal)
    );
}

#[tokio::test]
async fn subscription_events_keep_error_details_on_routes_and_channel_zero() {
    use fed::outbound::SubscriptionEvent;

    let root = crate::support::temp_root("outbound-subscription-error");
    let vaults = TwoVaults::new(&root).await;
    vaults.callosum.answer(
        "claustrum",
        "healthy-watch",
        Reply::Watch(json!({ "seq": 1 })),
    );
    let mut healthy = wait_for_signal(vaults.b.outbound.subscribe(
        "healthy-subscription",
        route("claustrum", json!({ "method": "healthy-watch" })),
        fed::HOME_OP_DEADLINE,
    ))
    .await
    .unwrap();
    assert_eq!(
        wait_for_signal(healthy.next_event()).await.unwrap(),
        SubscriptionEvent::Data(json!({ "seq": 1 }))
    );
    for channel_zero in [false, true] {
        for (body, expected) in [
            (
                json!({ "code": "fed_subscription_ended", "message": "ended", "detail": { "reason": "revoked" } }),
                SubscriptionEvent::Error {
                    code: "fed_subscription_ended".into(),
                    message: "ended".into(),
                    detail: Some(json!({ "reason": "revoked" })),
                },
            ),
            (
                json!({ "code": "module_error", "detail": "home refused" }),
                SubscriptionEvent::Error {
                    code: "module_error".into(),
                    message: "home refused".into(),
                    detail: Some(json!("home refused")),
                },
            ),
            (
                json!({ "code": "fed_not_exposed" }),
                SubscriptionEvent::Error {
                    code: "fed_not_exposed".into(),
                    message: "fed_not_exposed".into(),
                    detail: None,
                },
            ),
            (
                json!({}),
                SubscriptionEvent::Error {
                    code: "unrecognised".into(),
                    message: "the daemon refused the operation".into(),
                    detail: None,
                },
            ),
        ] {
            vaults.callosum.answer(
                "claustrum",
                "federation.remote_watch",
                Reply::SubscriptionError { channel_zero, body },
            );
            vaults
                .callosum
                .stray_error_before("federation.remote_watch", "unrelated-error");
            let mut subscription = wait_for_signal(vaults.b.outbound.subscribe(
                "subscription-error",
                route(
                    "claustrum",
                    json!({ "method": "federation.remote_watch", "params": {} }),
                ),
                fed::HOME_OP_DEADLINE,
            ))
            .await
            .unwrap();
            assert_eq!(
                wait_for_signal(subscription.next_event()).await.unwrap(),
                expected
            );
            assert_eq!(
                vaults
                    .callosum
                    .watch_snapshot(Some(json!({ "seq": 2 })))
                    .await,
                1
            );
            assert_eq!(
                wait_for_signal(healthy.next_event()).await.unwrap(),
                SubscriptionEvent::Data(json!({ "seq": 2 }))
            );
        }
    }
}

#[tokio::test]
async fn subscription_events_report_dropped_links_and_routes_as_errors() {
    let root = crate::support::temp_root("outbound-subscription-dropped");
    let vaults = TwoVaults::new(&root).await;
    for (key, reply) in [
        ("dropped-link", Reply::Drop),
        ("dropped-route", Reply::Watch(json!({}))),
    ] {
        vaults
            .callosum
            .answer("claustrum", "federation.remote_watch", reply);
        let mut subscription = wait_for_signal(vaults.b.outbound.subscribe(
            key,
            route(
                "claustrum",
                json!({ "method": "federation.remote_watch", "params": {} }),
            ),
            fed::HOME_OP_DEADLINE,
        ))
        .await
        .unwrap();
        if key == "dropped-route" {
            assert!(matches!(
                wait_for_signal(subscription.next_event()).await.unwrap(),
                fed::outbound::SubscriptionEvent::Data(_)
            ));
            assert_eq!(vaults.callosum.goodbye_routes("claustrum").await, 1);
        }
        assert!(matches!(
            wait_for_signal(subscription.next_event()).await,
            Err(fed::OutboundError::Unavailable(_))
        ));
    }
}

#[tokio::test]
async fn subscription_next_keeps_the_data_and_terminal_mapping() {
    let root = crate::support::temp_root("outbound-subscription-next");
    let vaults = TwoVaults::new(&root).await;
    for reply in [
        Reply::Watch(json!({ "result": { "seq": 1 } })),
        Reply::Ok(json!({ "error": { "code": "not_found" } })),
        Reply::RouteRefusal("module_error".into()),
        Reply::Permanent("fed_not_exposed".into()),
    ] {
        let data = matches!(reply, Reply::Watch(_));
        vaults
            .callosum
            .answer("claustrum", "federation.remote_watch", reply);
        let mut subscription = wait_for_signal(vaults.b.outbound.subscribe(
            "subscription-next",
            route(
                "claustrum",
                json!({ "method": "federation.remote_watch", "params": {} }),
            ),
            fed::HOME_OP_DEADLINE,
        ))
        .await
        .unwrap();
        if data {
            assert_eq!(
                wait_for_signal(subscription.next()).await.unwrap(),
                Some(json!({ "seq": 1 }))
            );
            assert_eq!(vaults.callosum.watch_snapshot(None).await, 1);
        }
        assert_eq!(wait_for_signal(subscription.next()).await.unwrap(), None);
    }
}

#[tokio::test]
async fn cancelled_pairing_lookup_withdraws_its_waiter_on_the_shared_link() {
    let root = crate::support::temp_root("outbound-cancelled-pairing");
    let vaults = TwoVaults::new(&root).await;
    tokio::time::pause();
    for _ in 0..2 {
        let held = Held::new();
        vaults.callosum.answer(
            "claustrum",
            "callosum.paired_devices_read",
            Reply::Hold(held.clone()),
        );
        let client = vaults.b.outbound.clone();
        let mut lookup = tokio::spawn(async move {
            fed::callosum_lookup(
                Some(&client),
                "callosum.paired_devices_read",
                Instant::now() + Duration::from_secs(30),
            )
            .await
        });
        held.arrived_before(&mut lookup).await;
        assert_eq!(
            vaults.b.outbound.pending_waiter_count_for_test().await,
            Some(1)
        );
        // Aborting the lookup must release its waiter before a late reply or
        // route close, rather than depending on either event to clean up.
        lookup.abort();
        assert!(wait_for_signal(lookup).await.unwrap_err().is_cancelled());
        assert_eq!(
            vaults.b.outbound.pending_waiter_count_for_test().await,
            Some(0)
        );
    }
}

#[tokio::test]
async fn an_enclosing_deadline_drops_only_the_cancelled_calls_binding() {
    let root = crate::support::temp_root("outbound-enclosing-deadline");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Ok(json!({ "payload": "tok" })),
    );
    for key in [&home, "healthy-route"] {
        wait_for_signal(call(
            &vaults.b.outbound,
            key,
            consumer_get(),
            Duration::from_secs(30),
        ))
        .await
        .unwrap();
    }
    assert_eq!(vaults.callosum.opens("claustrum").len(), 2);

    let held = Held::new();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Hold(held.clone()),
    );
    tokio::time::pause();
    let client = vaults.b.outbound.clone();
    let target = home.clone();
    let mut request = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(1),
            call(&client, &target, consumer_get(), Duration::from_secs(30)),
        )
        .await
    });
    held.arrived_before(&mut request).await;
    assert!(
        resolved_after_advance(request, Duration::from_millis(1_001))
            .await
            .is_err()
    );
    assert_eq!(
        vaults.b.outbound.pending_waiter_count_for_test().await,
        Some(0)
    );

    vaults.callosum.forget_answers();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Ok(json!({ "payload": "reconnected" })),
    );
    for (key, opens) in [("healthy-route", 2), (home.as_str(), 3)] {
        let reply = wait_for_signal(call(
            &vaults.b.outbound,
            key,
            consumer_get(),
            Duration::from_secs(30),
        ))
        .await
        .unwrap();
        assert_eq!(reply["payload"], "reconnected");
        assert_eq!(vaults.callosum.opens("claustrum").len(), opens);
    }
}

#[tokio::test]
async fn a_channel_zero_open_refusal_keeps_its_code_without_spending_the_deadline() {
    let root = crate::support::temp_root("outbound-open-refusal");
    let vaults = TwoVaults::new(&root).await;
    for (code, transient) in [("fed_not_exposed", false), ("fed_partition", true)] {
        let held = Held::new();
        vaults.callosum.hold_open("claustrum", held.clone());
        let client = vaults.b.outbound.clone();
        let mut request = tokio::spawn(async move {
            call(
                &client,
                "refused",
                consumer_get(),
                fed::CONSUMER_FACING_DEADLINE,
            )
            .await
        });
        held.arrived_before(&mut request).await;
        held.release(Reply::Permanent(code.into()));
        held.answered_before(&mut request).await;
        vaults.callosum.reply_fence(&vaults.b.outbound).await;
        tokio::time::pause();
        let error = resolved_before_deadline(request).await.unwrap_err();
        tokio::time::resume();
        assert!(
            matches!(&error, fed::OutboundError::Refused { code: actual, .. } if actual == code)
        );
        assert_eq!(error.is_transient(), transient);
    }
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
    let mut success = tokio::spawn(async move {
        call(
            &client,
            "good-route",
            json!({ "method": "good" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    good.arrived_before(&mut success).await;
    let client = vaults.b.outbound.clone();
    let mut failure = tokio::spawn(async move {
        call(
            &client,
            "refused-route",
            json!({ "method": "refused" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    refused.arrived_before(&mut failure).await;
    refused.release(Reply::Permanent("fed_not_exposed".into()));
    refused.answered_before(&mut failure).await;
    good.release(Reply::Ok(json!({ "untouched": true })));
    good.answered_before(&mut success).await;
    vaults.callosum.reply_fence(&vaults.b.outbound).await;
    tokio::time::pause();
    let error = resolved_before_deadline(failure).await.unwrap_err();
    assert_eq!(
        resolved_before_deadline(success).await.unwrap(),
        json!({ "untouched": true })
    );
    assert!(
        matches!(error, fed::OutboundError::Refused { ref code, .. } if code == "fed_not_exposed"),
        "{error:?}"
    );
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
    let mut one = tokio::spawn(async move {
        call(
            &client,
            "first-route",
            json!({ "method": "first" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    first.arrived_before(&mut one).await;
    let client = vaults.b.outbound.clone();
    let mut two = tokio::spawn(async move {
        call(
            &client,
            "second-route",
            json!({ "method": "second" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    second.arrived_before(&mut two).await;
    first.release(Reply::Ok(json!({ "first": true })));
    second.release(Reply::Ok(json!({ "second": true })));
    first.answered_before(&mut one).await;
    second.answered_before(&mut two).await;
    vaults.callosum.reply_fence(&vaults.b.outbound).await;
    tokio::time::pause();
    assert_eq!(
        resolved_before_deadline(one).await.unwrap(),
        json!({ "first": true })
    );
    assert_eq!(
        resolved_before_deadline(two).await.unwrap(),
        json!({ "second": true })
    );
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
    let held = Held::new();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Hold(held.clone()),
    );

    tokio::time::pause();
    let started = Instant::now();
    let mut request = std::pin::pin!(call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    ));
    held.arrived_before(&mut request).await;
    tokio::time::advance(fed::CONSUMER_FACING_DEADLINE - Duration::from_millis(1)).await;
    assert!(
        poll_once(&mut request).await.is_none(),
        "a stalled call must not end before its deadline"
    );
    tokio::time::advance(Duration::from_millis(2)).await;
    let error = wait_for_signal(request)
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
    wait_for_signal(call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    ))
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
    let held = Held::new();
    vaults.callosum.answer(
        "claustrum",
        "callosum.peer_keys_read",
        Reply::Hold(held.clone()),
    );

    tokio::time::pause();
    let mut request = std::pin::pin!(call(
        &vaults.b.outbound,
        &home,
        json!({ "method": "callosum.peer_keys_read", "params": {} }),
        fed::ADMIN_OP_BUDGET,
    ));
    held.arrived_before(&mut request).await;
    tokio::time::advance(fed::ADMIN_OP_BUDGET - Duration::from_millis(100)).await;
    assert!(
        poll_once(&mut request).await.is_none(),
        "the admin budget has not expired"
    );
    tokio::time::advance(Duration::from_millis(101)).await;
    assert!(wait_for_signal(request).await.is_err());
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

// ---------------------------------------------------------------------------------
// Multiplexing: one connection carries many calls, and one slow or failing call must
// not decide another call's outcome.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_slow_admin_call_does_not_delay_a_consumer_call_on_the_same_connection() {
    let root = crate::support::temp_root("outbound-mux-admin");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();
    // Hold the admin reply until the consumer has answered, proving actual overlap.
    let held = Held::new();
    vaults.callosum.answer(
        "claustrum",
        "callosum.peer_keys_read",
        Reply::Hold(held.clone()),
    );
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Ok(json!({ "payload": "tok" })),
    );

    tokio::time::pause();
    let mut admin = {
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
    held.arrived_before(&mut admin).await;

    let started = Instant::now();
    wait_for_signal(call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    ))
    .await
    .expect("a consumer call still succeeds while an admin call is in flight");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(1_000),
        "the consumer call waited on the admin call: {elapsed:?}"
    );

    assert!(!admin.is_finished(), "the admin reply is still held");
    held.release(Reply::Ok(json!({ "keys": [] })));
    held.answered_before(&mut admin).await;
    wait_for_signal(admin)
        .await
        .expect("admin task joined")
        .expect("the admin call eventually gets its own reply");
}

#[tokio::test]
async fn two_concurrent_consumer_calls_on_different_routes_both_succeed() {
    let root = crate::support::temp_root("outbound-mux-two-routes");
    let vaults = TwoVaults::new(&root).await;
    let home = vaults.home_member().to_string();

    // Both requests must reach the stand-in before either reply is released. This
    // proves overlap without depending on two real-time delays finishing promptly.
    let first_reply = Held::new();
    let second_reply = Held::new();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Hold(first_reply.clone()),
    );
    vaults.callosum.answer(
        "claustrum",
        "credential.list_scoped",
        Reply::Hold(second_reply.clone()),
    );

    tokio::time::pause();
    let started = Instant::now();
    let client = vaults.b.outbound.clone();
    let mut first = tokio::spawn(async move {
        call(
            &client,
            &home,
            consumer_get(),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    let client = vaults.b.outbound.clone();
    let mut second = tokio::spawn(async move {
        call(
            &client,
            "fed-computer:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            json!({ "method": "credential.list_scoped", "params": {} }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    first_reply.arrived_before(&mut first).await;
    second_reply.arrived_before(&mut second).await;
    tokio::time::advance(Duration::from_millis(400)).await;
    first_reply.release(Reply::Ok(json!({ "payload": "tok" })));
    second_reply.release(Reply::Ok(json!({ "credentials": [] })));
    let (a, b) = wait_for_signal(async { tokio::join!(first, second) }).await;
    a.expect("the first task joined")
        .expect("the first route answers");
    b.expect("the second task joined")
        .expect("the second route answers");
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
    // Both requests reach the same route before the shorter budget expires. The
    // test releases their replies at 2 s, between the two calls' deadlines.
    let held = Held::new();
    vaults.callosum.answer(
        "claustrum",
        "credential.get_scoped",
        Reply::Hold(held.clone()),
    );

    tokio::time::pause();
    let client = vaults.b.outbound.clone();
    let target = home.clone();
    let impatient = tokio::spawn(async move {
        call(&client, &target, consumer_get(), Duration::from_millis(300)).await
    });
    // Same route, so the second call joins the same connection and binding.
    let client = vaults.b.outbound.clone();
    let patient =
        tokio::spawn(
            async move { call(&client, &home, consumer_get(), Duration::from_secs(4)).await },
        );
    wait_until(|| vaults.callosum.methods("claustrum").len() == 2).await;
    let impatient = resolved_after_advance(impatient, Duration::from_millis(301)).await;
    assert!(
        impatient.is_err(),
        "the call with a 300 ms budget cannot get a 2 s reply"
    );
    tokio::time::advance(Duration::from_millis(1_699)).await;
    held.release(Reply::Ok(json!({ "payload": "tok" })));
    wait_for_signal(patient)
        .await
        .expect("the patient task joined")
        .expect("the call with a 4 s budget gets its reply on the same connection");
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

// ---------------------------------------------------------------------------------
// Recovery: subc closes a route or the whole connection while no call is waiting on
// it, and the next call must not inherit the breakage. Nothing here waits on a clock:
// each step waits for the stand-in's own signal, behind its hang guard.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_route_goodbye_with_no_call_in_flight_leaves_the_next_call_working() {
    let root = crate::support::temp_root("outbound-route-goodbye-idle");
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
    .expect("the first call succeeds");

    // The shape of a callosum restart: subc drains the route with a route GOODBYE and
    // keeps the vault's connection open, while no call is waiting on the route.
    assert_eq!(vaults.callosum.goodbye_routes("claustrum").await, 1);
    // A round trip on another route of the same connection proves the client's reader
    // has handled the GOODBYE, and that the connection still carries calls.
    vaults.callosum.reply_fence(&vaults.b.outbound).await;

    call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect("the call after the route goodbye reopens the route and succeeds");
    call(
        &vaults.b.outbound,
        &home,
        consumer_get(),
        fed::CONSUMER_FACING_DEADLINE,
    )
    .await
    .expect("the reopened route serves the next call too");

    let channels = vaults.callosum.route_channels("claustrum");
    assert_eq!(
        channels.len(),
        2,
        "the closed route was reopened once, and the reopened binding was then reused: \
         {channels:?}"
    );
    assert_eq!(
        channels[0], channels[1],
        "the stand-in handed the old channel number to the reopened route, which the \
         client treats as live again"
    );
    assert_eq!(
        vaults.callosum.connections(),
        1,
        "a route goodbye leaves the connection in use"
    );
}

#[tokio::test]
async fn a_connection_ended_with_no_call_in_flight_is_redialed_by_the_next_call() {
    // Once by a channel-0 GOODBYE and once by a bare close: either way the reader is
    // the only one who sees it, because no call is waiting.
    for goodbye in [true, false] {
        let root = crate::support::temp_root(&format!("outbound-idle-close-{goodbye}"));
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
        .expect("the first call succeeds");

        vaults.callosum.close_connections(goodbye).await;

        call(
            &vaults.b.outbound,
            &home,
            consumer_get(),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
        .unwrap_or_else(|error| {
            panic!("goodbye={goodbye}: the next call dials a new connection: {error:?}")
        });
        assert_eq!(
            vaults.callosum.connections(),
            2,
            "goodbye={goodbye}: the next call dialed a fresh connection"
        );
        assert_eq!(
            vaults.callosum.route_channels("claustrum").len(),
            2,
            "goodbye={goodbye}: a route belongs to the connection it was opened on, so \
             the new connection opened its own"
        );
    }
}

#[tokio::test]
async fn a_route_goodbye_fails_that_routes_call_and_leaves_another_routes_call_alone() {
    let root = crate::support::temp_root("outbound-route-goodbye-other");
    let vaults = TwoVaults::new(&root).await;
    let doomed = Held::new();
    let survivor = Held::new();
    vaults
        .callosum
        .answer("claustrum", "route-a.held", Reply::Hold(doomed.clone()));
    vaults
        .callosum
        .answer("claustrum", "route-b.held", Reply::Hold(survivor.clone()));

    let client = vaults.b.outbound.clone();
    let mut on_a = tokio::spawn(async move {
        client
            .call(
                "route-a",
                route("route-a", json!({ "method": "route-a.held" })),
                fed::CONSUMER_FACING_DEADLINE,
            )
            .await
    });
    doomed.arrived_before(&mut on_a).await;
    let client = vaults.b.outbound.clone();
    let mut on_b = tokio::spawn(async move {
        call(
            &client,
            "route-b",
            json!({ "method": "route-b.held" }),
            fed::CONSUMER_FACING_DEADLINE,
        )
        .await
    });
    survivor.arrived_before(&mut on_b).await;

    assert_eq!(vaults.callosum.goodbye_routes("route-a").await, 1);
    survivor.release(Reply::Ok(json!({ "survived": true })));
    survivor.answered_before(&mut on_b).await;
    vaults.callosum.reply_fence(&vaults.b.outbound).await;
    tokio::time::pause();
    let error = resolved_before_deadline(on_a).await.unwrap_err();
    assert_eq!(
        resolved_before_deadline(on_b).await.unwrap(),
        json!({ "survived": true })
    );
    assert!(
        error.is_transient() && error.message().contains("closed the route"),
        "the closed route's call fails at once, as a route closure: {error:?}"
    );
}
