//! A grant, flow grant or pending request belongs to the computer that asked for it.
//!
//! `''` is this vault's own asker; a paired computer that forwards a call here is named by
//! its member id. These tests drive the store's `*_from` entry points the way the
//! federation ingress will, and check that one asker's approval never serves, merges
//! with or revokes another's.

use super::*;

const ASKER_B: &str = "fed-computer:33333333333333333333333333333333";
const ASKER_C: &str = "fed-computer:44444444444444444444444444444444";

fn use_from(store: &EncryptedStore, asker: &str) -> Value {
    store
        .secret_use_from(&call(), asker, || NOW)
        .map_or_else(|e| e.body(), |o| o.reply)
}

fn request_from(store: &EncryptedStore, asker: &str) -> Value {
    store
        .secret_request_flow_approval_from(&install(), asker, || NOW)
        .map_or_else(|e| e.body(), |o| o.reply)
}

fn run_from(store: &EncryptedStore, asker: &str) -> Value {
    store
        .secret_flow_use_from(&run(), asker, || NOW)
        .map_or_else(|e| e.body(), |o| o.reply)
}

/// The asking member and serving member stored for one pending request.
fn pending_members(store: &EncryptedStore, request: &Value) -> (String, String) {
    store
        .store
        .with_conn(|c| {
            c.query_row(
                "SELECT asking_member_id,member_id FROM secret_pending_requests WHERE request_id=?1",
                [request["request_id"].as_str().unwrap()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap()
}

fn grant_askers(store: &EncryptedStore, table: &str) -> Vec<String> {
    store
        .store
        .with_conn(|c| {
            c.prepare(&format!(
                "SELECT asking_member_id FROM {table} ORDER BY asking_member_id"
            ))?
            .query_map([], |r| r.get(0))?
            .collect()
        })
        .unwrap()
}

fn approve_permanently(store: &EncryptedStore, request: &Value) {
    let e = envelope(vec![item(request)], "permanent", NOW);
    assert_eq!(
        phone(store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[granted(request)]})
    );
}

#[test]
fn an_agent_grant_releases_only_to_the_asker_its_request_came_from() {
    let (_root, store) = registered("asking-member-agent");
    let from_b = use_from(&store, ASKER_B);
    assert_eq!(from_b["status"], "approval_required", "{from_b}");
    // The same scope stamp asked locally is a separate request, never B's.
    let local = use_reply(&store, &call(), NOW);
    assert_eq!(local["status"], "approval_required", "{local}");
    assert_ne!(local["request_id"], from_b["request_id"]);
    // Each asker's retry reuses its own request.
    assert_eq!(use_from(&store, ASKER_B), from_b);
    assert_eq!(use_reply(&store, &call(), NOW), local);
    // pending.member_id names the serving vault for both; only the asker differs.
    assert_eq!(
        pending_members(&store, &from_b),
        (ASKER_B.to_owned(), MEMBER.to_owned())
    );
    assert_eq!(
        pending_members(&store, &local),
        (String::new(), MEMBER.to_owned())
    );

    approve_permanently(&store, &from_b);
    assert_eq!(grant_askers(&store, "secret_grants"), [ASKER_B]);
    assert_eq!(use_from(&store, ASKER_B)["status"], "released");
    // B's grant answers neither this vault's own request nor a third computer's.
    assert_eq!(use_reply(&store, &call(), NOW), local);
    let from_c = use_from(&store, ASKER_C);
    assert_eq!(from_c["status"], "approval_required", "{from_c}");
    assert_ne!(from_c["request_id"], from_b["request_id"]);
    assert_ne!(from_c["request_id"], local["request_id"]);

    approve_permanently(&store, &local);
    assert_eq!(grant_askers(&store, "secret_grants"), ["", ASKER_B]);
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
    assert_eq!(use_from(&store, ASKER_C), from_c);
}

#[test]
fn flow_grants_release_and_revoke_per_asker() {
    let (_root, store) = registered("asking-member-flow");
    let from_b = request_from(&store, ASKER_B);
    let local = request(&store, &install(), NOW);
    assert_eq!(from_b["status"], "approval_required", "{from_b}");
    assert_eq!(local["status"], "approval_required", "{local}");
    assert_ne!(local["request_id"], from_b["request_id"]);
    assert_eq!(request_from(&store, ASKER_B), from_b);
    assert_eq!(
        pending_members(&store, &from_b),
        (ASKER_B.to_owned(), MEMBER.to_owned())
    );

    approve(&store, &from_b);
    assert_eq!(grant_askers(&store, "secret_flow_grants"), [ASKER_B]);
    assert_eq!(run_from(&store, ASKER_B)["status"], "released");
    // The same flow identity on this vault, or on another computer, has no grant.
    assert_eq!(
        release_flow(&store, &run(), NOW),
        SecretError::NotFound.body()
    );
    assert_eq!(run_from(&store, ASKER_C), SecretError::NotFound.body());

    approve(&store, &local);
    assert_eq!(grant_askers(&store, "secret_flow_grants"), ["", ASKER_B]);
    assert_eq!(release_flow(&store, &run(), NOW)["status"], "released");
    let from_c = request_from(&store, ASKER_C);
    assert_eq!(from_c["status"], "approval_required", "{from_c}");

    // B's revoke removes B's grant only; this vault's grant and C's request stay.
    assert_eq!(
        store.revoke_flow_grants_from("install-A", None, ASKER_B),
        Ok(1)
    );
    assert_eq!(grant_askers(&store, "secret_flow_grants"), [""]);
    assert_eq!(run_from(&store, ASKER_B), SecretError::NotFound.body());
    assert_eq!(release_flow(&store, &run(), NOW)["status"], "released");
    assert_eq!(request_from(&store, ASKER_C), from_c);

    // The local revoke leaves C's unconsumed request in place too.
    assert_eq!(store.revoke_flow_grants("install-A", None), Ok(1));
    assert!(grant_askers(&store, "secret_flow_grants").is_empty());
    assert_eq!(request_from(&store, ASKER_C), from_c);
    assert_eq!(
        store.revoke_flow_grants_from("install-A", None, ASKER_C),
        Ok(0)
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE consumed=0"
        ),
        0
    );
}
