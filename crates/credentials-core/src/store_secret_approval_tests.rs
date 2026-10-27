use super::*;
use crate::store::PhoneOperation;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

#[path = "store_secret_flow_approval_tests.rs"]
mod flow_tests;

#[path = "store_secret_flow_tests.rs"]
mod store_flow_tests;

const FP: &str = "11111111111111111111111111111111";
const UNKNOWN: &str = "00000000000000000000000000";
fn signer() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn phone(store: &EncryptedStore, op: &PhoneOperation, now: i64) -> Result<Value, SecretError> {
    store.secret_phone_operation(FP, Some("pair-A"), now, op, || true, || now)
}
fn approval_setup(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>, Value) {
    let (root, store) = setup(tag);
    phone(
        &store,
        &PhoneOperation::Register {
            deposit_pub: vec![2; 32],
            approval_pub: signer()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        },
        NOW,
    )
    .unwrap();
    let request = use_reply(&store, &call(), NOW);
    (root, store, request)
}
fn item(request: &Value) -> Value {
    let bytes = URL_SAFE_NO_PAD
        .decode(request["statement_b64url"].as_str().unwrap())
        .unwrap();
    json!({"request_id":request["request_id"],"statement_sha256":phone::hex(&payload_hash(&bytes))})
}
fn envelope(items: Vec<Value>, duration: &str, issued: i64) -> Value {
    let expiry = match duration {
        "once" => issued + 600_000,
        "hour" => issued + 3_600_000,
        "session" => issued + 86_400_000,
        "permanent" => 0,
        "none" => NOW + 600_000,
        _ => 0,
    };
    json!({"v":"ck-secret-use-envelope/v1","items":items,"decision":if duration=="none" {"delete"}else{"allow"},"duration":duration,"grant_expires_at_ms":expiry,"device_fingerprint":FP,"issued_at_ms":issued})
}
fn signed_bytes(bytes: Vec<u8>, delete: bool) -> PhoneOperation {
    let signature: Signature = signer().sign(&bytes);
    if delete {
        PhoneOperation::DeleteCommit {
            envelope: bytes,
            signature: signature.to_der().as_bytes().to_vec(),
        }
    } else {
        PhoneOperation::Approve {
            envelope: bytes,
            signature: signature.to_der().as_bytes().to_vec(),
            card_ref: Some("card-1".into()),
        }
    }
}
fn signed(e: &Value, delete: bool) -> PhoneOperation {
    signed_bytes(serde_json::to_vec(e).unwrap(), delete)
}
fn granted(request: &Value) -> Value {
    json!({"request_id":request["request_id"],"outcome":"granted"})
}
fn refused(request: &Value) -> Value {
    json!({"request_id":request["request_id"],"outcome":"refused","code":"approval_invalid"})
}

#[test]
fn secret_approval_creates_one_grant_with_exact_envelope_hash_and_releases() {
    let (_root, store, r) = approval_setup("approve-positive");
    let e = envelope(vec![item(&r)], "permanent", NOW);
    let bytes = serde_json::to_vec(&e).unwrap();
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[granted(&r)]})
    );
    let hash = phone::hex(&payload_hash(&bytes));
    store.store.with_conn(|c| {
        let actual:(String,String)=c.query_row("SELECT g.envelope_sha256,a.payload_hash FROM secret_grants g JOIN audit_log a ON a.op='secret_grant_create'",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!(actual,(hash.clone(),hash)); Ok(())
    }).unwrap();
    let listed = store.secret_permissions_list(Some("agent-A"), NOW).unwrap();
    let row = &listed["grants"][0];
    assert_eq!(
        row["holder"],
        json!({"kind":"agent","agent_id":"agent-A","scope_ref":"H"})
    );
    assert_eq!(row["scope_label"], "use key on x.test/repos/a");
    assert_eq!(row["card_ref"], "card-1");
    assert!(row.get("expires_at_ms").is_none());
    assert_eq!(
        store.secret_permissions_list(Some("other"), NOW).unwrap(),
        json!({"grants":[]})
    );
    assert_eq!(use_reply(&store, &call(), NOW)["status"], "released");
}

#[test]
fn secret_approval_request_is_single_use_even_when_commits_race() {
    let (_root, store, r) = approval_setup("approve-race");
    let e = envelope(vec![item(&r)], "hour", NOW);
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let store = store.clone();
            let b = barrier.clone();
            let op = signed(&e, false);
            std::thread::spawn(move || {
                b.wait();
                phone(&store, &op, NOW).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let replies = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    // The same envelope sent twice at once is one decision: the later commit answers
    // with the earlier one's reply, and only one grant exists.
    assert_eq!(replies[0], json!({"results":[granted(&r)]}));
    assert_eq!(replies[1], replies[0]);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 1);
}

#[test]
fn secret_approval_resend_of_an_applied_envelope_answers_with_its_first_reply() {
    let (_root, store, r) = approval_setup("approve-resend");
    let e = envelope(vec![item(&r)], "hour", NOW);
    let bytes = serde_json::to_vec(&e).unwrap();
    let first = phone(&store, &signed_bytes(bytes.clone(), false), NOW).unwrap();
    assert_eq!(first, json!({"results":[granted(&r)]}));
    // The reply was lost; the phone resends the exact bytes with a fresh signature (P-256
    // signatures are not deterministic). It learns the grant instead of a refusal.
    let resent = phone(&store, &signed_bytes(bytes.clone(), false), NOW + 1_000).unwrap();
    assert_eq!(resent, first);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 1);
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_grant_create'"
        ),
        1
    );
    // A different envelope for the same consumed request is still refused.
    let other = envelope(vec![item(&r)], "once", NOW);
    assert_eq!(
        phone(&store, &signed(&other, false), NOW + 2_000).unwrap(),
        json!({"results":[refused(&r)]})
    );
    // A bad signature over the same bytes never reaches the stored reply.
    let PhoneOperation::Approve {
        envelope, card_ref, ..
    } = signed_bytes(bytes.clone(), false)
    else {
        unreachable!()
    };
    let other_signature: Signature = signer().sign(b"something else");
    let forged = other_signature.to_der().as_bytes().to_vec();
    assert!(phone(
        &store,
        &PhoneOperation::Approve {
            envelope,
            signature: forged,
            card_ref
        },
        NOW + 3_000
    )
    .is_err());
}

#[test]
fn secret_approval_stored_reply_ends_with_the_skew_window() {
    let (_root, store, r) = approval_setup("approve-resend-late");
    let e = envelope(vec![item(&r)], "hour", NOW);
    let bytes = serde_json::to_vec(&e).unwrap();
    phone(&store, &signed_bytes(bytes.clone(), false), NOW).unwrap();
    // Past the skew window the envelope could not be applied anyway, so the stored reply
    // is gone and the resend reads the consumed request as refused.
    let late = NOW + crate::agent_secret::SECRET_ISSUE_SKEW_LIMIT_MS;
    assert_eq!(
        phone(&store, &signed_bytes(bytes.clone(), false), late).unwrap(),
        json!({"results":[refused(&r)]})
    );
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_approval_replies"),
        1,
        "the late resend stores its own reply"
    );
    // Just inside the window, the stored reply still answers.
    let (_root2, store2, r2) = approval_setup("approve-resend-edge");
    let e2 = envelope(vec![item(&r2)], "hour", NOW);
    let bytes2 = serde_json::to_vec(&e2).unwrap();
    phone(&store2, &signed_bytes(bytes2.clone(), false), NOW).unwrap();
    assert_eq!(
        phone(&store2, &signed_bytes(bytes2, false), late - 1).unwrap(),
        json!({"results":[granted(&r2)]})
    );
}

#[test]
fn secret_approval_respects_offered_coverage_and_omits_absent_agent_ids() {
    let (_root, store, _) = approval_setup("approve-offered");
    let mut c = call();
    c.coverage = "agent_and_workers".into();
    c.agent_id = None;
    let r = use_reply(&store, &c, NOW);
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&r)], "hour", NOW), false),
            NOW
        )
        .unwrap(),
        json!({"results":[refused(&r)]})
    );
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&r)], "permanent", NOW), false),
            NOW
        )
        .unwrap(),
        json!({"results":[granted(&r)]})
    );
    let listed = store.secret_permissions_list(None, NOW).unwrap();
    let row = &listed["grants"][0];
    assert!(row.get("agent_id").is_none());
    assert!(row["holder"].get("agent_id").is_none());
    assert_eq!(
        store
            .secret_permissions_revoke(row["id"].as_str().unwrap(), "reserved:cingulate", NOW)
            .unwrap(),
        json!({"outcome":"revoked"})
    );
    assert_eq!(count(&store,"SELECT COUNT(*) FROM audit_log WHERE op='secret_grant_revoke' AND actor='reserved:cingulate' AND credential_id='secret|key'"),1);
}

#[test]
fn secret_approval_batch_preserves_order_and_unlisted_requests() {
    let (_root, store, a) = approval_setup("approve-batch");
    let mut bcall = call();
    bcall.scope.scope_ref = "B".into();
    let b = use_reply(&store, &bcall, NOW);
    let unknown = json!({"request_id":UNKNOWN,"statement_sha256":"0".repeat(64)});
    let e = envelope(vec![unknown, item(&a)], "hour", NOW);
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[{"request_id":UNKNOWN,"outcome":"refused","code":"approval_invalid"},granted(&a)]})
    );
    assert_eq!(use_reply(&store, &bcall, NOW), b);
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&b)], "hour", NOW), false),
            NOW + 600_000
        )
        .unwrap(),
        json!({"results":[refused(&b)]})
    );
}

#[test]
fn secret_approval_statement_digest_and_decision_are_bound() {
    let (_root, store, r) = approval_setup("approve-digest");
    let mut wrong = item(&r);
    wrong["statement_sha256"] = json!("0".repeat(64));
    let mut wrong_decision = envelope(vec![item(&r)], "hour", NOW);
    wrong_decision["decision"] = json!("delete");
    for e in [envelope(vec![wrong], "hour", NOW), wrong_decision] {
        assert_eq!(
            phone(&store, &signed(&e, false), NOW).unwrap(),
            json!({"results":[refused(&r)]})
        );
    }
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
}

#[test]
fn secret_approval_signature_must_use_the_registered_p256_key() {
    let (_root, store, r) = approval_setup("approve-signature");
    let bytes = serde_json::to_vec(&envelope(vec![item(&r)], "hour", NOW)).unwrap();
    let other = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let signature: Signature = other.sign(&bytes);
    let op = PhoneOperation::Approve {
        envelope: bytes,
        signature: signature.to_der().as_bytes().to_vec(),
        card_ref: None,
    };
    assert_eq!(phone(&store, &op, NOW), Err(SecretError::ApprovalInvalid));
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
}

#[test]
fn secret_approval_requires_current_pairing() {
    let (_root, store, r) = approval_setup("approve-pairing");
    let op = signed(&envelope(vec![item(&r)], "hour", NOW), false);
    assert_eq!(
        store.secret_phone_operation(FP, Some("pair-B"), NOW, &op, || true, || NOW),
        Err(SecretError::PhoneNotRegistered)
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
}

#[test]
fn secret_approval_and_delete_bind_current_member_per_item() {
    let (_root, store, r) = approval_setup("approve-member");
    let d = phone(
        &store,
        &PhoneOperation::DeleteRequest { name: "key".into() },
        NOW,
    )
    .unwrap();
    sql(&store,"UPDATE settings SET value='fed-computer:33333333333333333333333333333333' WHERE name='federation.self_member'");
    for (request, delete, duration) in [(&r, false, "hour"), (&d, true, "none")] {
        assert_eq!(
            phone(
                &store,
                &signed(&envelope(vec![item(request)], duration, NOW), delete),
                NOW
            )
            .unwrap(),
            json!({"results":[refused(request)]})
        );
    }
    let new = use_reply(&store, &call(), NOW);
    assert_ne!(new["request_id"], r["request_id"]);
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&new)], "hour", NOW), false),
            NOW
        )
        .unwrap(),
        json!({"results":[granted(&new)]})
    );
    let new_delete = phone(
        &store,
        &PhoneOperation::DeleteRequest { name: "key".into() },
        NOW,
    )
    .unwrap();
    assert_ne!(new_delete["request_id"], d["request_id"]);
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&new_delete)], "none", NOW), true),
            NOW
        )
        .unwrap(),
        json!({"results":[granted(&new_delete)]})
    );
    sql(
        &store,
        "DELETE FROM settings WHERE name='federation.self_member'",
    );
    assert_eq!(
        phone(
            &store,
            &PhoneOperation::DeleteRequest { name: "key".into() },
            NOW
        ),
        Err(SecretError::SecretSetupIncomplete)
    );
}

#[test]
fn secret_approval_incarnation_cannot_survive_delete_and_recreate() {
    let (_root, store, r) = approval_setup("approve-incarnation");
    sql(&store, "DELETE FROM agent_secrets");
    seed(
        &store,
        "key",
        &scope(),
        &SecretMaterial::ApiKey(Secret::new(b"new-key".to_vec())),
    );
    sql(
        &store,
        "UPDATE agent_secrets SET incarnation='ffffffffffffffffffffffffffffffff'",
    );
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&r)], "hour", NOW), false),
            NOW
        )
        .unwrap(),
        json!({"results":[refused(&r)]})
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
}

#[test]
fn secret_approval_time_interval_skew_and_exact_expiry_boundaries() {
    for (delta, now_delta, valid) in [
        (0, 0, true),
        (599_999, 599_999, true),
        (-1, 0, false),
        (600_000, 600_000, false),
        (0, 120_000, true),
        (0, 120_001, false),
        (0, -120_000, true),
        (0, -120_001, false),
    ] {
        let (_root, store, r) = approval_setup("approve-time");
        let e = envelope(vec![item(&r)], "hour", NOW + delta);
        let answer = phone(&store, &signed(&e, false), NOW + now_delta).unwrap();
        assert_eq!(
            answer,
            json!({"results":[if valid {granted(&r)}else{refused(&r)}]}),
            "issued {delta}, now {now_delta}"
        );
    }
    for duration in ["once", "hour", "session", "permanent"] {
        let (_root, store, r) = approval_setup("approve-expiry");
        let mut e = envelope(vec![item(&r)], duration, NOW);
        e["grant_expires_at_ms"] = json!(e["grant_expires_at_ms"].as_i64().unwrap() + 1);
        assert_eq!(
            phone(&store, &signed(&e, false), NOW).unwrap(),
            json!({"results":[refused(&r)]})
        );
    }
    for delete in [false, true] {
        for (now, valid) in [(NOW + 599_999, true), (NOW + 600_000, false)] {
            let (_root, store, r) = approval_setup("approve-late");
            let r = if delete {
                phone(
                    &store,
                    &PhoneOperation::DeleteRequest { name: "key".into() },
                    NOW,
                )
                .unwrap()
            } else {
                r
            };
            let e = envelope(
                vec![item(&r)],
                if delete { "none" } else { "hour" },
                NOW + 599_999,
            );
            assert_eq!(
                phone(&store, &signed(&e, delete), now).unwrap(),
                json!({"results":[if valid {granted(&r)}else{refused(&r)}]})
            );
        }
    }
}

#[test]
fn secret_approval_whole_envelope_strictness_and_item_limit() {
    let (_root, store, r) = approval_setup("approve-strict");
    let e = envelope(vec![item(&r)], "hour", NOW);
    let bytes = serde_json::to_vec(&e).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let mut bad = vec![
        b"not-json".to_vec(),
        format!(" {text}").into_bytes(),
        text.replacen("{", "{\"unknown\":1,", 1).into_bytes(),
        text.replacen("{", "{\"v\":\"ck-secret-use-envelope/v1\",", 1)
            .into_bytes(),
        text.replace(
            "\"statement_sha256\":",
            "\"request_id\":\"00000000000000000000000000\",\"statement_sha256\":",
        )
        .into_bytes(),
        text.replace("1700000000000", "1700000000000.0")
            .into_bytes(),
    ];
    let mut wrong = e.clone();
    wrong["device_fingerprint"] = json!("2".repeat(32));
    bad.push(serde_json::to_vec(&wrong).unwrap());
    let mut duplicate = e.clone();
    duplicate["items"] = json!([item(&r), item(&r)]);
    bad.push(serde_json::to_vec(&duplicate).unwrap());
    let mut over = e.clone();
    over["items"] = json!((0..17)
        .map(|i| json!({"request_id":format!("{i:026}"),"statement_sha256":"0".repeat(64)}))
        .collect::<Vec<_>>());
    bad.push(serde_json::to_vec(&over).unwrap());
    let mut unsafe_integer = e.clone();
    unsafe_integer["issued_at_ms"] = json!(1u64 << 53);
    bad.push(serde_json::to_vec(&unsafe_integer).unwrap());
    let mut at_integer = e.clone();
    at_integer["issued_at_ms"] = json!((1u64 << 53) - 1);
    assert_eq!(
        phone(&store, &signed(&at_integer, false), NOW).unwrap(),
        json!({"results":[refused(&r)]})
    );
    for bytes in bad {
        assert_eq!(
            phone(&store, &signed_bytes(bytes, false), NOW),
            Err(SecretError::ApprovalInvalid)
        );
    }
    let raw = PhoneOperation::Approve {
        envelope: bytes,
        signature: vec![0; 64],
        card_ref: None,
    };
    assert_eq!(phone(&store, &raw, NOW), Err(SecretError::ApprovalInvalid));
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
    let at = envelope(
        (0..15)
            .map(|i| json!({"request_id":format!("{i:026}"),"statement_sha256":"0".repeat(64)}))
            .chain([item(&r)])
            .collect(),
        "hour",
        NOW,
    );
    let result = phone(&store, &signed(&at, false), NOW).unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 16);
    assert_eq!(result["results"][15], granted(&r));
}

#[test]
fn secret_approval_checks_sealed_release_scope_not_caller_scope() {
    let (_root, store, r) = approval_setup("approve-kind-quarantine");
    sql(
        &store,
        "PRAGMA ignore_check_constraints=ON; UPDATE agent_secrets SET kind='site_login'",
    );
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&r)], "hour", NOW), false),
            NOW
        )
        .unwrap(),
        json!({"results":[refused(&r)]})
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM agent_secrets WHERE state='corrupt'"
        ),
        1
    );
    let (_root, store, r) = approval_setup("approve-scope");
    sql(
        &store,
        "UPDATE agent_secrets SET location='header:X-Changed'",
    );
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&r)], "hour", NOW), false),
            NOW
        )
        .unwrap(),
        json!({"results":[refused(&r)]})
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM agent_secrets WHERE state='corrupt'"
        ),
        1
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_quarantine'"
        ),
        1
    );
    phone(
        &store,
        &signed(&envelope(vec![item(&r)], "hour", NOW), false),
        NOW,
    )
    .unwrap();
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_quarantine'"
        ),
        1
    );
    let (_root, store, r) = approval_setup("approve-quarantine-rollback");
    sql(&store,"UPDATE agent_secrets SET location='header:X-Changed'; CREATE TRIGGER fail_quarantine BEFORE INSERT ON audit_log WHEN NEW.op='secret_quarantine' BEGIN SELECT RAISE(ABORT,'audit failed'); END;");
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&r)], "hour", NOW), false),
            NOW
        )
        .unwrap(),
        json!({"results":[refused(&r)]})
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM agent_secrets WHERE state='active'"
        ),
        1
    );
}

#[test]
fn secret_delete_is_signed_reusable_uncapped_and_removes_corrupt_records() {
    let (_root, store, r) = approval_setup("delete-positive");
    grant(&store, "fixture-grant", "permanent", 0, NOW);
    for n in 1..64 {
        let mut call = call();
        call.scope.scope_ref = format!("H{n}");
        assert_eq!(use_reply(&store, &call, NOW)["status"], "approval_required");
    }
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE request_kind='approve'"
        ),
        64
    );
    let op = PhoneOperation::DeleteRequest { name: "key".into() };
    let d = phone(&store, &op, NOW).unwrap();
    assert_eq!(phone(&store, &op, NOW + 1).unwrap(), d);
    assert_eq!(
        d.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["expires_at_ms", "request_id", "statement_b64url", "status"]
    );
    assert_eq!(
        phone(
            &store,
            &PhoneOperation::DeleteRequest {
                name: "absent".into()
            },
            NOW
        ),
        Err(SecretError::NotFound)
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM secret_pending_requests WHERE request_kind='delete'"
        ),
        1
    );
    assert_eq!(
        phone(
            &store,
            &signed(&envelope(vec![item(&r)], "hour", NOW), true),
            NOW
        )
        .unwrap(),
        json!({"results":[refused(&r)]})
    );
    let e = envelope(vec![item(&d)], "none", NOW);
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[refused(&d)]})
    );
    assert_eq!(
        phone(
            &store,
            &PhoneOperation::DeleteCommit {
                envelope: serde_json::to_vec(&e).unwrap(),
                signature: vec![]
            },
            NOW
        ),
        Err(SecretError::ApprovalInvalid)
    );
    sql(&store, "PRAGMA ignore_check_constraints=ON; UPDATE agent_secrets SET state='corrupt',kind='site_login'");
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let s = store.clone();
            let b = barrier.clone();
            let op = signed(&e, true);
            std::thread::spawn(move || {
                b.wait();
                phone(&s, &op, NOW).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let answers = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    // The same signed delete sent twice at once is one decision: both learn the delete.
    assert_eq!(answers[0]["results"][0]["outcome"], "granted");
    assert_eq!(answers[1], answers[0]);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM agent_secrets"), 0);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
    assert_eq!(
        count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
        0
    );
    assert_eq!(phone(&store, &op, NOW), Err(SecretError::NotFound));
    store
        .store
        .with_conn(|c| {
            let hash: String = c.query_row(
                "SELECT payload_hash FROM audit_log WHERE op='secret_delete'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(
                hash,
                phone::hex(&payload_hash(&serde_json::to_vec(&e).unwrap()))
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn secret_approval_audit_failure_rolls_back_and_deadline_is_checked_before_commit() {
    let (_root, store, r) = approval_setup("approve-rollback");
    let op = signed(&envelope(vec![item(&r)], "hour", NOW), false);
    assert_eq!(
        store.secret_phone_operation(
            FP,
            Some("pair-A"),
            NOW,
            &op,
            || false,
            || panic!("not admitted")
        ),
        Err(SecretError::PairingUnavailable)
    );
    sql(&store,"CREATE TRIGGER fail_grant BEFORE INSERT ON audit_log WHEN NEW.op='secret_grant_create' BEGIN SELECT RAISE(ABORT,'audit failed'); END;");
    assert_eq!(phone(&store, &op, NOW), Err(SecretError::StoreError));
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
    assert_eq!(
        count(&store, "SELECT consumed FROM secret_pending_requests"),
        0
    );
    sql(&store, "DROP TRIGGER fail_grant");
    assert_eq!(
        phone(&store, &op, NOW).unwrap(),
        json!({"results":[granted(&r)]})
    );
}

#[test]
fn secret_revoke_is_unsigned_and_provider_lists_only_live_grants() {
    let (_root, store, r) = approval_setup("approve-revoke");
    phone(
        &store,
        &signed(&envelope(vec![item(&r)], "hour", NOW), false),
        NOW,
    )
    .unwrap();
    let listed = store.secret_permissions_list(None, NOW).unwrap();
    let id = listed["grants"][0]["id"].as_str().unwrap();
    assert_eq!(
        store
            .secret_permissions_list(None, NOW + 3_600_000)
            .unwrap(),
        json!({"grants":[]})
    );
    assert_eq!(
        store
            .secret_permissions_revoke(id, "reserved:cingulate", NOW + 3_600_000)
            .unwrap(),
        json!({"outcome":"not_found"})
    );
    assert_eq!(
        phone(
            &store,
            &PhoneOperation::Revoke {
                grant_id: id.into()
            },
            NOW
        )
        .unwrap(),
        json!({"outcome":"revoked"})
    );
    assert_eq!(
        phone(
            &store,
            &PhoneOperation::Revoke {
                grant_id: id.into()
            },
            NOW
        )
        .unwrap(),
        json!({"outcome":"not_found"})
    );
    assert_eq!(count(&store,"SELECT COUNT(*) FROM audit_log WHERE op='secret_grant_revoke' AND actor='fed-phone:11111111111111111111111111111111' AND credential_id='secret|key'"),1);
}

#[test]
fn secret_agent_approval_refuses_a_version_envelope_and_a_key_inside_an_item() {
    let (_root, store, request) = approval_setup("agent-version-envelope");
    // A `version` envelope offers a duration no agent statement carries, so its agent item
    // is refused and no agent grant appears.
    let e = envelope(vec![item(&request)], "version", NOW);
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[refused(&request)]})
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
    // An item holds `request_id` and `statement_sha256` and nothing else. It has no
    // `deny_unknown_fields` of its own, so a key such as `duration` inside it must still be
    // refused by the whole-envelope parse rather than ignored.
    let mut with_key = envelope(vec![item(&request)], "hour", NOW);
    with_key["items"][0]["duration"] = json!("version");
    assert_eq!(
        phone(&store, &signed(&with_key, false), NOW),
        Err(SecretError::ApprovalInvalid)
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
    // The same envelope without the extra key grants, so the refusal above is the key.
    let e = envelope(vec![item(&request)], "hour", NOW);
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[granted(&request)]})
    );
}

#[test]
fn secret_ckios_vectors_are_emitted_by_vault_code_and_pinned() {
    let a = "01HF7YAT000000000000000001";
    let b = "01HF7YAT000000000000000002";
    let mut vectors = Vec::new();
    for (label, delete, unknown) in [
        ("approval", false, false),
        ("delete", true, false),
        ("batch-omitted", false, false),
        ("batch-unknown", false, true),
    ] {
        let (_root, store, _) = approval_setup("ckios-vector");
        sql(&store, "DELETE FROM secret_pending_requests");
        let incarnation = format!(
            "{:032x}",
            b"key".iter().copied().map(u64::from).sum::<u64>()
        );
        let mut statements = Vec::new();
        for id in if label == "batch-omitted" {
            vec![a, b]
        } else {
            vec![a]
        } {
            let s = if delete {
                agent_secret::delete_statement(
                    id,
                    MEMBER,
                    "key",
                    "agent_api_key",
                    &incarnation,
                    NOW + 600_000,
                )
            } else {
                agent_secret::approval_statement(
                    id,
                    MEMBER,
                    &incarnation,
                    &call(),
                    &scope(),
                    NOW + 600_000,
                )
            };
            let bytes = serde_json::to_vec(&s).unwrap();
            let hash = phone::hex(&payload_hash(&bytes));
            store.fenced_write(|tx|tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,mapped_owner,mapped_kind,mapped_ref,mapped_epoch,coverage,agent_id,statement_bytes,statement_sha256,request_expires_at_ms) VALUES (?1,?2,'key',?3,?4,'reserved:prefrontal-core','head','H',7,'scope','agent-A',?5,?6,?7)",rusqlite::params![id,if delete {"delete"}else{"approve"},incarnation,MEMBER,bytes,hash,NOW+600_000]).map(|_|())).unwrap();
            statements.push(json!({"request_id":id,"statement_b64url":URL_SAFE_NO_PAD.encode(&bytes),"statement_sha256":hash}));
        }
        let mut items =
            vec![json!({"request_id":a,"statement_sha256":statements[0]["statement_sha256"]})];
        if unknown {
            items.insert(
                0,
                json!({"request_id":UNKNOWN,"statement_sha256":"0".repeat(64)}),
            );
        }
        let e = envelope(items, if delete { "none" } else { "hour" }, NOW);
        let bytes = serde_json::to_vec(&e).unwrap();
        let signature: Signature = signer().sign(&bytes);
        let result = phone(&store, &signed(&e, delete), NOW).unwrap();
        if label == "batch-omitted" {
            assert_eq!(
                count(
                    &store,
                    "SELECT COUNT(*) FROM secret_pending_requests WHERE consumed=0"
                ),
                1
            );
        }
        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(agent_secret::ApprovalEnvelope::verify(
            &tampered,
            signature.to_der().as_bytes(),
            signer().verifying_key().to_encoded_point(false).as_bytes(),
            FP
        )
        .is_err());
        vectors.push(json!({"case":label,"statements":statements,"envelope_b64url":URL_SAFE_NO_PAD.encode(&bytes),"signature_b64url":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),"envelope_sha256":phone::hex(&payload_hash(&bytes)),"results":result["results"],"tampered_envelope_b64url":URL_SAFE_NO_PAD.encode(tampered),"unlisted_pending":label=="batch-omitted"}));
    }
    let phone_pem = crate::kem::pem_from_scalar(&[3; 32]);
    let recipient_pem = crate::kem::pem_from_scalar(&[9; 32]);
    let (phone_public, _) = crate::kem::public_half(&phone_pem).unwrap();
    let (recipient_public, _) = crate::kem::public_half(&recipient_pem).unwrap();
    let aad = agent_secret::deposit_aad(a, MEMBER, "key", &scope()).unwrap();
    let plaintext = agent_secret::deposit_plaintext(&SecretMaterial::ApiKey(Secret::new(
        b"ckios-fixed-api-key".to_vec(),
    )));
    let (enc, ciphertext) = crate::kem::seal_auth_with_ephemeral_ikm(
        &phone_pem,
        &recipient_public,
        plaintext.expose(),
        agent_secret::DEPOSIT_INFO,
        &aad,
        [4; 32],
    )
    .unwrap();
    let opened = Secret::new(
        crate::kem::open_auth(
            &recipient_pem,
            &phone_public,
            &enc,
            &ciphertext,
            agent_secret::DEPOSIT_INFO,
            &aad,
        )
        .unwrap(),
    );
    assert_eq!(opened.expose(), plaintext.expose());
    let emitted = json!({"approval_private_key_hex":"07".repeat(32),"vectors":vectors,"deposit":{"phone_scalar_hex":"03".repeat(32),"recipient_scalar_hex":"09".repeat(32),"ephemeral_ikm_hex":"04".repeat(32),"phone_public_hex":phone::hex(&phone_public),"recipient_public_hex":phone::hex(&recipient_public),"aad_b64url":URL_SAFE_NO_PAD.encode(&aad),"plaintext_b64url":URL_SAFE_NO_PAD.encode(plaintext.expose()),"enc_b64url":URL_SAFE_NO_PAD.encode(&enc),"ciphertext_b64url":URL_SAFE_NO_PAD.encode(&ciphertext),"deposit_digest":phone::hex(&agent_secret::deposit_digest(a,&enc,&ciphertext,&aad))}});
    let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/secret-approval-v1.json");
    if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
        std::fs::create_dir_all(pinned.parent().unwrap()).unwrap();
        std::fs::write(&pinned, serde_json::to_vec_pretty(&emitted).unwrap()).unwrap();
        println!("emitted four CKIOS approval/delete/batch vectors and one deposit vector");
    } else {
        let expected: Value =
            serde_json::from_slice(&std::fs::read(&pinned).expect("pinned CKIOS vectors")).unwrap();
        assert_eq!(emitted, expected, "vault-emitted CKIOS vectors changed");
    }
}
