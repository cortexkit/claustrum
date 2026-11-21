use super::*;
use crate::secret_phone::{self, PhoneAnswer};
use std::{fmt::Write, path::PathBuf};

const NUMBER_CANARY: &str = "synthetic-issue-number-canary";
const REASON_CANARY: &str = "synthetic-state-reason-canary";

struct Samples {
    rig: Rig,
    clock: Arc<AtomicI64>,
    cases: Vec<Value>,
    error_text: Vec<String>,
    debug: Vec<String>,
    statements: Vec<String>,
}

impl Samples {
    fn new(rig: Rig) -> Self {
        let clock = token_gate_clock(&rig);
        // The mint's monotonic ULID path advances this expired fixture row, even
        // if the new ULID's random suffix is maximal.
        rig.sql(&format!(
            "INSERT INTO broker_action_requests (
            request_id, principal, agent_id, scope_json, statement_bytes, statement_sha256,
            policy_version, identity, legs_json, created_at_ms, expires_at_ms
        ) VALUES ('01MCC5RM00ZZZZZZZZZZZZZZZZ', 'reserved:plexus', 'fixture', '{{}}',
                  X'00', 'fixture', 1, '{APP}', '[{{}}]', {}, {NOW})",
            NOW - TTL
        ));
        Self {
            rig,
            clock,
            cases: Vec::new(),
            error_text: Vec::new(),
            debug: Vec::new(),
            statements: Vec::new(),
        }
    }

    fn at(&self, now: i64) {
        self.clock.store(now, Ordering::SeqCst);
    }

    fn request_debug(&mut self, method: &str, params: &Value) {
        let frame = super::request(method, params.clone(), 1, 1);
        let request = crate::RouteRequest::decode(frame).body.unwrap();
        self.debug.push(format!("{request:?}"));
    }

    fn record(
        &mut self,
        name: &str,
        method: &str,
        route: &str,
        params: Value,
        response: (FrameType, Value),
        expected: &str,
    ) -> Value {
        let (frame, reply) = response;
        let result = &reply["result"];
        let frame = if expected == "invalid_params" {
            assert_eq!(frame, FrameType::Error, "{name}");
            assert_eq!(reply["code"], expected, "{name}");
            "error"
        } else {
            assert_eq!(frame, FrameType::Response, "{name}");
            if !expected.is_empty() {
                let class = match expected {
                    "approval_pending_limit" | "store_error" | "github_unavailable" => "transient",
                    "needs_reauth" => "auth_required",
                    _ => "permanent",
                };
                assert_eq!(*result, refusal(expected, class), "{name}");
            } else {
                assert!(
                    result.is_object() && result.get("error").is_none(),
                    "{name}"
                );
            }
            "response"
        };
        if !expected.is_empty() {
            self.error_text.push(reply.to_string());
        }
        let mut case = json!({"name": name, "method": method, "route": route,
            "at_ms": self.clock.load(Ordering::SeqCst), "frame": frame, "body": reply});
        if name == "mint_oversized_statement" {
            case["params_omitted"] =
                json!("mint_head params with the body field value replaced by 524288 copies of x");
        } else {
            case["params"] = params;
        }
        self.cases.push(case);
        result.clone()
    }

    async fn reserved(
        &mut self,
        name: &str,
        method: &str,
        module: &str,
        params: Value,
        expected: &str,
    ) -> Value {
        self.request_debug(method, &params);
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(Some(self.clock.load(Ordering::SeqCst)));
        let ingress = Ingress::new(&self.rig);
        ingress.bind(&self.rig, 1, module);
        ingress
            .dispatch(&self.rig, super::request(method, params.clone(), 1, 1))
            .await;
        let response = frame(&mut self.rig).await;
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(None);
        self.record(
            name,
            method,
            &format!("reserved:{module}"),
            params,
            (response.header.ty, body(&response)),
            expected,
        )
    }

    async fn mint(&mut self, name: &str, module: &str, params: Value) -> BrokerActionRequestReply {
        let result = self
            .reserved(name, OP_REQUEST_ACTION, module, params, "")
            .await;
        let encoded = result["statement_b64url"].as_str().unwrap();
        let checked = check_statement(encoded).unwrap();
        let canonical = std::str::from_utf8(checked.bytes()).unwrap();
        assert!(canonical.contains(FIELD_CANARY) && canonical.contains(CONTEXT_CANARY));
        assert_eq!(result["request_id"], checked.statement().request_id);
        assert_eq!(result["statement_sha256"], checked.sha256());
        assert_eq!(
            result["expires_at_ms"],
            self.clock.load(Ordering::SeqCst) + TTL
        );
        self.statements
            .extend([encoded.to_owned(), canonical.to_owned()]);
        self.debug
            .push(format!("{checked:?} {:?}", checked.statement()));
        for field in &checked.statement().fields {
            self.debug.push(format!("{:?}", field.value));
        }
        let mut malformed: Value = serde_json::from_str(canonical).unwrap();
        malformed[CONTEXT_CANARY] = Value::Null;
        let error =
            check_statement(&BASE64_URL_SAFE_NO_PAD.encode(malformed.to_string())).unwrap_err();
        assert_eq!(error.member(), CONTEXT_CANARY);
        self.error_text.push(error.to_string());
        self.debug.push(format!("{error:?}"));
        BrokerActionRequestReply {
            request_id: checked.statement().request_id.clone(),
            statement_b64url: encoded.to_owned(),
            statement_sha256: checked.sha256().to_owned(),
            expires_at_ms: checked.statement().expires_at_ms,
        }
    }

    async fn desktop(&mut self, name: &str, params: Value, expected: &str) -> Value {
        self.request_debug(OP_APPROVE_ACTION, &params);
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(Some(self.clock.load(Ordering::SeqCst)));
        let response = approve_on_route(&self.rig, params.clone()).await;
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(None);
        self.record(
            name,
            OP_APPROVE_ACTION,
            "desktop:development",
            params,
            response,
            expected,
        )
    }

    async fn phone(
        &mut self,
        name: &str,
        params: Value,
        build: &str,
        pairing: Option<&str>,
        expected: &str,
    ) -> Value {
        self.request_debug(OP_APPROVE_ACTION, &params);
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(Some(self.clock.load(Ordering::SeqCst)));
        let answer = secret_phone::serve_with_lookup(
            Arc::clone(&self.rig.store), APPROVING_PHONE, Some(build), OP_APPROVE_ACTION, &params,
            tokio::time::Instant::now() + secret_phone::PHONE_OP_DEADLINE,
            async { pairing.map(|id| json!({"devices":[{"class":"phone","fingerprint":APPROVING_PHONE,"pairing_id":id}]})) },
        ).await;
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(None);
        let (tx, mut rx) = mpsc::channel(1);
        let header = super::request(OP_APPROVE_ACTION, Value::Null, 1, 1).header;
        match answer {
            PhoneAnswer::Reply(reply) => {
                crate::send_route_result(&tx, header, crate::wrap_result(reply)).await
            }
            PhoneAnswer::InvalidParams(detail) => {
                crate::invalid_params(
                    &tx,
                    header.ver,
                    header.channel,
                    header.epoch,
                    header.corr,
                    &detail,
                )
                .await
            }
            PhoneAnswer::PermissionsOperatorRequired => panic!("approval routed to permissions"),
        }
        .unwrap();
        let response = rx.recv().await.unwrap();
        self.record(
            name,
            OP_APPROVE_ACTION,
            &format!("fed-phone:{APPROVING_PHONE}:{build}"),
            params,
            (response.header.ty, body(&response)),
            expected,
        )
    }
}

fn head() -> Value {
    let mut request = one();
    request["fields"][1]["value"] = json!(NUMBER_CANARY);
    request
}

fn worker() -> Value {
    let mut request = template(&head());
    let legs = request["legs"].as_array_mut().unwrap();
    let third = changed(legs[0].clone(), "request_sha256", json!("3".repeat(64)));
    legs.push(third);
    request["fields"][0]["value"] = json!(REASON_CANARY);
    request["stamp"]["kind"] = json!("worker");
    request["stamp"]["attributes"] =
        json!({"agent_id":"worker-agent", "on_behalf_of_agent":"agent"});
    request
}

fn flow() -> Value {
    let mut request = map_stamp(head(), "kind", json!("ephemeral"));
    request["stamp"]["attributes"] =
        json!({"agent_id":"agent", "flow_id":"fixture-flow", "run_id":"fixture-run"});
    request["stamp"]["parent_state"] = json!("linked");
    request["stamp"]["parent"] = json!({"owner":{"kind":"reserved","module_id":"prefrontal"}, "ref":"fixture-parent", "scope_epoch":3});
    request
}

async fn mint_refusals(samples: &mut Samples) {
    grant(
        &samples.rig,
        "aft",
        "github_app:unbound",
        GrantOperation::PolicyToken,
    );
    for (name, module, request, expected) in [
        ("mint_wrong_caller", "other", head(), "not_found"),
        (
            "mint_missing_grant",
            "aft",
            changed(head(), "identity", json!("github_app:ungranted")),
            "not_found",
        ),
        (
            "mint_unmapped_stamp",
            "aft",
            map_stamp(head(), "attributes", json!({})),
            "not_found",
        ),
        (
            "mint_malformed_stamp",
            "aft",
            changed(head(), "stamp", Value::Null),
            "invalid_params",
        ),
        (
            "mint_malformed_body",
            "aft",
            changed(head(), "method", json!("Post")),
            "invalid_params",
        ),
        (
            "mint_wrong_service",
            "aft",
            changed(head(), "service", json!("other")),
            "not_found",
        ),
        (
            "mint_no_binding",
            "aft",
            changed(head(), "identity", json!("github_app:unbound")),
            "not_found",
        ),
        (
            "mint_wrong_agent",
            "aft",
            map_stamp(head(), "attributes", json!({"agent_id":"wrong"})),
            "not_found",
        ),
        (
            "mint_unknown_kind",
            "aft",
            changed(
                changed(head(), "kind", json!("unknown")),
                "action",
                json!("unknown"),
            ),
            "not_found",
        ),
        (
            "mint_wrong_host",
            "aft",
            changed(head(), "host", json!("api.github.com:8443")),
            "not_found",
        ),
        (
            "mint_unbound_resource",
            "aft",
            changed(head(), "resource", json!("org/unbound")),
            "not_found",
        ),
        (
            "mint_no_approval_required",
            "aft",
            changed(
                changed(head(), "kind", json!("node_repository")),
                "action",
                json!("node_repository"),
            ),
            "approval_not_required",
        ),
    ] {
        samples
            .reserved(name, OP_REQUEST_ACTION, module, request, expected)
            .await;
    }
    for (name, field) in [
        ("mint_missing_field", None),
        ("mint_duplicate_field", Some("number")),
        ("mint_unknown_field", Some("unexpected")),
    ] {
        let mut request = head();
        match field {
            None => {
                request["fields"].as_array_mut().unwrap().pop();
            }
            Some(field) => request["fields"][0]["name"] = json!(field),
        }
        samples
            .reserved(
                name,
                OP_REQUEST_ACTION,
                "aft",
                request,
                "consent_fields_invalid",
            )
            .await;
    }
    let mut oversized = head();
    oversized["fields"][0]["value"] =
        json!("x".repeat(credentials_core::broker_action::MAX_STATEMENT_BYTES));
    samples
        .reserved(
            "mint_oversized_statement",
            OP_REQUEST_ACTION,
            "aft",
            oversized,
            "invalid_params",
        )
        .await;
    samples.rig.sql(&format!("UPDATE credentials SET github_app_agent = 'wrong', github_app_created_at_ms = 1 WHERE credential_id = '{APP}'"));
    samples
        .reserved(
            "mint_wrong_credential_agent",
            OP_REQUEST_ACTION,
            "aft",
            head(),
            "not_found",
        )
        .await;
    samples.rig.sql(&format!(
        "DELETE FROM credentials WHERE credential_id = '{APP}'"
    ));
    samples
        .reserved(
            "mint_missing_credential",
            OP_REQUEST_ACTION,
            "aft",
            head(),
            "not_found",
        )
        .await;
    samples.rig.store.create(APP, &app_record(None)).unwrap();
    samples.rig.sql("CREATE TRIGGER fail_sample_mint BEFORE INSERT ON audit_log WHEN NEW.op = 'broker_action_request'
                     BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END;");
    samples
        .reserved(
            "mint_store_error",
            OP_REQUEST_ACTION,
            "aft",
            head(),
            "store_error",
        )
        .await;
    samples.rig.sql("DROP TRIGGER fail_sample_mint");

    // Three requests were minted above. Fill the agent limit, then swap those
    // fixture rows for distinct agents to reach the total limit independently.
    seed_pending_for(&samples.rig, 13, Some("agent"));
    samples
        .reserved(
            "mint_agent_pending_limit",
            OP_REQUEST_ACTION,
            "aft",
            head(),
            "approval_pending_limit",
        )
        .await;
    samples
        .rig
        .sql("DELETE FROM broker_action_requests WHERE statement_sha256 = 'digest'");
    seed_pending(&samples.rig, 253);
    samples
        .reserved(
            "mint_total_pending_limit",
            OP_REQUEST_ACTION,
            "aft",
            head(),
            "approval_pending_limit",
        )
        .await;
    samples
        .rig
        .sql("DELETE FROM broker_action_requests WHERE statement_sha256 = 'digest'");
}

async fn phone_cases(samples: &mut Samples, request: &BrokerActionRequestReply) {
    let key = SigningKey::from_slice(&[51; 32]).unwrap();
    let other_key = SigningKey::from_slice(&[52; 32]).unwrap();
    register_approver(&samples.rig, &key);
    let canonical = envelope(request, APPROVING_PHONE, NOW);
    let signed = |value: &Value| phone_approval_params(&serde_json::to_vec(value).unwrap(), &key);
    let valid = signed(&canonical);
    for (name, input, build, pairing, expected) in [
        (
            "approve_phone_wrong_build",
            valid.clone(),
            "development",
            Some("pair-A"),
            "not_found",
        ),
        (
            "approve_phone_malformed_body",
            changed(
                valid.clone(),
                "statement_b64url",
                json!(request.statement_b64url),
            ),
            "production",
            Some("pair-A"),
            "invalid_params",
        ),
        (
            "approve_phone_wrong_pairing",
            valid.clone(),
            "production",
            Some("pair-B"),
            "approval_invalid",
        ),
        (
            "approve_phone_lookup_unavailable",
            valid.clone(),
            "production",
            None,
            "approval_invalid",
        ),
        (
            "approve_phone_wrong_key",
            phone_approval_params(&serde_json::to_vec(&canonical).unwrap(), &other_key),
            "production",
            Some("pair-A"),
            "approval_invalid",
        ),
    ] {
        samples.phone(name, input, build, pairing, expected).await;
    }
    for (name, member, value) in [
        (
            "approve_phone_wrong_digest",
            "statement_sha256",
            json!("a".repeat(64)),
        ),
        (
            "approve_phone_wrong_fingerprint",
            "device_fingerprint",
            json!(DEVELOPMENT_DESKTOP),
        ),
        (
            "approve_phone_wrong_domain",
            "v",
            json!("ck-manifest-binding-envelope/v1"),
        ),
        ("approve_phone_non_allow", "decision", json!("decline")),
        (
            "approve_phone_unknown_request",
            "request_id",
            json!("01HF7YAT000000000000000004"),
        ),
        (
            "approve_phone_before_creation",
            "issued_at_ms",
            json!(NOW - 1),
        ),
        (
            "approve_phone_skew",
            "issued_at_ms",
            json!(NOW + SECRET_ISSUE_SKEW_LIMIT_MS + 1),
        ),
    ] {
        samples
            .phone(
                name,
                signed(&changed(canonical.clone(), member, value)),
                "production",
                Some("pair-A"),
                "approval_invalid",
            )
            .await;
    }
    let noncanonical = phone_approval_params(&serde_json::to_vec_pretty(&canonical).unwrap(), &key);
    samples
        .phone(
            "approve_phone_noncanonical_envelope",
            noncanonical,
            "production",
            Some("pair-A"),
            "approval_invalid",
        )
        .await;
    samples.at(NOW + TTL);
    let expired = signed(&changed(
        canonical.clone(),
        "issued_at_ms",
        json!(NOW + TTL - 1),
    ));
    samples
        .phone(
            "approve_phone_expired",
            expired,
            "production",
            Some("pair-A"),
            "approval_invalid",
        )
        .await;
    samples.at(NOW);
    let initial = samples
        .phone(
            "approve_phone",
            valid.clone(),
            "production",
            Some("pair-A"),
            "",
        )
        .await;
    assert_eq!(initial, approval_reply(request));
    let replay = samples
        .phone(
            "approve_phone_replay",
            changed(valid, "card_ref", json!("fixture-card")),
            "production",
            Some("pair-A"),
            "",
        )
        .await;
    assert_eq!(replay, initial);
    let different = signed(&changed(canonical, "issued_at_ms", json!(NOW + 1)));
    samples
        .phone(
            "approve_phone_changed_replay",
            different,
            "production",
            Some("pair-A"),
            "approval_invalid",
        )
        .await;
}

async fn desktop_cases(samples: &mut Samples, request: &BrokerActionRequestReply) {
    let bytes = serde_json::to_vec(&envelope(request, DEVELOPMENT_DESKTOP, NOW)).unwrap();
    let params =
        json!({"envelope_b64url":BASE64_URL_SAFE_NO_PAD.encode(bytes), "card_ref":"desktop-card"});
    samples
        .rig
        .admin
        .record_bind_at(77, 1, Principal::Direct, "");
    samples
        .desktop("approve_desktop_disabled", params.clone(), "not_found")
        .await;
    samples
        .rig
        .store
        .set_secret_dev_desktop_approvals_audited(
            true,
            AuditCtx::admin(AuditOp::SecretDevDesktopApprovalsSet),
        )
        .unwrap();
    samples.rig.admin.record_bind_at(
        77,
        1,
        Principal::Reserved {
            module_id: "aft".into(),
        },
        "",
    );
    samples
        .desktop("approve_desktop_wrong_route", params.clone(), "not_found")
        .await;
    samples
        .rig
        .admin
        .record_bind_at(77, 1, Principal::Direct, "");
    samples
        .desktop(
            "approve_desktop_signature_present",
            changed(params.clone(), "signature_b64url", Value::Null),
            "invalid_params",
        )
        .await;
    let canonical_statement = String::from_utf8(
        BASE64_URL_SAFE_NO_PAD
            .decode(&request.statement_b64url)
            .unwrap(),
    )
    .unwrap();
    samples
        .desktop(
            "approve_desktop_unknown_member",
            changed(params.clone(), "statement", json!(canonical_statement)),
            "invalid_params",
        )
        .await;
    let wrong = serde_json::to_vec(&envelope(request, APPROVING_PHONE, NOW)).unwrap();
    samples
        .desktop(
            "approve_desktop_wrong_fingerprint",
            changed(
                params.clone(),
                "envelope_b64url",
                json!(BASE64_URL_SAFE_NO_PAD.encode(wrong)),
            ),
            "approval_invalid",
        )
        .await;
    samples.rig.sql("CREATE TRIGGER fail_sample_approval BEFORE INSERT ON audit_log WHEN NEW.op = 'broker_action_approve'
                     BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END;");
    samples
        .desktop(
            "approve_desktop_store_error",
            params.clone(),
            "approval_invalid",
        )
        .await;
    samples.rig.sql("DROP TRIGGER fail_sample_approval");
    let approved = samples.desktop("approve_desktop", params.clone(), "").await;
    assert_eq!(approved, approval_reply(request));
    assert_eq!(
        samples.desktop("approve_desktop_replay", params, "").await,
        approved
    );
}

async fn token_cases(
    samples: &mut Samples,
    github: &Github,
    head: &BrokerActionRequestReply,
    worker: &BrokerActionRequestReply,
    flow: &BrokerActionRequestReply,
) {
    let single = issue_params(head);
    let worker_first = issue_params(worker);
    let mut worker_second = changed(
        worker_first.clone(),
        "request_sha256",
        json!("2".repeat(64)),
    );
    worker_second["kind"] = json!(CLOSE);
    worker_second["resource"] = json!("org/s");
    let worker_third = changed(
        worker_first.clone(),
        "request_sha256",
        json!("3".repeat(64)),
    );
    let flow_issue = issue_params(flow);
    for (name, module, params, expected) in [
        (
            "issue_no_approval_members",
            "aft",
            params(),
            "approval_required",
        ),
        (
            "issue_missing_request_id",
            "aft",
            without(single.clone(), "approval_request_id"),
            "invalid_params",
        ),
        (
            "issue_missing_digest",
            "aft",
            without(single.clone(), "request_sha256"),
            "invalid_params",
        ),
        (
            "issue_malformed_request_id",
            "aft",
            changed(single.clone(), "approval_request_id", json!(CONTEXT_CANARY)),
            "invalid_params",
        ),
        (
            "issue_malformed_digest",
            "aft",
            changed(
                single.clone(),
                "request_sha256",
                json!(head.statement_b64url),
            ),
            "invalid_params",
        ),
        ("issue_ungranted", "other", single.clone(), "not_found"),
        (
            "issue_wrong_service",
            "aft",
            changed(single.clone(), "service", json!("other")),
            "not_found",
        ),
        (
            "issue_unbound_resource_without_approval",
            "aft",
            changed(params(), "resource", json!("org/unbound")),
            "not_found",
        ),
        (
            "issue_proof_for_no_approval_kind",
            "aft",
            changed(single.clone(), "kind", json!("update_issue_comment")),
            "invalid_params",
        ),
        (
            "issue_unknown_request",
            "aft",
            changed(
                single.clone(),
                "approval_request_id",
                json!("01HF7YAT000000000000000004"),
            ),
            "approval_invalid",
        ),
        (
            "issue_unapproved",
            "plexus",
            worker_first.clone(),
            "approval_invalid",
        ),
        (
            "issue_wrong_caller",
            "plexus",
            single.clone(),
            "approval_invalid",
        ),
        (
            "issue_wrong_identity",
            "aft",
            changed(single.clone(), "identity", json!("github_app:unbound")),
            "approval_invalid",
        ),
        (
            "issue_wrong_kind",
            "aft",
            changed(single.clone(), "kind", json!(CLOSE)),
            "approval_invalid",
        ),
        (
            "issue_wrong_resource",
            "aft",
            changed(single.clone(), "resource", json!("org/s")),
            "approval_invalid",
        ),
        (
            "issue_wrong_digest",
            "aft",
            changed(single.clone(), "request_sha256", json!("f".repeat(64))),
            "approval_invalid",
        ),
    ] {
        samples
            .reserved(name, OP_POLICY_TOKEN, module, params, expected)
            .await;
    }
    samples.at(NOW + TTL);
    samples
        .reserved(
            "issue_expired",
            OP_POLICY_TOKEN,
            "plexus",
            flow_issue.clone(),
            "approval_invalid",
        )
        .await;
    samples.at(NOW);
    let key = SigningKey::from_slice(&[51; 32]).unwrap();
    let bytes = serde_json::to_vec(&envelope(worker, APPROVING_PHONE, NOW)).unwrap();
    let approved = samples
        .phone(
            "approve_phone_three_legs",
            phone_approval_params(&bytes, &key),
            "production",
            Some("pair-A"),
            "",
        )
        .await;
    assert_eq!(approved, approval_reply(worker));
    samples
        .reserved(
            "issue_leg_out_of_order",
            OP_POLICY_TOKEN,
            "plexus",
            worker_second.clone(),
            "approval_invalid",
        )
        .await;
    github.counts(0, 0);
    github
        .exchange_faults
        .lock()
        .unwrap()
        .push_back((503, json!({"message": "fixture provider unavailable"})));
    samples
        .reserved(
            "issue_provider_error",
            OP_POLICY_TOKEN,
            "aft",
            single.clone(),
            "github_unavailable",
        )
        .await;
    samples.rig.sql("CREATE TRIGGER fail_sample_issue BEFORE INSERT ON audit_log WHEN NEW.op = 'broker_action_issue'
                     BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END;");
    samples
        .reserved(
            "issue_store_error",
            OP_POLICY_TOKEN,
            "aft",
            single.clone(),
            "store_error",
        )
        .await;
    samples.rig.sql("DROP TRIGGER fail_sample_issue");
    for (name, module, params, request, issued) in [
        ("issue_one_leg", "aft", single.clone(), head, 1),
        (
            "issue_first_of_three",
            "plexus",
            worker_first.clone(),
            worker,
            1,
        ),
        ("issue_second_of_three", "plexus", worker_second, worker, 2),
        (
            "issue_third_of_three",
            "plexus",
            worker_third.clone(),
            worker,
            3,
        ),
    ] {
        let reply = samples
            .reserved(name, OP_POLICY_TOKEN, module, params, "")
            .await;
        assert!(reply["token"]
            .as_str()
            .unwrap()
            .starts_with("fixture-token-"));
        assert_eq!(issued_legs(&samples.rig, request), issued);
        if name == "issue_first_of_three" {
            samples
                .reserved(
                    "issue_leg_replay",
                    OP_POLICY_TOKEN,
                    "plexus",
                    worker_first.clone(),
                    "approval_invalid",
                )
                .await;
        }
    }
    samples
        .reserved(
            "issue_approval_spent",
            OP_POLICY_TOKEN,
            "aft",
            single,
            "approval_invalid",
        )
        .await;
    samples
        .reserved(
            "issue_three_legs_spent",
            OP_POLICY_TOKEN,
            "plexus",
            worker_third,
            "approval_invalid",
        )
        .await;
    activate_policy_without_approval(&samples.rig);
    samples
        .reserved(
            "issue_policy_changed",
            OP_POLICY_TOKEN,
            "plexus",
            flow_issue.clone(),
            "approval_policy_changed",
        )
        .await;
    samples
        .reserved(
            "issue_old_policy_without_proof",
            OP_POLICY_TOKEN,
            "aft",
            params(),
            "policy_version_not_active",
        )
        .await;
    samples
        .reserved(
            "issue_none_kind",
            OP_POLICY_TOKEN,
            "aft",
            changed(params(), "policy_version", json!(2)),
            "",
        )
        .await;
}

async fn record_change_cases(samples: &mut Samples, github: &Github) {
    let params = changed(params(), "policy_version", json!(2));
    for (name, state) in [
        ("issue_needs_reauth", "needs_reauth"),
        ("issue_retired", "retired"),
    ] {
        samples.rig.sql(&format!(
            "UPDATE credentials SET state = '{state}' WHERE credential_id = '{APP}'"
        ));
        samples
            .reserved(name, OP_POLICY_TOKEN, "aft", params.clone(), "needs_reauth")
            .await;
    }
    samples.rig.sql(&format!(
        "DELETE FROM credentials WHERE credential_id = '{APP}'"
    ));
    samples
        .reserved(
            "issue_deleted_record",
            OP_POLICY_TOKEN,
            "aft",
            params.clone(),
            "not_installed",
        )
        .await;
    samples.rig.store.create(APP, &app_record(None)).unwrap();

    for (name, twice) in [
        ("issue_record_replaced_during_mint", false),
        ("issue_record_changed_twice", true),
    ] {
        replace_record(&samples.rig, false);
        let previous_gets = github.gets.load(Ordering::SeqCst);
        let previous_posts = github.posts.lock().unwrap().len();
        let (posted, release) = github.stall_next_post();
        let second = twice.then(|| github.stall_next_post());
        samples.request_debug(OP_POLICY_TOKEN, &params);
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(Some(samples.clock.load(Ordering::SeqCst)));
        let ingress = Ingress::new(&samples.rig);
        ingress.bind(&samples.rig, 1, "aft");
        ingress
            .dispatch(
                &samples.rig,
                super::request(OP_POLICY_TOKEN, params.clone(), 1, 1),
            )
            .await;
        signal(posted).await;
        replace_record(&samples.rig, false);
        release.send(()).unwrap();
        if let Some((posted_again, release_again)) = second {
            signal(posted_again).await;
            replace_record(&samples.rig, true);
            release_again.send(()).unwrap();
        }
        let response = frame(&mut samples.rig).await;
        secret_phone::BROKER_ACTION_TEST_CLOCK_MS.set(None);
        let result = samples.record(
            name,
            OP_POLICY_TOKEN,
            "reserved:aft",
            params.clone(),
            (response.header.ty, body(&response)),
            if twice { "github_unavailable" } else { "" },
        );
        if !twice {
            assert_eq!(
                result["token"],
                format!("fixture-token-{}", previous_posts + 2)
            );
        }
        github.counts(previous_gets + 2, previous_posts + 2);
    }
}

async fn generate() -> Samples {
    let (rig, github, digest) = setup_actions();
    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    let mut samples = Samples::new(rig);
    let head = samples.mint("mint_head", "aft", head()).await;
    let worker = samples
        .mint("mint_worker_three_legs", "plexus", worker())
        .await;
    let flow = samples.mint("mint_flow_stamp", "plexus", flow()).await;
    mint_refusals(&mut samples).await;
    report_version(&samples.rig, SELF, 41, &digest, GhManifestVerdict::Invalid);
    samples
        .reserved(
            "mint_policy_absent",
            OP_REQUEST_ACTION,
            "aft",
            self::head(),
            "policy_absent",
        )
        .await;
    ready(&samples.rig, SELF, 41, &digest);
    phone_cases(&mut samples, &head).await;
    desktop_cases(&mut samples, &flow).await;
    token_cases(&mut samples, &github, &head, &worker, &flow).await;
    use_remote_home(&samples.rig);
    samples
        .reserved(
            "issue_wrong_serving_role",
            OP_POLICY_TOKEN,
            "plexus",
            issue_params(&flow),
            "not_found",
        )
        .await;
    samples
        .reserved(
            "mint_wrong_serving_role",
            OP_REQUEST_ACTION,
            "aft",
            self::head(),
            "not_found",
        )
        .await;
    samples
        .rig
        .store
        .set_secret_home_audited(Some(SELF), AuditCtx::admin(AuditOp::SecretHomeSet))
        .unwrap();
    record_change_cases(&mut samples, &github).await;
    samples
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/broker-action")
}

#[tokio::test]
async fn broker_action_samples_regenerate_byte_for_byte() {
    let samples = generate().await;
    let pack = json!({"phone_approval_pub_sec1_hex": SigningKey::from_slice(&[51; 32]).unwrap()
        .verifying_key().to_encoded_point(false).as_bytes().iter().fold(String::new(), |mut out, byte| {
            write!(out, "{byte:02x}").unwrap();
            out
        }), "cases": samples.cases});
    let mut cases = serde_json::to_vec_pretty(&pack).unwrap();
    cases.push(b'\n');
    let sums = format!("{:x}  cases.json\n", Sha256::digest(&cases));
    let dir = fixture_path();
    let emit = std::env::var("CK_EMIT_SECRET_VECTORS").as_deref() == Ok("1");
    if emit {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, bytes) in [
        ("cases.json", cases.as_slice()),
        ("SHA256SUMS", sums.as_bytes()),
    ] {
        let path = dir.join(name);
        if emit {
            std::fs::write(&path, bytes).unwrap();
        } else {
            assert!(
                std::fs::read(&path).unwrap() == bytes,
                "{name} differs; regenerate with CK_EMIT_SECRET_VECTORS=1"
            );
        }
    }
}

#[derive(Default, Clone)]
struct Capture(Arc<Mutex<Vec<String>>>);

struct LogFields(String);

impl tracing::field::Visit for LogFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        write!(self.0, " {}={value:?}", field.name()).unwrap();
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut fields = LogFields(attrs.metadata().name().into());
        attrs.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut fields = LogFields(String::new());
        values.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = LogFields(event.metadata().name().into());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn broker_action_samples_canary() {
    const CHILD: &str = "CK_TEST_BROKER_ACTION_CANARY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // A thread-local subscriber misses logs from SQLite's blocking pool.
        // Use a subprocess to give the probe a global subscriber without changing other tests.
        let path = module_path!().split_once("::").unwrap().1;
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("{path}::broker_action_samples_canary"),
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "broker-action canary subprocess failed");
        return;
    }
    let capture = Capture::default();
    tracing::subscriber::set_global_default(capture.clone()).unwrap();
    let samples = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::task::spawn_blocking(|| tracing::info!("broker action blocking log probe"))
                .await
                .unwrap();
            generate().await
        });
    let logs = capture.0.lock().unwrap();
    for expected in [
        "broker action blocking log probe",
        "admitted development desktop approval",
    ] {
        assert!(
            logs.iter().any(|line| line.contains(expected)),
            "missing log capture for {expected}"
        );
    }
    let audit = samples.rig.store.read_audit(None).unwrap();
    for (op, count) in [
        ("broker_action_request", 3),
        ("broker_action_approve", 3),
        ("broker_action_issue", 4),
    ] {
        assert_eq!(
            audit.iter().filter(|row| row.op == op).count(),
            count,
            "{op}"
        );
    }
    let audit_rows = approval_snapshot(&samples.rig).swap_remove(2);
    let mut audit_text = vec![format!("{audit:?} {audit_rows:?}")];
    for row in audit_rows {
        for value in row {
            match value {
                rusqlite::types::Value::Text(text) => audit_text.push(text),
                rusqlite::types::Value::Blob(bytes) => {
                    audit_text.push(String::from_utf8_lossy(&bytes).into_owned())
                }
                _ => (),
            }
        }
    }
    let tokens = [
        FIELD_CANARY,
        NUMBER_CANARY,
        REASON_CANARY,
        CONTEXT_CANARY,
        STAMP_CANARY,
    ];
    for (sink, records) in [
        ("logs", logs.as_slice()),
        ("audit", &audit_text),
        ("error text", &samples.error_text),
        ("Debug", &samples.debug),
    ] {
        assert!(!records.is_empty(), "{sink} was not exercised");
        for (index, needle) in tokens
            .into_iter()
            .chain(samples.statements.iter().map(String::as_str))
            .enumerate()
        {
            let escaped = serde_json::to_string(needle).unwrap();
            let escaped = &escaped[1..escaped.len() - 1];
            assert!(
                !records
                    .iter()
                    .any(|record| record.contains(needle) || record.contains(escaped)),
                "{sink} leaked broker-action canary {index}"
            );
        }
    }
}
