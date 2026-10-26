// Flow boundary tests share the registered-phone and deposit harness with the
// agent contract tests, without changing the existing agent golden requests.

fn sf_identity() -> serde_json::Value {
    json!({"flow_id":"daily-fetch", "version":7, "code_hash":"0123456789abcdef".repeat(4), "install_id":"install-A"})
}

fn sf_run(login: bool) -> serde_json::Value {
    let mut request = secret_golden(if login {
        "use.request.site_login"
    } else {
        "use.request.api_key"
    });
    request.as_object_mut().unwrap().remove("coverage");
    let flow = sf_identity();
    for (attribute, field) in [
        ("flow_id", "flow_id"),
        ("flow_version", "version"),
        ("flow_code_hash", "code_hash"),
        ("flow_install_id", "install_id"),
    ] {
        request["stamp"]["attributes"][attribute] = flow[field].clone();
    }
    if !login {
        request["method"] = json!("GET");
    }
    request
}

fn sf_install(login: bool) -> serde_json::Value {
    let run = sf_run(login);
    let mut request = json!({"name":run["name"], "flow":sf_identity(), "target":run["target"]});
    if !login {
        request["methods"] = json!(["GET"]);
    }
    request
}

fn sf_request(flow: &SecretFlow, params: &serde_json::Value) -> serde_json::Value {
    sc_use_answer(crate::secret_use::serve_flow_approval(
        &flow.store,
        Some(&reserved("basal")),
        params,
        sc_now_ms,
    ))
}

fn sf_revoke(flow: &SecretFlow, params: &serde_json::Value) -> serde_json::Value {
    sc_use_answer(crate::secret_use::serve_revoke_flow_grants(
        &flow.store,
        Some(&reserved("basal")),
        params,
    ))
}

fn sf_pending(flow: &SecretFlow) -> i64 {
    rusqlite::Connection::open_with_flags(
        flow._root.join("store.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row("SELECT COUNT(*) FROM secret_pending_requests", [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn sf_refusal(flow: &SecretFlow, request: &serde_json::Value, detail: &str) {
    let reply = flow.use_secret("basal", request);
    assert_eq!(
        serde_json::to_vec(&reply).unwrap(),
        serde_json::to_vec(&json!({"error":{"code":"not_found", "class":"permanent"}})).unwrap()
    );
    let events = flow.store.recent_auth_events(1).unwrap();
    assert_eq!(events[0].detail.as_deref(), Some(detail));
    assert_eq!(events[0].principal_id.as_deref(), Some("basal"));
}

#[tokio::test]
async fn secret_flow_sender_admission_precedes_parsing_and_diagnostics() {
    let flow = SecretFlow::new(216).await;
    for principal in [
        None,
        Some(subc_protocol::Principal::Direct),
        Some(subc_protocol::Principal::Unverified),
        Some(reserved("aft")),
        Some(reserved("cerebellum")),
        Some(reserved("callosum")),
        Some(reserved("prefrontal-core")),
        Some(reserved("cingulate")),
        Some(reserved("harness:basal")),
    ] {
        for params in [json!({}), sf_install(false)] {
            assert_eq!(
                sc_use_answer(crate::secret_use::serve_flow_approval(
                    &flow.store,
                    principal.as_ref(),
                    &params,
                    sc_now_ms
                )),
                json!({"error":{"code":"not_found", "class":"permanent"}})
            );
        }
        for params in [json!({}), json!({"flow_install_id":"install-A"})] {
            assert_eq!(
                sc_use_answer(crate::secret_use::serve_revoke_flow_grants(
                    &flow.store,
                    principal.as_ref(),
                    &params
                )),
                json!({"error":{"code":"not_found", "class":"permanent"}})
            );
        }
    }
    assert_eq!(sf_pending(&flow), 0);
    assert!(flow.store.recent_auth_events(100).unwrap().is_empty());
}

#[tokio::test]
async fn secret_flow_methods_are_validated_against_target_before_lookup() {
    let flow = SecretFlow::new(217).await;
    flow.deposit_both().await;
    let invalid = json!({"transport":"invalid_params"});
    for name in [sf_run(false)["name"].as_str().unwrap(), "unknown"] {
        for method in [
            None,
            Some(json!(null)),
            Some(json!("get")),
            Some(json!("")),
            Some(json!("A".repeat(17))),
            Some(json!(["GET"])),
        ] {
            let mut request = sf_run(false);
            request["name"] = json!(name);
            match method {
                Some(value) => {
                    request["method"] = value;
                }
                None => {
                    request.as_object_mut().unwrap().remove("method");
                }
            }
            assert_eq!(flow.use_secret("basal", &request), invalid, "{request}");
        }
        for methods in [
            None,
            Some(json!(null)),
            Some(json!([])),
            Some(json!(["GET", "GET"])),
            Some(json!(["get"])),
            Some(json!([""])),
            Some(json!(["A".repeat(17)])),
            Some(json!("GET")),
        ] {
            let mut request = sf_install(false);
            request["name"] = json!(name);
            match methods {
                Some(value) => {
                    request["methods"] = value;
                }
                None => {
                    request.as_object_mut().unwrap().remove("methods");
                }
            }
            assert_eq!(sf_request(&flow, &request), invalid, "{request}");
        }
        for value in [json!(null), json!([]), json!(["GET"]), json!("GET")] {
            let mut request = sf_install(true);
            request["name"] = json!(name);
            request["methods"] = value.clone();
            assert_eq!(sf_request(&flow, &request), invalid);
            let mut request = sf_run(true);
            request["name"] = json!(name);
            request["method"] = value;
            assert_eq!(flow.use_secret("basal", &request), invalid);
        }
        let mut request = sf_install(true);
        request["name"] = json!(name);
        assert_eq!(
            sf_request(&flow, &request),
            json!({"error":{"code":"not_found", "class":"permanent"}})
        );
        let mut request = sf_run(true);
        request["name"] = json!(name);
        assert_eq!(
            flow.use_secret("basal", &request),
            json!({"error":{"code":"not_found", "class":"permanent"}})
        );
    }
    for (operation, key) in [
        ("request", "method"),
        ("use", "methods"),
        ("use", "coverage"),
        ("use", "flow"),
    ] {
        let mut request = if operation == "request" {
            sf_install(false)
        } else {
            sf_run(false)
        };
        request[key] = json!("scope");
        assert_eq!(
            if operation == "request" {
                sf_request(&flow, &request)
            } else {
                flow.use_secret("basal", &request)
            },
            invalid
        );
    }
    for version in [
        json!(0),
        json!(9_007_199_254_740_992u64),
        json!(-1),
        json!(1.5),
        json!("7"),
    ] {
        let mut request = sf_install(false);
        request["flow"]["version"] = version;
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    let mut request = sf_run(false);
    request["stamp"]["attributes"]["flow_version"] = json!(9_007_199_254_740_992u64);
    assert_eq!(flow.use_secret("basal", &request), invalid);
    assert_eq!(sf_pending(&flow), 0);
}

#[tokio::test]
async fn secret_flow_release_refusals_are_uniform_and_never_create_pending_rows() {
    let flow = SecretFlow::new(218).await;
    flow.deposit_both().await;
    sf_refusal(&flow, &sf_run(false), "flow_no_grant");
    sf_refusal(&flow, &sf_run(true), "flow_no_grant");
    assert_eq!(sf_pending(&flow), 0);
    for login in [false, true] {
        let request = sf_request(&flow, &sf_install(login));
        assert_eq!(request["status"], "approval_required");
        assert_eq!(sf_request(&flow, &sf_install(login)), request);
        let approved = flow.approve(&request, "version", false).await;
        assert_eq!(approved["results"][0]["outcome"], "granted");
    }
    let pending = sf_pending(&flow);
    for _ in 0..3 {
        for login in [false, true] {
            let released = flow.use_secret("basal", &sf_run(login));
            assert_eq!(released["status"], "released", "{released}");
            assert_secret_reply_matches(
                if login {
                    "use.result.released.site_login"
                } else {
                    "use.result.released.api_key"
                },
                &released,
            );
        }
    }
    let mut request = sf_run(false);
    request["method"] = json!("POST");
    sf_refusal(&flow, &request, "flow_method");
    for (key, value) in [
        ("flow_id", json!("another-flow")),
        ("flow_version", json!(8)),
        ("flow_code_hash", json!("f".repeat(64))),
        ("flow_install_id", json!("another-install")),
    ] {
        let mut request = sf_run(false);
        request["stamp"]["attributes"][key] = value;
        sf_refusal(&flow, &request, "flow_no_grant");
    }
    for key in [
        "flow_id",
        "flow_version",
        "flow_code_hash",
        "flow_install_id",
    ] {
        let mut request = sf_run(false);
        request["stamp"]["attributes"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        sf_refusal(&flow, &request, "flow_identity");
        let events = flow.store.recent_auth_events(1).unwrap();
        assert_eq!(events[0].credential_id, "secret-use|unaddressed");
        assert!(!format!("{events:?}").contains("daily-fetch"));
        assert!(!format!("{events:?}").contains("install-A"));
    }
    let mut request = sf_run(false);
    request["stamp"] = secret_golden("use.request.api_key")["stamp"].clone();
    sf_refusal(&flow, &request, "flow_identity");
    let mut request = sf_run(false);
    request["name"] = json!("unknown");
    sf_refusal(&flow, &request, "unknown_name");
    let mut request = sf_run(true);
    request["name"] = sf_run(false)["name"].clone();
    sf_refusal(&flow, &request, "target");
    let mut request = sf_run(false);
    request["target"]["host"] = json!("wrong.example");
    sf_refusal(&flow, &request, "target");
    let mut request = sf_run(false);
    request["stamp"]["attributes"]["flow_install_id"] = json!("");
    sf_refusal(&flow, &request, "flow_identity");
    let mut request = sf_run(false);
    request["target"]["path"] = json!(format!(
        "{}/second",
        request["target"]["path"]
            .as_str()
            .unwrap()
            .trim_end_matches('/')
    ));
    assert_eq!(flow.use_secret("basal", &request)["status"], "released");
    assert_eq!(sf_pending(&flow), pending);
}

#[tokio::test]
async fn secret_flow_and_agent_grants_never_satisfy_each_other() {
    let flow = SecretFlow::new(219).await;
    flow.deposit_both().await;
    let request = sf_request(&flow, &sf_install(false));
    assert_eq!(
        flow.approve(&request, "version", false).await["results"][0]["outcome"],
        "granted"
    );
    let agent = secret_golden("use.request.api_key");
    let agent_request = flow.use_secret("aft", &agent);
    assert_eq!(agent_request["status"], "approval_required");
    assert_ne!(agent_request["request_id"], request["request_id"]);
    assert_eq!(
        flow.approve(&agent_request, "permanent", false).await["results"][0]["outcome"],
        "granted"
    );
    assert_eq!(
        sf_revoke(
            &flow,
            &json!({"flow_install_id":"install-A", "flow_version":8})
        ),
        json!({"status":"revoked", "grants":0})
    );
    assert_eq!(
        flow.use_secret("basal", &sf_run(false))["status"],
        "released"
    );
    assert_eq!(
        sf_revoke(
            &flow,
            &json!({"flow_install_id":"install-A", "flow_version":7})
        ),
        json!({"status":"revoked", "grants":1})
    );
    let pending = sf_pending(&flow);
    sf_refusal(&flow, &sf_run(false), "flow_no_grant");
    assert_eq!(flow.use_secret("aft", &agent)["status"], "released");
    let mut head = sf_run(false);
    head["stamp"] = agent["stamp"].clone();
    sf_refusal(&flow, &head, "flow_identity");
    assert_eq!(sf_pending(&flow), pending);
    let request = sf_request(&flow, &sf_install(false));
    assert_eq!(
        flow.approve(&request, "version", false).await["results"][0]["outcome"],
        "granted"
    );
    assert_eq!(
        sf_revoke(&flow, &json!({"flow_install_id":"install-A"})),
        json!({"status":"revoked", "grants":1})
    );
    assert_eq!(
        sf_revoke(&flow, &json!({"flow_install_id":"install-A"})),
        json!({"status":"revoked", "grants":0})
    );
}

#[tokio::test]
async fn secret_flow_stamps_preserve_the_agent_closed_key_set_and_goldens() {
    let flow = SecretFlow::new(220).await;
    flow.deposit_both().await;
    for (sender, login) in [("aft", false), ("cerebellum", true)] {
        let golden = secret_golden(if login {
            "use.request.site_login"
        } else {
            "use.request.api_key"
        });
        let request = flow.use_secret(sender, &golden);
        assert_eq!(request["status"], "approval_required");
        assert_eq!(
            flow.approve(&request, "permanent", false).await["results"][0]["outcome"],
            "granted"
        );
        assert_eq!(flow.use_secret(sender, &golden)["status"], "released");
        let mut stamped = golden.clone();
        stamped["stamp"] = sf_run(login)["stamp"].clone();
        let pending = sf_pending(&flow);
        assert_eq!(
            flow.use_secret(sender, &stamped),
            json!({"error":{"code":"not_found", "class":"permanent"}})
        );
        stamped["method"] = json!("GET");
        assert_eq!(
            flow.use_secret(sender, &stamped),
            json!({"transport":"invalid_params"})
        );
        let mut with_method = golden.clone();
        with_method["method"] = json!("GET");
        assert_eq!(
            flow.use_secret(sender, &with_method),
            json!({"transport":"invalid_params"})
        );
        assert_eq!(sf_pending(&flow), pending);
    }
}

#[tokio::test]
async fn secret_flow_ops_dispatch_only_for_basal_and_revoke_params_are_closed() {
    use federation::RouteCaller;
    let seed = 221;
    let (surface, store, db_path, _root) = tmp_surface_with_store(seed);
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    let engine = Arc::new(RefreshEngine::new(
        Arc::clone(&store),
        Vec::new(),
        Arc::new(crate::test_support::NoHttp),
    ));
    let admin = Arc::new(admin_surface::AdminSurface::new(
        engine,
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        credentials_core::vault_id_for(db_path.parent().unwrap()).unwrap(),
        key.key_id(),
    ));
    let expected = serde_json::to_vec(&uniform_not_found()).unwrap();
    for caller in [
        RouteCaller::Principal(None),
        RouteCaller::Principal(Some(subc_protocol::Principal::Direct)),
        RouteCaller::Principal(Some(subc_protocol::Principal::Unverified)),
        RouteCaller::Principal(Some(reserved("aft"))),
        RouteCaller::Principal(Some(reserved("cerebellum"))),
        RouteCaller::Principal(Some(reserved("cingulate"))),
        RouteCaller::Principal(Some(reserved("callosum"))),
        RouteCaller::Principal(Some(reserved("prefrontal-core"))),
        RouteCaller::Phone(SC_FP.into()),
        RouteCaller::Member(SC_MEMBER.into()),
        RouteCaller::Refused,
    ] {
        for method in ["secret.request_flow_approval", "secret.revoke_flow_grants"] {
            let reply = sc_dispatch(&surface, &admin, caller.clone(), method, json!({})).await;
            assert_eq!(
                reply,
                (FrameType::Response, expected.clone()),
                "{caller:?} {method}"
            );
        }
    }
    assert!(store.recent_auth_events(100).unwrap().is_empty());
    let basal = RouteCaller::Principal(Some(reserved("basal")));
    for method in [
        "secret.use",
        "secret.request_flow_approval",
        "secret.revoke_flow_grants",
    ] {
        let (kind, bytes) = sc_dispatch(&surface, &admin, basal.clone(), method, json!({})).await;
        assert_eq!(kind, FrameType::Error);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "invalid_params"
        );
    }
    let reply = sc_dispatch(
        &surface,
        &admin,
        basal.clone(),
        "secret.request_flow_approval",
        sf_install(false),
    )
    .await;
    assert_eq!(reply, (FrameType::Response, expected));
    assert_eq!(
        store.recent_auth_events(1).unwrap()[0].detail.as_deref(),
        Some("unknown_name")
    );
    for params in [
        json!({"flow_install_id":"install-A"}),
        json!({"flow_install_id":"install-A", "flow_version":7}),
    ] {
        let (kind, bytes) = sc_dispatch(
            &surface,
            &admin,
            basal.clone(),
            "secret.revoke_flow_grants",
            params,
        )
        .await;
        assert_eq!(kind, FrameType::Response);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            wrap_result(json!({"status":"revoked", "grants":0}))
        );
    }
    for params in [
        json!({}),
        json!({"flow_install_id":""}),
        json!({"flow_install_id":"x".repeat(257)}),
        json!({"flow_install_id":"bad\n"}),
        json!({"flow_install_id":"é"}),
        json!({"flow_install_id":"install-A", "flow_version":null}),
        json!({"flow_install_id":"install-A", "flow_version":0}),
        json!({"flow_install_id":"install-A", "flow_version":9_007_199_254_740_992u64}),
        json!({"flow_install_id":"install-A", "flow_version":"7"}),
        json!({"flow_install_id":"install-A", "extra":true}),
    ] {
        let (kind, bytes) = sc_dispatch(
            &surface,
            &admin,
            basal.clone(),
            "secret.revoke_flow_grants",
            params.clone(),
        )
        .await;
        assert_eq!(kind, FrameType::Error, "{params}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "invalid_params"
        );
    }
}

#[tokio::test]
async fn secret_flow_install_errors_and_closed_shapes_do_not_create_pending_rows() {
    let flow = SecretFlow::new(222).await;
    flow.deposit_both().await;
    let invalid = json!({"transport":"invalid_params"});
    for key in ["name", "flow", "target", "methods"] {
        let mut request = sf_install(false);
        request.as_object_mut().unwrap().remove(key);
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    for key in ["name", "stamp", "target", "method"] {
        let mut request = sf_run(false);
        request.as_object_mut().unwrap().remove(key);
        assert_eq!(flow.use_secret("basal", &request), invalid);
    }
    for key in ["flow_id", "version", "code_hash", "install_id"] {
        let mut request = sf_install(false);
        request["flow"].as_object_mut().unwrap().remove(key);
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    let mut request = sf_install(false);
    request["flow"]["extra"] = json!(true);
    assert_eq!(sf_request(&flow, &request), invalid);
    for key in ["extra", "stamp", "coverage"] {
        let mut request = sf_install(false);
        request[key] = json!(true);
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    let mut request = sf_install(false);
    request["name"] = json!("a".repeat(65));
    assert_eq!(
        sf_request(&flow, &request),
        json!({"error":{"code":"limit_exceeded", "class":"context_overflow"}})
    );
    let conn = rusqlite::Connection::open(flow._root.join("store.db")).unwrap();
    conn.execute(
        "DELETE FROM settings WHERE name='federation.self_member'",
        [],
    )
    .unwrap();
    assert_eq!(
        sf_request(&flow, &sf_install(false)),
        json!({"error":{"code":"secret_setup_incomplete", "class":"permanent"}})
    );
    assert_eq!(sf_pending(&flow), 0);
    flow.store
        .set_federation_self_member_audited(SC_MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    conn.execute_batch("CREATE TRIGGER fail_flow_pending BEFORE INSERT ON secret_pending_requests BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(
        sf_request(&flow, &sf_install(false)),
        json!({"error":{"code":"store_error", "class":"transient"}})
    );
    assert_eq!(sf_pending(&flow), 0);
    conn.execute_batch("DROP TRIGGER fail_flow_pending")
        .unwrap();
    let mut request = sf_install(false);
    request["methods"] = json!(["POST", "GET"]);
    let pending = sf_request(&flow, &request);
    assert_eq!(pending["status"], "approval_required");
    let statement: serde_json::Value =
        serde_json::from_slice(&sc_unb64(pending["statement_b64url"].as_str().unwrap())).unwrap();
    assert_eq!(statement["use"]["methods"], json!(["GET", "POST"]));
    request["methods"] = json!(["GET", "POST"]);
    assert_eq!(sf_request(&flow, &request), pending);
}

/// A second install of the same flow version: its grants differ only in `install_id`.
fn sf_other_install() -> serde_json::Value {
    let mut install = sf_install(false);
    install["flow"]["install_id"] = json!("install-B");
    install
}

async fn sf_approve(flow: &SecretFlow, request: &serde_json::Value) {
    let reply = sf_request(flow, request);
    assert_eq!(reply["status"], "approval_required", "{reply}");
    let approved = flow.approve(&reply, "version", false).await;
    assert_eq!(approved["results"][0]["outcome"], "granted", "{approved}");
}

#[tokio::test]
async fn secret_flow_grants_list_with_flow_holders_and_revoke_one_at_a_time() {
    let seed = 223;
    let flow = SecretFlow::new(seed).await;
    flow.deposit_both().await;
    sf_approve(&flow, &sf_install(false)).await;
    sf_approve(&flow, &sf_other_install()).await;
    sf_approve(&flow, &sf_install(true)).await;
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    let mac = credentials_core::admin_auth::AdminMacKey::derive(&key);
    let engine = Arc::new(RefreshEngine::new(
        Arc::clone(&flow.store),
        Vec::new(),
        Arc::new(crate::test_support::NoHttp),
    ));
    let db = flow._root.join("store.db");
    let vault_id = credentials_core::vault_id_for(db.parent().unwrap()).unwrap();
    let admin =
        admin_surface::AdminSurface::new(engine, mac, vault_id.clone(), key.key_id());

    // The provider surface: one row per installed version, no expiry, no agent, and the
    // approved methods only where the secret has methods at all.
    let listed = admin
        .serve_permissions("permissions.list", &json!({}), "test")
        .unwrap();
    let rows = listed["grants"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{listed}");
    for row in rows {
        assert_eq!(row["holder"]["kind"], "flow");
        assert_eq!(row["holder"]["flow_id"], "daily-fetch");
        assert_eq!(row["holder"]["flow_version"], 7);
        assert!(row.get("expires_at_ms").is_none(), "{row}");
        assert!(row.get("agent_id").is_none(), "{row}");
        if row["scope"] == "api_key" {
            assert_eq!(row["methods"], json!(["GET"]), "{row}");
        } else {
            assert!(row.get("methods").is_none(), "{row}");
        }
    }
    let installs: Vec<&str> = rows
        .iter()
        .map(|row| row["holder"]["flow_install_id"].as_str().unwrap())
        .collect();
    assert!(installs.contains(&"install-A") && installs.contains(&"install-B"));
    // An agent-filtered listing never contains a flow grant, and it is the only reason
    // the two installs are distinguishable here: they share flow id and version.
    assert_eq!(
        admin
            .serve_permissions("permissions.list", &json!({"agent_id":"agent-A"}), "test")
            .unwrap(),
        json!({"grants":[]})
    );
    let ids: std::collections::BTreeSet<&str> = rows
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 3, "{listed}");

    // The phone surface: the same grants under the secret, with `flow` and duration
    // `version` in place of an asking scope and coverage.
    let phone = flow.phone("secret.list", json!({})).await;
    let key_secret = phone["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|secret| secret["kind"] == "agent_api_key")
        .unwrap();
    let flow_rows = key_secret["flow_grants"].as_array().unwrap();
    assert_eq!(flow_rows.len(), 2, "{phone}");
    for row in flow_rows {
        assert_eq!(row["duration"], "version");
        assert_eq!(row["flow"]["flow_id"], "daily-fetch");
        assert_eq!(row["flow"]["version"], 7);
        assert_eq!(row["methods"], json!(["GET"]), "{row}");
        assert!(
            row.get("scope").is_none() && row.get("coverage").is_none(),
            "{row}"
        );
        assert!(row.get("expires_at_ms").is_none(), "{row}");
        assert!(row.get("agent_id").is_none(), "{row}");
    }
    let login_secret = phone["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|secret| secret["kind"] == "site_login")
        .unwrap();
    let login_row = &login_secret["flow_grants"][0];
    assert_eq!(login_row["duration"], "version");
    assert_eq!(login_row["flow"]["install_id"], "install-A");
    assert!(login_row.get("methods").is_none(), "{login_row}");

    // Revoking one of two grants that share flow id and version leaves the other install
    // releasing, and the login's own grant untouched. Both revokes go through the
    // operator's single-grant delete by id.
    let listed = admin
        .serve_permissions("permissions.list", &json!({}), "test")
        .unwrap();
    let rows = listed["grants"].as_array().unwrap();
    let id_of = |install: &str, scope: &str| -> String {
        rows.iter()
            .find(|row| row["holder"]["flow_install_id"] == install && row["scope"] == scope)
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .unwrap_or_else(|| panic!("no {scope} grant for {install}"))
    };
    let (api_a, api_b, login_a) = (
        id_of("install-A", "api_key"),
        id_of("install-B", "api_key"),
        id_of("install-A", "site_login"),
    );
    // Revoke over a bind whose principal is the operator: only a direct bind may run an
    // admin op, and the path is the same MAC-authenticated one `ck auth secret revoke`
    // takes through the daemon.
    admin.record_bind(7, subc_protocol::Principal::Direct);
    let revoke = |id: String| {
        let body = serde_json::to_vec(&json!({"op":"permissions.revoke","v":1,"id":id})).unwrap();
        let admin_surface::AdminOutcome::Challenge { nonce_hex, .. } = admin.challenge(7) else {
            panic!("challenge refused");
        };
        let nonce: [u8; credentials_core::admin_auth::ADMIN_NONCE_LEN] =
            sc_unhex(&nonce_hex).try_into().expect("nonce length");
        let tag = sc_hex(
            &credentials_core::admin_auth::AdminMacKey::derive(&key).sign(
                &credentials_core::admin_auth::TranscriptParts {
                    vault_id: &vault_id,
                    key_id: key.key_id(),
                    nonce: &nonce,
                    op_body: &body,
                },
            ),
        );
        (body, tag)
    };
    let (body, tag) = revoke(api_a);
    assert!(
        matches!(
            admin.execute(7, &body, &tag).await,
            admin_surface::AdminOutcome::Ok(_)
        ),
        "the operator's MAC-authenticated revoke is served"
    );
    // Only the other install's grant survives, so a run stamped with it still releases
    // while one stamped with the revoked install is refused.
    let mut other_install = sf_run(false);
    other_install["stamp"]["attributes"]["flow_install_id"] = json!("install-B");
    assert_eq!(
        flow.use_secret("basal", &other_install)["status"],
        "released"
    );
    sf_refusal(&flow, &sf_run(false), "flow_no_grant");
    // The same single-grant delete, this time for the login's grant.
    let (body, tag) = revoke(login_a);
    assert!(
        matches!(
            admin.execute(7, &body, &tag).await,
            admin_surface::AdminOutcome::Ok(_)
        ),
        "the operator's MAC-authenticated revoke is served"
    );
    sf_refusal(&flow, &sf_run(true), "flow_no_grant");
    // The other install's API-key grant is the only one left, and revoking the login's
    // never touched it.
    assert_eq!(
        flow.use_secret("basal", &other_install)["status"],
        "released"
    );
    let remaining = admin
        .serve_permissions("permissions.list", &json!({}), "test")
        .unwrap();
    assert_eq!(remaining["grants"].as_array().unwrap().len(), 1, "{remaining}");
    assert_eq!(remaining["grants"][0]["id"], json!(api_b));
}
