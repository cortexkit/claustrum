use super::*;

fn fields(params: &Value) -> Value {
    let mut fields = serde_json::Map::new();
    for key in ["host", "path_prefix", "origin", "rules", "origins"] {
        if let Some(value) = params.get(key) {
            fields.insert(key.into(), value.clone());
        }
    }
    Value::Object(fields)
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vector_material(case: &Value) -> SecretMaterial {
    let material = &case["material"];
    if let Some(hex) = material["api_key_hex"].as_str() {
        SecretMaterial::ApiKey(Secret::new(unhex(hex)))
    } else {
        SecretMaterial::SiteLogin {
            username: Secret::new(material["username"].as_str().unwrap().into()),
            password: Secret::new(material["password"].as_str().unwrap().into()),
            otpauth: material["otpauth"]
                .as_str()
                .map(|uri| Secret::new(uri.into())),
        }
    }
}

fn vector_deposit(store: &EncryptedStore, sender: &str, case: &Value) -> PhoneDeposit {
    let params = &case["params"];
    let scope = SecretScope::from_input(
        params["kind"].as_str().unwrap(),
        &fields(params),
        params["location"].as_str(),
    )
    .unwrap();
    let material = vector_material(case);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let deposit = sealed_deposit(
        store,
        sender,
        params["name"].as_str().unwrap(),
        params["deposit_id"].as_str().unwrap(),
        scope,
        &material,
    );
    if let Some(expected) = case.get("aad_hex") {
        assert_eq!(
            json!(hex(&agent_secret::deposit_aad(
                &deposit.deposit_id,
                &deposit.member_id,
                &deposit.name,
                &deposit.scope
            )
            .unwrap())),
            *expected,
            "{} AAD",
            case["case"]
        );
    }
    assert_eq!(
        json!(hex(agent_secret::deposit_plaintext(&material).expose())),
        case["plaintext_hex"],
        "{} plaintext",
        case["case"]
    );
    assert_eq!(
        json!(hex(agent_secret::sealed_body(&deposit.scope, &material)
            .unwrap()
            .expose())),
        case["sealed_body_hex"],
        "{} body",
        case["case"]
    );
    assert_eq!(
        json!(agent_secret::SECRET_RECORD_VERSION),
        case["record_version"]
    );
    deposit
}

fn writes(store: &EncryptedStore) -> Value {
    json!({
        "agent_secrets":count(store,"SELECT count(*) FROM agent_secrets"),
        "tombstones":count(store,"SELECT count(*) FROM secret_deposit_tombstones"),
        "secret_store_audits":count(store,"SELECT count(*) FROM audit_log WHERE op='secret_store'"),
    })
}

fn assert_error(result: Result<Value, SecretError>, expected: &Value, label: &str) {
    let error = result.unwrap_err();
    if expected.get("error").is_some() {
        assert_eq!(error.body()["error"], expected["error"], "{label}");
    } else {
        assert_eq!(json!(error.code()), expected["code"], "{label}");
    }
}

fn check_wrong_body_version(store: &EncryptedStore, case: &Value) {
    let extended = case["setup"]["scope_json_nonnull"].as_bool().unwrap();
    let scope = if extended {
        let raw = r#"[{"host":"*.x.test","path_prefix":""}]"#;
        store_scope_json(store, "key", "agent_api_key", raw);
        SecretScope::from_scope_json("agent_api_key", Some(LOCATION), raw).unwrap()
    } else {
        let scope = scope();
        seed(store, "key", &scope, &material("agent_api_key"));
        scope
    };
    let incarnation: String = store
        .store
        .with_conn(|conn| {
            conn.query_row(
                "SELECT incarnation FROM agent_secrets WHERE name='key'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    let mut body = agent_secret::sealed_body(&scope, &material("agent_api_key"))
        .unwrap()
        .into_inner();
    let mut tag = vec![];
    let version = case["setup"]["sealed_body_version"].as_u64().unwrap();
    agent_secret::push_field(
        &mut tag,
        match version {
            1 => agent_secret::SEALED_BODY_TAG,
            2 => agent_secret::SEALED_BODY_V2_TAG,
            _ => panic!("unknown body version"),
        },
    );
    body[..tag.len()].copy_from_slice(&tag);
    let id = agent_secret::record_binding("agent_api_key", &incarnation, "key").unwrap();
    let blob = envelope::seal(
        &store.key,
        &body,
        &RecordBinding {
            credential_id: &id,
            record_version: agent_secret::SECRET_RECORD_VERSION,
        },
    )
    .unwrap();
    store
        .fenced_write(|tx| {
            tx.execute(
                "UPDATE agent_secrets SET envelope=?1 WHERE name='key'",
                [blob],
            )
        })
        .unwrap();
    assert_eq!(case["setup"]["live_grant"], true);
    grant(store, "g", "permanent", 0, NOW);
    store
        .store
        .with_conn(|conn| {
            let checked =
                store.check_secret_target(conn, "key", SecretSender::Basal, &call().target)?;
            assert_eq!(
                json!(
                    checked
                        .err()
                        .expect("wrong body version must refuse")
                        .detail
                ),
                case["expect"]["code"],
                "{}",
                case["case"]
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(use_reply(store, &call(), NOW)["error"]["code"], "not_found");
}

#[test]
fn conformance_every_deposit_vector_reproduces_encoding_validation_gate_or_use_outcome() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../tests/vectors/multi-host/secret-deposit-v2.json"
    ))
    .unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    let mut checked = [0; 3];
    for case in cases {
        let label = case["case"].as_str().unwrap();
        let (_root, store, sender) = conformance_setup(label);
        let params = &case["params"];
        let expected = &case["expect"];
        if case["operation"] == "secret.use" {
            checked[2] += 1;
            check_wrong_body_version(&store, case);
            continue;
        }
        let kind = params["kind"].as_str().unwrap();
        let scope_fields = fields(params);
        let location = params["location"].as_str();
        let deposit = if case["operation"] == "secret.deposit" {
            checked[0] += 1;
            // Scope-shape failures happen before the typed phone operation exists.
            if let Err(error) = SecretScope::from_input(kind, &scope_fields, location) {
                assert_error(Err(error.into()), expected, label);
                assert_eq!(
                    writes(&store),
                    json!({"agent_secrets":0,"tombstones":0,"secret_store_audits":0})
                );
                continue;
            }
            let deposit = vector_deposit(&store, &sender, case);
            if let Some(previous) = case["setup"]["tombstone_from_case"].as_str() {
                let previous = cases.iter().find(|case| case["case"] == previous).unwrap();
                let previous = vector_deposit(&store, &sender, previous);
                assert_eq!(
                    phone(&store, &PhoneOperation::Deposit(previous)).unwrap()["status"],
                    "stored"
                );
            } else if case["setup"]["tombstone"].is_string() {
                assert_eq!(
                    phone(&store, &PhoneOperation::Deposit(deposit.clone())).unwrap()["status"],
                    "stored"
                );
            }
            Some(deposit)
        } else {
            assert_eq!(case["operation"], "admin.secret_put", "{label}");
            checked[1] += 1;
            None
        };
        store.store.with_conn(|conn| {
            conn.execute("DELETE FROM settings WHERE name='secret.multi_host'",[])?;
            if let Some(gate) = case["setup"]["secret.multi_host"].as_str() {
                conn.execute("INSERT INTO settings(name,value,updated_at_ms) VALUES ('secret.multi_host',?1,0)",[gate])?;
            }
            Ok(())
        }).unwrap();
        let result = if let Some(deposit) = deposit {
            phone(&store, &PhoneOperation::Deposit(deposit))
        } else {
            match store.secret_put_audited(
                &put(
                    params["name"].as_str().unwrap(),
                    kind,
                    &scope_fields,
                    location,
                ),
                "test",
            ) {
                Ok(value) => Ok(value),
                Err(error) => {
                    let code = expected["error"]["code"]
                        .as_str()
                        .or_else(|| expected["code"].as_str())
                        .unwrap();
                    assert_put_refusal(error, code, label);
                    assert_eq!(writes(&store), expected["writes"], "{label}");
                    continue;
                }
            }
        };
        if expected.get("error").is_some() || expected.get("code").is_some() {
            assert_error(result, expected, label);
            if let Some(expected) = expected.get("writes") {
                assert_eq!(writes(&store), *expected, "{label}");
            }
        } else {
            let result = result.unwrap();
            assert_eq!(
                result["status"],
                expected.get("status").cloned().unwrap_or(json!("stored")),
                "{label}"
            );
            if let Some(scope) = expected.get("stored_scope") {
                let listed = phone(&store, &PhoneOperation::List).unwrap();
                let row = &listed["secrets"][0];
                for (key, value) in scope.as_object().unwrap() {
                    assert_eq!(row[key], *value, "{label}: {key}");
                }
                if let Some(version) = expected.get("statement_v") {
                    let mut call = call();
                    call.name = params["name"].as_str().unwrap().into();
                    call.sender = if kind == "agent_api_key" {
                        SecretSender::Aft
                    } else {
                        SecretSender::Cerebellum
                    };
                    call.target = targets_for(scope).remove(0);
                    let pending = use_reply(&store, &call, NOW);
                    assert_eq!(pending["status"], "approval_required", "{label}: {pending}");
                    let bytes = URL_SAFE_NO_PAD
                        .decode(pending["statement_b64url"].as_str().unwrap())
                        .unwrap();
                    let statement: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(statement["v"], *version, "{label}");
                    assert_eq!(statement["use"], *scope, "{label}");
                }
            }
        }
    }
    assert_eq!(
        checked,
        [30, 4, 2],
        "every deposit corpus record must be exercised"
    );
}
