use super::*;
use crate::module_secret::{self as wire, ModuleSecretError};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use subc_protocol::peer::{CallerAttestation, CallerClaim, CallerOrigin};

fn attestation(claim: CallerClaim, first_party: bool) -> CallerAttestation {
    CallerAttestation::new("module-secret-test", 1, 1, claim, first_party, CallerOrigin::Release, "approved").unwrap()
}

fn caller(module: &str) -> federation::RouteCaller {
    let mut caller = federation::ingress::ScopedCaller::hand_only(Some(reserved(module)));
    caller.attestation = Some(attestation(CallerClaim::Own, false));
    federation::RouteCaller::Principal(caller)
}

async fn frame(
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    caller: federation::RouteCaller,
    method: &str,
    params: serde_json::Value,
) -> Frame {
    let (writer, mut responses) = mpsc::channel(1);
    let request = Frame::build_with_version(
        PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false),
        51, 1, 1, serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
    ).unwrap();
    dispatch_route_request(request, &writer, surface, admin, caller, None).await.unwrap();
    responses.recv().await.unwrap()
}

async fn call(
    surface: &Arc<ReadSurface>, admin: &Arc<admin_surface::AdminSurface>, module: &str,
    method: &str, params: serde_json::Value,
) -> serde_json::Value {
    let frame = frame(surface, admin, caller(module), method, params).await;
    assert_eq!(frame.header.ty, FrameType::Response);
    serde_json::from_slice(&frame.body).unwrap()
}

fn refusal(error: ModuleSecretError) -> serde_json::Value {
    wrap_result(wire::reply(error))
}

#[test]
fn module_secret_manifest_kinds_are_exact() {
    let manifest = manifest(credentials_core::MODULE_ID, None);
    let ProviderRole::ManagementSurface { operations, .. } = &manifest.provides[0] else { panic!("management surface") };
    for (method, kind) in [
        (wire::GET, ManagementOperationKind::Query), (wire::LIST, ManagementOperationKind::Query),
        (wire::PUT, ManagementOperationKind::Mutate), (wire::DELETE, ManagementOperationKind::Mutate),
    ] {
        let found: Vec<_> = operations.iter().filter(|op| op.name == method).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, kind);
    }
}

#[tokio::test]
async fn module_secret_admission_matrix_is_uniform_before_decode() {
    let (surface, admin, store) = deposit_cookie_rig(201);
    let principal = |principal| federation::RouteCaller::Principal(federation::ingress::ScopedCaller::hand_only(principal));
    let mut relay = federation::ingress::ScopedCaller::hand_only(Some(reserved("relay")));
    relay.attestation = Some(attestation(CallerClaim::Relay, true));
    let refused = [
        principal(Some(reserved("missing-attestation"))),
        federation::RouteCaller::Principal(relay),
        principal(Some(subc_protocol::Principal::Direct)),
        principal(Some(subc_protocol::Principal::Unverified)), principal(None),
        federation::RouteCaller::Member("member".into()),
        federation::RouteCaller::Phone("phone".into()), federation::RouteCaller::Refused,
        caller("Uppercase"), caller(&"a".repeat(65)), caller("pipe|owner"), caller(""),
    ];
    let expected = serde_json::to_vec(&uniform_not_found()).unwrap();
    for rejected in refused {
        for method in [wire::PUT, wire::GET, wire::DELETE, wire::LIST] {
            for params in [json!(null), json!({"unexpected":"never echo"})] {
                let reply = frame(&surface, &admin, rejected.clone(), method, params).await;
                assert_eq!(reply.header.ty, FrameType::Response, "{rejected:?} {method}");
                assert_eq!(reply.body, expected, "{rejected:?} {method}");
            }
        }
    }
    for bearer in ["handle", "enrollment_token"] {
        for value in [json!(null), json!("bearer")] {
            let params = json!({bearer: value});
            let reply = frame(&surface, &admin, caller("module"), wire::LIST, params).await;
            assert_eq!(reply.body, expected);
            let direct = principal(Some(subc_protocol::Principal::Direct));
            let reply = frame(&surface, &admin, direct, wire::LIST, json!({bearer:"enrolled:consumer"})).await;
            assert_eq!(reply.body, expected);
        }
    }
    for first_party in [true, false] {
        admin.record_connector_bind(51, 1, reserved("own"), "own", None, None,
            Some(&attestation(CallerClaim::Own, first_party)), None);
        let snapshot = admin.route_caller(51);
        assert!(wire::admit(&snapshot, &json!({})).is_some());
        let reply = frame(&surface, &admin, snapshot, wire::LIST, json!({})).await;
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&reply.body).unwrap(), json!({"result":{"items":[]}}));
    }
    assert!(store.list_all_module_secrets().unwrap().is_empty());
}

#[tokio::test]
async fn module_secret_two_modules_have_disjoint_names_and_lists() {
    let (surface, admin, _store) = deposit_cookie_rig(202);
    let put = |value| json!({"name":"key", "value":value});
    assert_eq!(call(&surface, &admin, "one", wire::PUT, put("AQ==")).await,
        json!({"result":{"name":"key","version":1,"created":true}}));
    assert_eq!(call(&surface, &admin, "two", wire::GET, json!({"name":"key"})).await, uniform_not_found());
    assert_eq!(call(&surface, &admin, "two", wire::DELETE, json!({"name":"key"})).await, uniform_not_found());
    assert_eq!(call(&surface, &admin, "two", wire::LIST, json!({})).await, json!({"result":{"items":[]}}));
    call(&surface, &admin, "two", wire::PUT, put("Ag==")).await;
    for (module, value) in [("one", "AQ=="), ("two", "Ag==")] {
        assert_eq!(call(&surface, &admin, module, wire::GET, json!({"name":"key"})).await,
            json!({"result":{"name":"key","version":1,"protected":false,"value":value}}));
        let list = call(&surface, &admin, module, wire::LIST, json!({})).await;
        assert_eq!(list["result"]["items"].as_array().unwrap().len(), 1);
        assert_eq!(list["result"]["items"][0]["name"], "key");
        assert!(list["result"]["items"][0].get("value").is_none());
        call(&surface, &admin, module, wire::DELETE, json!({"name":"key"})).await;
    }
}

#[tokio::test]
async fn module_secret_validation_refuses_without_store_or_audit_writes() {
    let (surface, admin, store) = deposit_cookie_rig(203);
    let before = store.with_raw_conn(|conn| conn.query_row("SELECT count(*) FROM audit_log", [], |row| row.get::<_, i64>(0))).unwrap();
    let mut cases = vec![
        (wire::PUT, json!({"name":"key","value":"AQ==","extra":true})),
        (wire::GET, json!({"name":"key","extra":true})),
        (wire::DELETE, json!({"name":"key","extra":true})),
        (wire::LIST, json!({"extra":true})),
        (wire::PUT, json!({"name":"key","value":42})),
        (wire::GET, json!({"name":false})),
        (wire::DELETE, json!({"name":"key","expected_version":0})),
        (wire::PUT, json!({"name":"key","value":"AQ==","expected_version":0})),
        (wire::PUT, json!({"name":"key","value":"AQ==","expected_version":-1})),
        (wire::PUT, json!({"name":"key","value":"AQ==","protected":"true"})),
    ];
    for method in [wire::PUT, wire::GET, wire::DELETE, wire::LIST] {
        cases.push((method, json!(null)));
        cases.push((method, json!([])));
    }
    for name in ["".into(), "A".into(), "_name".into(), "bad|name".into(), "é".into(), "a".repeat(65)] {
        for method in [wire::PUT, wire::GET, wire::DELETE] {
            let mut params = json!({"name":name});
            if method == wire::PUT { params["value"] = json!("AQ=="); }
            cases.push((method, params));
        }
    }
    for value in ["".into(), "AQ".into(), "AR==".into(), "AQ==\n".into(), "AQ===".into(), "_w==".into(), STANDARD.encode(vec![0; 65_537])] {
        cases.push((wire::PUT, json!({"name":"key", "value":value})));
    }
    for (method, params) in cases {
        assert_eq!(call(&surface, &admin, "validation", method, params).await, refusal(ModuleSecretError::InvalidParams));
        assert!(store.list_all_module_secrets().unwrap().is_empty());
        let after = store.with_raw_conn(|conn| conn.query_row("SELECT count(*) FROM audit_log", [], |row| row.get::<_, i64>(0))).unwrap();
        assert_eq!(after, before);
    }
}

#[tokio::test]
async fn module_secret_wire_boundaries_accept_at_and_refuse_past() {
    let (surface, admin, _store) = deposit_cookie_rig(204);
    let owner = "m".repeat(64);
    let name = "n".repeat(64);
    let value = STANDARD.encode(vec![0x59; 65_536]);
    assert_eq!(call(&surface, &admin, &owner, wire::PUT, json!({"name":name,"value":value})).await,
        json!({"result":{"name":name,"version":1,"created":true}}));
    assert_eq!(call(&surface, &admin, &owner, wire::GET, json!({"name":name})).await,
        json!({"result":{"name":name,"version":1,"protected":false,"value":value}}));
    assert_eq!(call(&surface, &admin, &"m".repeat(65), wire::GET, json!({"name":name})).await, uniform_not_found());
    assert_eq!(call(&surface, &admin, &owner, wire::PUT, json!({"name":"n".repeat(65),"value":"AQ=="})).await, refusal(ModuleSecretError::InvalidParams));
    assert_eq!(call(&surface, &admin, &owner, wire::PUT, json!({"name":"large","value":STANDARD.encode(vec![0;65_537])})).await, refusal(ModuleSecretError::InvalidParams));
    for i in 1..64 {
        assert_eq!(call(&surface, &admin, &owner, wire::PUT, json!({"name":format!("item-{i:02}"),"value":"AQ=="})).await["result"]["created"], true);
    }
    assert_eq!(call(&surface, &admin, &owner, wire::LIST, json!({})).await["result"]["items"].as_array().unwrap().len(), 64);
    assert_eq!(call(&surface, &admin, &owner, wire::PUT, json!({"name":"overflow","value":"AQ=="})).await, refusal(ModuleSecretError::Limit));
    assert_eq!(call(&surface, &admin, &owner, wire::PUT, json!({"name":name,"value":"AQ==","expected_version":1})).await,
        json!({"result":{"name":name,"version":2,"created":false}}));
}

#[tokio::test]
async fn module_secret_wire_fixture_and_refusal_table_are_exact() {
    use credentials_core::envelope::{self, RecordBinding};
    use std::collections::{BTreeMap, BTreeSet};
    let (surface, admin, store) = deposit_cookie_rig(205);
    let mut success = BTreeMap::new();
    success.insert("create", call(&surface, &admin, "fixture", wire::PUT, json!({"name":"key","value":"AQID"})).await);
    success.insert("replace", call(&surface, &admin, "fixture", wire::PUT, json!({"name":"key","value":"BAU=","expected_version":1})).await);
    success.insert("get", call(&surface, &admin, "fixture", wire::GET, json!({"name":"key"})).await);
    success.insert("create_protected", call(&surface, &admin, "fixture", wire::PUT, json!({"name":"protected","value":"Bg==","protected":true})).await);
    success.insert("get_protected", call(&surface, &admin, "fixture", wire::GET, json!({"name":"protected"})).await);
    store.with_raw_conn(|conn| conn.execute("UPDATE module_secrets SET updated_at_ms=123", [])).unwrap();
    success.insert("list", call(&surface, &admin, "fixture", wire::LIST, json!({})).await);
    success.insert("list_empty", call(&surface, &admin, "empty", wire::LIST, json!({})).await);

    let mut errors = BTreeMap::new();
    errors.insert("invalid_params", call(&surface, &admin, "fixture", wire::PUT, json!({"name":"key","value":"AQ==","protected":true})).await);
    errors.insert("not_found", call(&surface, &admin, "fixture", wire::GET, json!({"name":"absent"})).await);
    errors.insert("module_secret_protected", call(&surface, &admin, "fixture", wire::PUT, json!({"name":"protected","value":"AQ==","expected_version":9,"protected":true})).await);
    assert_eq!(call(&surface, &admin, "fixture", wire::DELETE, json!({"name":"protected","expected_version":9})).await, errors["module_secret_protected"]);
    errors.insert("module_secret_version_conflict", call(&surface, &admin, "fixture", wire::PUT, json!({"name":"key","value":"AQ==","expected_version":1,"protected":true})).await);
    assert_eq!(call(&surface, &admin, "fixture", wire::DELETE, json!({"name":"key","expected_version":1})).await, errors["module_secret_version_conflict"]);
    assert_eq!(call(&surface, &admin, "fixture", wire::PUT, json!({"name":"absent","value":"AQ==","expected_version":1})).await, errors["module_secret_version_conflict"]);
    for i in 0..64 {
        call(&surface, &admin, "full", wire::PUT, json!({"name":format!("item-{i}"),"value":"AQ=="})).await;
    }
    errors.insert("module_secret_limit", call(&surface, &admin, "full", wire::PUT, json!({"name":"overflow","value":"AQ=="})).await);
    assert_eq!(call(&surface, &admin, "full", wire::PUT, json!({"name":"overflow","value":"AQ==","expected_version":1})).await, errors["module_secret_version_conflict"]);

    let blob = envelope::seal(&MasterKey::from_bytes([7; MASTER_KEY_LEN]), b"other-key", &RecordBinding {
        credential_id: "module-secret|fixture|key", record_version: 2,
    }).unwrap();
    store.with_raw_conn(|conn| conn.execute("UPDATE module_secrets SET envelope=?1 WHERE module_id='fixture' AND name='key'", [blob])).unwrap();
    errors.insert("vault_locked", call(&surface, &admin, "fixture", wire::GET, json!({"name":"key"})).await);
    store.with_raw_conn(|conn| conn.execute("UPDATE module_secrets SET envelope=x'00' WHERE module_id='fixture' AND name='key'", [])).unwrap();
    errors.insert("corrupt", call(&surface, &admin, "fixture", wire::GET, json!({"name":"key"})).await);
    assert_eq!(call(&surface, &admin, "fixture", wire::GET, json!({"name":"key"})).await, errors["corrupt"]);
    success.insert("list_corrupt", call(&surface, &admin, "fixture", wire::LIST, json!({})).await);
    success.insert("delete", call(&surface, &admin, "fixture", wire::DELETE, json!({"name":"key","expected_version":2})).await);

    store.with_raw_conn(|conn| conn.execute_batch("CREATE TRIGGER refuse_module_audit BEFORE INSERT ON audit_log WHEN NEW.op LIKE 'module_secret_%' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;")).unwrap();
    errors.insert("store_error", call(&surface, &admin, "fixture", wire::PUT, json!({"name":"rolled-back","value":"AQ=="})).await);
    assert_eq!(call(&surface, &admin, "fixture", wire::GET, json!({"name":"rolled-back"})).await, errors["not_found"]);

    let all = [
        ModuleSecretError::InvalidParams, ModuleSecretError::NotFound, ModuleSecretError::Protected,
        ModuleSecretError::VersionConflict, ModuleSecretError::Limit,
        ModuleSecretError::Corrupt, ModuleSecretError::VaultLocked, ModuleSecretError::Store,
    ];
    let mut codes = BTreeSet::new();
    for error in all {
        let code = match error {
            ModuleSecretError::InvalidParams => "invalid_params",
            ModuleSecretError::NotFound => "not_found",
            ModuleSecretError::Protected => "module_secret_protected",
            ModuleSecretError::VersionConflict => "module_secret_version_conflict",
            ModuleSecretError::Limit => "module_secret_limit",
            ModuleSecretError::Corrupt => "corrupt",
            ModuleSecretError::VaultLocked => "vault_locked",
            ModuleSecretError::Store => "store_error",
        };
        assert_eq!(errors[code], refusal(error), "{code}");
        assert!(codes.insert((code.to_string(), error.class().to_string())));
    }
    let doc = include_str!("../../../docs/wire-contract-v1.md");
    let table = doc.split("### Module-secret refusals").nth(1).unwrap().split("\n## ").next().unwrap();
    let documented: BTreeSet<_> = table.lines().filter_map(|line| {
        let columns: Vec<_> = line.split('|').map(str::trim).collect();
        if columns.get(1).is_some_and(|column| column.starts_with('`')) {
            Some((columns[1].trim_matches('`').to_owned(), columns[2].trim_matches('`').to_owned()))
        } else { None }
    }).collect();
    assert_eq!(documented, codes);
    let generated = json!({"success":success,"refusals":errors});
    let text = format!("{}\n", serde_json::to_string_pretty(&generated).unwrap());
    if std::env::var_os("CK_EMIT_MODULE_SECRET_WIRE").is_some() {
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/module_secret_wire_contract.json"), &text).unwrap();
    } else {
        assert_eq!(text, include_str!("../tests/fixtures/module_secret_wire_contract.json"));
    }
}
