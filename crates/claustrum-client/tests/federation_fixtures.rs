use cortexkit_claustrum_client::{
    decode_credential_reply, decode_credential_status_reply, decode_list_scoped_reply,
    decode_report_auth_failure_reply, CredentialErrorClass,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../credentials-module/tests/fixtures/federation_wire_contract.json"
    ))
    .expect("producer fixture JSON")
}

#[test]
fn remote_get_and_status_producer_fixtures_decode_without_client_changes() {
    let fixture = fixture();
    for case in fixture["clients"]["cases"].as_array().unwrap() {
        let adapter = case["adapter"].as_str().unwrap();
        let get = decode_credential_reply(case["get"].clone()).expect("remote get decodes");
        assert_eq!(
            get.expose(),
            format!("fixture-{adapter}-access-not-a-secret").as_bytes()
        );
        assert_eq!(get.record_version, "1");
        assert_eq!(get.expires_at_ms, None);
        assert_eq!(get.account_id, Some(format!("fixture-{adapter}-account")));
        assert_eq!(get.email.as_deref(), Some("fixture@example.invalid"));
        assert_eq!(get.org_name.as_deref(), Some("Fixture Team"));
        let status =
            decode_credential_status_reply(case["status"].clone()).expect("remote status decodes");
        assert!(status.ready);
        assert_eq!(status.record_version.as_deref(), Some("1"));
        assert!(!status.stale_pending);
        assert_eq!(status.last_error_code, None);
    }
}

#[test]
fn remote_inventory_producer_rows_decode_without_dropping_either_adapter() {
    let listing = decode_list_scoped_reply(fixture()["clients"]["inventory"].clone()).unwrap();
    assert!(listing.undecodable_credentials.is_empty());
    assert!(listing.undecodable_grants.is_empty());
    assert_eq!(listing.credentials.len(), 2);
    assert_eq!(listing.grant_tuples.len(), 2);
    for (adapter, method) in [("anthropic", "oauth"), ("antigravity", "antigravity")] {
        let row = listing
            .credentials
            .iter()
            .find(|row| row.id == format!("oauth:{adapter}:fixture"))
            .unwrap();
        assert_eq!(row.credential_type, "oauth");
        assert_eq!(row.refresh_adapter.as_deref(), Some(adapter));
        assert_eq!(row.auth_method.as_deref(), Some(method));
        assert_eq!(row.categories, ["llm-provider"]);
        assert_eq!(row.account_id, Some(format!("fixture-{adapter}-account")));
        assert_eq!(row.state, "active");
        assert_eq!(row.record_version, 1);
    }
}

#[test]
fn a_remote_refusal_with_remedy_member_remains_a_structured_error() {
    let error = decode_credential_reply(fixture()["clients"]["refusal"].clone()).unwrap_err();
    assert_eq!(error.class, CredentialErrorClass::Permanent);
    // The existing Rust API returns a class-derived code and retains the wire
    // refusal code in its safe display message, rather than exposing remedy_member.
    assert_eq!(error.code(), "credential_permanent");
    assert!(error.to_string().contains("remote_setup_incomplete"));
    let status_error =
        decode_credential_status_reply(fixture()["clients"]["refusal"].clone()).unwrap_err();
    assert_eq!(status_error.class, CredentialErrorClass::Permanent);
    assert_eq!(status_error.code(), "credential_permanent");
    assert!(status_error.to_string().contains("remote_setup_incomplete"));
}

#[test]
fn forwarded_report_producer_receipts_and_refusals_decode() {
    for case in fixture()["home"]["cases"].as_array().unwrap() {
        assert!(decode_report_auth_failure_reply(case["report"].clone()).unwrap());
        let error = decode_report_auth_failure_reply(case["refused_report"].clone()).unwrap_err();
        assert_eq!(error.class, CredentialErrorClass::Permanent);
        assert_eq!(error.code(), "credential_permanent");
        assert!(error
            .to_string()
            .contains("report_status_not_credential_death"));
    }
}
