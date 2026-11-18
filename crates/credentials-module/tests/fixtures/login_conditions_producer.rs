use super::*;
use credentials_core::record::RecordState;
use credentials_core::store::Condition;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const ID: &str = "oauth:antigravity:condition-fixture";
const VERIFY: &str = "provider_verification_required";
const INELIGIBLE: &str = "provider_ineligible";
const QUERY: &str = "condition-query-not-for-diagnostics";
const CHANNEL: u16 = 51;
const READER: &str = "condition-reader";

struct Rig {
    surface: Arc<ReadSurface>,
    admin: Arc<admin_surface::AdminSurface>,
    store: Arc<EncryptedStore>,
    db: std::path::PathBuf,
    _root: TestTempDir,
}

impl Rig {
    fn new() -> Self {
        let seed = 94;
        let (surface, store, db, root) = tmp_surface_with_store(seed);
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(&store),
            Vec::new(),
            Arc::new(crate::test_support::NoHttp),
        ));
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let admin = Arc::new(admin_surface::AdminSurface::new(
            engine,
            credentials_core::admin_auth::AdminMacKey::derive(&key),
            credentials_core::vault_id_for(db.parent().unwrap()).unwrap(),
            key.key_id(),
        ));
        admin.record_bind_at(CHANNEL, 1, reserved(READER), "");
        Self {
            surface,
            admin,
            store,
            db,
            _root: root,
        }
    }

    fn grant(&self, kind: &str, reader: &str, selector: SelectorKind, target: &str) {
        self.store
            .create_read_grant_audited(
                kind,
                reader,
                selector,
                target,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }

    fn login(&self, record: &VaultRecord) {
        self.store.create(ID, record).unwrap();
        self.grant("reserved", READER, SelectorKind::Exact, ID);
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.db).unwrap()
    }

    fn condition(&self) -> Option<Condition> {
        let incarnation = self.store.credential_incarnation(ID).unwrap();
        self.store.credential_condition(ID, &incarnation).unwrap()
    }

    async fn call(&self, method: &str, params: Value) -> (FrameType, Value) {
        let request = ReadRequest {
            method: method.into(),
            params: params.clone(),
        };
        no_query(&format!("{request:?}"));
        if method == OP_REPORT_CONDITION {
            if let Ok(params) =
                serde_json::from_value::<read_surface::ReportConditionParams>(params.clone())
            {
                no_query(&format!("{params:?}"));
            }
        }
        let (kind, bytes) = routed_reply(&self.surface, &self.admin, CHANNEL, method, params).await;
        no_query(std::str::from_utf8(&bytes).unwrap());
        no_query(&format!("{:?}", self.store.recent_auth_events(40).unwrap()));
        no_query(&format!("{:?}", self.store.read_audit(None).unwrap()));
        no_query(&format!("{:?}", self.condition()));
        (kind, serde_json::from_slice(&bytes).unwrap())
    }
}

fn no_query(text: &str) {
    assert!(
        !text.contains(QUERY),
        "the action link leaked its query value"
    );
}

fn action(host: &str) -> String {
    format!("https://{host}/check?account={QUERY}")
}

fn report(version: u64, reason: &str, status: u16, link: Option<&str>) -> Value {
    let mut params = json!({
        "credential_id": ID, "record_version": version, "reason": reason, "provider_status": status
    });
    if let Some(link) = link {
        params["action_url"] = json!(link);
    }
    params
}

fn clear(version: u64) -> Value {
    json!({"credential_id": ID, "record_version": version})
}

fn result(field: &str, applied: bool) -> Value {
    json!({"result": {(field): applied}})
}

fn refused(field: &str, code: &str) -> Value {
    json!({"result": {(field): false, "error": {"code": code, "class": "permanent"}}})
}

#[derive(Default, Clone)]
struct Logged(Arc<std::sync::Mutex<String>>);

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        writeln!(self.0, "{}={value:?}", field.name()).unwrap();
    }
}

impl tracing::Subscriber for Logged {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attrs.record(&mut Fields(&mut self.0.lock().unwrap()));
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Fields(&mut self.0.lock().unwrap()));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut Fields(&mut self.0.lock().unwrap()));
    }
}

#[tokio::test]
async fn consumer_condition_producer_replies_and_local_outcomes_are_pinned() {
    let logs = Logged::default();
    let _capture = tracing::subscriber::set_default(logs.clone());
    tracing::warn!("condition log capture control");

    let mut samples = BTreeMap::new();
    applied_and_noop_samples(&mut samples).await;
    refusal_samples(&mut samples).await;
    let logs = logs.0.lock().unwrap();
    assert!(logs.contains("condition log capture control"));
    no_query(&logs);

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/login-conditions-v1");
    let bytes = format!("{}\n", serde_json::to_string_pretty(&samples).unwrap());
    let sums = format!(
        "{:x}  consumer-ops.json\n",
        Sha256::digest(bytes.as_bytes())
    );
    let manifest_path = path.join("SHA256SUMS");
    if std::env::var("CK_EMIT_CONDITION_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("consumer-ops.json"), bytes).unwrap();
        let manifest = match std::fs::read_to_string(&manifest_path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("read SHA256SUMS: {error}"),
        };
        let mut rows: Vec<_> = manifest
            .lines()
            .filter(|line| !line.ends_with("  consumer-ops.json"))
            .collect();
        rows.push(sums.trim_end());
        rows.sort_by_key(|line| line.split_once("  ").unwrap().1);
        std::fs::write(manifest_path, rows.join("\n") + "\n").unwrap();
    } else {
        assert_eq!(
            std::fs::read(path.join("consumer-ops.json")).unwrap(),
            bytes.as_bytes()
        );
        let manifest = std::fs::read_to_string(manifest_path).unwrap();
        assert_eq!(
            manifest
                .lines()
                .filter(|line| line.ends_with("  consumer-ops.json"))
                .collect::<Vec<_>>(),
            [sums.trim_end()]
        );
    }
}

async fn applied_and_noop_samples(samples: &mut BTreeMap<&'static str, Value>) {
    let rig = Rig::new();
    rig.login(&oauth_record_with_adapter("antigravity"));
    let meta = rig.store.meta(ID).unwrap();
    let link = action("accounts.google.com");
    let changed_link = format!("{link}&next=1");
    let before_audit = rig.store.read_audit(None).unwrap().len();

    for (name, method, params, changed, expected) in [
        (
            "report_verification_required",
            OP_REPORT_CONDITION,
            report(1, VERIFY, 403, Some(&link)),
            true,
            Some((VERIFY, Some(link.as_str()))),
        ),
        (
            "report_identical",
            OP_REPORT_CONDITION,
            report(1, VERIFY, 403, Some(&link)),
            false,
            Some((VERIFY, Some(link.as_str()))),
        ),
        (
            "report_new_link",
            OP_REPORT_CONDITION,
            report(1, VERIFY, 403, Some(&changed_link)),
            true,
            Some((VERIFY, Some(changed_link.as_str()))),
        ),
        (
            "report_reason_replacement",
            OP_REPORT_CONDITION,
            report(1, INELIGIBLE, 403, None),
            true,
            Some((INELIGIBLE, None)),
        ),
        (
            "report_version_mismatch",
            OP_REPORT_CONDITION,
            report(2, VERIFY, 403, Some(&link)),
            false,
            Some((INELIGIBLE, None)),
        ),
        (
            "clear_version_mismatch",
            OP_CLEAR_CONDITION,
            clear(2),
            false,
            Some((INELIGIBLE, None)),
        ),
        ("clear_applied", OP_CLEAR_CONDITION, clear(1), true, None),
        ("clear_unset", OP_CLEAR_CONDITION, clear(1), false, None),
        (
            "report_ineligible",
            OP_REPORT_CONDITION,
            report(1, INELIGIBLE, 403, None),
            true,
            Some((INELIGIBLE, None)),
        ),
    ] {
        if name == "report_new_link" {
            rig.db()
                .execute(
                    "UPDATE credential_conditions SET since_ms = 7 WHERE credential_id = ?1",
                    [ID],
                )
                .unwrap();
        }
        let previous = rig.condition();
        let audit_before = rig.store.read_audit(None).unwrap().len();
        let events_before = rig.store.recent_auth_events(40).unwrap().len();
        let (frame, reply) = rig.call(method, params).await;
        let is_report = method == OP_REPORT_CONDITION;
        assert_eq!(frame, FrameType::Response, "{name}");
        assert_eq!(
            reply,
            if is_report {
                result("accepted", true)
            } else {
                result("cleared", changed)
            },
            "{name}"
        );
        samples.insert(name, reply);
        let condition = rig.condition();
        if !changed {
            assert_eq!(condition, previous, "{name}");
        }
        assert_eq!(
            condition
                .as_ref()
                .map(|row| (row.reason.as_str(), row.action_url.as_deref())),
            expected,
            "{name}"
        );
        if name == "report_new_link" {
            assert_eq!(condition.as_ref().unwrap().since_ms, 7);
        }
        if name == "report_reason_replacement" {
            assert!(condition.as_ref().unwrap().since_ms > 7);
        }
        assert_eq!(rig.store.meta(ID).unwrap(), meta);

        let audit = rig.store.read_audit(None).unwrap();
        assert_eq!(audit.len(), audit_before + usize::from(changed), "{name}");
        if changed {
            let row = audit.last().unwrap();
            assert_eq!(
                row.op,
                if is_report {
                    "report_condition"
                } else {
                    "clear_condition"
                }
            );
            assert_eq!(row.actor, READER);
            assert_eq!(row.credential_id.as_deref(), Some(ID));
            assert_eq!(row.payload_hash, None);
        }
        let events = rig.store.recent_auth_events(40).unwrap();
        let first_use = name == "report_verification_required";
        assert_eq!(
            events.len(),
            events_before + 1 + usize::from(first_use),
            "{name}"
        );
        let event = &events[0];
        assert_eq!(
            event.kind,
            if is_report {
                "consumer_report_condition"
            } else {
                "consumer_clear_condition"
            }
        );
        assert_eq!(event.applied, changed);
        assert_eq!(event.detail, None);
        assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
        assert_eq!(event.principal_id.as_deref(), Some(READER));
        assert_eq!(event.provider_status, is_report.then_some(403));
        if first_use {
            assert_eq!(events[1].kind, "scoped_first_use");
        }
    }
    assert_eq!(rig.store.read_audit(None).unwrap().len(), before_audit + 5);
    assert_eq!(
        rig.store.connector_auth_reason(ID).unwrap().as_deref(),
        Some("read")
    );
    let served = routed_json(
        &rig.surface,
        &rig.admin,
        CHANNEL,
        OP_GET_SCOPED,
        json!({"credential_id": ID}),
    )
    .await;
    assert_eq!(served["result"]["record_version"], 1);
}

async fn refusal_samples(samples: &mut BTreeMap<&'static str, Value>) {
    let link = action("accounts.google.com");
    let too_long = format!("{link}{}", "a".repeat(2049 - link.len()));
    for (name, reason, status, link, adapter, code) in [
        (
            "report_unsupported_adapter",
            VERIFY,
            401,
            action("other.invalid"),
            "anthropic",
            "condition_not_admitted",
        ),
        (
            "report_api_key",
            VERIFY,
            403,
            link.clone(),
            "api_key",
            "condition_not_admitted",
        ),
        (
            "report_unopenable",
            VERIFY,
            403,
            link.clone(),
            "unopenable",
            "condition_not_admitted",
        ),
        (
            "report_unknown_reason",
            "future_reason",
            401,
            action("other.invalid"),
            "antigravity",
            "condition_not_admitted",
        ),
        (
            "report_status_refused",
            VERIFY,
            401,
            action("other.invalid"),
            "antigravity",
            "condition_status_refused",
        ),
        (
            "report_link_refused",
            VERIFY,
            403,
            action("other.invalid"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_subdomain",
            VERIFY,
            403,
            action("a.accounts.google.com"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_userinfo",
            VERIFY,
            403,
            action("user@accounts.google.com"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_empty_userinfo",
            VERIFY,
            403,
            action("@accounts.google.com"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_default_port",
            VERIFY,
            403,
            action("accounts.google.com:443"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_other_port",
            VERIFY,
            403,
            action("accounts.google.com:8443"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_fragment",
            VERIFY,
            403,
            format!("{link}#fragment"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_space",
            VERIFY,
            403,
            format!("{link} "),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_control",
            VERIFY,
            403,
            format!("{link}\t"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_non_ascii",
            VERIFY,
            403,
            format!("{link}é"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_relative",
            VERIFY,
            403,
            format!("/check?account={QUERY}"),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_non_https",
            VERIFY,
            403,
            link.replacen("https:", "http:", 1),
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_link_too_long",
            VERIFY,
            403,
            too_long,
            "antigravity",
            "condition_link_refused",
        ),
        (
            "report_ineligible_with_link",
            INELIGIBLE,
            403,
            link.clone(),
            "antigravity",
            "condition_link_refused",
        ),
    ] {
        let rig = Rig::new();
        let record = match adapter {
            "api_key" => VaultRecord::new_static(
                CredentialKind::ApiKey,
                "fixture",
                b"fixture-api-key".to_vec(),
                None,
            ),
            "unopenable" => oauth_record_with_adapter("antigravity"),
            adapter => oauth_record_with_adapter(adapter),
        };
        rig.login(&record);
        if adapter == "unopenable" {
            rig.db()
                .execute(
                    "UPDATE credentials SET envelope = X'00' WHERE credential_id = ?1",
                    [ID],
                )
                .unwrap();
        }
        let meta = rig.store.meta(ID).unwrap();
        let audit = rig.store.read_audit(None).unwrap();
        let (frame, response) = rig
            .call(OP_REPORT_CONDITION, report(2, reason, status, Some(&link)))
            .await;
        assert_eq!(frame, FrameType::Response, "{name}");
        assert_eq!(response, refused("accepted", code), "{name}");
        samples.insert(name, response);
        assert_eq!(rig.condition(), None, "{name}");
        assert_eq!(rig.store.read_audit(None).unwrap(), audit, "{name}");
        assert_eq!(rig.store.meta(ID).unwrap(), meta, "{name}");
        let events = rig.store.recent_auth_events(40).unwrap();
        assert_eq!(events.len(), 1, "{name}");
        assert_eq!(events[0].kind, "scoped_first_use", "{name}");
    }

    for (method, field, invalid, absent) in [
        (
            OP_REPORT_CONDITION,
            "accepted",
            "report_invalid_params",
            "report_not_found",
        ),
        (
            OP_CLEAR_CONDITION,
            "cleared",
            "clear_invalid_params",
            "clear_not_found",
        ),
    ] {
        let params = if method == OP_REPORT_CONDITION {
            report(1, "unknown_reason", 401, Some(&link))
        } else {
            clear(1)
        };
        let rig = Rig::new();
        rig.login(&oauth_record_with_adapter("antigravity"));
        let audit = rig.store.read_audit(None).unwrap();
        let mut extra = params.clone();
        // Unknown field names may themselves contain the link.
        extra[link.as_str()] = json!(true);
        let (frame, response) = rig.call(method, extra).await;
        assert_eq!(frame, FrameType::Error);
        assert_eq!(response["code"], "invalid_params");
        samples.insert(invalid, response);
        assert!(rig.store.recent_auth_events(40).unwrap().is_empty());

        let mut unknown = params.clone();
        unknown["credential_id"] = json!("oauth:antigravity:missing-condition-fixture");
        let (frame, response) = rig.call(method, unknown).await;
        assert_eq!(frame, FrameType::Response);
        assert_eq!(response, refused(field, "not_found"));
        samples.insert(absent, response.clone());
        rig.admin
            .record_bind_at(CHANNEL, 1, reserved("another-reader"), "");
        assert_eq!(
            rig.call(method, params.clone()).await,
            (FrameType::Response, response.clone())
        );
        rig.grant(
            "reserved",
            "another-reader",
            SelectorKind::Category,
            "another-category",
        );
        assert_eq!(
            rig.call(method, params).await,
            (FrameType::Response, response)
        );
        let events = rig.store.recent_auth_events(40).unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|row| row.kind == "scoped_read_refusal"));
        assert_eq!(rig.condition(), None);
        // Only the setup of the out-of-reach grant appended an audit row.
        let after = rig.store.read_audit(None).unwrap();
        assert_eq!(after.len(), audit.len() + 1);
        assert_eq!(after.last().unwrap().op, AuditOp::GrantCreate.as_str());
    }
}

#[tokio::test]
async fn consumer_condition_link_accepts_2048_bytes_and_refuses_2049() {
    let rig = Rig::new();
    rig.login(&oauth_record_with_adapter("antigravity"));
    let base = action("ACCOUNTS.GOOGLE.COM");
    let boundary = format!("{base}{}", "a".repeat(2048 - base.len()));
    assert_eq!(
        rig.call(OP_REPORT_CONDITION, report(1, VERIFY, 403, Some(&boundary)))
            .await,
        (FrameType::Response, result("accepted", true))
    );
    let accepted = rig.condition().unwrap();
    assert!(accepted.action_url.as_deref() == Some(boundary.as_str()));

    let above = boundary + "a";
    assert_eq!(
        rig.call(OP_REPORT_CONDITION, report(1, VERIFY, 403, Some(&above)))
            .await,
        (
            FrameType::Response,
            refused("accepted", "condition_link_refused")
        )
    );
    assert_eq!(rig.condition(), Some(accepted));
}

#[tokio::test]
async fn consumer_condition_is_independent_of_state_and_clear_needs_no_admitted_adapter() {
    for state in [
        RecordState::Active,
        RecordState::NeedsReauth,
        RecordState::Retired,
    ] {
        let rig = Rig::new();
        rig.login(&oauth_record_with_adapter("antigravity"));
        rig.db()
            .execute(
                "UPDATE credentials SET state = ?1 WHERE credential_id = ?2",
                [state.as_str(), ID],
            )
            .unwrap();
        let before = routed_json(
            &rig.surface,
            &rig.admin,
            CHANNEL,
            OP_GET_SCOPED,
            json!({"credential_id": ID}),
        )
        .await;
        assert_eq!(
            rig.call(
                OP_REPORT_CONDITION,
                report(1, VERIFY, 403, Some(&action("accounts.google.com")))
            )
            .await,
            (FrameType::Response, result("accepted", true))
        );
        assert_eq!(rig.condition().unwrap().reason, VERIFY);
        assert_eq!(rig.store.meta(ID).unwrap().state, state);
        let after = routed_json(
            &rig.surface,
            &rig.admin,
            CHANNEL,
            OP_GET_SCOPED,
            json!({"credential_id": ID}),
        )
        .await;
        assert_eq!(after, before);
        if state == RecordState::Active {
            assert!(after["result"]["payload"].is_array());
        } else {
            assert_eq!(after["result"]["error"]["code"], "needs_reauth");
        }
    }

    let rig = Rig::new();
    rig.login(&oauth_record_with_adapter("anthropic"));
    let audit = rig.store.read_audit(None).unwrap();
    assert_eq!(
        rig.call(OP_CLEAR_CONDITION, clear(1)).await,
        (FrameType::Response, result("cleared", false))
    );
    assert_eq!(rig.store.read_audit(None).unwrap(), audit);
    let events = rig.store.recent_auth_events(40).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, "consumer_clear_condition");
    assert!(!events[0].applied);
    assert_eq!(events[1].kind, "scoped_first_use");
}

#[tokio::test]
async fn consumer_condition_enrollment_selects_the_authorizing_principal_on_both_ops() {
    use credentials_core::enrollment::{enrollment_secret_hash, EnrollmentPoll};
    let rig = Rig::new();
    rig.login(&oauth_record_with_adapter("antigravity"));
    let secret = "ac".repeat(32);
    let enrolled = "condition-enrolled";
    let request = rig
        .store
        .propose_enrollment(enrolled, &enrollment_secret_hash(&secret).unwrap())
        .unwrap();
    rig.store
        .approve_enrollment(&request.request_id, enrolled, "operator")
        .unwrap();
    let EnrollmentPoll::Approved { token, .. } = rig
        .store
        .poll_enrollment(&request.request_id, &secret)
        .unwrap()
    else {
        panic!("expected an approved enrollment");
    };
    rig.grant("enrolled", enrolled, SelectorKind::Exact, ID);
    let link = action("accounts.google.com");
    for (method, field, mut params) in [
        (
            OP_REPORT_CONDITION,
            "accepted",
            report(1, VERIFY, 403, Some(&link)),
        ),
        (OP_CLEAR_CONDITION, "cleared", clear(1)),
    ] {
        params["enrollment_token"] = json!("unresolvable-token");
        assert_eq!(
            rig.call(method, params.clone()).await,
            (FrameType::Response, refused(field, "not_found")),
            "never fall back to the ambient read grant"
        );
        params["enrollment_token"] = json!(&token);
        assert_eq!(
            rig.call(method, params).await,
            (FrameType::Response, result(field, true))
        );
        let audit = rig.store.read_audit(None).unwrap();
        assert_eq!(audit.last().unwrap().actor, format!("enrolled:{enrolled}"));
        let events = rig.store.recent_auth_events(40).unwrap();
        assert_eq!(events[0].principal_kind.as_deref(), Some("enrolled"));
        assert_eq!(events[0].principal_id.as_deref(), Some(enrolled));
        if method == OP_REPORT_CONDITION {
            let reporter: String = rig
                .db()
                .query_row(
                    "SELECT reporter FROM credential_conditions WHERE credential_id = ?1",
                    [ID],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(reporter, format!("enrolled:{enrolled}"));
        }
    }
}

#[tokio::test]
async fn consumer_condition_admission_uses_the_record_image_at_the_version_fence() {
    let rig = Rig::new();
    rig.login(&oauth_record_with_adapter("antigravity"));
    let incarnation = rig.store.credential_incarnation(ID).unwrap();
    let audit = rig.store.read_audit(None).unwrap().len();
    let writer = Arc::clone(&rig.store);
    rig.surface.set_incarnation_hook("admitted", move || {
        writer
            .overwrite_unconditional_audited(
                ID,
                &oauth_record_with_adapter("anthropic"),
                AuditCtx::admin(AuditOp::Overwrite),
            )
            .unwrap();
    });
    assert_eq!(
        rig.call(
            OP_REPORT_CONDITION,
            report(2, VERIFY, 403, Some(&action("accounts.google.com")))
        )
        .await,
        (
            FrameType::Response,
            refused("accepted", "condition_not_admitted")
        )
    );
    assert_eq!(rig.store.credential_incarnation(ID).unwrap(), incarnation);
    assert_eq!(rig.store.meta(ID).unwrap().record_version, 2);
    assert_eq!(rig.condition(), None);
    let after = rig.store.read_audit(None).unwrap();
    assert_eq!(after.len(), audit + 1);
    assert_eq!(after.last().unwrap().op, AuditOp::Overwrite.as_str());
    let events = rig.store.recent_auth_events(40).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "scoped_first_use");
}

#[tokio::test]
async fn consumer_condition_changes_never_cross_an_admitted_records_incarnation() {
    let link = action("accounts.google.com");
    for (method, field, params) in [
        (
            OP_REPORT_CONDITION,
            "accepted",
            report(1, VERIFY, 403, Some(&link)),
        ),
        (OP_CLEAR_CONDITION, "cleared", clear(1)),
    ] {
        let rig = Rig::new();
        rig.login(&oauth_record_with_adapter("antigravity"));
        if method == OP_CLEAR_CONDITION {
            assert_eq!(
                rig.call(OP_REPORT_CONDITION, report(1, VERIFY, 403, Some(&link)))
                    .await,
                (FrameType::Response, result("accepted", true))
            );
            assert!(rig.condition().is_some());
        }
        let audit = rig.store.read_audit(None).unwrap().len();
        let old = rig.store.credential_incarnation(ID).unwrap();
        let writer = Arc::clone(&rig.store);
        rig.surface.set_incarnation_hook("admitted", move || {
            writer
                .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
                .unwrap();
            writer
                .create_audited(
                    ID,
                    &oauth_record_with_adapter("antigravity"),
                    AuditCtx::admin(AuditOp::Put),
                )
                .unwrap();
        });
        assert_eq!(
            rig.call(method, params).await,
            (FrameType::Response, refused(field, "not_found"))
        );
        let new = rig.store.credential_incarnation(ID).unwrap();
        assert_ne!(old, new);
        assert_eq!(rig.store.meta(ID).unwrap().record_version, 1);
        assert_eq!(rig.condition(), None);
        assert_eq!(rig.store.credential_condition(ID, &old).unwrap(), None);
        assert!(rig.store.recent_auth_events(40).unwrap().is_empty());
        let after = rig.store.read_audit(None).unwrap();
        assert_eq!(
            after[audit..]
                .iter()
                .map(|row| row.op.as_str())
                .collect::<Vec<_>>(),
            ["remove", "put"]
        );

        // A request that arrives after recreation has no old lifetime to compare against.
        assert_eq!(
            rig.call(OP_REPORT_CONDITION, report(1, VERIFY, 403, Some(&link)))
                .await,
            (FrameType::Response, result("accepted", true))
        );
        assert!(rig.store.credential_condition(ID, &new).unwrap().is_some());
        assert_eq!(rig.store.credential_condition(ID, &old).unwrap(), None);
    }
}

#[test]
fn consumer_condition_operations_are_manifest_mutations() {
    let declared = manifest("claustrum", None).provides;
    for method in ["credential.report_condition", "credential.clear_condition"] {
        assert!(
            declared.iter().any(|role| match role {
                ProviderRole::ManagementSurface { operations, .. } => operations
                    .iter()
                    .any(|op| { op.name == method && op.kind == ManagementOperationKind::Mutate }),
                _ => false,
            }),
            "manifest must list {method} as a mutation"
        );
    }
}
