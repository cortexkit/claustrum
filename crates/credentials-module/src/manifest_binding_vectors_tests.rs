use super::*;
use base64::engine::general_purpose::STANDARD;
use credentials_core::{
    admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V2},
    agent_secret::{ApprovalEnvelope, ApprovalItem, SecretError, USE_ENVELOPE_TAG},
    gh_manifest::{
        ManifestBindingEnvelope, ManifestBindingStatement, MANIFEST_BINDING_ENVELOPE_V1_TAG,
    },
    store::{GhManifestHandoffEnvelope, PhoneOperation},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::collections::BTreeMap;
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

const FP: &str = "11111111111111111111111111111111";
const SELF: &str = "fed-computer:22222222222222222222222222222222";
const OTHER: &str = "fed-computer:33333333333333333333333333333333";
const ID: &str = "01HF7YAT000000000000000001";
const EPOCH: &str = "00112233445566778899aabbccddeeff";
const BEGIN: &str = "<!-- manifest-binding-generated:start -->\n";
const END: &str = "<!-- manifest-binding-generated:end -->";

fn sql(rig: &Rig, statement: &str) {
    rig.with_raw_conn(|conn| conn.execute_batch(statement))
        .unwrap();
}

fn setup() -> (Rig, Ed25519KeyPair) {
    let rig = rig("version");
    sql(&rig, "DELETE FROM credentials WHERE credential_id='signing:gh-manifest-root:1'; DELETE FROM settings WHERE name='manifest.one_tap';");
    // RFC 8410 PKCS#8 v1 around a TEST-ONLY fixed seed. Never trust this key outside tests.
    let mut der = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    der.extend_from_slice(&[19; 32]);
    let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der)
    );
    rig.store
        .create_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "test-only",
                pem.into_bytes(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    (rig, pair)
}

fn import_v28(rig: &Rig, pair: &Ed25519KeyPair) {
    let envelope = GhManifestHandoffEnvelope {
        key_id: credentials_core::signing::key_id_for_public(pair.public_key().as_ref()),
        manifest_bytes: std::str::from_utf8(V28).unwrap().into(),
        signature: STANDARD.encode(pair.sign(V28).as_ref()),
    };
    assert_eq!(
        apply(
            &rig.store,
            AdminOpBody::ManifestImport {
                v: ADMIN_OP_SCHEMA_V2,
                envelope,
            },
            "test-admin"
        )
        .unwrap()["version"],
        28
    );
}

fn phone(rig: &Rig, method: &str, params: &Value, now: i64) -> Value {
    let op = crate::secret_phone::parse(method, params).expect("valid phone params");
    rig.store
        .secret_phone_operation(FP, Some("pair-A"), now, &op, || true, || now)
        .unwrap_or_else(SecretError::body)
}

fn register(rig: &Rig) -> SigningKey {
    // TEST-ONLY P-256 key; deterministic RFC 6979 signatures make the corpus reproducible.
    let key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let (deposit_pub, _) =
        credentials_core::kem::public_half(&credentials_core::kem::generate_key().unwrap())
            .unwrap();
    assert_eq!(
        rig.store
            .secret_phone_operation(
                FP,
                Some("pair-A"),
                NOW,
                &PhoneOperation::Register {
                    deposit_pub,
                    approval_pub: key
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec(),
                },
                || true,
                || NOW
            )
            .unwrap(),
        json!({"status":"stored"})
    );
    key
}

fn signed_request(
    statement: &ManifestBindingStatement,
    key: &SigningKey,
    now: i64,
) -> (Vec<u8>, Value) {
    let bytes = ManifestBindingEnvelope {
        v: String::from_utf8(MANIFEST_BINDING_ENVELOPE_V1_TAG.to_vec()).unwrap(),
        proposal_id: statement.proposal_id.clone(),
        statement_sha256: statement.statement_sha256().unwrap(),
        decision: "allow".into(),
        device_fingerprint: FP.into(),
        issued_at_ms: now as u64,
    }
    .canonical_bytes()
    .unwrap();
    let signature: Signature = key.sign(&bytes);
    let request = json!({"method":"manifest.approve","params":{
        "envelope_b64url":URL_SAFE_NO_PAD.encode(&bytes),
        "signature_b64url":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
    }});
    (bytes, request)
}

async fn call(rig: &Rig, module: &str, method: &str, params: Value) -> Value {
    let (tx, mut rx) = mpsc::channel(8);
    crate::manifest::serve(
        header(method),
        &tx,
        &rig.surface,
        Some(&Principal::Reserved {
            module_id: module.into(),
        }),
        method,
        &params,
    )
    .await
    .unwrap();
    let frame = rx.recv().await.unwrap();
    assert_eq!(frame.header.ty, FrameType::Response);
    serde_json::from_slice::<Value>(&frame.body).unwrap()
}

fn header(method: &str) -> subc_protocol::EnvelopeHeader {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        11,
        3,
        7,
        serde_json::to_vec(&json!({"method":method,"params":{}})).unwrap(),
    )
    .unwrap()
    .header
}

async fn watch(rig: &Rig) -> (mpsc::Receiver<Frame>, Value) {
    let (tx, mut rx) = mpsc::channel(8);
    crate::manifest::serve(
        header("manifest.watch"),
        &tx,
        &rig.surface,
        Some(&Principal::Reserved {
            module_id: "aft".into(),
        }),
        "manifest.watch",
        &json!({}),
    )
    .await
    .unwrap();
    let frame = rx.recv().await.unwrap();
    assert_eq!(frame.header.ty, FrameType::StreamData);
    let mut notice: Value = serde_json::from_slice(&frame.body).unwrap();
    let epoch = notice["epoch"].as_str().unwrap();
    assert_eq!(epoch.len(), 32);
    assert!(epoch
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(notice["seq"], 1);
    // Only the process-random epoch is normalized; the notice body is otherwise untouched.
    notice["epoch"] = json!(EPOCH);
    (rx, notice)
}

fn fixed_pending(rig: &Rig, answer: &Value) -> ManifestBindingStatement {
    let original = URL_SAFE_NO_PAD
        .decode(answer["statement_b64url"].as_str().unwrap())
        .unwrap();
    let mut statement: ManifestBindingStatement = serde_json::from_slice(&original).unwrap();
    assert_eq!(statement.canonical_bytes().unwrap(), original);
    // Stabilize only the random ULID, then ask the real proposal producer to reread
    // the pending row. The separate end-to-end test never rewrites a proposal.
    statement.proposal_id = ID.into();
    let bytes = statement.canonical_bytes().unwrap();
    rig.with_raw_conn(|conn| conn.execute(
        "UPDATE gh_manifest_proposals SET proposal_id=?1,statement_bytes=?2,statement_sha256=?3 WHERE proposal_id=?4",
        rusqlite::params![ID, bytes, hash(&bytes), answer["proposal_id"].as_str().unwrap()],
    )).unwrap();
    statement
}

fn report_body(hash: &str) -> Value {
    json!({"version":29,"payload_sha256":hash,"verdict":"valid","reason":null})
}

fn verify_latest(latest: &Value, public: &[u8]) {
    let envelope = &latest["envelope"];
    let signature = STANDARD
        .decode(envelope["signature"].as_str().unwrap())
        .unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(
            envelope["manifest_bytes"].as_str().unwrap().as_bytes(),
            &signature,
        )
        .unwrap();
}

async fn reports(rig: &Rig, hash: &str, public: &[u8]) -> (Value, Value, Value) {
    use crate::federation::ingress::{OP_MANIFEST_LATEST, OP_MANIFEST_REPORT_ACTIVE};
    use crate::tests::federation_fixture_support::{temp_root, TwoVaults};
    use claustrum_module_probe::federation::{HomeAnswer, HomeVault};
    let root = temp_root("manifest-binding-activation");
    let vaults = TwoVaults::new(&root).await;
    vaults.callosum.set_pairing(OTHER, Some("pairing"));
    sql(rig,"INSERT OR REPLACE INTO settings(name,value,updated_at_ms) VALUES('secrets.home_member','self',0)");
    rig.store
        .set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    rig.store
        .create_member_grant_audited(
            OTHER,
            credentials_core::federation::MemberGrantOperation::SecretUse,
            &credentials_core::federation::MemberGrantSelector::None,
            "pairing",
        )
        .unwrap();
    let engine = Arc::new(credentials_core::engine::RefreshEngine::new(
        Arc::clone(&rig.store),
        vec![],
        Arc::new(crate::test_support::NoHttp),
    ));
    let home = HomeVault::new(engine);
    home.attach_outbound(vaults.a.outbound.clone());
    let request = report_body(hash);
    let latest = call(rig, "aft", "manifest.latest", json!({})).await;
    assert_eq!(latest["result"]["version"], 29);
    verify_latest(&latest["result"], public);
    assert_eq!(
        self::hash(
            latest["result"]["envelope"]["manifest_bytes"]
                .as_str()
                .unwrap()
                .as_bytes()
        ),
        hash
    );
    let reply = call(rig, "aft", "manifest.report_active", request.clone()).await;
    assert_eq!(reply["result"]["member_id"], SELF);
    let missing = call(
        rig,
        "plexus",
        "manifest.active_status",
        json!({"version":29}),
    )
    .await;
    assert_eq!(missing["result"]["ready"], false);
    assert_eq!(missing["result"]["computers"][1]["member_id"], OTHER);
    assert!(missing["result"]["computers"][1]["version"].is_null());
    // A second AFT reads and reports through the paired-member home ingress. Its
    // attested member is a separate argument, never part of the report params.
    let HomeAnswer::Reply(latest) = home.serve(OTHER, OP_MANIFEST_LATEST, &json!({})).await else {
        panic!("expected latest")
    };
    assert_eq!(latest["version"], 29);
    verify_latest(&latest, public);
    assert_eq!(
        self::hash(
            latest["envelope"]["manifest_bytes"]
                .as_str()
                .unwrap()
                .as_bytes()
        ),
        hash
    );
    let HomeAnswer::Reply(recorded) = home.serve(OTHER, OP_MANIFEST_REPORT_ACTIVE, &request).await
    else {
        panic!("expected report reply")
    };
    assert_eq!(
        recorded,
        json!({"status":"recorded","member_id":OTHER,"version":29})
    );
    let ready = call(
        rig,
        "plexus",
        "manifest.active_status",
        json!({"version":29}),
    )
    .await;
    assert_eq!(ready["result"]["ready"], true);
    (reply, missing, ready)
}

fn fixed_report_times(mut status: Value) -> Value {
    for computer in status["result"]["computers"].as_array_mut().unwrap() {
        if !computer["reported_at_ms"].is_null() {
            assert!(computer["reported_at_ms"].as_i64().unwrap() > 0);
            computer["reported_at_ms"] = json!(NOW);
        }
    }
    status
}

#[tokio::test]
async fn manifest_binding_end_to_end_import_propose_approve_watch_and_activate() {
    let (rig, pair) = setup();
    import_v28(&rig, &pair);
    assert!(!rig.store.manifest_one_tap_enabled());
    assert_eq!(
        reply(propose(&rig, &IdentityStub::good(), &HttpStub::good()).await)["error"]["code"],
        "one_tap_disabled"
    );
    rig.store
        .set_manifest_one_tap_audited(true, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .unwrap();
    let key = register(&rig);
    let (mut rx, initial) = watch(&rig).await;
    assert_eq!(initial["version"], 28);
    let answer = reply(propose(&rig, &IdentityStub::good(), &HttpStub::good()).await);
    let statement: ManifestBindingStatement = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(answer["statement_b64url"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(statement.repo, REPO);
    let installations: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    assert_eq!(
        json!(statement.installation_permissions),
        installations[0]["permissions"]
    );
    let (_, request) = signed_request(&statement, &key, NOW);
    let approved = phone(&rig, "manifest.approve", &request["params"], NOW);
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["version"], 29);
    let latest = rig.store.latest_gh_manifest().unwrap().unwrap();
    let raw = STANDARD.decode(&latest.envelope.signature).unwrap();
    let verifier = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        pair.public_key().as_ref(),
    );
    verifier
        .verify(latest.envelope.manifest_bytes.as_bytes(), &raw)
        .unwrap();
    let mut changed = latest.envelope.manifest_bytes.as_bytes().to_vec();
    changed[0] ^= 1;
    assert!(verifier.verify(&changed, &raw).is_err());
    // Independently exercise the consumer's Node crypto API over the exact stored
    // UTF-8 bytes, including their final newline, and reject a one-bit change.
    let node = std::process::Command::new("node").args(["-e", r#"
const {createPublicKey, verify} = require('node:crypto');
const e = JSON.parse(process.argv[1]);
const key = createPublicKey({key:Buffer.from(e.spki,'base64'),format:'der',type:'spki'});
const bytes = Buffer.from(e.manifest_bytes,'utf8');
const signature = Buffer.from(e.signature,'base64');
if (!verify(null,bytes,key,signature)) process.exit(1);
bytes[0] ^= 1;
if (verify(null,bytes,key,signature)) process.exit(2);
console.log('2 Node Ed25519 verification checks passed');
"#]).arg(serde_json::to_string(&json!({
        "spki":STANDARD.encode([&[0x30,0x2a,0x30,5,6,3,0x2b,0x65,0x70,3,0x21,0][..],pair.public_key().as_ref()].concat()),
        "manifest_bytes":latest.envelope.manifest_bytes,"signature":latest.envelope.signature,
    })).unwrap()).output().expect("Node is required for the manifest consumer verification");
    assert!(
        node.status.success(),
        "Node verification failed: {}",
        String::from_utf8_lossy(&node.stderr)
    );
    assert_eq!(
        String::from_utf8(node.stdout).unwrap().trim(),
        "2 Node Ed25519 verification checks passed"
    );
    rig.with_raw_conn(|conn| {
        let count:i64=conn.query_row("SELECT COUNT(*) FROM audit_log WHERE op='approval' AND credential_id='signing:gh-manifest-root:1'",[],|r|r.get(0))?;
        assert_eq!(count,1);
        Ok(())
    }).unwrap();
    let frame = rx.recv().await.unwrap();
    assert_eq!(frame.header.ty, FrameType::StreamData);
    let notice: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(notice["seq"], 2);
    assert_eq!(notice["version"], 29);
    assert_eq!(notice["manifest_sha256"], statement.manifest_sha256);
    reports(&rig, &statement.manifest_sha256, pair.public_key().as_ref()).await;
    rig.surface.watches.close_all();
}

async fn proposal_refusals() -> BTreeMap<String, Value> {
    let mut bodies = BTreeMap::new();
    for (case, code) in [
        ("disabled", "one_tap_disabled"),
        ("setup", "manifest_setup_incomplete"),
        ("identity", "identity_mismatch"),
        ("unreachable", "identity_unavailable"),
        ("missing", "not_installed"),
        ("all", "installation_all"),
        ("several", "installation_unusable"),
        ("large", "installation_too_large"),
        ("github", "github_unavailable"),
        ("same", "already_bound"),
        ("other", "bound_to_other_agent"),
        ("ahead", "stale_base"),
        ("format", "not_reproducible"),
        ("store", "store_error"),
    ] {
        let rig = rig(if case == "setup" { "root" } else { "" });
        let mut identity = IdentityStub::good();
        let mut http = HttpStub::good();
        match case {
            "disabled" => { rig.store.set_manifest_one_tap_audited(false, AuditCtx::admin(AuditOp::GhManifestOneTapSet)).unwrap(); }
            "identity" => identity = IdentityStub::new(json!({"result":{"github_identity":null,"agent_generation":1,"generation":1,"incarnation":"0123456789abcdef"}})),
            "unreachable" => identity = IdentityStub::new(json!({"bad":"shape"})),
            "missing" => http = HttpStub::new(vec![(200,b"[]".to_vec())]),
            "all" | "several" => {
                let mut installations:Value=serde_json::from_slice(INSTALLATIONS).unwrap();
                if case == "all" { installations[0]["repository_selection"]=json!("all"); }
                else { let another=installations[0].clone(); installations.as_array_mut().unwrap().push(another); }
                http=HttpStub::new(vec![(200,serde_json::to_vec(&installations).unwrap()),(201,TOKENS.to_vec()),(200,page(1,&[REPO]))]);
            }
            "large" => http=HttpStub::new(vec![(200,INSTALLATIONS.to_vec()),(201,TOKENS.to_vec()),(200,page(1001,&[]))]),
            "github" => http=HttpStub::new(vec![(403,b"{}".to_vec())]),
            "same" | "other" | "format" => {
                let mut manifest:Value=serde_json::from_slice(V28).unwrap();
                manifest["manifest_version"]=json!(30);
                if case != "format" { manifest["bindings"][REPO]=json!(if case=="same" {AGENT} else {"agent_other"}); }
                store_bytes(&rig.store,30,&serde_json::to_vec(&manifest).unwrap());
            }
            "ahead" => sql(&rig, &format!("INSERT INTO gh_manifest_activations(member_id,version,payload_sha256,verdict,reported_at_ms) VALUES('{OTHER}',31,'{}','valid',0)", "a".repeat(64))),
            "store" => sql(&rig,"UPDATE credentials SET envelope=x'00' WHERE credential_id='github_app:plex-alfonso'"),
            _ => {}
        }
        let before = snapshot(&rig);
        let result = reply(propose(&rig, &identity, &http).await);
        assert_eq!(result["error"]["code"], code, "{case}");
        assert_eq!(snapshot(&rig), before, "{case} wrote on refusal");
        bodies.insert(code.into(), json!({"result":result}));
    }
    bodies
}

async fn samples() -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let (rig, pair) = setup();
    let (_, empty) = watch(&rig).await;
    out.insert("watch.empty".into(), empty);
    rig.surface.watches.close_all();
    import_v28(&rig, &pair);
    rig.store
        .set_manifest_one_tap_audited(true, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .unwrap();
    let key = register(&rig);
    let first = reply(propose(&rig, &IdentityStub::good(), &HttpStub::good()).await);
    let statement = fixed_pending(&rig, &first);
    let answer = reply(propose(&rig, &IdentityStub::good(), &HttpStub::good()).await);
    assert_eq!(answer["proposal_id"], ID);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(answer["statement_b64url"].as_str().unwrap())
            .unwrap(),
        statement.canonical_bytes().unwrap()
    );
    out.insert(
        "propose.request".into(),
        json!({"method":"manifest.propose_binding","params":params()}),
    );
    out.insert("propose.reply".into(), json!({"result":answer}));
    out.insert("statement".into(),json!({
        "statement":statement,"statement_utf8":String::from_utf8(statement.canonical_bytes().unwrap()).unwrap(),
        "statement_b64url":URL_SAFE_NO_PAD.encode(statement.canonical_bytes().unwrap()),
        "statement_sha256":hash(&statement.canonical_bytes().unwrap()),
    }));
    let (bytes, approve) = signed_request(&statement, &key, NOW);
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    out.insert("envelope".into(),json!({"envelope":parsed,"envelope_utf8":String::from_utf8(bytes).unwrap(),
        "envelope_b64url":approve["params"]["envelope_b64url"],
        "signature_b64url":approve["params"]["signature_b64url"],
        "approval_public_key_sec1_hex":key.verifying_key().to_encoded_point(false).as_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>(),
        "test_only_private_scalar_hex":"07".repeat(32),
    }));
    out.insert("approve.request".into(), approve.clone());
    let (kind, invalid) = wire(
        &rig,
        crate::federation::RouteCaller::Principal(Some(plexus())),
        "manifest.propose_binding",
        json!({"unexpected":true}),
    )
    .await;
    assert_eq!(kind, FrameType::Error);
    out.insert(
        "refusal.invalid_params".into(),
        serde_json::from_slice(&invalid).unwrap(),
    );

    let secret = ApprovalEnvelope {
        v: String::from_utf8(USE_ENVELOPE_TAG.to_vec()).unwrap(),
        items: vec![ApprovalItem {
            request_id: ID.into(),
            statement_sha256: statement.statement_sha256().unwrap(),
        }],
        decision: "allow".into(),
        duration: "once".into(),
        grant_expires_at_ms: 0,
        device_fingerprint: FP.into(),
        issued_at_ms: NOW as u64,
    }
    .canonical_bytes()
    .unwrap();
    for (id, method, envelope) in [
        ("cross.secret_to_manifest", "manifest.approve", secret),
        (
            "cross.manifest_to_secret",
            "secret.approve",
            URL_SAFE_NO_PAD
                .decode(approve["params"]["envelope_b64url"].as_str().unwrap())
                .unwrap(),
        ),
    ] {
        let signature: Signature = key.sign(&envelope);
        let request = json!({"method":method,"params":{"envelope_b64url":URL_SAFE_NO_PAD.encode(envelope),"signature_b64url":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())}});
        let before = snapshot(&rig);
        let result = phone(&rig, method, &request["params"], NOW);
        assert_eq!(result, SecretError::ApprovalInvalid.body());
        assert_eq!(snapshot(&rig), before);
        out.insert(
            id.into(),
            json!({"request":request,"reply":{"result":result}}),
        );
    }
    for (state, code) in [("superseded", "superseded"), ("expired", "expired")] {
        sql(
            &rig,
            &format!("UPDATE gh_manifest_proposals SET state='{state}'"),
        );
        let before = snapshot(&rig);
        let result = phone(&rig, "manifest.approve", &approve["params"], NOW);
        assert_eq!(result["error"]["code"], code);
        assert_eq!(snapshot(&rig), before);
        out.insert(format!("refusal.{code}"), json!({"result":result}));
    }
    sql(&rig, "UPDATE gh_manifest_proposals SET state='pending'");
    let approved = phone(&rig, "manifest.approve", &approve["params"], NOW);
    assert_eq!(approved["status"], "approved");
    out.insert("approve.reply".into(), json!({"result":approved}));
    let before = snapshot(&rig);
    let resend = phone(&rig, "manifest.approve", &approve["params"], NOW + 1);
    assert_eq!(resend, approved);
    assert_eq!(snapshot(&rig), before);
    out.insert("approve.resend".into(), json!({"result":resend}));
    out.insert(
        "latest.reply".into(),
        call(&rig, "aft", "manifest.latest", json!({})).await,
    );
    let (_, stored) = watch(&rig).await;
    out.insert("watch.stored".into(), stored);
    rig.surface.watches.close_all();
    let (report, missing, ready) =
        reports(&rig, &statement.manifest_sha256, pair.public_key().as_ref()).await;
    out.insert(
        "report.request".into(),
        json!({"method":"manifest.report_active","params":report_body(&statement.manifest_sha256)}),
    );
    out.insert("report.reply".into(), report);
    out.insert(
        "active_status.not_ready".into(),
        fixed_report_times(missing),
    );
    out.insert("active_status.ready".into(), fixed_report_times(ready));
    out.insert(
        "refusal.unknown_version".into(),
        call(
            &rig,
            "plexus",
            "manifest.active_status",
            json!({"version":999}),
        )
        .await,
    );
    out.insert(
        "refusal.not_found".into(),
        call(&rig, "other", "manifest.latest", json!({})).await,
    );
    out.insert("refusal.approval_invalid".into(),json!({"result":phone(&rig,"manifest.approve",&json!({"envelope_b64url":"AA","signature_b64url":"AA"}),NOW)}));
    let unregistered = super::rig("member");
    out.insert(
        "refusal.secret_setup_incomplete".into(),
        call(
            &unregistered,
            "aft",
            "manifest.report_active",
            report_body(&statement.manifest_sha256),
        )
        .await,
    );
    out.insert(
        "refusal.phone_not_registered".into(),
        json!({"result":phone(&unregistered,"manifest.approve",&approve["params"],NOW)}),
    );
    let unavailable = crate::secret_phone::serve_with_lookup(
        Arc::clone(&rig.store),
        FP,
        "manifest.approve",
        &approve["params"],
        Instant::now() + PROPOSE_DEADLINE,
        async { None },
    )
    .await;
    let crate::secret_phone::PhoneAnswer::Reply(result) = unavailable else {
        panic!("expected pairing refusal")
    };
    out.insert(
        "refusal.pairing_unavailable".into(),
        json!({"result":result}),
    );
    sql(&rig,&format!("INSERT OR REPLACE INTO settings(name,value,updated_at_ms) VALUES('secrets.home_member','{OTHER}',0)"));
    out.insert(
        "refusal.secret_home_elsewhere".into(),
        json!({"result":phone(&rig,"manifest.approve",&approve["params"],NOW)}),
    );
    out.insert(
        "refusal.home_unavailable".into(),
        call(&rig, "aft", "manifest.latest", json!({})).await,
    );
    // Use the setting constant because its persisted name is not part of this contract.
    rig.with_raw_conn(|conn| {
        conn.execute(
            "DELETE FROM settings WHERE name=?1",
            [credentials_core::federation::SELF_MEMBER_SETTING],
        )
    })
    .unwrap();
    out.insert(
        "refusal.remote_setup_incomplete".into(),
        json!({"result":phone(&rig,"manifest.approve",&approve["params"],NOW)}),
    );
    out.insert(
        "refusal.remote_setup_incomplete.forwarded".into(),
        call(&rig, "aft", "manifest.latest", json!({})).await,
    );
    rig.store
        .set_federation_self_member_audited(OTHER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    out.insert(
        "refusal.remote_setup_incomplete.with_remedy".into(),
        json!({"result":phone(&rig,"manifest.approve",&approve["params"],NOW)}),
    );
    out.insert(
        "refusal.remote_setup_incomplete.forwarded_with_remedy".into(),
        call(&rig, "aft", "manifest.latest", json!({})).await,
    );
    for (code, body) in proposal_refusals().await {
        out.insert(format!("refusal.{code}"), body);
    }
    out
}

fn generated_blocks(samples: &BTreeMap<String, Value>) -> String {
    let mut text = String::from(BEGIN);
    for (id, value) in samples {
        text.push_str(&format!(
            "\n<!-- golden:manifest.{id} -->\n```json\n{}\n```\n",
            serde_json::to_string_pretty(value).unwrap()
        ));
    }
    text.push_str(END);
    text
}

#[tokio::test]
async fn manifest_binding_vectors_and_wire_goldens_are_producer_pinned() {
    let samples = samples().await;
    for code in [
        "not_found",
        "invalid_params",
        "one_tap_disabled",
        "manifest_setup_incomplete",
        "identity_mismatch",
        "identity_unavailable",
        "not_installed",
        "installation_all",
        "installation_unusable",
        "installation_too_large",
        "github_unavailable",
        "already_bound",
        "bound_to_other_agent",
        "stale_base",
        "not_reproducible",
        "store_error",
        "pairing_unavailable",
        "phone_not_registered",
        "secret_home_elsewhere",
        "remote_setup_incomplete",
        "approval_invalid",
        "superseded",
        "expired",
        "home_unavailable",
        "secret_setup_incomplete",
        "unknown_version",
    ] {
        let body = &samples[&format!("refusal.{code}")];
        assert_eq!(
            if code == "invalid_params" {
                &body["code"]
            } else {
                &body["result"]["error"]["code"]
            },
            code
        );
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let vectors = root.join("tests/vectors/manifest-binding-v1.json");
    let sums = root.join("tests/vectors/SHA256SUMS");
    let doc = root.join("../../docs/wire-contract-v1.md");
    let mut bytes =
        serde_json::to_vec_pretty(&json!({"format":"manifest-binding-v1","samples":samples}))
            .unwrap();
    bytes.push(b'\n');
    let checksum = format!("{}  manifest-binding-v1.json", hash(&bytes));
    let blocks = generated_blocks(&samples);
    let original = std::fs::read_to_string(&doc).unwrap();
    if std::env::var_os("CK_EMIT_MANIFEST_VECTORS").is_some() {
        std::fs::write(&vectors, &bytes).unwrap();
        let old = std::fs::read_to_string(&sums).unwrap();
        let mut lines: Vec<_> = old
            .lines()
            .filter(|line| !line.ends_with("  manifest-binding-v1.json"))
            .map(str::to_owned)
            .collect();
        lines.push(checksum.clone());
        lines.sort_by(|a, b| {
            a.split_once("  ")
                .unwrap()
                .1
                .cmp(b.split_once("  ").unwrap().1)
        });
        std::fs::write(&sums, format!("{}\n", lines.join("\n"))).unwrap();
        let updated = if let Some(start) = original.find(BEGIN) {
            let end = start + original[start..].find(END).unwrap() + END.len();
            format!("{}{}{}", &original[..start], blocks, &original[end..])
        } else {
            format!("{original}\n### Producer-generated manifest samples\n\nThese TEST-ONLY samples use fixed Ed25519 and P-256 keys, a fixed clock and\nproposal ULID. Process epochs and report timestamps are normalized to fixed\nvalues after validating their wire types. Regenerate only with\n`CK_EMIT_MANIFEST_VECTORS=1 cargo test --locked -p credentials-module\n--features credentials-core/test-support --bin ck-claustrum\nmanifest_binding_vectors_and_wire_goldens_are_producer_pinned`.\nThe writer also updates `tests/vectors/manifest-binding-v1.json` and its\n`SHA256SUMS` entry. No sample key is trusted outside tests.\n\n{blocks}\n")
        };
        std::fs::write(&doc, updated).unwrap();
    } else {
        assert_eq!(
            std::fs::read(&vectors).expect("generate manifest vectors"),
            bytes,
            "manifest vector bytes changed"
        );
        let sums = std::fs::read_to_string(&sums).unwrap();
        assert_eq!(
            sums.lines()
                .filter(|line| line.ends_with("  manifest-binding-v1.json"))
                .collect::<Vec<_>>(),
            vec![checksum.as_str()]
        );
        let start = original.find(BEGIN).expect("generate manifest goldens");
        let end = start + original[start..].find(END).unwrap() + END.len();
        assert_eq!(
            &original[start..end],
            blocks,
            "manifest golden bytes changed"
        );
    }
    let current = std::fs::read_to_string(doc).unwrap();
    let marker = "<!-- golden:manifest.";
    let mut ids: Vec<_> = current
        .match_indices(marker)
        .map(|(at, _)| {
            let rest = &current[at + marker.len()..];
            &rest[..rest.find(" -->").unwrap()]
        })
        .collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        samples.keys().map(String::as_str).collect::<Vec<_>>(),
        "every manifest golden must be checked exactly once"
    );
}
