// Wire-contract tests for the agent-secret surface (docs/wire-contract-v1.md §15).
//
// Included into the daemon's `tests` module so each test's full name is
// `tests::<name>`, which is how scripts/fast-check.py pins required protections.
//
// The §15 golden examples are the contract: every test below reads them from the doc,
// pins their key sets with literals written here (not derived from the vault), proves
// the vault's own parser accepts each golden request and refuses it with a key removed
// or added, and compares the vault's real reply against the golden reply's key set.
// Hosts and origins come only from the doc, so this file holds no URL literals.

const SECRET_CONTRACT_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/wire-contract-v1.md"
));
const SECRET_CONTRACT_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../credentials-core/tests/vectors/secret-approval-v1.json"
));
const SC_FP: &str = "11111111111111111111111111111111";
const SC_MEMBER: &str = "fed-computer:22222222222222222222222222222222";
const SC_UNKNOWN_REQUEST: &str = "00000000000000000000000000";

/// Every golden id the §15 text carries. `every_secret_golden_example_in_the_wire_contract_is_checked`
/// requires this list and the doc's markers to be the same set, so a golden added to the
/// doc without a test, or a test whose golden was deleted, fails.
const SECRET_GOLDEN_IDS: &[&str] = &[
    "phone_keys_register.request",
    "phone_keys_register.result",
    "deposit_keys.request",
    "deposit_keys.result",
    "deposit.request.api_key",
    "deposit.request.site_login",
    "deposit.result.stored",
    "deposit.result.already_stored",
    "approve.request",
    "approve.result",
    "list.request",
    "list.result",
    "delete.request.name",
    "delete.result.statement",
    "delete.request.signed",
    "delete.result",
    "revoke_grant.request",
    "revoke_grant.result",
    "use.request.api_key",
    "use.request.api_key.defaults",
    "use.request.site_login",
    "use.result.released.api_key",
    "use.result.released.site_login",
    "use.result.approval_required",
    "statement.use",
    "statement.delete",
    "envelope.allow",
    "envelope.delete",
    "error.result",
];

/// The raw JSON text of one `<!-- golden:<id> -->` block in §15.
fn secret_golden_text(id: &str) -> &'static str {
    let marker = format!("<!-- golden:{id} -->\n```json\n");
    let found: Vec<usize> = SECRET_CONTRACT_DOC
        .match_indices(&marker)
        .map(|(at, _)| at)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "docs/wire-contract-v1.md must carry golden `{id}` exactly once"
    );
    let start = found[0] + marker.len();
    let end = SECRET_CONTRACT_DOC[start..]
        .find("\n```")
        .unwrap_or_else(|| panic!("golden `{id}` has no closing fence"));
    &SECRET_CONTRACT_DOC[start..start + end]
}

fn secret_golden(id: &str) -> serde_json::Value {
    serde_json::from_str(secret_golden_text(id))
        .unwrap_or_else(|e| panic!("golden `{id}` is not JSON: {e}"))
}

/// Every object key path in `value`: `a`, `a.b`, and `a[].b` for objects inside arrays.
/// Arrays contribute the union of their elements, so one example can show an optional
/// key that only some elements carry.
fn secret_shape(value: &serde_json::Value) -> std::collections::BTreeSet<String> {
    fn walk(value: &serde_json::Value, prefix: &str, out: &mut std::collections::BTreeSet<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    out.insert(path.clone());
                    walk(child, &path, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, &format!("{prefix}[]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    walk(value, "", &mut out);
    out
}

fn secret_keys(paths: &str) -> std::collections::BTreeSet<String> {
    paths.split_whitespace().map(str::to_owned).collect()
}

/// The golden's key set equals the literal pinned here, which is written independently
/// of both the doc and the vault: renaming a field in either fails.
fn assert_secret_golden_shape(id: &str, pinned: &str) -> serde_json::Value {
    let golden = secret_golden(id);
    assert_eq!(
        secret_shape(&golden),
        secret_keys(pinned),
        "golden `{id}` changed its key set"
    );
    golden
}

/// The vault's real reply has exactly the golden's key set.
fn assert_secret_reply_matches(id: &str, reply: &serde_json::Value) {
    assert_eq!(
        secret_shape(reply),
        secret_shape(&secret_golden(id)),
        "the vault's reply differs in key set from golden `{id}`: {reply}"
    );
}

fn sc_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sc_unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn sc_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sc_unb64(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url")
}

fn sc_sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sc_hex(&sha2::Sha256::digest(bytes))
}

fn sc_now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn sc_answer(answer: crate::secret_phone::PhoneAnswer) -> serde_json::Value {
    match answer {
        crate::secret_phone::PhoneAnswer::Reply(value) => value,
        crate::secret_phone::PhoneAnswer::InvalidParams(_) => {
            json!({"transport":"invalid_params"})
        }
        crate::secret_phone::PhoneAnswer::PermissionsOperatorRequired => {
            json!({"transport":"permissions_operator_required"})
        }
    }
}

fn sc_use_answer(answer: crate::secret_use::UseAnswer) -> serde_json::Value {
    match answer {
        crate::secret_use::UseAnswer::Reply(value) => value,
        crate::secret_use::UseAnswer::InvalidParams => json!({"transport":"invalid_params"}),
    }
}

/// A test vault with this computer's member id, the deposit key and one phone
/// registered under pairing `pair-A`, driven through the phone transport with an
/// injected pairing lookup.
struct SecretFlow {
    _root: TestTempDir,
    store: Arc<EncryptedStore>,
    signer: p256::ecdsa::SigningKey,
    phone_pem: String,
    vault_pub: Vec<u8>,
    deposit_keys_reply: serde_json::Value,
    register_reply: serde_json::Value,
}

impl SecretFlow {
    async fn new(seed: u8) -> Self {
        let (_surface, store, _db, root) = tmp_surface_with_store(seed);
        store.ensure_secret_deposit_key().expect("deposit key");
        store
            .set_federation_self_member_audited(
                SC_MEMBER,
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .expect("self member");
        let signer = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).expect("signer");
        let phone_pem = credentials_core::kem::pem_from_scalar(&[3; 32]);
        let mut flow = SecretFlow {
            _root: root,
            store,
            signer,
            phone_pem,
            vault_pub: Vec::new(),
            deposit_keys_reply: json!(null),
            register_reply: json!(null),
        };
        flow.deposit_keys_reply = flow.phone("secret.deposit_keys", json!({})).await;
        flow.vault_pub = sc_unhex(
            flow.deposit_keys_reply["keys"][0]["pub"]
                .as_str()
                .expect("deposit key pub"),
        );
        flow.register_reply = flow
            .phone("secret.phone_keys_register", flow.register_request())
            .await;
        assert_eq!(flow.register_reply, json!({"status":"stored"}));
        flow
    }

    /// The golden registration request, carrying this test phone's real keys.
    fn register_request(&self) -> serde_json::Value {
        let mut request = secret_golden("phone_keys_register.request");
        let (deposit_pub, _) =
            credentials_core::kem::public_half(&self.phone_pem).expect("phone public key");
        request["deposit_pub"] = json!(sc_hex(&deposit_pub));
        request["approval_pub"] = json!(sc_hex(
            self.signer
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        ));
        request
    }

    async fn phone(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        sc_answer(
            crate::secret_phone::serve_with_lookup(
                Arc::clone(&self.store),
                SC_FP,
                method,
                &params,
                tokio::time::Instant::now() + crate::secret_phone::PHONE_OP_DEADLINE,
                async {
                    Some(json!({"devices":[{"class":"phone","fingerprint":SC_FP,"pairing_id":"pair-A"}]}))
                },
            )
            .await,
        )
    }

    /// Seal `material` to the vault's deposit key for the golden deposit request `id`.
    fn deposit_request(
        &self,
        id: &str,
        material: &credentials_core::agent_secret::SecretMaterial,
    ) -> serde_json::Value {
        use credentials_core::agent_secret::{self as secrets, SecretScope};
        let mut request = secret_golden(id);
        let text = |key: &str| request[key].as_str().expect("golden text").to_owned();
        let scope = if request["kind"] == "agent_api_key" {
            SecretScope::ApiKey {
                host: text("host"),
                path_prefix: request["path_prefix"].as_str().map(str::to_owned),
                location: text("location"),
            }
        } else {
            SecretScope::SiteLogin {
                origin: text("origin"),
            }
        };
        let aad = secrets::deposit_aad(
            &text("deposit_id"),
            &text("member_id"),
            &text("name"),
            &scope,
        )
        .expect("aad");
        let plaintext = secrets::deposit_plaintext(material);
        let (enc, ciphertext) = credentials_core::kem::seal_auth(
            &self.phone_pem,
            &self.vault_pub,
            plaintext.expose(),
            secrets::DEPOSIT_INFO,
            &aad,
        )
        .expect("seal deposit");
        request["enc_b64url"] = json!(sc_b64(&enc));
        request["ciphertext_b64url"] = json!(sc_b64(&ciphertext));
        request
    }

    async fn deposit_both(&self) -> (serde_json::Value, serde_json::Value) {
        use credentials_core::{agent_secret::SecretMaterial, secret::Secret};
        let api = self.deposit_request(
            "deposit.request.api_key",
            &SecretMaterial::ApiKey(Secret::new(b"sk-example".to_vec())),
        );
        let login = self.deposit_request(
            "deposit.request.site_login",
            &SecretMaterial::SiteLogin {
                username: Secret::new("alice".to_owned()),
                password: Secret::new("correct horse".to_owned()),
                otpauth: Some(Secret::new(
                    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_owned(),
                )),
            },
        );
        (
            self.phone("secret.deposit", api).await,
            self.phone("secret.deposit", login).await,
        )
    }

    fn use_secret(&self, sender: &str, params: &serde_json::Value) -> serde_json::Value {
        sc_use_answer(crate::secret_use::serve(
            &self.store,
            Some(&subc_protocol::Principal::Reserved {
                module_id: sender.into(),
            }),
            params,
            sc_now_ms,
        ))
    }

    /// The golden envelope with this flow's items and decision, signed by the registered
    /// approval key, inside the golden request `golden_request`. Starting from the golden
    /// envelope means a key renamed in the doc reaches the vault's strict parser.
    fn signed(
        &self,
        golden_request: &str,
        items: serde_json::Value,
        duration: &str,
        grant_expires_at_ms: i64,
        issued_at_ms: i64,
    ) -> serde_json::Value {
        use p256::ecdsa::signature::Signer as _;
        let decision = if duration == "none" {
            "delete"
        } else {
            "allow"
        };
        let mut envelope = secret_golden(if decision == "delete" {
            "envelope.delete"
        } else {
            "envelope.allow"
        });
        envelope["items"] = items;
        envelope["decision"] = json!(decision);
        envelope["duration"] = json!(duration);
        envelope["grant_expires_at_ms"] = json!(grant_expires_at_ms);
        envelope["device_fingerprint"] = json!(SC_FP);
        envelope["issued_at_ms"] = json!(issued_at_ms);
        // serde_json sorts object keys and these values are ASCII strings and small
        // integers, so this is the RFC 8785 canonical form the vault requires.
        let bytes = serde_json::to_vec(&envelope).expect("envelope bytes");
        let signature: p256::ecdsa::Signature = self.signer.sign(&bytes);
        let mut request = secret_golden(golden_request);
        request["envelope_b64url"] = json!(sc_b64(&bytes));
        request["signature_b64url"] = json!(sc_b64(signature.to_der().as_bytes()));
        request
    }

    async fn approve(
        &self,
        statement_reply: &serde_json::Value,
        duration: &str,
        with_unknown: bool,
    ) -> serde_json::Value {
        let mut items = vec![json!({
            "request_id": statement_reply["request_id"],
            "statement_sha256": sc_sha256_hex(&sc_unb64(
                statement_reply["statement_b64url"].as_str().expect("statement")
            )),
        })];
        if with_unknown {
            items.push(json!({"request_id":SC_UNKNOWN_REQUEST,"statement_sha256":"0".repeat(64)}));
        }
        let issued = sc_now_ms();
        let expiry = match duration {
            "hour" => issued + 3_600_000,
            "permanent" => 0,
            other => panic!("unsupported test duration {other}"),
        };
        let request = self.signed("approve.request", json!(items), duration, expiry, issued);
        self.phone("secret.approve", request).await
    }

    /// Deposit both kinds, ask for both, approve both, and release both once.
    async fn granted_and_used(&self) -> (serde_json::Value, serde_json::Value) {
        self.deposit_both().await;
        let api_statement = self.use_secret("aft", &secret_golden("use.request.api_key"));
        let login_statement =
            self.use_secret("cerebellum", &secret_golden("use.request.site_login"));
        let approved = self.approve(&api_statement, "permanent", false).await;
        assert_eq!(approved["results"][0]["outcome"], "granted", "{approved}");
        let approved = self.approve(&login_statement, "hour", false).await;
        assert_eq!(approved["results"][0]["outcome"], "granted", "{approved}");
        (
            self.use_secret("aft", &secret_golden("use.request.api_key")),
            self.use_secret("cerebellum", &secret_golden("use.request.site_login")),
        )
    }
}

/// The phone parser accepts the golden request; refuses it with any required key
/// removed, any key renamed, or an unknown key added; and still accepts it with each
/// optional key removed.
fn assert_phone_request_key_set_is_closed(
    method: &str,
    golden: &serde_json::Value,
    optional: &[&str],
) {
    use credentials_core::agent_secret::SecretError;
    let parse = |params: &serde_json::Value| crate::secret_phone::parse(method, params);
    assert!(parse(golden).is_ok(), "{method} refused its golden request");
    let object = golden.as_object().expect("request object");
    for key in object.keys() {
        let mut without = golden.clone();
        without.as_object_mut().unwrap().remove(key);
        if optional.contains(&key.as_str()) {
            assert!(
                parse(&without).is_ok(),
                "{method} must accept {key} omitted"
            );
        } else {
            assert!(
                matches!(parse(&without), Err(SecretError::InvalidParams)),
                "{method} must refuse a request without {key}"
            );
        }
        let mut renamed = without.clone();
        renamed[format!("{key}_renamed")] = object[key].clone();
        assert!(
            matches!(parse(&renamed), Err(SecretError::InvalidParams)),
            "{method} must refuse {key} under another name"
        );
    }
    let mut extra = golden.clone();
    extra["unexpected"] = json!(true);
    assert!(
        matches!(parse(&extra), Err(SecretError::InvalidParams)),
        "{method} must refuse an unknown key"
    );
}

#[tokio::test]
async fn secret_phone_keys_register_request_and_result_key_sets_match_the_contract() {
    let golden =
        assert_secret_golden_shape("phone_keys_register.request", "deposit_pub approval_pub");
    assert_phone_request_key_set_is_closed("secret.phone_keys_register", &golden, &[]);
    assert_secret_golden_shape("phone_keys_register.result", "status");
    let flow = SecretFlow::new(201).await;
    assert_secret_reply_matches("phone_keys_register.result", &flow.register_reply);
    let again = flow
        .phone("secret.phone_keys_register", flow.register_request())
        .await;
    assert_eq!(again, json!({"status":"already_stored"}));
    assert_secret_reply_matches("phone_keys_register.result", &again);
}

#[tokio::test]
async fn secret_deposit_keys_request_and_result_key_sets_match_the_contract() {
    let golden = assert_secret_golden_shape("deposit_keys.request", "");
    assert_phone_request_key_set_is_closed("secret.deposit_keys", &golden, &[]);
    assert_secret_golden_shape(
        "deposit_keys.result",
        "member_id keys keys[].state keys[].key_id keys[].pub",
    );
    let flow = SecretFlow::new(202).await;
    assert_secret_reply_matches("deposit_keys.result", &flow.deposit_keys_reply);
    assert_eq!(flow.deposit_keys_reply["member_id"], SC_MEMBER);
}

#[tokio::test]
async fn secret_deposit_request_and_result_key_sets_match_the_contract() {
    let api = assert_secret_golden_shape(
        "deposit.request.api_key",
        "deposit_id member_id name kind host path_prefix location enc_b64url ciphertext_b64url",
    );
    assert_phone_request_key_set_is_closed("secret.deposit", &api, &["path_prefix"]);
    let login = assert_secret_golden_shape(
        "deposit.request.site_login",
        "deposit_id member_id name kind origin enc_b64url ciphertext_b64url",
    );
    assert_phone_request_key_set_is_closed("secret.deposit", &login, &[]);
    // A login deposit never carries the API-key scope keys, nor an API key the login one.
    for (golden, foreign) in [(&login, "host"), (&login, "location"), (&api, "origin")] {
        let mut mixed = golden.clone();
        mixed[foreign] = api.get(foreign).or(login.get(foreign)).unwrap().clone();
        assert!(crate::secret_phone::parse("secret.deposit", &mixed).is_err());
    }
    assert_secret_golden_shape("deposit.result.stored", "status incarnation");
    assert_secret_golden_shape("deposit.result.already_stored", "status");

    let flow = SecretFlow::new(203).await;
    let (api_reply, login_reply) = flow.deposit_both().await;
    assert_eq!(api_reply["status"], "stored", "{api_reply}");
    assert_eq!(login_reply["status"], "stored", "{login_reply}");
    assert_secret_reply_matches("deposit.result.stored", &api_reply);
    assert_secret_reply_matches("deposit.result.stored", &login_reply);
    // The incarnation is 32 lowercase hex, as the golden shows.
    assert_eq!(api_reply["incarnation"].as_str().unwrap().len(), 32);
    use credentials_core::{agent_secret::SecretMaterial, secret::Secret};
    let first = flow.deposit_request(
        "deposit.request.api_key",
        &SecretMaterial::ApiKey(Secret::new(b"sk-example".to_vec())),
    );
    // A fresh seal under the stored deposit id has a different digest: conflict.
    let conflict = flow.phone("secret.deposit", first).await;
    assert_eq!(
        conflict,
        credentials_core::agent_secret::SecretError::DepositConflict.body()
    );
}

#[tokio::test]
async fn secret_deposit_retry_answers_the_already_stored_key_set() {
    let flow = SecretFlow::new(204).await;
    use credentials_core::{agent_secret::SecretMaterial, secret::Secret};
    let request = flow.deposit_request(
        "deposit.request.api_key",
        &SecretMaterial::ApiKey(Secret::new(b"sk-example".to_vec())),
    );
    assert_eq!(
        flow.phone("secret.deposit", request.clone()).await["status"],
        "stored"
    );
    let retry = flow.phone("secret.deposit", request).await;
    assert_eq!(retry, json!({"status":"already_stored"}));
    assert_secret_reply_matches("deposit.result.already_stored", &retry);
}

#[tokio::test]
async fn secret_use_request_and_result_key_sets_match_the_contract() {
    let stamp = "stamp stamp.owner stamp.owner.kind stamp.owner.module_id stamp.ref \
                 stamp.scope_epoch stamp.kind stamp.attributes stamp.attributes.agent_id \
                 stamp.owner_authorized";
    let api = assert_secret_golden_shape(
        "use.request.api_key",
        &format!("name coverage {stamp} target target.scheme target.host target.port target.path"),
    );
    let defaults = assert_secret_golden_shape(
        "use.request.api_key.defaults",
        &format!("name {stamp} target target.scheme target.host target.path"),
    );
    let login = assert_secret_golden_shape(
        "use.request.site_login",
        &format!(
            "name {stamp} stamp.parent stamp.parent.owner stamp.parent.owner.kind \
             stamp.parent.owner.module_id stamp.parent.ref stamp.parent.scope_epoch \
             stamp.parent_state target target.origin"
        ),
    );
    // The golden stamps are real subc ScopeStamps.
    for golden in [&api, &defaults, &login] {
        serde_json::from_value::<subc_protocol::scope::ScopeStamp>(golden["stamp"].clone())
            .expect("golden stamp decodes as subc's ScopeStamp");
    }
    assert_secret_golden_shape(
        "use.result.released.api_key",
        "status kind key_b64url location",
    );
    assert_secret_golden_shape(
        "use.result.released.site_login",
        "status kind username password totp",
    );
    assert_secret_golden_shape(
        "use.result.approval_required",
        "status request_id statement_b64url expires_at_ms",
    );

    let flow = SecretFlow::new(205).await;
    flow.deposit_both().await;
    let asked = flow.use_secret("aft", &api);
    assert_eq!(asked["status"], "approval_required", "{asked}");
    assert_secret_reply_matches("use.result.approval_required", &asked);
    // Omitting coverage and port is the same call, so it reuses the same request.
    assert_eq!(flow.use_secret("aft", &defaults), asked);
    let login_asked = flow.use_secret("cerebellum", &login);
    assert_eq!(login_asked["status"], "approval_required", "{login_asked}");
    assert_secret_reply_matches("use.result.approval_required", &login_asked);

    // The key set is closed: each required key removed, any key renamed, an unknown
    // key, and a caller-supplied agent name are refused at grammar.
    let invalid = json!({"transport":"invalid_params"});
    let object = api.as_object().unwrap().clone();
    for key in object.keys() {
        let mut without = api.clone();
        without.as_object_mut().unwrap().remove(key);
        let answer = flow.use_secret("aft", &without);
        if key == "coverage" {
            assert_eq!(answer, asked, "coverage defaults to scope");
        } else {
            assert_eq!(answer, invalid, "secret.use without {key}");
        }
        let mut renamed = without.clone();
        renamed[format!("{key}_renamed")] = object[key].clone();
        assert_eq!(flow.use_secret("aft", &renamed), invalid, "{key} renamed");
    }
    for extra in ["unexpected", "display_name"] {
        let mut params = api.clone();
        params[extra] = json!("Alice");
        assert_eq!(flow.use_secret("aft", &params), invalid, "{extra}");
    }
    for key in ["scheme", "host", "path"] {
        let mut params = api.clone();
        params["target"].as_object_mut().unwrap().remove(key);
        assert_eq!(
            flow.use_secret("aft", &params),
            invalid,
            "target without {key}"
        );
    }
    let mut params = api.clone();
    params["target"]["unexpected"] = json!(1);
    assert_eq!(flow.use_secret("aft", &params), invalid);
    let mut params = login.clone();
    params["target"]["host"] = api["target"]["host"].clone();
    assert_eq!(flow.use_secret("cerebellum", &params), invalid);
    // A stamp missing a field the mapping needs is the uniform refusal, not grammar.
    let not_found = credentials_core::agent_secret::SecretError::NotFound.body();
    for key in ["owner", "ref", "scope_epoch", "kind", "owner_authorized"] {
        let mut params = api.clone();
        params["stamp"].as_object_mut().unwrap().remove(key);
        assert_eq!(
            flow.use_secret("aft", &params),
            not_found,
            "stamp without {key}"
        );
    }

    let approved = flow.approve(&asked, "permanent", false).await;
    assert_eq!(approved["results"][0]["outcome"], "granted", "{approved}");
    let approved = flow.approve(&login_asked, "hour", false).await;
    assert_eq!(approved["results"][0]["outcome"], "granted", "{approved}");
    let released = flow.use_secret("aft", &api);
    assert_eq!(released["status"], "released", "{released}");
    assert_secret_reply_matches("use.result.released.api_key", &released);
    assert_eq!(
        released["location"],
        api_location(),
        "location comes from the record"
    );
    let released = flow.use_secret("cerebellum", &login);
    assert_eq!(released["status"], "released", "{released}");
    assert_secret_reply_matches("use.result.released.site_login", &released);
}

fn api_location() -> serde_json::Value {
    secret_golden("deposit.request.api_key")["location"].clone()
}

#[tokio::test]
async fn secret_approve_request_and_result_key_sets_match_the_contract() {
    let golden = assert_secret_golden_shape(
        "approve.request",
        "envelope_b64url signature_b64url card_ref",
    );
    assert_phone_request_key_set_is_closed("secret.approve", &golden, &["card_ref"]);
    assert_secret_golden_shape(
        "approve.result",
        "results results[].request_id results[].outcome results[].code",
    );
    let flow = SecretFlow::new(206).await;
    flow.deposit_both().await;
    let asked = flow.use_secret("aft", &secret_golden("use.request.api_key"));
    let reply = flow.approve(&asked, "permanent", true).await;
    assert_eq!(
        reply,
        json!({"results":[
            {"request_id":asked["request_id"],"outcome":"granted"},
            {"request_id":SC_UNKNOWN_REQUEST,"outcome":"refused","code":"approval_invalid"},
        ]})
    );
    assert_secret_reply_matches("approve.result", &reply);
}

#[tokio::test]
async fn secret_list_request_and_result_key_sets_match_the_contract() {
    let golden = assert_secret_golden_shape("list.request", "");
    assert_phone_request_key_set_is_closed("secret.list", &golden, &[]);
    assert_secret_golden_shape(
        "list.result",
        "secrets secrets[].name secrets[].kind secrets[].incarnation secrets[].state \
         secrets[].host secrets[].path_prefix secrets[].location secrets[].origin \
         secrets[].grants secrets[].grants[].grant_id secrets[].grants[].scope \
         secrets[].grants[].scope.owner secrets[].grants[].scope.kind \
         secrets[].grants[].scope.ref secrets[].grants[].coverage \
         secrets[].grants[].duration secrets[].grants[].expires_at_ms \
         secrets[].grants[].last_use_ms",
    );
    let flow = SecretFlow::new(207).await;
    flow.granted_and_used().await;
    let listed = flow.phone("secret.list", json!({})).await;
    assert_secret_reply_matches("list.result", &listed);
    // The permanent grant omits its expiry; the hour grant carries one.
    let grants: Vec<&serde_json::Value> = listed["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|secret| &secret["grants"][0])
        .collect();
    for grant in grants {
        assert_eq!(
            grant.get("expires_at_ms").is_some(),
            grant["duration"] != "permanent",
            "{grant}"
        );
    }
}

#[tokio::test]
async fn secret_delete_request_and_result_key_sets_match_the_contract() {
    let name = assert_secret_golden_shape("delete.request.name", "name");
    assert_phone_request_key_set_is_closed("secret.delete", &name, &[]);
    let signed =
        assert_secret_golden_shape("delete.request.signed", "envelope_b64url signature_b64url");
    assert_phone_request_key_set_is_closed("secret.delete", &signed, &[]);
    // A card_ref belongs to approve only.
    let mut with_card = signed.clone();
    with_card["card_ref"] = json!("card-1");
    assert!(crate::secret_phone::parse("secret.delete", &with_card).is_err());
    assert_secret_golden_shape(
        "delete.result.statement",
        "status request_id statement_b64url expires_at_ms",
    );
    assert_secret_golden_shape(
        "delete.result",
        "results results[].request_id results[].outcome",
    );

    let flow = SecretFlow::new(208).await;
    flow.deposit_both().await;
    let step_one = flow.phone("secret.delete", name).await;
    assert_eq!(step_one["status"], "approval_required", "{step_one}");
    assert_secret_reply_matches("delete.result.statement", &step_one);
    let statement: serde_json::Value =
        serde_json::from_slice(&sc_unb64(step_one["statement_b64url"].as_str().unwrap())).unwrap();
    assert_secret_reply_matches("statement.delete", &statement);
    let items = json!([{
        "request_id": step_one["request_id"],
        "statement_sha256": sc_sha256_hex(&sc_unb64(step_one["statement_b64url"].as_str().unwrap())),
    }]);
    let request = flow.signed(
        "delete.request.signed",
        items,
        "none",
        step_one["expires_at_ms"].as_i64().unwrap(),
        sc_now_ms(),
    );
    let step_two = flow.phone("secret.delete", request).await;
    assert_eq!(
        step_two,
        json!({"results":[{"request_id":step_one["request_id"],"outcome":"granted"}]})
    );
    assert_secret_reply_matches("delete.result", &step_two);
}

#[tokio::test]
async fn secret_revoke_grant_request_and_result_key_sets_match_the_contract() {
    let golden = assert_secret_golden_shape("revoke_grant.request", "grant_id");
    assert_phone_request_key_set_is_closed("secret.revoke_grant", &golden, &[]);
    assert_secret_golden_shape("revoke_grant.result", "outcome");
    let flow = SecretFlow::new(209).await;
    flow.granted_and_used().await;
    let listed = flow.phone("secret.list", json!({})).await;
    let mut request = golden.clone();
    request["grant_id"] = listed["secrets"][0]["grants"][0]["grant_id"].clone();
    let revoked = flow.phone("secret.revoke_grant", request.clone()).await;
    assert_eq!(revoked, json!({"outcome":"revoked"}));
    assert_secret_reply_matches("revoke_grant.result", &revoked);
    let again = flow.phone("secret.revoke_grant", request).await;
    assert_eq!(again, json!({"outcome":"not_found"}));
    assert_secret_reply_matches("revoke_grant.result", &again);
}

/// The signed byte layouts in §15 equal the pinned phone-app (iOS) test vectors byte for
/// byte, and the statement the vault really issues has the golden statement's key set.
#[tokio::test]
async fn secret_statement_and_envelope_key_sets_match_the_contract_and_the_pinned_vectors() {
    assert_secret_golden_shape(
        "statement.use",
        "v request_id member_id scope scope.owner scope.kind scope.ref scope.epoch agent_id \
         coverage secret secret.name secret.kind secret.incarnation use use.host \
         use.path_prefix use.location durations request_expires_at_ms",
    );
    assert_secret_golden_shape(
        "statement.delete",
        "v request_id member_id secret secret.name secret.kind secret.incarnation \
         request_expires_at_ms",
    );
    let envelope = "v items items[].request_id items[].statement_sha256 decision duration \
                    grant_expires_at_ms device_fingerprint issued_at_ms";
    assert_secret_golden_shape("envelope.allow", envelope);
    assert_secret_golden_shape("envelope.delete", envelope);

    let vectors: serde_json::Value =
        serde_json::from_str(SECRET_CONTRACT_VECTORS).expect("pinned vectors");
    let case = |name: &str| {
        vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["case"] == name)
            .unwrap_or_else(|| panic!("vector case {name}"))
            .clone()
    };
    let decoded = |b64: &serde_json::Value| {
        String::from_utf8(sc_unb64(b64.as_str().unwrap())).expect("UTF-8")
    };
    let approval = case("approval");
    let delete = case("delete");
    assert_eq!(
        secret_golden_text("statement.use"),
        decoded(&approval["statements"][0]["statement_b64url"])
    );
    assert_eq!(
        secret_golden_text("envelope.allow"),
        decoded(&approval["envelope_b64url"])
    );
    assert_eq!(
        secret_golden_text("statement.delete"),
        decoded(&delete["statements"][0]["statement_b64url"])
    );
    assert_eq!(
        secret_golden_text("envelope.delete"),
        decoded(&delete["envelope_b64url"])
    );
    let approve = secret_golden("approve.request");
    assert_eq!(approve["envelope_b64url"], approval["envelope_b64url"]);
    assert_eq!(approve["signature_b64url"], approval["signature_b64url"]);
    let signed_delete = secret_golden("delete.request.signed");
    assert_eq!(signed_delete["envelope_b64url"], delete["envelope_b64url"]);
    assert_eq!(
        signed_delete["signature_b64url"],
        delete["signature_b64url"]
    );
    assert_eq!(
        secret_golden("use.result.approval_required")["statement_b64url"],
        approval["statements"][0]["statement_b64url"]
    );
    assert_eq!(
        secret_golden("delete.result.statement")["statement_b64url"],
        delete["statements"][0]["statement_b64url"]
    );

    // The statement the vault issues today has the golden's key set, with the agent
    // named by the stamp's agent id.
    let flow = SecretFlow::new(210).await;
    flow.deposit_both().await;
    let use_request = secret_golden("use.request.api_key");
    let asked = flow.use_secret("aft", &use_request);
    let statement: serde_json::Value =
        serde_json::from_slice(&sc_unb64(asked["statement_b64url"].as_str().unwrap())).unwrap();
    assert_secret_reply_matches("statement.use", &statement);
    assert_eq!(
        statement["agent_id"],
        use_request["stamp"]["attributes"]["agent_id"]
    );
    let login = flow.use_secret("cerebellum", &secret_golden("use.request.site_login"));
    let statement: serde_json::Value =
        serde_json::from_slice(&sc_unb64(login["statement_b64url"].as_str().unwrap())).unwrap();
    assert_eq!(
        statement["use"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec!["origin"],
        "a login statement's use object is the origin alone"
    );
}

#[test]
fn every_secret_golden_example_in_the_wire_contract_is_checked() {
    let marker = "<!-- golden:";
    let in_doc: std::collections::BTreeSet<&str> = SECRET_CONTRACT_DOC
        .match_indices(marker)
        .map(|(at, _)| {
            let rest = &SECRET_CONTRACT_DOC[at + marker.len()..];
            &rest[..rest.find(" -->").expect("golden marker end")]
        })
        .collect();
    let checked: std::collections::BTreeSet<&str> = SECRET_GOLDEN_IDS.iter().copied().collect();
    assert_eq!(
        in_doc, checked,
        "§15 goldens and the checked list must agree"
    );
    assert!(
        in_doc.len() >= 20,
        "control: the marker scan found too few goldens"
    );
    for id in SECRET_GOLDEN_IDS {
        secret_golden(id);
    }
}

/// One row per `SecretError` variant: its wire code, class and refusal form. Written
/// once and expanded into an exhaustive `match`, so a new variant does not compile
/// until it has a row here.
macro_rules! secret_error_golden {
    ($($variant:ident => $code:literal, $class:literal, $form:literal;)*) => {
        const SECRET_ERROR_GOLDEN: &[(credentials_core::agent_secret::SecretError, &str, &str, &str)] =
            &[$((credentials_core::agent_secret::SecretError::$variant, $code, $class, $form)),*];
        #[allow(dead_code)]
        fn every_secret_error_has_a_golden_row(error: credentials_core::agent_secret::SecretError) {
            match error {
                $(credentials_core::agent_secret::SecretError::$variant => {})*
            }
        }
    };
}

secret_error_golden! {
    InvalidParams => "invalid_params", "none", "transport Error";
    LimitExceeded => "limit_exceeded", "context_overflow", "result error";
    NotFound => "not_found", "permanent", "result error";
    PairingUnavailable => "pairing_unavailable", "transient", "result error";
    PhoneNotRegistered => "phone_not_registered", "permanent", "result error";
    PhoneKeyConflict => "phone_key_conflict", "permanent", "result error";
    DepositConflict => "deposit_conflict", "permanent", "result error";
    NameExists => "name_exists", "permanent", "result error";
    SecretSetupIncomplete => "secret_setup_incomplete", "permanent", "result error";
    ApprovalInvalid => "approval_invalid", "permanent", "result error, or the `code` of a refused `results` item";
    PendingLimit => "pending_limit", "transient", "result error";
    StoreError => "store_error", "transient", "result error";
}

/// The one secret-surface code that is not a `SecretError`: the provider refusal, which
/// `permissions/v1` defines as an Error body with no class.
const SECRET_PERMISSIONS_CODE: (&str, &str, &str) =
    ("permissions_operator_required", "none", "transport Error");

/// `(code, class, form)` for each row of §15's "Secret codes" table. Panics if the table
/// cannot be found, so a reorganised doc fails instead of checking nothing.
fn secret_doc_code_table() -> Vec<(String, String, String)> {
    let section = SECRET_CONTRACT_DOC
        .split("### Secret codes")
        .nth(1)
        .expect("wire contract lost its 'Secret codes' section");
    let rows: Vec<(String, String, String)> = section
        .lines()
        .skip_while(|line| !line.starts_with("| Code"))
        .skip(2)
        .take_while(|line| line.starts_with('|'))
        .filter_map(|line| {
            let cells: Vec<&str> = line
                .split(" | ")
                .map(|c| c.trim_matches(['|', ' ']))
                .collect();
            let code = cells.first()?.strip_prefix('`')?.strip_suffix('`')?;
            let class = cells.get(1)?.trim_matches('`');
            Some((code.to_owned(), class.to_owned(), cells.get(2)?.to_string()))
        })
        .collect();
    assert!(
        rows.len() >= 10,
        "the secret code table parsed to {} rows; the parser no longer matches the doc",
        rows.len()
    );
    rows
}

/// Every `SecretError` is pinned to its wire code, class and body, and §15's code table
/// lists exactly those codes plus the provider refusal, with the same class and form.
/// Removing a row from the doc, changing a class on either side, or adding a code only
/// one side knows fails here.
#[tokio::test]
async fn secret_error_codes_are_golden_and_match_the_doc_table() {
    for &(error, code, class, form) in SECRET_ERROR_GOLDEN {
        assert_eq!(error.code(), code, "{error:?} changed its wire code");
        if form == "transport Error" {
            continue;
        }
        assert_eq!(error.class(), class, "{error:?} changed its class");
        assert_eq!(
            error.body(),
            json!({"error":{"code":code,"class":class}}),
            "{error:?} changed its body"
        );
    }
    assert_eq!(
        credentials_core::agent_secret::SecretError::ApprovalInvalid.body(),
        secret_golden("error.result")
    );
    // The transport rows really leave the vault as transport errors: grammar on the
    // phone channel, and the provider refusal on a non-Cingulate route.
    let (_root, store) = {
        let (_surface, store, _db, root) = tmp_surface_with_store(211);
        (root, store)
    };
    assert!(matches!(
        crate::secret_phone::serve_with_lookup(
            store,
            SC_FP,
            "secret.list",
            &json!({"unexpected":true}),
            tokio::time::Instant::now() + crate::secret_phone::PHONE_OP_DEADLINE,
            async { None },
        )
        .await,
        crate::secret_phone::PhoneAnswer::InvalidParams(_)
    ));

    let table = secret_doc_code_table();
    let expected: Vec<(&str, &str, &str)> = SECRET_ERROR_GOLDEN
        .iter()
        .map(|&(_, code, class, form)| (code, class, form))
        .chain([SECRET_PERMISSIONS_CODE])
        .collect();
    for (code, class, form) in &expected {
        let rows: Vec<_> = table.iter().filter(|(c, _, _)| c == code).collect();
        assert_eq!(rows.len(), 1, "§15 must list `{code}` exactly once");
        assert_eq!(rows[0].1, *class, "§15 gives `{code}` another class");
        assert_eq!(rows[0].2, *form, "§15 gives `{code}` another refusal form");
    }
    for (code, _, _) in &table {
        assert!(
            expected.iter().any(|(c, _, _)| c == code),
            "§15 lists `{code}`, which the secret surface never produces"
        );
    }
}

/// What one cell of the §15 caller matrix answers.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SecretCell {
    Served,
    NotFound,
    InvalidParams,
    OperatorRequired,
}

/// One caller row of the §15 matrix: the route principal and, for callosum, the
/// opener harness.
#[derive(Clone, Copy)]
struct SecretMatrixRow {
    principal: &'static str,
    harness: &'static str,
}

fn secret_matrix_expected(
    row: SecretMatrixRow,
    member: federation::MappingGate,
    phone: federation::MappingGate,
) -> [SecretCell; 5] {
    use federation::MappingGate::{Off, On};
    use SecretCell::*;
    // Columns: phone ops, secret.use, permissions.*, credential get, scoped get.
    let refused = [NotFound, NotFound, OperatorRequired, NotFound, NotFound];
    let no_principal = [NotFound, NotFound, OperatorRequired, Served, NotFound];
    match (row.principal, row.harness) {
        ("callosum", "callosum-self") => [NotFound, NotFound, OperatorRequired, Served, Served],
        ("callosum", "fed-phone:11111111111111111111111111111111") => match (member, phone) {
            (On, On) => [Served, NotFound, OperatorRequired, InvalidParams, NotFound],
            (Off, _) => no_principal,
            _ => refused,
        },
        // A `fed-computer:` member channel (member On) refuses every op outside its
        // three federation ops as not_found before it looks at bearer params (§14), so
        // it answers like a refused channel here.
        ("callosum", _) => match member {
            Off => no_principal,
            _ => refused,
        },
        ("aft" | "cerebellum", _) => [NotFound, Served, OperatorRequired, Served, Served],
        ("cingulate", _) => [NotFound, NotFound, Served, Served, Served],
        ("direct", _) => [NotFound, NotFound, OperatorRequired, Served, NotFound],
        other => panic!("no expectation for {other:?}"),
    }
}

/// Every caller, gate combination and column of the §15 matrix through the real route
/// dispatcher, with the refusal bodies compared byte for byte against the doc's legend.
#[tokio::test]
async fn secret_caller_gate_and_op_matrix_matches_the_wire_contract() {
    use federation::MappingGate;
    let seed = 212;
    let (surface, store, db_path, _root) = tmp_surface_with_store(seed);
    let http = Arc::new(crate::test_support::NoHttp);
    let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    let mac = credentials_core::admin_auth::AdminMacKey::derive(&key);
    let vault_id = credentials_core::vault_id_for(db_path.parent().unwrap()).unwrap();
    let admin = Arc::new(admin_surface::AdminSurface::new(
        engine,
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        vault_id,
        key.key_id(),
    ));
    store
        .create(
            FORWARDED_TEST_ID,
            &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
        )
        .unwrap();
    for module in ["callosum", "aft", "cerebellum", "cingulate"] {
        store
            .create_read_grant_audited(
                "reserved",
                module,
                SelectorKind::Exact,
                FORWARDED_TEST_ID,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    let handle = mint_test_handle(&store, FORWARDED_TEST_ID);
    set_member_mapping(&store, true);
    store
        .set_secret_phone_mapping_audited(true, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
        .unwrap();

    // The refusal bodies are the ones the legend writes out.
    let legend = |label: &str| -> serde_json::Value {
        let line = SECRET_CONTRACT_DOC
            .lines()
            .find(|line| line.starts_with(&format!("* **{label}**")))
            .unwrap_or_else(|| panic!("§15 legend lost {label}"));
        let mut text = line.to_owned();
        let mut lines = SECRET_CONTRACT_DOC
            .lines()
            .skip_while(|l| *l != line)
            .skip(1);
        while !text.contains("}`") {
            text.push_str(lines.next().expect("legend continues").trim_start());
        }
        let json = text
            .split('`')
            .find(|part| part.starts_with('{'))
            .expect("legend JSON");
        serde_json::from_str(json).expect("legend JSON parses")
    };
    let not_found = (
        FrameType::Response,
        serde_json::to_vec(&legend("NF")).unwrap(),
    );
    assert_eq!(
        not_found.1,
        serde_json::to_vec(&uniform_not_found()).unwrap()
    );
    let operator_required = legend("POR");

    let rows = [
        ("callosum", "callosum-self"),
        ("callosum", "fed-phone:11111111111111111111111111111111"),
        ("callosum", "fed-phone:1111111111111111111111111111111A"),
        ("callosum", "fed-computer:22222222222222222222222222222222"),
        ("callosum", "fed-sim:abc"),
        ("aft", ""),
        ("cerebellum", ""),
        ("cingulate", ""),
        ("direct", ""),
    ];
    let gates = [MappingGate::On, MappingGate::Off, MappingGate::Unreadable];
    let mut cells = 0;
    for (principal_name, harness) in rows {
        let principal = if principal_name == "direct" {
            subc_protocol::Principal::Direct
        } else {
            reserved(principal_name)
        };
        for member in gates {
            for phone in gates {
                let caller = federation::ingress::map_route_caller_with_phone(
                    &principal, harness, member, phone,
                );
                let expected = secret_matrix_expected(
                    SecretMatrixRow {
                        principal: principal_name,
                        harness,
                    },
                    member,
                    phone,
                );
                let at = format!("{principal_name} {harness} member={member:?} phone={phone:?}");
                let call = |method: &'static str, params: serde_json::Value| {
                    let (surface, admin, caller) =
                        (Arc::clone(&surface), Arc::clone(&admin), caller.clone());
                    async move { sc_dispatch(&surface, &admin, caller, method, params).await }
                };
                let check_refusal = |cell: SecretCell,
                                     answer: &(FrameType, Vec<u8>),
                                     column: &str| match cell {
                    SecretCell::NotFound => assert_eq!(answer, &not_found, "{at} {column}"),
                    SecretCell::OperatorRequired => {
                        assert_eq!(answer.0, FrameType::Error, "{at} {column}");
                        let body: serde_json::Value = serde_json::from_slice(&answer.1).unwrap();
                        assert_eq!(body, operator_required, "{at} {column}");
                    }
                    SecretCell::InvalidParams => {
                        assert_eq!(answer.0, FrameType::Error, "{at} {column}");
                        let body: serde_json::Value = serde_json::from_slice(&answer.1).unwrap();
                        assert_eq!(body["code"], "invalid_params", "{at} {column}");
                        assert!(body.get("class").is_none(), "{at} {column}");
                    }
                    SecretCell::Served => unreachable!(),
                };

                // Seven phone ops.
                for op in crate::secret_phone::PHONE_OPS {
                    let answer = call(op, json!({})).await;
                    if expected[0] == SecretCell::Served {
                        assert_ne!(
                            answer, not_found,
                            "{at} {op} must reach the phone preflight"
                        );
                        if op == "secret.deposit_keys" {
                            let body: serde_json::Value =
                                serde_json::from_slice(&answer.1).unwrap();
                            assert_eq!(
                                body["result"]["error"]["code"], "secret_setup_incomplete",
                                "{at} {op}"
                            );
                        }
                    } else {
                        check_refusal(expected[0], &answer, op);
                    }
                }
                // secret.use: a sender reaches grammar, so empty params are invalid_params.
                let answer = call("secret.use", json!({})).await;
                if expected[1] == SecretCell::Served {
                    check_refusal(SecretCell::InvalidParams, &answer, "secret.use grammar");
                } else {
                    check_refusal(expected[1], &answer, "secret.use");
                }
                // permissions.list and permissions.revoke.
                for (method, params, served) in [
                    ("permissions.list", json!({}), json!({"grants":[]})),
                    (
                        "permissions.revoke",
                        json!({"id":"unknown"}),
                        json!({"outcome":"not_found"}),
                    ),
                ] {
                    let answer = call(method, params).await;
                    if expected[2] == SecretCell::Served {
                        assert_eq!(answer.0, FrameType::Response, "{at} {method}");
                        let body: serde_json::Value = serde_json::from_slice(&answer.1).unwrap();
                        assert_eq!(body, wrap_result(served), "{at} {method}");
                    } else {
                        check_refusal(expected[2], &answer, method);
                    }
                }
                // credential.get by handle and credential.get_scoped.
                for (column, method, params) in [
                    (3, OP_GET, json!({"handle": handle.clone()})),
                    (
                        4,
                        OP_GET_SCOPED,
                        json!({"credential_id": FORWARDED_TEST_ID}),
                    ),
                ] {
                    let answer = call(method, params).await;
                    if expected[column] == SecretCell::Served {
                        assert_eq!(answer.0, FrameType::Response, "{at} {method}");
                        let body: serde_json::Value = serde_json::from_slice(&answer.1).unwrap();
                        assert!(
                            body["result"].get("error").is_none(),
                            "{at} {method}: {body}"
                        );
                    } else {
                        check_refusal(expected[column], &answer, method);
                    }
                }
                cells += 1;
            }
        }
    }
    assert_eq!(
        cells,
        rows.len() * 9,
        "every row under every gate combination"
    );

    // Direct with the admin MAC reaches the permissions operations only through the
    // authenticated admin.op wrapper; without a valid MAC the wrapper refuses.
    admin.record_bind(77, subc_protocol::Principal::Direct);
    let signed_tag = |body: &str| {
        let admin_surface::AdminOutcome::Challenge { nonce_hex, .. } = admin.challenge(77) else {
            panic!("challenge refused");
        };
        let nonce: [u8; credentials_core::admin_auth::ADMIN_NONCE_LEN] =
            sc_unhex(&nonce_hex).try_into().expect("nonce length");
        sc_hex(&mac.sign(&credentials_core::admin_auth::TranscriptParts {
            vault_id: &vault_id,
            key_id: key.key_id(),
            nonce: &nonce,
            op_body: body.as_bytes(),
        }))
    };
    for body in [
        r#"{"op":"permissions.list","v":1}"#,
        r#"{"op":"permissions.revoke","v":1,"id":"unknown"}"#,
    ] {
        signed_tag(body);
        assert!(matches!(
            admin.execute(77, body.as_bytes(), &"00".repeat(32)).await,
            admin_surface::AdminOutcome::Refused(_)
        ));
        let tag = signed_tag(body);
        assert!(
            matches!(
                admin.execute(77, body.as_bytes(), &tag).await,
                admin_surface::AdminOutcome::Ok(_)
            ),
            "the MAC-authenticated operator is served {body}"
        );
    }
}

/// One request through `dispatch_route_request` for an explicit caller.
async fn sc_dispatch(
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    caller: federation::RouteCaller,
    method: &str,
    params: serde_json::Value,
) -> (FrameType, Vec<u8>) {
    let (writer, mut responses) = mpsc::channel(1);
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        1,
        1,
        1,
        serde_json::to_vec(&json!({ "method": method, "params": params })).expect("request"),
    )
    .expect("build request");
    dispatch_route_request(frame, &writer, surface, admin, caller)
        .await
        .expect("serve request");
    let reply = responses.recv().await.expect("route response");
    (reply.header.ty, reply.body)
}
