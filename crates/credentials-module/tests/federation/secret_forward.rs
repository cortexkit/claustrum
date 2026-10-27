//! Forwarded agent secrets across two vaults, with a real home behind the callosum
//! stand-in.
//!
//! A is the secret home (`secrets.home_member` = `self`): it holds an API key and a
//! site login, B's selector-free `secret_use` member grant and a registered phone. B is
//! a remote-role vault (`secrets.home_member` names A). B's local senders call B's own
//! `RemoteReader::route_secret_call`, exactly as the daemon does for an admitted
//! `secret.use`; B looks nothing up locally and forwards the call to A at
//! `fed:<fp>:claustrum`. A handler on the stand-in passes each forwarded request to A's
//! real `HomeVault` as the attested member B, unless the test scripted another answer
//! (a reply sealed to another key, or over an AAD with one field changed). So every
//! release is sealed by one vault and opened by the other over a real route.
//!
//! The phone's approval is a signed envelope applied to A's store, with A's virtual
//! clock, as A's phone transport applies it after its pairing lookup.
//!
//! Every test ends with the reply-custody check: no request B sent and no reply the
//! stand-in carried holds plaintext secret material, and no reply to an op the
//! production catalogue declares a mutate holds sealed material.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use claustrum_module_probe::federation::ingress::{
    secret_call_sha256, OP_REMOTE_TOKEN, OP_SECRET_REQUEST_FLOW_APPROVAL,
    OP_SECRET_REVOKE_FLOW_GRANTS, OP_SECRET_USE, OP_TRANSFER_DELIVER, SECRET_RELEASE_INFO,
};
use claustrum_module_probe::federation::remote_read::{
    fed_provider_module, SecretForwardAnswer, SecretRoute,
};
use claustrum_module_probe::federation::{
    management_surface, HomeAnswer, HomeVault, RemoteReader, RouteCall,
};
use credentials_core::agent_secret::{deposit_plaintext, SecretMaterial, SecretPut};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{MemberGrantOperation, MemberGrantSelector, VAULT_TRANSFER_ID};
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::secret::Secret;
use credentials_core::store::{EncryptedStore, PhoneOperation};
use p256::ecdsa::signature::Signer as _;
use serde_json::{json, Value};
use subc_protocol::Principal;

use crate::support::{
    catalogue_kind, production_catalogue, HomeStore, Ledger, OpKind, Reply, Responder,
    SharedCallosumStandIn, TwoVaults, VaultFixture, FAKE_ADAPTERS, TARGET_MODULE,
};

const PAIRING_B: &str = "pair-b";
const PAIRING_C: &str = "pair-c";
/// A third computer, paired with A and granted `secret_use` there, used where a test
/// needs a second asker.
const C_FINGERPRINT: &str = "5555666677778888999900001111aaaa";
/// A member id no vault in these tests holds.
const STRANGER: &str = "fed-computer:0000000000000000000000000000000e";
const PHONE_FP: &str = "44444444444444444444444444444444";
const PHONE_PAIRING: &str = "pair-phone";

/// The secret material A holds. Each value is long and distinctive, so finding it in a
/// recorded body cannot be a coincidence.
const API_KEY: &[u8] = b"sk-forwarded-canary-7f3a9c";
const USERNAME: &str = "forwarded-user-canary";
const PASSWORD: &str = "forwarded-password-canary-5b2e";
const OTPAUTH: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
const OTP_SEED: &str = "JBSWY3DPEHPK3PXP";
/// A key that A never holds: what a reply sealed by anyone but A's real release says.
const DECOY_KEY: &[u8] = b"sk-decoy-never-released";

const SECRET_HOME_SET: AuditOp = AuditOp::SecretHomeSet;

// ---------------------------------------------------------------------------------
// §15 goldens
// ---------------------------------------------------------------------------------

/// The wire contract that carries the §15 golden blocks, so the calls here are the
/// documented ones and not a shape this file invented.
const WIRE_CONTRACT: &str = include_str!("../../../../docs/wire-contract-v1.md");

fn golden(id: &str) -> Value {
    let marker = format!("<!-- golden:{id} -->\n```json\n");
    let start = WIRE_CONTRACT
        .find(&marker)
        .unwrap_or_else(|| panic!("golden `{id}` is missing from the wire contract"))
        + marker.len();
    let end = WIRE_CONTRACT[start..]
        .find("\n```")
        .unwrap_or_else(|| panic!("golden `{id}` has no closing fence"));
    serde_json::from_str(&WIRE_CONTRACT[start..start + end])
        .unwrap_or_else(|error| panic!("golden `{id}` is not JSON: {error}"))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex(&sha2::Sha256::digest(bytes))
}

fn not_found() -> Value {
    json!({"error":{"code":"not_found","class":"permanent"}})
}

fn error_code(reply: &Value) -> &str {
    reply["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a refusal, got {reply}"))
}

/// The statement an `approval_required` reply asks the phone to sign.
fn statement(reply: &Value) -> Value {
    assert_eq!(reply["status"], "approval_required", "{reply}");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(reply["statement_b64url"].as_str().expect("statement"))
        .expect("base64url statement");
    serde_json::from_slice(&bytes).expect("statement JSON")
}

// ---------------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------------

fn install_transfer_key(store: &EncryptedStore, member: &str) -> (String, Vec<u8>) {
    let pem = credentials_core::kem::generate_key().expect("transfer key");
    let (public, _) = credentials_core::kem::public_half(&pem).expect("public half");
    store
        .create_audited(
            VAULT_TRANSFER_ID,
            &VaultRecord::new_static(
                CredentialKind::KemKey,
                "operator",
                pem.clone().into_bytes(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .expect("transfer init");
    store
        .set_federation_self_member_audited(member, AuditCtx::admin(AuditOp::FederationSelfSet))
        .expect("self member");
    (pem, public)
}

fn put_secret(store: &EncryptedStore, put: SecretPut) {
    store
        .secret_put_audited(&put, "operator")
        .unwrap_or_else(|error| panic!("put {}: {error}", put.name));
}

fn api_key_put() -> SecretPut {
    SecretPut {
        kind: "agent_api_key".into(),
        name: "key".into(),
        host: Some("x.test".into()),
        path_prefix: Some("/repos/a".into()),
        location: Some("header:X-Api-Key".into()),
        origin: None,
        material_b64url: b64url(
            deposit_plaintext(&SecretMaterial::ApiKey(Secret::new(API_KEY.to_vec()))).expose(),
        ),
    }
}

fn site_login_put() -> SecretPut {
    SecretPut {
        kind: "site_login".into(),
        name: "login".into(),
        host: None,
        path_prefix: None,
        location: None,
        origin: Some("https://x.test".into()),
        material_b64url: b64url(
            deposit_plaintext(&SecretMaterial::SiteLogin {
                username: Secret::new(USERNAME.to_owned()),
                password: Secret::new(PASSWORD.to_owned()),
                otpauth: Some(Secret::new(OTPAUTH.to_owned())),
            })
            .expose(),
        ),
    }
}

/// A released plaintext that A never produced: a valid §15 `released` object, so a
/// reply that wrongly opened would hand it to the sender and the test would see it.
fn decoy_release() -> Value {
    json!({
        "status": "released",
        "kind": "agent_api_key",
        "key_b64url": b64url(DECOY_KEY),
        "location": "header:X-Api-Key",
    })
}

/// A `federation.secret_use` sealed reply carrying `plaintext`, sealed from `sender_pem`
/// to `recipient` over `aad` under the secret-release info.
fn sealed_reply(sender_pem: &str, recipient: &[u8], plaintext: &Value, aad: &str) -> Value {
    let (enc, ciphertext) = credentials_core::kem::seal_auth(
        sender_pem,
        recipient,
        &serde_json::to_vec(plaintext).unwrap(),
        SECRET_RELEASE_INFO,
        aad.as_bytes(),
    )
    .expect("seal");
    let b64 = base64::engine::general_purpose::STANDARD;
    json!({ "status": "sealed", "enc": b64.encode(enc), "ciphertext": b64.encode(ciphertext) })
}

// ---------------------------------------------------------------------------------
// Scripted home answers
// ---------------------------------------------------------------------------------

/// One field of the release AAD a scripted step changes.
#[derive(Clone, Copy, Debug)]
enum AadField {
    Requester,
    Home,
    Nonce,
    SecretName,
    CallSha256,
}

const AAD_FIELDS: [AadField; 5] = [
    AadField::Requester,
    AadField::Home,
    AadField::Nonce,
    AadField::SecretName,
    AadField::CallSha256,
];

/// `aad` with exactly one field's value replaced, every other byte (field order,
/// spacing) kept.
fn alter_aad(aad: &str, field: AadField) -> String {
    let parsed: Value = serde_json::from_str(aad).expect("aad JSON");
    let (key, replacement) = match field {
        AadField::Requester => ("requester", STRANGER.to_string()),
        AadField::Home => ("home", STRANGER.to_string()),
        AadField::Nonce => {
            let nonce = parsed["nonce"].as_str().unwrap();
            let flipped = if nonce.ends_with('0') { '1' } else { '0' };
            ("nonce", format!("{}{flipped}", &nonce[..nonce.len() - 1]))
        }
        // Another secret A holds, so the change names something real.
        AadField::SecretName => ("secret_name", "login".to_string()),
        AadField::CallSha256 => (
            "call_sha256",
            secret_call_sha256("aft", &json!({ "name": "key" })).unwrap(),
        ),
    };
    let old = format!("\"{key}\":\"{}\"", parsed[key].as_str().unwrap());
    assert_eq!(aad.matches(&old).count(), 1, "{key} appears once in {aad}");
    let altered = aad.replace(&old, &format!("\"{key}\":\"{replacement}\""));
    assert_ne!(altered, aad);
    altered
}

/// What the stand-in answers one forwarded `federation.secret_use` with.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// A's real answer to B's request.
    Forward,
    /// A's real answer to B's request with this AAD field changed on the way.
    AlterAtHome(AadField),
    /// A decoy release sealed by A's real key to B's real key, over B's AAD with this
    /// field changed.
    SealedOver(AadField),
    /// A decoy release sealed by A's real key over B's exact AAD, to a key that is not
    /// B's.
    SealedToAnotherKey,
}

type Script = Arc<Mutex<VecDeque<Step>>>;

/// Everything the `federation.secret_use` handler needs to answer as A, or as a
/// scripted forger holding A's key.
#[derive(Clone)]
struct HomeLine {
    home: Arc<HomeVault>,
    member: String,
    script: Script,
    home_pem: String,
    asker_public: Vec<u8>,
}

impl HomeLine {
    fn responder(self) -> Responder {
        Responder(Arc::new(move |params: Value| {
            let line = self.clone();
            Box::pin(async move { line.answer(params).await })
        }))
    }

    async fn answer(&self, mut params: Value) -> Reply {
        let step = self
            .script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Step::Forward);
        let aad = params["aad"].as_str().unwrap_or_default().to_string();
        match step {
            Step::Forward => self.serve(OP_SECRET_USE, &params).await,
            Step::AlterAtHome(field) => {
                params["aad"] = json!(alter_aad(&aad, field));
                self.serve(OP_SECRET_USE, &params).await
            }
            Step::SealedOver(field) => Reply::Ok(sealed_reply(
                &self.home_pem,
                &self.asker_public,
                &decoy_release(),
                &alter_aad(&aad, field),
            )),
            Step::SealedToAnotherKey => {
                let other = credentials_core::kem::generate_key().unwrap();
                let (other_public, _) = credentials_core::kem::public_half(&other).unwrap();
                Reply::Ok(sealed_reply(
                    &self.home_pem,
                    &other_public,
                    &decoy_release(),
                    &aad,
                ))
            }
        }
    }

    async fn serve(&self, method: &str, params: &Value) -> Reply {
        match self.home.serve(&self.member, method, params).await {
            HomeAnswer::Reply(body) => Reply::Ok(body),
            HomeAnswer::InvalidParams(_) => Reply::RouteRefusal("invalid_params".into()),
        }
    }
}

/// Route `method` calls on `callosum` to `home` as the attested `member`.
fn route_to_home(callosum: &SharedCallosumStandIn, method: &'static str, line: &HomeLine) {
    let line = line.clone();
    callosum.answer(
        TARGET_MODULE,
        method,
        Reply::Handler(Responder(Arc::new(move |params: Value| {
            let line = line.clone();
            Box::pin(async move { line.serve(method, &params).await })
        }))),
    );
}

// ---------------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------------

/// A computer other than B that also forwards to A: its own store, its own stand-in
/// connection (whose handler calls A as this member) and its own reader.
struct OtherAsker {
    member: String,
    callosum: SharedCallosumStandIn,
    _fixture: VaultFixture,
    _store: HomeStore,
    reader: Arc<RemoteReader>,
}

struct Rig {
    root: credentials_core::test_support::TestTempDir,
    vaults: TwoVaults,
    a: HomeStore,
    home: Arc<HomeVault>,
    home_pem: String,
    home_public: Vec<u8>,
    _b: HomeStore,
    reader: Arc<RemoteReader>,
    script: Script,
    phone: p256::ecdsa::SigningKey,
    /// Every TOTP code a test saw released, so the custody check can look for it.
    released_codes: Mutex<Vec<String>>,
}

fn reader_over(store: &HomeStore, fixture: &VaultFixture) -> Arc<RemoteReader> {
    let wall = fixture.clock.clone();
    let mono = fixture.clock.clone();
    let reader = RemoteReader::new(
        Arc::clone(&store.store),
        FAKE_ADAPTERS.iter().map(|name| name.to_string()),
    )
    .with_clocks(
        Arc::new(move || wall.wall_ms()),
        Arc::new(move || mono.mono_ms()),
    );
    assert!(reader.attach_outbound(fixture.outbound.clone()));
    Arc::new(reader)
}

impl Rig {
    async fn new(tag: &str) -> Self {
        let root = crate::support::temp_root(tag);
        let vaults = TwoVaults::new(&root).await;
        let home_id = vaults.home_member().to_string();
        let requester = vaults.requester_member().to_string();

        // A: the home, holding both secrets, B's grant and a registered phone.
        let a = HomeStore::open(&vaults.a.data_dir);
        let (home_pem, home_public) = install_transfer_key(&a.store, &home_id);
        a.store
            .set_secret_home_audited(Some("self"), AuditCtx::admin(SECRET_HOME_SET))
            .expect("home set self");
        a.store.ensure_secret_deposit_key().expect("deposit key");
        put_secret(&a.store, api_key_put());
        put_secret(&a.store, site_login_put());
        a.store
            .create_member_grant_audited(
                &requester,
                MemberGrantOperation::SecretUse,
                &MemberGrantSelector::None,
                PAIRING_B,
            )
            .expect("secret_use member grant");
        let phone = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).expect("signer");
        let now = vaults.a.clock.wall_ms();
        a.store
            .secret_phone_operation(
                PHONE_FP,
                Some(PHONE_PAIRING),
                now,
                &PhoneOperation::Register {
                    deposit_pub: vec![2; 32],
                    approval_pub: phone
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec(),
                },
                || true,
                || now,
            )
            .expect("phone registered");

        // B: a remote-role vault whose secrets live on A. It holds none itself.
        let b = HomeStore::open(&vaults.b.data_dir);
        let (_b_pem, b_public) = install_transfer_key(&b.store, &requester);
        b.store
            .set_secret_home_audited(Some(&home_id), AuditCtx::admin(SECRET_HOME_SET))
            .expect("home set A");

        vaults.callosum.set_pairing(&requester, Some(PAIRING_B));
        vaults
            .callosum
            .announce_peer_key(&requester, &hex(&b_public));
        vaults
            .callosum
            .announce_peer_key(&home_id, &hex(&home_public));

        let clock = vaults.a.clock.clone();
        let home = HomeVault::new(Arc::clone(&a.engine))
            .with_secret_clock(Arc::new(move || clock.wall_ms()));
        assert!(home.attach_outbound(vaults.a.outbound.clone()));
        let home = Arc::new(home);
        let script: Script = Arc::default();
        let line = HomeLine {
            home: Arc::clone(&home),
            member: requester.clone(),
            script: Arc::clone(&script),
            home_pem: home_pem.clone(),
            asker_public: b_public.clone(),
        };
        vaults.callosum.answer(
            TARGET_MODULE,
            OP_SECRET_USE,
            Reply::Handler(line.clone().responder()),
        );
        for method in [
            OP_SECRET_REQUEST_FLOW_APPROVAL,
            OP_SECRET_REVOKE_FLOW_GRANTS,
            "secret.home",
        ] {
            route_to_home(&vaults.callosum, method, &line);
        }
        let reader = reader_over(&b, &vaults.b);
        Self {
            root,
            vaults,
            a,
            home,
            home_pem,
            home_public,
            _b: b,
            reader,
            script,
            phone,
            released_codes: Mutex::default(),
        }
    }

    fn home_id(&self) -> String {
        self.vaults.home_member().to_string()
    }

    fn requester(&self) -> String {
        self.vaults.requester_member().to_string()
    }

    fn then(&self, step: Step) {
        self.script.lock().unwrap().push_back(step);
    }

    /// A sender call made on B, admitted and routed as B's daemon does.
    async fn on_b(&self, sender: &str, method: &str, params: &Value) -> Value {
        ask_through(&self.reader, sender, method, params).await
    }

    /// `secret.use` from `sender` on B.
    async fn use_on_b(&self, sender: &str, call: &Value) -> Value {
        let reply = self.on_b(sender, "secret.use", call).await;
        if let Some(code) = reply["totp"].as_str() {
            self.released_codes.lock().unwrap().push(code.to_string());
        }
        reply
    }

    /// The same `secret.use` made by `sender` on A itself, served from A's own store.
    fn use_on_home(&self, sender: &str, call: &Value) -> Value {
        let clock = self.vaults.a.clock.clone();
        match claustrum_module_probe::secret_use::serve(
            &self.a.store,
            Some(&Principal::Reserved {
                module_id: sender.into(),
            }),
            call,
            move || clock.wall_ms(),
        ) {
            claustrum_module_probe::secret_use::UseAnswer::Reply(reply) => reply,
            claustrum_module_probe::secret_use::UseAnswer::InvalidParams => {
                panic!("the home refused the call's params")
            }
        }
    }

    /// The phone signs an allow envelope for `request` with `duration` and sends it to
    /// A, at A's virtual time.
    fn approve(&self, request: &Value, duration: &str) -> Value {
        let statement_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(request["statement_b64url"].as_str().expect("statement"))
            .unwrap();
        let issued = self.vaults.a.clock.wall_ms();
        let expiry = match duration {
            "hour" => issued + 3_600_000,
            "permanent" => 0,
            other => panic!("no test duration {other}"),
        };
        // serde_json orders object keys, and every value here is an ASCII string or a
        // small integer, so these bytes are the canonical form the vault requires.
        let envelope = serde_json::to_vec(&json!({
            "v": "ck-secret-use-envelope/v1",
            "items": [{
                "request_id": request["request_id"],
                "statement_sha256": sha256_hex(&statement_bytes),
            }],
            "decision": "allow",
            "duration": duration,
            "grant_expires_at_ms": expiry,
            "device_fingerprint": PHONE_FP,
            "issued_at_ms": issued,
        }))
        .unwrap();
        let signature: p256::ecdsa::Signature = self.phone.sign(&envelope);
        self.a
            .store
            .secret_phone_operation(
                PHONE_FP,
                Some(PHONE_PAIRING),
                issued,
                &PhoneOperation::Approve {
                    envelope,
                    signature: signature.to_der().as_bytes().to_vec(),
                    card_ref: None,
                },
                || true,
                || issued,
            )
            .expect("approval applied")
    }

    /// Approve `request` and check the phone was told the grant was made.
    fn grant(&self, request: &Value, duration: &str) {
        let approved = self.approve(request, duration);
        assert_eq!(
            approved,
            json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]})
        );
    }

    /// The `federation.secret_use` replies the stand-in carried back to B, in order.
    fn secret_use_replies(&self) -> Vec<Value> {
        self.vaults
            .callosum
            .routed_replies()
            .into_iter()
            .filter(|reply| reply.method == OP_SECRET_USE)
            .map(|reply| reply.body)
            .collect()
    }

    /// A third computer that forwards to A with its own pairing and `secret_use` grant.
    async fn other_asker(&self) -> OtherAsker {
        let side = self.root.join("asker-c");
        std::fs::create_dir_all(&side).unwrap();
        let callosum = SharedCallosumStandIn::start(&side).await;
        let fixture = VaultFixture::new(&side, "vault-c", C_FINGERPRINT, &callosum);
        let member = fixture.member.member_id.clone();
        let store = HomeStore::open(&fixture.data_dir);
        let (_pem, public) = install_transfer_key(&store.store, &member);
        store
            .store
            .set_secret_home_audited(Some(&self.home_id()), AuditCtx::admin(SECRET_HOME_SET))
            .expect("home set A");
        // A asks the main stand-in about C's pairing and key, as it does for B.
        self.vaults.callosum.set_pairing(&member, Some(PAIRING_C));
        self.vaults
            .callosum
            .announce_peer_key(&member, &hex(&public));
        self.a
            .store
            .create_member_grant_audited(
                &member,
                MemberGrantOperation::SecretUse,
                &MemberGrantSelector::None,
                PAIRING_C,
            )
            .expect("secret_use grant for C");
        // C reads A's announced key from its own stand-in, and its calls reach A as C.
        callosum.announce_peer_key(&self.home_id(), &hex(&self.home_public));
        let line = HomeLine {
            home: Arc::clone(&self.home),
            member: member.clone(),
            script: Arc::default(),
            home_pem: self.home_pem.clone(),
            asker_public: public,
        };
        callosum.answer(
            TARGET_MODULE,
            OP_SECRET_USE,
            Reply::Handler(line.responder()),
        );
        let reader = reader_over(&store, &fixture);
        OtherAsker {
            member,
            callosum,
            _fixture: fixture,
            _store: store,
            reader,
        }
    }

    /// No request B (or another asker) sent and no reply the stand-ins carried holds
    /// plaintext secret material, and no reply to a mutate op holds sealed material.
    fn assert_reply_custody(&self, others: &[&SharedCallosumStandIn]) {
        let codes = self.released_codes.lock().unwrap().clone();
        let mut carried = 0;
        for callosum in std::iter::once(&self.vaults.callosum).chain(others.iter().copied()) {
            for row in callosum.ledger() {
                if let Ledger::Request { method, params, .. } = row {
                    assert_no_plaintext(&format!("request {method}"), &params, &codes);
                }
            }
            for reply in callosum.routed_replies() {
                carried += 1;
                let what = format!("{:?} reply to {}", reply.kind, reply.method);
                assert_no_plaintext(&what, &reply.body, &codes);
                if reply.kind == Some(OpKind::Mutate) {
                    assert_no_sealed_material(&what, &reply.body);
                }
            }
        }
        assert!(carried > 0, "the custody check saw no reply at all");
    }
}

/// Admit `sender`'s call to `method` as the daemon does and route it by the vault's
/// role, which forwards it to the home.
async fn ask_through(reader: &RemoteReader, sender: &str, method: &str, params: &Value) -> Value {
    let principal = Principal::Reserved {
        module_id: sender.into(),
    };
    let call = claustrum_module_probe::secret_use::sender_call(method, Some(&principal), params)
        .unwrap_or_else(|| panic!("{sender} is not admitted to {method}"));
    match reader.route_secret_call(call).await {
        SecretRoute::Answer(SecretForwardAnswer::Reply(reply)) => reply,
        SecretRoute::Answer(SecretForwardAnswer::InvalidParams) => {
            panic!("{method} from {sender} answered invalid_params")
        }
        SecretRoute::Local => panic!("a remote-role vault served {method} locally"),
    }
}

/// Fail if `body` holds any of the secrets' plaintext, under any key or encoding a
/// release uses, or a key that only a released object carries.
fn assert_no_plaintext(what: &str, body: &Value, codes: &[String]) {
    let text = body.to_string();
    for needle in [
        String::from_utf8(API_KEY.to_vec()).unwrap(),
        b64url(API_KEY),
        USERNAME.to_string(),
        PASSWORD.to_string(),
        OTP_SEED.to_string(),
    ] {
        assert!(
            !text.contains(&needle),
            "{what} holds secret material: {text}"
        );
    }
    walk(body, &mut |key, value| {
        if let Some(key) = key {
            assert!(
                !matches!(key, "key_b64url" | "username" | "password" | "totp"),
                "{what} carries `{key}` in the clear: {text}"
            );
        }
        if let Some(value) = value.as_str() {
            assert!(
                value != "released" && !codes.iter().any(|code| code == value),
                "{what} holds a released value: {text}"
            );
        }
    });
}

fn assert_no_sealed_material(what: &str, body: &Value) {
    let text = body.to_string();
    walk(body, &mut |key, value| {
        assert!(
            !matches!(key, Some("enc" | "ciphertext")) && value.as_str() != Some("sealed"),
            "{what} holds sealed material: {text}"
        );
    });
}

/// Visit every object member (with its key) and array element (with none) in `value`.
fn walk(value: &Value, visit: &mut dyn FnMut(Option<&str>, &Value)) {
    match value {
        Value::Object(members) => {
            for (key, child) in members {
                visit(Some(key), child);
                walk(child, visit);
            }
        }
        Value::Array(items) => {
            for item in items {
                visit(None, item);
                walk(item, visit);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------------
// The flows
// ---------------------------------------------------------------------------------

/// An AFT `secret.use` on B is answered `approval_required` with a v2 statement naming
/// A as the home and B as the asking computer. The phone's envelope, sent to A, grants
/// it, and B's retry is released with the key's exact bytes, opened from a sealed
/// `federation.secret_use` reply.
#[tokio::test]
async fn an_agent_key_asked_on_a_member_is_approved_on_the_home_and_released_sealed() {
    let rig = Rig::new("secret-forward-agent-key").await;
    let call = golden("use.request.api_key");

    let asked = rig.use_on_b("aft", &call).await;
    let asking = statement(&asked);
    assert_eq!(asking["v"], "ck-secret-use-statement/v2", "{asking}");
    assert_eq!(asking["member_id"], rig.home_id().as_str());
    assert_eq!(asking["asking_member_id"], rig.requester().as_str());
    assert_eq!(asking["secret"]["name"], "key");
    // B held nothing to decide with: the statement came from A, over the route.
    assert_eq!(rig.secret_use_replies(), vec![asked.clone()]);

    rig.grant(&asked, "permanent");
    let released = rig.use_on_b("aft", &call).await;
    assert_eq!(
        released,
        json!({
            "status": "released",
            "kind": "agent_api_key",
            "key_b64url": b64url(API_KEY),
            "location": "header:X-Api-Key",
        })
    );
    // It crossed sealed: the reply the stand-in carried is the sealed form only.
    let sealed = rig.secret_use_replies().pop().unwrap();
    let keys: Vec<&str> = sealed
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["ciphertext", "enc", "status"], "{sealed}");
    assert_eq!(sealed["status"], "sealed");
    rig.assert_reply_custody(&[]);
}

/// The same flow for Cerebellum's site login releases the username, the password and
/// the TOTP code for A's virtual time, and a later release follows A's clock.
#[tokio::test]
async fn a_site_login_asked_on_a_member_releases_the_totp_for_the_homes_time() {
    let rig = Rig::new("secret-forward-site-login").await;
    let call = golden("use.request.site_login");

    let asked = rig.use_on_b("cerebellum", &call).await;
    let asking = statement(&asked);
    assert_eq!(asking["v"], "ck-secret-use-statement/v2", "{asking}");
    assert_eq!(asking["member_id"], rig.home_id().as_str());
    assert_eq!(asking["asking_member_id"], rig.requester().as_str());
    rig.grant(&asked, "hour");

    let code_at = |now: i64| {
        credentials_core::agent_secret::totp(OTPAUTH, now)
            .unwrap()
            .expose()
            .to_string()
    };
    let first_time = rig.vaults.a.clock.wall_ms();
    let released = rig.use_on_b("cerebellum", &call).await;
    assert_eq!(
        released,
        json!({
            "status": "released",
            "kind": "site_login",
            "username": USERNAME,
            "password": PASSWORD,
            "totp": code_at(first_time),
        })
    );
    // B's own clock is far from A's; only A's virtual time decides the code.
    rig.vaults.b.clock.advance(7 * 86_400_000);
    rig.vaults.a.clock.advance(30_000);
    let later = rig.use_on_b("cerebellum", &call).await;
    let later_code = code_at(rig.vaults.a.clock.wall_ms());
    assert_ne!(
        later_code,
        code_at(first_time),
        "pick a time whose codes differ"
    );
    assert_eq!(later["totp"], later_code.as_str(), "{later}");
    rig.assert_reply_custody(&[]);
}

/// A release B cannot open, or one A refuses because the AAD names another request,
/// releases nothing: a reply sealed to another key, or over an AAD with a different
/// requester, home, nonce, secret name or `call_sha256`, is `remote_seal_invalid` at
/// B; an AAD changed on the way to A is refused there (`not_found` for another home,
/// secret name or call digest) or sealed over bytes B never sent.
#[tokio::test]
async fn a_release_bound_to_another_request_or_key_releases_nothing() {
    let rig = Rig::new("secret-forward-binding").await;
    let call = golden("use.request.api_key");
    let asked = rig.use_on_b("aft", &call).await;
    rig.grant(&asked, "permanent");
    assert_eq!(rig.use_on_b("aft", &call).await["status"], "released");

    let refused_with = |reply: &Value, code: &str, what: &str| {
        assert_eq!(error_code(reply), code, "{what}: {reply}");
        assert!(!reply.to_string().contains(&b64url(API_KEY)), "{what}");
        assert!(!reply.to_string().contains(&b64url(DECOY_KEY)), "{what}");
    };

    rig.then(Step::SealedToAnotherKey);
    let reply = rig.use_on_b("aft", &call).await;
    refused_with(&reply, "remote_seal_invalid", "sealed to another key");

    for field in AAD_FIELDS {
        rig.then(Step::SealedOver(field));
        let reply = rig.use_on_b("aft", &call).await;
        refused_with(
            &reply,
            "remote_seal_invalid",
            &format!("sealed over {field:?}"),
        );
    }

    for (field, code) in [
        (AadField::Home, "not_found"),
        (AadField::SecretName, "not_found"),
        (AadField::CallSha256, "not_found"),
        // A seals over the AAD it received, which is not the one B opens with.
        (AadField::Nonce, "remote_seal_invalid"),
        // A's requester check: the AAD must name the attested caller, which is B's own
        // setup to fix (the same check `federation.remote_token` makes).
        (AadField::Requester, "remote_setup_incomplete"),
    ] {
        rig.then(Step::AlterAtHome(field));
        let reply = rig.use_on_b("aft", &call).await;
        refused_with(&reply, code, &format!("{field:?} changed on the way to A"));
    }

    // Positive control: the grant still releases an unaltered request.
    assert_eq!(rig.use_on_b("aft", &call).await["status"], "released");
    rig.assert_reply_custody(&[]);
}

/// A grant belongs to the computer that asked. The same stamp on another member, or on
/// A itself, gets its own `approval_required` and no release; a pending request is
/// reused only for the same asker; and removing B's `secret_use` member grant, or
/// re-pairing B, refuses B with `not_found`.
#[tokio::test]
async fn a_grant_releases_only_to_the_computer_that_asked() {
    let rig = Rig::new("secret-forward-holder").await;
    let c = rig.other_asker().await;
    let call = golden("use.request.api_key");

    let b_asked = rig.use_on_b("aft", &call).await;
    let c_asked = ask_through(&c.reader, "aft", "secret.use", &call).await;
    let home_asked = rig.use_on_home("aft", &call);
    let ids = [&b_asked, &c_asked, &home_asked].map(|reply| {
        statement(reply);
        reply["request_id"].as_str().unwrap().to_string()
    });
    assert!(
        ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2],
        "each asker has its own request: {ids:?}"
    );
    assert_eq!(statement(&c_asked)["asking_member_id"], c.member.as_str());
    let local = statement(&home_asked);
    assert_eq!(local["v"], "ck-secret-use-statement/v1", "{local}");
    assert!(local.get("asking_member_id").is_none());
    // Asking again reuses each asker's own request, never another's.
    assert_eq!(
        rig.use_on_b("aft", &call).await["request_id"],
        ids[0].as_str()
    );
    assert_eq!(
        ask_through(&c.reader, "aft", "secret.use", &call).await["request_id"],
        ids[1].as_str()
    );

    rig.grant(&b_asked, "permanent");
    assert_eq!(rig.use_on_b("aft", &call).await["status"], "released");
    let c_again = ask_through(&c.reader, "aft", "secret.use", &call).await;
    assert_eq!(c_again["status"], "approval_required", "{c_again}");
    assert_eq!(c_again["request_id"], ids[1].as_str());
    let home_again = rig.use_on_home("aft", &call);
    assert_eq!(home_again["status"], "approval_required", "{home_again}");
    assert_eq!(home_again["request_id"], ids[2].as_str());

    // Without B's `secret_use` member grant, A refuses B outright.
    rig.a
        .store
        .revoke_member_grant_audited(
            &rig.requester(),
            MemberGrantOperation::SecretUse,
            &MemberGrantSelector::None,
        )
        .expect("revoke member grant");
    assert_eq!(rig.use_on_b("aft", &call).await, not_found());
    let regrant = |pairing: &str| {
        rig.a
            .store
            .create_member_grant_audited(
                &rig.requester(),
                MemberGrantOperation::SecretUse,
                &MemberGrantSelector::None,
                pairing,
            )
            .expect("member grant");
    };
    regrant(PAIRING_B);
    assert_eq!(rig.use_on_b("aft", &call).await["status"], "released");

    // Re-pairing B leaves its member grant under the old pairing, so A refuses B.
    rig.vaults
        .callosum
        .set_pairing(&rig.requester(), Some("pair-b-2"));
    assert_eq!(rig.use_on_b("aft", &call).await, not_found());
    regrant("pair-b-2");
    assert_eq!(rig.use_on_b("aft", &call).await["status"], "released");
    rig.assert_reply_custody(&[&c.callosum]);
}

/// The production catalogue declares `federation.secret_use` a query, the two flow
/// federation ops mutates and `secret.home` a query; the stand-in records each routed
/// reply under that kind. A's member route serves the three `federation.secret_*` ops
/// and refuses `secret.home` with the uniform `not_found`.
#[tokio::test]
async fn the_catalogue_kinds_hold_and_the_member_route_serves_only_the_secret_ops() {
    assert_eq!(catalogue_kind(OP_SECRET_USE), Some(OpKind::Query));
    assert_eq!(
        catalogue_kind(OP_SECRET_REQUEST_FLOW_APPROVAL),
        Some(OpKind::Mutate)
    );
    assert_eq!(
        catalogue_kind(OP_SECRET_REVOKE_FLOW_GRANTS),
        Some(OpKind::Mutate)
    );
    assert_eq!(catalogue_kind("secret.home"), Some(OpKind::Query));
    // Controls that the reader parsed the real list: kinds the earlier federation ops
    // were declared with, the local `secret.use` (a mutate, unlike its federation
    // form), and the catalogue's size.
    assert_eq!(catalogue_kind(OP_REMOTE_TOKEN), Some(OpKind::Query));
    assert_eq!(catalogue_kind(OP_TRANSFER_DELIVER), Some(OpKind::Mutate));
    assert_eq!(catalogue_kind("secret.use"), Some(OpKind::Mutate));
    assert!(
        production_catalogue().len() > 30,
        "{:?}",
        production_catalogue()
    );

    let rig = Rig::new("secret-forward-catalogue").await;
    let asked = rig.use_on_b("aft", &golden("use.request.api_key")).await;
    assert_eq!(statement(&asked)["v"], "ck-secret-use-statement/v2");

    let flow = rig
        .on_b(
            "basal",
            "secret.request_flow_approval",
            &golden("request_flow_approval.request.api_key"),
        )
        .await;
    let flow_statement = statement(&flow);
    assert_eq!(flow_statement["v"], "ck-secret-flow-statement/v2", "{flow}");
    assert_eq!(flow_statement["member_id"], rig.home_id().as_str());
    assert_eq!(flow_statement["asking_member_id"], rig.requester().as_str());
    let revoked = rig
        .on_b(
            "basal",
            "secret.revoke_flow_grants",
            &golden("revoke_flow_grants.request"),
        )
        .await;
    assert_eq!(revoked, json!({"status":"revoked","grants":0}));

    // `secret.home` is a phone op: A's member route refuses it, directly and over the
    // route from B.
    assert_eq!(
        rig.home
            .serve(&rig.requester(), "secret.home", &json!({}))
            .await,
        HomeAnswer::Reply(not_found())
    );
    let routed = rig
        .vaults
        .b
        .outbound
        .call(
            "secret-home-probe",
            RouteCall {
                target: management_surface(&fed_provider_module(&rig.home_id())),
                prelude: None,
                request: json!({ "method": "secret.home", "params": {} }),
            },
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("the route answers");
    assert_eq!(routed, not_found());

    let kinds: Vec<(String, Option<OpKind>)> = rig
        .vaults
        .callosum
        .routed_replies()
        .into_iter()
        .filter(|reply| !reply.method.starts_with("callosum."))
        .map(|reply| (reply.method, reply.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (OP_SECRET_USE.to_string(), Some(OpKind::Query)),
            (
                OP_SECRET_REQUEST_FLOW_APPROVAL.to_string(),
                Some(OpKind::Mutate)
            ),
            (
                OP_SECRET_REVOKE_FLOW_GRANTS.to_string(),
                Some(OpKind::Mutate)
            ),
            ("secret.home".to_string(), Some(OpKind::Query)),
        ]
    );
    rig.assert_reply_custody(&[]);
}

/// The custody check would fail on what it exists to catch: a released object in the
/// clear in any recorded body, and sealed material in a mutate reply.
#[test]
fn the_custody_check_finds_material_in_the_clear_and_sealed_mutate_replies() {
    let caught = |check: Box<dyn FnOnce() + std::panic::UnwindSafe>| {
        std::panic::catch_unwind(check).is_err()
    };
    assert!(caught(Box::new(|| assert_no_plaintext(
        "released",
        &json!({"status":"released","kind":"agent_api_key","key_b64url":b64url(API_KEY),"location":"x"}),
        &[],
    ))));
    assert!(caught(Box::new(|| assert_no_plaintext(
        "nested password",
        &json!({"result":{"note":PASSWORD}}),
        &[],
    ))));
    assert!(caught(Box::new(|| assert_no_plaintext(
        "a released code",
        &json!({"value":"123456"}),
        &["123456".to_string()],
    ))));
    assert!(caught(Box::new(|| assert_no_sealed_material(
        "sealed mutate",
        &json!({"status":"sealed","enc":"AA","ciphertext":"AA"}),
    ))));
    // And it passes what may cross: a sealed query reply, and an approval request.
    assert_no_plaintext(
        "sealed",
        &json!({"status":"sealed","enc":"AA","ciphertext":"AA"}),
        &[],
    );
    assert_no_sealed_material(
        "approval",
        &json!({"status":"approval_required","request_id":"r","statement_b64url":"s","expires_at_ms":1}),
    );
}
