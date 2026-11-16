#![cfg(feature = "test-support")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::agent_secret::{
    self, ApprovalEnvelope, ApprovalItem, AskingScope, SecretError, SecretMaterial, SecretPut,
    SecretScope, SecretSender, SecretUseByTarget, UseTarget,
};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::key::MasterKey;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::secret::Secret;
use credentials_core::store::{payload_hash, EncryptedStore, PhoneDeposit, PhoneOperation};
use credentials_core::test_support::TestTempDir;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

const NOW: i64 = 1_700_000_000_000;
const HOME: &str = "fed-computer:22222222222222222222222222222222";
const PHONE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEPOSIT_ID: &str = "01HF7YAT000000000000000001";
const REQUEST_ID: &str = "01HF7YAT000000000000000100";
const INCARNATION: &str = "000000000000000000000000000000ab";
const TOKEN: &[u8] = &[0, 255, b':', b'\n', b't', b'o', b'k', b'e', b'n'];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn signer() -> SigningKey {
    SigningKey::from_bytes((&[7; 32]).into()).unwrap()
}
fn scope(location: &str) -> SecretScope {
    SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: Some("/repos/a".into()),
        location: location.into(),
    }
}
fn material() -> SecretMaterial {
    SecretMaterial::ApiKey(Secret::new(TOKEN.to_vec()))
}
fn call() -> SecretUseByTarget {
    SecretUseByTarget {
        sender: SecretSender::Aft,
        scope: AskingScope {
            owner: "reserved:prefrontal-core".into(),
            kind: "head".into(),
            scope_ref: "H".into(),
            epoch: 7,
        },
        worker_parent: None,
        coverage: "scope".into(),
        agent_id: Some("agent-A".into()),
        target: UseTarget::ApiKey {
            scheme: "https".into(),
            host: "x.test".into(),
            port: 443,
            path: "/repos/a/project.git/info/refs".into(),
        },
    }
}
fn request(named: bool) -> Value {
    let mut value = json!({"stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"kind":"head","ref":"H","scope_epoch":7,"attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"scheme":"https","host":"x.test","path":"/repos/a/project.git/info/refs"}});
    if named {
        value["name"] = json!("git");
    }
    value
}
fn put(name: &str, location: &str) -> SecretPut {
    SecretPut {
        name: name.into(),
        kind: "agent_api_key".into(),
        host: Some("x.test".into()),
        path_prefix: Some("/repos/a".into()),
        location: Some(location.into()),
        origin: None,
        rules: None,
        origins: None,
        program: None,
        r#use: None,
        targets: None,
        material_b64url: URL_SAFE_NO_PAD
            .encode(agent_secret::deposit_plaintext(&material()).expose()),
    }
}

#[derive(Default)]
struct Pack {
    files: BTreeMap<String, Vec<u8>>,
}
impl Pack {
    fn bytes(&mut self, name: &str, bytes: &[u8]) -> Value {
        assert!(self.files.insert(name.into(), bytes.to_vec()).is_none());
        json!({"file":name,"b64url":URL_SAFE_NO_PAD.encode(bytes),"sha256":hex(&payload_hash(bytes))})
    }
    fn json(&mut self, name: &str, value: &Value) -> Value {
        let mut record = self.bytes(name, &serde_json::to_vec(value).unwrap());
        record["json"] = value.clone();
        record
    }
}

struct Rig {
    _root: TestTempDir,
    store: EncryptedStore,
    sql: Connection,
    master: MasterKey,
}
impl Rig {
    fn new() -> Self {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/scratch");
        std::fs::create_dir_all(&parent).unwrap();
        let root = TestTempDir::from_path(
            parent.join(format!("basic-auth-vectors-{}", std::process::id())),
        );
        let path = root.join("store.db");
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        EncryptedStore::migrate(&sqlite).unwrap();
        let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([29; 32])).unwrap();
        store
            .set_federation_self_member_audited(HOME, AuditCtx::admin(AuditOp::FederationSelfSet))
            .unwrap();
        store
            .create(
                agent_secret::DEPOSIT_KEY_ID,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "test",
                    credentials_core::kem::pem_from_scalar(&[9; 32]).into_bytes(),
                    None,
                ),
            )
            .unwrap();
        let rig = Self {
            _root: root,
            store,
            sql: Connection::open(path).unwrap(),
            master: MasterKey::from_bytes([29; 32]),
        };
        rig.phone(&PhoneOperation::Register {
            deposit_pub: credentials_core::kem::public_half(
                &credentials_core::kem::pem_from_scalar(&[3; 32]),
            )
            .unwrap()
            .0,
            approval_pub: signer()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        })
        .unwrap();
        rig
    }
    fn phone(&self, op: &PhoneOperation) -> Result<Value, SecretError> {
        self.store
            .secret_phone_operation(PHONE, Some("pair-A"), NOW, op, || true, || NOW)
    }
    fn counts(&self) -> (i64, i64, i64, i64, i64) {
        self.sql.query_row("SELECT (SELECT count(*) FROM audit_log),(SELECT count(*) FROM agent_secrets),(SELECT count(*) FROM secret_deposit_tombstones),(SELECT count(*) FROM secret_pending_requests),(SELECT count(*) FROM secret_grants)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap()
    }
    fn use_secret(&self, named: bool) -> Value {
        let outcome = if named {
            self.store
                .secret_use(&call().with_name("git".into()), || NOW)
        } else {
            self.store.secret_use_by_target(&call(), || NOW)
        };
        outcome.map_or_else(|e| e.body(), |o| o.reply)
    }
    fn pin_incarnation(&self) {
        let (incarnation, blob): (String, Vec<u8>) = self
            .sql
            .query_row(
                "SELECT incarnation,envelope FROM agent_secrets WHERE name='git'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            agent_secret::open(
                &self.master,
                &incarnation,
                "git",
                &scope("authorization_basic:git"),
                &blob
            )
            .unwrap(),
            material()
        );
        // Normalize only the random fixture identity; sealing and opening remain production code.
        let blob = agent_secret::seal(
            &self.master,
            INCARNATION,
            "git",
            &scope("authorization_basic:git"),
            &material(),
        )
        .unwrap();
        self.sql
            .execute(
                "UPDATE agent_secrets SET incarnation=?1,envelope=?2 WHERE name='git'",
                params![INCARNATION, blob],
            )
            .unwrap();
        self.sql
            .execute(
                "UPDATE secret_deposit_tombstones SET incarnation=?1 WHERE deposit_id=?2",
                params![INCARNATION, DEPOSIT_ID],
            )
            .unwrap();
    }
    fn pending(&self) -> Value {
        let first = self.use_secret(true);
        assert_eq!(first["status"], "approval_required");
        let statement = agent_secret::approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &call().with_name("git".into()),
            &scope("authorization_basic:git"),
            NOW + 600_000,
        );
        let bytes = serde_json::to_vec(&statement).unwrap();
        self.sql.execute("UPDATE secret_pending_requests SET request_id=?1,statement_bytes=?2,statement_sha256=?3 WHERE request_id=?4", params![REQUEST_ID,bytes,hex(&payload_hash(&bytes)),first["request_id"].as_str().unwrap()]).unwrap();
        let replay = self.use_secret(true);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(replay["statement_b64url"].as_str().unwrap())
                .unwrap(),
            bytes
        );
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&self.use_secret(false)).unwrap()
        );
        replay
    }
}

fn produce() -> Pack {
    let rig = Rig::new();
    let mut pack = Pack::default();
    let not_found = rig.use_secret(false);
    assert_eq!(not_found, SecretError::NotFound.body());
    let missing = json!({"request":pack.json("not-found.request.json", &request(false)),"reply":pack.json("not-found.reply.json", &not_found)});
    let api_scope = scope("authorization_basic:git");
    let aad = agent_secret::deposit_aad(DEPOSIT_ID, HOME, "git", &api_scope).unwrap();
    let plaintext = agent_secret::deposit_plaintext(&material());
    let recipient = rig.store.secret_deposit_public_key().unwrap().public_key;
    let (enc, ciphertext) = credentials_core::kem::seal_auth_with_ephemeral_ikm(
        &credentials_core::kem::pem_from_scalar(&[3; 32]),
        &recipient,
        plaintext.expose(),
        agent_secret::DEPOSIT_INFO,
        &aad,
        [4; 32],
    )
    .unwrap();
    let deposit = PhoneDeposit {
        deposit_id: DEPOSIT_ID.into(),
        member_id: HOME.into(),
        name: "git".into(),
        scope: api_scope.clone(),
        enc,
        ciphertext,
    };
    let deposit_request = json!({"deposit_id":DEPOSIT_ID,"member_id":HOME,"name":"git","kind":"agent_api_key","host":"x.test","path_prefix":"/repos/a","location":"authorization_basic:git","enc_b64url":URL_SAFE_NO_PAD.encode(&deposit.enc),"ciphertext_b64url":URL_SAFE_NO_PAD.encode(&deposit.ciphertext)});
    let before = rig.counts();
    let off_deposit = rig
        .phone(&PhoneOperation::Deposit(deposit.clone()))
        .unwrap_err();
    assert_eq!(off_deposit, SecretError::SecretBasicAuthDisabled);
    let off_put = rig
        .store
        .secret_put_audited(&put("git-operator", "authorization_basic:git"), "operator")
        .unwrap_err();
    assert_eq!(off_put.wire_code(), Some("secret_basic_auth_disabled"));
    assert_eq!(rig.counts(), before);
    let put_request = json!({"name":"git-operator","kind":"agent_api_key","host":"x.test","path_prefix":"/repos/a","location":"authorization_basic:git","material_b64url":put("git-operator", "authorization_basic:git").material_b64url});
    let disabled = json!({"deposit_request":pack.json("disabled-deposit.request.json", &deposit_request),"deposit_reply":pack.json("disabled-deposit.reply.json", &off_deposit.body()),"put_request":pack.json("disabled-put.request.json", &put_request),"put_reply":pack.json("disabled-put.reply.json", &SecretError::SecretBasicAuthDisabled.body())});
    rig.store
        .set_secret_basic_auth_audited(true, AuditCtx::admin(AuditOp::SecretBasicAuthSet))
        .unwrap();
    let mut stored = rig
        .phone(&PhoneOperation::Deposit(deposit.clone()))
        .unwrap();
    assert_eq!(stored["status"], "stored");
    rig.pin_incarnation();
    stored["incarnation"] = json!(INCARNATION);
    let deposit_sample = json!({
        "request":pack.json("deposit.request.json", &deposit_request),
        "reply":pack.json("deposit.reply.json", &stored),
        "recipient_public":pack.bytes("recipient-public.bin", &recipient),
        "phone_deposit_public":pack.bytes("phone-deposit-public.bin", &credentials_core::kem::public_half(&credentials_core::kem::pem_from_scalar(&[3;32])).unwrap().0),
        "aad":pack.bytes("deposit.aad.bin", &aad),
        "plaintext":pack.bytes("deposit.plaintext.bin", plaintext.expose()),
        "enc":pack.bytes("deposit.enc.bin", &deposit.enc),
        "ciphertext":pack.bytes("deposit.ciphertext.bin", &deposit.ciphertext),
        "sealed_body":pack.bytes("deposit.sealed-body.bin", agent_secret::sealed_body(&api_scope,&material()).unwrap().expose()),
    });
    let pending = rig.pending();
    let statement = URL_SAFE_NO_PAD
        .decode(pending["statement_b64url"].as_str().unwrap())
        .unwrap();
    let envelope = ApprovalEnvelope {
        v: "ck-secret-use-envelope/v1".into(),
        items: vec![ApprovalItem {
            request_id: REQUEST_ID.into(),
            statement_sha256: hex(&payload_hash(&statement)),
        }],
        decision: "allow".into(),
        duration: "hour".into(),
        grant_expires_at_ms: (NOW + 3_600_000) as u64,
        device_fingerprint: PHONE.into(),
        issued_at_ms: NOW as u64,
    };
    let envelope_bytes = envelope.canonical_bytes().unwrap();
    let signature: Signature = signer().sign(&envelope_bytes);
    let signature = signature.to_der().as_bytes().to_vec();
    ApprovalEnvelope::verify(
        &envelope_bytes,
        &signature,
        signer().verifying_key().to_encoded_point(false).as_bytes(),
        PHONE,
    )
    .unwrap();
    let approved = rig
        .phone(&PhoneOperation::Approve {
            envelope: envelope_bytes.clone(),
            signature: signature.clone(),
            card_ref: Some("basic-auth-vector".into()),
        })
        .unwrap();
    assert_eq!(approved["results"][0]["outcome"], "granted");
    // Neither release path is gated once the record exists.
    rig.store
        .set_secret_basic_auth_audited(false, AuditCtx::admin(AuditOp::SecretBasicAuthSet))
        .unwrap();
    let named_release = rig.use_secret(true);
    let nameless_release = rig.use_secret(false);
    assert_eq!(
        serde_json::to_vec(&named_release).unwrap(),
        serde_json::to_vec(&nameless_release).unwrap()
    );
    assert_eq!(
        named_release,
        json!({"status":"released","kind":"agent_api_key","location":"authorization_basic:git","key_b64url":URL_SAFE_NO_PAD.encode(TOKEN)})
    );
    let mut cases = vec![];
    for (label, named, reply) in [
        ("named", true, named_release),
        ("nameless", false, nameless_release),
    ] {
        let statement_json: Value = serde_json::from_slice(&statement).unwrap();
        let envelope_json: Value = serde_json::from_slice(&envelope_bytes).unwrap();
        cases.push(json!({"case":label,
            "request":pack.json(&format!("{label}.request.json"), &request(named)),
            "statement":pack.json(&format!("{label}.statement.json"), &statement_json),
            "approval_required":pack.json(&format!("{label}.approval-required.json"), &pending),
            "envelope":pack.json(&format!("{label}.envelope.json"), &envelope_json),
            "signature_der":pack.bytes(&format!("{label}.signature.der"), &signature),
            "approval_result":pack.json(&format!("{label}.approval-result.json"), &approved),
            "release":pack.json(&format!("{label}.release.json"), &reply),
        }));
    }
    rig.store
        .set_secret_basic_auth_audited(true, AuditCtx::admin(AuditOp::SecretBasicAuthSet))
        .unwrap();
    rig.store
        .secret_put_audited(&put("other", "authorization_basic:other"), "operator")
        .unwrap();
    let before = rig.counts();
    let ambiguous = rig.use_secret(false);
    assert_eq!(ambiguous, SecretError::Ambiguous.body());
    assert_eq!(rig.counts(), before);
    let ambiguous = json!({"request":pack.json("ambiguous.request.json", &request(false)),"reply":pack.json("ambiguous.reply.json", &ambiguous)});
    let mut grammar = vec![];
    for (label, user, expected) in [
        (
            "colon",
            "user:password".into(),
            agent_secret::ValidationError::InvalidParams,
        ),
        (
            "empty",
            String::new(),
            agent_secret::ValidationError::InvalidParams,
        ),
        (
            "129-bytes",
            "a".repeat(129),
            agent_secret::ValidationError::LimitExceeded,
        ),
        (
            "non-ascii",
            "usér".into(),
            agent_secret::ValidationError::InvalidParams,
        ),
    ] {
        let location = format!("authorization_basic:{user}");
        let mut request = deposit_request.clone();
        request["location"] = json!(location);
        let validation = SecretScope::from_input(
            "agent_api_key",
            &json!({"host":"x.test","path_prefix":"/repos/a"}),
            Some(&location),
        )
        .unwrap_err();
        assert_eq!(validation, expected);
        assert_eq!(
            put("grammar", &location).scope_and_material().unwrap_err(),
            expected
        );
        let result =
            json!({"validation_error":format!("{validation:?}"),"code":validation.wire_code()});
        grammar.push(json!({"case":label,"request":pack.json(&format!("grammar-{label}.request.json"), &request),"validation":pack.json(&format!("grammar-{label}.validation.json"), &result)}));
    }
    let approval_public = pack.bytes(
        "approval-public.sec1.bin",
        signer().verifying_key().to_encoded_point(false).as_bytes(),
    );
    let manifest = json!({"v":"secret-basic-auth-vectors-v1","clock_ms":NOW,"approval_public":approval_public,"deposit":deposit_sample,"cases":cases,"not_found":missing,"ambiguous":ambiguous,"setting_off":disabled,"grammar":grammar});
    pack.files.insert(
        "vectors.json".into(),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    );
    let sums = pack
        .files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", hex(&payload_hash(bytes))))
        .collect::<String>();
    pack.files.insert("SHA256SUMS".into(), sums.into_bytes());
    pack
}

#[test]
fn secret_basic_auth_vectors_are_producer_generated_and_pinned() {
    let pack = produce();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/secret-basic-auth-vectors-v1");
    for (name, bytes) in &pack.files {
        let path = root.join(name);
        if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(&path, bytes).unwrap();
        }
        assert_eq!(
            std::fs::read(&path).unwrap_or_else(|_| panic!("generate {}", path.display())),
            *bytes,
            "producer-generated sample changed: {name}"
        );
    }
    println!("checked {} pinned files: Auth HPKE deposit; named/name-less card, approval and release; not_found, ambiguous, setting-off and four grammar refusals", pack.files.len());
}
