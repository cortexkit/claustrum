#![cfg(feature = "test-support")]

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::agent_secret::{
    self, ApprovalEnvelope, ApprovalItem, AskingScope, LocalUse, SecretError, SecretMaterial,
    SecretScope, SecretSender, SecretSshSign, SecretUse, SshUserauth, UseTarget,
};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::key::MasterKey;
use credentials_core::record::{AgentSsh, AgentSshTarget, CredentialKind, VaultRecord};
use credentials_core::secret::Secret;
use credentials_core::store::{payload_hash, EncryptedStore, PhoneDeposit, PhoneOperation};
use credentials_core::test_support::TestTempDir;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const NOW: i64 = 1_700_000_000_000;
const HOME: &str = "fed-computer:22222222222222222222222222222222";
const ASKER: &str = "fed-computer:11111111111111111111111111111111";
const PHONE: &str = "11111111111111111111111111111111";
const KEY: &str = "signing:local-use-vector";
const UNMARKED: &str = "signing:unmarked-vector";
const INCARNATION: &str = "000000000000000000000000000000ab";
const KEY_INCARNATION: &str = "000000000000000000000000000000cd";
const DEPOSIT_ID: &str = "01HF7YAT000000000000000001";
const PASSWORD: &str = "şifre🔑";

fn scratch() -> TestTempDir {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/scratch");
    std::fs::create_dir_all(&parent).unwrap();
    TestTempDir::from_path(parent.join(format!(
        "local-use-vectors-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bytes_record(bytes: &[u8]) -> Value {
    json!({"b64url":URL_SAFE_NO_PAD.encode(bytes),"sha256":hex(&payload_hash(bytes))})
}

fn json_record(value: &Value) -> Value {
    let mut record = bytes_record(&serde_json::to_vec(value).unwrap());
    record["json"] = value.clone();
    record
}

fn approval_key() -> SigningKey {
    SigningKey::from_bytes((&[7; 32]).into()).unwrap()
}

fn signing_pem() -> String {
    // RFC 8410 PKCS#8 v1, with a fixed test-only Ed25519 seed.
    let mut der = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    der.extend_from_slice(&[11; 32]);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der)
    )
}

fn ssh_blob() -> Vec<u8> {
    let public = credentials_core::signing::public_key_ed25519(&signing_pem()).unwrap();
    let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    for pair in public.public_key_hex.as_bytes().as_chunks::<2>().0 {
        blob.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    blob
}

fn userauth(user: &str) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut data = vec![];
    string(&mut data, &[0x42; 32]);
    data.push(50);
    for field in [user.as_bytes(), b"ssh-connection", b"publickey"] {
        string(&mut data, field);
    }
    data.push(1);
    string(&mut data, b"ssh-ed25519");
    string(&mut data, &ssh_blob());
    data
}

fn members(ssh: bool) -> Value {
    if ssh {
        json!({"program":"ssh","use":"ssh_sign","target":{"user":"alice","host":std::net::Ipv4Addr::LOCALHOST.to_string(),"port":22},"command":"ssh alice@127.0.0.1","workdir":"/home/alice"})
    } else {
        json!({"program":"sudo","use":"sudo_password","target":{"user":"root"},"command":"apt upgrade","workdir":"/home/alice","purpose":"update packages","expects":"password prompt","undoable":"no"})
    }
}

fn use_call(ssh: bool, agent: bool) -> SecretUse {
    SecretUse {
        name: if ssh { KEY } else { "sudo" }.into(),
        sender: SecretSender::Aft,
        scope: AskingScope {
            owner: "reserved:prefrontal-core".into(),
            kind: "head".into(),
            scope_ref: "H".into(),
            epoch: 7,
        },
        worker_parent: None,
        coverage: "scope".into(),
        agent_id: agent.then(|| "agent-A".into()),
        target: UseTarget::LocalProgram(LocalUse::from_value(&members(ssh)).unwrap()),
    }
}

fn ssh_call(agent: bool, data: Vec<u8>, key: &str) -> SecretSshSign {
    let call = use_call(true, agent);
    SecretSshSign {
        key: key.into(),
        sender: call.sender,
        scope: call.scope,
        worker_parent: None,
        coverage: call.coverage,
        agent_id: call.agent_id,
        local_use: LocalUse::from_value(&members(true)).unwrap(),
        data: SshUserauth::parse(data).unwrap(),
    }
}

fn request(ssh: bool, agent: bool) -> Value {
    let mut stamp = json!({"owner":{"kind":"reserved","module_id":"prefrontal-core"},"kind":"head","ref":"H","scope_epoch":7,"attributes":{},"owner_authorized":true});
    if agent {
        stamp["attributes"]["agent_id"] = json!("agent-A");
    }
    if ssh {
        let local = members(true);
        json!({"key":KEY,"stamp":stamp,"target":local["target"],"command":local["command"],"workdir":local["workdir"],"data":URL_SAFE_NO_PAD.encode(userauth("alice"))})
    } else {
        json!({"name":"sudo","stamp":stamp,"target":members(false)})
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
        let root = scratch();
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
            .set_secret_local_programs_audited(
                true,
                AuditCtx::admin(AuditOp::SecretLocalProgramsSet),
            )
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
        for id in [KEY, UNMARKED] {
            store
                .create(
                    id,
                    &VaultRecord::new_static(
                        CredentialKind::SigningKey,
                        "test",
                        signing_pem().into_bytes(),
                        None,
                    ),
                )
                .unwrap();
        }
        store.force_credential_incarnation_for_test(KEY, KEY_INCARNATION);
        store
            .set_agent_ssh_audited(
                KEY,
                Some(AgentSsh {
                    targets: vec![AgentSshTarget {
                        user: Some("alice".into()),
                        host: std::net::Ipv4Addr::LOCALHOST.to_string(),
                        port: Some(22),
                    }],
                }),
                "admin",
            )
            .unwrap();
        let rig = Self {
            _root: root,
            store,
            sql: Connection::open(path).unwrap(),
            master: MasterKey::from_bytes([29; 32]),
        };
        let (phone_pub, _) =
            credentials_core::kem::public_half(&credentials_core::kem::pem_from_scalar(&[3; 32]))
                .unwrap();
        rig.phone(&PhoneOperation::Register {
            deposit_pub: phone_pub,
            approval_pub: approval_key()
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

    fn counts(&self) -> (i64, i64, i64) {
        self.sql.query_row("SELECT (SELECT COUNT(*) FROM audit_log),(SELECT COUNT(*) FROM secret_pending_requests),(SELECT COUNT(*) FROM secret_grants)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
    }

    fn deposit(&self) -> (PhoneDeposit, Value) {
        let scope = SecretScope::from_input("local_program", &json!({"program":"sudo","use":"sudo_password","targets":[{"user":"root"},{"user":"admin"}]}), None).unwrap();
        let material = SecretMaterial::LocalProgram(Secret::new(PASSWORD.into()));
        let aad = agent_secret::deposit_aad(DEPOSIT_ID, HOME, "sudo", &scope).unwrap();
        let plaintext = agent_secret::deposit_plaintext(&material);
        let (phone_pub, _) =
            credentials_core::kem::public_half(&credentials_core::kem::pem_from_scalar(&[3; 32]))
                .unwrap();
        let recipient_pub = self.store.secret_deposit_public_key().unwrap().public_key;
        let (enc, ciphertext) = credentials_core::kem::seal_auth_with_ephemeral_ikm(
            &credentials_core::kem::pem_from_scalar(&[3; 32]),
            &recipient_pub,
            plaintext.expose(),
            agent_secret::DEPOSIT_INFO,
            &aad,
            [4; 32],
        )
        .unwrap();
        let deposit = PhoneDeposit {
            deposit_id: DEPOSIT_ID.into(),
            member_id: HOME.into(),
            name: "sudo".into(),
            scope: scope.clone(),
            enc,
            ciphertext,
        };
        let result = self
            .phone(&PhoneOperation::Deposit(deposit.clone()))
            .unwrap();
        assert_eq!(result["status"], "stored");
        let (incarnation, blob): (String, Vec<u8>) = self
            .sql
            .query_row(
                "SELECT incarnation,envelope FROM agent_secrets WHERE name='sudo'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            agent_secret::open(
                &self.master,
                &incarnation,
                "sudo",
                &scope.canonicalized().unwrap(),
                &blob
            )
            .unwrap(),
            material
        );
        // Only fixture identities change: production still seals and opens the body.
        let canonical = scope.canonicalized().unwrap();
        let blob =
            agent_secret::seal(&self.master, INCARNATION, "sudo", &canonical, &material).unwrap();
        self.sql
            .execute(
                "UPDATE agent_secrets SET incarnation=?1,envelope=?2 WHERE name='sudo'",
                params![INCARNATION, blob],
            )
            .unwrap();
        self.sql
            .execute(
                "UPDATE secret_deposit_tombstones SET incarnation=?1 WHERE deposit_id=?2",
                params![INCARNATION, DEPOSIT_ID],
            )
            .unwrap();
        let params = json!({"deposit_id":DEPOSIT_ID,"member_id":HOME,"name":"sudo","kind":"local_program","program":"sudo","use":"sudo_password","targets":[{"user":"root"},{"user":"admin"}],"enc_b64url":URL_SAFE_NO_PAD.encode(&deposit.enc),"ciphertext_b64url":URL_SAFE_NO_PAD.encode(&deposit.ciphertext)});
        let sample = json!({"request":json_record(&params),"phone_public_b64url":URL_SAFE_NO_PAD.encode(phone_pub),"recipient_public_b64url":URL_SAFE_NO_PAD.encode(recipient_pub),"aad":bytes_record(&aad),"plaintext":bytes_record(plaintext.expose()),"sealed_body":bytes_record(agent_secret::sealed_body(&canonical,&material).unwrap().expose()),"stored_scope_json":canonical.scope_json().unwrap()});
        (deposit, sample)
    }
}

impl Rig {
    fn pending(&self, ssh: bool, forwarded: bool, index: usize) -> Value {
        let asker = if forwarded { ASKER } else { "" };
        let agent = ssh == forwarded;
        let run = || {
            if ssh {
                self.store
                    .secret_ssh_sign_from(&ssh_call(agent, userauth("alice"), KEY), asker, || NOW)
                    .unwrap()
                    .reply
            } else {
                self.store
                    .secret_use_from(&use_call(false, agent), asker, || NOW)
                    .unwrap()
                    .reply
            }
        };
        let first = run();
        assert_eq!(first["status"], "approval_required");
        let bytes = URL_SAFE_NO_PAD
            .decode(first["statement_b64url"].as_str().unwrap())
            .unwrap();
        let mut statement: Value = serde_json::from_slice(&bytes).unwrap();
        let id = format!("01HF7YAT0000000000000001{index:02}");
        statement["request_id"] = json!(id);
        let fingerprint = format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(payload_hash(&ssh_blob()))
        );
        assert_eq!(
            statement,
            agent_secret::local_approval_statement(
                &id,
                HOME,
                if ssh { KEY_INCARNATION } else { INCARNATION },
                &use_call(ssh, agent),
                &LocalUse::from_value(&members(ssh)).unwrap(),
                ssh.then_some(fingerprint.as_str()),
                first["expires_at_ms"].as_i64().unwrap(),
                asker
            )
            .unwrap()
        );
        let bytes = serde_json::to_vec(&statement).unwrap();
        // Replace the generated nonce before asking the store to replay its own card.
        self.sql.execute("UPDATE secret_pending_requests SET request_id=?1,statement_bytes=?2,statement_sha256=?3 WHERE request_id=?4",
            params![id,bytes,hex(&payload_hash(&bytes)),first["request_id"].as_str().unwrap()]).unwrap();
        let replay = run();
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(replay["statement_b64url"].as_str().unwrap())
                .unwrap(),
            bytes
        );
        replay
    }

    fn approve(&self, pending: &Value, duration: &str) -> (Value, Value) {
        let statement = URL_SAFE_NO_PAD
            .decode(pending["statement_b64url"].as_str().unwrap())
            .unwrap();
        let envelope = ApprovalEnvelope {
            v: String::from_utf8(agent_secret::USE_ENVELOPE_TAG.to_vec()).unwrap(),
            items: vec![ApprovalItem {
                request_id: pending["request_id"].as_str().unwrap().into(),
                statement_sha256: hex(&payload_hash(&statement)),
            }],
            decision: "allow".into(),
            duration: duration.into(),
            grant_expires_at_ms: (NOW
                + match duration {
                    "once" => 600_000,
                    "hour" => 3_600_000,
                    "session" => 86_400_000,
                    _ => panic!("unexpected sample duration"),
                }) as u64,
            device_fingerprint: PHONE.into(),
            issued_at_ms: NOW as u64,
        };
        let bytes = envelope.canonical_bytes().unwrap();
        let signature: Signature = approval_key().sign(&bytes);
        let signature = signature.to_der().as_bytes().to_vec();
        ApprovalEnvelope::verify(
            &bytes,
            &signature,
            approval_key()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
            PHONE,
        )
        .unwrap();
        let reply = self
            .phone(&PhoneOperation::Approve {
                envelope: bytes.clone(),
                signature: signature.clone(),
                card_ref: Some("local-use-vector".into()),
            })
            .unwrap();
        (
            json!({"envelope":json_record(&serde_json::from_slice(&bytes).unwrap()),"signature_der_b64url":URL_SAFE_NO_PAD.encode(signature),"reply":json_record(&reply)}),
            reply,
        )
    }
}

fn refusal(case: &str, op: &str, request: &Value, error: SecretError) -> Value {
    let mut result = json!({"case":case,"operation":op,"request":json_record(request),"validation_error":format!("{error:?}"),"code":error.code()});
    let local_limit =
        error == SecretError::LimitExceeded && matches!(op, "secret.use" | "secret.ssh_sign");
    if error != SecretError::InvalidParams && !local_limit {
        result["reply"] = json_record(&error.body());
    }
    result
}

fn refusal_vectors(rig: &Rig, deposit: &PhoneDeposit, deposit_sample: &Value) -> Vec<Value> {
    let mut cases = vec![];
    let before = rig.counts();
    for (label, field, value) in [
        ("off-grammar-sudo-target", "target", json!({"user":"-root"})),
        ("cc-command", "command", json!("apt\nupgrade")),
        ("cf-purpose", "purpose", json!("update\u{200e}packages")),
        ("over-cap-command", "command", json!("x".repeat(2049))),
    ] {
        let mut input = members(false);
        input[field] = value;
        let error = LocalUse::from_value(&input).unwrap_err();
        assert_eq!(
            error,
            if label == "over-cap-command" {
                SecretError::LimitExceeded
            } else {
                SecretError::InvalidParams
            }
        );
        let mut params = request(false, true);
        params["target"] = input;
        cases.push(refusal(label, "secret.use", &params, error));
    }
    let mut accepted = members(false);
    accepted["command"] = json!("x".repeat(2048));
    assert!(
        LocalUse::from_value(&accepted).is_ok(),
        "last accepted command length"
    );
    let mut bad_host = members(true);
    bad_host["target"]["host"] = json!("LOCALHOST");
    let error = LocalUse::from_value(&bad_host).unwrap_err();
    assert_eq!(error, SecretError::InvalidParams);
    let mut params = request(true, false);
    params["target"] = bad_host["target"].clone();
    cases.push(refusal(
        "off-grammar-ssh-target",
        "secret.ssh_sign",
        &params,
        error,
    ));

    let non_userauth = b"SSHSIG".to_vec();
    let error = SshUserauth::parse(non_userauth.clone()).err().unwrap();
    assert_eq!(error, SecretError::InvalidParams);
    let mut params = request(true, false);
    params["data"] = json!(URL_SAFE_NO_PAD.encode(non_userauth));
    cases.push(refusal(
        "non-userauth-data",
        "secret.ssh_sign",
        &params,
        error,
    ));

    let mut params = request(true, false);
    params["data"] = json!(URL_SAFE_NO_PAD.encode(userauth("bob")));
    let error = rig
        .store
        .secret_ssh_sign(&ssh_call(false, userauth("bob"), KEY), || NOW)
        .err()
        .unwrap();
    assert_eq!(error, SecretError::InvalidParams);
    cases.push(refusal("wrong-user", "secret.ssh_sign", &params, error));

    let mut params = request(true, false);
    params["key"] = json!(UNMARKED);
    let error = rig
        .store
        .secret_ssh_sign(&ssh_call(false, userauth("alice"), UNMARKED), || NOW)
        .err()
        .unwrap();
    assert_eq!(error, SecretError::NotFound);
    cases.push(refusal("unmarked-key", "secret.ssh_sign", &params, error));
    assert_eq!(
        rig.counts(),
        before,
        "refusals must not approve, audit or create cards"
    );

    rig.store
        .set_secret_local_programs_audited(false, AuditCtx::admin(AuditOp::SecretLocalProgramsSet))
        .unwrap();
    let before = rig.counts();
    let auth_before: i64 = rig
        .sql
        .query_row("SELECT COUNT(*) FROM auth_events", [], |r| r.get(0))
        .unwrap();
    for (label, op, input, error) in [
        (
            "setting-off-sudo",
            "secret.use",
            request(false, true),
            rig.store
                .secret_use(&use_call(false, true), || NOW)
                .err()
                .unwrap(),
        ),
        (
            "setting-off-ssh",
            "secret.ssh_sign",
            request(true, false),
            rig.store
                .secret_ssh_sign(&ssh_call(false, userauth("alice"), KEY), || NOW)
                .err()
                .unwrap(),
        ),
        (
            "setting-off-deposit-replay",
            "secret.deposit",
            deposit_sample["request"]["json"].clone(),
            rig.phone(&PhoneOperation::Deposit(deposit.clone()))
                .unwrap_err(),
        ),
    ] {
        assert_eq!(error, SecretError::SecretLocalProgramsDisabled);
        cases.push(refusal(label, op, &input, error));
    }
    assert_eq!(rig.counts(), before);
    assert_eq!(
        rig.sql
            .query_row("SELECT COUNT(*) FROM auth_events", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        auth_before
    );
    cases
}

#[test]
fn ssh_sign_core_refuses_unreadable_card_key_ids_without_writing() {
    let rig = Rig::new();
    let before = rig.counts();
    for id in [
        "signing:".to_owned(),
        format!("signing:{}x", "é".repeat(124)),
        "signing:a\nb".to_owned(),
        "signing:a\u{e007f}b".to_owned(),
        "signing:a\u{2028}b".to_owned(),
        "signing:a\u{2029}b".to_owned(),
        "signing:bad|id".to_owned(),
    ] {
        assert!(matches!(
            rig.store
                .secret_ssh_sign(&ssh_call(true, userauth("alice"), &id), || NOW),
            Err(SecretError::InvalidParams)
        ));
        assert_eq!(rig.counts(), before);
    }
}

fn produce() -> Value {
    let rig = Rig::new();
    let (deposit, deposit_sample) = rig.deposit();
    assert_eq!(
        rig.phone(&PhoneOperation::Deposit(deposit.clone()))
            .unwrap()["status"],
        "already_stored"
    );
    let mut cases = vec![];
    let mut sudo_hour = Value::Null;
    for (index, (ssh, forwarded, duration)) in [
        (false, false, "once"),
        (false, true, "once"),
        (true, false, "hour"),
        (true, true, "session"),
    ]
    .into_iter()
    .enumerate()
    {
        let pending = rig.pending(ssh, forwarded, index);
        if index == 0 {
            let (sample, reply) = rig.approve(&pending, "hour");
            assert_eq!(reply["results"][0]["outcome"], "refused");
            assert_eq!(reply["results"][0]["code"], "approval_invalid");
            sudo_hour = sample;
        }
        let (approval, reply) = rig.approve(&pending, duration);
        assert_eq!(reply["results"][0]["outcome"], "granted");
        let grant_id = format!("01HF7YAT0000000000000002{index:02}");
        assert_eq!(rig.sql.execute("UPDATE secret_grants SET grant_id=?1 WHERE secret_name=?2 AND asking_member_id=?3",params![grant_id,if ssh { KEY } else { "sudo" },if forwarded { ASKER } else { "" }]).unwrap(),1);
        let statement = URL_SAFE_NO_PAD
            .decode(pending["statement_b64url"].as_str().unwrap())
            .unwrap();
        cases.push(json!({"case":format!("{}-{}",if ssh { "ssh_sign" } else { "sudo_password" },if forwarded { "forwarded" } else { "local" }),"request":json_record(&request(ssh,ssh==forwarded)),"statement":json_record(&serde_json::from_slice::<Value>(&statement).unwrap()),"approval_required":json_record(&pending),"approval":approval}));
    }
    let listing = rig.phone(&PhoneOperation::List).unwrap();
    assert_eq!(listing["secrets"][0]["grants"].as_array().unwrap().len(), 2);
    assert_eq!(
        listing["ssh_keys"][0]["grants"].as_array().unwrap().len(),
        2
    );
    for (index, (ssh, forwarded)) in [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        let asker = if forwarded { ASKER } else { "" };
        let reply = if ssh {
            rig.store
                .secret_ssh_sign_from(
                    &ssh_call(ssh == forwarded, userauth("alice"), KEY),
                    asker,
                    || NOW,
                )
                .unwrap()
                .reply
        } else {
            rig.store
                .secret_use_from(&use_call(false, ssh == forwarded), asker, || NOW)
                .unwrap()
                .reply
        };
        if ssh {
            assert_eq!(reply["status"], "signed");
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(reply["signature_b64url"].as_str().unwrap())
                    .unwrap()
                    .len(),
                64
            );
        } else {
            assert_eq!(
                reply,
                json!({"status":"released","kind":"local_program","use":"sudo_password","value":PASSWORD})
            );
        }
        cases[index]["reply"] = json_record(&reply);
    }
    let refusals = refusal_vectors(&rig, &deposit, &deposit_sample);
    for sample in &refusals {
        if matches!(
            sample["operation"].as_str(),
            Some("secret.use" | "secret.ssh_sign")
        ) {
            // Local-use limits have permanent wire framing, unlike the shared core error.
            assert_ne!(
                sample["reply"]["json"]["error"]["class"], "context_overflow",
                "local-use refusal {} must not publish shared core framing",
                sample["case"]
            );
        }
    }
    json!({"v":"secret-local-use-vectors-v1","approval_public_sec1_b64url":URL_SAFE_NO_PAD.encode(approval_key().verifying_key().to_encoded_point(false).as_bytes()),"ssh_public_blob_b64url":URL_SAFE_NO_PAD.encode(ssh_blob()),"userauth_data":bytes_record(&userauth("alice")),"deposit":deposit_sample,"cases":cases,"list":json_record(&listing),"sudo_hour_refused":sudo_hour,"refusals":refusals})
}

fn pinned_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/secret-local-use-vectors-v1.2/vectors.json")
}

#[test]
fn secret_local_use_vectors_are_producer_generated_and_pinned() {
    let sample = produce();
    let previous: Value = serde_json::from_slice(include_bytes!(
        "vectors/secret-local-use-vectors-v1/vectors.json"
    ))
    .unwrap();
    for (case, prior) in sample["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(previous["cases"].as_array().unwrap())
    {
        if case["statement"]["json"]["program"] == "sudo" {
            assert_eq!(case, prior, "sudo sample bytes must stay identical to v1.1");
        } else {
            assert!(case["request"]["json"].get("purpose").is_none());
            assert!(case["statement"]["json"].get("purpose").is_none());
            assert_eq!(
                case["statement"]["json"]["v"],
                "ck-secret-local-use-statement/v1"
            );
        }
    }
    for key in [
        "deposit",
        "sudo_hour_refused",
        "list",
        "userauth_data",
        "ssh_public_blob_b64url",
        "approval_public_sec1_b64url",
    ] {
        assert_eq!(sample[key], previous[key], "unchanged sample {key}");
    }
    for (case, prior) in sample["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .zip(previous["refusals"].as_array().unwrap())
    {
        if case["operation"] != "secret.ssh_sign" {
            assert_eq!(
                case, prior,
                "non-SSH refusal bytes must stay identical to v1.1"
            );
        } else {
            assert!(case["request"]["json"].get("purpose").is_none());
        }
    }
    for approval in sample["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| &case["approval"])
        .chain(std::iter::once(&sample["sudo_hour_refused"]))
    {
        let fingerprint = approval["envelope"]["json"]["device_fingerprint"]
            .as_str()
            .unwrap();
        assert_eq!(
            fingerprint.len(),
            32,
            "phone fingerprint must be 32 hex digits"
        );
        assert!(fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }
    let generated = serde_json::to_vec_pretty(&sample).unwrap();
    let path = pinned_path();
    let sums_path = path.with_file_name("SHA256SUMS");
    let sums = format!("{}  vectors.json\n", hex(&payload_hash(&generated)));
    if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        std::fs::write(&sums_path, &sums).unwrap();
        println!("emitted 4 local/forwarded statements and approvals, 1 deposit, 1 listing, 4 replies, sudo-hour refusal and 11 request refusals");
    }
    assert_eq!(
        std::fs::read(&path).expect("generate the pinned local-use vectors"),
        generated,
        "production-generated local-use vector bytes changed"
    );
    assert_eq!(std::fs::read(&sums_path).unwrap(), sums.as_bytes());
    let checked = std::process::Command::new("sha256sum")
        .args(["-c", "SHA256SUMS"])
        .current_dir(path.parent().unwrap())
        .output()
        .expect("sha256sum is required to verify the pack's checksum format");
    assert!(checked.status.success(), "{checked:?}");
}

#[test]
fn secret_local_use_userauth_sample_verifies_with_openssl() {
    let vectors: Value = serde_json::from_slice(&std::fs::read(pinned_path()).unwrap()).unwrap();
    let data = URL_SAFE_NO_PAD
        .decode(vectors["userauth_data"]["b64url"].as_str().unwrap())
        .unwrap();
    let blob = URL_SAFE_NO_PAD
        .decode(vectors["ssh_public_blob_b64url"].as_str().unwrap())
        .unwrap();
    let signature = URL_SAFE_NO_PAD
        .decode(
            vectors["cases"][2]["reply"]["json"]["signature_b64url"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(blob.len(), 51);
    assert_eq!(signature.len(), 64);
    let root = scratch();
    // OpenSSL consumes an RFC 8410 SubjectPublicKeyInfo, not an SSH wire blob.
    let mut spki = vec![0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3, 0x21, 0];
    spki.extend_from_slice(&blob[19..]);
    std::fs::write(root.join("public.der"), &spki).unwrap();
    std::fs::write(root.join("data"), &data).unwrap();
    std::fs::write(root.join("signature"), &signature).unwrap();
    let verify = || {
        std::process::Command::new("openssl")
            .args([
                "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-rawin", "-inkey",
            ])
            .arg(root.join("public.der"))
            .arg("-in")
            .arg(root.join("data"))
            .arg("-sigfile")
            .arg(root.join("signature"))
            .output()
            .expect("OpenSSL with Ed25519 support is required to verify the published sample")
    };
    let result = verify();
    assert!(
        result.status.success(),
        "OpenSSL rejected the userauth sample: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut tampered = data.clone();
    tampered[4] ^= 1;
    std::fs::write(root.join("data"), tampered).unwrap();
    assert!(!verify().status.success(), "changed userauth data verified");
    std::fs::write(root.join("data"), data).unwrap();
    let mut tampered = signature;
    tampered[0] ^= 1;
    std::fs::write(root.join("signature"), tampered).unwrap();
    assert!(!verify().status.success(), "changed signature verified");
}
