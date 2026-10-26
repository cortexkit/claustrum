use super::*;
use crate::{
    agent_secret::{SecretMaterial, ValidationError},
    secret::Secret,
    store::taxonomy_tests::rig,
};
use std::sync::{Arc, Barrier};

const FP: &str = "11111111111111111111111111111111";
const MEMBER: &str = "fed-computer:22222222222222222222222222222222";
const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn approval_signer() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn approval_public() -> Vec<u8> {
    approval_signer()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn scope() -> SecretScope {
    SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: None,
        location: "authorization_bearer".into(),
    }
}
fn run(
    store: &EncryptedStore,
    pairing: Option<&str>,
    op: &PhoneOperation,
) -> Result<Value, SecretError> {
    store.secret_phone_operation(FP, pairing, 1000, op, || true, || 1000)
}
fn setup(
    tag: &str,
) -> (
    crate::test_support::TestTempDir,
    Arc<EncryptedStore>,
    String,
) {
    let (root, store) = rig(tag, 57);
    store.ensure_secret_deposit_key().unwrap();
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    let sender = crate::kem::generate_key().unwrap();
    let (public, _) = crate::kem::public_half(&sender).unwrap();
    run(
        &store,
        Some("pair-A"),
        &PhoneOperation::Register {
            deposit_pub: public,
            approval_pub: approval_public(),
        },
    )
    .unwrap();
    (root, Arc::new(store), sender)
}
fn deposit(
    store: &EncryptedStore,
    sender: &str,
    name: &str,
    id: &str,
    scope: SecretScope,
    material: SecretMaterial,
) -> PhoneDeposit {
    let aad = agent_secret::deposit_aad(id, MEMBER, name, &scope).unwrap();
    let body = agent_secret::deposit_plaintext(&material);
    let public = store.secret_deposit_public_key().unwrap();
    let (enc, ciphertext) = crate::kem::seal_auth(
        sender,
        &public.public_key,
        body.expose(),
        agent_secret::DEPOSIT_INFO,
        &aad,
    )
    .unwrap();
    PhoneDeposit {
        deposit_id: id.into(),
        member_id: MEMBER.into(),
        name: name.into(),
        scope,
        enc,
        ciphertext,
    }
}
fn key() -> SecretMaterial {
    SecretMaterial::ApiKey(Secret::new(b"secret-canary".to_vec()))
}
fn snapshot(store: &EncryptedStore) -> (Vec<i64>, String) {
    store
        .store
        .with_conn(|conn| {
            let mut counts = Vec::new();
            for table in [
                "agent_secrets",
                "secret_phone_keys",
                "secret_phone_observations",
                "secret_pending_requests",
                "secret_grants",
                "secret_deposit_tombstones",
                "audit_log",
                "auth_events",
            ] {
                counts.push(
                    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?,
                );
            }
            Ok((
                counts,
                conn.query_row(
                    "SELECT entry_mac FROM audit_log ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )?,
            ))
        })
        .unwrap()
}

#[test]
fn phone_registration_is_create_only_per_pairing_and_conflict_is_phone_diagnostic() {
    let (_root, store, sender) = setup("phone-register");
    let (public, _) = crate::kem::public_half(&sender).unwrap();
    let op = PhoneOperation::Register {
        deposit_pub: public.clone(),
        approval_pub: approval_public(),
    };
    let before = snapshot(&store);
    assert_eq!(
        run(&store, Some("pair-A"), &op).unwrap(),
        json!({"status":"already_stored"})
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        run(
            &store,
            Some("pair-A"),
            &PhoneOperation::Register {
                deposit_pub: public,
                approval_pub: vec![5; 65]
            }
        ),
        Err(SecretError::PhoneKeyConflict)
    );
    let after = snapshot(&store);
    assert_eq!(before.1, after.1);
    assert_eq!(after.0[7], before.0[7] + 1);
    store.store.with_conn(|conn| {
        let row:(String,String,String,String,String)=conn.query_row("SELECT credential_id,kind,detail,principal_kind,principal_id FROM auth_events ORDER BY seq DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        assert_eq!(row,(format!("secret-phone|{FP}"),"secret_use_refusal".into(),"phone_key_conflict".into(),"phone".into(),format!("fed-phone:{FP}")));
        Ok(())
    }).unwrap();
    for op in [
        PhoneOperation::List,
        PhoneOperation::Approve {
            envelope: vec![],
            signature: vec![],
            card_ref: None,
        },
        PhoneOperation::Deposit(deposit(&store, &sender, "a", ID, scope(), key())),
    ] {
        assert_eq!(
            run(&store, Some("pair-B"), &op),
            Err(SecretError::PhoneNotRegistered)
        );
    }
    assert_eq!(
        run(&store, Some("pair-B"), &op).unwrap()["status"],
        "stored"
    );
    assert_eq!(
        run(
            &store,
            Some("pair-B"),
            &PhoneOperation::Deposit(deposit(&store, &sender, "a", ID, scope(), key()))
        )
        .unwrap()["status"],
        "stored"
    );
}

#[test]
fn phone_deposit_rebuilds_aad_and_checks_current_member_before_replay() {
    let (_root, store, sender) = setup("phone-aad");
    let d = deposit(&store, &sender, "token", ID, scope(), key());
    let mut tampered = d.clone();
    tampered.scope = SecretScope::ApiKey {
        host: "another.test".into(),
        path_prefix: None,
        location: "authorization_bearer".into(),
    };
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(tampered)),
        Err(SecretError::NotFound)
    );
    let mut wrong = d.clone();
    wrong.member_id = "fed-computer:33333333333333333333333333333333".into();
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(wrong)),
        Err(SecretError::NotFound)
    );
    let mut wrong_sender = d.clone();
    let other = crate::kem::generate_key().unwrap();
    let aad = agent_secret::deposit_aad(ID, MEMBER, "token", &scope()).unwrap();
    let (enc, ciphertext) = crate::kem::seal_auth(
        &other,
        &store.secret_deposit_public_key().unwrap().public_key,
        agent_secret::deposit_plaintext(&key()).expose(),
        agent_secret::DEPOSIT_INFO,
        &aad,
    )
    .unwrap();
    wrong_sender.enc = enc;
    wrong_sender.ciphertext = ciphertext;
    assert_eq!(
        run(
            &store,
            Some("pair-A"),
            &PhoneOperation::Deposit(wrong_sender)
        ),
        Err(SecretError::NotFound)
    );
    let mut other_member = d.clone();
    other_member.member_id = "fed-computer:33333333333333333333333333333333".into();
    let aad = agent_secret::deposit_aad(ID, &other_member.member_id, "token", &scope()).unwrap();
    let (enc, ciphertext) = crate::kem::seal_auth(
        &sender,
        &store.secret_deposit_public_key().unwrap().public_key,
        agent_secret::deposit_plaintext(&key()).expose(),
        agent_secret::DEPOSIT_INFO,
        &aad,
    )
    .unwrap();
    other_member.enc = enc;
    other_member.ciphertext = ciphertext;
    assert_eq!(
        run(
            &store,
            Some("pair-A"),
            &PhoneOperation::Deposit(other_member)
        ),
        Err(SecretError::NotFound)
    );
    let result = run(&store, Some("pair-A"), &PhoneOperation::Deposit(d.clone())).unwrap();
    assert_eq!(result["status"], "stored");
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(d.clone())).unwrap(),
        json!({"status":"already_stored"})
    );
    let fresh = deposit(&store, &sender, "token", ID, scope(), key());
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(fresh)),
        Err(SecretError::DepositConflict)
    );
    let another = deposit(
        &store,
        &sender,
        "token",
        "01ARZ3NDEKTSV4RRFFQ69G5FAW",
        scope(),
        key(),
    );
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(another)),
        Err(SecretError::NameExists)
    );
    let bytes = store
        .store
        .with_conn(|conn| {
            conn.query_row(
                "SELECT envelope FROM agent_secrets WHERE name='token'",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
        })
        .unwrap();
    assert!(!bytes.windows(13).any(|w| w == b"secret-canary"));
    assert_eq!(
        agent_secret::open(
            &store.key,
            result["incarnation"].as_str().unwrap(),
            "token",
            &scope(),
            &bytes
        )
        .unwrap(),
        key()
    );
    store
        .set_federation_self_member_audited(
            "fed-computer:33333333333333333333333333333333",
            AuditCtx::admin(AuditOp::FederationSelfSet),
        )
        .unwrap();
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(d)),
        Err(SecretError::DepositConflict)
    );
}

#[test]
fn phone_deposit_concurrency_serializes_all_three_collisions() {
    for case in 0..3 {
        let (_root, store, sender) = setup(&format!("phone-race-{case}"));
        let a = deposit(&store, &sender, "token", ID, scope(), key());
        let b = if case == 0 {
            a.clone()
        } else {
            deposit(
                &store,
                &sender,
                "token",
                if case == 1 {
                    ID
                } else {
                    "01ARZ3NDEKTSV4RRFFQ69G5FAW"
                },
                scope(),
                key(),
            )
        };
        let barrier = Arc::new(Barrier::new(3));
        let joins: Vec<_> = [a, b]
            .into_iter()
            .map(|d| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    run(&store, Some("pair-A"), &PhoneOperation::Deposit(d))
                })
            })
            .collect();
        barrier.wait();
        let mut outcomes: Vec<_> = joins
            .into_iter()
            .map(|j| match j.join().unwrap() {
                Ok(v) => v["status"].as_str().unwrap().to_owned(),
                Err(e) => e.code().to_owned(),
            })
            .collect();
        outcomes.sort();
        let mut expected = vec![
            "stored".to_owned(),
            ["already_stored", "deposit_conflict", "name_exists"][case].to_owned(),
        ];
        expected.sort();
        assert_eq!(outcomes, expected);
    }
}

#[test]
fn phone_deposit_keeps_corrupt_names_and_tombstones_after_removal_and_rolls_back_failed_audit() {
    let (_root, store, sender) = setup("phone-tombstone");
    let d = deposit(&store, &sender, "token", ID, scope(), key());
    store.store.with_conn(|conn|conn.execute_batch("CREATE TRIGGER fail_secret_store BEFORE INSERT ON audit_log WHEN NEW.op='secret_store' BEGIN SELECT RAISE(ABORT,'injected'); END")).unwrap();
    let before = snapshot(&store);
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(d.clone())),
        Err(SecretError::StoreError)
    );
    assert_eq!(snapshot(&store), before);
    store
        .store
        .with_conn(|conn| conn.execute_batch("DROP TRIGGER fail_secret_store"))
        .unwrap();
    run(&store, Some("pair-A"), &PhoneOperation::Deposit(d.clone())).unwrap();
    store
        .fenced_write(|tx| {
            tx.execute(
                "UPDATE agent_secrets SET state='corrupt' WHERE name='token'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let new = deposit(
        &store,
        &sender,
        "token",
        "01ARZ3NDEKTSV4RRFFQ69G5FAW",
        scope(),
        key(),
    );
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(new)),
        Err(SecretError::NameExists)
    );
    store
        .fenced_write(|tx| {
            tx.execute("DELETE FROM agent_secrets WHERE name='token'", [])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(d)),
        Err(SecretError::DepositConflict)
    );
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::List).unwrap(),
        json!({"secrets":[]})
    );
}

#[test]
fn phone_plaintext_failures_leave_deposit_id_reusable() {
    let (_root, store, sender) = setup("phone-plaintext");
    let login_scope = SecretScope::SiteLogin {
        origin: "https://x.test".into(),
    };
    let login = |password: String, uri: Option<String>| SecretMaterial::SiteLogin {
        username: Secret::new("u".into()),
        password: Secret::new(password),
        otpauth: uri.map(Secret::new),
    };
    let bad = [
        (login("p".repeat(1025), None), SecretError::LimitExceeded),
        (
            login(
                "p".into(),
                Some("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=7".into()),
            ),
            SecretError::InvalidParams,
        ),
        (
            login(
                "p".into(),
                Some("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=14".into()),
            ),
            SecretError::InvalidParams,
        ),
        (
            login(
                "p".into(),
                Some("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=121".into()),
            ),
            SecretError::InvalidParams,
        ),
        (
            login(
                "p".into(),
                Some("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=1".into()),
            ),
            SecretError::InvalidParams,
        ),
    ];
    for (material, error) in bad {
        let before = snapshot(&store);
        let d = deposit(&store, &sender, "login", ID, login_scope.clone(), material);
        assert_eq!(
            run(&store, Some("pair-A"), &PhoneOperation::Deposit(d)),
            Err(error)
        );
        assert_eq!(snapshot(&store), before);
    }
    let mut d = deposit(
        &store,
        &sender,
        "login",
        ID,
        login_scope.clone(),
        login("p".into(), None),
    );
    let aad = agent_secret::deposit_aad(ID, MEMBER, "login", &login_scope).unwrap();
    let (enc, ciphertext) = crate::kem::seal_auth(
        &sender,
        &store.secret_deposit_public_key().unwrap().public_key,
        b"truncated",
        agent_secret::DEPOSIT_INFO,
        &aad,
    )
    .unwrap();
    d.enc = enc;
    d.ciphertext = ciphertext;
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(d)),
        Err(SecretError::InvalidParams)
    );
    let d = deposit(
        &store,
        &sender,
        "login",
        ID,
        login_scope,
        login("p".into(), None),
    );
    assert_eq!(
        run(&store, Some("pair-A"), &PhoneOperation::Deposit(d)).unwrap()["status"],
        "stored"
    );
}

#[test]
fn phone_deadline_keeps_observation_but_not_mutation_and_admitted_commit_finishes() {
    let (_root, store, sender) = setup("phone-deadline");
    let d = PhoneOperation::Deposit(deposit(&store, &sender, "token", ID, scope(), key()));
    let before = snapshot(&store);
    assert_eq!(
        store.secret_phone_operation(FP, Some("pair-B"), 2000, &d, || false, || 2000),
        Err(SecretError::PairingUnavailable)
    );
    assert_eq!(snapshot(&store), before);
    store.store.with_conn(|conn| {
        let row:(String,i64)=conn.query_row("SELECT pairing_id,observed_at_ms FROM secret_phone_observations WHERE fingerprint=?1",[FP],|r|Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!(row,("pair-B".into(),2000)); Ok(())
    }).unwrap();
    let admitted = std::sync::atomic::AtomicBool::new(false);
    let result = store
        .secret_phone_operation(
            FP,
            Some("pair-A"),
            3000,
            &d,
            || {
                assert!(!admitted.swap(true, std::sync::atomic::Ordering::SeqCst));
                true
            },
            || 3000,
        )
        .unwrap();
    assert_eq!(result["status"], "stored");
    assert_eq!(
        run(&store, Some("pair-A"), &d).unwrap()["status"],
        "already_stored"
    );
}

#[test]
fn phone_list_sweeps_only_after_current_registration() {
    let (_root, store, sender) = setup("phone-list-sweep");
    let result = run(
        &store,
        Some("pair-A"),
        &PhoneOperation::Deposit(deposit(&store, &sender, "token", ID, scope(), key())),
    )
    .unwrap();
    let incarnation = result["incarnation"].as_str().unwrap();
    store.fenced_write(|tx| {
        for (id,duration,expiry) in [("expired","hour",1000),("live","hour",1001),("permanent","permanent",0)] {
            tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256) VALUES (?1,'token',?2,'prefrontal-core','head','h','scope',?3,?4,0,'hash')",rusqlite::params![id,incarnation,duration,expiry])?;
        }
        Ok(())
    }).unwrap();
    let before = snapshot(&store);
    assert_eq!(
        run(&store, None, &PhoneOperation::List),
        Err(SecretError::PhoneNotRegistered)
    );
    assert_eq!(
        run(&store, Some("pair-B"), &PhoneOperation::List),
        Err(SecretError::PhoneNotRegistered)
    );
    assert_eq!(snapshot(&store), before);
    let listed = store
        .secret_phone_operation(
            FP,
            Some("pair-A"),
            999,
            &PhoneOperation::List,
            || true,
            || 1000,
        )
        .unwrap();
    assert_eq!(listed["secrets"][0]["grants"].as_array().unwrap().len(), 2);
    assert_eq!(listed["secrets"][0]["grants"][0]["grant_id"], "live");
    assert!(listed["secrets"][0]["grants"][1]
        .get("expires_at_ms")
        .is_none());
    assert_eq!(snapshot(&store).0[6], before.0[6] + 1);
    run(&store, Some("pair-A"), &PhoneOperation::List).unwrap();
    assert_eq!(snapshot(&store).0[6], before.0[6] + 1);
}

#[test]
fn phone_gate_persists_and_defaults_off_and_audits_once() {
    let (root, store) = rig("phone-gate", 58);
    assert!(!store.secret_phone_mapping().unwrap());
    assert_eq!(
        store.secret_phone_mapping_gates().unwrap(),
        (false, Some(false))
    );
    let op = crate::AdminOpBody::SecretPhoneGateSet {
        v: crate::ADMIN_OP_SCHEMA_V2,
        enabled: true,
    };
    assert_eq!(
        crate::admin_ops::apply(&store, op.clone(), "offline-cli").unwrap()["changed"],
        true
    );
    assert_eq!(
        crate::admin_ops::apply(&store, op, "offline-cli").unwrap()["changed"],
        false
    );
    assert!(store.secret_phone_mapping().unwrap());
    store
        .store
        .with_conn(|conn| {
            let (op, actor, hash): (String, String, String) = conn.query_row(
                "SELECT op,actor,payload_hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            assert_eq!(
                (op.as_str(), actor.as_str()),
                ("secret_phone_gate_set", "offline-cli")
            );
            assert_eq!(
                hash,
                "46d058fc4ef77f3fd874fde10d5335b24dbbb60eb4f66d45d732ab1c5b0d7250"
            );
            Ok(())
        })
        .unwrap();
    drop(store);
    let descriptor = cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "taxonomy-phone-gate".into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let reopened = EncryptedStore::open(
        cortexkit_store::open_sqlite(&descriptor).unwrap(),
        MasterKey::from_bytes([58; 32]),
    )
    .unwrap();
    assert!(reopened.secret_phone_mapping().unwrap());
    assert_eq!(
        reopened.secret_phone_mapping_gates().unwrap(),
        (false, Some(true))
    );
    reopened
        .set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    assert_eq!(
        reopened.secret_phone_mapping_gates().unwrap(),
        (true, Some(true))
    );
    reopened
        .store
        .with_conn(|conn| {
            conn.execute_batch(
                "UPDATE settings SET value='damaged' WHERE name='secret.phone_mapping'",
            )
        })
        .unwrap();
    assert_eq!(reopened.secret_phone_mapping_gates().unwrap(), (true, None));
}

#[test]
fn secret_shared_validators_pin_material_and_header_boundaries() {
    for (limit, location) in [(64, "query:"), (256, "json_pointer:/")] {
        for len in [limit, limit + 1] {
            let value = if location == "query:" {
                "x".repeat(len)
            } else {
                format!("/{}", "x".repeat(len - 1))
            };
            let location = if location == "query:" {
                format!("query:{value}")
            } else {
                format!("json_pointer:{value}")
            };
            let scope = SecretScope::ApiKey {
                host: "x.test".into(),
                path_prefix: None,
                location,
            };
            assert_eq!(
                agent_secret::validate_scope(&scope),
                if len == limit {
                    Ok(())
                } else {
                    Err(ValidationError::LimitExceeded)
                }
            );
        }
    }
    for len in [253, 254] {
        let scope = SecretScope::ApiKey {
            host: "x".repeat(len),
            path_prefix: None,
            location: "authorization_bearer".into(),
        };
        assert_eq!(
            agent_secret::validate_scope(&scope),
            if len == 253 {
                Ok(())
            } else {
                Err(ValidationError::LimitExceeded)
            }
        );
    }
    for len in [1024, 1025] {
        let scope = SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some(format!("/{}", "x".repeat(len - 1))),
            location: "authorization_bearer".into(),
        };
        assert_eq!(
            agent_secret::validate_scope(&scope),
            if len == 1024 {
                Ok(())
            } else {
                Err(ValidationError::LimitExceeded)
            }
        );
    }
    for (username, password, expected) in [
        (256, 1024, Ok(())),
        (257, 1024, Err(ValidationError::LimitExceeded)),
        (256, 1025, Err(ValidationError::LimitExceeded)),
    ] {
        let material = SecretMaterial::SiteLogin {
            username: Secret::new("u".repeat(username)),
            password: Secret::new("p".repeat(password)),
            otpauth: None,
        };
        assert_eq!(agent_secret::validate_material(&material), expected);
    }
    for header in ["Host", "COOKIE", "Content-Length", "authorization"] {
        let s = SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: None,
            location: format!("header:{header}"),
        };
        assert_eq!(
            agent_secret::validate_scope(&s),
            Err(ValidationError::InvalidParams)
        );
    }
    for len in [64, 65] {
        let s = SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: None,
            location: format!("header:{}", "X".repeat(len)),
        };
        assert_eq!(
            agent_secret::validate_scope(&s),
            if len == 64 {
                Ok(())
            } else {
                Err(ValidationError::LimitExceeded)
            }
        );
    }
    for len in [8192, 8193] {
        assert_eq!(
            agent_secret::validate_material(&SecretMaterial::ApiKey(Secret::new(vec![1; len]))),
            if len == 8192 {
                Ok(())
            } else {
                Err(ValidationError::LimitExceeded)
            }
        );
    }
    for period in [14, 15, 120, 121] {
        for digits in [5, 6, 7, 8, 9] {
            let m = SecretMaterial::SiteLogin {
                username: Secret::new("u".into()),
                password: Secret::new("p".into()),
                otpauth: Some(Secret::new(format!(
                    "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period={period}&digits={digits}"
                ))),
            };
            assert_eq!(
                agent_secret::validate_material(&m),
                if (15..=120).contains(&period) && [6, 8].contains(&digits) {
                    Ok(())
                } else {
                    Err(ValidationError::InvalidParams)
                }
            );
        }
    }
}
