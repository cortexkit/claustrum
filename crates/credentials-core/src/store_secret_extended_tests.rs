use super::*;
use crate::{envelope, key::MasterKey, RecordBinding};

const INCARNATION: &str = "00000000000000000000000000000149";

fn replace_scope(store: &EncryptedStore, scope: &SecretScope) {
    let material = if scope.kind() == "agent_api_key" {
        SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec()))
    } else {
        SecretMaterial::SiteLogin {
            username: Secret::new("test-user".into()),
            password: Secret::new("test-password".into()),
            otpauth: None,
        }
    };
    let blob = agent_secret::seal(&store.key, INCARNATION, "key", scope, &material).unwrap();
    let (host, prefix, location, origin) = phone::columns(scope);
    store.fenced_write(|tx| tx.execute("UPDATE agent_secrets SET kind=?1,host=?2,path_prefix=?3,location=?4,origin=?5,scope_json=?6,envelope=?7 WHERE name='key'",rusqlite::params![scope.kind(),host,prefix,location,origin,scope.scope_json().unwrap(),blob])).unwrap();
}

fn extended_scopes() -> Vec<SecretScope> {
    vec![
        SecretScope::from_input(
            "agent_api_key",
            &json!({"rules":[{"host":"first.test","path_prefix":"/v1"},{"host":"*.x.test"}]}),
            Some("header:X-Api-Key"),
        )
        .unwrap(),
        SecretScope::from_input(
            "site_login",
            &json!({"origins":["https://x.test","https://y.test:443"]}),
            None,
        )
        .unwrap(),
    ]
}

fn blob(store: &EncryptedStore) -> Vec<u8> {
    store
        .store
        .with_conn(|conn| {
            conn.query_row(
                "SELECT envelope FROM agent_secrets WHERE name='key'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap()
}

fn assert_sealed_scope(store: &EncryptedStore) {
    store
        .store
        .with_conn(|conn| {
            let result =
                store.check_secret_target(conn, "key", SecretSender::Basal, &call().target)?;
            assert_eq!(
                result.err().expect("corrupt scope must refuse").detail,
                "sealed_scope"
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn extended_use_releases_for_any_rule_or_origin_and_survives_rotation_unchanged() {
    for scope in extended_scopes() {
        let (_root, store) = setup("extended-use-rotate");
        let mut store = Arc::try_unwrap(store).ok().unwrap();
        replace_scope(&store, &scope);
        grant(&store, "g", "permanent", 0, NOW);
        let mut request = call();
        let targets = if scope.kind() == "agent_api_key" {
            request.sender = SecretSender::Aft;
            vec![
                agent_secret::UseTarget::ApiKey {
                    scheme: "https".into(),
                    host: "first.test".into(),
                    port: 443,
                    path: "/v1/items".into(),
                },
                agent_secret::UseTarget::ApiKey {
                    scheme: "https".into(),
                    host: "a.x.test".into(),
                    port: 443,
                    path: "/".into(),
                },
            ]
        } else {
            request.sender = SecretSender::Cerebellum;
            vec![
                agent_secret::UseTarget::SiteLogin {
                    origin: "https://x.test:443".into(),
                },
                agent_secret::UseTarget::SiteLogin {
                    origin: "https://y.test".into(),
                },
            ]
        };
        let expected = if scope.kind() == "agent_api_key" {
            json!({"status":"released","kind":"agent_api_key","key_b64url":"bWF0ZXJpYWwtY2FuYXJ5","location":"header:X-Api-Key"})
        } else {
            json!({"status":"released","kind":"site_login","username":"test-user","password":"test-password"})
        };
        for target in targets {
            request.target = target;
            assert_eq!(use_reply(&store, &request, NOW), expected);
        }
        let outside = if scope.kind() == "agent_api_key" {
            agent_secret::UseTarget::ApiKey {
                scheme: "https".into(),
                host: "a.b.x.test".into(),
                port: 443,
                path: "/".into(),
            }
        } else {
            agent_secret::UseTarget::SiteLogin {
                origin: "https://outside.test".into(),
            }
        };
        store
            .store
            .with_conn(|conn| {
                let result = store.check_secret_target(conn, "key", request.sender, &outside)?;
                assert_eq!(
                    result.err().expect("outside scope must refuse").detail,
                    "target"
                );
                Ok(())
            })
            .unwrap();
        let id = agent_secret::record_binding(scope.kind(), INCARNATION, "key").unwrap();
        let binding = RecordBinding {
            credential_id: &id,
            record_version: agent_secret::SECRET_RECORD_VERSION,
        };
        let old_body = envelope::open(&store.key, &blob(&store), &binding).unwrap();
        let old_key = MasterKey::from_bytes([65; 32]);
        assert!(store
            .rotate_master_key(MasterKey::from_bytes([66; 32]))
            .unwrap()
            .is_empty());
        let new_blob = blob(&store);
        let new_body = envelope::open(&store.key, &new_blob, &binding).unwrap();
        assert_eq!(
            &*new_body, &*old_body,
            "rotation must not reinterpret or downgrade the body"
        );
        assert!(envelope::open(&old_key, &new_blob, &binding).is_err());
        assert_eq!(use_reply(&store, &request, NOW + 1), expected);
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }
}

#[test]
fn extended_use_refuses_corrupt_scope_json_without_panicking() {
    let (_root, store) = setup("extended-use-corrupt");
    replace_scope(&store, &extended_scopes().remove(0));
    for raw in [
        "not json",
        "[]",
        r#"[{"host":"*.x.test"}]"#,
        r#"[ {"host":"*.x.test","path_prefix":""}]"#,
        r#"[{"host":"x.test","path_prefix":""}]"#,
        r#"[{"host":"*.x.test","path_prefix":""},{"host":"*.x.test","path_prefix":""}]"#,
        r#"[{"host":"z.test","path_prefix":""},{"host":"a.test","path_prefix":""}]"#,
    ] {
        store
            .fenced_write(|tx| {
                tx.execute(
                    "UPDATE agent_secrets SET scope_json=?1 WHERE name='key'",
                    [raw],
                )
            })
            .unwrap();
        assert_sealed_scope(&store);
    }
    replace_scope(&store, &extended_scopes().remove(1));
    for raw in [
        r#"["https://x.test"]"#,
        r#"["https://x.test","https://x.test:443"]"#,
    ] {
        store
            .fenced_write(|tx| {
                tx.execute(
                    "UPDATE agent_secrets SET scope_json=?1 WHERE name='key'",
                    [raw],
                )
            })
            .unwrap();
        assert_sealed_scope(&store);
    }
}

#[test]
fn extended_use_rejects_body_version_mismatches_as_sealed_scope() {
    let (_root, store) = setup("extended-use-body-version");
    let mut scopes = extended_scopes();
    scopes.push(scope());
    scopes.push(SecretScope::SiteLogin {
        origin: "https://x.test".into(),
    });
    for scope in scopes {
        replace_scope(&store, &scope);
        let id = agent_secret::record_binding(scope.kind(), INCARNATION, "key").unwrap();
        let binding = RecordBinding {
            credential_id: &id,
            record_version: agent_secret::SECRET_RECORD_VERSION,
        };
        let mut body = envelope::open(&store.key, &blob(&store), &binding).unwrap();
        let wrong_tag = if scope.is_extended() {
            agent_secret::SEALED_BODY_TAG
        } else {
            agent_secret::SEALED_BODY_V2_TAG
        };
        let mut tag = Vec::new();
        agent_secret::push_field(&mut tag, wrong_tag);
        body[..tag.len()].copy_from_slice(&tag);
        let wrong_blob = envelope::seal(&store.key, &body, &binding).unwrap();
        store
            .fenced_write(|tx| {
                tx.execute(
                    "UPDATE agent_secrets SET envelope=?1 WHERE name='key'",
                    [wrong_blob],
                )
            })
            .unwrap();
        assert_sealed_scope(&store);
    }
}
