// The CKIOS Secrets page's pinned samples for the `secret.home` query.
//
// The iPhone app decodes these replies: the role answer that tells it which vault holds
// the account's secrets, the two refusals that stop it from using a vault that does not
// hold them, and the uniform `not_found` the daemon answers when `secret.home` arrives on
// a route whose caller is not a phone. This file generates
// `tests/vectors/secret-home-v1.json` from the daemon's own phone channel and route
// dispatch, and keeps it pinned: if the reply bytes change, the pinned file has to be
// regenerated deliberately with `CK_EMIT_SECRET_VECTORS=1`.
//
// A phone route asks callosum for the pairing over an outbound client, and a test may not
// open one. So the phone channel's answer is produced by
// `secret_phone::serve_with_lookup`, the function the route calls, given a fixed
// paired-devices answer. `Rig::phone` then runs the same request through the real
// dispatcher, which with no client attached can only answer the transient
// `pairing_unavailable` before it looks at any role. The one case that is not a phone
// request at all (an ordinary principal's route) goes through the dispatcher alone.
//
// Included into the daemon's `tests` module, so each test's full name is
// `tests::<name>`, like the other contract tests here.

/// The CKIOS Secrets page vectors: real dispatch replies, pinned byte for byte.
mod secret_home_vectors {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use credentials_core::store::SecretHomeRole;

    /// This vault's own federation self id.
    const SELF_MEMBER: &str = "fed-computer:00000000000000000000000000000011";
    /// The computer that holds the secrets in the remote case. Deliberately not this
    /// vault's own id, so "remote" really means another computer.
    const HOME_MEMBER: &str = "fed-computer:00000000000000000000000000000021";
    /// The phone's fingerprint, as callosum lists it to the app.
    const PHONE_FP: &str = "00000000000000000000000000000031";
    /// The channels this rig binds: the phone's route, and a route whose caller is an
    /// ordinary principal rather than a phone.
    const PHONE_CHANNEL: u16 = 210;
    const PRINCIPAL_CHANNEL: u16 = 211;

    /// The paired-devices answer callosum gives for [`PHONE_FP`].
    fn paired_devices() -> serde_json::Value {
        json!({"devices":[{"class":"phone","fingerprint":PHONE_FP,"pairing_id":"pair-home"}]})
    }

    /// Ask `method` on the phone channel with `lookup` as callosum's paired-devices
    /// answer, and return the reply body bytes the way the phone route delivers them:
    /// the phone channel's answer, or the error body on its own for an Error frame.
    async fn phone_bytes(
        store: &Arc<EncryptedStore>,
        fingerprint: &str,
        method: &str,
        lookup: Option<serde_json::Value>,
    ) -> Vec<u8> {
        let answer = sc_answer(
            secret_phone::serve_with_lookup(
                Arc::clone(store),
                fingerprint,
                method,
                &json!({}),
                tokio::time::Instant::now() + secret_phone::PHONE_OP_DEADLINE,
                async move { lookup },
            )
            .await,
        );
        serde_json::to_vec(&frame(answer)).expect("reply bytes")
    }

    /// The body the phone route writes for an answer: a reply wrapped in `result`, an
    /// Error frame body (a bare `{"error":…}`) as it is.
    fn frame(answer: serde_json::Value) -> serde_json::Value {
        match answer {
            serde_json::Value::Object(reply) if reply.contains_key("error") => {
                serde_json::json!(reply)
            }
            reply => wrap_result(reply),
        }
    }

    /// One vault, used for one case at a time so each case sets its own role.
    ///
    /// The store is the one the read surface serves, so a route bind and a routed
    /// request see the same vault, exactly as the daemon does.
    struct Rig {
        surface: Arc<ReadSurface>,
        admin: Arc<admin_surface::AdminSurface>,
        store: Arc<EncryptedStore>,
        db_path: std::path::PathBuf,
        _root: TestTempDir,
    }

    impl Rig {
        /// A vault with member mapping and phone mapping on, the phone bound on
        /// [`PHONE_CHANNEL`] and `reserved:aft` bound on [`PRINCIPAL_CHANNEL`]. It has no
        /// self id and no home setting, which is a single computer.
        async fn new(seed: u8) -> Self {
            // The store's own directory guard stays alive for the length of the test,
            // like every other rig here.
            let (surface, store, db_path, guard) = tmp_surface_with_store(seed);
            let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
            let vault_id =
                credentials_core::vault_id_for(db_path.parent().expect("db dir")).expect("vault id");
            let admin = Arc::new(admin_surface::AdminSurface::new(
                Arc::new(RefreshEngine::new(
                    Arc::clone(&store),
                    Vec::new(),
                    Arc::new(crate::test_support::NoHttp),
                )),
                credentials_core::admin_auth::AdminMacKey::derive(&key),
                vault_id,
                key.key_id(),
            ));
            store
                .set_federation_member_mapping_audited(
                    true,
                    AuditCtx::admin(AuditOp::FederationGateSet),
                )
                .expect("member mapping");
            store
                .set_secret_phone_mapping_audited(true, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
                .expect("phone mapping");
            let routes = Arc::new(RouteEpochs::default());
            bind_reserved_route(
                &surface,
                &admin,
                &routes,
                PHONE_CHANNEL,
                1,
                "callosum",
                &format!("fed-phone:{PHONE_FP}"),
            )
            .await;
            bind_reserved_route(
                &surface,
                &admin,
                &routes,
                PRINCIPAL_CHANNEL,
                1,
                "aft",
                "",
            )
            .await;
            Rig {
                surface,
                admin,
                store,
                db_path,
                _root: guard,
            }
        }

        fn set_home(&self, home: Option<&str>) {
            self.store
                .set_secret_home_audited(home, AuditCtx::admin(AuditOp::SecretHomeSet))
                .expect("home setting");
        }

        fn set_self(&self, member: &str) {
            self.store
                .set_federation_self_member_audited(
                    member,
                    AuditCtx::admin(AuditOp::FederationSelfSet),
                )
                .expect("self member");
        }

        /// `secret.home` on the phone's route, callosum answering the pairing.
        async fn ask_home(&self) -> Vec<u8> {
            self.phone(secret_phone::HOME_OP, Some(paired_devices()))
                .await
        }

        /// Leave `secrets.home_member` naming this vault's own self id, the state the
        /// operator command refuses to create (it stores `self` instead, so a home can
        /// never turn into a remote through a later self-id change). The store accepts
        /// only `self` here, so the setting goes into the store file directly, the way a
        /// vault damaged by hand carries it.
        fn store_home_naming_own_self_id(&self) {
            let conn = rusqlite::Connection::open(&self.db_path).expect("open the store file");
            conn.execute(
                "INSERT INTO settings (name, value, updated_at_ms) VALUES (?1, ?2, 0) \
                 ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                rusqlite::params!["secrets.home_member", SELF_MEMBER],
            )
            .expect("write the home setting");
        }

        /// `method` with empty params on the phone's route, the pairing lookup answered
        /// by `lookup` (`None` is no answer). Returns the exact reply body bytes.
        ///
        /// The daemon asks callosum for the pairing through its outbound client, and a
        /// test may not open one. So the answer is produced by
        /// `secret_phone::serve_with_lookup`, the function the route calls, handed
        /// `lookup` instead of a client. The route then runs the same request, and with
        /// no client attached it must be refused the transient `pairing_unavailable`
        /// before any role is read: if it starts answering phone requests some other way,
        /// the bytes pinned here would no longer be the ones the daemon serves, so this
        /// fails rather than silently drift.
        async fn phone(&self, method: &str, lookup: Option<serde_json::Value>) -> Vec<u8> {
            let caller = self.admin.route_caller(PHONE_CHANNEL);
            let federation::RouteCaller::Phone(fingerprint) = &caller else {
                panic!("channel {PHONE_CHANNEL} is the phone's route: {caller:?}");
            };
            let body = phone_bytes(&self.store, fingerprint, method, lookup).await;
            let (kind, served) =
                sc_dispatch(&self.surface, &self.admin, caller, method, json!({})).await;
            if kind == FrameType::Response {
                let served: serde_json::Value =
                    serde_json::from_slice(&served).expect("route reply JSON");
                assert_eq!(
                    served,
                    wrap_result(serde_json::json!({"error":{
                        "code":"pairing_unavailable","class":"transient",
                    }})),
                    "{method}: with no outbound client the route never hears from callosum"
                );
            }
            body
        }

        /// `method` with empty params on the ordinary principal's route.
        async fn principal(&self, method: &str) -> Vec<u8> {
            let caller = self.admin.route_caller(PRINCIPAL_CHANNEL);
            assert!(
                matches!(caller, federation::RouteCaller::Principal(_)),
                "channel {PRINCIPAL_CHANNEL} is a plain principal's route: {caller:?}"
            );
            let (kind, body) = sc_dispatch(&self.surface, &self.admin, caller, method, json!({})).await;
            assert_eq!(kind, FrameType::Response, "{method}");
            body
        }
    }

    fn hex_of(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// One pinned case: the request, and the reply as the exact bytes the phone decodes
    /// plus their SHA-256, so the app can check the bytes it ships are these.
    fn case(name: &str, method: &str, reply: &[u8]) -> serde_json::Value {
        let value: serde_json::Value = serde_json::from_slice(reply)
            .unwrap_or_else(|e| panic!("{name}: reply is not JSON ({e}): {reply:?}"));
        json!({
            "case": name,
            "request": {"method": method, "params": {}},
            "reply_b64url": URL_SAFE_NO_PAD.encode(reply),
            "reply_sha256": hex_of(reply),
            "reply": value,
        })
    }

    /// Every case, ready to be pinned. The phone replies come from the route's own
    /// handler with a fixed pairing answer, the plain-principal refusal from the real
    /// dispatch, and `Rig::phone` runs each phone request through the dispatch as well.
    async fn emitted() -> serde_json::Value {
        // A vault that never joined a federation, with no home setting: it is a single
        // computer and serves its own secrets.
        let single = Rig::new(221).await;
        assert_eq!(single.store.secret_home_role(), SecretHomeRole::Single);
        let unset = single.ask_home().await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&unset).unwrap(),
            json!({"result":{"home":true,"home_member_id":null}})
        );

        // The home: the setting is `self`, and the reply names the self id.
        let home = Rig::new(222).await;
        home.set_self(SELF_MEMBER);
        home.set_home(Some("self"));
        let at_home = home.ask_home().await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&at_home).unwrap(),
            json!({"result":{"home":true,"home_member_id":SELF_MEMBER}})
        );

        // Remote: another computer is the home. The phone learns where to go, and every
        // phone op on this vault is refused with the home named before anything else.
        let remote = Rig::new(223).await;
        remote.set_self(SELF_MEMBER);
        remote.set_home(Some(HOME_MEMBER));
        let at_remote = remote.ask_home().await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&at_remote).unwrap(),
            json!({"result":{"home":false,"home_member_id":HOME_MEMBER}})
        );
        let audit_rows = remote.store.read_audit(None).unwrap().len();
        let refused_list = remote.phone("secret.list", Some(paired_devices())).await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&refused_list).unwrap(),
            json!({"error":{
                "code":"secret_home_elsewhere","class":"permanent","remedy_member":HOME_MEMBER,
            }})
        );
        assert_eq!(
            remote.store.read_audit(None).unwrap().len(),
            audit_rows,
            "a refused phone op writes nothing"
        );

        // A setting naming a member while the self id equals it: this vault cannot tell
        // whether it is the home, so `secret.home` gets the setup refusal.
        //
        // `set_secret_home_audited` stores a member that equals the live self id as
        // `self`, so this pair of settings is written the way a vault damaged by hand
        // carries it.
        let unplaceable = Rig::new(224).await;
        unplaceable.set_self(SELF_MEMBER);
        unplaceable.store_home_naming_own_self_id();
        let incomplete = unplaceable.ask_home().await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&incomplete).unwrap(),
            json!({"error":{
                "code":"remote_setup_incomplete","class":"permanent","remedy_member":SELF_MEMBER,
            }})
        );

        // `secret.home` is a phone op: a route whose caller is an ordinary principal
        // answers the uniform not_found, never a role.
        let plain = single.principal(secret_phone::HOME_OP).await;

        json!({
            "v": "ck-secret-home-vectors/v1",
            "member_ids": {
                "self": SELF_MEMBER,
                "home": HOME_MEMBER,
            },
            "phone_fingerprint": PHONE_FP,
            "pairing_id": "pair-home",
            "cases": [
                case("home.unset.single", secret_phone::HOME_OP, &unset),
                case("home.self.named", secret_phone::HOME_OP, &at_home),
                case("home.remote.named", secret_phone::HOME_OP, &at_remote),
                case("list.refused.remote", "secret.list", &refused_list),
                case("home.refused.unplaceable", secret_phone::HOME_OP, &incomplete),
                case("home.refused.not_phone_route", secret_phone::HOME_OP, &plain),
            ],
        })
    }

    /// The pinned file, rewritten when `CK_EMIT_SECRET_VECTORS` is set and compared
    /// byte for byte against freshly generated replies otherwise.
    #[tokio::test]
    async fn secret_home_ckios_vectors_are_emitted_by_vault_code_and_pinned() {
        let emitted = emitted().await;
        let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/secret-home-v1.json");
        if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
            std::fs::create_dir_all(pinned.parent().unwrap()).unwrap();
            std::fs::write(&pinned, serde_json::to_vec_pretty(&emitted).unwrap()).unwrap();
            println!("emitted the CKIOS secret-home vectors");
        } else {
            let expected: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&pinned).expect("pinned CKIOS home vectors"))
                    .unwrap();
            assert_eq!(emitted, expected, "vault-emitted CKIOS home vectors changed");
        }
    }
}
