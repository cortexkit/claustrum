#![forbid(unsafe_code)]

//! Test-only supervised module: register on the inherited channel, then read the
//! vault using the SDK's claim-bound consumer. Requires feature `consumer-e2e`.

use std::sync::Arc;

use cortexkit_claustrum_client::{
    ClaustrumCredentialResolver, CredentialErrorClass, CredentialResolver,
};
use subc_client_rs::{async_trait, HandlerOutcome, ModuleHandler, RequestCtx};
use subc_protocol::manifest::{
    Concurrency, ManagementOperation, ManagementOperationKind, ProviderRole,
};

struct Handler;

#[async_trait]
impl ModuleHandler for Handler {
    async fn handle(&self, _ctx: RequestCtx, _body: Vec<u8>) -> HandlerOutcome {
        let closed_consumer = Arc::new(
            subc_client_rs::SubcConsumer::connect_default(Default::default())
                .await
                .expect("consumer to close"),
        );
        let closed_resolver =
            ClaustrumCredentialResolver::with_consumer(Arc::clone(&closed_consumer));
        closed_consumer.close().await;
        let refusal = closed_resolver
            .get_scoped("operator:test")
            .await
            .expect_err("a resolver must not read through the caller's closed SDK connection");
        // This rig's configuration has no operator-approved configuration record,
        // so the daemon still enables its older nonce-based authentication. Even
        // a module registered on the inherited channel can use that launch nonce
        // on a separate raw socket. A successful read alone cannot prove that the
        // supplied SDK consumer was used. Closing that consumer must instead
        // cause a transport refusal. The class/code, followed by the same
        // successful read on a fresh consumer, distinguish closure from grant or
        // lookup refusals such as not_found.
        assert_eq!(refusal.class, CredentialErrorClass::Transport);
        assert_eq!(refusal.code(), "credential_transport");

        let consumer = Arc::new(
            subc_client_rs::SubcConsumer::connect_default(Default::default())
                .await
                .expect("claim-bound consumer"),
        );
        let resolver = ClaustrumCredentialResolver::with_consumer(consumer);
        let credential = resolver
            .get_scoped("operator:test")
            .await
            .expect("claim-bound scoped vault read");
        assert_eq!(credential.expose(), b"the-secret-bytes");
        HandlerOutcome::Response(br#"{"claim_bound_read":true}"#.to_vec())
    }
}

#[tokio::main]
async fn main() {
    let module_id = std::env::var("SUBC_MODULE_ID").expect("supervised module id");
    let manifest = subc_protocol::manifest::ModuleManifest::builder(module_id, "0.0.0".to_owned())
        .registration_channel(true)
        .provides(vec![ProviderRole::ManagementSurface {
            concurrency: Concurrency::ModuleManaged,
            config_schema: serde_json::json!({"type":"object"}),
            observability: Vec::new(),
            identity_scope: Vec::new(),
            operations: vec![ManagementOperation {
                name: "probe.read".into(),
                description: None,
                kind: ManagementOperationKind::Query,
            }],
        }])
        .build();
    subc_client_rs::serve(manifest, Handler)
        .await
        .expect("serve on inherited registration channel");
}
