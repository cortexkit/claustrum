#![forbid(unsafe_code)]

//! Test-only supervised module: register on the inherited channel, then read the
//! vault using the SDK's claim-bound consumer. Requires feature `consumer-e2e`.

use std::sync::Arc;

use cortexkit_claustrum_client::{ClaustrumCredentialResolver, CredentialResolver};
use subc_client_rs::{async_trait, HandlerOutcome, ModuleHandler, RequestCtx};
use subc_protocol::manifest::{
    Concurrency, ManagementOperation, ManagementOperationKind, ProviderRole,
};

struct Handler;

#[async_trait]
impl ModuleHandler for Handler {
    async fn handle(&self, _ctx: RequestCtx, _body: Vec<u8>) -> HandlerOutcome {
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
