#![forbid(unsafe_code)]

//! Test-only supervised module: register on the inherited channel, then read the
//! vault using the SDK's claim-bound consumer. Requires feature `consumer-e2e`.

use std::sync::Arc;

use cortexkit_claustrum_client::{
    ClaustrumCredentialResolver, CredentialErrorClass, CredentialResolver, ModuleSecretError,
    ModuleSecretState, Secret,
};
use subc_client_rs::{async_trait, HandlerOutcome, ModuleHandler, RequestCtx};
use subc_protocol::manifest::{
    Concurrency, ManagementOperation, ManagementOperationKind, ProviderRole,
};

struct Handler;

#[async_trait]
impl ModuleHandler for Handler {
    async fn handle(&self, _ctx: RequestCtx, body: Vec<u8>) -> HandlerOutcome {
        let request: serde_json::Value = serde_json::from_slice(&body).expect("probe request");
        if request["method"] == "probe.module-secret" {
            return module_secret_probe(request["params"]["phase"].as_str().expect("probe phase"))
                .await;
        }
        if request["method"] != "probe.read" {
            return HandlerOutcome::Response(
                br#"{"result":{"error":{"code":"not_found","class":"permanent"}}}"#.to_vec(),
            );
        }
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

/// Runs one phase and replies `{"module_secret_probe":true}`, or names the failing
/// step and its error. A panic here would reach the test only as "module handler
/// panicked", which says nothing about which call failed.
async fn module_secret_probe(phase: &str) -> HandlerOutcome {
    match module_secret_phase(phase).await {
        Ok(()) => HandlerOutcome::Response(br#"{"module_secret_probe":true}"#.to_vec()),
        Err(failure) => HandlerOutcome::Response(
            serde_json::to_vec(
                &serde_json::json!({"module_secret_probe": false, "failure": failure}),
            )
            .expect("failure reply"),
        ),
    }
}

fn check(condition: bool, step: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("{step}: check failed"))
    }
}

fn absent(result: Result<cortexkit_claustrum_client::ModuleSecret, ModuleSecretError>) -> bool {
    matches!(result, Err(ModuleSecretError::Other(error)) if error.class == CredentialErrorClass::CredentialAbsent)
}

async fn module_secret_phase(phase: &str) -> Result<(), String> {
    let failed = |step: &'static str| move |error: ModuleSecretError| format!("{step}: {error:?}");
    let consumer = Arc::new(
        subc_client_rs::SubcConsumer::connect_default(Default::default())
            .await
            .map_err(|error| format!("claim-bound consumer: {error:?}"))?,
    );
    let resolver = ClaustrumCredentialResolver::with_consumer(consumer);
    match phase {
        "put-get" => {
            let written = resolver
                .module_secret_put("identity", Secret::new(vec![0xa5; 65_536]), None, None)
                .await
                .map_err(failed("create"))?;
            check(
                written.name == "identity" && written.version == 1 && written.created,
                "create reply",
            )?;
            let got = resolver
                .module_secret_get("identity")
                .await
                .map_err(failed("maximum-size get"))?;
            check(
                got.name == "identity"
                    && got.version == 1
                    && !got.protected
                    && got.value.expose().len() == 65_536
                    && got.value.expose().iter().all(|byte| *byte == 0xa5),
                "maximum-size get value",
            )?;
            let list = resolver
                .module_secret_list()
                .await
                .map_err(failed("list"))?;
            check(
                list.len() == 1
                    && list[0].name == "identity"
                    && list[0].state == ModuleSecretState::Active
                    && list[0].version == 1
                    && !list[0].protected,
                "list contents",
            )?;
        }
        "isolated" => {
            check(
                absent(resolver.module_secret_get("identity").await),
                "other module's item is absent",
            )?;
            check(
                resolver
                    .module_secret_list()
                    .await
                    .map_err(failed("isolated list"))?
                    .is_empty(),
                "isolated list is empty",
            )?;
            resolver
                .module_secret_put("identity", Secret::new(vec![7]), None, None)
                .await
                .map_err(failed("independent same-name item"))?;
            let got = resolver
                .module_secret_get("identity")
                .await
                .map_err(failed("second module's own item"))?;
            check(got.value.expose() == &[7], "second module's value")?;
            resolver
                .module_secret_delete("identity", Some(1))
                .await
                .map_err(failed("second module cleanup"))?;
        }
        "delete" => {
            let got = resolver
                .module_secret_get("identity")
                .await
                .map_err(failed("first module retains its item"))?;
            check(
                got.value.expose().len() == 65_536
                    && got.value.expose().iter().all(|byte| *byte == 0xa5),
                "first module's value",
            )?;
            resolver
                .module_secret_delete("identity", Some(1))
                .await
                .map_err(failed("owner delete"))?;
            check(
                resolver
                    .module_secret_list()
                    .await
                    .map_err(failed("list after delete"))?
                    .is_empty(),
                "list is empty after delete",
            )?;
            check(
                absent(resolver.module_secret_get("identity").await),
                "deleted item is absent",
            )?;
        }
        _ => return Err(format!("unknown module-secret probe phase {phase}")),
    }
    Ok(())
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
            operations: vec![
                ManagementOperation {
                    name: "probe.read".into(),
                    description: None,
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: "probe.module-secret".into(),
                    description: None,
                    kind: ManagementOperationKind::Mutate,
                },
            ],
        }])
        .build();
    subc_client_rs::serve(manifest, Handler)
        .await
        .expect("serve on inherited registration channel");
}
