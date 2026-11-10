//! Pairing wakes cross the real Callosum connection without needing a store commit.

use std::sync::Arc;

use claustrum_module_probe::federation::{sharing::run_with_home_watches, HomeVault};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{MemberGrantOperation, MemberGrantSelector};
use serde_json::{json, Value};
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

use crate::support::{
    temp_root, wait_for_signal, wait_until, Held, HomeStore, Reply, SharedCallosumStandIn,
    VaultFixture, TARGET_MODULE,
};

const READ: &str = "callosum.paired_devices_read";
const WATCH: &str = "callosum.paired_devices_watch";
const FP: &str = "648aa5c579fb30f38af744d97d6ec840";
const MEMBER: &str = "fed-computer:648aa5c579fb30f38af744d97d6ec840";

fn snapshot(pairing: &str) -> Value {
    json!({
        "self":{"static_public_key_hex":"01".repeat(32)},
        "devices":[{"class":"computer", "fingerprint":FP,
            "pairing_id":pairing, "shares":[{"share":"vault", "enabled":false}]}],
    })
}

#[tokio::test]
async fn remote_watch_stream_sharing_decodes_repair_after_callosum_failure_without_store_writes() {
    let root = temp_root("home-watch-sharing");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let vault = VaultFixture::new(
        root.path(),
        "home",
        "300c9c9603b92a4b39ed3958bf924011",
        &callosum,
    );
    let local = HomeStore::open(&vault.data_dir);
    let store = &local.store;
    store
        .set_federation_self_member_audited(
            &vault.member.member_id,
            AuditCtx::admin(AuditOp::FederationSelfSet),
        )
        .unwrap();
    store
        .set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    claustrum_module_probe::federation::transfer::ensure_transfer_key(store, "vault").unwrap();
    store
        .create_member_grant_audited(
            MEMBER,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Category("llm-provider".into()),
            "pair-1",
        )
        .unwrap();
    let home = HomeVault::new(Arc::clone(&local.engine));
    home.attach_outbound(vault.outbound.clone());
    callosum.answer(TARGET_MODULE, READ, Reply::Ok(snapshot("pair-1")));
    callosum.answer(TARGET_MODULE, WATCH, Reply::Watch(snapshot("pair-1")));
    let task = tokio::spawn(run_with_home_watches(
        Arc::clone(store),
        vault.outbound.clone(),
        Some(Arc::clone(&home.remote_watches)),
    ));
    wait_until(|| callosum.saw_method(WATCH)).await;
    let (writer, mut rx) = mpsc::channel(16);
    let header = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        11,
        1,
        7,
        vec![],
    )
    .unwrap()
    .header;
    let pending = home.remote_watches.register(header);
    wait_for_signal(
        home.remote_watches
            .open(&home, pending, &writer, header, MEMBER, &json!({})),
    )
    .await
    .unwrap();
    let first = rx.try_recv().unwrap();
    assert_eq!(first.header.ty, FrameType::StreamData);
    assert_eq!(
        serde_json::from_slice::<Value>(&first.body).unwrap()["seq"],
        1
    );
    let writes = store.subscribe_writes();
    let audit = store.audit_tip().unwrap();

    // End the watch and fail its next full read. Neither means an empty pairing list.
    let held = Held::new();
    callosum.answer(TARGET_MODULE, READ, Reply::Hold(held.clone()));
    callosum.watch_snapshot(None).await;
    held.arrived().await;
    held.release(Reply::RetrySafe("temporary_unavailable".into()));
    held.answered().await;
    callosum.reply_fence(&vault.outbound).await;
    assert!(rx.try_recv().is_err());
    assert!(!writes.has_changed().unwrap());

    // The switch is still off and only an operator grant exists, so reconciliation
    // cannot produce the commit that used to be needed to wake a home stream.
    callosum.answer(TARGET_MODULE, READ, Reply::Ok(snapshot("pair-2")));
    callosum.answer(TARGET_MODULE, WATCH, Reply::Watch(snapshot("pair-2")));
    let terminal = wait_for_signal(rx.recv()).await.unwrap();
    assert_eq!(terminal.header.ty, FrameType::Error);
    assert_eq!(
        serde_json::from_slice::<Value>(&terminal.body).unwrap(),
        json!({"code":"not_found","message":"not found","detail":{"class":"permanent"}})
    );
    assert!(!writes.has_changed().unwrap());
    assert_eq!(store.audit_tip().unwrap(), audit);
    assert_eq!(store.list_member_grants().unwrap().len(), 1);
    task.abort();
    assert!(wait_for_signal(task).await.unwrap_err().is_cancelled());
}
