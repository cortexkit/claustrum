//! The daemon's sharing task, over the multiplexed connection to the Callosum stand-in.

use std::sync::Arc;

use claustrum_module_probe::federation::sharing::{decode_snapshot, run};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{
    MemberGrantOperation, MemberGrantSelector, MemberGrantSource, VAULT_TRANSFER_ID,
};
use credentials_core::store::{GrantOperation, SelectorKind};
use credentials_core::test_support::TestTempDir;
use serde_json::{json, Value};

use crate::support::{
    temp_root, wait_for_signal, wait_until, Held, HomeStore, Reply, SharedCallosumStandIn,
    VaultFixture, TARGET_MODULE,
};

const READ: &str = "callosum.paired_devices_read";
const WATCH: &str = "callosum.paired_devices_watch";
const MEMBER: &str = "fed-computer:648aa5c579fb30f38af744d97d6ec840";

#[tokio::test]
async fn hub_binding_feed_joins_live_callosum_watches_and_invalidates_on_end() {
    const PEER_KEYS_WATCH: &str = "callosum.peer_keys_watch";
    let rig = Rig::new("hub-binding-feed", snapshot("all_classes")).await;
    rig.callosum.answer(
        TARGET_MODULE,
        PEER_KEYS_WATCH,
        Reply::Watch(json!({"peers": [{
            "class":"computer",
            "fingerprint":"648aa5c579fb30f38af744d97d6ec840",
            "machine_id":"00000000000000000000000000000002",
            "pairing_id":"11111111-2222-4333-8444-555555555555:3"
        }]})),
    );
    let (observed_tx, mut observed) = tokio::sync::watch::channel(None);
    let task = tokio::spawn(claustrum_module_probe::observe_hub_bindings_for_test(
        Arc::clone(&rig.home.store),
        rig.vault.outbound.clone(),
        "00000000000000000000000000000001",
        observed_tx,
    ));
    wait_for_signal(observed.changed()).await.unwrap();
    assert_eq!(
        observed.borrow_and_update().as_deref(),
        Some(&[MEMBER.to_string()][..])
    );
    wait_until(|| rig.callosum.saw_method(WATCH)).await;
    assert_eq!(rig.callosum.watch_snapshot(None).await, 2);
    wait_for_signal(observed.changed()).await.unwrap();
    assert_eq!(*observed.borrow_and_update(), None);
    task.abort();
    assert!(wait_for_signal(task).await.unwrap_err().is_cancelled());
}

fn snapshot(name: &str) -> Value {
    let file: Value = serde_json::from_str(include_str!(
        "../fixtures/callosum/paired-devices/cases.json"
    ))
    .unwrap();
    file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()["reply"]
        .clone()
}

struct Rig {
    task: Option<tokio::task::JoinHandle<()>>,
    home: HomeStore,
    vault: VaultFixture,
    callosum: SharedCallosumStandIn,
    _root: TestTempDir,
}

impl Rig {
    async fn new(name: &str, initial: Value) -> Self {
        let root = temp_root(name);
        let callosum = SharedCallosumStandIn::start(root.path()).await;
        let vault = VaultFixture::new(
            root.path(),
            "vault",
            "300c9c9603b92a4b39ed3958bf924011",
            &callosum,
        );
        let home = HomeStore::open(&vault.data_dir);
        callosum.answer(TARGET_MODULE, READ, Reply::Ok(initial.clone()));
        callosum.answer(TARGET_MODULE, WATCH, Reply::Watch(initial));
        Self {
            task: None,
            home,
            vault,
            callosum,
            _root: root,
        }
    }

    async fn start(&mut self) {
        self.task = Some(tokio::spawn(run(
            Arc::clone(&self.home.store),
            self.vault.outbound.clone(),
        )));
        wait_until(|| self.callosum.saw_method(WATCH)).await;
    }

    async fn grants(&self, count: usize) {
        let ready = crate::support::poll_until_ready(std::future::poll_fn(|_| {
            if self.home.store.list_member_grants().unwrap().len() == count {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        }))
        .await;
        assert!(
            ready.is_some(),
            "expected {count} grants, found {}",
            self.home.store.list_member_grants().unwrap().len()
        );
    }

    async fn stop(&mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        assert!(wait_for_signal(task).await.unwrap_err().is_cancelled());
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[tokio::test]
async fn switch_on_writes_both_grants_and_prepares_transfer_key_once() {
    let mut rig = Rig::new("sharing-on", snapshot("empty")).await;
    rig.start().await;
    assert!(rig.home.store.meta(VAULT_TRANSFER_ID).is_err());
    assert_eq!(
        rig.callosum
            .watch_snapshot(Some(snapshot("all_classes")))
            .await,
        1
    );
    rig.grants(2).await;
    let grants = rig.home.store.list_member_grants().unwrap();
    assert_eq!(grants[0].operation, MemberGrantOperation::RemoteRead);
    assert_eq!(
        grants[0].selector,
        MemberGrantSelector::Category("llm-provider".into())
    );
    assert_eq!(grants[1].operation, MemberGrantOperation::SecretUse);
    assert_eq!(grants[1].selector, MemberGrantSelector::None);
    for grant in &grants {
        assert_eq!(grant.member_id, MEMBER);
        assert_eq!(grant.pairing_id, "11111111-2222-4333-8444-555555555555:3");
        assert_eq!(grant.source, MemberGrantSource::SharingSwitch);
    }
    let key = rig.home.store.get(VAULT_TRANSFER_ID).unwrap();
    let audit = rig.home.store.read_audit(None).unwrap();
    let switches: Vec<_> = audit
        .iter()
        .filter(|entry| entry.op == "member_grant_create")
        .collect();
    assert_eq!(switches.len(), 2);
    assert!(switches.iter().all(|entry| entry.actor == "vault"));
    // A second off/on cycle must retain the key and announce grant, not rotate them.
    rig.callosum.watch_snapshot(Some(snapshot("empty"))).await;
    rig.grants(0).await;
    rig.callosum
        .watch_snapshot(Some(snapshot("all_classes")))
        .await;
    rig.grants(2).await;
    assert_eq!(rig.home.store.get(VAULT_TRANSFER_ID).unwrap(), key);
    assert_eq!(
        rig.home
            .store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|entry| entry.op == "put"
                && entry.credential_id.as_deref() == Some(VAULT_TRANSFER_ID))
            .count(),
        1
    );
    assert!(matches!(
        rig.home.store.create_read_grant_audited(
            "reserved",
            "callosum",
            SelectorKind::Exact,
            VAULT_TRANSFER_ID,
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate)
        ),
        Err(credentials_core::store::StoreOpError::AlreadyExists)
    ));
    assert_eq!(rig.home.store.federation_self_member().unwrap(), None);
    assert!(!rig.home.store.federation_member_mapping().unwrap());
    assert_eq!(rig.home.store.verify_audit_chain().unwrap(), None);
    rig.stop().await;
    wait_until(|| rig.callosum.cancelled_watches() == 1).await;
}

async fn revokes(name: &str, next: Value) {
    let mut rig = Rig::new(name, snapshot("all_classes")).await;
    rig.start().await;
    rig.grants(2).await;
    rig.callosum.watch_snapshot(Some(next)).await;
    rig.grants(0).await;
    let audit = rig.home.store.read_audit(None).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.op == "member_grant_revoke" && entry.actor == "vault")
            .count(),
        2
    );
}

#[tokio::test]
async fn switch_off_revokes() {
    let mut next = snapshot("all_classes");
    next["devices"][0]["shares"][2]["enabled"] = json!(false);
    revokes("sharing-off", next).await;
}

#[tokio::test]
async fn device_removal_revokes() {
    revokes("sharing-removal", snapshot("empty")).await;
}

#[tokio::test]
async fn re_pair_revokes_and_new_pairing_can_share_again() {
    let mut rig = Rig::new("sharing-repair", snapshot("all_classes")).await;
    rig.start().await;
    rig.grants(2).await;
    let mut next = snapshot("all_classes");
    next["devices"][0]["pairing_id"] = json!("new-pairing");
    next["devices"][0]["shares"][2]["enabled"] = json!(false);
    rig.callosum.watch_snapshot(Some(next.clone())).await;
    rig.grants(0).await;
    next["devices"][0]["shares"][2]["enabled"] = json!(true);
    rig.callosum.watch_snapshot(Some(next)).await;
    rig.grants(2).await;
    assert!(rig
        .home
        .store
        .list_member_grants()
        .unwrap()
        .iter()
        .all(|g| g.pairing_id == "new-pairing"));
}

#[tokio::test]
async fn non_computer_revokes() {
    for class in ["phone", "sim", "unknown"] {
        let mut next = snapshot("all_classes");
        next["devices"][0]["class"] = json!(class);
        revokes(&format!("sharing-{class}"), next).await;
    }
}

#[tokio::test]
async fn operator_rows_are_never_replaced_or_revoked() {
    let mut rig = Rig::new("sharing-operator", snapshot("all_classes")).await;
    rig.home
        .store
        .create_member_grant_audited(
            MEMBER,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Category("llm-provider".into()),
            "operator-old-pairing",
        )
        .unwrap();
    let operator = rig.home.store.list_member_grants().unwrap();
    rig.start().await;
    rig.grants(2).await;
    assert_eq!(rig.home.store.list_member_grants().unwrap()[0], operator[0]);
    rig.callosum.watch_snapshot(Some(snapshot("empty"))).await;
    rig.grants(1).await;
    assert_eq!(rig.home.store.list_member_grants().unwrap(), operator);
}

#[tokio::test]
async fn undecodable_watch_snapshot_changes_nothing() {
    let mut rig = Rig::new("sharing-undecodable", snapshot("all_classes")).await;
    rig.start().await;
    rig.grants(2).await;
    let before = rig.home.store.list_member_grants().unwrap();
    let audit = rig.home.store.read_audit(None).unwrap();
    let reread = Held::new();
    rig.callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(reread.clone()));
    let mut invalid = snapshot("empty");
    invalid["devices"] =
        json!([{"class":"computer", "fingerprint":"bad", "pairing_id":"pair", "shares":[]}]);
    rig.callosum.watch_snapshot(Some(invalid)).await;
    reread.arrived().await;
    assert_eq!(rig.home.store.list_member_grants().unwrap(), before);
    assert_eq!(rig.home.store.read_audit(None).unwrap(), audit);
}

#[tokio::test]
async fn unreachable_callosum_changes_nothing() {
    let mut rig = Rig::new("sharing-unreachable", snapshot("all_classes")).await;
    rig.start().await;
    rig.grants(2).await;
    let before = rig.home.store.list_member_grants().unwrap();
    let audit = rig.home.store.read_audit(None).unwrap();
    let failed_read = Held::new();
    rig.callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(failed_read.clone()));
    rig.callosum.watch_snapshot(None).await;
    failed_read.arrived().await;
    let retry = Held::new();
    rig.callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(retry.clone()));
    failed_read.release(Reply::RetrySafe("fed_target_unavailable".into()));
    retry.arrived().await;
    assert_eq!(rig.home.store.list_member_grants().unwrap(), before);
    assert_eq!(rig.home.store.read_audit(None).unwrap(), audit);
}

#[tokio::test]
async fn second_grant_audit_failure_rolls_back_the_daemon_snapshot() {
    let mut rig = Rig::new("sharing-audit-atomic", snapshot("empty")).await;
    rig.start().await;
    rusqlite::Connection::open(rig.vault.store_path()).unwrap().execute_batch("CREATE TRIGGER fail_second_sharing_audit BEFORE INSERT ON audit_log WHEN NEW.op = 'member_grant_create' AND (SELECT count(*) FROM member_grants) = 2 BEGIN SELECT RAISE(ABORT, 'second grant audit failed'); END;").unwrap();
    let retry = Held::new();
    rig.callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(retry.clone()));
    rig.callosum
        .watch_snapshot(Some(snapshot("all_classes")))
        .await;
    retry.arrived().await;
    assert!(rig.home.store.list_member_grants().unwrap().is_empty());
    assert!(!rig
        .home
        .store
        .read_audit(None)
        .unwrap()
        .iter()
        .any(|entry| entry.op == "member_grant_create"));
    rusqlite::Connection::open(rig.vault.store_path())
        .unwrap()
        .execute_batch("DROP TRIGGER fail_second_sharing_audit")
        .unwrap();
    retry.release(Reply::Ok(snapshot("all_classes")));
    rig.grants(2).await;
    assert_eq!(rig.home.store.verify_audit_chain().unwrap(), None);
}

#[tokio::test]
async fn watch_reopen_rereads_on_stream_end_route_close_and_daemon_loss() {
    for close in ["stream_end", "route_close", "daemon_eof", "daemon_goodbye"] {
        let mut rig = Rig::new(&format!("sharing-reopen-{close}"), snapshot("all_classes")).await;
        rig.start().await;
        rig.grants(2).await;
        rig.callosum
            .answer(TARGET_MODULE, READ, Reply::Ok(snapshot("empty")));
        // No initial watch notice can perform the revocation: only the reopen read can.
        rig.callosum.answer(TARGET_MODULE, WATCH, Reply::Stall);
        match close {
            "stream_end" => {
                assert_eq!(rig.callosum.watch_snapshot(None).await, 1);
            }
            "route_close" => {
                assert_eq!(
                    wait_for_signal(rig.callosum.goodbye_routes("callosum")).await,
                    1
                );
            }
            _ => wait_for_signal(rig.callosum.close_connections(close == "daemon_goodbye")).await,
        }
        rig.grants(0).await;
        wait_until(|| {
            rig.callosum
                .methods("callosum")
                .iter()
                .filter(|method| method.as_str() == WATCH)
                .count()
                == 2
        })
        .await;
        assert_eq!(
            rig.callosum
                .methods("callosum")
                .iter()
                .filter(|method| method.as_str() == READ)
                .count(),
            2
        );
        assert_eq!(
            rig.callosum.connections(),
            if close.starts_with("daemon") { 2 } else { 1 }
        );
        assert!(rig
            .callosum
            .opens("callosum")
            .iter()
            .all(|open| open["consumer_identity"]["module_id"] == "claustrum"));
    }
}

#[test]
fn malformed_snapshots_are_not_partial_or_empty_inventories() {
    let valid = snapshot("all_classes");
    let mut cases = Vec::new();
    let mut missing_shares = valid.clone();
    missing_shares["devices"][0]
        .as_object_mut()
        .unwrap()
        .remove("shares");
    cases.push(missing_shares);
    let mut wrong_bool = valid.clone();
    wrong_bool["devices"][0]["shares"][2]["enabled"] = json!("true");
    cases.push(wrong_bool);
    let mut duplicate_device = valid.clone();
    duplicate_device["devices"]
        .as_array_mut()
        .unwrap()
        .push(valid["devices"][0].clone());
    cases.push(duplicate_device);
    let mut duplicate_share = valid.clone();
    duplicate_share["devices"][0]["shares"]
        .as_array_mut()
        .unwrap()
        .push(valid["devices"][0]["shares"][2].clone());
    cases.push(duplicate_share);
    let mut empty_pairing = valid.clone();
    empty_pairing["devices"][1]["pairing_id"] = json!("");
    cases.push(empty_pairing);
    let mut invalid_fingerprint = valid.clone();
    invalid_fingerprint["devices"][0]["fingerprint"] = json!("not-hex");
    cases.push(invalid_fingerprint);
    let mut missing_self = valid.clone();
    missing_self.as_object_mut().unwrap().remove("self");
    cases.push(missing_self);
    for invalid in cases {
        assert!(decode_snapshot(&invalid).is_none(), "{invalid}");
    }
}

#[tokio::test]
async fn changed_pairing_with_enabled_switch_replaces_only_switch_pairings() {
    let mut rig = Rig::new("sharing-new-pair-enabled", snapshot("all_classes")).await;
    rig.start().await;
    rig.grants(2).await;
    let mut next = snapshot("all_classes");
    next["devices"][0]["pairing_id"] = json!("next-pairing");
    rig.callosum.watch_snapshot(Some(next)).await;
    wait_until(|| {
        rig.home
            .store
            .list_member_grants()
            .unwrap()
            .iter()
            .all(|grant| grant.pairing_id == "next-pairing")
    })
    .await;
    assert_eq!(rig.home.store.list_member_grants().unwrap().len(), 2);
    assert_eq!(
        rig.home
            .store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|entry| entry.op == "member_grant_revoke")
            .count(),
        2
    );
}

#[tokio::test]
async fn extra_snapshot_fields_do_not_freeze_switch_off_revocation() {
    let mut next = snapshot("empty");
    next["future_metadata"] = json!({"revision": 2});
    revokes("sharing-extra-top-level", next).await;
}

#[tokio::test]
async fn extra_device_identity_and_share_fields_still_reconcile() {
    let mut rig = Rig::new("sharing-extra-fields", snapshot("empty")).await;
    rig.start().await;
    let mut next = snapshot("all_classes");
    next["devices"][0]["future_metadata"] = json!({"revision": 2});
    next["self"]["future_identity"] = json!(true);
    next["devices"][0]["shares"][2]["future_share"] = json!(true);
    rig.callosum.watch_snapshot(Some(next.clone())).await;
    rig.grants(2).await;
    assert!(rig
        .home
        .store
        .list_member_grants()
        .unwrap()
        .iter()
        .all(|grant| grant.member_id == MEMBER));
    next["devices"][0]["shares"][2]["enabled"] = json!(false);
    rig.callosum.watch_snapshot(Some(next)).await;
    rig.grants(0).await;
}

#[tokio::test]
async fn unknown_device_class_gets_no_grants_and_other_devices_still_reconcile() {
    let mut rig = Rig::new("sharing-unknown-class", snapshot("all_classes")).await;
    rig.start().await;
    rig.grants(2).await;
    let mut next = snapshot("all_classes");
    next["devices"][0]["class"] = json!("future-tablet");
    next["devices"][1]["class"] = json!("computer");
    next["devices"][1]["shares"] = json!([{"share": "vault", "enabled": true}]);
    let other = format!(
        "fed-computer:{}",
        next["devices"][1]["fingerprint"].as_str().unwrap()
    );
    rig.callosum.watch_snapshot(Some(next)).await;
    wait_until(|| {
        let grants = rig.home.store.list_member_grants().unwrap();
        grants.len() == 2 && grants.iter().all(|grant| grant.member_id == other)
    })
    .await;
    let audit = rig.home.store.read_audit(None).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.op == "member_grant_revoke")
            .count(),
        2
    );
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.op == "member_grant_create")
            .count(),
        4
    );
}

#[tokio::test]
async fn fleet_tombstones_persist_from_the_existing_watch_but_local_unpair_does_not_change_epochs()
{
    use credentials_core::fleet::FleetPeer;
    let mut rig = Rig::new("fleet-sharing-tombstones", snapshot("all_classes")).await;
    let myself = "fed-computer:00000000000000000000000000000001";
    rig.home
        .store
        .set_federation_self_member_audited(myself, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    rig.home.store.ensure_fleet_keys(1).unwrap();
    let public =
        credentials_core::kem::public_half(&credentials_core::kem::generate_key().unwrap())
            .unwrap()
            .0;
    let peer = FleetPeer::new(MEMBER.into(), public.try_into().unwrap()).unwrap();
    let minted = rig
        .home
        .store
        .fleet_epoch_mint(&[myself.into(), MEMBER.into()], &[peer])
        .unwrap();
    rig.home
        .store
        .fleet_epoch_commit(minted.epoch, &minted.mint_id)
        .unwrap();
    rig.start().await;
    rig.grants(2).await;
    let status = rig.home.store.fleet_epoch_status().unwrap();
    rig.callosum.watch_snapshot(Some(snapshot("empty"))).await;
    rig.grants(0).await;
    assert_eq!(rig.home.store.fleet_epoch_status().unwrap(), status);
    rig.home
        .store
        .fleet_epoch_seal(
            credentials_core::fleet::FleetSealer::Entorhinal,
            b"",
            b"still paired at account level",
        )
        .unwrap();
    let tombstone = json!([{"fingerprint":&MEMBER[13..],"removal_id":"opaque:account-removal"}]);
    let mut removed = snapshot("all_classes");
    removed["tombstones"] = tombstone.clone();
    rig.callosum.watch_snapshot(Some(removed)).await;
    rig.grants(2).await;
    wait_until(|| {
        rig.home
            .store
            .fleet_epoch_status()
            .unwrap()
            .sealing_blocked_by
            == vec![MEMBER.to_string()]
    })
    .await;
    assert_eq!(
        rig.home
            .store
            .fleet_epoch_seal(
                credentials_core::fleet::FleetSealer::Entorhinal,
                b"",
                b"blocked"
            )
            .unwrap_err(),
        credentials_core::fleet::FleetError::EpochUnavailable
    );
    let mut repeat = snapshot("empty");
    repeat["tombstones"] = tombstone;
    rig.callosum.watch_snapshot(Some(repeat)).await;
    rig.grants(0).await;
    rig.callosum
        .watch_snapshot(Some(snapshot("all_classes")))
        .await;
    rig.grants(2).await;
    assert_eq!(
        rig.home
            .store
            .fleet_epoch_status()
            .unwrap()
            .sealing_blocked_by,
        vec![MEMBER.to_string()]
    );
    assert_eq!(
        rig.home
            .store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|a| a.op == "fleet_removal")
            .count(),
        1
    );
    rig.stop().await;
}

#[tokio::test]
async fn fleet_removal_retries_after_a_failed_write_on_a_quiet_watch() {
    use std::time::Duration;

    let mut rig = Rig::new("fleet-sharing-local-retry", snapshot("empty")).await;
    rig.start().await;
    tokio::time::pause();
    let conn = rusqlite::Connection::open(rig.vault.store_path()).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_removal_audit BEFORE INSERT ON audit_log WHEN NEW.op = 'fleet_removal' BEGIN SELECT RAISE(ABORT, 'fleet removal failure'); END;").unwrap();
    let mut changed = snapshot("all_classes");
    changed["tombstones"] =
        json!([{"fingerprint":&MEMBER[13..],"removal_id":"opaque:account-removal"}]);
    rig.callosum.watch_snapshot(Some(changed)).await;
    rig.grants(2).await;
    let removal_count = || {
        rig.home
            .store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|a| a.op == "fleet_removal")
            .count()
    };
    assert_eq!(removal_count(), 0);
    conn.execute_batch("DROP TRIGGER fail_removal_audit")
        .unwrap();
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(1)).await;
    }
    wait_until(|| removal_count() == 1).await;
    assert_eq!(
        rig.callosum
            .methods("callosum")
            .iter()
            .filter(|method| *method == WATCH)
            .count(),
        1
    );
    assert_eq!(rig.home.store.verify_audit_chain().unwrap(), None);
    rig.stop().await;
}

#[tokio::test]
async fn fleet_removal_write_failure_does_not_block_sharing_and_retries_on_next_snapshot_without_self(
) {
    let mut rig = Rig::new("fleet-sharing-failure", snapshot("empty")).await;
    rig.start().await;
    let conn = rusqlite::Connection::open(rig.vault.store_path()).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_fleet_removal BEFORE INSERT ON fleet_removals BEGIN SELECT RAISE(ABORT, 'fleet removal failure'); END;").unwrap();
    let mut changed = snapshot("all_classes");
    changed["tombstones"] =
        json!([{"fingerprint":&MEMBER[13..],"removal_id":"opaque:account-removal"}]);
    rig.callosum.watch_snapshot(Some(changed.clone())).await;
    rig.grants(2).await;
    assert!(!rig
        .home
        .store
        .read_audit(None)
        .unwrap()
        .iter()
        .any(|a| a.op == "fleet_removal"));
    conn.execute_batch("DROP TRIGGER fail_fleet_removal")
        .unwrap();
    changed["devices"] = json!([]);
    rig.callosum.watch_snapshot(Some(changed)).await;
    rig.grants(0).await;
    assert_eq!(
        rig.home
            .store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|a| a.op == "fleet_removal")
            .count(),
        1
    );
    assert_eq!(rig.home.store.verify_audit_chain().unwrap(), None);
    rig.stop().await;
}
