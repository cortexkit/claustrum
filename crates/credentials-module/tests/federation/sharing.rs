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

#[tokio::test(start_paused = true)]
async fn login_sharing_invalid_startup_edits_warn_once_and_poll_on_tokio_clock() {
    use claustrum_module_probe::federation::login_sharing::ConfigPoll;
    use std::{sync::Mutex, time::Duration};
    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Fields(String);
    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={value:?};", field.name()));
        }
    }
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if event
                .metadata()
                .module_path()
                .is_some_and(|p| p.ends_with("login_sharing"))
            {
                assert_eq!(*event.metadata().level(), tracing::Level::WARN);
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let rig = Rig::new("login-sharing-poll", snapshot("all_classes")).await;
    let logs = Arc::new(Mutex::new(Vec::new()));
    let _capture = tracing::subscriber::set_default(Capture(Arc::clone(&logs)));
    let path = rig._root.join("claustrum.jsonc");
    std::fs::write(&path, "private-marker-one").unwrap();
    let mut poll = ConfigPoll::new(path.clone(), Arc::clone(&rig.home.store));
    poll.poll().await.unwrap();
    assert!(
        !rig.home.store.login_sharing().unwrap(),
        "invalid startup applies off"
    );
    poll.poll().await.unwrap();
    std::fs::write(&path, r#"{"login_sharing":true}"#).unwrap();
    poll.poll().await.unwrap();
    assert!(rig.home.store.login_sharing().unwrap());
    for text in [
        "private-marker-one",
        "private-marker-two",
        "private-marker-two",
        "private-marker-one",
    ] {
        std::fs::write(&path, text).unwrap();
        poll.poll().await.unwrap();
        assert!(
            rig.home.store.login_sharing().unwrap(),
            "invalid edit keeps last valid value"
        );
    }
    {
        let logs = logs.lock().unwrap();
        assert_eq!(
            logs.len(),
            2,
            "one WARN per distinct invalid content, even after a valid edit"
        );
        for log in logs.iter() {
            assert!(log.contains(&path.display().to_string()));
            assert!(log.contains("reason="));
            assert!(!log.contains("private-marker"));
        }
    }
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        ready.send(()).unwrap();
        poll.run().await;
    });
    wait_for_signal(started).await.unwrap();
    let mut writes = rig.home.store.subscribe_writes();
    std::fs::write(&path, r#"{"login_sharing":false}"#).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    wait_for_signal(writes.changed()).await.unwrap();
    assert!(
        !rig.home.store.login_sharing().unwrap(),
        "next poll applies the edit"
    );
    task.abort();
    assert!(wait_for_signal(task).await.unwrap_err().is_cancelled());
}

/// Collects WARN events logged by one daemon module, as `name=value;` fields.
struct WarnCapture {
    logs: Arc<std::sync::Mutex<Vec<String>>>,
    module: &'static str,
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?};", field.name()));
            }
        }
        if *event.metadata().level() == tracing::Level::WARN
            && event
                .metadata()
                .module_path()
                .is_some_and(|path| path.ends_with(self.module))
        {
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.logs.lock().unwrap().push(fields.0);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

type Published = Arc<std::sync::Mutex<Vec<Option<Vec<String>>>>>;

fn record_published(rig: &Rig) -> (Published, tokio::task::JoinHandle<()>) {
    let published = Published::default();
    let task = tokio::spawn(claustrum_module_probe::record_pairing_snapshots_for_test(
        Arc::clone(&rig.home.store),
        rig.vault.outbound.clone(),
        Arc::clone(&published),
    ));
    (published, task)
}

fn method_count(rig: &Rig, method: &str) -> usize {
    rig.callosum
        .methods("callosum")
        .iter()
        .filter(|seen| seen.as_str() == method)
        .count()
}

#[tokio::test(start_paused = true)]
async fn a_refused_watch_backs_off_and_warns_once_with_its_code() {
    use std::time::Duration;
    let warnings = Arc::new(std::sync::Mutex::new(Vec::new()));
    let _capture = tracing::subscriber::set_default(WarnCapture {
        logs: Arc::clone(&warnings),
        module: "federation::sharing",
    });
    let rig = Rig::new("sharing-refused-watch", snapshot("all_classes")).await;
    rig.callosum.answer(
        TARGET_MODULE,
        WATCH,
        Reply::SubscriptionError {
            channel_zero: false,
            body: json!({"code": "fed_not_ready", "message": "watch refused"}),
        },
    );
    let (published, task) = record_published(&rig);
    // Each round publishes the read's roster, then withdraws it when the watch is
    // refused, just before the loop sleeps.
    let rounds = || published.lock().unwrap().iter().filter(|seen| seen.is_none()).count();
    wait_until(|| rounds() == 1).await;
    let mut gaps = Vec::new();
    for round in 2..=5 {
        let mut seconds = 0;
        loop {
            tokio::time::advance(Duration::from_secs(1)).await;
            seconds += 1;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            // The next round starts with a read, which waits for its reply.
            if rig.vault.outbound.pending_waiter_count_for_test().await.unwrap_or(0) > 0 {
                break;
            }
            assert!(seconds <= 64, "no reread after {seconds} s");
        }
        gaps.push(seconds);
        wait_until(|| rounds() == round).await;
    }
    assert_eq!(gaps, [1, 2, 4, 8], "seconds between successive reads");
    // One WARN per distinct failure, never one per round.
    let warnings = warnings.lock().unwrap();
    let distinct: std::collections::BTreeSet<_> = warnings.iter().collect();
    assert_eq!(distinct.len(), warnings.len(), "{warnings:?}");
    assert!(
        warnings.iter().any(|warning| warning.contains("fed_not_ready")),
        "{warnings:?}"
    );
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn stalled_first_notices_reopen_both_local_feeds_after_the_setup_budget() {
    use claustrum_module_probe::federation::ADMIN_OP_BUDGET;
    const PEER_KEYS_WATCH: &str = "callosum.peer_keys_watch";
    let rig = Rig::new("sharing-first-notice", snapshot("all_classes")).await;
    // Both watches are accepted and never send a notice.
    rig.callosum.answer(TARGET_MODULE, WATCH, Reply::SilentWatch);
    rig.callosum
        .answer(TARGET_MODULE, PEER_KEYS_WATCH, Reply::SilentWatch);
    let (observed, _bindings) = tokio::sync::watch::channel(None);
    let task = tokio::spawn(claustrum_module_probe::observe_hub_bindings_for_test(
        Arc::clone(&rig.home.store),
        rig.vault.outbound.clone(),
        "00000000000000000000000000000001",
        observed,
    ));
    wait_until(|| method_count(&rig, WATCH) == 1 && method_count(&rig, PEER_KEYS_WATCH) == 1)
        .await;
    tokio::time::advance(ADMIN_OP_BUDGET).await;
    // Both accepted-but-silent watches are given up and cancelled.
    wait_until(|| rig.callosum.cancelled_watches() == 2).await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    wait_until(|| method_count(&rig, WATCH) == 2 && method_count(&rig, PEER_KEYS_WATCH) == 2)
        .await;
    assert_eq!(method_count(&rig, READ), 2);
    task.abort();
}

#[tokio::test]
async fn a_coalesced_off_on_rereads_the_roster_and_restores_the_switch_grants() {
    let mut rig = Rig::new("sharing-off-on", snapshot("all_classes")).await;
    rig.home
        .store
        .set_login_sharing_audited(true, "test")
        .unwrap();
    rig.start().await;
    rig.grants(2).await;
    assert_eq!(method_count(&rig, READ), 1);
    // No await between the two changes, so the reconciler sees one coalesced write
    // notice and the setting where it started. Callosum sends nothing unsolicited.
    assert!(rig
        .home
        .store
        .set_login_sharing_audited(false, "test")
        .unwrap());
    assert!(rig.home.store.list_member_grants().unwrap().is_empty());
    assert!(rig
        .home
        .store
        .set_login_sharing_audited(true, "test")
        .unwrap());
    rig.grants(2).await;
    assert_eq!(method_count(&rig, READ), 2);
}

#[tokio::test(start_paused = true)]
async fn a_roster_reaches_hub_workers_only_after_it_validates_and_its_grants_commit() {
    use std::time::Duration;
    const OTHER: &str = "0123456789abcdef0123456789abcdef";
    let rig = Rig::new("sharing-publish-order", snapshot("all_classes")).await;
    let paired = &MEMBER["fed-computer:".len()..];
    let (published, task) = record_published(&rig);
    rig.grants(2).await;
    let showed = |fingerprint: &str| {
        published
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .any(|devices| devices.iter().any(|seen| seen == fingerprint))
    };
    wait_until(|| showed(paired)).await;
    let before = rig.home.store.list_member_grants().unwrap();
    // The loop withdraws its roster just before it sleeps after a failure.
    let withdrawn = || published.lock().unwrap().iter().filter(|seen| seen.is_none()).count();

    // A roster that omits the paired computer and names another one with a
    // pairing id the store refuses is no roster at all.
    let reread = Held::new();
    rig.callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(reread.clone()));
    let mut malformed = snapshot("empty");
    malformed["devices"] = json!([{"class": "computer", "fingerprint": OTHER,
        "pairing_id": "bad pairing", "shares": [{"share": "vault", "enabled": true}]}]);
    rig.callosum.watch_snapshot(Some(malformed)).await;
    wait_until(|| withdrawn() == 1).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    reread.arrived().await;
    assert!(!showed(OTHER), "{:?}", published.lock().unwrap());
    assert!(published
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .all(|devices| devices.iter().any(|seen| seen == paired)));
    assert_eq!(rig.home.store.list_member_grants().unwrap(), before);

    // A valid roster whose grants cannot commit is not published either.
    let conn = rusqlite::Connection::open(rig.vault.store_path()).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_grant_audit BEFORE INSERT ON audit_log WHEN NEW.op = 'member_grant_create' BEGIN SELECT RAISE(ABORT, 'grant audit failed'); END;").unwrap();
    let mut fresh = snapshot("all_classes");
    fresh["devices"].as_array_mut().unwrap().push(json!({"class": "computer",
        "fingerprint": OTHER, "pairing_id": "pair-other",
        "shares": [{"share": "vault", "enabled": true}]}));
    let retry = Held::new();
    rig.callosum
        .answer(TARGET_MODULE, READ, Reply::Hold(retry.clone()));
    reread.release(Reply::Ok(fresh));
    wait_until(|| withdrawn() == 2).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    retry.arrived().await;
    assert!(!showed(OTHER), "{:?}", published.lock().unwrap());
    assert_eq!(rig.home.store.list_member_grants().unwrap(), before);

    // A later valid roster is still published, including one without the computer.
    conn.execute_batch("DROP TRIGGER fail_grant_audit").unwrap();
    retry.release(Reply::Ok(snapshot("empty")));
    wait_until(|| published.lock().unwrap().contains(&Some(Vec::new()))).await;
    task.abort();
}
