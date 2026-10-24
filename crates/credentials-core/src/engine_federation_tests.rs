//! The two facts a federation fetch needs from one read: when a deferred refresh
//! becomes allowed, and which stored bytes the served token came from.
//!
//! Both are properties of `get_with_refresh_status` itself, so they are pinned here
//! rather than through the module, and both are expressed as durations and digests the
//! caller can compare without ever seeing a wall clock from another machine.

use crate::audit::{AuditCtx, AuditOp};
use crate::engine::REPORT_REFRESH_COOLDOWN_MS;
use crate::engine_tests::*;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// The deferral deadline is the end of the report cooldown, so a caller that reports it
/// as a duration says exactly what the engine decided. At twenty seconds into the window
/// forty seconds are left; at the boundary, nothing is deferred and the read refreshes.
#[tokio::test]
async fn a_deferred_refresh_reports_the_time_left_in_its_cooldown() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 91);
    store
        .create("id", &unexpired_oauth_record())
        .expect("create");
    let written = written_at(&store, "id");
    report_stale(&store, "id", 1);
    let clock = Arc::new(AtomicI64::new(written + 20_000));
    let (eng, calls) = engine(store, StubAdapter::new("stub"));
    let eng = eng.with_clock(pinned_clock(&clock));

    let deferred = eng
        .get_with_refresh_status("id", None, false)
        .await
        .expect("held read");
    let now = clock.load(Ordering::SeqCst);
    let remaining = deferred
        .refresh_deferred_until_ms
        .expect("a held-back refresh must say when it becomes allowed")
        .checked_sub(now)
        .expect("the deadline is after now");
    assert_eq!(
        remaining,
        REPORT_REFRESH_COOLDOWN_MS - 20_000,
        "twenty seconds into the window, forty seconds are left"
    );
    assert_eq!(remaining, 40_000);
    assert_eq!(deferred.record.record_version, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // A read that refreshes has nothing deferred, and there is exactly one exchange.
    clock.store(written + REPORT_REFRESH_COOLDOWN_MS, Ordering::SeqCst);
    let refreshed = eng
        .get_with_refresh_status("id", None, false)
        .await
        .expect("refresh at the boundary");
    assert!(
        refreshed.refresh_deferred_until_ms.is_none(),
        "a read that refreshed must not carry a deferral deadline"
    );
    assert_eq!(refreshed.record.record_version, 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_dir_all(&root);
}

/// The digest describes the bytes this read served, from the same row: it changes with
/// the stored material, and a delete plus re-create at the SAME version yields different
/// material under a different digest. Without that second property a caller keyed on
/// (version, digest) could mistake one stored record for another.
#[tokio::test]
async fn every_read_reports_the_digest_of_the_bytes_it_served() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 92);
    store
        .create("id", &unexpired_oauth_record())
        .expect("create");
    let (eng, calls) = engine(store, StubAdapter::new("stub"));

    let first = eng
        .get_with_refresh_status("id", None, false)
        .await
        .expect("served read");
    let again = eng
        .get_with_refresh_status("id", None, false)
        .await
        .expect("second served read");
    assert_eq!(first.record.record_version, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        first.stored_digest_hex.len(),
        64,
        "the digest is a lowercase-hex SHA-256"
    );
    assert!(
        first
            .stored_digest_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "the digest is lowercase hex: {}",
        first.stored_digest_hex
    );
    assert_eq!(
        first.stored_digest_hex, again.stored_digest_hex,
        "an unchanged record keeps its digest across reads"
    );

    // Rotate the material: same id, a new version and new bytes.
    let mut rotated = unexpired_oauth_record();
    rotated.oauth.as_mut().expect("oauth").access_token = "rotated-access".to_string().into();
    rotated.payload = b"rotated-access".to_vec().into();
    eng.store()
        .overwrite_unconditional_audited("id", &rotated, AuditCtx::vault(AuditOp::Overwrite))
        .expect("rotate in place");
    let after_rotation = eng
        .get_with_refresh_status("id", None, false)
        .await
        .expect("served after rotation");
    assert_eq!(after_rotation.record.record_version, 2);
    assert_ne!(
        after_rotation.stored_digest_hex, first.stored_digest_hex,
        "different stored bytes must not share a digest"
    );

    // A delete and re-create restarts the version sequence at 1, which is exactly the
    // case a version number alone cannot tell apart.
    eng.store()
        .remove_audited("id", AuditCtx::vault(AuditOp::Remove))
        .expect("remove");
    let mut recreated = unexpired_oauth_record();
    recreated.oauth.as_mut().expect("oauth").access_token = "recreated-access".to_string().into();
    recreated.payload = b"recreated-access".to_vec().into();
    eng.store()
        .create_audited("id", &recreated, AuditCtx::vault(AuditOp::Put))
        .expect("re-create");
    let after_recreate = eng
        .get_with_refresh_status("id", None, false)
        .await
        .expect("served after re-create");
    assert_eq!(
        after_recreate.record.record_version, 1,
        "the re-created id restarts at version 1"
    );
    assert_ne!(
        after_recreate.stored_digest_hex, first.stored_digest_hex,
        "new material at the same version number must not share a digest"
    );
    let _ = std::fs::remove_dir_all(&root);
}
