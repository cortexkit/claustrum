//! Tests for exact-before-category scoped grant coverage.

use super::*;
use crate::store::taxonomy_tests::{api_record, rig};

#[test]
fn scoped_reads_skip_category_phase_after_exact_coverage_but_list_scoped_is_exempt() {
    let (_root, store) = rig("coverage-phase", 91);
    for id in ["operator:prefix", "other:category"] {
        store
            .create_audited(id, &api_record(), AuditCtx::admin(AuditOp::Put))
            .unwrap();
    }
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            "operator:prefix",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Category,
            "monitoring",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute("DROP TABLE credential_categories", [])
                .map(|_| ())
        })
        .unwrap();

    let exact = store
        .evaluate_scoped_coverage(
            "reserved",
            "consumer",
            "operator:prefix",
            GrantOperation::Read,
            &crate::store::DeclaredGrantSet::empty(),
        )
        .expect("an exact match never enters phase 2");
    assert!(exact.covered);
    assert_eq!(exact.id_category_count, None);
    assert!(
        store
            .evaluate_scoped_coverage(
                "reserved",
                "consumer",
                "other:category",
                GrantOperation::Read,
                &DeclaredGrantSet::empty(),
            )
            .is_err(),
        "an uncovered scoped read with a category selector must enter phase 2"
    );
    assert!(
        store
            .list_scoped_snapshot("reserved", "consumer", &DeclaredGrantSet::empty())
            .is_err(),
        "list_scoped intentionally reads categories in its one snapshot"
    );
}
