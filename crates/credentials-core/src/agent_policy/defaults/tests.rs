use super::{github_default_rule_set, GITHUB_DEFAULT_BYTES};
use crate::agent_policy::{canonical_bytes, policy_sha256, Approval, Class, Identity};

#[test]
fn github_release_artifact_sha256_is_pinned() {
    assert_eq!(
        policy_sha256(GITHUB_DEFAULT_BYTES),
        "aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7"
    );
}

#[test]
fn github_default_source_identifies_the_exact_source_free_bytes() {
    let rules = github_default_rule_set().unwrap();
    let mut object = serde_json::to_value(&rules).unwrap();
    object.as_object_mut().unwrap().remove("source").unwrap();
    assert_eq!(canonical_bytes(&object).unwrap(), GITHUB_DEFAULT_BYTES);
    assert_eq!(rules.source.release, "cortexkit-defaults-2026.11");
    assert_eq!(rules.source.sha256, policy_sha256(GITHUB_DEFAULT_BYTES));
}

#[test]
fn github_default_passes_model_checks_and_only_allows_unprompted_reads_and_speech() {
    let rules = github_default_rule_set().unwrap();
    assert_eq!(rules.rule_set, "github");
    assert_eq!(rules.revision, 1);
    assert_eq!(rules.extractor, "github-rest-graphql/v1");
    assert_eq!(rules.hosts, ["api.github.com", "uploads.github.com"]);
    assert!(rules.redirect_hosts.is_empty());
    assert_eq!(rules.kinds.len(), 39); // 38 reviewed catalog rows plus node_repository.
    for kind in &rules.kinds {
        assert!(
            matches!(kind.class, Class::Read | Class::Speech),
            "{}",
            kind.kind
        );
        assert_eq!(kind.approval, Approval::None, "{}", kind.kind);
        assert_eq!(kind.identity, Identity::Agent, "{}", kind.kind);
        let permissions = &kind.credential.as_ref().unwrap().github_permissions;
        assert!(
            permissions.values().all(|level| level != "admin"),
            "{}",
            kind.kind
        );
        if kind.class == Class::Read {
            assert!(
                permissions.values().all(|level| level == "read"),
                "{}",
                kind.kind
            );
        }
    }
    for action in &rules.actions {
        assert_eq!(
            action.requirements(&rules).unwrap(),
            (Class::Speech, Approval::None)
        );
    }
}

#[test]
fn github_default_actions_match_the_ordered_plexus_catalog_transcription() {
    // Plexus's request kinds and their ordered write legs, typed from the same
    // catalog export named in defaults.rs and kept apart from the embedded JSON,
    // so an edit to the JSON alone fails here. The bool marks a conditional leg.
    type ExpectedAction = (&'static str, &'static [(&'static str, bool)]);
    let expected: [ExpectedAction; 21] = [
        ("comment", &[("add_issue_comment", false)]),
        ("comment_edit_last", &[("update_issue_comment", false)]),
        ("comment_edit", &[("update_issue_comment", false)]),
        ("pr_review", &[("add_pr_review", false)]),
        ("reaction", &[("add_reaction", false)]),
        ("issue_create", &[("create_issue", false)]),
        (
            "issue_edit",
            &[
                ("edit_issue", true),
                ("add_issue_labels", true),
                ("remove_issue_label", true),
                ("add_issue_assignees", true),
                ("remove_issue_assignees", true),
            ],
        ),
        ("pr_create", &[("create_pull_request", false)]),
        (
            "close",
            &[("add_issue_comment", true), ("close_issue", false)],
        ),
        (
            "reopen",
            &[("add_issue_comment", true), ("reopen_issue", false)],
        ),
        ("pr_ready", &[("mark_pull_request_ready", true)]),
        ("pr_draft", &[("convert_pull_request_to_draft", true)]),
        ("pr_enqueue", &[("enqueue_pull_request", true)]),
        ("pr_dequeue", &[("dequeue_pull_request", true)]),
        ("pr_edit", &[("edit_pull_request", false)]),
        ("review_reply", &[("reply_to_review_comment", false)]),
        ("resolve_thread", &[("resolve_review_thread", false)]),
        ("unresolve_thread", &[("unresolve_review_thread", false)]),
        ("stack_create", &[("create_pull_request_stack", false)]),
        ("stack_add", &[("add_to_pull_request_stack", false)]),
        ("stack_unstack", &[("unstack_pull_requests", false)]),
    ];

    let rules = github_default_rule_set().unwrap();
    assert_eq!(rules.actions.len(), expected.len());
    for (action, (name, legs)) in rules.actions.iter().zip(expected) {
        assert_eq!(action.action, name);
        let actual: Vec<_> = action
            .legs
            .iter()
            .map(|leg| (leg.kind.as_str(), leg.optional.unwrap_or(false)))
            .collect();
        assert_eq!(actual, legs, "{name}");
    }
}
