use super::{
    github_default_rule_set, github_rule_set_for_release, GITHUB_DEFAULT_RELEASE,
    GITHUB_DEFAULT_SHA256, GITHUB_RELEASES,
};
use crate::agent_policy::{
    canonical_bytes, policy_sha256, Approval, Class, Constraints, Identity, Request,
};

const GITHUB_DEFAULT_BYTES: &[u8] = include_bytes!("../../../policy-defaults/github.json");

#[test]
fn github_release_artifact_sha256_is_pinned() {
    let mut keys = std::collections::BTreeSet::new();
    for entry in GITHUB_RELEASES {
        assert!(
            keys.insert((entry.release, entry.sha256)),
            "duplicate default key"
        );
        assert_eq!(
            policy_sha256(entry.bytes),
            entry.sha256,
            "{}",
            entry.release
        );
    }
    assert_eq!(policy_sha256(GITHUB_DEFAULT_BYTES), GITHUB_DEFAULT_SHA256);
    assert!(keys.contains(&(GITHUB_DEFAULT_RELEASE, GITHUB_DEFAULT_SHA256)));
}

#[test]
fn github_default_source_identifies_the_exact_source_free_bytes() {
    let rules = github_default_rule_set().unwrap();
    let mut object = serde_json::to_value(&rules).unwrap();
    object.as_object_mut().unwrap().remove("source").unwrap();
    assert_eq!(canonical_bytes(&object).unwrap(), GITHUB_DEFAULT_BYTES);
    assert_eq!(rules.source.release, "cortexkit-defaults-2026.11.2");
    assert_eq!(rules.source.sha256, policy_sha256(GITHUB_DEFAULT_BYTES));
}

#[test]
fn github_default_passes_model_checks_and_only_allows_unprompted_reads_and_speech() {
    let rules = github_default_rule_set().unwrap();
    assert_eq!(rules.rule_set, "github");
    assert_eq!(rules.revision, 2);
    assert_eq!(rules.extractor, "github-rest-graphql/v1");
    assert_eq!(rules.hosts, ["api.github.com", "uploads.github.com"]);
    assert!(rules.redirect_hosts.is_empty());
    assert_eq!(rules.kinds.len(), 45);
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
fn github_revision_two_only_appends_six_non_overlapping_reads() {
    let first = &GITHUB_RELEASES[0];
    let revision_one = github_rule_set_for_release(first.release, first.sha256).unwrap();
    let mut revision_two = github_default_rule_set().unwrap();
    let appended = revision_two.kinds.split_off(revision_one.kinds.len());
    revision_two.revision = revision_one.revision;
    revision_two.source = revision_one.source.clone();
    assert_eq!(revision_two, revision_one);

    let expected: [(&str, &str, &[&str]); 6] = [
        (
            "github.issue_timeline.list",
            "issues/{number}/timeline",
            &["issues", "pull_requests"],
        ),
        (
            "github.commit.check_runs",
            "commits/{name}/check-runs",
            &["checks"],
        ),
        (
            "github.commit.status",
            "commits/{name}/status",
            &["statuses"],
        ),
        (
            "github.git.matching_refs",
            "git/matching-refs/{ref*}",
            &["contents"],
        ),
        ("github.actions.run.get", "actions/runs/{id}", &["actions"]),
        (
            "github.actions.run.jobs",
            "actions/runs/{id}/jobs",
            &["actions"],
        ),
    ];
    assert_eq!(appended.len(), expected.len());
    for (kind, (name, suffix, permissions)) in appended.iter().zip(expected) {
        assert_eq!(kind.kind, name);
        assert_eq!(kind.class, Class::Read, "{name}");
        assert!(kind.ownership.is_none() && kind.consent.is_none(), "{name}");
        let actual_permissions = &kind.credential.as_ref().unwrap().github_permissions;
        assert_eq!(actual_permissions.len(), permissions.len(), "{name}");
        for permission in permissions {
            assert_eq!(actual_permissions[*permission], "read", "{name}");
        }
        let [Request::Rest(rest)] = kind.requests.as_slice() else {
            panic!("expected one REST request for {name}");
        };
        assert_eq!(rest.host, "api.github.com", "{name}");
        assert_eq!(rest.method, "GET", "{name}");
        assert_eq!(
            rest.path,
            format!("/repos/{{owner}}/{{repo}}/{suffix}"),
            "{name}"
        );
        assert!(rest.body.is_none(), "{name}");
        let query = (name == "github.issue_timeline.list").then(|| Constraints {
            optional: Some(vec!["page".into(), "per_page".into()]),
            ..Constraints::default()
        });
        assert_eq!(rest.query, query, "{name}");
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
