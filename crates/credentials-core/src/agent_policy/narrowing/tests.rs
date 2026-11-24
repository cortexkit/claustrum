use super::*;
use crate::agent_policy::{
    github_default_rule_set, Class, Consent, Identity, AGENT_POLICY_SCHEMA_V1,
};

fn with_shipped_default(edit: impl FnOnce(&mut RuleSet)) -> Result<(), PolicyError> {
    let mut rules = github_default_rule_set().unwrap();
    edit(&mut rules);
    let policy = AgentPolicy {
        schema: AGENT_POLICY_SCHEMA_V1.into(),
        version: 1,
        issued_at_unix_secs: 1,
        root_key_id: "0123456789abcdef".into(),
        rule_sets: [("github".into(), rules)].into(),
        bindings: vec![],
    };
    let policy = AgentPolicy::parse_canonical(&policy.canonical_bytes().unwrap()).unwrap();
    validate_signer_rule_sets(&policy)
}

fn kind_mut<'a>(rules: &'a mut RuleSet, name: &str) -> &'a mut Kind {
    rules
        .kinds
        .iter_mut()
        .find(|kind| kind.kind == name)
        .unwrap()
}

fn multi_request_kind(rules: &mut RuleSet) -> &mut Kind {
    rules
        .kinds
        .iter_mut()
        .find(|kind| kind.requests.len() > 1)
        .unwrap()
}

#[test]
fn signer_accepts_the_named_release_unchanged() {
    assert_eq!(with_shipped_default(|_| {}), Ok(()));
}

#[test]
fn signer_allows_removing_a_kind() {
    assert_eq!(
        with_shipped_default(|rules| {
            let unreferenced = rules
                .kinds
                .iter()
                .position(|kind| {
                    kind.kind != "node_repository"
                        && !rules
                            .actions
                            .iter()
                            .flat_map(|a| &a.legs)
                            .any(|leg| leg.kind == kind.kind)
                        && !rules
                            .kinds
                            .iter()
                            .filter_map(|k| k.ownership.as_ref())
                            .any(|own| own.reads.contains(&kind.kind))
                })
                .unwrap();
            rules.kinds.remove(unreferenced);
        }),
        Ok(())
    );
}

#[test]
fn signer_allows_removing_an_action() {
    assert_eq!(
        with_shipped_default(|rules| {
            rules.actions.remove(0);
        }),
        Ok(())
    );
}

#[test]
fn signer_allows_changing_approval_from_none_to_once() {
    assert_eq!(
        with_shipped_default(|rules| kind_mut(rules, "add_issue_comment").approval = Approval::Once),
        Ok(())
    );
}

#[test]
fn signer_allows_removing_a_permission_entry() {
    assert_eq!(
        with_shipped_default(|rules| {
            let permissions = &mut kind_mut(rules, "enqueue_pull_request")
                .credential
                .as_mut()
                .unwrap()
                .github_permissions;
            assert_eq!(permissions.remove("merge_queues").as_deref(), Some("write"));
        }),
        Ok(())
    );
}

#[test]
fn signer_allows_lowering_a_permission_level() {
    assert_eq!(
        with_shipped_default(|rules| {
            let level = kind_mut(rules, "add_issue_comment")
                .credential
                .as_mut()
                .unwrap()
                .github_permissions
                .values_mut()
                .find(|level| level.as_str() == "write")
                .unwrap();
            *level = "read".into();
        }),
        Ok(())
    );

    // The shipped revision has no admin permissions, so exercise the complete ladder
    // against a baseline containing admin as well.
    let default = BTreeMap::from([("issues".into(), "admin".into())]);
    for lower in ["write", "read"] {
        assert!(permissions_are_narrower_or_equal(
            &BTreeMap::from([("issues".into(), lower.into())]),
            &default
        ));
    }
}

#[test]
fn signer_allows_removing_a_request_alternative() {
    assert_eq!(
        with_shipped_default(|rules| {
            multi_request_kind(rules).requests.remove(0);
        }),
        Ok(())
    );
}

#[test]
fn signer_refuses_an_unknown_default_release() {
    assert_eq!(
        with_shipped_default(|rules| rules.source.release = "unknown-release".into()),
        Err(PolicyError::UnknownDefaultRelease)
    );
}

#[test]
fn signer_refuses_an_unknown_default_digest() {
    assert_eq!(
        with_shipped_default(|rules| rules.source.sha256 = "0".repeat(64)),
        Err(PolicyError::UnknownDefaultDigest)
    );
}

#[test]
fn signer_refuses_rule_set_metadata_changes() {
    fn revision(rules: &mut RuleSet) {
        rules.revision += 1;
    }
    fn remove_host(rules: &mut RuleSet) {
        rules.hosts.retain(|host| !host.starts_with("uploads."));
    }
    fn change_redirects(rules: &mut RuleSet) {
        rules
            .redirect_hosts
            .push(format!("redirect.{}", rules.hosts[0]));
    }
    for (case, edit) in [
        ("revision", revision as fn(&mut RuleSet)),
        ("host", remove_host),
        ("redirect hosts", change_redirects),
    ] {
        assert_eq!(
            with_shipped_default(edit),
            Err(PolicyError::RuleSetNotNarrowed),
            "{case}"
        );
    }

    let default = github_default_rule_set().unwrap();
    let mut candidate = default.clone();
    candidate.rule_set.push_str("-other");
    assert_eq!(
        validate_narrowing(&candidate, &default),
        Err(PolicyError::RuleSetNotNarrowed)
    );
    let mut candidate = default.clone();
    candidate.extractor.push_str("-other");
    assert_eq!(
        validate_narrowing(&candidate, &default),
        Err(PolicyError::RuleSetNotNarrowed)
    );
}

#[test]
fn signer_refuses_changes_to_kinds_or_request_alternatives() {
    fn new_kind(rules: &mut RuleSet) {
        let mut denied = rules.kinds[0].clone();
        denied.kind = "unknown".into();
        denied.class = Class::Denied;
        denied.requests.clear();
        denied.credential = None;
        denied.ownership = None;
        denied.consent = None;
        rules.kinds.push(denied);
    }
    fn class(rules: &mut RuleSet) {
        let kind = kind_mut(rules, "add_issue_comment");
        kind.class = Class::Operator;
        kind.approval = Approval::Once;
    }
    fn identity(rules: &mut RuleSet) {
        let kind = kind_mut(rules, "github.repo.get");
        kind.identity = Identity::Anonymous;
        kind.credential = None;
    }
    fn remove_credential(rules: &mut RuleSet) {
        kind_mut(rules, "add_issue_comment").credential = None;
    }
    fn ownership(rules: &mut RuleSet) {
        kind_mut(rules, "update_issue_comment").ownership = None;
    }
    fn consent(rules: &mut RuleSet) {
        let kind = kind_mut(rules, "add_issue_comment");
        kind.approval = Approval::Once;
        kind.consent = Some(Consent {
            fields: vec!["body".into()],
        });
    }
    fn request(rules: &mut RuleSet) {
        let request = &mut kind_mut(rules, "add_issue_comment").requests[0];
        let super::super::Request::Rest(rest) = request else {
            panic!("expected REST");
        };
        rest.path.push_str("/extended");
    }
    fn reorder_requests(rules: &mut RuleSet) {
        multi_request_kind(rules).requests.swap(0, 1);
    }
    fn reorder_kinds(rules: &mut RuleSet) {
        rules.kinds.swap(0, 1);
    }
    for (case, edit) in [
        ("new kind", new_kind as fn(&mut RuleSet)),
        ("class", class),
        ("identity", identity),
        ("credential", remove_credential),
        ("ownership", ownership),
        ("consent", consent),
        ("request", request),
        ("request order", reorder_requests),
        ("kind order", reorder_kinds),
    ] {
        assert_eq!(
            with_shipped_default(edit),
            Err(PolicyError::RuleSetNotNarrowed),
            "{case}"
        );
    }
}

#[test]
fn signer_refuses_lowering_approval_from_once_to_none() {
    let candidate = github_default_rule_set().unwrap();
    let mut default = candidate.clone();
    kind_mut(&mut default, "add_issue_comment").approval = Approval::Once;
    assert_eq!(
        validate_narrowing(&candidate, &default),
        Err(PolicyError::RuleSetNotNarrowed)
    );
}

#[test]
fn signer_refuses_adding_or_raising_permissions() {
    assert_eq!(
        with_shipped_default(|rules| {
            kind_mut(rules, "add_issue_comment")
                .credential
                .as_mut()
                .unwrap()
                .github_permissions
                .insert("new_permission".into(), "read".into());
        }),
        Err(PolicyError::RuleSetNotNarrowed)
    );

    assert_eq!(
        with_shipped_default(|rules| {
            let permissions = &mut kind_mut(rules, "add_issue_comment")
                .credential
                .as_mut()
                .unwrap()
                .github_permissions;
            let level = permissions
                .values_mut()
                .find(|level| level.as_str() == "write")
                .unwrap();
            *level = "admin".into();
        }),
        Err(PolicyError::RuleSetNotNarrowed)
    );
}

#[test]
fn signer_refuses_adding_or_editing_actions() {
    assert_eq!(
        with_shipped_default(|rules| {
            let mut action = rules.actions[0].clone();
            action.action = "unknown".into();
            rules.actions.push(action);
        }),
        Err(PolicyError::RuleSetNotNarrowed)
    );

    assert_eq!(
        with_shipped_default(|rules| rules.actions[0].legs[0].optional = Some(true)),
        Err(PolicyError::RuleSetNotNarrowed)
    );
    assert_eq!(
        with_shipped_default(|rules| rules.actions.swap(0, 1)),
        Err(PolicyError::RuleSetNotNarrowed)
    );
}
