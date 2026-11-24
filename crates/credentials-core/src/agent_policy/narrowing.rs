use std::collections::BTreeMap;

use super::{
    defaults::github_rule_set_for_release, AgentPolicy, Approval, Kind, PolicyError, RuleSet,
};

/// The signer accepts only the shipped release or an explicitly permitted reduction.
/// Model parsing alone does not consult the vault's release defaults.
pub(crate) fn validate_signer_rule_sets(policy: &AgentPolicy) -> Result<(), PolicyError> {
    for rules in policy.rule_sets.values() {
        validate_narrowing(
            rules,
            &github_rule_set_for_release(&rules.source.release, &rules.source.sha256)?,
        )?;
    }
    Ok(())
}

fn validate_narrowing(rules: &RuleSet, default: &RuleSet) -> Result<(), PolicyError> {
    let RuleSet {
        rule_set,
        revision,
        source: _,
        extractor,
        hosts,
        redirect_hosts,
        kinds,
        actions,
    } = rules;
    if rule_set != &default.rule_set
        || revision != &default.revision
        || extractor != &default.extractor
        || hosts != &default.hosts
        || redirect_hosts != &default.redirect_hosts
        || !is_subsequence(actions, &default.actions, PartialEq::eq)
        || !is_subsequence(kinds, &default.kinds, kind_is_narrower_or_equal)
    {
        return Err(PolicyError::RuleSetNotNarrowed);
    }
    Ok(())
}

fn kind_is_narrower_or_equal(kind: &Kind, default: &Kind) -> bool {
    let Kind {
        kind,
        class,
        approval,
        identity,
        credential,
        ownership,
        requests,
        consent,
    } = kind;
    let safe_permissions = match (credential, &default.credential) {
        (None, None) => true,
        (Some(credential), Some(default)) => permissions_are_narrower_or_equal(
            &credential.github_permissions,
            &default.github_permissions,
        ),
        _ => false,
    };
    kind == &default.kind
        && class == &default.class
        && (*approval == default.approval
            || (default.approval, *approval) == (Approval::None, Approval::Once))
        && identity == &default.identity
        && ownership == &default.ownership
        && consent == &default.consent
        && safe_permissions
        && is_subsequence(requests, &default.requests, PartialEq::eq)
}

fn permissions_are_narrower_or_equal(
    permissions: &BTreeMap<String, String>,
    default: &BTreeMap<String, String>,
) -> bool {
    permissions.iter().all(|(name, level)| {
        let baseline = default.get(name).map(String::as_str);
        matches!(
            (level.as_str(), baseline),
            ("admin", Some("admin"))
                | ("write", Some("write" | "admin"))
                | ("read", Some("read" | "write" | "admin"))
        )
    })
}

// Only deletion is allowed: retained entries stay in their original order.
fn is_subsequence<T>(candidate: &[T], baseline: &[T], matches: impl Fn(&T, &T) -> bool) -> bool {
    let mut baseline = baseline.iter();
    candidate
        .iter()
        .all(|item| baseline.any(|original| matches(item, original)))
}

#[cfg(test)]
mod tests;
