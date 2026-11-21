use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{canonical_bytes, parse_canonical, policy_sha256, PolicyError, RuleSet};

// Catalog export from Plexus 187baca911cc, SHA-256:
// 1275025ad276e57f5ab702dc99f6c3f36350c4478302690caee396271744d8e1.
// update_issue_comment checks the target's author; Plexus selects the last own
// comment for edit-last. Search has no repository in its URL: Plexus supplies
// the bound repository to the token partner, and the HTTP broker can't route it.
// github.repo.get covers only the exact repository root, not Plexus's suffix reads.
const GITHUB_DEFAULT_BYTES: &[u8] = include_bytes!("../../policy-defaults/github.json");
const GITHUB_DEFAULT_RELEASE: &str = "cortexkit-defaults-2026.11";

/// Load the release default for GitHub, with `source` identifying the embedded bytes.
pub fn github_default_rule_set() -> Result<RuleSet, PolicyError> {
    let mut object: BTreeMap<String, Value> = parse_canonical(GITHUB_DEFAULT_BYTES)?;
    // The release artifact omits source so its digest doesn't depend on itself.
    if object
        .insert(
            "source".to_owned(),
            json!({"release": GITHUB_DEFAULT_RELEASE, "sha256": policy_sha256(GITHUB_DEFAULT_BYTES)}),
        )
        .is_some()
    {
        return Err(PolicyError::InvalidShape);
    }
    RuleSet::parse_canonical(&canonical_bytes(&object)?)
}

#[cfg(test)]
mod tests;
