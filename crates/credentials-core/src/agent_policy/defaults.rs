use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{canonical_bytes, parse_canonical, PolicyError, RuleSet};

// Transcribed from the action catalog of Plexus (CortexKit's GitHub module, the
// public github.com/cortexkit/plexus repository) at commit 187baca911cc: an export
// of its catalog entries with SHA-256
// 1275025ad276e57f5ab702dc99f6c3f36350c4478302690caee396271744d8e1.
// update_issue_comment checks the target's author; Plexus selects the last own
// comment for edit-last. Search has no repository in its URL: Plexus supplies
// the bound repository to the token partner, and the HTTP broker can't route it.
// github.repo.get covers only the exact repository root, not Plexus's suffix reads.
const GITHUB_DEFAULT_RELEASE: &str = "cortexkit-defaults-2026.11";
const GITHUB_DEFAULT_SHA256: &str =
    "aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7";

struct Release {
    release: &'static str,
    sha256: &'static str,
    bytes: &'static [u8],
}

// Append entries on release. Signed policies can keep referring to any earlier
// entry, so each entry embeds its own immutable copy of the release artifact.
const GITHUB_RELEASES: &[Release] = &[Release {
    release: "cortexkit-defaults-2026.11",
    sha256: "aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7",
    bytes: include_bytes!("../../policy-defaults/github-2026.11.json"),
}];

/// Load the release default for GitHub, with `source` identifying the embedded bytes.
pub fn github_default_rule_set() -> Result<RuleSet, PolicyError> {
    github_rule_set_for_release(GITHUB_DEFAULT_RELEASE, GITHUB_DEFAULT_SHA256)
}

pub(super) fn github_rule_set_for_release(
    release: &str,
    sha256: &str,
) -> Result<RuleSet, PolicyError> {
    let mut matching = GITHUB_RELEASES
        .iter()
        .filter(|item| item.release == release)
        .peekable();
    if matching.peek().is_none() {
        return Err(PolicyError::UnknownDefaultRelease);
    }
    let artifact = matching
        .find(|item| item.sha256 == sha256)
        .ok_or(PolicyError::UnknownDefaultDigest)?;
    let mut object: BTreeMap<String, Value> = parse_canonical(artifact.bytes)?;
    // The release artifact omits source so its digest doesn't depend on itself.
    if object
        .insert(
            "source".to_owned(),
            json!({"release": artifact.release, "sha256": artifact.sha256}),
        )
        .is_some()
    {
        return Err(PolicyError::InvalidShape);
    }
    RuleSet::parse_canonical(&canonical_bytes(&object)?)
}

#[cfg(test)]
mod tests;
