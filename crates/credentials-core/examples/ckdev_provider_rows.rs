//! Print reviewable catalog proposals; never write catalog rows or provider settings.
//! Run with `cargo run -p credentials-core --example ckdev_provider_rows`.

use credentials_core::catalog::missing_fusiform_providers;
use credentials_core::fusiform_providers::FusiformProvider;
use credentials_core::CredentialCategory;

fn proposal_categories(modalities: &[String]) -> Vec<CredentialCategory> {
    let mut categories = Vec::new();
    if modalities.iter().any(|modality| modality == "text") {
        categories.push(CredentialCategory::LlmProvider);
    }
    if modalities
        .iter()
        .any(|modality| matches!(modality.as_str(), "audio" | "image" | "video"))
    {
        categories.push(CredentialCategory::MediaProvider);
    }
    categories
}

fn proposed_row(provider: &FusiformProvider) -> String {
    let categories = proposal_categories(&provider.output_modalities);
    let default_provider_ids = if categories.contains(&CredentialCategory::LlmProvider) {
        format!("&[{:?}]", provider.id)
    } else {
        "&[]".to_owned()
    };
    let categories = categories
        .iter()
        .map(|category| format!("CredentialCategory::{category:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    // Deliberately incomplete: display facts cannot establish how or where to send a key.
    format!(
        "ApiKeyProvider {{\n\
         \x20   key: {id:?},\n\
         \x20   fusiform_provider_id: Some({id:?}),\n\
         \x20   default_provider_ids: {default_provider_ids},\n\
         \x20   display_name: {name:?},\n\
         \x20   default_id: {default_id:?},\n\
         \x20   dashboard_url: todo!(\"from provider documentation\"),\n\
         \x20   placeholder: todo!(\"from provider documentation\"),\n\
         \x20   auth: todo!(\"from provider documentation\"),\n\
         \x20   hosts: todo!(\"from provider documentation\"),\n\
         \x20   hosts_doc: todo!(\"from provider documentation\"),\n\
         \x20   invalid_key: None,\n\
         \x20   validation: todo!(\"from provider documentation\"),\n\
         \x20   categories: &[{categories}],\n\
         \x20   serves: &[],\n\
         \x20   account_id_prompt: None,\n\
         }},",
        id = provider.id,
        name = provider.name,
        default_id = format!("apikey:{}", provider.id),
    )
}

fn proposed_rows() -> Vec<String> {
    missing_fusiform_providers()
        .into_iter()
        .map(proposed_row)
        .collect()
}

fn main() {
    for proposal in proposed_rows() {
        println!("{proposal}\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(modalities: &[&str]) -> FusiformProvider {
        FusiformProvider {
            id: "test-provider".to_owned(),
            name: "Test \"Provider\"".to_owned(),
            doc: "".to_owned(),
            source: "hand_kept".to_owned(),
            output_modalities: modalities.iter().map(|value| (*value).to_owned()).collect(),
            env: vec![],
        }
    }

    #[test]
    fn proposer_groups_and_routing_defaults_follow_output_modalities() {
        for (modalities, expected_groups, expected_ids) in [
            (vec!["text"], vec!["llm-provider"], "&[\"test-provider\"]"),
            (vec!["audio"], vec!["media-provider"], "&[]"),
            (vec!["image"], vec!["media-provider"], "&[]"),
            (vec!["video"], vec!["media-provider"], "&[]"),
            (
                vec!["audio", "image", "video"],
                vec!["media-provider"],
                "&[]",
            ),
            (
                vec!["text", "audio"],
                vec!["llm-provider", "media-provider"],
                "&[\"test-provider\"]",
            ),
            (
                vec!["text", "image"],
                vec!["llm-provider", "media-provider"],
                "&[\"test-provider\"]",
            ),
            (
                vec!["video", "text", "text", "video"],
                vec!["llm-provider", "media-provider"],
                "&[\"test-provider\"]",
            ),
            (vec![], vec![], "&[]"),
            (vec!["embedding", "unknown"], vec![], "&[]"),
        ] {
            let provider = provider(&modalities);
            assert_eq!(
                proposal_categories(&provider.output_modalities)
                    .iter()
                    .map(|category| category.as_str())
                    .collect::<Vec<_>>(),
                expected_groups,
                "{modalities:?}"
            );
            assert!(
                proposed_row(&provider).contains(&format!("default_provider_ids: {expected_ids},")),
                "{modalities:?}"
            );
        }
    }

    #[test]
    fn proposer_leaves_documentation_fields_unfilled_and_escapes_display_names() {
        assert_eq!(
            proposed_row(&provider(&["text", "image"])),
            r#"ApiKeyProvider {
    key: "test-provider",
    fusiform_provider_id: Some("test-provider"),
    default_provider_ids: &["test-provider"],
    display_name: "Test \"Provider\"",
    default_id: "apikey:test-provider",
    dashboard_url: todo!("from provider documentation"),
    placeholder: todo!("from provider documentation"),
    auth: todo!("from provider documentation"),
    hosts: todo!("from provider documentation"),
    hosts_doc: todo!("from provider documentation"),
    invalid_key: None,
    validation: todo!("from provider documentation"),
    categories: &[CredentialCategory::LlmProvider, CredentialCategory::MediaProvider],
    serves: &[],
    account_id_prompt: None,
},"#
        );
    }

    #[test]
    fn proposer_emits_exactly_one_row_for_each_uncovered_vendored_id() {
        use credentials_core::catalog::{API_KEY_PROVIDERS, FUSIFORM_PROVIDER_SKIPS};
        use credentials_core::fusiform_providers::FUSIFORM_PROVIDERS_JSON;
        use std::collections::BTreeSet;

        let vendored: serde_json::Value = serde_json::from_slice(FUSIFORM_PROVIDERS_JSON).unwrap();
        let mut expected: BTreeSet<_> = vendored["providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|provider| provider["id"].as_str().unwrap())
            .collect();
        for row in API_KEY_PROVIDERS {
            if let Some(id) = row.fusiform_provider_id {
                expected.remove(id);
            }
        }
        for (id, _) in FUSIFORM_PROVIDER_SKIPS {
            expected.remove(id);
        }
        let actual: Vec<String> = proposed_rows()
            .iter()
            .map(|row| {
                let line = row
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("fusiform_provider_id: Some("))
                    .unwrap();
                serde_json::from_str(line.strip_suffix("),").unwrap()).unwrap()
            })
            .collect();
        assert_eq!(actual, expected.into_iter().collect::<Vec<_>>());
    }
}
