//! Reviewed provider ids and display facts from Fusiform's pinned provider list.
//!
//! The list is compiled in, not fetched at runtime. It supplies no credential groups,
//! authorization rules or receiving hosts; those remain the vault's own decisions.

use std::sync::OnceLock;

use serde::Deserialize;

/// Exact upstream bytes, shared by release code and the vendoring hash test.
pub const FUSIFORM_PROVIDERS_JSON: &[u8] =
    include_bytes!("../tests/fixtures/fusiform/providers-v1.json");

/// The only provider fields the vault reads from Fusiform.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FusiformProvider {
    pub id: String,
    pub name: String,
    pub doc: String,
    /// Upstream provenance: `models.dev` or Fusiform's manually maintained `hand_kept` entries.
    pub source: String,
    pub output_modalities: Vec<String>,
    /// Upstream key-variable names, kept verbatim rather than normalized.
    pub env: Vec<String>,
}

#[derive(Deserialize)]
struct ProviderList {
    providers: Vec<FusiformProvider>,
}

fn parse_provider_list(bytes: &[u8]) -> serde_json::Result<Vec<FusiformProvider>> {
    serde_json::from_slice::<ProviderList>(bytes).map(|list| list.providers)
}

/// Return the compiled-in provider list, in upstream order.
pub fn fusiform_providers() -> &'static [FusiformProvider] {
    static PROVIDERS: OnceLock<Vec<FusiformProvider>> = OnceLock::new();
    PROVIDERS.get_or_init(|| {
        parse_provider_list(FUSIFORM_PROVIDERS_JSON)
            .expect("the pinned Fusiform provider list must decode")
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn embedded_bytes_match_the_vendored_sha256_pin() {
        let manifest = include_str!("../tests/fixtures/fusiform/VENDORED.md");
        let rows: Vec<Vec<&str>> = manifest
            .lines()
            .filter(|line| line.starts_with('|'))
            .map(|line| {
                line.trim_matches('|')
                    .split('|')
                    .map(|cell| cell.trim().trim_matches('`'))
                    .collect::<Vec<_>>()
            })
            .filter(|cells| cells.first() == Some(&"providers-v1.json"))
            .collect();
        assert_eq!(rows.len(), 1, "VENDORED.md must pin the provider file once");
        assert_eq!(rows[0].len(), 5, "VENDORED.md pin table columns changed");
        let pin = rows[0][3];
        assert_eq!(pin.len(), 64, "VENDORED.md must contain a full sha256");
        assert_eq!(
            format!("{:x}", Sha256::digest(FUSIFORM_PROVIDERS_JSON)),
            pin
        );
    }

    #[test]
    fn published_providers_decode_with_unique_ids_and_verbatim_fields() {
        let providers = fusiform_providers();
        assert!(!providers.is_empty());
        let mut ids = BTreeSet::new();
        for provider in providers {
            assert!(!provider.id.is_empty());
            assert!(ids.insert(&provider.id), "duplicate id: {}", provider.id);
            assert!(!provider.name.is_empty());
            assert!(matches!(
                provider.source.as_str(),
                "models.dev" | "hand_kept"
            ));
        }

        let first = &providers[0];
        assert_eq!(first.id, "302ai");
        assert_eq!(first.name, "302.AI");
        assert_eq!(first.doc, "https://doc.302.ai");
        assert_eq!(first.source, "models.dev");
        assert_eq!(first.output_modalities, ["image", "text"]);
        assert_eq!(first.env, ["302AI_API_KEY"]);
    }

    #[test]
    fn parser_ignores_fields_outside_the_display_allowlist() {
        let mut published: serde_json::Value =
            serde_json::from_slice(FUSIFORM_PROVIDERS_JSON).unwrap();
        published["format"] = serde_json::Value::Null;
        published["snapshot_fetched_at"] = serde_json::Value::Null;
        for provider in published["providers"].as_array_mut().unwrap() {
            let fields = provider.as_object_mut().unwrap();
            for ignored in ["brand_id", "api_key", "hosts", "auth", "groups"] {
                fields.insert(ignored.to_owned(), serde_json::Value::Bool(true));
            }
        }

        assert_eq!(
            parse_provider_list(&serde_json::to_vec(&published).unwrap()).unwrap(),
            fusiform_providers()
        );
    }
}
