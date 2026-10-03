//! The `auth_method` a `credential.list_scoped` row reports.
//!
//! Derived on every read from two facts of the UNSEALED record, its
//! [`CredentialKind`] and its stored `refresh_adapter`, and from nothing else: never
//! stored, never parsed from the credential id, never read from the catalog, the
//! categories or `serves`. The credential id is a name an operator chose, and the stored
//! adapter can differ from what the id suggests, so only the record says how the
//! credential authenticates.
//!
//! Deliberately a separate type from [`crate::credential_id::AuthMethod`], which is the
//! id-scheme segment parsed from a credential id and has a wider vocabulary. The set
//! here is CLOSED: adding a value is a breaking change to `credential.list_scoped`.

use crate::record::CredentialKind;
use crate::refresh_adapters::{
    anthropic, antigravity, cursor, github_copilot, google, kimi, openai, xai,
};

/// The closed set of `auth_method` values a listed row can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ListAuthMethod {
    /// A static API key, whatever adapter (if any) it names.
    Apikey,
    /// An OAuth record refreshed by the `openai` adapter. `chatgpt:openai` and
    /// `oauth:openai` both store that adapter, so both report this value.
    Chatgpt,
    /// An OAuth record refreshed by the `antigravity` adapter.
    Antigravity,
    /// An OAuth record refreshed by one of the provider adapters whose tokens a consumer
    /// presents as an ordinary OAuth bearer.
    Oauth,
}

impl ListAuthMethod {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ListAuthMethod::Apikey => "apikey",
            ListAuthMethod::Chatgpt => "chatgpt",
            ListAuthMethod::Antigravity => "antigravity",
            ListAuthMethod::Oauth => "oauth",
        }
    }
}

/// Map a record's kind and stored refresh adapter to its listed `auth_method`, or
/// `None` when the wire key is to be omitted.
///
/// The table, where an adapter of `None` means the record stores none:
///
/// | kind | adapter | result |
/// |---|---|---|
/// | `ApiKey` | `None` or any string | `apikey` |
/// | `Oauth` | `openai` | `chatgpt` |
/// | `Oauth` | `antigravity` | `antigravity` |
/// | `Oauth` | `anthropic`, `google`, `xai`, `kimi`, `cursor`, `github-copilot` | `oauth` |
/// | `Oauth` | `github_app`, `devin`, `digitalocean`, `snowflake`, `None`, any other | omitted |
/// | `Dsn`, `Cookie`, `Opaque`, `SigningKey`, `KemKey` | anything | omitted |
pub fn list_auth_method(
    kind: CredentialKind,
    refresh_adapter: Option<&str>,
) -> Option<ListAuthMethod> {
    match kind {
        CredentialKind::ApiKey => Some(ListAuthMethod::Apikey),
        CredentialKind::Oauth => match refresh_adapter? {
            openai::ADAPTER_NAME => Some(ListAuthMethod::Chatgpt),
            antigravity::ADAPTER_NAME => Some(ListAuthMethod::Antigravity),
            anthropic::ADAPTER_NAME
            | google::ADAPTER_NAME
            | xai::ADAPTER_NAME
            | kimi::ADAPTER_NAME
            | cursor::ADAPTER_NAME
            | github_copilot::ADAPTER_NAME => Some(ListAuthMethod::Oauth),
            // `github_app`, `devin`, `digitalocean`, `snowflake`, and any adapter this
            // table has not been taught: no closed value describes them, so the key is
            // omitted rather than guessed.
            _ => None,
        },
        CredentialKind::Dsn
        | CredentialKind::Cookie
        | CredentialKind::Opaque
        | CredentialKind::SigningKey
        | CredentialKind::KemKey => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_adapters::{devin, digitalocean, github_app, snowflake};

    const ALL_KINDS: [CredentialKind; 7] = [
        CredentialKind::Oauth,
        CredentialKind::ApiKey,
        CredentialKind::Dsn,
        CredentialKind::Cookie,
        CredentialKind::Opaque,
        CredentialKind::SigningKey,
        CredentialKind::KemKey,
    ];

    /// Every adapter name the crate defines, with the value an OAuth record using it
    /// reports. Spelled out literally so a change to the table reddens here.
    const OAUTH_TABLE: [(&str, Option<&str>); 12] = [
        (anthropic::ADAPTER_NAME, Some("oauth")),
        (openai::ADAPTER_NAME, Some("chatgpt")),
        (google::ADAPTER_NAME, Some("oauth")),
        (xai::ADAPTER_NAME, Some("oauth")),
        (kimi::ADAPTER_NAME, Some("oauth")),
        (cursor::ADAPTER_NAME, Some("oauth")),
        (github_copilot::ADAPTER_NAME, Some("oauth")),
        (antigravity::ADAPTER_NAME, Some("antigravity")),
        (github_app::ADAPTER_NAME, None),
        (devin::ADAPTER_NAME, None),
        (digitalocean::ADAPTER_NAME, None),
        (snowflake::ADAPTER_NAME, None),
    ];

    fn wire(kind: CredentialKind, adapter: Option<&str>) -> Option<&'static str> {
        list_auth_method(kind, adapter).map(ListAuthMethod::as_str)
    }

    #[test]
    fn every_kind_and_adapter_maps_to_its_table_value() {
        // An exhaustive match over the kind, so a new kind cannot compile without a
        // decision here about what it reports.
        for kind in ALL_KINDS {
            let expected_for_adapter = |adapter: Option<&str>| -> Option<&'static str> {
                match kind {
                    CredentialKind::ApiKey => Some("apikey"),
                    CredentialKind::Oauth => adapter.and_then(|name| {
                        OAUTH_TABLE
                            .iter()
                            .find(|(known, _)| *known == name)
                            .and_then(|(_, value)| *value)
                    }),
                    CredentialKind::Dsn
                    | CredentialKind::Cookie
                    | CredentialKind::Opaque
                    | CredentialKind::SigningKey
                    | CredentialKind::KemKey => None,
                }
            };
            let mut adapters: Vec<Option<&str>> =
                OAUTH_TABLE.iter().map(|(name, _)| Some(*name)).collect();
            adapters.extend([None, Some("not-an-adapter"), Some(""), Some("OPENAI")]);
            for adapter in adapters {
                assert_eq!(
                    wire(kind, adapter),
                    expected_for_adapter(adapter),
                    "{kind:?} + {adapter:?}"
                );
            }
        }
    }

    #[test]
    fn the_twelve_adapters_yield_eight_values_and_four_omissions() {
        let values = OAUTH_TABLE
            .iter()
            .filter(|(name, _)| wire(CredentialKind::Oauth, Some(name)).is_some())
            .count();
        assert_eq!(values, 8);
        let mut names: Vec<&str> = OAUTH_TABLE.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 12, "each adapter name is listed once");
    }

    #[test]
    fn the_credential_id_is_never_consulted() {
        // The function takes no id, and these pairs are what an id that disagrees with
        // its stored adapter would carry: the adapter alone decides.
        assert_eq!(
            wire(CredentialKind::Oauth, Some("antigravity")),
            Some("antigravity"),
            "an oauth:* id storing the antigravity adapter"
        );
        assert_eq!(
            wire(CredentialKind::Oauth, Some("anthropic")),
            Some("oauth"),
            "a chatgpt:* id storing the anthropic adapter"
        );
        assert_eq!(wire(CredentialKind::ApiKey, None), Some("apikey"));
        assert_eq!(wire(CredentialKind::ApiKey, Some("openai")), Some("apikey"));
        assert_eq!(wire(CredentialKind::Oauth, None), None);
        assert_eq!(wire(CredentialKind::SigningKey, Some("openai")), None);
    }
}
