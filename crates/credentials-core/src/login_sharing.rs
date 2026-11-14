//! Shared, content-redacted resolution of the computer's login-sharing setting.

use std::path::{Path, PathBuf};

use serde::Deserialize;

pub fn config_path() -> Result<PathBuf, cortexkit_paths::PathsError> {
    cortexkit_paths::cortexkit_config_dir().map(|dir| dir.join("claustrum.jsonc"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Missing,
    Bytes(Vec<u8>),
    Unreadable(std::io::ErrorKind),
}

/// The live daemon has no `config.gate` in HELLO_ACK, so read the file directly
/// today. Once the gate is present, replace this byte source; never fall back to
/// reading the file when gate delivery fails.
pub fn read_input(path: &Path) -> Input {
    match std::fs::read(path) {
        Ok(bytes) => Input::Bytes(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Input::Missing,
        Err(error) => Input::Unreadable(error.kind()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Default,
    File(bool),
    Invalid(String),
}

impl Resolution {
    pub fn value(&self) -> Option<bool> {
        match self {
            Self::Default => Some(true),
            Self::File(value) => Some(*value),
            Self::Invalid(_) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "enabled")]
    login_sharing: bool,
}

fn enabled() -> bool {
    true
}

/// Reasons contain only a location or a fixed error category, never input text.
pub fn resolve(input: &Input) -> Resolution {
    let bytes = match input {
        Input::Missing => return Resolution::Default,
        Input::Unreadable(kind) => {
            return Resolution::Invalid(format!("unreadable at / ({kind:?})"));
        }
        Input::Bytes(bytes) => bytes,
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Resolution::Invalid("invalid UTF-8 at /".into());
    };
    let Ok(json) = subc_jsonc::jsonc_to_json(text) else {
        return Resolution::Invalid("invalid JSONC at /".into());
    };
    match serde_json::from_str::<Config>(&json) {
        Ok(config) => Resolution::File(config.login_sharing),
        Err(error) => Resolution::Invalid(format!(
            "invalid configuration at line {}, column {}",
            error.line(),
            error.column()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_sharing_resolver_accepts_jsonc_and_defaults() {
        assert_eq!(resolve(&Input::Missing), Resolution::Default);
        for (text, value) in [
            ("{}", true),
            (r#"{"login_sharing":true}"#, true),
            (r#"{"login_sharing":false}"#, false),
            (
                "{/* comment */\n\"login_sharing\": false, // comment\n}",
                false,
            ),
        ] {
            assert_eq!(resolve(&Input::Bytes(text.into())), Resolution::File(value));
        }
    }

    #[test]
    fn login_sharing_resolver_refuses_invalid_without_echoing_contents() {
        for text in [
            r#"{"private-marker":true}"#,
            r#"{"login_sharing":"private-marker"}"#,
            "private-marker",
            "/* private-marker",
        ] {
            let Resolution::Invalid(reason) = resolve(&Input::Bytes(text.into())) else {
                panic!("invalid configuration accepted");
            };
            assert!(!reason.contains("private-marker"));
            assert!(reason.contains("at "));
        }
        assert!(matches!(
            resolve(&Input::Unreadable(std::io::ErrorKind::PermissionDenied)),
            Resolution::Invalid(_)
        ));
    }
}
