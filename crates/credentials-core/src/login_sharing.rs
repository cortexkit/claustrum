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

/// Older daemons without `config.gate` need a direct file reader. With the gate,
/// only delivered snapshots are authoritative; a refusal never permits this read.
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

pub fn schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Credential Vault",
        "type": "object", "unevaluatedProperties": false,
        "properties": {"login_sharing": {
            "type": "boolean", "default": true,
            "title": "Share logins with paired computers",
            "description": "Turn off to stop sharing this computer's logins with paired computers and to remove the copies of their logins this computer received automatically.",
            "x-ck-apply": "live", "x-ck-layers": ["user"]
        }}
    })
}

/// Review immutable user bytes without consulting the filesystem or process state.
pub fn review_input(input: &Input) -> Result<subc_config::ReviewedTuple, subc_config::Refusal> {
    use subc_config::{Layer, LayerValue, Refusal, RefusalCode, Schema, ValidationContext};
    let invalid = || Refusal::new(RefusalCode::ValueInvalid, "/login_sharing", None);
    let layers = match input {
        Input::Missing => vec![],
        Input::Unreadable(_) => return Err(invalid()),
        Input::Bytes(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
            let json = subc_jsonc::jsonc_to_json(text).map_err(|_| invalid())?;
            // Keep the resolver's duplicate-field rejection; a generic JSON value
            // would silently discard all but the final occurrence before review.
            serde_json::from_str::<Config>(&json).map_err(|_| invalid())?;
            let value = serde_json::from_str(&json).map_err(|_| invalid())?;
            vec![LayerValue::new(Layer::User, value)]
        }
    };
    Schema::new(schema())?.review_tuple(&layers, &ValidationContext::new(crate::MODULE_ID, None))
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
    // Serde structs also accept positional arrays, including [] with all defaults.
    // Configuration is an object, so an array must not silently enable sharing.
    if !serde_json::from_str::<serde_json::Value>(&json).is_ok_and(|value| value.is_object()) {
        return Resolution::Invalid("expected configuration object at /".into());
    }
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

    const VALID: &[(&str, bool)] = &[
        ("{}", true),
        (r#"{"login_sharing":true}"#, true),
        (r#"{"login_sharing":false}"#, false),
        (
            "{/* comment */\n\"login_sharing\": false, // comment\n}",
            false,
        ),
    ];
    const INVALID: &[&str] = &[
        r#"{"private-marker":true}"#,
        r#"{"login_sharing":"private-marker"}"#,
        "private-marker",
        "/* private-marker",
        "null",
        "[]",
        r#"{"login_sharing":null}"#,
        r#"{"login_sharing":0}"#,
        r#"{"login_sharing":false,"login_sharing":true}"#,
    ];

    #[test]
    fn login_sharing_resolver_accepts_jsonc_and_defaults() {
        assert_eq!(resolve(&Input::Missing), Resolution::Default);
        for &(text, value) in VALID {
            assert_eq!(resolve(&Input::Bytes(text.into())), Resolution::File(value));
        }
    }

    #[test]
    fn login_sharing_resolver_refuses_invalid_without_echoing_contents() {
        for &text in INVALID {
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

    #[test]
    fn login_sharing_schema_and_resolver_agree_on_the_same_inputs() {
        let inputs = VALID
            .iter()
            .map(|(text, _)| Input::Bytes(text.as_bytes().to_vec()))
            .chain(
                INVALID
                    .iter()
                    .map(|text| Input::Bytes(text.as_bytes().to_vec())),
            )
            .chain([
                Input::Missing,
                Input::Unreadable(std::io::ErrorKind::PermissionDenied),
                Input::Bytes(vec![0xff]),
            ]);
        for input in inputs {
            match (resolve(&input).value(), review_input(&input)) {
                (Some(value), Ok(tuple)) => assert_eq!(tuple.effective["login_sharing"], value),
                (None, Err(_)) => {}
                other => panic!("resolver/schema disagree: {other:?}"),
            }
        }
    }
}
