//! Signed consent uses a closed JSON vocabulary and canonical bytes, not JSON equivalence.
use super::{SecretError, USE_ENVELOPE_TAG};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_ENVELOPE_ITEMS: usize = 16;
pub const SECRET_ISSUE_SKEW_LIMIT_MS: i64 = 120_000;
pub const MAX_SECRET_JSON_INTEGER: u64 = (1 << 53) - 1;

/// The v2 statement tags. A forwarded request carries the v1 object plus
/// `asking_member_id`, under a v2 tag so a v1-only phone or Cingulate decoder
/// refuses it rather than approving a statement it does not understand.
pub const USE_STATEMENT_V2: &str = "ck-secret-use-statement/v2";
pub const FLOW_STATEMENT_V2: &str = "ck-secret-flow-statement/v2";
pub const USE_STATEMENT_V3: &str = "ck-secret-use-statement/v3";
pub const FLOW_STATEMENT_V3: &str = "ck-secret-flow-statement/v3";
pub const LOCAL_USE_STATEMENT: &str = "ck-secret-local-use-statement/v1";
pub const LOCAL_USE_STATEMENT_TAG: &[u8] = b"ck-secret-local-use-statement/v1";
pub const MAX_LOCAL_COMMAND_BYTES: usize = 2048;
pub const MAX_LOCAL_WORKDIR_BYTES: usize = 1024;
pub const MAX_LOCAL_PURPOSE_BYTES: usize = 512;
pub const MAX_LOCAL_EXPECTS_BYTES: usize = 512;
pub const MAX_SSH_CARD_KEY_ID_BYTES: usize = 256;
pub const MAX_SSH_USERAUTH_BYTES: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
enum LocalUseKind {
    Sudo {
        user: String,
        purpose: String,
        expects: String,
        undoable: String,
    },
    Ssh {
        user: String,
        host: String,
        port: u16,
    },
}

/// Validated request members. Construction never normalizes text or destinations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalUse {
    kind: LocalUseKind,
    command: String,
    workdir: String,
}

impl LocalUse {
    pub fn from_value(value: &serde_json::Value) -> Result<Self, SecretError> {
        use SecretError::InvalidParams;
        let object = value.as_object().ok_or(InvalidParams)?;
        let text = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or(InvalidParams)
        };
        let command = local_text(text("command")?, MAX_LOCAL_COMMAND_BYTES)?;
        let workdir = local_text(text("workdir")?, MAX_LOCAL_WORKDIR_BYTES)?;
        if !workdir.starts_with('/') {
            return Err(InvalidParams);
        }
        let target = value
            .get("target")
            .and_then(serde_json::Value::as_object)
            .ok_or(InvalidParams)?;
        let user = target
            .get("user")
            .and_then(serde_json::Value::as_str)
            .ok_or(InvalidParams)?;
        super::validate_local_user(user)?;
        let kind = match (text("program")?, text("use")?) {
            ("sudo", "sudo_password") => {
                if object.len() != 8 || target.len() != 1 {
                    return Err(InvalidParams);
                }
                let purpose = local_text(text("purpose")?, MAX_LOCAL_PURPOSE_BYTES)?;
                let expects = local_text(text("expects")?, MAX_LOCAL_EXPECTS_BYTES)?;
                let undoable = text("undoable")?;
                if !matches!(undoable, "yes" | "no" | "unknown") {
                    return Err(InvalidParams);
                }
                LocalUseKind::Sudo {
                    user: user.into(),
                    purpose,
                    expects,
                    undoable: undoable.into(),
                }
            }
            ("ssh", "ssh_sign") => {
                if object.len() != 5 || target.len() != 3 {
                    return Err(InvalidParams);
                }
                let host = target
                    .get("host")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(InvalidParams)?;
                let port = target
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u16::try_from(v).ok())
                    .filter(|v| *v != 0)
                    .ok_or(InvalidParams)?;
                crate::record::AgentSshTarget {
                    user: Some(user.into()),
                    host: host.into(),
                    port: Some(port),
                }
                .validate()?;
                LocalUseKind::Ssh {
                    user: user.into(),
                    host: host.into(),
                    port,
                }
            }
            _ => return Err(InvalidParams),
        };
        Ok(Self {
            kind,
            command,
            workdir,
        })
    }

    pub fn is_ssh(&self) -> bool {
        match &self.kind {
            LocalUseKind::Sudo { .. } => false,
            LocalUseKind::Ssh { .. } => true,
        }
    }
    pub fn user(&self) -> &str {
        match &self.kind {
            LocalUseKind::Sudo { user, .. } | LocalUseKind::Ssh { user, .. } => user,
        }
    }
    pub fn triple(&self) -> serde_json::Value {
        use serde_json::json;
        match &self.kind {
            LocalUseKind::Sudo { user, .. } => {
                json!({"program":"sudo","use":"sudo_password","target":{"user":user}})
            }
            LocalUseKind::Ssh { user, host, port } => {
                json!({"program":"ssh","use":"ssh_sign","target":{"user":user,"host":host,"port":port}})
            }
        }
    }
    pub fn members(&self) -> serde_json::Value {
        let mut value = self.triple();
        value["command"] = self.command.clone().into();
        value["workdir"] = self.workdir.clone().into();
        match &self.kind {
            LocalUseKind::Sudo {
                purpose,
                expects,
                undoable,
                ..
            } => {
                value["purpose"] = purpose.clone().into();
                value["expects"] = expects.clone().into();
                value["undoable"] = undoable.clone().into();
            }
            LocalUseKind::Ssh { .. } => {}
        }
        value
    }
    pub fn matches_scope(&self, scope: &super::SecretScope) -> bool {
        match &self.kind {
            LocalUseKind::Sudo { user, .. } => match scope {
                super::SecretScope::LocalProgram {
                    program: super::LocalProgram::Sudo,
                    r#use: super::LocalProgramUse::SudoPassword,
                    targets,
                } => targets.iter().any(|t| match t {
                    super::LocalProgramTarget::Sudo { user: stored } => user == stored,
                }),
                super::SecretScope::ApiKey { .. }
                | super::SecretScope::ApiKeyRules { .. }
                | super::SecretScope::SiteLogin { .. }
                | super::SecretScope::SiteLoginOrigins { .. } => false,
            },
            LocalUseKind::Ssh { .. } => false,
        }
    }
    pub fn matches_enrollment(&self, enrollment: &crate::record::AgentSsh) -> bool {
        match &self.kind {
            LocalUseKind::Sudo { .. } => false,
            LocalUseKind::Ssh { user, host, port } => enrollment.targets.iter().any(|t| {
                t.host == *host
                    && t.user.as_ref().is_none_or(|u| u == user)
                    && t.port.is_none_or(|p| p == *port)
            }),
        }
    }
    pub fn durations(&self) -> Vec<&'static str> {
        match &self.kind {
            LocalUseKind::Sudo { .. } => vec!["once"],
            LocalUseKind::Ssh { .. } => vec!["once", "hour", "session"],
        }
    }
}

fn local_text(value: &str, cap: usize) -> Result<String, SecretError> {
    if value.len() > cap {
        return Err(SecretError::LimitExceeded);
    }
    if value.is_empty() || value.chars().any(unreadable_card_character) {
        return Err(SecretError::InvalidParams);
    }
    Ok(value.into())
}

fn unreadable_card_character(c: char) -> bool {
    // Unicode General_Category=Cf, including supplementary-plane format controls.
    let format_control = |c| matches!(c, '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{890}'..='\u{891}' | '\u{8e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}');
    c.is_control() || format_control(c) || matches!(c, '\u{2028}' | '\u{2029}')
}

/// SSH key identities on approval cards use bounded, nonempty signing ids with no
/// Unicode control, format, line-separator or paragraph-separator characters.
pub fn validate_ssh_card_key_id(id: &str) -> Result<(), SecretError> {
    if !id
        .strip_prefix("signing:")
        .is_some_and(|name| !name.is_empty())
        || id.len() > MAX_SSH_CARD_KEY_ID_BYTES
        || id.chars().any(unreadable_card_character)
        || !crate::credential_id::is_valid_deposit_credential_id(id)
    {
        return Err(SecretError::InvalidParams);
    }
    Ok(())
}

/// Strict RFC 4252 publickey userauth bytes; only this parsed type reaches signing.
pub struct SshUserauth {
    bytes: Vec<u8>,
    user: String,
    public_key: Vec<u8>,
    session_id: Vec<u8>,
}
impl SshUserauth {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, SecretError> {
        use SecretError::InvalidParams;
        if bytes.len() > MAX_SSH_USERAUTH_BYTES {
            return Err(SecretError::LimitExceeded);
        }
        fn string<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], SecretError> {
            let len = u32::from_be_bytes(
                rest.get(..4)
                    .ok_or(SecretError::InvalidParams)?
                    .try_into()
                    .map_err(|_| SecretError::InvalidParams)?,
            ) as usize;
            *rest = &rest[4..];
            let value = rest.get(..len).ok_or(SecretError::InvalidParams)?;
            *rest = &rest[len..];
            Ok(value)
        }
        let mut rest = bytes.as_slice();
        let session_id = string(&mut rest)?.to_vec();
        if session_id.is_empty() || rest.first() != Some(&50) {
            return Err(InvalidParams);
        }
        rest = &rest[1..];
        let user = std::str::from_utf8(string(&mut rest)?)
            .map_err(|_| InvalidParams)?
            .to_owned();
        super::validate_local_user(&user)?;
        if string(&mut rest)? != b"ssh-connection"
            || string(&mut rest)? != b"publickey"
            || rest.first() != Some(&1)
        {
            return Err(InvalidParams);
        }
        rest = &rest[1..];
        if string(&mut rest)? != b"ssh-ed25519" {
            return Err(InvalidParams);
        }
        let public_key = string(&mut rest)?.to_vec();
        if !rest.is_empty()
            || public_key.len() != 51
            || public_key[..19] != *b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
        {
            return Err(InvalidParams);
        }
        Ok(Self {
            bytes,
            user,
            public_key,
            session_id,
        })
    }
    pub fn user(&self) -> &str {
        &self.user
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The vault supplies the secret/key identity, not the asking program.
#[allow(clippy::too_many_arguments)]
pub fn local_approval_statement(
    id: &str,
    member: &str,
    incarnation: &str,
    call: &super::SecretUse,
    local: &LocalUse,
    fingerprint: Option<&str>,
    expiry: i64,
    asking_member: &str,
) -> Result<serde_json::Value, SecretError> {
    use serde_json::json;
    if local.is_ssh() {
        validate_ssh_card_key_id(&call.name)?;
    }
    let mut statement = local.members();
    statement["v"] = json!(LOCAL_USE_STATEMENT);
    statement["request_id"] = json!(id);
    statement["member_id"] = json!(member);
    statement["scope"] = json!({"owner":call.scope.owner,"kind":call.scope.kind,"ref":call.scope.scope_ref,"epoch":call.scope.epoch});
    statement["coverage"] = json!("scope");
    statement["durations"] = json!(local.durations());
    statement["request_expires_at_ms"] = json!(expiry);
    statement["agent_id"] = json!(call.agent_id);
    if !asking_member.is_empty() {
        statement["asking_member_id"] = json!(asking_member);
    }
    match &local.kind {
        LocalUseKind::Sudo { .. } => {
            statement["secret"] =
                json!({"name":call.name,"kind":"local_program","incarnation":incarnation})
        }
        LocalUseKind::Ssh { .. } => {
            statement["key"] = json!({"credential_id":call.name,"incarnation":incarnation,"fingerprint":fingerprint.expect("vault SSH fingerprint")})
        }
    }
    Ok(statement)
}

#[cfg(test)]
mod local_statement_tests {
    use super::*;
    use serde_json::json;

    fn sudo() -> serde_json::Value {
        json!({"program":"sudo","use":"sudo_password","target":{"user":"root"},"command":"apt upgrade","workdir":"/home/u","purpose":"update","expects":"password prompt","undoable":"no"})
    }

    fn ssh() -> serde_json::Value {
        json!({"program":"ssh","use":"ssh_sign","target":{"user":"u","host":"::1","port":22},"command":"ssh u@host","workdir":"/"})
    }

    #[test]
    fn ssh_local_use_accepts_no_purpose_and_stores_only_request_members() {
        let value = ssh();
        let local = LocalUse::from_value(&value).unwrap();
        assert_eq!(local.members(), value);
    }

    #[test]
    fn ssh_local_use_refuses_purpose_even_when_empty() {
        for purpose in ["login", ""] {
            let mut value = ssh();
            value["purpose"] = json!(purpose);
            assert_eq!(
                LocalUse::from_value(&value),
                Err(SecretError::InvalidParams)
            );
        }
    }

    #[test]
    fn sudo_local_use_still_requires_purpose() {
        let mut value = sudo();
        value.as_object_mut().unwrap().remove("purpose");
        assert_eq!(
            LocalUse::from_value(&value),
            Err(SecretError::InvalidParams)
        );
    }

    #[test]
    fn local_text_caps_count_utf8_bytes_and_refuse_controls() {
        for (field, cap) in [
            ("command", MAX_LOCAL_COMMAND_BYTES),
            ("workdir", MAX_LOCAL_WORKDIR_BYTES),
            ("purpose", MAX_LOCAL_PURPOSE_BYTES),
            ("expects", MAX_LOCAL_EXPECTS_BYTES),
        ] {
            let mut value = sudo();
            let text = if field == "workdir" {
                format!("/{}x", "é".repeat((cap - 2) / 2))
            } else {
                "é".repeat(cap / 2)
            };
            assert_eq!(text.len(), cap);
            value[field] = json!(text);
            assert!(LocalUse::from_value(&value).is_ok(), "{field}");
            value[field] = json!(format!("{}x", value[field].as_str().unwrap()));
            assert_eq!(
                LocalUse::from_value(&value),
                Err(SecretError::LimitExceeded)
            );
            for text in ["", "a\n", "a\u{85}", "a\u{ad}", "a\u{200b}", "a\u{e007f}"] {
                value[field] = json!(text);
                assert_eq!(
                    LocalUse::from_value(&value),
                    Err(SecretError::InvalidParams)
                );
            }
        }
    }

    fn refuse_local_separator(separator: char) {
        for field in ["command", "workdir", "purpose", "expects"] {
            let mut value = sudo();
            value[field] = json!(format!("/first{separator}second"));
            assert_eq!(
                LocalUse::from_value(&value),
                Err(SecretError::InvalidParams),
                "{field} must not add a card line"
            );
        }
    }

    #[test]
    fn local_text_refuses_line_separator() {
        refuse_local_separator('\u{2028}');
    }

    #[test]
    fn local_text_refuses_paragraph_separator() {
        refuse_local_separator('\u{2029}');
    }

    #[test]
    fn ssh_card_key_id_accepts_256_utf8_bytes_and_refuses_257() {
        let id = format!("signing:{}", "é".repeat(124));
        assert_eq!(id.len(), 256);
        assert_eq!(validate_ssh_card_key_id(&id), Ok(()));
        let too_long = format!("{id}x");
        assert_eq!(too_long.len(), 257);
        assert_eq!(
            validate_ssh_card_key_id(&too_long),
            Err(SecretError::InvalidParams)
        );
    }

    #[test]
    fn ssh_card_key_id_requires_nonempty_signing_id_and_readable_deposit_grammar() {
        for id in [
            "",
            "signing:",
            "opaque:key",
            "category:key",
            "signing:bad|id",
        ] {
            assert_eq!(
                validate_ssh_card_key_id(id),
                Err(SecretError::InvalidParams)
            );
        }
        for c in [
            '\n',
            '\u{85}',
            '\u{ad}',
            '\u{200b}',
            '\u{e007f}',
            '\u{2028}',
            '\u{2029}',
        ] {
            assert_eq!(
                validate_ssh_card_key_id(&format!("signing:a{c}b")),
                Err(SecretError::InvalidParams)
            );
        }
        for id in ["signing:a", "signing:鍵", "signing:é key"] {
            assert_eq!(validate_ssh_card_key_id(id), Ok(()));
        }
    }

    #[test]
    fn local_request_grammar_is_closed_and_never_normalized() {
        for (field, bad) in [
            ("program", json!("ssh")),
            ("undoable", json!("maybe")),
            ("workdir", json!("relative")),
            ("expects", serde_json::Value::Null),
            ("target", json!({"user":"-root"})),
            ("target", json!({"user":"root","host":"extra"})),
        ] {
            let mut value = sudo();
            value[field] = bad;
            assert_eq!(
                LocalUse::from_value(&value),
                Err(SecretError::InvalidParams)
            );
        }
        let mut value = sudo();
        value["extra"] = json!(true);
        assert_eq!(
            LocalUse::from_value(&value),
            Err(SecretError::InvalidParams)
        );
        for target in [
            json!({"user":"u","host":"Example.test","port":22}),
            json!({"user":"u","host":"::01","port":22}),
            json!({"user":"u","host":"host.test","port":0}),
            json!({"user":"u","host":"host.test","port":65536}),
            json!({"user":"u","host":"host.test"}),
        ] {
            assert!(LocalUse::from_value(&json!({"program":"ssh","use":"ssh_sign","target":target,"command":"ssh","workdir":"/"})).is_err());
        }
        for port in [1, 65535] {
            assert!(LocalUse::from_value(&json!({"program":"ssh","use":"ssh_sign","target":{"user":"u","host":"::1","port":port},"command":"ssh","workdir":"/"})).is_ok());
        }
    }

    #[test]
    fn local_statement_has_exact_members_and_nullable_agent_id() {
        let local = LocalUse::from_value(&sudo()).unwrap();
        let mut call = super::super::SecretUse {
            name: "pw".into(),
            sender: super::super::SecretSender::Aft,
            scope: super::super::AskingScope {
                owner: "o".into(),
                kind: "worker".into(),
                scope_ref: "W".into(),
                epoch: 7,
            },
            worker_parent: None,
            coverage: "scope".into(),
            agent_id: None,
            target: super::super::UseTarget::LocalProgram(local.clone()),
        };
        let statement =
            local_approval_statement("r", "m", "i", &call, &local, None, 42, "").unwrap();
        let expected = br#"{"agent_id":null,"command":"apt upgrade","coverage":"scope","durations":["once"],"expects":"password prompt","member_id":"m","program":"sudo","purpose":"update","request_expires_at_ms":42,"request_id":"r","scope":{"epoch":7,"kind":"worker","owner":"o","ref":"W"},"secret":{"incarnation":"i","kind":"local_program","name":"pw"},"target":{"user":"root"},"undoable":"no","use":"sudo_password","v":"ck-secret-local-use-statement/v1","workdir":"/home/u"}"#;
        assert_eq!(serde_json::to_vec(&statement).unwrap(), expected);
        call.agent_id = Some("agent-A".into());
        let statement =
            local_approval_statement("r", "m", "i", &call, &local, None, 42, "").unwrap();
        let expected = br#"{"agent_id":"agent-A","command":"apt upgrade","coverage":"scope","durations":["once"],"expects":"password prompt","member_id":"m","program":"sudo","purpose":"update","request_expires_at_ms":42,"request_id":"r","scope":{"epoch":7,"kind":"worker","owner":"o","ref":"W"},"secret":{"incarnation":"i","kind":"local_program","name":"pw"},"target":{"user":"root"},"undoable":"no","use":"sudo_password","v":"ck-secret-local-use-statement/v1","workdir":"/home/u"}"#;
        assert_eq!(serde_json::to_vec(&statement).unwrap(), expected);
        call.agent_id = None;
        call.name = "signing:ssh".into();
        let ssh = LocalUse::from_value(&ssh()).unwrap();
        let statement =
            local_approval_statement("r", "m", "i", &call, &ssh, Some("SHA256:test"), 42, "asker")
                .unwrap();
        assert_eq!(statement["durations"], json!(["once", "hour", "session"]));
        assert_eq!(
            statement["key"],
            json!({"credential_id":"signing:ssh","incarnation":"i","fingerprint":"SHA256:test"})
        );
        assert_eq!(statement["asking_member_id"], "asker");
        assert!(
            statement.get("secret").is_none()
                && statement.get("expects").is_none()
                && statement.get("undoable").is_none()
                && statement.get("purpose").is_none()
        );
        assert_eq!(statement.get("agent_id"), Some(&serde_json::Value::Null));
        assert_eq!(statement.as_object().unwrap().len(), 15);
        for id in [
            "signing:",
            "signing:a\u{2028}b",
            "signing:a\u{2029}b",
            "signing:bad|id",
            &format!("signing:{}", "x".repeat(249)),
        ] {
            call.name = id.into();
            assert_eq!(
                local_approval_statement(
                    "r",
                    "m",
                    "i",
                    &call,
                    &ssh,
                    Some("SHA256:test"),
                    42,
                    "asker"
                ),
                Err(SecretError::InvalidParams)
            );
        }
    }

    fn userauth(session_len: usize) -> Vec<u8> {
        fn push(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        let mut out = vec![];
        push(&mut out, &vec![1; session_len]);
        out.push(50);
        for value in [b"u".as_slice(), b"ssh-connection", b"publickey"] {
            push(&mut out, value);
        }
        out.push(1);
        push(&mut out, b"ssh-ed25519");
        let mut key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        key.extend_from_slice(&[2; 32]);
        push(&mut out, &key);
        out
    }

    #[test]
    fn ssh_userauth_is_strict_and_accepts_only_through_8192_bytes() {
        let overhead = userauth(0).len();
        let bytes = userauth(MAX_SSH_USERAUTH_BYTES - overhead);
        assert_eq!(bytes.len(), MAX_SSH_USERAUTH_BYTES);
        let parsed = SshUserauth::parse(bytes.clone()).unwrap();
        assert_eq!(parsed.user(), "u");
        assert_eq!(parsed.public_key().len(), 51);
        assert!(!parsed.session_id().is_empty());
        assert!(matches!(
            SshUserauth::parse(userauth(MAX_SSH_USERAUTH_BYTES - overhead + 1)),
            Err(SecretError::LimitExceeded)
        ));
        assert!(SshUserauth::parse(userauth(0)).is_err());
        for end in 0..userauth(1).len() {
            assert!(SshUserauth::parse(userauth(1)[..end].to_vec()).is_err());
        }
        let mut trailing = userauth(1);
        trailing.push(0);
        assert!(SshUserauth::parse(trailing).is_err());
        let mut unsigned = userauth(1);
        unsigned[42] = 0;
        assert!(SshUserauth::parse(unsigned).is_err());
        assert!(SshUserauth::parse(b"SSHSIG".to_vec()).is_err());
    }
}

pub fn approval_statement(
    id: &str,
    member: &str,
    incarnation: &str,
    call: &super::SecretUse,
    scope: &super::SecretScope,
    expiry: i64,
) -> serde_json::Value {
    use serde_json::json;
    let use_scope = scope.use_fields();
    let tag = if scope.is_extended() {
        USE_STATEMENT_V3
    } else {
        "ck-secret-use-statement/v1"
    };
    json!({"v":tag,"request_id":id,"member_id":member,"scope":{"owner":call.scope.owner,"kind":call.scope.kind,"ref":call.scope.scope_ref,"epoch":call.scope.epoch},"agent_id":call.agent_id,"coverage":call.coverage,"secret":{"name":call.name,"kind":scope.kind(),"incarnation":incarnation},"use":use_scope,"durations":if call.coverage=="agent_and_workers" {vec!["permanent"]}else{vec!["once","hour","session","permanent"]},"request_expires_at_ms":expiry})
}

/// The statement for a request `asking_member` forwarded to this vault. A local
/// legacy request keeps v1 locally and adds `asking_member_id` under v2 when
/// forwarded. Extended scopes use v3 in both cases, with the asker only when forwarded.
pub fn approval_statement_for_asker(
    id: &str,
    member: &str,
    incarnation: &str,
    call: &super::SecretUse,
    scope: &super::SecretScope,
    expiry: i64,
    asking_member: &str,
) -> serde_json::Value {
    let mut statement = approval_statement(id, member, incarnation, call, scope, expiry);
    if !asking_member.is_empty() {
        statement["asking_member_id"] = serde_json::json!(asking_member);
        if !scope.is_extended() {
            statement["v"] = serde_json::json!(USE_STATEMENT_V2);
        }
    }
    statement
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowIdentity {
    pub flow_id: String,
    pub version: u64,
    pub code_hash: String,
    pub install_id: String,
}

impl FlowIdentity {
    pub fn validate(&self) -> Result<(), super::ValidationError> {
        if !(1..=256).contains(&self.flow_id.len())
            || !self.flow_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || !(1..=MAX_SECRET_JSON_INTEGER).contains(&self.version)
            || self.code_hash.len() != 64
            || !self
                .code_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=256).contains(&self.install_id.len())
            || !self.install_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(super::ValidationError::InvalidParams);
        }
        Ok(())
    }
}

pub fn sorted_flow_methods(methods: &[String]) -> Result<Vec<String>, super::ValidationError> {
    if methods.is_empty()
        || methods
            .iter()
            .any(|m| !(1..=16).contains(&m.len()) || !m.bytes().all(|b| b.is_ascii_uppercase()))
    {
        return Err(super::ValidationError::InvalidParams);
    }
    let mut sorted = methods.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(super::ValidationError::InvalidParams);
    }
    Ok(sorted)
}

/// The statement tags. A flow id equal to one of them cannot sit in a statement object: the
/// JSON encoder writes a repeated key rather than refusing, and the bytes it produces are not
/// the statement anyone meant to sign.
const STATEMENT_TAGS: &[&str] = &["ck-secret-flow-statement/v1", "ck-secret-use-statement/v1"];

/// Refuses a flow identity that cannot be stored as given. A flow id equal to the
/// statement's own `v` tag would collide with that key when the statement object is built,
/// so it is refused here as well as at the sender boundary: approval signs that one object.
/// The remaining checks are the identity constraints the store's grant lookup relies on, so
/// a grant is never created for an identity it could not match later.
fn flow_identity_encodes_unchanged(flow: &FlowIdentity) -> Result<(), super::ValidationError> {
    flow.validate()?;
    if STATEMENT_TAGS.contains(&flow.flow_id.as_str()) {
        return Err(super::ValidationError::InvalidParams);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn flow_approval_statement(
    id: &str,
    member: &str,
    incarnation: &str,
    name: &str,
    flow: &FlowIdentity,
    scope: &super::SecretScope,
    methods: Option<&[String]>,
    expiry: i64,
) -> Result<serde_json::Value, super::ValidationError> {
    use serde_json::json;
    flow.validate()?;
    // Approval grants on the flow identity as given, so the encoder must be handed that
    // identity exactly as it is stored; a value it cannot carry verbatim is refused rather
    // than signed in some other form.
    flow_identity_encodes_unchanged(flow)?;
    if scope.is_extended() && flow_id_is_v3_statement_tag(&flow.flow_id) {
        return Err(super::ValidationError::InvalidParams);
    }
    let mut use_scope = scope.use_fields();
    match (scope.kind(), methods) {
        ("agent_api_key", Some(methods)) => {
            use_scope["methods"] = json!(sorted_flow_methods(methods)?)
        }
        ("site_login", None) => {}
        _ => return Err(super::ValidationError::InvalidParams),
    }
    let tag = if scope.is_extended() {
        FLOW_STATEMENT_V3
    } else {
        "ck-secret-flow-statement/v1"
    };
    Ok(
        json!({"v":tag,"request_id":id,"member_id":member,"flow":flow,"secret":{"name":name,"kind":scope.kind(),"incarnation":incarnation},"use":use_scope,"durations":["version"],"request_expires_at_ms":expiry}),
    )
}

/// Whether `flow_id` equals a v2 statement tag. Only a forwarded flow approval
/// refuses these. A local flow approval whose flow id equals a v2 tag is still
/// accepted, with v1 for a legacy scope or v3 for an extended scope.
pub fn flow_id_is_v2_statement_tag(flow_id: &str) -> bool {
    flow_id == USE_STATEMENT_V2 || flow_id == FLOW_STATEMENT_V2
}

pub fn flow_id_is_v3_statement_tag(flow_id: &str) -> bool {
    flow_id == USE_STATEMENT_V3 || flow_id == FLOW_STATEMENT_V3
}

/// The flow statement for a request `asking_member` forwarded to this vault.
/// Legacy scopes keep v1 locally and v2 when forwarded; extended scopes keep v3.
/// The asker is included only for forwarded requests. A forwarded request whose
/// flow id equals a v2 tag is refused because it collides with the statement's `v` key.
#[allow(clippy::too_many_arguments)]
pub fn flow_approval_statement_for_asker(
    id: &str,
    member: &str,
    incarnation: &str,
    name: &str,
    flow: &FlowIdentity,
    scope: &super::SecretScope,
    methods: Option<&[String]>,
    expiry: i64,
    asking_member: &str,
) -> Result<serde_json::Value, super::ValidationError> {
    if asking_member.is_empty() {
        return flow_approval_statement(
            id,
            member,
            incarnation,
            name,
            flow,
            scope,
            methods,
            expiry,
        );
    }
    if flow_id_is_v2_statement_tag(&flow.flow_id) {
        return Err(super::ValidationError::InvalidParams);
    }
    let mut statement =
        flow_approval_statement(id, member, incarnation, name, flow, scope, methods, expiry)?;
    statement["asking_member_id"] = serde_json::json!(asking_member);
    if !scope.is_extended() {
        statement["v"] = serde_json::json!(FLOW_STATEMENT_V2);
    }
    Ok(statement)
}

pub fn delete_statement(
    id: &str,
    member: &str,
    name: &str,
    kind: &str,
    incarnation: &str,
    expiry: i64,
) -> serde_json::Value {
    serde_json::json!({"v":"ck-secret-delete-statement/v1","request_id":id,"member_id":member,"secret":{"name":name,"kind":kind,"incarnation":incarnation},"request_expires_at_ms":expiry})
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalItem {
    pub request_id: String,
    pub statement_sha256: String,
}

/// Whether every element of the envelope's `items` array holds exactly `request_id` and
/// `statement_sha256`. Each element is compared with the rebuilt JSON value holding only
/// those two keys; a key such as `duration` inside an item is not part of the envelope
/// schema and makes the whole envelope `approval_invalid`.
fn envelope_items_carry_only_their_two_keys(bytes: &[u8]) -> bool {
    let parsed = serde_json::from_slice::<serde_json::Value>(bytes);
    let Ok(parsed) = parsed else {
        return false;
    };
    let Some(items) = parsed.get("items").and_then(serde_json::Value::as_array) else {
        return false;
    };
    items.iter().all(|item| {
        let rebuilt = serde_json::to_value(ApprovalItem {
            request_id: item
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            statement_sha256: item
                .get("statement_sha256")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
        rebuilt.is_ok_and(|rebuilt| rebuilt == *item)
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnvelope {
    pub v: String,
    /// One entry per answered request; `#[serde(deny_unknown_fields)]` on this struct does
    /// not reach an element, so `verify` refuses items carrying extra keys itself. A key
    /// inside an item, `duration` included, never takes part in approval.
    pub items: Vec<ApprovalItem>,
    pub decision: String,
    pub duration: String,
    pub grant_expires_at_ms: u64,
    pub device_fingerprint: String,
    pub issued_at_ms: u64,
}

impl ApprovalEnvelope {
    /// All object keys are fixed ASCII and numbers are exact nonnegative integers.
    /// Sorting those keys and using serde_json's string encoding produces JCS bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SecretError> {
        serde_json::to_value(self)
            .and_then(|v| serde_json::to_vec(&v))
            .map_err(|_| SecretError::ApprovalInvalid)
    }

    pub fn verify(
        bytes: &[u8],
        signature: &[u8],
        public_key: &[u8],
        fingerprint: &str,
    ) -> Result<Self, SecretError> {
        let invalid = SecretError::ApprovalInvalid;
        let envelope = Self::parse_canonical(bytes, fingerprint)?;
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| invalid)?;
        let signature = Signature::from_der(signature).map_err(|_| invalid)?;
        key.verify(bytes, &signature).map_err(|_| invalid)?;
        Ok(envelope)
    }

    pub fn parse_canonical(bytes: &[u8], fingerprint: &str) -> Result<Self, SecretError> {
        let invalid = SecretError::ApprovalInvalid;
        // Deserializing structs (not Value maps) rejects duplicate keys at every level.
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| invalid)?;
        let mut ids = HashSet::new();
        if envelope.v.as_bytes() != USE_ENVELOPE_TAG
            || envelope.items.is_empty()
            || envelope.items.len() > MAX_ENVELOPE_ITEMS
            || envelope.device_fingerprint != fingerprint
            || envelope.issued_at_ms > MAX_SECRET_JSON_INTEGER
            || envelope.grant_expires_at_ms > MAX_SECRET_JSON_INTEGER
            || !matches!(envelope.decision.as_str(), "allow" | "delete")
            || !matches!(
                envelope.duration.as_str(),
                "once" | "hour" | "session" | "permanent" | "none" | "version"
            )
            || (envelope.duration == "version"
                && (envelope.decision != "allow" || envelope.grant_expires_at_ms != 0))
            || envelope.items.iter().any(|item| {
                item.request_id.len() != 26
                    || item.request_id.as_bytes()[0] > b'7'
                    || !item
                        .request_id
                        .bytes()
                        .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
                    || item.statement_sha256.len() != 64
                    || !item
                        .statement_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !ids.insert(&item.request_id)
            })
            || !envelope_items_carry_only_their_two_keys(bytes)
            || envelope.canonical_bytes()? != bytes
        {
            return Err(invalid);
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod flow_identity_tests {
    use super::*;

    fn identity(flow_id: String) -> FlowIdentity {
        FlowIdentity {
            flow_id,
            version: 1,
            code_hash: "a".repeat(64),
            install_id: "install-1".into(),
        }
    }

    #[test]
    fn flow_ids_accept_one_through_256_printable_ascii_bytes() {
        for id in [
            "a".into(),
            "x".repeat(256),
            (0x20u8..=0x7e).map(char::from).collect(),
        ] {
            let flow = identity(id);
            flow.validate().unwrap();
            flow_identity_encodes_unchanged(&flow).unwrap();
        }
    }

    #[test]
    fn flow_ids_refuse_empty_and_257_byte_identities() {
        for id in [String::new(), "x".repeat(257)] {
            let flow = identity(id);
            assert!(flow.validate().is_err(), "{:?}", flow.flow_id);
            assert!(flow_identity_encodes_unchanged(&flow).is_err());
        }
    }

    #[test]
    fn flow_ids_refuse_controls_del_and_non_ascii() {
        let ids = (0u8..=0x1f)
            .chain([0x7f])
            .map(|b| format!("flow{}id", char::from(b)))
            .chain(["flowé".into(), "flow😀".into()]);
        for id in ids {
            let flow = identity(id);
            assert!(flow.validate().is_err(), "{:?}", flow.flow_id);
            assert!(flow_identity_encodes_unchanged(&flow).is_err());
        }
    }
}

#[cfg(test)]
mod v2_statement_tests {
    use super::*;
    use crate::agent_secret::{AskingScope, SecretScope, SecretSender, SecretUse};

    const HOME: &str = "fed-computer:22222222222222222222222222222222";
    const ASKER: &str = "fed-computer:11111111111111111111111111111111";
    const NOW: i64 = 1_700_000_000_000;
    const REQUEST_ID: &str = "01HF7YAT000000000000000001";
    const INCARNATION: &str = "00000000000000000000000000000149";

    fn api_scope() -> SecretScope {
        SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some("/repos/a".into()),
            location: "header:X-Api-Key".into(),
        }
    }

    fn api_call() -> SecretUse {
        SecretUse {
            name: "key".into(),
            sender: SecretSender::Aft,
            scope: AskingScope {
                owner: "reserved:prefrontal-core".into(),
                kind: "head".into(),
                scope_ref: "H".into(),
                epoch: 7,
            },
            worker_parent: None,
            coverage: "scope".into(),
            agent_id: Some("agent-A".into()),
            target: crate::agent_secret::UseTarget::ApiKey {
                scheme: "https".into(),
                host: "x.test".into(),
                port: 443,
                path: "/repos/a/canary-token".into(),
            },
        }
    }

    fn login_scope() -> SecretScope {
        SecretScope::SiteLogin {
            origin: "https://x.test".into(),
        }
    }

    fn flow_identity() -> FlowIdentity {
        FlowIdentity {
            flow_id: "daily-fetch".into(),
            version: 7,
            code_hash: "0123456789abcdef".repeat(4),
            install_id: "install-A".into(),
        }
    }

    #[test]
    fn forwarded_use_statement_is_v1_plus_asker_under_v2_tag() {
        let v1 = approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
        );
        assert_eq!(v1["v"], "ck-secret-use-statement/v1");
        assert!(v1.get("asking_member_id").is_none());
        let v1_bytes = serde_json::to_vec(&v1).unwrap();
        let v2 = approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
            ASKER,
        );
        assert_eq!(v2["v"], USE_STATEMENT_V2);
        assert_eq!(v2["asking_member_id"], ASKER);
        // Every other key is the v1 object unchanged.
        let mut v2_as_v1 = v2.clone();
        v2_as_v1["v"] = serde_json::json!("ck-secret-use-statement/v1");
        v2_as_v1.as_object_mut().unwrap().remove("asking_member_id");
        assert_eq!(v2_as_v1, v1);
        // Canonical bytes: the same Value re-encoded is identical.
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        assert_ne!(v1_bytes, v2_bytes);
        let decoded: serde_json::Value = serde_json::from_slice(&v2_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), v2_bytes);
    }

    #[test]
    fn local_use_statement_stays_v1_byte_for_byte() {
        let direct = approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
        );
        let via_asker = approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
            "",
        );
        assert_eq!(via_asker, direct);
        assert_eq!(via_asker["v"], "ck-secret-use-statement/v1");
        assert!(via_asker.get("asking_member_id").is_none());
    }

    #[test]
    fn forwarded_flow_statement_is_v1_plus_asker_under_v2_tag() {
        let v1 = flow_approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
        )
        .unwrap();
        assert_eq!(v1["v"], "ck-secret-flow-statement/v1");
        assert!(v1.get("asking_member_id").is_none());
        let v2 = flow_approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
            ASKER,
        )
        .unwrap();
        assert_eq!(v2["v"], FLOW_STATEMENT_V2);
        assert_eq!(v2["asking_member_id"], ASKER);
        let mut v2_as_v1 = v2.clone();
        v2_as_v1["v"] = serde_json::json!("ck-secret-flow-statement/v1");
        v2_as_v1.as_object_mut().unwrap().remove("asking_member_id");
        assert_eq!(v2_as_v1, v1);
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&v2_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), v2_bytes);
    }

    #[test]
    fn local_flow_statement_stays_v1_byte_for_byte() {
        let direct = flow_approval_statement(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
        )
        .unwrap();
        let via_asker = flow_approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
            "",
        )
        .unwrap();
        assert_eq!(via_asker, direct);
    }

    #[test]
    fn only_forwarded_flow_refuses_a_v2_tag_flow_id() {
        for tag in [USE_STATEMENT_V2, FLOW_STATEMENT_V2] {
            let mut identity = flow_identity();
            identity.flow_id = tag.into();
            // Local keeps the v1-only sender check, so a v2 tag still encodes.
            assert!(flow_approval_statement(
                REQUEST_ID,
                HOME,
                INCARNATION,
                "key",
                &identity,
                &api_scope(),
                Some(&["GET".to_string()]),
                NOW + 600_000,
            )
            .is_ok());
            // Forwarded refuses it: the id would collide with the v2 `v` key.
            assert!(flow_approval_statement_for_asker(
                REQUEST_ID,
                HOME,
                INCARNATION,
                "key",
                &identity,
                &api_scope(),
                Some(&["GET".to_string()]),
                NOW + 600_000,
                ASKER,
            )
            .is_err());
            assert!(flow_id_is_v2_statement_tag(tag));
        }
        assert!(!flow_id_is_v2_statement_tag("daily-fetch"));
        assert!(!flow_id_is_v2_statement_tag("ck-secret-flow-statement/v1"));
    }

    fn statement_record(statement: &serde_json::Value) -> serde_json::Value {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(statement).unwrap();
        let digest: Vec<u8> = Sha256::digest(&bytes).to_vec();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        serde_json::json!({
            "statement": statement,
            "statement_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes),
            "statement_sha256": hex,
        })
    }

    #[test]
    fn v2_statement_vectors_are_emitted_by_the_real_encoders_and_pinned() {
        let use_v2 = approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            &api_call(),
            &api_scope(),
            NOW + 600_000,
            ASKER,
        );
        let login_incarnation = format!(
            "{:032x}",
            b"login".iter().copied().map(u64::from).sum::<u64>()
        );
        let login_call = SecretUse {
            name: "login".into(),
            sender: SecretSender::Cerebellum,
            scope: AskingScope {
                owner: "reserved:prefrontal-core".into(),
                kind: "head".into(),
                scope_ref: "H".into(),
                epoch: 7,
            },
            worker_parent: None,
            coverage: "scope".into(),
            agent_id: Some("agent-A".into()),
            target: crate::agent_secret::UseTarget::SiteLogin {
                origin: "https://x.test".into(),
            },
        };
        let login_v2 = approval_statement_for_asker(
            "01HF7YAT000000000000000002",
            HOME,
            &login_incarnation,
            &login_call,
            &login_scope(),
            NOW + 600_000,
            ASKER,
        );
        let mut use_vectors = Vec::new();
        for (case, request_id, statement) in [
            ("forwarded-use-api-key", REQUEST_ID, use_v2),
            (
                "forwarded-use-site-login",
                "01HF7YAT000000000000000002",
                login_v2,
            ),
        ] {
            let mut record = statement_record(&statement);
            record["case"] = serde_json::json!(case);
            record["request_id"] = serde_json::json!(request_id);
            record["member_id"] = serde_json::json!(HOME);
            record["asking_member_id"] = serde_json::json!(ASKER);
            use_vectors.push(record);
        }
        let emitted_use = serde_json::json!({"vectors": use_vectors});
        let use_pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../credentials-core/tests/vectors/secret-approval-v2.json");
        if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
            std::fs::create_dir_all(use_pinned.parent().unwrap()).unwrap();
            std::fs::write(
                &use_pinned,
                serde_json::to_vec_pretty(&emitted_use).unwrap(),
            )
            .unwrap();
            println!("emitted v2 use statement vectors");
        } else {
            let expected: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&use_pinned).expect("pinned v2 use statement vectors"),
            )
            .unwrap();
            assert_eq!(
                emitted_use, expected,
                "vault-emitted v2 use vectors changed"
            );
        }
        let flow_api_v2 = flow_approval_statement_for_asker(
            REQUEST_ID,
            HOME,
            INCARNATION,
            "key",
            &flow_identity(),
            &api_scope(),
            Some(&["GET".to_string()]),
            NOW + 600_000,
            ASKER,
        )
        .unwrap();
        let flow_login_v2 = flow_approval_statement_for_asker(
            "01HF7YAT000000000000000002",
            HOME,
            &login_incarnation,
            "login",
            &flow_identity(),
            &login_scope(),
            None,
            NOW + 600_000,
            ASKER,
        )
        .unwrap();
        let mut flow_vectors = Vec::new();
        for (case, request_id, statement) in [
            ("forwarded-flow-api-key", REQUEST_ID, flow_api_v2),
            (
                "forwarded-flow-site-login",
                "01HF7YAT000000000000000002",
                flow_login_v2,
            ),
        ] {
            let mut record = statement_record(&statement);
            record["case"] = serde_json::json!(case);
            record["request_id"] = serde_json::json!(request_id);
            record["member_id"] = serde_json::json!(HOME);
            record["asking_member_id"] = serde_json::json!(ASKER);
            flow_vectors.push(record);
        }
        let emitted_flow = serde_json::json!({"vectors": flow_vectors});
        let flow_pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../credentials-core/tests/vectors/secret-flow-approval-v2.json");
        if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
            std::fs::create_dir_all(flow_pinned.parent().unwrap()).unwrap();
            std::fs::write(
                &flow_pinned,
                serde_json::to_vec_pretty(&emitted_flow).unwrap(),
            )
            .unwrap();
            println!("emitted v2 flow statement vectors");
        } else {
            let expected: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&flow_pinned).expect("pinned v2 flow statement vectors"),
            )
            .unwrap();
            assert_eq!(
                emitted_flow, expected,
                "vault-emitted v2 flow vectors changed"
            );
        }
    }
}
