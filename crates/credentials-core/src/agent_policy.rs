//! The canonical policy and signature envelope for binding GitHub Apps to agents.

use std::collections::{BTreeMap, BTreeSet};

use base64::prelude::{Engine, BASE64_STANDARD};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::gh_manifest::{
    sha256_hex, validate_installation_permissions, GhManifest, ManifestValue,
    MAX_MANIFEST_JSON_INTEGER,
};
use crate::signing::MAX_SIGN_PAYLOAD;

mod defaults;
mod matching;
mod narrowing;

pub use defaults::github_default_rule_set;
pub(crate) use narrowing::validate_signer_rule_sets;

pub const AGENT_POLICY_SCHEMA_V1: &str = "ck-agent-policy/v1";
pub const AGENT_POLICY_SEPARATOR: &[u8] = b"ck-agent-policy/v1\0";
pub const MAX_POLICY_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_RELEASE_BYTES: usize = 64;
const MAX_POLICY_HOST_BYTES: usize = 253;
const MAX_POLICY_DNS_LABEL_BYTES: usize = 63;
const APP_SLUG_LENGTH_LIMIT: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    InvalidJson,
    InvalidShape,
    NotCanonical,
    TooLarge,
    InvalidInteger,
    WrongSchema,
    InvalidVersion,
    InvalidRootKeyId,
    UnsupportedService,
    WrongRuleSetName,
    WrongExtractor,
    InvalidSourceRelease,
    InvalidSourceDigest,
    UnknownDefaultRelease,
    UnknownDefaultDigest,
    RuleSetNotNarrowed,
    InvalidHost,
    HostOrder,
    RedirectHostConflict,
    DuplicateKind,
    EmptyKindName,
    OperatorNeedsApproval,
    AnonymousCredential,
    AnonymousNotRead,
    DeniedKindContent,
    InvalidPermissions,
    UnexpectedConsent,
    UndeclaredConsentField,
    MissingRequests,
    InvalidOwnershipReads,
    UnknownOwnershipRead,
    OwnershipReadNotRead,
    InvalidNodeRepository,
    MissingNodeRepository,
    InvalidMethod,
    UndeclaredHost,
    InvalidPath,
    UnknownPathParameter,
    MisplacedTail,
    RepeatedResourceParameter,
    UnboundOwner,
    ReservedGraphqlPath,
    ConflictingConstraintName,
    InvalidBodyFixedValue,
    InvalidQueryFixedValue,
    OpenWriteBody,
    InvalidGraphqlFields,
    InvalidGraphqlArgumentPath,
    RequestOverlap,
    EmptyActionName,
    DuplicateAction,
    EmptyAction,
    UnknownActionLeg,
    DeniedActionLeg,
    EmptyAgentName,
    InvalidIdentity,
    SharedIdentity,
    DuplicateBinding,
    BindingOrder,
    EmptyResources,
    InvalidResource,
    DuplicateResource,
    ResourceOrder,
    ManifestProjectionCollision,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("policy_too_large"),
            Self::NotCanonical => f.write_str("policy is not canonical JSON"),
            reason => write!(f, "invalid agent policy: {reason:?}"),
        }
    }
}

impl std::error::Error for PolicyError {}

pub fn check_signed_input_len(policy_len: usize) -> Result<usize, PolicyError> {
    policy_len
        .checked_add(AGENT_POLICY_SEPARATOR.len())
        .filter(|len| *len <= MAX_SIGN_PAYLOAD)
        .ok_or(PolicyError::TooLarge)
}

pub fn signed_input(policy: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let mut input = Vec::with_capacity(check_signed_input_len(policy.len())?);
    input.extend_from_slice(AGENT_POLICY_SEPARATOR);
    input.extend_from_slice(policy);
    Ok(input)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicyEnvelope {
    pub v: u32,
    pub policy: String,
    pub key_id: String,
    pub signature_b64: String,
}

impl AgentPolicyEnvelope {
    pub fn new(policy: String, key_id: String, signature: &[u8; 64]) -> Self {
        Self {
            v: 1,
            policy,
            key_id,
            signature_b64: BASE64_STANDARD.encode(signature),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    pub schema: String,
    pub version: i64,
    pub issued_at_unix_secs: i64,
    pub root_key_id: String,
    pub rule_sets: BTreeMap<String, RuleSet>,
    pub bindings: Vec<Binding>,
}

impl AgentPolicy {
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, PolicyError> {
        let policy: Self = parse_canonical(bytes)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        let bytes = canonical_bytes(self)?;
        self.validate()?;
        Ok(bytes)
    }

    /// Encode a generated document, checking the signing-input length before model validation.
    pub(crate) fn canonical_signing_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        let bytes = encode_jcs(self)?;
        check_signed_input_len(bytes.len())?;
        self.validate()?;
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        use PolicyError::*;
        if self.schema != AGENT_POLICY_SCHEMA_V1 {
            return Err(WrongSchema);
        }
        if self.version <= 0 {
            return Err(InvalidVersion);
        }
        if !lower_hex(&self.root_key_id, 16) {
            return Err(InvalidRootKeyId);
        }
        for (service, rules) in &self.rule_sets {
            if service != "github" {
                return Err(UnsupportedService);
            }
            rules.validate()?;
        }
        validate_bindings(&self.bindings)
    }

    /// The repository-to-agent map represented by a validated policy's bindings.
    pub fn github_projection(&self) -> BTreeMap<String, String> {
        self.bindings
            .iter()
            .flat_map(|binding| {
                binding
                    .resources
                    .iter()
                    .map(|repo| (repo.clone(), binding.agent.clone()))
            })
            .collect()
    }
}

pub fn manifest_projection(manifest: &GhManifest) -> Result<BTreeMap<String, String>, PolicyError> {
    let mut projection = BTreeMap::new();
    for (repo, agent) in manifest.bindings() {
        if projection
            .insert(repo.to_ascii_lowercase(), agent.to_owned())
            .is_some()
        {
            return Err(PolicyError::ManifestProjectionCollision);
        }
    }
    Ok(projection)
}

pub fn policy_sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// The registry id that an App creation request may attest. Existing policy
/// bindings also accept older agent names and do not use this check.
pub fn valid_github_app_agent(agent: &str) -> bool {
    agent.strip_prefix("agent_").is_some_and(|id| {
        id.len() == 16
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, PolicyError> {
    if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
        return Err(PolicyError::TooLarge);
    }
    // The ordered JSON reader rejects duplicate keys even inside maps with dynamic names.
    let mut value: ManifestValue =
        serde_json::from_slice(bytes).map_err(|_| PolicyError::InvalidJson)?;
    validate_numbers(&value)?;
    let model = serde_json::from_slice(bytes).map_err(|_| PolicyError::InvalidShape)?;
    if canonical_bytes(&model)? != bytes {
        // Serde also accepts positional arrays for structs; the policy uses objects.
        return Err(if jcs_bytes(&mut value)? == bytes {
            PolicyError::InvalidShape
        } else {
            PolicyError::NotCanonical
        });
    }
    Ok(model)
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, PolicyError> {
    let bytes = encode_jcs(value)?;
    if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
        return Err(PolicyError::TooLarge);
    }
    Ok(bytes)
}

fn encode_jcs(value: &impl Serialize) -> Result<Vec<u8>, PolicyError> {
    let mut value = serde_json::to_value(value)
        .and_then(ManifestValue::deserialize)
        .map_err(|_| PolicyError::InvalidShape)?;
    validate_numbers(&value)?;
    jcs_bytes(&mut value)
}

fn validate_numbers(value: &ManifestValue) -> Result<(), PolicyError> {
    match value {
        ManifestValue::Number(n)
            if !n.as_i64().is_some_and(|n| {
                (-MAX_MANIFEST_JSON_INTEGER..=MAX_MANIFEST_JSON_INTEGER).contains(&n)
            }) =>
        {
            Err(PolicyError::InvalidInteger)
        }
        ManifestValue::Array(values) => values.iter().try_for_each(validate_numbers),
        ManifestValue::Object(members) => members.iter().try_for_each(|(_, v)| validate_numbers(v)),
        _ => Ok(()),
    }
}

fn jcs_bytes(value: &mut ManifestValue) -> Result<Vec<u8>, PolicyError> {
    value.sort_jcs_keys();
    serde_json::to_vec(value).map_err(|_| PolicyError::InvalidShape)
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A GitHub App credential id uses the App's lowercase slug as its suffix.
pub fn valid_app_slug(slug: &str) -> bool {
    (1..=APP_SLUG_LENGTH_LIMIT).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// Unlike Serde's implicit Option default, a nullable field still has to be present.
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

// Omitting a member invokes its default; explicitly giving null does not.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub service: String,
    pub agent: String,
    pub identity: String,
    pub resources: Vec<String>,
}

fn validate_bindings(bindings: &[Binding]) -> Result<(), PolicyError> {
    use PolicyError::*;
    let mut agents = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut resources = BTreeSet::new();
    for binding in bindings {
        if binding.service != "github" {
            return Err(UnsupportedService);
        }
        if binding.agent.is_empty() {
            return Err(EmptyAgentName);
        }
        if !agents.insert((&binding.service, &binding.agent)) {
            return Err(DuplicateBinding);
        }
        if !binding
            .identity
            .strip_prefix("github_app:")
            .is_some_and(valid_app_slug)
        {
            return Err(InvalidIdentity);
        }
        if !identities.insert(&binding.identity) {
            return Err(SharedIdentity);
        }
        if binding.resources.is_empty() {
            return Err(EmptyResources);
        }
        for resource in &binding.resources {
            if !matching::valid_resource(resource) {
                return Err(InvalidResource);
            }
            if !resources.insert(resource) {
                return Err(DuplicateResource);
            }
        }
        if binding.resources.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(ResourceOrder);
        }
    }
    if bindings
        .windows(2)
        .any(|pair| (&pair[0].service, &pair[0].agent) > (&pair[1].service, &pair[1].agent))
    {
        return Err(BindingOrder);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub rule_set: String,
    pub revision: i64,
    pub source: RuleSetSource,
    pub extractor: String,
    pub hosts: Vec<String>,
    pub redirect_hosts: Vec<String>,
    pub kinds: Vec<Kind>,
    pub actions: Vec<Action>,
}

impl RuleSet {
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, PolicyError> {
        let rules: Self = parse_canonical(bytes)?;
        rules.validate()?;
        Ok(rules)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        let bytes = canonical_bytes(self)?;
        self.validate()?;
        Ok(bytes)
    }

    pub fn kind(&self, name: &str) -> Option<&Kind> {
        self.kinds.iter().find(|kind| kind.kind == name)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        use PolicyError::*;
        if self.rule_set != "github" {
            return Err(WrongRuleSetName);
        }
        if self.extractor != "github-rest-graphql/v1" {
            return Err(WrongExtractor);
        }
        if !(1..=MAX_SOURCE_RELEASE_BYTES).contains(&self.source.release.len())
            || !self
                .source
                .release
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(InvalidSourceRelease);
        }
        if !lower_hex(&self.source.sha256, 64) {
            return Err(InvalidSourceDigest);
        }
        for hosts in [&self.hosts, &self.redirect_hosts] {
            if hosts.iter().any(|host| !valid_host(host)) {
                return Err(InvalidHost);
            }
            if hosts.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(HostOrder);
            }
        }
        if self
            .redirect_hosts
            .iter()
            .any(|host| self.hosts.binary_search(host).is_ok())
        {
            return Err(RedirectHostConflict);
        }

        let mut kinds = BTreeMap::new();
        let mut uses_node_lookup = false;
        for kind in &self.kinds {
            if kinds.insert(kind.kind.as_str(), kind).is_some() {
                return Err(DuplicateKind);
            }
            kind.validate()?;
            uses_node_lookup |= kind.requests.iter().any(|request| match request {
                Request::Graphql(entry) => entry.predicates().any(|p| p == Predicate::NodeInScope),
                Request::Rest(_) => false,
            });
        }
        if uses_node_lookup && !kinds.contains_key("node_repository") {
            return Err(MissingNodeRepository);
        }
        for kind in &self.kinds {
            if let Some(ownership) = &kind.ownership {
                if ownership.reads.len() != ownership.check.read_count() {
                    return Err(InvalidOwnershipReads);
                }
                for name in &ownership.reads {
                    let read = kinds.get(name.as_str()).ok_or(UnknownOwnershipRead)?;
                    if read.class != Class::Read {
                        return Err(OwnershipReadNotRead);
                    }
                }
            }
        }
        matching::validate_requests(self)?;

        let mut actions = BTreeSet::new();
        for action in &self.actions {
            if action.action.is_empty() {
                return Err(EmptyActionName);
            }
            if !actions.insert(&action.action) {
                return Err(DuplicateAction);
            }
            action.requirements_from(|name| kinds.get(name).copied())?;
        }
        Ok(())
    }
}

fn valid_host(host: &str) -> bool {
    host.len() <= MAX_POLICY_HOST_BYTES
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_POLICY_DNS_LABEL_BYTES
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSource {
    pub release: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Read,
    Speech,
    Operator,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    None,
    Once,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identity {
    Agent,
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kind {
    pub kind: String,
    pub class: Class,
    pub approval: Approval,
    pub identity: Identity,
    #[serde(deserialize_with = "nullable")]
    pub credential: Option<Credential>,
    #[serde(deserialize_with = "nullable")]
    pub ownership: Option<Ownership>,
    pub requests: Vec<Request>,
    #[serde(deserialize_with = "nullable")]
    pub consent: Option<Consent>,
}

impl Kind {
    fn validate(&self) -> Result<(), PolicyError> {
        use PolicyError::*;
        if self.kind.is_empty() {
            return Err(EmptyKindName);
        }
        if self.kind == "node_repository" && !self.is_node_repository() {
            return Err(InvalidNodeRepository);
        }
        if self.class == Class::Denied {
            if !self.requests.is_empty()
                || self.credential.is_some()
                || self.ownership.is_some()
                || self.consent.is_some()
            {
                return Err(DeniedKindContent);
            }
            return Ok(());
        }
        if self.class == Class::Operator && self.approval != Approval::Once {
            return Err(OperatorNeedsApproval);
        }
        if self.identity == Identity::Anonymous {
            if self.credential.is_some() {
                return Err(AnonymousCredential);
            }
            if self.class != Class::Read {
                return Err(AnonymousNotRead);
            }
        }
        if let Some(credential) = &self.credential {
            validate_installation_permissions(&credential.github_permissions)
                .map_err(|_| InvalidPermissions)?;
        }
        if self.requests.is_empty() {
            return Err(MissingRequests);
        }
        if self.consent.is_some() && self.approval != Approval::Once {
            return Err(UnexpectedConsent);
        }
        Ok(())
    }

    fn is_node_repository(&self) -> bool {
        let [Request::Graphql(request)] = self.requests.as_slice() else {
            return false;
        };
        let Some(credential) = &self.credential else {
            return false;
        };
        self.class == Class::Read
            && self.approval == Approval::None
            && self.identity == Identity::Agent
            && self.ownership.is_none()
            && self.consent.is_none()
            && request.operation == Operation::Query
            && request.fields == ["node"]
            && request.arguments.is_none()
            && credential.github_permissions.len() == 3
            && ["issues", "metadata", "pull_requests"].iter().all(|name| {
                credential.github_permissions.get(*name).map(String::as_str) == Some("read")
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub github_permissions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    pub check: OwnershipCheck,
    pub reads: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipCheck {
    OwnComment,
    OwnIssue,
    OwnPullRequest,
    OwnPullRequests,
    OwnStackPullRequests,
    ThreadInRepository,
    OwnLastComment,
    OwnThreadPullRequest,
}

impl OwnershipCheck {
    fn read_count(self) -> usize {
        match self {
            Self::OwnLastComment | Self::OwnThreadPullRequest => 2,
            Self::OwnComment
            | Self::OwnIssue
            | Self::OwnPullRequest
            | Self::OwnPullRequests
            | Self::OwnStackPullRequests
            | Self::ThreadInRepository => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Rest(Box<RestRequest>),
    Graphql(GraphqlRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub body: Option<Constraints>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub query: Option<Constraints>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub required: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub optional: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub fixed: Option<BTreeMap<String, Value>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub forbidden: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub additional: Option<Additional>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Additional {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlRequest {
    pub operation: Operation,
    pub fields: Vec<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub arguments: Option<BTreeMap<String, Predicate>>,
}

impl GraphqlRequest {
    fn predicates(&self) -> impl Iterator<Item = Predicate> + '_ {
        self.arguments.iter().flat_map(BTreeMap::values).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Query,
    Mutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    RepositoryInScope,
    NodeInScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub action: String,
    pub legs: Vec<Leg>,
}

impl Action {
    pub fn requirements(&self, rules: &RuleSet) -> Result<(Class, Approval), PolicyError> {
        self.requirements_from(|name| rules.kind(name))
    }

    fn requirements_from<'a>(
        &self,
        kind_by_name: impl Fn(&str) -> Option<&'a Kind>,
    ) -> Result<(Class, Approval), PolicyError> {
        if self.legs.is_empty() {
            return Err(PolicyError::EmptyAction);
        }
        let mut class = Class::Read;
        let mut approval = Approval::None;
        for leg in &self.legs {
            let kind = kind_by_name(&leg.kind).ok_or(PolicyError::UnknownActionLeg)?;
            if kind.class == Class::Denied {
                return Err(PolicyError::DeniedActionLeg);
            }
            class = class.max(kind.class);
            approval = approval.max(kind.approval);
        }
        Ok((class, approval))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Leg {
    pub kind: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub optional: Option<bool>,
}

#[cfg(test)]
mod tests;
