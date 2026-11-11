//! The shared admin-op wire contract: the exact op-body shapes the CLI/app signs
//! and the module verifies+executes.
//!
//! Both sides use THESE types, so the bytes the caller MACs are byte-identical to
//! what the module parses (the caller serializes an `AdminOpBody`, MACs those exact
//! bytes, and sends them verbatim; the module verifies those bytes, then decodes
//! them back into an `AdminOpBody`). Keeping the contract in one place is why the
//! transcript's op-body binding cannot silently drift between the two binaries — a
//! field rename breaks both at compile time, not at runtime.
//!
//! The body is treated as OPAQUE bytes during authentication (parse-after-verify);
//! these types are only used to BUILD the bytes (caller) and to INTERPRET them
//! (module) once the MAC has proven possession.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::agent_secret::SecretPut;
use crate::audit::AuditRecord;
use crate::audit::{AuditCtx, AuditOp};
use crate::federation::{MemberGrantOperation, MemberGrantSelector};
use crate::record::{CredentialKind, RecordIdentity, VaultRecord};
use crate::store::{
    mint_handle, EncryptedStore, GrantOperation, ReadGrant, RecordMeta, SelectorKind,
    SetCategoryMode, SetProvidersMode, StoreOpError,
};

/// The admin-op schema version. Bumped only on a breaking op-body change; the
/// module refuses any other version rather than best-effort parsing it.
pub const ADMIN_OP_SCHEMA_V1: u32 = 1;
pub const ADMIN_OP_SCHEMA_V2: u32 = 2;
pub const ADMIN_OP_SCHEMA_V3: u32 = 3;

/// Operator signing is for short machine-authentication transcripts, not artifacts.
/// Keep the decoded limit below the unchanged admin-envelope limit online.
pub const MAX_OPERATOR_SIGN_PAYLOAD: usize = 64 * 1024;

// Preserve explicit null on extended fields: presence affects schema admission and
// validation. Only omission is absent; legacy Option fields still accept null.
fn present_scope_value<'de, D>(deserializer: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(Some)
}

/// One authenticated admin operation. `#[serde(tag = "op")]` so the discriminator
/// is an `op` string inside the same object the transcript covers.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum AdminOpBody {
    #[serde(rename = "admin.provider_set")]
    ProviderSet {
        v: u32,
        service: String,
        categories: Vec<String>,
        provider_ids: Vec<String>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_scope_value"
        )]
        hosts: Option<serde_json::Value>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_scope_value"
        )]
        auth_header: Option<serde_json::Value>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_scope_value"
        )]
        auth_scheme: Option<serde_json::Value>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_scope_value"
        )]
        fusiform_provider_id: Option<serde_json::Value>,
    },
    #[serde(rename = "admin.provider_remove")]
    ProviderRemove { v: u32, service: String },
    /// Sign with an explicitly opted-in key, after committing signature history.
    #[serde(rename = "admin.operator_sign")]
    OperatorSign {
        v: u32,
        id: String,
        payload_b64: String,
    },
    #[serde(rename = "admin.manifest_import")]
    ManifestImport {
        v: u32,
        envelope: crate::store::GhManifestHandoffEnvelope,
    },
    #[serde(rename = "admin.manifest_sign")]
    ManifestSign {
        v: u32,
        manifest_bytes: String,
        approver: String,
    },
    #[serde(rename = "admin.manifest_export")]
    ManifestExport { v: u32, version: i64 },
    #[serde(rename = "admin.manifest_list")]
    ManifestList { v: u32 },
    #[serde(rename = "admin.manifest_retire_machine")]
    ManifestRetireMachine { v: u32, member_id: String },
    #[serde(rename = "admin.manifest_one_tap_set")]
    ManifestOneTapSet { v: u32, enabled: bool },
    #[serde(rename = "admin.manifest_one_tap_status")]
    ManifestOneTapStatus { v: u32 },
    #[serde(rename = "admin.store")]
    Store {
        v: u32,
        id: String,
        // Boxed to keep the enum variants' sizes comparable (a VaultRecord carries
        // token strings); serde flattens the box transparently.
        record: Box<VaultRecord>,
        audit_op: AdminAuditOp,
        mode: StoreMode,
    },
    /// A separate discriminator prevents an older daemon storing a plain API key.
    #[serde(rename = "admin.gateway_create")]
    GatewayCreate {
        v: u32,
        id: String,
        record: Box<VaultRecord>,
        audit_op: AdminAuditOp,
        base_url: String,
        auth_header: String,
        auth_scheme: String,
        headers: Vec<crate::gateway::GatewayHeader>,
        provider_ids: Vec<String>,
    },
    /// Identity-aware replacement has its own op discriminator so a daemon that predates
    /// sticky identity rejects it instead of silently treating it as a legacy replace.
    #[serde(rename = "admin.store_with_identity_policy")]
    StoreWithIdentityPolicy {
        v: u32,
        id: String,
        record: Box<VaultRecord>,
        audit_op: AdminAuditOp,
        clear_identity: bool,
    },
    /// Update only the non-secret identity attached to an existing record. The store
    /// re-seals the unchanged credential material and keeps its lifecycle state.
    #[serde(rename = "admin.set_identity")]
    SetIdentity {
        v: u32,
        id: String,
        identity: RecordIdentity,
    },
    #[serde(rename = "admin.invalidate")]
    Invalidate { v: u32, id: String },
    /// Reversibly stop serving a credential because an operator intentionally retired
    /// it. This is the only admin operation that writes `retired`; all discovery paths
    /// continue to use `needs_reauth` or `corrupt`.
    #[serde(rename = "admin.logout")]
    Logout { v: u32, id: String },
    /// Clear `needs_reauth` or `retired` back to active WITHOUT replacing the stored material: the
    /// operator asserting the credential was marked dead in error.
    ///
    /// The counterpart to `Invalidate`, and NOT a substitute for `Store` -- it changes
    /// no secret, only a verdict about one. Exists because a mistaken consumer report
    /// could otherwise strand material the vault holds intact: a GitHub App key is
    /// shredded after deposit by custody rule, so there is no copy to re-put and no
    /// login flow to re-mint, and recovering would need a browser ceremony.
    #[serde(rename = "admin.reactivate")]
    Reactivate { v: u32, id: String },
    /// PERMANENT removal: delete the credential row, its intent, and its handles
    /// (audited; the chain keeps the history). `logout` (invalidate) is the
    /// reversible sibling — remove is for retiring an account or cleaning up a
    /// mistaken id.
    #[serde(rename = "admin.remove")]
    Remove { v: u32, id: String },
    #[serde(rename = "admin.mint_handle")]
    MintHandle { v: u32, id: String },
    #[serde(rename = "admin.revoke_handle")]
    RevokeHandle { v: u32, handle: String },
    // A distinct tag makes older daemons refuse rather than reinterpret a hash as a bearer.
    #[serde(rename = "admin.revoke_handle_by_hash")]
    RevokeHandleByHash { v: u32, handle_hash: String },
    #[serde(rename = "admin.revoke_all_handles")]
    RevokeAllHandles { v: u32, id: String },
    /// Grant a reserved module principal one literal-prefix credential operation.
    #[serde(rename = "admin.grant_create")]
    GrantCreate {
        v: u32,
        principal_id: String,
        credential_prefix: String,
        operation: GrantOperation,
    },
    /// Revoke a reserved module principal literal-prefix credential operation grant.
    #[serde(rename = "admin.grant_revoke")]
    GrantRevoke {
        v: u32,
        principal_id: String,
        credential_prefix: String,
        operation: GrantOperation,
    },
    #[serde(rename = "admin.grant_create_v2")]
    GrantCreateV2 {
        v: u32,
        principal_kind: String,
        principal_id: String,
        selector_kind: SelectorKind,
        selector: String,
        operation: GrantOperation,
    },
    #[serde(rename = "admin.grant_revoke_v2")]
    GrantRevokeV2 {
        v: u32,
        principal_kind: String,
        principal_id: String,
        selector_kind: SelectorKind,
        selector: String,
        operation: GrantOperation,
    },
    /// Approve a pending enrollment request under the master key, optionally renaming it.
    ///
    /// GATE 2 IS THE WHOLE POINT OF THIS OP. Anything on the machine can PROPOSE an
    /// enrollment -- the request queue is reachable from the anonymous read plane by
    /// design, because a consumer has no identity yet. Only the master key can turn a
    /// proposal into a principal that grants can name. Without that asymmetry the
    /// ceremony would be self-service.
    ///
    /// Approval does NOT mint the token: the first successful poll does, against the
    /// request secret the proposer minted. So an operator approving a request cannot
    /// learn the token, and a squatter who proposed a name it does not hold cannot
    /// collect one even if an operator approves by mistake.
    #[serde(rename = "admin.enroll_approve")]
    EnrollApprove {
        v: u32,
        request_id: String,
        /// The name to admit. Usually the proposed one; an operator may correct it,
        /// because a name a stranger chose is a claim rather than a fact.
        final_name: String,
        /// Operator replacement for the proposed person-facing label.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::display_name::deserialize_optional_display_name"
        )]
        display_name: Option<String>,
        /// Explicitly allow the new consumer to inherit existing name-bound grants.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        keep_grants: bool,
        /// Apply only the permissions stored on the pending request, never caller-supplied grants.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        grant_requested: bool,
    },
    /// Set or clear the display name of a live, approved enrollment.
    #[serde(rename = "admin.enroll_label")]
    EnrollLabel {
        v: u32,
        name: String,
        display_name: Option<String>,
    },
    /// Deny a pending enrollment request.
    #[serde(rename = "admin.enroll_deny")]
    EnrollDeny { v: u32, request_id: String },
    /// Revoke a live enrollment and its grants in one transaction. Each removed grant
    /// gets the same audit row as an explicit revoke-grant, preserving its history
    /// without leaving reach for a different consumer later admitted under the name.
    #[serde(rename = "admin.enroll_revoke")]
    EnrollRevoke { v: u32, name: String },
    /// Mint a fresh token for a live enrollment, invalidating the previous one.
    ///
    /// The reply CARRIES THE TOKEN, which no other admin op does. That is unavoidable --
    /// an operator re-issuing on behalf of a consumer that lost its file has to deliver
    /// it somehow -- and it is why this op's result is the one place an admin reply holds
    /// bearer material. It must never be logged, and the generation bump is what makes
    /// the old token stop working rather than merely being superseded.
    #[serde(rename = "admin.enroll_reissue")]
    EnrollReissue { v: u32, name: String },
    #[serde(rename = "admin.set_category")]
    SetCategory {
        v: u32,
        credential_id: String,
        mode: SetCategoryMode,
        categories: Vec<String>,
    },
    /// Set, add to or remove from a credential's catalog provider ids. Non-secret
    /// operator metadata kept beside the record: the envelope is never opened, and the
    /// reply carries the resulting set in ascending byte order.
    #[serde(rename = "admin.set_providers")]
    SetProviders {
        v: u32,
        credential_id: String,
        mode: SetProvidersMode,
        provider_ids: Vec<String>,
    },
    /// Set or clear an operator-asserted subscription tier; pricing owns its vocabulary.
    #[serde(rename = "admin.set_plan")]
    SetPlan {
        v: u32,
        credential_id: String,
        plan_tier: Option<String>,
    },
    #[serde(rename = "admin.reclassify")]
    Reclassify { v: u32, force: bool },
    /// Record that a NAMED APPROVER approved a specific artifact, identified by the
    /// SHA-256 of its exact bytes, before a signing window is opened for it.
    ///
    /// Master-key-gated like every other admin op, and that is the point rather than
    /// uniformity: an approval a route caller could forge would prove nothing about who
    /// approved. The signing itself is NOT gated this way — `credential.sign` needs only
    /// a handle — so the gate is deliberately on the record of intent rather than on the
    /// act, which is the asymmetry the ceremony rests on.
    #[serde(rename = "admin.approval")]
    Approval {
        v: u32,
        /// The signing credential the window will open on, so the entry names WHICH key
        /// was approved for use and not merely that something was approved.
        credential_id: String,
        /// Lowercase hex SHA-256 of the exact artifact bytes. Never a rendering, never a
        /// canonicalized form: the verifier verifies received bytes, so the approver
        /// must approve those same bytes or the two meet at nothing.
        artifact_sha256: String,
        /// Who approved. Free text by design — the vault cannot authenticate a human,
        /// and pretending otherwise by constraining the field would imply a check that
        /// does not exist.
        approver: String,
    },
    /// An authenticated READ: the no-decrypt credential inventory + health summary.
    /// A read, but master-key-gated like every other admin op, because the full
    /// per-credential id/state list is not an anonymous enumeration surface (the
    /// anonymous read plane is capability-handle-scoped by design). Serves `ck creds
    /// status` against a RUNNING daemon.
    #[serde(rename = "admin.status")]
    Status { v: u32 },
    /// Switch the federation member-mapping gate. While it is off, callosum's channel
    /// keeps the release-1 behaviour; while it is on, another member's vault reaching
    /// this one is mapped to its member id and only `callosum-self` keeps callosum's
    /// grants. Read live on every federation decision, so it takes effect at once.
    #[serde(rename = "admin.federation_gate_set")]
    FederationGateSet { v: u32, enabled: bool },
    #[serde(rename = "admin.secret_phone_gate_set")]
    SecretPhoneGateSet { v: u32, enabled: bool },
    #[serde(rename = "admin.secret_multi_host_set")]
    SecretMultiHostSet { v: u32, enabled: bool },
    /// `ck auth secret put`: create an agent secret from operator-supplied material.
    ///
    /// THE ONLY ADMIN OP THAT CARRIES SECRET MATERIAL INBOUND, shortly after
    /// `admin.enroll_reissue` became the only one that carries a bearer outbound. The
    /// same custody rule applies in both directions: the material must never reach a
    /// process argument (argv is world-readable on many systems and lands in shell
    /// history), a log line, a `Debug` rendering or an error, so the CLI reads it from a
    /// mode-0600 file or a prompt and this body transports it once, inside the bytes the
    /// admin MAC already covers. A caller that could rewrite those bytes could also
    /// rewrite `op`, so carrying material here adds no new trust boundary.
    ///
    /// An API key uses `host` (optional `path_prefix`) or `rules`, plus `location`;
    /// a login uses `origin` or `origins`. The vault validates them with the same
    /// parser a phone deposit uses, so the two paths cannot accept different shapes.
    #[serde(rename = "admin.secret_put")]
    SecretPut {
        v: u32,
        kind: String,
        name: String,
        host: Option<String>,
        path_prefix: Option<String>,
        location: Option<String>,
        origin: Option<String>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_scope_value"
        )]
        rules: Option<serde_json::Value>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_scope_value"
        )]
        origins: Option<serde_json::Value>,
        material_b64url: String,
    },
    /// `ck auth secret delete`: remove a secret, its grants and its pending requests.
    ///
    /// The operator delete is unsigned by design (unlike the phone's two-step signed
    /// delete): the admin MAC already proves the master key, which is the strongest
    /// authority this vault has, and requiring a phone ceremony to remove a secret the
    /// operator put in place would make `put` reversible only through a device the
    /// operator may no longer hold.
    #[serde(rename = "admin.secret_delete")]
    SecretDelete { v: u32, name: String },
    /// `ck auth secret revoke`: remove one grant by id, keeping the secret itself.
    #[serde(rename = "admin.secret_revoke_grant")]
    SecretRevokeGrant { v: u32, grant_id: String },
    /// `ck auth secret home set <member-id>|self` and `ck auth secret home unset`: name
    /// the vault that holds this account's agent secrets (`secrets.home_member`).
    ///
    /// Setting `self` or clearing the setting is a local write and runs offline too.
    /// Naming a member runs only on the live daemon. An id that is this computer's own
    /// (the stored self id, or the id callosum computes for this computer) is stored as
    /// `self`; any other id must be a member callosum shows as paired.
    #[serde(rename = "admin.secret_home_set")]
    SecretHomeSet { v: u32, home: SecretHomeTarget },
    /// Set this vault's own member id (`fed-computer:<fp>`), which it writes into every
    /// `requester`, `home`, `sender` and `receiver` field it emits. Peers check those
    /// against the authenticated caller, so a wrong value fails closed.
    ///
    /// Runs only on the live daemon: it first asks callosum which member id this
    /// computer has and refuses a typed id that differs, so a mistyped id can never
    /// be stored.
    #[serde(rename = "admin.federation_self_set")]
    FederationSelfSet { v: u32, member: String },
    /// `ck auth transfer init --self <member>`: create this vault's transfer key
    /// (`kem:vault-transfer:1`) when it has none, grant callosum the one announce read on
    /// it, and set the self id. Daemon-only, for the same self-id check as
    /// [`AdminOpBody::FederationSelfSet`].
    #[serde(rename = "admin.transfer_init")]
    TransferInit { v: u32, self_member: String },
    /// `ck auth transfer init --replace`: replace a transfer key found off `Active`,
    /// rejecting every pending incoming transfer and abandoning every outgoing one.
    #[serde(rename = "admin.transfer_recover")]
    TransferRecover { v: u32 },
    /// `ck auth transfer send --id <credential> --to <member>`. Daemon-only: it looks up
    /// the receiver's announced key and delivers the sealed envelope.
    #[serde(rename = "admin.transfer_send")]
    TransferSend {
        v: u32,
        credential_id: String,
        to: String,
    },
    /// `ck auth transfer send --resume <transfer-id>`: redeliver a stored envelope.
    #[serde(rename = "admin.transfer_resume")]
    TransferResume { v: u32, transfer_id: String },
    /// `ck auth transfer receive`: the transfers waiting for this operator.
    #[serde(rename = "admin.transfer_receive")]
    TransferReceive { v: u32 },
    /// `ck auth transfer accept <transfer-id> --from <member> [--replace]`. Daemon-only:
    /// it looks up the sender's announced key to open the envelope again.
    #[serde(rename = "admin.transfer_accept")]
    TransferAccept {
        v: u32,
        transfer_id: String,
        from: String,
        replace: bool,
    },
    /// `ck auth transfer reject <transfer-id> --from <member>`.
    #[serde(rename = "admin.transfer_reject")]
    TransferReject {
        v: u32,
        transfer_id: String,
        from: String,
    },
    /// `ck auth remote add --id <id> --home <member>`. Daemon-only: it fetches the
    /// home's description of the login once and stores that, never the token.
    #[serde(rename = "admin.remote_add")]
    RemoteAdd {
        v: u32,
        credential_id: String,
        home: String,
    },
    /// `ck auth remote remove --id <id>`.
    #[serde(rename = "admin.remote_remove")]
    RemoteRemove { v: u32, credential_id: String },
    /// `ck auth remote list`.
    #[serde(rename = "admin.remote_list")]
    RemoteList { v: u32 },
    /// `ck auth member grant`. Daemon-only: it records the member's current pairing id,
    /// which only callosum knows.
    #[serde(rename = "admin.member_grant")]
    MemberGrant {
        v: u32,
        member: String,
        operation: MemberGrantOperation,
        selector: MemberGrantSelector,
    },
    /// `ck auth member revoke`. Needs no lookup.
    #[serde(rename = "admin.member_revoke")]
    MemberRevoke {
        v: u32,
        member: String,
        operation: MemberGrantOperation,
        selector: MemberGrantSelector,
    },
    /// `ck auth member list`.
    #[serde(rename = "admin.member_list")]
    MemberList { v: u32 },
}

/// Redacted `Debug`, hand-written rather than derived, and NOT only because of the
/// boxed `VaultRecord` -- that one is fixed transitively now that `VaultRecord` redacts
/// its own payload.
///
/// THE VARIANT THAT MADE THIS NECESSARY IS `RevokeHandle`. Its `handle` is the RAW
/// `ckh_...` bearer, not a hash: `apply` passes it straight to `store.revoke_handle`,
/// which hashes it there (`handle_hash(raw_handle)`). A capability handle in a log is
/// strictly worse than an encrypted payload in one -- it needs no key, no decoding, and
/// no vault access to use. Anyone who can read the line can read the credential it
/// grants, until someone notices and revokes it.
///
/// A MANUAL IMPL RATHER THAN A REDACTING NEWTYPE, deliberately: this enum IS the MAC
/// transcript, verified byte-for-byte on the admin route, so nothing that could perturb
/// its serialization belongs anywhere near it. A `Debug` impl cannot; a serde-adjacent
/// type change could.
///
/// The exhaustive match is the forcing function. A new variant carrying a new secret
/// will not compile until someone has decided how it renders, which is the property a
/// derive gives up.
impl std::fmt::Debug for AdminOpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminOpBody::ProviderSet {
                v,
                service,
                categories,
                provider_ids,
                hosts,
                auth_header,
                auth_scheme,
                fusiform_provider_id,
            } => f
                .debug_struct("ProviderSet")
                .field("v", v)
                .field("service", service)
                .field("categories", categories)
                .field("provider_ids", provider_ids)
                .field("hosts", hosts)
                .field("auth_header", auth_header)
                .field("auth_scheme", auth_scheme)
                .field("fusiform_provider_id", fusiform_provider_id)
                .finish(),
            AdminOpBody::ProviderRemove { v, service } => f
                .debug_struct("ProviderRemove")
                .field("v", v)
                .field("service", service)
                .finish(),
            AdminOpBody::ManifestImport { v, .. } | AdminOpBody::ManifestSign { v, .. } => f
                .debug_struct(self.op_name())
                .field("v", v)
                .field("manifest_bytes", &"<redacted>")
                .finish(),
            AdminOpBody::ManifestExport { v, version } => f
                .debug_struct("ManifestExport")
                .field("v", v)
                .field("version", version)
                .finish(),
            AdminOpBody::ManifestList { v } | AdminOpBody::ManifestOneTapStatus { v } => {
                f.debug_struct(self.op_name()).field("v", v).finish()
            }
            AdminOpBody::ManifestRetireMachine { v, member_id } => f
                .debug_struct("ManifestRetireMachine")
                .field("v", v)
                .field("member_id", member_id)
                .finish(),
            AdminOpBody::ManifestOneTapSet { v, enabled } => f
                .debug_struct("ManifestOneTapSet")
                .field("v", v)
                .field("enabled", enabled)
                .finish(),
            AdminOpBody::OperatorSign { v, id, .. } => f
                .debug_struct("OperatorSign")
                .field("v", v)
                .field("id", id)
                .field("payload_b64", &"<redacted>")
                .finish(),
            AdminOpBody::Store {
                v,
                id,
                record,
                audit_op,
                mode,
            } => f
                .debug_struct("Store")
                .field("v", v)
                .field("id", id)
                // VaultRecord redacts its own payload.
                .field("record", record)
                .field("audit_op", audit_op)
                .field("mode", mode)
                .finish(),
            AdminOpBody::StoreWithIdentityPolicy {
                v,
                id,
                record,
                audit_op,
                clear_identity,
            } => f
                .debug_struct("StoreWithIdentityPolicy")
                .field("v", v)
                .field("id", id)
                .field("record", record)
                .field("audit_op", audit_op)
                .field("clear_identity", clear_identity)
                .finish(),
            AdminOpBody::GatewayCreate {
                v,
                id,
                record,
                audit_op,
                base_url,
                auth_header,
                auth_scheme,
                headers,
                provider_ids,
            } => f
                .debug_struct("GatewayCreate")
                .field("v", v)
                .field("id", id)
                .field("record", record)
                .field("audit_op", audit_op)
                .field("base_url", base_url)
                .field("auth_header", auth_header)
                .field("auth_scheme", auth_scheme)
                .field(
                    "header_names",
                    &headers
                        .iter()
                        .map(|header| &header.name)
                        .collect::<Vec<_>>(),
                )
                .field("provider_ids", provider_ids)
                .finish(),
            AdminOpBody::SetIdentity { v, id, identity } => f
                .debug_struct("SetIdentity")
                .field("v", v)
                .field("id", id)
                .field("identity", identity)
                .finish(),
            AdminOpBody::Invalidate { v, id } => f
                .debug_struct("Invalidate")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Logout { v, id } => f
                .debug_struct("Logout")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Reactivate { v, id } => f
                .debug_struct("Reactivate")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Remove { v, id } => f
                .debug_struct("Remove")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::MintHandle { v, id } => f
                .debug_struct("MintHandle")
                .field("v", v)
                .field("id", id)
                .finish(),
            // The one that matters: a live bearer token.
            AdminOpBody::RevokeHandle { v, .. } => f
                .debug_struct("RevokeHandle")
                .field("v", v)
                .field("handle", &"<redacted>")
                .finish(),
            AdminOpBody::RevokeHandleByHash { v, handle_hash } => f
                .debug_struct("RevokeHandleByHash")
                .field("v", v)
                .field("handle_hash", handle_hash)
                .finish(),
            AdminOpBody::RevokeAllHandles { v, id } => f
                .debug_struct("RevokeAllHandles")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::GrantCreate {
                v,
                principal_id,
                credential_prefix,
                operation,
            } => f
                .debug_struct("GrantCreate")
                .field("v", v)
                .field("principal_id", principal_id)
                .field("credential_prefix", credential_prefix)
                .field("operation", operation)
                .finish(),
            AdminOpBody::GrantRevoke {
                v,
                principal_id,
                credential_prefix,
                operation,
            } => f
                .debug_struct("GrantRevoke")
                .field("v", v)
                .field("principal_id", principal_id)
                .field("credential_prefix", credential_prefix)
                .field("operation", operation)
                .finish(),
            AdminOpBody::EnrollApprove {
                v,
                request_id,
                final_name,
                keep_grants,
                display_name,
                grant_requested,
            } => f
                .debug_struct("EnrollApprove")
                .field("v", v)
                .field("request_id", request_id)
                .field("final_name", final_name)
                .field("display_name", display_name)
                .field("keep_grants", keep_grants)
                .field("grant_requested", grant_requested)
                .finish(),
            AdminOpBody::EnrollLabel {
                v,
                name,
                display_name,
            } => f
                .debug_struct("EnrollLabel")
                .field("v", v)
                .field("name", name)
                .field("display_name", display_name)
                .finish(),
            AdminOpBody::EnrollDeny { v, request_id } => f
                .debug_struct("EnrollDeny")
                .field("v", v)
                .field("request_id", request_id)
                .finish(),
            AdminOpBody::EnrollRevoke { v, name } => f
                .debug_struct("EnrollRevoke")
                .field("v", v)
                .field("name", name)
                .finish(),
            AdminOpBody::EnrollReissue { v, name } => f
                .debug_struct("EnrollReissue")
                .field("v", v)
                .field("name", name)
                .finish(),
            AdminOpBody::GrantCreateV2 {
                v,
                principal_kind,
                principal_id,
                selector_kind,
                selector,
                operation,
            } => f
                .debug_struct("GrantCreateV2")
                .field("v", v)
                .field("principal_kind", principal_kind)
                .field("principal_id", principal_id)
                .field("selector_kind", selector_kind)
                .field("selector", selector)
                .field("operation", operation)
                .finish(),
            AdminOpBody::GrantRevokeV2 {
                v,
                principal_kind,
                principal_id,
                selector_kind,
                selector,
                operation,
            } => f
                .debug_struct("GrantRevokeV2")
                .field("v", v)
                .field("principal_kind", principal_kind)
                .field("principal_id", principal_id)
                .field("selector_kind", selector_kind)
                .field("selector", selector)
                .field("operation", operation)
                .finish(),
            AdminOpBody::SetCategory {
                v,
                credential_id,
                mode,
                categories,
            } => f
                .debug_struct("SetCategory")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("mode", mode)
                .field("categories", categories)
                .finish(),
            AdminOpBody::SetProviders {
                v,
                credential_id,
                mode,
                provider_ids,
            } => f
                .debug_struct("SetProviders")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("mode", mode)
                .field("provider_ids", provider_ids)
                .finish(),
            AdminOpBody::SetPlan {
                v,
                credential_id,
                plan_tier,
            } => f
                .debug_struct("SetPlan")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("plan_tier", plan_tier)
                .finish(),
            AdminOpBody::Reclassify { v, force } => f
                .debug_struct("Reclassify")
                .field("v", v)
                .field("force", force)
                .finish(),
            AdminOpBody::Approval {
                v,
                credential_id,
                artifact_sha256,
                approver,
            } => f
                .debug_struct("Approval")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("artifact_sha256", artifact_sha256)
                .field("approver", approver)
                .finish(),
            AdminOpBody::Status { v } => f.debug_struct("Status").field("v", v).finish(),
            AdminOpBody::SecretMultiHostSet { v, enabled } => f
                .debug_struct("SecretMultiHostSet")
                .field("v", v)
                .field("enabled", enabled)
                .finish(),
            AdminOpBody::SecretPhoneGateSet { v, enabled } => f
                .debug_struct("SecretPhoneGateSet")
                .field("v", v)
                .field("enabled", enabled)
                .finish(),
            // Secondary defence only: the CLI never renders this body. The material itself
            // is redacted here for the same reason `RevokeHandle` redacts its bearer — a
            // derived Debug could put a live password in a crash report — and the scope
            // fields stay visible because they are non-secret metadata an operator
            // diagnosing a bad put needs to see.
            AdminOpBody::SecretPut {
                v,
                kind,
                name,
                host,
                path_prefix,
                location,
                origin,
                rules,
                origins,
                ..
            } => f
                .debug_struct("SecretPut")
                .field("v", v)
                .field("kind", kind)
                .field("name", name)
                .field("host", host)
                .field("path_prefix", path_prefix)
                .field("location", location)
                .field("origin", origin)
                .field("rules", rules)
                .field("origins", origins)
                .field("material_b64url", &"<redacted>")
                .finish(),
            AdminOpBody::SecretDelete { v, name } => f
                .debug_struct("SecretDelete")
                .field("v", v)
                .field("name", name)
                .finish(),
            AdminOpBody::SecretRevokeGrant { v, grant_id } => f
                .debug_struct("SecretRevokeGrant")
                .field("v", v)
                .field("grant_id", grant_id)
                .finish(),
            AdminOpBody::SecretHomeSet { v, home } => f
                .debug_struct("SecretHomeSet")
                .field("v", v)
                .field("home", home)
                .finish(),
            AdminOpBody::FederationGateSet { v, enabled } => f
                .debug_struct("FederationGateSet")
                .field("v", v)
                .field("enabled", enabled)
                .finish(),
            AdminOpBody::FederationSelfSet { v, member } => f
                .debug_struct("FederationSelfSet")
                .field("v", v)
                .field("member", member)
                .finish(),
            // None of the federation admin ops carries secret material: member ids,
            // credential ids and transfer ids are all non-secret.
            AdminOpBody::TransferInit { v, self_member } => f
                .debug_struct("TransferInit")
                .field("v", v)
                .field("self_member", self_member)
                .finish(),
            AdminOpBody::TransferRecover { v } => {
                f.debug_struct("TransferRecover").field("v", v).finish()
            }
            AdminOpBody::TransferSend {
                v,
                credential_id,
                to,
            } => f
                .debug_struct("TransferSend")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("to", to)
                .finish(),
            AdminOpBody::TransferResume { v, transfer_id } => f
                .debug_struct("TransferResume")
                .field("v", v)
                .field("transfer_id", transfer_id)
                .finish(),
            AdminOpBody::TransferReceive { v } => {
                f.debug_struct("TransferReceive").field("v", v).finish()
            }
            AdminOpBody::TransferAccept {
                v,
                transfer_id,
                from,
                replace,
            } => f
                .debug_struct("TransferAccept")
                .field("v", v)
                .field("transfer_id", transfer_id)
                .field("from", from)
                .field("replace", replace)
                .finish(),
            AdminOpBody::TransferReject {
                v,
                transfer_id,
                from,
            } => f
                .debug_struct("TransferReject")
                .field("v", v)
                .field("transfer_id", transfer_id)
                .field("from", from)
                .finish(),
            AdminOpBody::RemoteAdd {
                v,
                credential_id,
                home,
            } => f
                .debug_struct("RemoteAdd")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("home", home)
                .finish(),
            AdminOpBody::RemoteRemove { v, credential_id } => f
                .debug_struct("RemoteRemove")
                .field("v", v)
                .field("credential_id", credential_id)
                .finish(),
            AdminOpBody::RemoteList { v } => f.debug_struct("RemoteList").field("v", v).finish(),
            AdminOpBody::MemberGrant {
                v,
                member,
                operation,
                selector,
            } => f
                .debug_struct("MemberGrant")
                .field("v", v)
                .field("member", member)
                .field("operation", operation)
                .field("selector", selector)
                .finish(),
            AdminOpBody::MemberRevoke {
                v,
                member,
                operation,
                selector,
            } => f
                .debug_struct("MemberRevoke")
                .field("v", v)
                .field("member", member)
                .field("operation", operation)
                .field("selector", selector)
                .finish(),
            AdminOpBody::MemberList { v } => f.debug_struct("MemberList").field("v", v).finish(),
        }
    }
}

impl AdminOpBody {
    /// The schema version this op declares.
    pub fn schema_version(&self) -> u32 {
        match self {
            AdminOpBody::Store { v, .. }
            | AdminOpBody::GatewayCreate { v, .. }
            | AdminOpBody::ProviderSet { v, .. }
            | AdminOpBody::ProviderRemove { v, .. }
            | AdminOpBody::OperatorSign { v, .. }
            | AdminOpBody::ManifestImport { v, .. }
            | AdminOpBody::ManifestSign { v, .. }
            | AdminOpBody::ManifestExport { v, .. }
            | AdminOpBody::ManifestList { v }
            | AdminOpBody::ManifestRetireMachine { v, .. }
            | AdminOpBody::ManifestOneTapSet { v, .. }
            | AdminOpBody::ManifestOneTapStatus { v }
            | AdminOpBody::StoreWithIdentityPolicy { v, .. }
            | AdminOpBody::SetIdentity { v, .. }
            | AdminOpBody::Invalidate { v, .. }
            | AdminOpBody::Logout { v, .. }
            | AdminOpBody::Reactivate { v, .. }
            | AdminOpBody::Remove { v, .. }
            | AdminOpBody::MintHandle { v, .. }
            | AdminOpBody::RevokeHandle { v, .. }
            | AdminOpBody::RevokeHandleByHash { v, .. }
            | AdminOpBody::RevokeAllHandles { v, .. }
            | AdminOpBody::GrantCreate { v, .. }
            | AdminOpBody::GrantRevoke { v, .. }
            | AdminOpBody::GrantCreateV2 { v, .. }
            | AdminOpBody::GrantRevokeV2 { v, .. }
            | AdminOpBody::SetCategory { v, .. }
            | AdminOpBody::SetProviders { v, .. }
            | AdminOpBody::SetPlan { v, .. }
            | AdminOpBody::Reclassify { v, .. }
            | AdminOpBody::Approval { v, .. }
            | AdminOpBody::EnrollApprove { v, .. }
            | AdminOpBody::EnrollLabel { v, .. }
            | AdminOpBody::EnrollDeny { v, .. }
            | AdminOpBody::EnrollRevoke { v, .. }
            | AdminOpBody::EnrollReissue { v, .. }
            | AdminOpBody::FederationGateSet { v, .. }
            | AdminOpBody::SecretPhoneGateSet { v, .. }
            | AdminOpBody::SecretMultiHostSet { v, .. }
            | AdminOpBody::SecretPut { v, .. }
            | AdminOpBody::SecretDelete { v, .. }
            | AdminOpBody::SecretRevokeGrant { v, .. }
            | AdminOpBody::SecretHomeSet { v, .. }
            | AdminOpBody::FederationSelfSet { v, .. }
            | AdminOpBody::TransferInit { v, .. }
            | AdminOpBody::TransferRecover { v }
            | AdminOpBody::TransferSend { v, .. }
            | AdminOpBody::TransferResume { v, .. }
            | AdminOpBody::TransferReceive { v }
            | AdminOpBody::TransferAccept { v, .. }
            | AdminOpBody::TransferReject { v, .. }
            | AdminOpBody::RemoteAdd { v, .. }
            | AdminOpBody::RemoteRemove { v, .. }
            | AdminOpBody::RemoteList { v }
            | AdminOpBody::MemberGrant { v, .. }
            | AdminOpBody::MemberRevoke { v, .. }
            | AdminOpBody::MemberList { v }
            | AdminOpBody::Status { v } => *v,
        }
    }

    /// Minimum version for this body. ProviderSet also admits v3 with no new keys,
    /// which clears the descriptor rather than preserving it as a legacy v2 set does.
    pub const fn required_schema_version(&self) -> u32 {
        match self {
            AdminOpBody::ProviderSet {
                hosts,
                auth_header,
                auth_scheme,
                fusiform_provider_id,
                ..
            } => {
                if hosts.is_some()
                    || auth_header.is_some()
                    || auth_scheme.is_some()
                    || fusiform_provider_id.is_some()
                {
                    ADMIN_OP_SCHEMA_V3
                } else {
                    ADMIN_OP_SCHEMA_V2
                }
            }
            AdminOpBody::ManifestImport { .. }
            | AdminOpBody::ManifestSign { .. }
            | AdminOpBody::ManifestExport { .. }
            | AdminOpBody::ManifestList { .. }
            | AdminOpBody::ManifestRetireMachine { .. }
            | AdminOpBody::ManifestOneTapSet { .. }
            | AdminOpBody::ManifestOneTapStatus { .. }
            | AdminOpBody::GrantCreateV2 { .. }
            | AdminOpBody::GatewayCreate { .. }
            | AdminOpBody::ProviderRemove { .. }
            | AdminOpBody::GrantRevokeV2 { .. }
            | AdminOpBody::SetCategory { .. }
            | AdminOpBody::SetProviders { .. }
            | AdminOpBody::SetPlan { .. }
            | AdminOpBody::Reclassify { .. }
            | AdminOpBody::EnrollApprove { .. }
            | AdminOpBody::EnrollLabel { .. }
            | AdminOpBody::EnrollDeny { .. }
            | AdminOpBody::EnrollRevoke { .. }
            | AdminOpBody::EnrollReissue { .. }
            | AdminOpBody::FederationGateSet { .. }
            | AdminOpBody::SecretPhoneGateSet { .. }
            | AdminOpBody::SecretMultiHostSet { .. }
            | AdminOpBody::SecretPut { .. }
            | AdminOpBody::SecretDelete { .. }
            | AdminOpBody::SecretRevokeGrant { .. }
            | AdminOpBody::SecretHomeSet { .. }
            | AdminOpBody::FederationSelfSet { .. }
            | AdminOpBody::TransferInit { .. }
            | AdminOpBody::TransferRecover { .. }
            | AdminOpBody::TransferSend { .. }
            | AdminOpBody::TransferResume { .. }
            | AdminOpBody::TransferReceive { .. }
            | AdminOpBody::TransferAccept { .. }
            | AdminOpBody::TransferReject { .. }
            | AdminOpBody::RemoteAdd { .. }
            | AdminOpBody::RemoteRemove { .. }
            | AdminOpBody::RemoteList { .. }
            | AdminOpBody::MemberGrant { .. }
            | AdminOpBody::MemberRevoke { .. }
            | AdminOpBody::MemberList { .. } => ADMIN_OP_SCHEMA_V2,
            AdminOpBody::Store { .. }
            | AdminOpBody::OperatorSign { .. }
            | AdminOpBody::StoreWithIdentityPolicy { .. }
            | AdminOpBody::SetIdentity { .. }
            | AdminOpBody::Invalidate { .. }
            | AdminOpBody::Logout { .. }
            | AdminOpBody::Reactivate { .. }
            | AdminOpBody::Remove { .. }
            | AdminOpBody::MintHandle { .. }
            | AdminOpBody::RevokeHandle { .. }
            | AdminOpBody::RevokeHandleByHash { .. }
            | AdminOpBody::RevokeAllHandles { .. }
            | AdminOpBody::GrantCreate { .. }
            | AdminOpBody::GrantRevoke { .. }
            | AdminOpBody::Approval { .. }
            | AdminOpBody::Status { .. } => ADMIN_OP_SCHEMA_V1,
        }
    }

    pub fn has_valid_schema_version(&self) -> bool {
        if matches!(self, AdminOpBody::ProviderSet { .. }) {
            return self.schema_version() == ADMIN_OP_SCHEMA_V3
                || (self.schema_version() == ADMIN_OP_SCHEMA_V2
                    && self.required_schema_version() == ADMIN_OP_SCHEMA_V2);
        }
        self.schema_version() == self.required_schema_version()
    }

    /// The credential id this op serializes against, for per-credential single-flight
    /// locking. `None` for `revoke_handle` (addressed by handle, not credential id),
    /// which therefore takes no per-id lock.
    pub fn lock_id(&self) -> Option<&str> {
        match self {
            // An approval takes the signing credential's lock: it is the record whose
            // window is about to open, so an approval racing an admin mutation of that
            // same key should serialize rather than interleave.
            AdminOpBody::Approval {
                credential_id: id, ..
            }
            | AdminOpBody::Store { id, .. }
            | AdminOpBody::GatewayCreate { id, .. }
            | AdminOpBody::OperatorSign { id, .. }
            | AdminOpBody::StoreWithIdentityPolicy { id, .. }
            | AdminOpBody::SetIdentity { id, .. }
            | AdminOpBody::Invalidate { id, .. }
            | AdminOpBody::Logout { id, .. }
            | AdminOpBody::Reactivate { id, .. }
            | AdminOpBody::Remove { id, .. }
            | AdminOpBody::MintHandle { id, .. }
            | AdminOpBody::RevokeAllHandles { id, .. }
            | AdminOpBody::SetCategory {
                credential_id: id, ..
            }
            | AdminOpBody::SetPlan { credential_id: id, .. }
            | AdminOpBody::SetProviders {
                credential_id: id, ..
            }
            // A send serializes against other admin writes to the record it seals, and
            // a remote add or remove against other writes to the id it claims.
            | AdminOpBody::TransferSend {
                credential_id: id, ..
            }
            | AdminOpBody::RemoteAdd {
                credential_id: id, ..
            }
            | AdminOpBody::RemoteRemove {
                credential_id: id, ..
            } => Some(id),
            // Creating or replacing the transfer key writes that one record.
            AdminOpBody::TransferInit { .. } | AdminOpBody::TransferRecover { .. } => {
                Some(crate::federation::VAULT_TRANSFER_ID)
            }
            AdminOpBody::ManifestSign { .. } | AdminOpBody::ManifestImport { .. } => {
                Some(crate::store::GH_MANIFEST_ROOT_KEY_ID)
            }
            AdminOpBody::RevokeHandle { .. }
            | AdminOpBody::ManifestExport { .. }
            | AdminOpBody::ManifestList { .. }
            | AdminOpBody::ManifestRetireMachine { .. }
            | AdminOpBody::ManifestOneTapSet { .. }
            | AdminOpBody::ManifestOneTapStatus { .. }
            | AdminOpBody::ProviderSet { .. }
            | AdminOpBody::ProviderRemove { .. }
            | AdminOpBody::RevokeHandleByHash { .. }
            | AdminOpBody::GrantCreate { .. }
            | AdminOpBody::GrantRevoke { .. }
            | AdminOpBody::GrantCreateV2 { .. }
            | AdminOpBody::GrantRevokeV2 { .. }
            | AdminOpBody::Reclassify { .. }
            // Enrollment ops take NO per-credential lock: they mutate the consumer
            // ledger, not any credential's record, so there is no id to serialize on.
            // The store's fenced write is what orders them against each other.
            | AdminOpBody::EnrollApprove { .. }
            | AdminOpBody::EnrollLabel { .. }
            | AdminOpBody::EnrollDeny { .. }
            | AdminOpBody::EnrollRevoke { .. }
            | AdminOpBody::EnrollReissue { .. }
            // Federation settings belong to no credential; the fenced write orders them.
            // Federation settings belong to no credential; the fenced write orders them.
            // Agent secrets do not live in the `credentials` table at all, so the three
            // value ops have no credential id to serialize on either: the fenced write
            // orders them against each other and against the phone path's transactions.
            | AdminOpBody::FederationGateSet { .. }
            | AdminOpBody::SecretPhoneGateSet { .. }
            | AdminOpBody::SecretMultiHostSet { .. }
            | AdminOpBody::SecretPut { .. }
            | AdminOpBody::SecretDelete { .. }
            | AdminOpBody::SecretRevokeGrant { .. }
            | AdminOpBody::SecretHomeSet { .. }
            | AdminOpBody::FederationSelfSet { .. }
            // A resume, receive, reject, list or member grant writes no credential
            // record. An accept's record id is known only from its stored pending row,
            // so the daemon's federation path takes that lock itself.
            | AdminOpBody::TransferResume { .. }
            | AdminOpBody::TransferReceive { .. }
            | AdminOpBody::TransferAccept { .. }
            | AdminOpBody::TransferReject { .. }
            | AdminOpBody::RemoteList { .. }
            | AdminOpBody::MemberGrant { .. }
            | AdminOpBody::MemberRevoke { .. }
            | AdminOpBody::MemberList { .. }
            | AdminOpBody::Status { .. } => None,
        }
    }

    /// Serialize to the exact bytes the caller MACs and the module verifies. The
    /// caller sends THESE bytes verbatim; the module verifies THESE bytes before
    /// decoding — so serialization non-canonicality is irrelevant (the bytes are
    /// the contract, not a re-derived form).
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// The variant's own discriminators, for diagnostics (`Store` reports which op it
    /// refused without nesting the whole body).
    pub fn op_name(&self) -> &'static str {
        match self {
            AdminOpBody::OperatorSign { .. } => "admin.operator_sign",
            AdminOpBody::ManifestImport { .. } => "admin.manifest_import",
            AdminOpBody::ManifestSign { .. } => "admin.manifest_sign",
            AdminOpBody::ManifestExport { .. } => "admin.manifest_export",
            AdminOpBody::ManifestList { .. } => "admin.manifest_list",
            AdminOpBody::ManifestRetireMachine { .. } => "admin.manifest_retire_machine",
            AdminOpBody::ManifestOneTapSet { .. } => "admin.manifest_one_tap_set",
            AdminOpBody::ManifestOneTapStatus { .. } => "admin.manifest_one_tap_status",
            AdminOpBody::ProviderSet { .. } => "admin.provider_set",
            AdminOpBody::ProviderRemove { .. } => "admin.provider_remove",
            AdminOpBody::Store { .. } => "admin.store",
            AdminOpBody::GatewayCreate { .. } => "admin.gateway_create",
            AdminOpBody::StoreWithIdentityPolicy { .. } => "admin.store_with_identity_policy",
            AdminOpBody::SetIdentity { .. } => "admin.set_identity",
            AdminOpBody::Invalidate { .. } => "admin.invalidate",
            AdminOpBody::Logout { .. } => "admin.logout",
            AdminOpBody::Reactivate { .. } => "admin.reactivate",
            AdminOpBody::Remove { .. } => "admin.remove",
            AdminOpBody::MintHandle { .. } => "admin.mint_handle",
            AdminOpBody::RevokeHandle { .. } => "admin.revoke_handle",
            AdminOpBody::RevokeHandleByHash { .. } => "admin.revoke_handle_by_hash",
            AdminOpBody::RevokeAllHandles { .. } => "admin.revoke_all_handles",
            AdminOpBody::GrantCreate { .. } => "admin.grant_create",
            AdminOpBody::GrantRevoke { .. } => "admin.grant_revoke",
            AdminOpBody::GrantCreateV2 { .. } => "admin.grant_create_v2",
            AdminOpBody::GrantRevokeV2 { .. } => "admin.grant_revoke_v2",
            AdminOpBody::EnrollApprove { .. } => "admin.enroll_approve",
            AdminOpBody::EnrollLabel { .. } => "admin.enroll_label",
            AdminOpBody::EnrollDeny { .. } => "admin.enroll_deny",
            AdminOpBody::EnrollRevoke { .. } => "admin.enroll_revoke",
            AdminOpBody::EnrollReissue { .. } => "admin.enroll_reissue",
            AdminOpBody::SetCategory { .. } => "admin.set_category",
            AdminOpBody::SetProviders { .. } => "admin.set_providers",
            AdminOpBody::SetPlan { .. } => "admin.set_plan",
            AdminOpBody::Reclassify { .. } => "admin.reclassify",
            AdminOpBody::Approval { .. } => "admin.approval",
            AdminOpBody::Status { .. } => "admin.status",
            AdminOpBody::FederationGateSet { .. } => "admin.federation_gate_set",
            AdminOpBody::SecretPhoneGateSet { .. } => "admin.secret_phone_gate_set",
            AdminOpBody::SecretMultiHostSet { .. } => "admin.secret_multi_host_set",
            AdminOpBody::SecretPut { .. } => "admin.secret_put",
            AdminOpBody::SecretDelete { .. } => "admin.secret_delete",
            AdminOpBody::SecretRevokeGrant { .. } => "admin.secret_revoke_grant",
            AdminOpBody::SecretHomeSet { .. } => "admin.secret_home_set",
            AdminOpBody::FederationSelfSet { .. } => "admin.federation_self_set",
            AdminOpBody::TransferInit { .. } => "admin.transfer_init",
            AdminOpBody::TransferRecover { .. } => "admin.transfer_recover",
            AdminOpBody::TransferSend { .. } => "admin.transfer_send",
            AdminOpBody::TransferResume { .. } => "admin.transfer_resume",
            AdminOpBody::TransferReceive { .. } => "admin.transfer_receive",
            AdminOpBody::TransferAccept { .. } => "admin.transfer_accept",
            AdminOpBody::TransferReject { .. } => "admin.transfer_reject",
            AdminOpBody::RemoteAdd { .. } => "admin.remote_add",
            AdminOpBody::RemoteRemove { .. } => "admin.remote_remove",
            AdminOpBody::RemoteList { .. } => "admin.remote_list",
            AdminOpBody::MemberGrant { .. } => "admin.member_grant",
            AdminOpBody::MemberRevoke { .. } => "admin.member_revoke",
            AdminOpBody::MemberList { .. } => "admin.member_list",
        }
    }

    /// Whether this op needs the running daemon because it awaits an outbound call
    /// (a peer key lookup, a home fetch, a delivery). Such an op is refused by
    /// [`apply`] with `federation_requires_daemon` before any write, so the offline
    /// lease path cannot run it.
    ///
    /// The exhaustive match is the forcing function: a new federation op has to say
    /// here whether `apply` may run it, rather than defaulting to a synchronous
    /// half-implementation.
    pub const fn requires_daemon(&self) -> bool {
        match self {
            AdminOpBody::Store { .. }
            | AdminOpBody::GatewayCreate { .. }
            | AdminOpBody::ProviderSet { .. }
            | AdminOpBody::ProviderRemove { .. }
            | AdminOpBody::OperatorSign { .. }
            | AdminOpBody::ManifestImport { .. }
            | AdminOpBody::ManifestSign { .. }
            | AdminOpBody::ManifestExport { .. }
            | AdminOpBody::ManifestList { .. }
            | AdminOpBody::ManifestRetireMachine { .. }
            | AdminOpBody::ManifestOneTapSet { .. }
            | AdminOpBody::ManifestOneTapStatus { .. }
            | AdminOpBody::StoreWithIdentityPolicy { .. }
            | AdminOpBody::SetIdentity { .. }
            | AdminOpBody::Invalidate { .. }
            | AdminOpBody::Logout { .. }
            | AdminOpBody::Reactivate { .. }
            | AdminOpBody::Remove { .. }
            | AdminOpBody::MintHandle { .. }
            | AdminOpBody::RevokeHandle { .. }
            | AdminOpBody::RevokeHandleByHash { .. }
            | AdminOpBody::RevokeAllHandles { .. }
            | AdminOpBody::GrantCreate { .. }
            | AdminOpBody::GrantRevoke { .. }
            | AdminOpBody::GrantCreateV2 { .. }
            | AdminOpBody::GrantRevokeV2 { .. }
            | AdminOpBody::EnrollApprove { .. }
            | AdminOpBody::EnrollLabel { .. }
            | AdminOpBody::EnrollDeny { .. }
            | AdminOpBody::EnrollRevoke { .. }
            | AdminOpBody::EnrollReissue { .. }
            | AdminOpBody::SetCategory { .. }
            | AdminOpBody::SetProviders { .. }
            | AdminOpBody::SetPlan { .. }
            | AdminOpBody::Reclassify { .. }
            | AdminOpBody::Approval { .. }
            | AdminOpBody::Status { .. }
            // The gate is a store setting: a pure local write, run through `apply`
            // from the offline lease path too. The secret value ops are local too; only
            // the phone channel reaches callosum, and these three never do, which is what
            // lets an operator put and delete secrets with the daemon stopped.
            | AdminOpBody::FederationGateSet { .. }
            | AdminOpBody::SecretPhoneGateSet { .. }
            | AdminOpBody::SecretMultiHostSet { .. }
            | AdminOpBody::SecretPut { .. }
            | AdminOpBody::SecretDelete { .. }
            | AdminOpBody::SecretRevokeGrant { .. }
            // Setting the secret home to this vault, or clearing it, is a local write.
            | AdminOpBody::SecretHomeSet {
                home: SecretHomeTarget::ThisVault | SecretHomeTarget::Unset,
                ..
            }
            // Local reads and writes with no outbound call.
            | AdminOpBody::TransferRecover { .. }
            | AdminOpBody::TransferReceive { .. }
            | AdminOpBody::TransferReject { .. }
            | AdminOpBody::RemoteRemove { .. }
            | AdminOpBody::RemoteList { .. }
            | AdminOpBody::MemberRevoke { .. }
            | AdminOpBody::MemberList { .. } => false,
            // The self id is checked against the member id callosum computes for this
            // computer; a send and an accept look up a peer's announced key, a send and
            // a resume deliver, a remote add fetches from the home, and a member grant
            // reads the member's current pairing id, as does naming another member's
            // vault as the secret home.
            AdminOpBody::FederationSelfSet { .. }
            | AdminOpBody::SecretHomeSet {
                home: SecretHomeTarget::Member(_),
                ..
            }
            | AdminOpBody::TransferInit { .. }
            | AdminOpBody::TransferSend { .. }
            | AdminOpBody::TransferResume { .. }
            | AdminOpBody::TransferAccept { .. }
            | AdminOpBody::RemoteAdd { .. }
            | AdminOpBody::MemberGrant { .. } => true,
        }
    }
}

/// Where `admin.secret_home_set` points `secrets.home_member`. On the wire it is the
/// `home` field: `"self"`, a member id, or `null` to clear the setting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Option<String>", into = "Option<String>")]
pub enum SecretHomeTarget {
    /// Clear the setting: this vault serves its own secrets, as a single computer does.
    Unset,
    /// This vault is the home. Stored as the literal `self`.
    ThisVault,
    /// Another member's vault is the home (or this one, when the id equals the self id).
    Member(String),
}

impl From<Option<String>> for SecretHomeTarget {
    fn from(value: Option<String>) -> Self {
        match value.as_deref() {
            None => SecretHomeTarget::Unset,
            Some(crate::store::SECRET_HOME_SELF) => SecretHomeTarget::ThisVault,
            Some(_) => SecretHomeTarget::Member(value.expect("matched Some")),
        }
    }
}

impl From<SecretHomeTarget> for Option<String> {
    fn from(value: SecretHomeTarget) -> Self {
        match value {
            SecretHomeTarget::Unset => None,
            SecretHomeTarget::ThisVault => Some(crate::store::SECRET_HOME_SELF.to_owned()),
            SecretHomeTarget::Member(member) => Some(member),
        }
    }
}

/// The audit op an `admin.store` records: login, import, or put/overwrite. A closed
/// set so a caller cannot inject an arbitrary audit label.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditOp {
    Login,
    Import,
    Put,
    Overwrite,
}

impl AdminAuditOp {
    pub fn to_audit_op(self) -> AuditOp {
        match self {
            AdminAuditOp::Login => AuditOp::Login,
            AdminAuditOp::Import => AuditOp::Import,
            AdminAuditOp::Put => AuditOp::Put,
            AdminAuditOp::Overwrite => AuditOp::Overwrite,
        }
    }
}

/// Apply an admin op to the store, auditing under `actor`. This is the ONE place
/// the mutation is applied — the running module calls it under the engine's
/// per-credential single-flight lock; the offline CLI calls it directly against the
/// leased store. Sharing it means the online and offline admin paths can never drift
/// in what a given op actually does. Returns a small non-secret JSON result (e.g. a
/// freshly minted handle, or a revoked count).
///
/// The schema version is validated by the caller (the module refuses an unknown
/// version before dispatch); this function assumes a v1 body.
pub fn apply(
    store: &EncryptedStore,
    op: AdminOpBody,
    actor: &str,
) -> Result<serde_json::Value, StoreOpError> {
    if !op.has_valid_schema_version() {
        return Err(StoreOpError::Encode(format!(
            "unsupported admin op schema version/variant pairing {}",
            op.schema_version()
        )));
    }
    // The federation ops that need an awaited outbound call (a peer key lookup, a home
    // fetch, a delivery) cannot run here: `apply` is synchronous and runs wherever a
    // caller holds the write lease, including the offline CLI. They are dispatched by
    // the daemon's federation path instead, and this refusal sits before any match arm
    // that could write, so the offline path can never run one half-way.
    if op.requires_daemon() {
        return Err(requires_daemon_refusal(&op));
    }
    match op {
        AdminOpBody::ManifestImport { envelope, .. } => {
            store.import_gh_manifest_admin(&envelope, actor)
        }
        AdminOpBody::ManifestSign {
            manifest_bytes,
            approver,
            ..
        } => store.sign_gh_manifest_admin(&manifest_bytes, &approver, actor),
        AdminOpBody::ManifestExport { version, .. } => {
            let envelope = store.export_gh_manifest_admin(version)?;
            serde_json::to_value(envelope).map_err(|e| StoreOpError::Encode(e.to_string()))
        }
        AdminOpBody::ManifestList { .. } => store.list_gh_manifests_admin(),
        AdminOpBody::ManifestRetireMachine { member_id, .. } => {
            crate::federation::check_member_id(&member_id)?;
            store.retire_gh_manifest_member(
                &member_id,
                wall_now_ms(),
                AuditCtx::route_admin(AuditOp::GhManifestRetire, actor),
            )?;
            Ok(serde_json::json!({"retired": true, "member_id": member_id}))
        }
        AdminOpBody::ManifestOneTapSet { enabled, .. } => {
            let changed = store.set_manifest_one_tap_audited(
                enabled,
                AuditCtx::route_admin(AuditOp::GhManifestOneTapSet, actor),
            )?;
            Ok(serde_json::json!({"one_tap": enabled, "changed": changed}))
        }
        AdminOpBody::ManifestOneTapStatus { .. } => {
            Ok(serde_json::json!({"one_tap": store.manifest_one_tap_status()}))
        }
        AdminOpBody::ProviderSet {
            v,
            service,
            categories,
            provider_ids,
            hosts,
            auth_header,
            auth_scheme,
            fusiform_provider_id,
        } => {
            let settings = if v == ADMIN_OP_SCHEMA_V3 {
                let hosts = hosts
                    .filter(|value| !value.is_null())
                    .unwrap_or_else(|| serde_json::json!([]));
                let value = serde_json::json!({"hosts": hosts, "auth_header": auth_header,
                    "auth_scheme": auth_scheme, "fusiform_provider_id": fusiform_provider_id});
                Some(
                    serde_json::from_value::<crate::store::RegisteredProviderSettings>(
                        value.clone(),
                    )
                    .map_err(|error| {
                        StoreOpError::Encode(format!("invalid provider settings {value}: {error}"))
                    })?,
                )
            } else {
                None
            };
            let changed = store.set_registered_provider_settings_audited(
                &service,
                &categories,
                &provider_ids,
                settings.as_ref(),
                AuditCtx::route_admin(AuditOp::ProviderSet, actor),
            )?;
            Ok(serde_json::json!({"changed": changed}))
        }
        AdminOpBody::ProviderRemove { service, .. } => {
            let changed = store.remove_registered_provider_audited(
                &service,
                AuditCtx::route_admin(AuditOp::ProviderRemove, actor),
            )?;
            Ok(serde_json::json!({"changed": changed}))
        }
        AdminOpBody::OperatorSign {
            id, payload_b64, ..
        } => {
            let refusal = || StoreOpError::Encode("key is not marked for operator signing".into());
            let snapshot = match store.get_with_stale_pending_and_digest(&id) {
                Ok(record) => record,
                Err(StoreOpError::NotFound) => return Err(refusal()),
                Err(e) => return Err(e),
            };
            let record = snapshot.record;
            if record.kind != CredentialKind::SigningKey || !record.operator_sign {
                return Err(refusal());
            }
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&payload_b64)
                .map_err(|_| StoreOpError::Encode("payload is not valid base64".into()))?;
            if payload.len() > MAX_OPERATOR_SIGN_PAYLOAD {
                return Err(StoreOpError::Encode(
                    "payload exceeds the 64 KiB operator signing cap".into(),
                ));
            }
            let corrupt = || StoreOpError::Corrupt("unusable signing key".into());
            let pem = std::str::from_utf8(record.payload.expose()).map_err(|_| corrupt())?;
            let prepared = crate::signing::prepare_ed25519(pem, &payload).map_err(|e| match e {
                crate::signing::SignError::TooLarge { .. } => StoreOpError::Encode(e.to_string()),
                crate::signing::SignError::UnusableKey(_) => corrupt(),
            })?;
            let public = crate::signing::public_key_ed25519(pem).map_err(|_| corrupt())?;
            // Operator permission always requires durable history, even if a record
            // was stored without the separate bus-signature audit opt-in.
            store.append_signature_audit(
                &id,
                (record.record_version, &snapshot.incarnation),
                &payload,
                actor,
            )?;
            let signature = prepared.sign();
            let signature_bytes = base64::engine::general_purpose::STANDARD
                .decode(&signature.signature_b64)
                .expect("signing produces valid base64");
            let signature_hex: String =
                signature_bytes.iter().map(|b| format!("{b:02x}")).collect();
            Ok(serde_json::json!({
                "key_id": signature.key_id,
                "public_key_hex": public.public_key_hex,
                "signature_hex": signature_hex,
            }))
        }
        AdminOpBody::EnrollApprove {
            request_id,
            final_name,
            keep_grants,
            display_name,
            grant_requested,
            ..
        } => {
            let (enrollment_id, display_name) = store.approve_enrollment_with_requested_grants(
                &request_id,
                &final_name,
                keep_grants,
                display_name.as_deref(),
                grant_requested,
                actor,
            )?;
            // The token is deliberately absent: approval admits a NAME, and only the
            // consumer's own poll -- authenticated by the request secret it minted --
            // turns that into bearer material.
            let mut reply = serde_json::json!({
                "enrollment_id": enrollment_id,
                "name": final_name,
            });
            if let Some(name) = display_name {
                reply["display_name"] = serde_json::json!(name);
            }
            Ok(reply)
        }
        AdminOpBody::EnrollLabel {
            name, display_name, ..
        } => {
            let changed = store.label_enrollment(&name, display_name.as_deref(), actor)?;
            Ok(serde_json::json!({
                "name": name,
                "display_name": display_name.map(|label| label.trim().to_string()),
                "changed": changed,
            }))
        }
        AdminOpBody::EnrollDeny { request_id, .. } => {
            store.deny_enrollment(&request_id, actor)?;
            Ok(serde_json::json!({ "denied": true }))
        }
        AdminOpBody::EnrollRevoke { name, .. } => {
            let removed_grants: Vec<serde_json::Value> = store
                .revoke_enrollment(&name, actor)?
                .iter()
                .map(|grant| {
                    serde_json::json!({
                        "principal_kind": grant.principal_kind,
                        "principal_id": grant.principal_id,
                        "selector_kind": grant.selector_kind.as_str(),
                        "credential_prefix": grant.selector,
                        "operation": grant.operation.as_str(),
                        "created_at_ms": grant.created_at_ms,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "revoked": true, "removed_grants": removed_grants }))
        }
        AdminOpBody::EnrollReissue { name, .. } => {
            let rotation = store.reissue_enrollment(&name, actor)?;
            // THE ONE ADMIN REPLY THAT CARRIES BEARER MATERIAL. The generation rides
            // beside it so the operator can tell the consumer which incarnation they
            // now hold, and so a forensic reader can date a spend to one side of the
            // rotation rather than seeing one undifferentiated name.
            Ok(serde_json::json!({
                "token": rotation.token,
                "token_generation": rotation.token_generation,
            }))
        }
        AdminOpBody::Approval {
            credential_id,
            artifact_sha256,
            approver,
            ..
        } => {
            if artifact_sha256.len() != 64
                || !artifact_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(StoreOpError::Encode(
                    "artifact_sha256 must be exactly 64 lowercase hex characters".into(),
                ));
            }
            if store.get(&credential_id)?.kind != CredentialKind::SigningKey {
                return Err(StoreOpError::Encode(
                    "approval requires a signing key".into(),
                ));
            }
            // Keep the authenticated origin and namespace the human label so it cannot
            // impersonate a vault-owned actor. The hash remains the artifact commitment.
            let ctx = AuditCtx::route_admin(AuditOp::Approval, actor);
            store.append_audit(&AuditRecord {
                op: ctx.op,
                credential_id: Some(credential_id.clone()),
                payload_hash: Some(artifact_sha256.clone()),
                actor: format!("{}/approver:{}", ctx.actor, approver),
                alarm: ctx.alarm,
            })?;
            Ok(serde_json::json!({
                "approved": artifact_sha256,
                "credential_id": credential_id,
                "approver": approver,
            }))
        }
        AdminOpBody::GatewayCreate {
            id,
            record,
            audit_op,
            base_url,
            auth_header,
            auth_scheme,
            headers,
            provider_ids,
            ..
        } => {
            let settings = crate::gateway::GatewaySettings {
                base_url,
                auth: crate::gateway::GatewayAuth {
                    header: auth_header,
                    scheme: auth_scheme,
                },
                headers,
            };
            store.gateway_create_audited(
                &id,
                &record,
                &settings,
                &provider_ids,
                AuditCtx::route_admin(audit_op.to_audit_op(), actor),
            )?;
            Ok(serde_json::json!({ "stored": true }))
        }
        AdminOpBody::Store {
            id,
            record,
            audit_op,
            mode,
            ..
        } => {
            crate::store::validate_deposit_credential_id(&id)?;
            let ctx = AuditCtx::route_admin(audit_op.to_audit_op(), actor);
            match mode {
                StoreMode::Create => store.create_audited(&id, &record, ctx)?,
                StoreMode::ReplaceUnconditional => {
                    store.overwrite_unconditional_audited(&id, &record, ctx)?
                }
                StoreMode::ReplaceCas { expected_hash_hex } => {
                    let expected = decode_hash32(&expected_hash_hex)
                        .ok_or_else(|| StoreOpError::Encode("bad expected hash hex".into()))?;
                    store.overwrite_cas_audited(&id, &record, &expected, ctx)?
                }
            }
            Ok(serde_json::json!({ "stored": true }))
        }
        AdminOpBody::StoreWithIdentityPolicy {
            id,
            record,
            audit_op,
            clear_identity,
            ..
        } => {
            crate::store::validate_deposit_credential_id(&id)?;
            store.overwrite_unconditional_with_identity_policy_audited(
                &id,
                &record,
                !clear_identity,
                AuditCtx::route_admin(audit_op.to_audit_op(), actor),
            )?;
            Ok(serde_json::json!({ "stored": true }))
        }
        AdminOpBody::SetIdentity { id, identity, .. } => {
            store.set_identity_audited(
                &id,
                identity,
                AuditCtx::route_admin(AuditOp::SetIdentity, actor),
            )?;
            Ok(serde_json::json!({ "identity_updated": true }))
        }
        AdminOpBody::Invalidate { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Invalidate, actor);
            let outcome = store.invalidate_and_revoke_all_audited(&id, ctx)?;
            // `state_changed` rides the wire so the CLI can tell an operator whether
            // this call did anything. `handles_revoked` alone cannot: a credential
            // with no handles reports zero whether it was live or already dead.
            Ok(serde_json::json!({
                "handles_revoked": outcome.handles_revoked,
                "state_changed": outcome.state_changed,
                "intent_cleared": outcome.intent_cleared,
            }))
        }
        AdminOpBody::Logout { id, .. } => {
            // Keep the established `invalidate` audit label. Historic rows are
            // intentionally not reclassified, and the current lifecycle state carries
            // the operator's retirement intent without changing that chain vocabulary.
            let ctx = AuditCtx::route_admin(AuditOp::Invalidate, actor);
            let outcome = store.retire_and_revoke_all_audited(&id, ctx)?;
            Ok(serde_json::json!({
                "handles_revoked": outcome.handles_revoked,
                "state_changed": outcome.state_changed,
                "intent_cleared": outcome.intent_cleared,
            }))
        }
        AdminOpBody::Reactivate { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Reactivate, actor);
            let state_changed = store.reactivate_audited(&id, ctx)?;
            // `state_changed` rides the wire for the same reason it does on invalidate:
            // without it, a no-op (already active, or corrupt and refused) is
            // indistinguishable from a real repair, and an operator would read success
            // as "the credential is back" when nothing happened.
            Ok(serde_json::json!({ "state_changed": state_changed }))
        }
        AdminOpBody::Remove { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Remove, actor);
            let handles_deleted = store.remove_audited(&id, ctx)?;
            // The count rides the wire so the CLI can tell an operator that live
            // capability handles just stopped resolving. Handles are bearer tokens
            // with no record of who holds them, so this is the only warning
            // available and it is only useful at the moment of the removal.
            Ok(serde_json::json!({
                "removed": true,
                "handles_deleted": handles_deleted,
            }))
        }
        AdminOpBody::MintHandle { id, .. } => {
            // A remote record has no local material for a handle to reach: its token is
            // fetched from its home on each read. Named, so the operator is not told the
            // id they can see in `remote list` does not exist.
            if store.remote_record(&id)?.is_some() {
                return Err(StoreOpError::Encode(format!(
                    "{REMOTE_RECORD_CODE}: {id} is a remote record served by its home vault; \
                     a capability handle cannot be minted for it"
                )));
            }
            // The credential must exist before a handle is minted for it (the handles
            // table has no FK, so this guard is the check). meta() is a no-decrypt
            // plaintext read, so it works on any lifecycle state.
            store.meta(&id)?;
            let handle = mint_handle().map_err(|e| StoreOpError::Encode(format!("csprng: {e}")))?;
            let ctx = AuditCtx::route_admin(AuditOp::MintHandle, actor);
            store.put_handle_hash(&handle.hash, &id, ctx)?;
            // The raw handle is returned ONCE here; only its hash is persisted.
            Ok(serde_json::json!({ "handle": handle.raw }))
        }
        AdminOpBody::RevokeHandle { handle, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            // `revoked` stays for wire compatibility; `credential_id` is the new fact and
            // is null when nothing matched, which is the case an operator needs to see.
            let owner = store.revoke_handle(&handle, ctx)?;
            Ok(serde_json::json!({
                "revoked": owner.is_some(),
                "credential_id": owner,
            }))
        }
        AdminOpBody::RevokeHandleByHash { handle_hash, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            let owner = store.revoke_handle_by_hash_audited(&handle_hash, ctx)?;
            Ok(serde_json::json!({
                "revoked": owner.is_some(),
                "credential_id": owner,
            }))
        }
        AdminOpBody::RevokeAllHandles { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            let n = store.revoke_all_handles(&id, ctx)?;
            Ok(serde_json::json!({ "handles_revoked": n }))
        }
        AdminOpBody::GrantCreate { .. } | AdminOpBody::GrantRevoke { .. } => {
            Err(StoreOpError::Encode(
                "prefix grants were removed; use v2 exact or category grants".into(),
            ))
        }
        AdminOpBody::GrantCreateV2 {
            principal_kind,
            principal_id,
            selector_kind,
            selector,
            operation,
            ..
        } => {
            if selector_kind == SelectorKind::Category
                && !crate::catalog::valid_category_name(&selector)
            {
                return Err(StoreOpError::InvalidCategoryName);
            }
            // The transfer key's fence answers here, before the store's identical check,
            // so a grant on it is refused with `transfer_key_reserved` rather than a
            // generic write error, and the `already_granted` shortcut below can never
            // swallow it.
            if selector_kind == SelectorKind::Exact {
                crate::federation::transfer_key_admits_grant(
                    &selector,
                    &format!("{principal_kind}:{principal_id}"),
                    operation,
                )
                .map_err(|_| StoreOpError::TransferKeyReserved)?;
            }
            let stored_selector = selector;
            // Re-granting an identical row is a no-op, not a failure: setup scripts re-run
            // the same grant, and the store's create-only `AlreadyExists` reads as "the
            // credential already exists" to every caller. The store writes no audit row
            // and doesn't bump the grants generation when the row is already there, so
            // reporting success changes nothing durable.
            match store.create_read_grant_audited(
                &principal_kind,
                &principal_id,
                selector_kind,
                &stored_selector,
                operation,
                AuditCtx::route_admin(AuditOp::GrantCreate, actor),
            ) {
                Ok(()) => Ok(serde_json::json!({ "grant_created": true })),
                Err(StoreOpError::AlreadyExists) => Ok(serde_json::json!({
                    "grant_created": false,
                    "already_granted": true
                })),
                Err(e) => Err(e),
            }
        }
        AdminOpBody::GrantRevokeV2 {
            principal_kind,
            principal_id,
            selector_kind,
            selector,
            operation,
            ..
        } => {
            if selector_kind == SelectorKind::Category
                && !crate::catalog::valid_category_name(&selector)
            {
                return Err(StoreOpError::InvalidCategoryName);
            }
            let stored_selector = selector;
            // The transfer key's fence answers before the store write, so a revoke on it
            // is refused by that name; the admitted announce read can still be revoked,
            // which the store's identical check allows.
            if selector_kind == SelectorKind::Exact {
                crate::federation::transfer_key_admits_grant(
                    &stored_selector,
                    &format!("{principal_kind}:{principal_id}"),
                    operation,
                )
                .map_err(|_| StoreOpError::TransferKeyReserved)?;
            }
            store.revoke_read_grant_audited(
                &principal_kind,
                &principal_id,
                selector_kind,
                &stored_selector,
                operation,
                AuditCtx::route_admin(AuditOp::GrantRevoke, actor),
            )?;
            Ok(serde_json::json!({ "grant_revoked": true }))
        }
        AdminOpBody::SetCategory {
            credential_id,
            mode,
            categories,
            ..
        } => {
            let changed = store.set_categories_audited(
                &credential_id,
                mode,
                &categories,
                AuditCtx::route_admin(AuditOp::SetCategory, actor),
            )?;
            Ok(serde_json::json!({ "category_changed": changed }))
        }
        AdminOpBody::SetProviders {
            credential_id,
            mode,
            provider_ids,
            ..
        } => {
            let resulting = store.set_providers_audited(
                &credential_id,
                mode,
                &provider_ids,
                AuditCtx::route_admin(AuditOp::SetProviders, actor),
            )?;
            Ok(serde_json::json!({ "provider_ids": resulting }))
        }
        AdminOpBody::SetPlan {
            credential_id,
            plan_tier,
            ..
        } => {
            let resulting = store.set_plan_audited(
                &credential_id,
                plan_tier.as_deref(),
                AuditCtx::route_admin(AuditOp::SetPlan, actor),
            )?;
            Ok(serde_json::json!({ "plan_tier": resulting }))
        }
        AdminOpBody::Reclassify { force, .. } => {
            let changed = store
                .reclassify_audited(force, AuditCtx::route_admin(AuditOp::SetCategory, actor))?;
            Ok(serde_json::json!({ "credentials_reclassified": changed }))
        }
        AdminOpBody::SecretMultiHostSet { enabled, .. } => {
            let changed = store.set_secret_multi_host_audited(
                enabled,
                AuditCtx::route_admin(AuditOp::SecretMultiHostSet, actor),
            )?;
            Ok(serde_json::json!({"multi_host": enabled, "changed": changed}))
        }
        AdminOpBody::SecretPhoneGateSet { enabled, .. } => {
            let changed = store.set_secret_phone_mapping_audited(
                enabled,
                AuditCtx::route_admin(AuditOp::SecretPhoneGateSet, actor),
            )?;
            Ok(serde_json::json!({"phone_mapping": enabled, "changed": changed}))
        }
        AdminOpBody::SecretPut {
            kind,
            name,
            host,
            path_prefix,
            location,
            origin,
            rules,
            origins,
            material_b64url,
            ..
        } => store.secret_put_audited(
            &SecretPut {
                kind,
                name,
                host,
                path_prefix,
                location,
                origin,
                rules,
                origins,
                material_b64url,
            },
            actor,
        ),
        AdminOpBody::SecretDelete { name, .. } => {
            store.secret_operator_delete_audited(&name, actor)
        }
        AdminOpBody::SecretRevokeGrant { grant_id, .. } => {
            store.secret_operator_revoke_audited(&grant_id, actor)
        }
        AdminOpBody::SecretHomeSet {
            home: home @ (SecretHomeTarget::ThisVault | SecretHomeTarget::Unset),
            ..
        } => {
            let wanted = match home {
                SecretHomeTarget::ThisVault => Some(crate::store::SECRET_HOME_SELF),
                _ => None,
            };
            let change = store.set_secret_home_audited(
                wanted,
                AuditCtx::route_admin(AuditOp::SecretHomeSet, actor),
            )?;
            Ok(serde_json::json!({ "home_member": change.stored, "changed": change.changed }))
        }
        AdminOpBody::FederationGateSet { enabled, .. } => {
            let changed = store.set_federation_member_mapping_audited(
                enabled,
                AuditCtx::route_admin(AuditOp::FederationGateSet, actor),
            )?;
            Ok(serde_json::json!({ "member_mapping": enabled, "changed": changed }))
        }
        // Refused above, before any write: these need the daemon's outbound calls.
        op @ (AdminOpBody::FederationSelfSet { .. }
        | AdminOpBody::TransferInit { .. }
        | AdminOpBody::TransferSend { .. }
        | AdminOpBody::TransferResume { .. }
        | AdminOpBody::TransferAccept { .. }
        | AdminOpBody::RemoteAdd { .. }
        | AdminOpBody::MemberGrant { .. }
        | AdminOpBody::SecretHomeSet {
            home: SecretHomeTarget::Member(_),
            ..
        }) => Err(requires_daemon_refusal(&op)),
        AdminOpBody::TransferRecover { .. } => recover_transfer_key(store, actor),
        AdminOpBody::TransferReceive { .. } => {
            store.expire_incoming_transfers(wall_now_ms())?;
            let pending: Vec<serde_json::Value> = store
                .list_incoming_transfers()?
                .into_iter()
                .filter(|row| row.state == crate::federation::IncomingTransferState::Pending)
                .map(|row| {
                    serde_json::json!({
                        "transfer_id": row.transfer_id,
                        "sender": row.sender_member,
                        "credential_id": row.credential_id,
                        "kind": row.kind,
                        "categories": row.categories,
                        "size_bytes": row.size_bytes,
                        "received_at_ms": row.received_at_ms,
                        "expires_at_ms": row.expires_at_ms,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "pending": pending }))
        }
        AdminOpBody::TransferReject {
            transfer_id, from, ..
        } => {
            crate::federation::check_member_id(&from)?;
            check_transfer_id(&transfer_id)?;
            let state = store.reject_incoming_transfer_audited(
                &from,
                &transfer_id,
                crate::federation::REJECT_BY_OPERATOR,
            )?;
            Ok(serde_json::json!({ "transfer_id": transfer_id, "state": state.as_str() }))
        }
        AdminOpBody::RemoteRemove { credential_id, .. } => {
            let removed = store.remote_remove_audited(&credential_id)?;
            Ok(serde_json::json!({
                "removed": true,
                "credential_id": removed.credential_id,
                "home": removed.home_member,
                "incarnation": removed.incarnation,
            }))
        }
        AdminOpBody::RemoteList { .. } => {
            let records: Vec<serde_json::Value> = store
                .list_remote_records()?
                .into_iter()
                .map(|record| {
                    serde_json::json!({
                        "credential_id": record.credential_id,
                        "home": record.home_member,
                        "source": record.source.as_str(),
                        "home_pairing_id": record.home_pairing_id,
                        "incarnation": record.incarnation,
                        "last_home_version": record.last_home_version,
                        "last_home_state": record.last_home_state.as_str(),
                        "last_home_error": record.last_home_error,
                        "last_fetch_outcome": record.last_fetch_outcome,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "remote_records": records }))
        }
        AdminOpBody::MemberRevoke {
            member,
            operation,
            selector,
            ..
        } => {
            store.revoke_member_grant_audited(&member, operation, &selector)?;
            Ok(serde_json::json!({ "revoked": true }))
        }
        AdminOpBody::MemberList { .. } => {
            let grants = store.list_member_grants()?;
            Ok(serde_json::json!({ "member_grants": grants }))
        }
        AdminOpBody::Status { .. } => {
            // Status health uses credential lifecycle columns. Each row's detected
            // subscription tier is read from its encrypted record and added to the
            // status result. This read neither quarantines unreadable rows nor writes an
            // audit entry.
            let metas = store.list_meta()?;
            let grants = store.list_read_grants()?;
            let open_intents = store.list_intents()?.len();
            let mut result = status_result(&metas, &grants, open_intents, store.is_fenced_out());
            if let Ok(plans) = store.detected_plans() {
                attach_detected_plans(&mut result, &plans);
            }
            Ok(result)
        }
    }
}

/// The refusal code [`apply`] answers for an op that needs the running daemon's
/// outbound calls (see [`AdminOpBody::requires_daemon`]).
pub const FEDERATION_REQUIRES_DAEMON: &str = "federation_requires_daemon";

/// The refusal code for minting a capability handle on a remote record.
pub const REMOTE_RECORD_CODE: &str = "remote_record";

fn requires_daemon_refusal(op: &AdminOpBody) -> StoreOpError {
    StoreOpError::Encode(format!(
        "{FEDERATION_REQUIRES_DAEMON}: {} needs the running daemon for its outbound \
         calls and cannot run against a leased store; run it with the daemon up \
         (--subc <connection-file>)",
        op.op_name()
    ))
}

/// A transfer id is 32 lowercase hex characters.
fn check_transfer_id(transfer_id: &str) -> Result<(), StoreOpError> {
    if crate::federation::is_lower_hex_16_bytes(transfer_id) {
        Ok(())
    } else {
        Err(StoreOpError::Encode(
            "invalid_params: a transfer id is 32 lowercase hex characters".into(),
        ))
    }
}

fn wall_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// `transfer init --replace`: a fresh transfer key in place of one found off `Active`,
/// settling every transfer sealed under the old key in the same transaction. The reply
/// lists those transfers so the operator can send each credential again.
fn recover_transfer_key(
    store: &EncryptedStore,
    actor: &str,
) -> Result<serde_json::Value, StoreOpError> {
    let pem = crate::kem::generate_key()
        .map_err(|e| StoreOpError::Encode(format!("transfer key generation failed: {e}")))?;
    let record =
        VaultRecord::new_static(CredentialKind::KemKey, "operator", pem.into_bytes(), None);
    let recovery = store.recover_vault_transfer_key_audited(
        &record,
        AuditCtx::route_admin(AuditOp::Overwrite, actor),
    )?;
    let rejected: Vec<serde_json::Value> = recovery
        .rejected_incoming
        .iter()
        .map(|row| {
            serde_json::json!({
                "transfer_id": row.transfer_id,
                "sender": row.sender_member,
                "credential_id": row.credential_id,
            })
        })
        .collect();
    let abandoned: Vec<serde_json::Value> = recovery
        .abandoned_outgoing
        .iter()
        .map(|row| {
            serde_json::json!({
                "transfer_id": row.transfer_id,
                "receiver": row.receiver_member,
                "credential_id": row.credential_id,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "replaced": true,
        "rejected_incoming": rejected,
        "abandoned_outgoing": abandoned,
    }))
}

/// Build the status report shared by the authenticated route and lease-free CLI fallback.
pub fn status_result(
    metas: &[(String, RecordMeta)],
    grants: &[ReadGrant],
    open_intents: usize,
    fenced_out: bool,
) -> serde_json::Value {
    let health = crate::health::VaultHealth::summarize(metas, open_intents, fenced_out);
    let credentials: Vec<serde_json::Value> = metas
        .iter()
        .map(|(id, m)| {
            let mut row = serde_json::json!({
                "id": id,
                "state": m.state.as_str(),
                "record_version": m.record_version,
                "categories": m.categories,
                "provider_ids": m.provider_ids,
                "plan_tier": m.plan_tier,
                "incarnation": m.incarnation,
                "plan_tier_observed_at_ms": m.plan_tier_observed_at_ms,
                "provider": crate::catalog::provider(id),
            });
            if let Some(gateway) = &m.gateway {
                row["base_url"] = serde_json::json!(gateway.settings.base_url);
                row["headers"] = serde_json::json!(gateway
                    .settings
                    .headers
                    .iter()
                    .map(|header| (&header.name, &header.value))
                    .collect::<std::collections::BTreeMap<_, _>>());
            }
            row
        })
        .collect();
    // Both source lists are SQL-sorted, and the filter retains credential order.
    // Grants are ordered by principal, selector kind, selector, then operation so the
    // complete authority set is stable across repeated status reads. Stable covered-set
    // output makes a category assignment visible in a status diff.
    let read_grants: Vec<serde_json::Value> = grants
        .iter()
        .map(|grant| {
            let covered_credential_ids: Vec<&str> = metas
                .iter()
                .filter(|(id, meta)| match grant.selector_kind {
                    SelectorKind::Audience => false,
                    SelectorKind::Exact => id == &grant.selector,
                    SelectorKind::Category => meta
                        .categories
                        .iter()
                        .any(|category| grant.selector == category.as_str()),
                })
                .map(|(id, _)| id.as_str())
                .collect();
            serde_json::json!({
                "principal_kind": grant.principal_kind,
                "principal_id": grant.principal_id,
                "selector_kind": grant.selector_kind.as_str(),
                "credential_prefix": grant.selector,
                "operation": grant.operation.as_str(),
                "created_at_ms": grant.created_at_ms,
                "covered_credential_ids": covered_credential_ids,
            })
        })
        .collect();
    serde_json::json!({
        "status": health.status.as_str(),
        "credentials_total": health.credentials_total,
        "active": health.active,
        "needs_reauth": health.needs_reauth,
        "retired": health.retired,
        "corrupt": health.corrupt,
        "needs_reauth_ids": health.needs_reauth_ids,
        "retired_ids": health.retired_ids,
        "corrupt_ids": health.corrupt_ids,
        "open_intents": health.open_intents,
        "fenced_out": health.fenced_out,
        "credentials": credentials,
        "read_grants": read_grants,
    })
}

/// Add each credential's detected plan to a status snapshot, but only when the plan was
/// read from the same `record_version` the snapshot row reports, so a row and its tier
/// always describe the same stored record.
pub fn attach_detected_plans(
    result: &mut serde_json::Value,
    plans: &crate::store::DetectedPlanListing,
) {
    if let Some(rows) = result["credentials"].as_array_mut() {
        for row in rows {
            let operator = row["plan_tier"].as_str().map(str::to_owned);
            let detected = row["id"]
                .as_str()
                .and_then(|id| plans.get(id))
                .filter(|(version, _, _)| Some(*version) == row["record_version"].as_u64());
            let (tier, source) =
                crate::plan_detection::effective_plan(operator, detected.map(|(_, plan, _)| plan));
            if source.as_deref() == Some("detected") {
                row["plan_tier_observed_at_ms"] =
                    serde_json::json!(detected.and_then(|(_, _, time)| *time));
            }
            row["plan_tier"] = serde_json::json!(tier);
            if let Some(source) = source {
                row["plan_tier_source"] = serde_json::json!(source);
            }
        }
    }
}

fn decode_hash32(s: &str) -> Option<[u8; 32]> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect();
    <[u8; 32]>::try_from(bytes?.as_slice()).ok()
}

/// The write mode for `admin.store`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreMode {
    /// Create-only: fails if the id already exists.
    Create,
    /// Legacy unconditional overwrite. Its serialized shape remains frozen for old
    /// clients; identity-aware replacements use `admin.store_with_identity_policy`.
    ReplaceUnconditional,
    /// CAS overwrite gated on the current payload hash (lowercase hex).
    ReplaceCas { expected_hash_hex: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::CredentialKind;

    fn inventory_meta() -> RecordMeta {
        RecordMeta {
            incarnation: Some("fixture-incarnation".into()),
            plan_tier_observed_at_ms: None,
            record_version: 1,
            key_id_hex: "00".into(),
            state: crate::record::RecordState::Active,
            stale_pending: false,
            categories: vec!["llm-gateway".into()],
            created_by: Some("operator".into()),
            provider_ids: vec![],
            plan_tier: None,
            gateway: None,
        }
    }

    #[test]
    fn status_inventory_non_gateway_row_keeps_its_exact_bytes() {
        // Category membership alone must not add gateway fields to an ordinary key.
        let result = status_result(&[("apikey:custom".into(), inventory_meta())], &[], 0, false);
        assert_eq!(
            serde_json::to_string(&result["credentials"][0]).unwrap(),
            r#"{"categories":["llm-gateway"],"id":"apikey:custom","incarnation":"fixture-incarnation","plan_tier":null,"plan_tier_observed_at_ms":null,"provider":null,"provider_ids":[],"record_version":1,"state":"active"}"#
        );
    }

    #[test]
    fn status_inventory_gateway_fields_match_the_scoped_descriptor_shape() {
        use crate::gateway::{GatewayAuth, GatewayHeader, GatewaySettings};
        use crate::store::StoredGatewaySettings;

        for headers in [
            vec![],
            vec![
                GatewayHeader {
                    name: "x-a".into(),
                    value: "first".into(),
                },
                GatewayHeader {
                    name: "x-z".into(),
                    value: "last".into(),
                },
            ],
        ] {
            let mut meta = inventory_meta();
            meta.gateway = Some(StoredGatewaySettings {
                incarnation: "fixture-incarnation".into(),
                settings: GatewaySettings {
                    base_url: "http://[::1]:4000/v1".into(),
                    auth: GatewayAuth {
                        header: "authorization".into(),
                        scheme: "bearer".into(),
                    },
                    headers: headers.clone(),
                },
                host: "[::1]".into(),
                vendor: crate::catalog::ModelVendor::Anthropic,
            });
            let result = status_result(&[("apikey:anthropic-gw-acme".into(), meta)], &[], 0, false);
            let row = &result["credentials"][0];
            assert_eq!(row["base_url"], "http://[::1]:4000/v1");
            let expected = if headers.is_empty() {
                serde_json::json!({})
            } else {
                serde_json::json!({"x-a": "first", "x-z": "last"})
            };
            assert_eq!(row["headers"], expected);
            assert_eq!(
                row["headers"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                if headers.is_empty() {
                    vec![]
                } else {
                    vec!["x-a", "x-z"]
                }
            );
        }
    }

    /// A capability handle never reaches a `Debug` rendering.
    ///
    /// `RevokeHandle.handle` is the RAW `ckh_...` bearer -- `apply` hands it to
    /// `store.revoke_handle`, which hashes it there. Unlike an encrypted payload, a
    /// handle in a log needs no key and no vault access: whoever reads the line holds
    /// the credential it grants.
    ///
    /// Asserts the marker is present as well as the secret absent, so an impl that
    /// rendered nothing cannot pass.
    #[test]
    fn debug_never_renders_a_capability_handle() {
        let op = AdminOpBody::RevokeHandle {
            v: 1,
            handle: "ckh_LIVEBEARERTOKENVALUE".to_string(),
        };
        let rendered = format!("{op:?}");
        assert!(
            !rendered.contains("ckh_LIVEBEARERTOKENVALUE"),
            "a live capability handle rendered into Debug output: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "the redaction marker must be present, or an empty rendering would pass: \
             {rendered}"
        );
    }

    #[test]
    fn secret_put_legacy_bytes_omit_extended_fields_and_preserve_explicit_null() {
        let legacy = br#"{"op":"admin.secret_put","v":2,"kind":"agent_api_key","name":"key","host":"x.test","path_prefix":null,"location":"authorization_bearer","origin":null,"material_b64url":""}"#;
        let op: AdminOpBody = serde_json::from_slice(legacy).unwrap();
        assert_eq!(op.to_bytes().unwrap(), legacy);
        let mut extended: serde_json::Value = serde_json::from_slice(legacy).unwrap();
        extended["host"] = serde_json::Value::Null;
        extended["rules"] = serde_json::json!([{"host":"*.x.test"}]);
        let op: AdminOpBody = serde_json::from_value(extended.clone()).unwrap();
        assert_eq!(serde_json::to_value(op).unwrap(), extended);
        extended["rules"] = serde_json::Value::Null;
        let op: AdminOpBody = serde_json::from_value(extended).unwrap();
        let AdminOpBody::SecretPut { rules, origins, .. } = op else {
            panic!()
        };
        assert_eq!(rules, Some(serde_json::Value::Null));
        assert_eq!(origins, None);
    }

    #[test]
    fn provider_set_extended_keys_preserve_presence_and_require_v3() {
        let legacy = br#"{"op":"admin.provider_set","v":2,"service":"custom","categories":[],"provider_ids":[]}"#;
        let op: AdminOpBody = serde_json::from_slice(legacy).unwrap();
        assert_eq!(op.to_bytes().unwrap(), legacy);
        assert!(op.has_valid_schema_version());
        for (key, value) in [
            ("hosts", serde_json::json!(["api.example.com"])),
            ("auth_header", serde_json::json!("x-api-key")),
            ("auth_scheme", serde_json::json!("raw")),
            ("fusiform_provider_id", serde_json::json!("custom")),
        ] {
            for value in [value, serde_json::Value::Null] {
                let mut body: serde_json::Value = serde_json::from_slice(legacy).unwrap();
                body[key] = value;
                let op: AdminOpBody = serde_json::from_value(body.clone()).unwrap();
                assert_eq!(serde_json::to_value(&op).unwrap(), body);
                assert_eq!(op.required_schema_version(), ADMIN_OP_SCHEMA_V3);
                assert!(!op.has_valid_schema_version(), "v2 must refuse {key}");
                body["v"] = serde_json::json!(3);
                let op: AdminOpBody = serde_json::from_value(body).unwrap();
                assert!(op.has_valid_schema_version());
            }
        }
        for version in [0, 1, 3, 4, u32::MAX] {
            let mut body: serde_json::Value = serde_json::from_slice(legacy).unwrap();
            body["v"] = serde_json::json!(version);
            let op: AdminOpBody = serde_json::from_value(body).unwrap();
            assert_eq!(op.has_valid_schema_version(), version == 3);
        }
    }

    #[test]
    fn debug_never_renders_agent_secret_material() {
        let op = AdminOpBody::SecretPut {
            v: 2,
            kind: "agent_api_key".into(),
            name: "billing-key".into(),
            host: Some("x.test".into()),
            path_prefix: Some("/v1".into()),
            location: Some("authorization_bearer".into()),
            origin: None,
            rules: None,
            origins: None,
            material_b64url: "TUFURVJJQUwtQ0FOQVJZ".into(),
        };
        let rendered = format!("{op:?}");
        assert!(
            !rendered.contains("TUFURVJJQUwtQ0FOQVJZ"),
            "agent-secret material rendered into Debug output: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "the redaction marker must be present, or an empty rendering would pass: {rendered}"
        );
        // Scope metadata stays visible: an operator diagnosing a bad put needs to see
        // which host and location were named, and neither is material.
        assert!(rendered.contains("x.test"), "{rendered}");
        assert!(rendered.contains("/v1"), "{rendered}");
    }

    /// The boxed record inside `Store` is redacted transitively.
    ///
    /// Pins the delegation rather than assuming it: if `VaultRecord` ever went back to a
    /// derived `Debug`, this enum's careful impl would start leaking through a field it
    /// does not itself redact.
    #[test]
    fn debug_of_store_does_not_render_the_boxed_records_payload() {
        let record = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "operator",
            b"sk-INNER".to_vec(),
            None,
        );
        let op = AdminOpBody::Store {
            v: 1,
            id: "apikey:x".to_string(),
            record: Box::new(record),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::Create,
        };
        let rendered = format!("{op:?}");
        assert!(
            !rendered.contains("sk-INNER"),
            "the boxed record's payload rendered as text: {rendered}"
        );
        assert!(
            !rendered.contains("115, 107, 45, 73"),
            "the boxed record's payload rendered as bytes: {rendered}"
        );
    }

    /// Both grant-mutating ops carry the metadata-only `list` operation over the wire in
    /// its snake_case spelling, and re-encode it the same way.
    #[test]
    fn grant_create_and_revoke_accept_the_list_operation_on_the_wire() {
        for tag in ["admin.grant_create_v2", "admin.grant_revoke_v2"] {
            let wire = serde_json::json!({
                "op": tag,
                "v": ADMIN_OP_SCHEMA_V2,
                "principal_kind": "reserved",
                "principal_id": "router",
                "selector_kind": "category",
                "selector": "llm-provider",
                "operation": "list",
            });
            let decoded: AdminOpBody =
                serde_json::from_value(wire.clone()).unwrap_or_else(|e| panic!("{tag}: {e}"));
            let operation = match &decoded {
                AdminOpBody::GrantCreateV2 { operation, .. }
                | AdminOpBody::GrantRevokeV2 { operation, .. } => *operation,
                other => panic!("{tag} decoded as {other:?}"),
            };
            assert_eq!(operation, GrantOperation::List, "{tag}");
            assert_eq!(
                serde_json::to_value(&decoded).expect("encode"),
                wire,
                "{tag} re-encodes byte-compatibly"
            );
        }
    }

    #[test]
    fn round_trips_through_bytes() {
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None);
        let op = AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:x".into(),
            record: Box::new(record),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::Create,
        };
        let bytes = op.to_bytes().unwrap();
        let back: AdminOpBody = serde_json::from_slice(&bytes).unwrap();
        // Re-serializing the decoded value yields the same bytes (serde is stable
        // for these types), which is what lets the module verify the caller's exact
        // bytes and then decode them.
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(back.schema_version(), ADMIN_OP_SCHEMA_V1);
    }

    #[test]
    fn op_discriminator_is_present_in_bytes() {
        let op = AdminOpBody::Invalidate {
            v: 1,
            id: "apikey:x".into(),
        };
        let s = String::from_utf8(op.to_bytes().unwrap()).unwrap();
        assert!(s.contains("\"op\":\"admin.invalidate\""));
    }

    #[test]
    fn legacy_unconditional_store_bytes_remain_compatible() {
        let op = AdminOpBody::Store {
            v: 1,
            id: "apikey:x".into(),
            record: Box::new(VaultRecord::new_static(
                CredentialKind::ApiKey,
                "t",
                b"k".to_vec(),
                None,
            )),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::ReplaceUnconditional,
        };
        assert_eq!(
            String::from_utf8(op.to_bytes().unwrap()).unwrap(),
            "{\"op\":\"admin.store\",\"v\":1,\"id\":\"apikey:x\",\"record\":{\"schema_version\":1,\"kind\":\"api_key\",\"source\":\"t\",\"record_version\":1,\"expires_at_ms\":null,\"refresh_adapter\":null,\"oauth\":null,\"payload\":[107]},\"audit_op\":\"put\",\"mode\":{\"kind\":\"replace_unconditional\"}}"
        );
    }

    #[test]
    fn identity_policy_store_op_round_trips() {
        let raw = b"{\"op\":\"admin.store_with_identity_policy\",\"v\":1,\"id\":\"apikey:x\",\"record\":{\"schema_version\":1,\"kind\":\"api_key\",\"source\":\"t\",\"record_version\":1,\"expires_at_ms\":null,\"refresh_adapter\":null,\"oauth\":null,\"payload\":[107]},\"audit_op\":\"put\",\"clear_identity\":false}";
        let op: AdminOpBody = serde_json::from_slice(raw).expect("new policy op decodes");
        assert_eq!(op.to_bytes().unwrap(), raw);
    }
}

#[cfg(test)]
mod admin_schema_v2_tests {
    use super::*;
    use crate::record::CredentialKind;

    fn record() -> Box<VaultRecord> {
        Box::new(VaultRecord::new_static(
            CredentialKind::ApiKey,
            "test",
            b"key".to_vec(),
            None,
        ))
    }

    #[test]
    fn every_admin_variant_is_listed_in_version_and_lock_tables() {
        let v1 = ADMIN_OP_SCHEMA_V1;
        let v2 = ADMIN_OP_SCHEMA_V2;
        let variants: Vec<(&str, AdminOpBody, u32, Option<&str>)> = vec![
            (
                "ManifestImport",
                AdminOpBody::ManifestImport {
                    v: v2,
                    envelope: crate::store::GhManifestHandoffEnvelope {
                        key_id: "a".repeat(16),
                        manifest_bytes: "{}".into(),
                        signature: "".into(),
                    },
                },
                v2,
                Some(crate::store::GH_MANIFEST_ROOT_KEY_ID),
            ),
            (
                "ManifestSign",
                AdminOpBody::ManifestSign {
                    v: v2,
                    manifest_bytes: "{}".into(),
                    approver: "operator".into(),
                },
                v2,
                Some(crate::store::GH_MANIFEST_ROOT_KEY_ID),
            ),
            (
                "ManifestExport",
                AdminOpBody::ManifestExport { v: v2, version: 28 },
                v2,
                None,
            ),
            (
                "ManifestList",
                AdminOpBody::ManifestList { v: v2 },
                v2,
                None,
            ),
            (
                "ManifestRetireMachine",
                AdminOpBody::ManifestRetireMachine {
                    v: v2,
                    member_id: "member".into(),
                },
                v2,
                None,
            ),
            (
                "ManifestOneTapSet",
                AdminOpBody::ManifestOneTapSet {
                    v: v2,
                    enabled: true,
                },
                v2,
                None,
            ),
            (
                "ManifestOneTapStatus",
                AdminOpBody::ManifestOneTapStatus { v: v2 },
                v2,
                None,
            ),
            (
                "OperatorSign",
                AdminOpBody::OperatorSign {
                    v: v1,
                    id: "id".into(),
                    payload_b64: "".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "Store",
                AdminOpBody::Store {
                    v: v1,
                    id: "id".into(),
                    record: record(),
                    audit_op: AdminAuditOp::Put,
                    mode: StoreMode::Create,
                },
                v1,
                Some("id"),
            ),
            (
                "StoreWithIdentityPolicy",
                AdminOpBody::StoreWithIdentityPolicy {
                    v: v1,
                    id: "id".into(),
                    record: record(),
                    audit_op: AdminAuditOp::Put,
                    clear_identity: false,
                },
                v1,
                Some("id"),
            ),
            (
                "SetIdentity",
                AdminOpBody::SetIdentity {
                    v: v1,
                    id: "id".into(),
                    identity: RecordIdentity::default(),
                },
                v1,
                Some("id"),
            ),
            (
                "Invalidate",
                AdminOpBody::Invalidate {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "Logout",
                AdminOpBody::Logout {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "Reactivate",
                AdminOpBody::Reactivate {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "Remove",
                AdminOpBody::Remove {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "MintHandle",
                AdminOpBody::MintHandle {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "RevokeHandle",
                AdminOpBody::RevokeHandle {
                    v: v1,
                    handle: "secret".into(),
                },
                v1,
                None,
            ),
            (
                "RevokeHandleByHash",
                AdminOpBody::RevokeHandleByHash {
                    v: v1,
                    handle_hash: "hash".into(),
                },
                v1,
                None,
            ),
            (
                "RevokeAllHandles",
                AdminOpBody::RevokeAllHandles {
                    v: v1,
                    id: "id".into(),
                },
                v1,
                Some("id"),
            ),
            (
                "GrantCreate",
                AdminOpBody::GrantCreate {
                    v: v1,
                    principal_id: "p".into(),
                    credential_prefix: "a:".into(),
                    operation: GrantOperation::Read,
                },
                v1,
                None,
            ),
            (
                "GrantRevoke",
                AdminOpBody::GrantRevoke {
                    v: v1,
                    principal_id: "p".into(),
                    credential_prefix: "a:".into(),
                    operation: GrantOperation::Read,
                },
                v1,
                None,
            ),
            (
                "Approval",
                AdminOpBody::Approval {
                    v: v1,
                    credential_id: "id".into(),
                    artifact_sha256: "00".repeat(32),
                    approver: "operator".into(),
                },
                v1,
                Some("id"),
            ),
            ("Status", AdminOpBody::Status { v: v1 }, v1, None),
            (
                "GrantCreateV2",
                AdminOpBody::GrantCreateV2 {
                    v: v2,
                    principal_kind: "reserved".into(),
                    principal_id: "p".into(),
                    selector_kind: SelectorKind::Category,
                    selector: "llm-provider".into(),
                    operation: GrantOperation::Read,
                },
                v2,
                None,
            ),
            (
                "GrantRevokeV2",
                AdminOpBody::GrantRevokeV2 {
                    v: v2,
                    principal_kind: "reserved".into(),
                    principal_id: "p".into(),
                    selector_kind: SelectorKind::Category,
                    selector: "llm-provider".into(),
                    operation: GrantOperation::Read,
                },
                v2,
                None,
            ),
            (
                "SetCategory",
                AdminOpBody::SetCategory {
                    v: v2,
                    credential_id: "id".into(),
                    mode: SetCategoryMode::Set,
                    categories: vec!["llm-provider".into()],
                },
                v2,
                Some("id"),
            ),
            (
                "SetProviders",
                AdminOpBody::SetProviders {
                    v: v2,
                    credential_id: "id".into(),
                    mode: SetProvidersMode::Add,
                    provider_ids: vec!["zai-coding-plan".into()],
                },
                v2,
                Some("id"),
            ),
            (
                "SetPlan",
                AdminOpBody::SetPlan {
                    v: v2,
                    credential_id: "id".into(),
                    plan_tier: Some("pro_200".into()),
                },
                v2,
                Some("id"),
            ),
            (
                "Reclassify",
                AdminOpBody::Reclassify {
                    v: v2,
                    force: false,
                },
                v2,
                None,
            ),
            (
                "FederationGateSet",
                AdminOpBody::FederationGateSet {
                    v: v2,
                    enabled: true,
                },
                v2,
                None,
            ),
            (
                "SecretMultiHostSet",
                AdminOpBody::SecretMultiHostSet {
                    v: v2,
                    enabled: true,
                },
                v2,
                None,
            ),
            (
                "SecretPhoneGateSet",
                AdminOpBody::SecretPhoneGateSet {
                    v: v2,
                    enabled: true,
                },
                v2,
                None,
            ),
            (
                "SecretPut",
                AdminOpBody::SecretPut {
                    v: v2,
                    kind: "agent_api_key".into(),
                    name: "key".into(),
                    host: Some("x.test".into()),
                    path_prefix: None,
                    location: Some("authorization_bearer".into()),
                    origin: None,
                    rules: None,
                    origins: None,
                    material_b64url: "".into(),
                },
                v2,
                None,
            ),
            (
                "SecretDelete",
                AdminOpBody::SecretDelete {
                    v: v2,
                    name: "key".into(),
                },
                v2,
                None,
            ),
            (
                "SecretRevokeGrant",
                AdminOpBody::SecretRevokeGrant {
                    v: v2,
                    grant_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                },
                v2,
                None,
            ),
            (
                "SecretHomeSet",
                AdminOpBody::SecretHomeSet {
                    v: v2,
                    home: SecretHomeTarget::ThisVault,
                },
                v2,
                None,
            ),
            (
                "FederationSelfSet",
                AdminOpBody::FederationSelfSet {
                    v: v2,
                    member: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                },
                v2,
                None,
            ),
            (
                "TransferInit",
                AdminOpBody::TransferInit {
                    v: v2,
                    self_member: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                },
                v2,
                Some(crate::federation::VAULT_TRANSFER_ID),
            ),
            (
                "TransferRecover",
                AdminOpBody::TransferRecover { v: v2 },
                v2,
                Some(crate::federation::VAULT_TRANSFER_ID),
            ),
            (
                "TransferSend",
                AdminOpBody::TransferSend {
                    v: v2,
                    credential_id: "id".into(),
                    to: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                },
                v2,
                Some("id"),
            ),
            (
                "TransferResume",
                AdminOpBody::TransferResume {
                    v: v2,
                    transfer_id: "00".repeat(16),
                },
                v2,
                None,
            ),
            (
                "TransferReceive",
                AdminOpBody::TransferReceive { v: v2 },
                v2,
                None,
            ),
            (
                "TransferAccept",
                AdminOpBody::TransferAccept {
                    v: v2,
                    transfer_id: "00".repeat(16),
                    from: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                    replace: false,
                },
                v2,
                None,
            ),
            (
                "TransferReject",
                AdminOpBody::TransferReject {
                    v: v2,
                    transfer_id: "00".repeat(16),
                    from: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                },
                v2,
                None,
            ),
            (
                "RemoteAdd",
                AdminOpBody::RemoteAdd {
                    v: v2,
                    credential_id: "id".into(),
                    home: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                },
                v2,
                Some("id"),
            ),
            (
                "RemoteRemove",
                AdminOpBody::RemoteRemove {
                    v: v2,
                    credential_id: "id".into(),
                },
                v2,
                Some("id"),
            ),
            ("RemoteList", AdminOpBody::RemoteList { v: v2 }, v2, None),
            (
                "MemberGrant",
                AdminOpBody::MemberGrant {
                    v: v2,
                    member: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                    operation: MemberGrantOperation::TransferDeliver,
                    selector: MemberGrantSelector::None,
                },
                v2,
                None,
            ),
            (
                "MemberRevoke",
                AdminOpBody::MemberRevoke {
                    v: v2,
                    member: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                    operation: MemberGrantOperation::RemoteRead,
                    selector: MemberGrantSelector::Category("llm-provider".into()),
                },
                v2,
                None,
            ),
            ("MemberList", AdminOpBody::MemberList { v: v2 }, v2, None),
        ];
        for (name, op, version, lock) in variants {
            assert_eq!(op.schema_version(), version, "{name} schema field");
            assert_eq!(op.required_schema_version(), version, "{name} pairing row");
            assert!(op.has_valid_schema_version(), "{name} must be admitted");
            assert_eq!(op.lock_id(), lock, "{name} lock row");
        }

        assert!(!AdminOpBody::Invalidate {
            v: v2,
            id: "id".into()
        }
        .has_valid_schema_version());
        assert!(!AdminOpBody::Reclassify {
            v: v1,
            force: false
        }
        .has_valid_schema_version());
    }
}

#[cfg(test)]
mod operator_sign_tests {
    use super::*;
    use crate::key::MasterKey;
    use crate::test_support::TestTempDir;
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
    use ring::signature::{UnparsedPublicKey, ED25519};

    fn vault() -> (TestTempDir, EncryptedStore) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = TestTempDir::new(format!(
            "operator-sign-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let sqlite = open_sqlite(&descriptor).unwrap();
        EncryptedStore::migrate(&sqlite).unwrap();
        let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([0x61; 32])).unwrap();
        (root, store)
    }

    fn record(kind: CredentialKind, enabled: bool) -> VaultRecord {
        let der = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der.as_ref())
        );
        let mut record = VaultRecord::new_static(kind, "operator", pem.into_bytes(), None);
        record.operator_sign = enabled;
        // Deliberately leave audit_each_signature false: admin signing must audit
        // independently of the bus path's optional audit policy.
        record
    }

    fn put(store: &EncryptedStore, id: &str, record: &VaultRecord) {
        store
            .create_audited(id, record, AuditCtx::route_admin(AuditOp::Put, "test"))
            .unwrap();
    }

    fn sign(
        store: &EncryptedStore,
        id: &str,
        payload: &[u8],
        actor: &str,
    ) -> Result<serde_json::Value, StoreOpError> {
        apply(
            store,
            AdminOpBody::OperatorSign {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.into(),
                payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
            },
            actor,
        )
    }

    fn unhex(value: &str) -> Vec<u8> {
        assert!(value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn operator_sign_commits_payload_hash_and_returns_a_verifiable_signature() {
        let (_root, store) = vault();
        put(
            &store,
            "signing:machine:1",
            &record(CredentialKind::SigningKey, true),
        );
        let payload = b"server challenge\0\xff\n";
        for actor in ["route-admin", "offline-cli"] {
            let result = sign(&store, "signing:machine:1", payload, actor).unwrap();
            assert_eq!(result.as_object().unwrap().len(), 3);
            let public = result["public_key_hex"].as_str().unwrap();
            let signature = result["signature_hex"].as_str().unwrap();
            assert_eq!(public.len(), 64);
            assert_eq!(signature.len(), 128);
            let public = unhex(public);
            UnparsedPublicKey::new(&ED25519, &public)
                .verify(payload, &unhex(signature))
                .unwrap();
            assert_eq!(result["key_id"], crate::signing::key_id_for_public(&public));
            let rows = store.read_audit(None).unwrap();
            let row = rows.last().unwrap();
            assert_eq!(row.op, "sign");
            assert_eq!(row.credential_id.as_deref(), Some("signing:machine:1"));
            assert_eq!(row.actor, actor);
            let hash: String = crate::store::payload_hash(payload)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(row.payload_hash.as_deref(), Some(hash.as_str()));
            assert_eq!(row.payload_hash.as_ref().unwrap().len(), 64);
            assert!(!format!("{row:?}").contains("server challenge"));
        }
        assert_eq!(
            store
                .read_audit(None)
                .unwrap()
                .iter()
                .filter(|r| r.op == "sign")
                .count(),
            2
        );
    }

    #[test]
    fn operator_sign_refuses_unflagged_wrong_kind_and_unknown_identically_without_audit() {
        let (_root, store) = vault();
        for id in [
            "signing:unflagged:1",
            "signing:cortexkit-root:1",
            "signing:gh-manifest-root:1",
        ] {
            put(&store, id, &record(CredentialKind::SigningKey, false));
        }
        put(
            &store,
            "apikey:wrong-kind",
            &record(CredentialKind::ApiKey, true),
        );
        let before = store.read_audit(None).unwrap().len();
        for id in [
            "signing:unflagged:1",
            "signing:cortexkit-root:1",
            "signing:gh-manifest-root:1",
            "apikey:wrong-kind",
            "signing:unknown:1",
        ] {
            // A malformed payload must not take precedence over the permission fence.
            let error = apply(
                &store,
                AdminOpBody::OperatorSign {
                    v: 1,
                    id: id.into(),
                    payload_b64: "!".into(),
                },
                "offline-cli",
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "record encode failed: key is not marked for operator signing"
            );
            let error = sign(&store, id, b"challenge", "offline-cli").unwrap_err();
            assert_eq!(
                error.to_string(),
                "record encode failed: key is not marked for operator signing"
            );
            assert_eq!(store.read_audit(None).unwrap().len(), before);
        }
    }

    #[test]
    fn operator_sign_accepts_the_cap_and_refuses_one_byte_over_without_audit() {
        let (_root, store) = vault();
        put(
            &store,
            "signing:machine:1",
            &record(CredentialKind::SigningKey, true),
        );
        let before = store.read_audit(None).unwrap().len();
        let error = sign(
            &store,
            "signing:machine:1",
            &vec![0; MAX_OPERATOR_SIGN_PAYLOAD + 1],
            "offline-cli",
        )
        .unwrap_err();
        assert!(error.to_string().contains("signing cap"));
        let error = apply(
            &store,
            AdminOpBody::OperatorSign {
                v: 1,
                id: "signing:machine:1".into(),
                payload_b64: "!".into(),
            },
            "offline-cli",
        )
        .unwrap_err();
        assert!(error.to_string().contains("not valid base64"));
        assert_eq!(store.read_audit(None).unwrap().len(), before);
        let result = sign(
            &store,
            "signing:machine:1",
            &vec![0; MAX_OPERATOR_SIGN_PAYLOAD],
            "offline-cli",
        )
        .unwrap();
        assert_eq!(result["signature_hex"].as_str().unwrap().len(), 128);
        assert_eq!(store.read_audit(None).unwrap().len(), before + 1);
    }

    #[test]
    fn operator_sign_audit_failure_returns_error_and_no_signature() {
        let (root, store) = vault();
        put(
            &store,
            "signing:machine:1",
            &record(CredentialKind::SigningKey, true),
        );
        let before = store.read_audit(None).unwrap().len();
        // Refuse only sign rows in the real append transaction; successful signing
        // above proves that this fixture's key and payload are otherwise usable.
        let db = rusqlite::Connection::open(root.join("store.db")).unwrap();
        db.execute_batch("CREATE TRIGGER refuse_sign_audit BEFORE INSERT ON audit_log WHEN NEW.op = 'sign' BEGIN SELECT RAISE(ABORT, 'injected sign audit failure'); END;").unwrap();
        let result = sign(&store, "signing:machine:1", b"challenge", "offline-cli");
        assert!(
            matches!(result, Err(StoreOpError::Store(ref message)) if message.contains("injected sign audit failure")),
            "audit failure must return an error and no signature: {result:?}"
        );
        assert_eq!(store.read_audit(None).unwrap().len(), before);
        db.execute_batch("DROP TRIGGER refuse_sign_audit;").unwrap();
        assert!(sign(&store, "signing:machine:1", b"challenge", "offline-cli").is_ok());
    }

    #[test]
    fn operator_sign_debug_redacts_payload() {
        let op = AdminOpBody::OperatorSign {
            v: 1,
            id: "signing:machine:1".into(),
            payload_b64: "c2VjcmV0".into(),
        };
        let rendered = format!("{op:?}");
        assert!(!rendered.contains("c2VjcmV0"));
        assert!(rendered.contains("<redacted>"));
    }
}

#[cfg(test)]
mod remote_record_handle_tests {
    use super::*;
    use crate::federation::NewRemoteRecord;
    use crate::key::MasterKey;
    use crate::test_support::TestTempDir;
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

    fn vault() -> (TestTempDir, EncryptedStore) {
        let root = TestTempDir::new(format!("remote-record-handle-{}", std::process::id()));
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let sqlite = open_sqlite(&descriptor).unwrap();
        EncryptedStore::migrate(&sqlite).unwrap();
        let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([0x62; 32])).unwrap();
        (root, store)
    }

    /// A remote record's token is fetched from its home on each read, so no handle may
    /// reach it: minting one is refused by name and writes no handle and no audit row.
    #[test]
    fn minting_a_handle_for_a_remote_record_is_refused_as_remote_record() {
        let (_root, store) = vault();
        let id = "oauth:anthropic:remote";
        store
            .remote_add_audited(&NewRemoteRecord {
                credential_id: id.into(),
                home_member: "fed-computer:0123456789abcdef0123456789abcdef".into(),
                refresh_adapter: Some("anthropic".into()),
                detected_plan: None,
                identity: RecordIdentity::default(),
                home_version: 1,
                categories: vec![],
            })
            .unwrap();
        let audit_before = store.read_audit(None).unwrap().len();
        let refused = apply(
            &store,
            AdminOpBody::MintHandle {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.into(),
            },
            "offline-cli",
        );
        match refused {
            Err(StoreOpError::Encode(message)) => {
                assert!(message.starts_with(REMOTE_RECORD_CODE), "{message}")
            }
            other => panic!("expected the remote_record refusal, got {other:?}"),
        }
        // A minted handle writes a `mint_handle` audit row in the same transaction, so
        // an unchanged chain also proves no handle row was stored.
        assert_eq!(store.read_audit(None).unwrap().len(), audit_before);
    }
}
