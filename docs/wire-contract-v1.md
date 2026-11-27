# claustrum wire contract v1 — the consumer's reference

This document describes the read surface the `ck-claustrum` daemon serves today. Where a
claim is pinned by a test, the test is named, and those cannot drift silently. Where it
is not, treat it as documentation and check the source if it is load-bearing for you.

Consumers in other repositories branch on the values below, and a consumer cannot vendor
a `.rs` file, so this is the canonical statement of them.

**What this is not:** the parts and invariants behind this surface are in
[the architecture](architecture.md), and the threat model is in
[SECURITY.md](../SECURITY.md). This document is the surface, not the argument.

---

## 1. The four error classes

Every credential refusal body carries `class` alongside `code`, normally nested under
`result.error`. `credential.get_many` instead puts refusals in `results[i].error`
(§ 2); transport `Error` frames carry no class (§ 1a).
**Branch on `class`, never on `code`** — codes are added as new
conditions are distinguished; the class set is a contract with an announcement
obligation attached (`error_class_wire_strings_match_pinned_set` in `read_surface.rs`
fails loudly if the set changes, and its failure message names the obligation).

| class | means | your remedy |
|---|---|---|
| `transient` | a temporary failure — provider error, or the master key was momentarily unresolvable | retry with backoff |
| `permanent` | no retry can succeed without out-of-band action | refuse, account for it, **and preserve client state** |
| `auth_required` | a human must re-authenticate, or an operator must `ck auth reactivate` | surface an auth prompt; do not retry automatically |
| `context_overflow` | your request exceeded a bound | **reduce and retry — never wait and retry** |

Two of those remedies are worth stating in full because getting them wrong is expensive:

**`permanent` does not license destroying client state.** A revoked handle and an
unknown handle are one observation — both answer `not_found`/`permanent`, deliberately,
so a caller cannot probe which handles exist. Consequently a `permanent` refusal cannot
distinguish "this credential is gone" from "you typed it wrong", and a consumer that
reaps its configuration on `permanent` turns a typo into a self-sustaining outage.

**`context_overflow` is a request bound, not a wait.** Backing off and retrying an
oversized request re-spends the same budget forever. For `ttl_unsatisfiable` specifically
the vault has already performed a real upstream token exchange to prove your `min_ttl_ms`
cannot be met; retrying unchanged buys another one against the provider's mint budget.

### Codes you will see

| code | class | condition |
|---|---|---|
| `not_found` | permanent | unknown handle, revoked handle, or an id no grant covers — indistinguishable by design |
| `kind_not_gettable` | permanent | `credential.get` on a `SigningKey`; use `credential.sign` or `credential.public_key` |
| `kind_not_signable` | permanent | `credential.sign` on a record that is not a `SigningKey` |
| `reserved_payload_prefix` | permanent | `credential.sign` on `signing:fleet-record:*` with decoded payload bytes beginning with ASCII `ck-vault-hub/` |
| `kind_not_openable` | permanent | authorized `credential.open` on a record that is not a `KemKey` |
| `bus_seal_info_domain` | permanent | authorized bus-seal open with a missing, wrong or bare caller-specific `info` prefix |
| `open_failed` | permanent | KEM payload or HPKE opening failed; all crypto faults have the same reply |
| `open_rate_limited` | transient | this connection has reached the scoped-open refusal threshold |
| `malformed_encoding` | permanent | a `credential.sign` payload or a `credential.open` or `credential.seal` byte field failed strict standard base64 decoding |
| `invalid_recipient_key` | permanent | a `credential.seal` recipient key is not 32 bytes, or is a low-order X25519 point |
| `seal_rate_limited` | transient | this connection has reached the scoped refusal threshold `credential.open` and `credential.seal` share |
| `corrupt` | permanent | the record failed to decrypt or parse and has been quarantined |
| `refresh_unsupported` | permanent | an operation that requires a refresh cannot run for this record |
| `needs_reauth` | auth_required | the provider refused the stored login for good (for example `invalid_grant`, or a GitHub App that is no longer installed) and it stays refused until a new login, the credential was deliberately retired, or it has an unresolved refresh intent |
| `refresh_failed` | transient | the provider refused or the exchange failed |
| `vault_locked` | transient | the master key could not be resolved |
| `store_error` | transient | `credential.list_scoped` could not read one complete snapshot |
| `invalid_category_name` | permanent | a category is outside `^[a-z][a-z0-9-]{1,31}$` |
| `invalid_service_name` | permanent | an API-key service is empty, contains `-gw-`, or contains a colon, whitespace, control character or `\|` |
| `service_in_provider_catalog` | permanent | a provider registration names a service already owned by the fixed API-key catalog |
| `invalid_provider_id` | permanent | provider metadata fails `charset`, `length`, `duplicate`, `reserved`, or resulting-set `count`; text is `invalid_provider_id/permanent: rule=<rule> value=<value>` |
| `invalid_credential_id` | permanent | an id begins with reserved `category:` or contains `|` |
| `invalid_principal` | permanent | a grant principal is not `reserved` or contains `|` |
| `hub_audience_reserved` | permanent | an `account_token` grant for `cortexkit-hub` names any principal other than `reserved:ckbus`; no grant or audit row is written |
| `enrollment_name_has_grants` | permanent | enrollment approval needs explicit consent to inherit existing name-bound grants; revoke them first or pass `--keep-grants` |
| `invalid_plan_tier` | permanent | a plan tier set with `ck auth set-plan` is outside `^[a-z][a-z0-9_]{0,31}$` |
| `report_status_not_credential_death` | permanent | `report_auth_failure` carried a `provider_status` outside {401, 403} |
| `condition_not_admitted` | permanent | the login or its refresh adapter does not admit the reported condition reason |
| `condition_status_refused` | permanent | a condition report carried a `provider_status` other than 403 |
| `condition_link_refused` | permanent | a condition report carried a link that its reason does not permit or that failed the link rules |
| `condition_home_owned` | permanent | the operator tried to clear a condition on a shared copy instead of at its home |
| `too_many_items` | context_overflow | a batch exceeded the per-request cap |
| `sign_payload_too_large` | context_overflow | a sign payload or the combined `credential.open` fields exceeded 1 MiB (`MAX_SIGN_PAYLOAD`) |
| `seal_input_too_large` | context_overflow | a `credential.seal` plaintext over 64 KiB, or info or aad over 1 KiB |
| `ttl_unsatisfiable` | context_overflow | a freshly minted token still cannot satisfy your `min_ttl_ms` |

An unresolved refresh intent prevents reads with
`needs_reauth`/`auth_required`: a storage failure after rotation must not cause the old
refresh token to be sent again, even if its access token is still fresh. Reconciliation
or an operator replacement must resolve that intent before the credential is served.

**Codes from the admin write path, not the read surface:** `invalid_category_name`,
`invalid_service_name`, `service_in_provider_catalog`,
`invalid_provider_id`, `invalid_credential_id`, `invalid_principal`, `invalid_plan_tier`,
`enrollment_name_has_grants`, `hub_audience_reserved`, and `condition_home_owned` are store-taxonomy
refusals (`StoreOpError::wire_code` in `credentials-core/src/store.rs`). A read never
produces them. Every other code in the table is a `ReadError` the read surface emits;
`read_error_wire_codes_are_golden_and_match_the_doc_table` in `read_surface.rs` checks
both directions.

**On an unknown class:** render a generic degraded state. Do not fall back to the
nearest known class — each known class carries an actionable remedy, and applying the
wrong one (prompting a human for a transient network failure) is worse than saying
"something is wrong and I do not know what".

### 1a. Two refusal shapes, and only one of them carries a class

A read-surface operation can be refused in two structurally different ways, and a
consumer must handle both. This section exists because a consumer reading section 1
would reasonably conclude that every refusal carries a class, and one of these does not.

| | frame | body | carries `class` |
|---|---|---|---|
| the credential answered no | `Response` | `result.error.{code, class}` (or `results[i].error` for `credential.get_many`) | yes |
| the request never got that far | `Error` | `{code, message}` | **no** |

The second shape is the transport refusal: a malformed frame, an unknown operation, or
ordinary read params that failed to decode (`invalid_params`). Enrollment operations
and `module_secret.*` are exceptions: their typed-param decode failures are classified
`Response` refusals (`invalid_params`/`permanent`), as described in § 2.1 and § 19.
Purpose-bound ck-bus signing input refusals use the classless transport `Error`
shape with `invalid_params`, after authorizing the caller; ordinary request decoding
is unchanged.
The transport refusal is emitted by `send_route_error` in
`main.rs` using `subc_protocol::ErrorBody`, whose fields are `code`, `message` and an
optional `detail` — **there is no `class` field on that type**, so its absence is
structural rather than an omission on some paths.

**Why the class vocabulary is deliberately not extended to cover it.** The four classes
each name a remedy the consumer can act on — retry, reduce, re-authenticate, give up.
A transport refusal has no such remedy, because it means the request itself was wrong:
the fix is a code change in the caller, not a different action at runtime. Labelling it
`permanent` would be true in the useless sense and would invite a consumer to treat a
bug in its own serialisation as a credential verdict.

**What a consumer must do:** distinguish the two by FRAME TYPE before decoding. An
`Error` frame is never a statement about a credential — do not map it into a credential
state, do not mark anything `needs_reauth`, and do not delete client state on it.

**Some `Error` codes are definitive: retrying or reconnecting cannot change them.** They
say nothing about a credential, but the same request will be refused the same way on
any connection, so a retry loop around them only delays the failure. Stop and surface
the code:

- `unknown_method`: the vault does not implement the operation. From a released vault
  this means **the vault predates that operation**: update the vault. (The one
  exception is `auth.watch_scoped`, where `unknown_method` is the documented signal to
  fall back to polling `credential.list_scoped`.)
- `invalid_params`, `invalid_request`: the params, or the whole request body, did not
  decode. The fix is in the caller's serialisation.
- `flow_scopes_unsupported`: a route opened under a flow scope; the vault never serves
  those.
- `invalid_control_body`: this vault build cannot decode the daemon's route bind; the
  daemon is newer than the vault in a way the vault cannot follow. Update the vault.
- `unknown_module` (sent by subc, not the vault): no module with this id is registered
  or supervised on the daemon at all. A vault that is starting, restarting or busy is
  reported as `module_warming`, `module_reloading`, `target_unavailable` or
  `module_timeout` instead. These codes can be retryable.

Both clients use the subc daemon's shared route-open retry rule for coded terminal refusals. Unknown
codes and `missing_identity` are terminal. A normally retryable code is terminal
when `detail.expected_back` is `false`. This does not change how clients handle
connection loss without an error reply. The TypeScript client reports a terminal
refusal as `permanent`/`gone`; the Rust client reports it as unclassified and not
retryable. Neither classification describes the credential's state.

`admin_refused` is sent by admin operations, never by a credential read.

**And do not decode an `Error` frame's body as a result.** A decoder reaching for
`result.credentials` in an `Error` body gets a missing-field failure, which presents as
corruption and sends the reader hunting a serialisation defect in the producer that does
not exist.

---

## 2. Addressing

Three ways to be authorized, and they differ in what they prove.

**A capability handle** (`ckh_…`) is a bearer token. Possession is the authorization;
there is no principal check. Treat it as a secret: it belongs in a `0600` file, never in
a log line, an error message, or a shell history. The vault never logs one.

**A supervised module principal** is the supervisor's attestation, stamped at route-bind.
For a channel-registered module, the inherited registration stream proves the
spawn's identity. Its HELLO omits `launch_nonce` and declares
`registration_channel: true`; `supervisor.provenance` reports `registration: channel`.
The vault's separate outbound connections authenticate with the connection-file key,
then present a fresh single-use `self` claim minted over the live registration
connection (`claim.mint`, then `claim.present`). Claim-bound route opens omit
`consumer_identity`: an explicit identity conflicts with the connection binding.
Failed minting or presentation refuses the outbound call without sending it anonymously.
The config gate uses the registration control lane itself and sends no consumer identity.

On the legacy nonce path, a supervised module's calls to
another module's route surface carry `Principal::Reserved { module_id }` when its
`route.open` presents the `consumer_identity` (`SUBC_MODULE_ID`, `SUBC_LAUNCH_NONCE`) that
the daemon injected at spawn; the daemon verifies the nonce against the live supervisor and
stamps the principal into the `route.bind` it relays here. A `route.open` WITHOUT it is
`Direct` regardless of who sent it, and a mismatched nonce is refused
`bad_consumer_identity` rather than downgraded. The auth handshake proves connection-file
access and carries no identity at all.

Nonce-based clients attach the pair (`ConnectOptions.consumer_identity` in older
SDKs reads both variables when non-empty). A HAND-ROLLED NONCE CLIENT MUST SEND IT,
and that is the entire
difference between a scoped call that works and one that answers `not_found`: a consumer
dialling over a raw socket plus `authenticate_client` arrives `Direct` and every scoped op
refuses it correctly.

**On the nonce path, nonce possession, not process ancestry, is the authority boundary.** The supported
handoffs are an inherited descriptor and, when no descriptor is named, the
`SUBC_LAUNCH_NONCE` environment fallback. The vault reads and closes its nonce
descriptor before spawning children; before that read the descriptor is inheritable.
The environment fallback can also be inherited unless scrubbed. Neither delivery mode
alone proves that every helper lacks the nonce, and `env_clear` alone does not close an
inherited descriptor. Do not assume a child is automatically `Direct`, the principal
for a route that presents no launch identity.

Helpers that should be anonymous must omit `consumer_identity` on `route.open`
(`consumerIdentity: null` in subc-client), and launchers must scrub nonce environment
variables and close nonce descriptors before spawning untrusted helpers. `ck auth` and
the TypeScript vault client deliberately omit route identity so inherited launch
credentials cannot lend them the host's `Reserved` identity, the principal a supervised
module gets by presenting its own launch nonce.

A host-launched plugin without a supervised launch identity uses an enrollment token.

**A route opened under a flow's scope is refused at bind.** If the `route.bind` stamp's
scope carries `flow_id`, the vault answers the bind with an error frame, code
`flow_scopes_unsupported`, and binds nothing. The vault authorizes on the bind's principal
and never on its scope, so serving such a route would hand a flow whatever the opening
module's grants reach. A scoped route without a `flow_id` binds as before. A `route.bind`
this build cannot decode at all is refused the same way, code `invalid_control_body`, so it
fails at once instead of waiting out the daemon's bind timeout.

**Callosum-forwarded channels are isolated.** On `reserved:callosum` only, a harness
derived from the authenticated peer can select a federation member channel (§14) or a
phone channel (§15). Neither borrows callosum's grants. Both refuse bearer params
(`handle`, `enrollment_token`) with an `invalid_params` Error frame. With the member gate
off, the older behavior remains: a `fed-` harness has no principal but can still use a
vault-local bearer secret on credential operations. A phone setting off or unreadable
never enables phone operations. Other principals' harnesses are ignored.

**`secret.use` is addressed by sender, not by grant.** Only `reserved:aft` and
`reserved:cerebellum` may call it, and the asking agent scope comes only from the subc
`ScopeStamp` they relay in the params (§15). Every other caller, Direct and every
callosum-forwarded channel included, gets the uniform `not_found` before its params are
read. No read grant, handle or enrollment token reaches an agent secret.

**An enrollment token** is the vault's OWN attestation: it minted it, holds only its
hash, and can revoke it. This is how a host-launched consumer gets a name that grants can
reach. Present it in the params (`enrollment_token`) on `credential.list_scoped` or
the credential-id forms of the scoped operations in the address matrix below;
see § 2.1. It is not a replacement for a bearer handle.

Grants name one of the two principal kinds, per operation:

    ck auth grant --principal reserved:<module> --selector-kind exact --selector <id-text> --operation read
    ck auth grant --principal enrolled:<name>   --selector-kind category --selector <bare-name> --operation read

**`--prefix` is gone and is REFUSED, not aliased.** Its reach changed whenever someone
named a new credential. A former `--prefix` that named a family is a **category** now; a
former one that named a single credential is `exact`. Aliasing it to `exact` would have
succeeded while granting nothing, because a prefix like `apikey:` names no credential
exactly.

Selectors are stored as **bare text** — an `exact` selector is the credential id, a
`category` selector is the bare category name. Neither carries a kind marker; the kind is
its own column. (Audit TARGETS do carry `category|<name>`, and split on the **first**
`|`.)

**`exact` means byte equality.** A grant on `signing:agent-assertion:1` covers exactly
that id and does NOT cover `…:10`. This is narrower than the old prefix behaviour, which
is the point: a grant whose reach can grow when someone else names a credential is not a
grant you can reason about. Use `category` when you want a set that moves, and it moves
only when an operator assigns the category under the master key.

A grant carries one operation. Each authorizes only its own surfaces, and none implies
another (`deposit` and `account_token` are described in sections 11 and 12):

| grant operation | authorizes | does not authorize |
|---|---|---|
| `read` | `get_scoped` (the token), scoped `status`, `public_key`, `report_auth_failure`, `report_condition`, `clear_condition`; identity in `list_scoped` | `sign`, `open` |
| `sign` | `credential.sign` with a signing key; the row (without identity) in `list_scoped` | the token, `public_key`, `open` |
| `open` | `credential.open` with a KEM key; the row (without identity) in `list_scoped` | the token, `sign` |
| `list` | the row in `list_scoped` WITH its identity (`account_id`, `email`, `org_name`) and `refresh_adapter` | every other operation: no token, no status, no key use, no report |
| `seal` | `credential.seal` with a KEM key; the row (without identity) in `list_scoped`. **Exact selector only** | the token, `public_key`, `sign`, `open` |
| `policy_token` | `credential.policy_token` and `policy.request_action` for one GitHub App credential, limited by the signed policy and subject to each method's partner allowlist. **Exact selector only** | `get_scoped` or any other `read` authority |

An operator can add or revoke `policy_token` with `ck auth grant` or
`ck auth revoke-grant`, using `--selector-kind exact --selector <credential-id>` and
`--operation policy_token`. Category and audience selectors are refused. `read` does
not confer `policy_token`, and a module declaration cannot request it. The hand grant
appears as `policy_token` in `ck auth grants` and the apps' permission list.

`list` is the account roster without the tokens, for a consumer that chooses which
account serves a request and must never be able to fetch one. It unseals the record only
to read those metadata fields; no payload leaves the vault. A `list`-only principal that
calls `get_scoped`, scoped `status`, `sign`, `public_key`, `open` or `report_auth_failure`
is refused with the same `not_found` as a principal holding no grant at all, so it also
cannot use those surfaces to learn whether an id exists.

| operation | handle | credential_id | enrollment token |
|---|---|---|---|
| `credential.get` | yes | — | — |
| `credential.get_many` | yes | — | — |
| `credential.get_scoped` | — | yes (`read`) | yes |
| `credential.list_scoped` | — | principal-addressed; all of the caller's grants | yes |
| `credential.sign` | yes | yes (`sign`) | yes (credential-id form) |
| `credential.open` | — | yes (`open`) | yes |
| `credential.seal` | — | yes (`seal`) | yes |
| `credential.public_key` | yes | yes (`read`) | yes (credential-id form) |
| `credential.status` | yes | yes (`read`) | yes (credential-id form) |
| `credential.report_auth_failure` | yes | yes (`read`) | yes (credential-id form) |
| `credential.report_condition` | — | yes (`read`) | yes |
| `credential.clear_condition` | — | yes (`read`) | yes |

A request carries exactly one address. `credential.status` with both a handle and a
`credential_id` is refused as `invalid_params`
(`tests::scoped_status_rejects_both_addressing_forms_as_invalid_params`). A report carrying
both addresses or neither is refused as a malformed request
(`tests::a_report_supplying_both_addresses_or_neither_is_refused`).
`credential.status` with neither address is the overall vault-health probe.

`enrollment_token` selects the principal for a scoped credential-id request or
`credential.list_scoped`; it is not an additional credential address and does not
authorize a handle-form request.

**Batch envelope.** `credential.get_many` takes `params: { items: [{ handle, ... }, ...] }`
and returns a `Response` with top-level `results`, not `result`. Each entry is either
the ordinary get success fields or `{ "error": { "code": "...", "class": "..." } }`,
in request order; one item's refusal does not fail the other items. An over-cap batch
is refused as a whole with exactly one entry:

    {"results":[{"error":{"code":"too_many_items","class":"context_overflow"}}]}

There is no per-item execution in that case. A batch whose params cannot decode
instead receives the classless `invalid_params` `Error` frame from § 1a.

Signing keys minted with `ck auth mint-signing-key --audit-each-signature` opt
into a permanent per-signature history. After key and payload validation, but
before signing, the vault commits one HMAC-chained row with `audit_log.op = sign`,
the credential id, the plain SHA-256 of the exact decoded payload, and the resolved
`reserved:<module>` or `enrolled:<name>` actor. Anonymous handle holders use the
existing `conn-N` channel attribution. Payload bytes are never recorded. A failed
audit write (including a lost writer fence) returns `store_error` / `transient`
and no signature; refused payloads write no signature row. Keys without this
sealed flag (including existing keys) retain the no-write signing path. Signed bytes
are published with the signature, so the plain hash lets anyone compare those bytes
with the sign row without a vault key.

The public key id is derived from the signing key and returned with the signature,
not stored in an extra audit column. A sign row belongs to the key generation
installed by the most recent `put`/`overwrite` row for that credential id; the
chain orders signatures around replacements. Normal rotation uses a new id.
Older record decoders ignore the additive flag; rollback reads remain compatible,
but older binaries do not enforce this policy and drop it when rewriting a record.

### Purpose-bound ck-bus signing keys

Daemon startup creates these Ed25519 keys on every computer, including computers
that are not hubs:

| credential id | purpose |
|---|---|
| `signing:bus-leaf:1` | sign the hub's NATS connect nonce |
| `signing:bus-hub-operator:1` | sign NATS operator JWTs |
| `signing:bus-hub-account:1` | sign NATS account/user JWTs |
| `signing:bus-hub-tls:1` | sign the hub's TLS 1.3 server CertificateVerify |
| `signing:bus-federation-account:1` | sign NATS user JWTs for modules in the computer's federation account |

Creation is create-only: one `fleet_key_create` audit row per missing key, with
actor `vault`, and no replacement or new row on a subsequent start. All generations
under these five prefixes admit only exact `read` and `sign` grants to
`reserved:ckbus`. Other principals, operations, non-exact selectors naming these
keys, and bearer-handle minting receive `bus_key_reserved` / `permanent`. Category
grants never cover these keys. `read` exposes the public half, not the private key;
the NATS server never receives private material.

Every vault-key signing entry point applies the same core purpose check to the
decoded signing bytes, including `credential.sign` and operator `ck auth sign`:

- **Leaf:** exactly 15 bytes, each in `A-Z a-z 0-9 - _`. This is the unpadded
  base64url NATS nonce representing 11 random bytes, not its decoded random bytes.
- **TLS:** exactly 64 bytes of `0x20`, the ASCII context
  `TLS 1.3, server CertificateVerify`, one `0x00`, then exactly 32 or 48 transcript
  hash bytes (RFC 8446 §4.4.3). No extra bytes or other context is accepted.
- **Operator/account JWT:** at most 65,536 bytes total, exactly two nonempty,
  unpadded base64url segments separated by one dot (`<header>.<claims>`). The
  decoded header must be a JSON object with `alg: "ed25519-nkey"` and `typ: "JWT"`;
  additional header members are allowed. This is the JWT signing input, without
  the signature segment.

An input outside its key's purpose receives a classless transport `invalid_params`
Error, with no signature or write. Unauthorized callers still receive uniform
`not_found` regardless of their input. Other signing keys continue to accept arbitrary bytes
within their existing caps. These startup keys have `audit_each_signature = false`,
so consumer TLS handshakes and other consumer signatures add no per-signature audit
row. They are not opted into operator signing: `ck auth sign` requires a separate
operator opt-in as for any other key. If opted in, operator signatures still require
their normal durable audit row and still apply the purpose check.

### 2.1 Enrollment, for a consumer with no supervised identity

The ceremony is `auth.enroll_propose` → operator approval → `auth.enroll_poll`, with
`auth.enroll_rotate` for later rotation.

1. **Propose.** You mint a 32-byte request secret encoded as exactly 64 lowercase
   hex characters. Send `request_secret_hash` as the lowercase hex SHA-256 of the
   **32 decoded bytes**, not of the 64-character UTF-8 hex string, and receive a
   request id. **Persist the secret and hash before you send**, so a crash between the call and its reply
   does not leave you unable to poll a request that exists.
   Optional `display_name` proposes a person-facing label, such as
   `Claude sign-in for Pi`. The vault trims surrounding whitespace and accepts
   1–40 Unicode scalar values. It refuses control characters (Cc), U+2028/U+2029,
   bidi controls (U+061C, U+200E/U+200F, U+202A–U+202E, U+2066–U+2069), and
   zero-width characters (U+200B–U+200D, U+FEFF), with `invalid_params`; it never
   truncates. An older vault refuses this field as `invalid_params`.
   Optional `requested_grants` is a nonempty array of at most four entries, each
   `{"selector":{"category":"llm-provider"},"operation":"read"}` or
   `{"selector":{"exact":"apikey:zai"},"operation":"list"}`. Only `read`
   and `list` are accepted; selectors use the ordinary store grant validation.
   An empty array, duplicates (same selector and operation), more than four entries,
   any other operation, malformed selectors, unknown entry fields, or a non-array
   (including null) refuses as `invalid_params` / `permanent`, with no stored request.
   Omission retains the original enrollment-only ceremony. Older vaults refuse the
   field as `invalid_params`; clients must explicitly choose whether to retry without
   it, since that refusal also identifies malformed grants. A resumed proposal keeps
   the first request's list and display name; it cannot widen or remove either.
2. **Wait.** An operator approves with the master key (`ck auth enroll approve`).
   `ck auth enroll list` shows the proposed display name. Approval admits a NAME and mints nothing — which is what stops a squatter who proposed
   a name it does not hold from collecting a token even if approval is granted by mistake.
3. **Poll.** Send `request_secret` as the original 64 lowercase hex characters,
   not the hash. The first successful poll, authenticated by that secret, mints the
   token. Only `pending` means keep polling; every other outcome is terminal.
4. **Persist at `0600`** with a parent directory that is not group- or world-writable.

**Operator approval and revocation.** The master-key-authenticated `admin.op` body
`{"op":"admin.enroll_approve","v":2,"request_id":"<id>","final_name":"consumer"}`
admits a pending request without minting a token. Optional `keep_grants` defaults to
`false`; if the unused final name already has grants (including grants retained by
older revocations or deliberately preprovisioned), approval refuses through the existing
admin refusal path as `enrollment_name_has_grants` / `permanent` unless
`keep_grants:true` explicitly authorizes inheritance. The grant check and approval
are one transaction. `ck auth enroll approve` lists those
grants and explains how to revoke them or consent with `--keep-grants`. The success
result is `{"enrollment_id":"<id>","name":"consumer"}`, with optional
`display_name` when a label was approved. The optional admin field `display_name`
(`ck auth enroll approve --display-name <text>`) replaces the proposed label under
the same validation rules; an empty override refuses without changing the request.
Without an override, approval keeps the proposed label. Without either, it stores
no label. The CLI prints the approved label. Only an approved label is stored on
the enrollment; token rotation preserves it, revocation removes it, and reusing
the enrollment name does not inherit it.

Optional `grant_requested:true` on `admin.enroll_approve` applies **only the list
stored with the pending request** to `enrolled:<final_name>`. It defaults to false
when omitted, preserving older CLI behavior; the approve body never accepts a new
grant list. Enrollment, ordinary grants, grant-generation changes, and the same
audit rows as `ck auth grant` commit in one transaction, checked against the store's
current writer lease so a superseded writer cannot approve. The grant-generation
counter tells permission readers that grants changed. A grant or audit failure rolls
all of them back. `keep_grants` remains independent consent
to inherit any existing name-bound grants. Created grants appear normally in
`ck auth grants` and `permissions.list` with an enrolled holder.

`ck auth enroll list` and approval show the stored requested grants and their current
reach (the number of matching credentials) before consent, including exact credential
ids. A zero-reach warning means no credential matches now, not that approval is invalid. With
requested grants, interactive approval asks `Approve and grant these? [y/N]` unless
an explicit choice is supplied. Non-terminal approval requires `--grant-requested`
or `--no-grants`; combining them refuses. `--no-grants` approves only the enrollment.
Without a requested list, approval behaves as before. Additive proposal and approve
request bytes are pinned by `enrollment_requested_grants_wire_golden`; malformed
grant refusals and the four/five-entry boundary are exercised by
`enrollment_requested_grants_validates_shapes_and_four_entry_boundary` against the
same `invalid_params` envelope pinned in the enrollment wire fixture.

**Operator labeling.** The master-key-authenticated `admin.op` body
`{"op":"admin.enroll_label","v":2,"name":"consumer","display_name":"My plugin"}`
sets the display name of a live approved enrollment under the same validation
rules. `display_name:null` clears it. The result is
`{"name":"consumer","display_name":"My plugin","changed":true}` (or a null
display name when cleared). Repeating the current value returns `changed:false`
without an audit row. Unknown and revoked names refuse as missing enrollments.
The label update and audit append are atomic; grants, token material, token
generation and approval details are unchanged. This is an operator operation,
not a consumer route.

`{"op":"admin.enroll_revoke","v":2,"name":"consumer"}` revokes the live enrollment
and every grant on `enrolled:consumer` in one transaction. Each removed grant gets a
normal `grant_revoke` audit row. Its success result keeps `revoked:true` and adds
`removed_grants`, an array ordered by selector kind, selector, then operation. Each row
uses the existing grant inventory fields: `principal_kind`, `principal_id`,
`selector_kind`, `credential_prefix` (the selector text), `operation`, and
`created_at_ms`. The array is empty when no grants were removed. The CLI prints the
removed grants. Consumer token rotation (`auth.enroll_rotate`) and operator reissue
preserve grants because they keep the same enrollment. Golden admin request and reply
examples are pinned by
`enrollment_regression_admin_wire_examples_pin_consent_and_removed_grants` in the
enrollment wire fixture below. Consumer token replies and refusal shapes are unchanged.

**Refusals.** Every enrollment op refuses in the same shape as a read-surface
refusal: a `Response` frame whose body is

    {"result":{"error":{"class":"<permanent|transient>","code":"<refusal code>"}}}

`class` is a member of the four-class set in § 1 and carries the retry policy;
`code` names the outcome (`pending_exists`, `pending_queue_full`, `invalid_params`,
`not_found`, `already_consumed`, `superseded`, `stale_generation`, and `store_error`
when the vault's store fails). Only `pending_queue_full` and `store_error` are
`transient`. The exact bytes are pinned in
`crates/credentials-module/tests/fixtures/enrollment_wire_contract.json` by
`enrollment_wire_fixture_pins_exact_requests_successes_and_nine_refusals`.

Malformed typed params for `auth.enroll_propose`, `auth.enroll_poll`, and
`auth.enroll_rotate` produce the same classified `Response` envelope, with
`invalid_params`/`permanent`. Unlike ordinary read-param decoding in § 1a, they do
not produce an `Error` frame. Malformed outer request frames and unknown operations
still produce classless `Error` frames, which are not enrollment verdicts. Do not
treat those as `not_found`, `superseded` or any other enrollment refusal.

Then present the token on the scoped ops. Three properties worth knowing:

- **A presented token decides who you are**, overriding any ambient bus principal. If you
  send one, you meant it.
- **A token that does not resolve REFUSES.** It does not fall back to your bus principal.
  Otherwise a revoked consumer would keep working from whatever identity its transport
  happens to carry, which would make revocation a property of your process rather than of
  the vault.
- **A revoked enrollment answers exactly like an unknown token** (`not_found`,
  `permanent`), so you cannot distinguish "revoked" from "never existed" — and neither
  can anyone enumerating consumer names.

An older daemon REFUSES a token-bearing call at decode rather than ignoring the token: the
params struct is `deny_unknown_fields`. You will see an explicit decode refusal, not a
plausible list computed for grants you do not hold.

### 2.2 Declared grants for first-party modules

The daemon may attest a module's approved `provider_declarations.claustrum` entry in
the `caller` record of `route.bind`. The daemon sends that record only to targets that
declare `caller-attestation/v1`, which the vault's manifest does. The daemon has
already selected the vault's entry;
the vault reads that declaration as given, not as a request for operator consent.
Declared grants supplement hand-made grants without creating `read_grants` rows.

**Admission is conjunctive.** A declaration is admitted only when all of these hold:

- The bind principal is `Principal::Reserved` (`reserved:<module>`).
- `caller` is present, its `claim` is `Own` (`own` on the wire), and `first_party` is true.
- Both `declaration` and a non-empty `declaration_digest` are present.
- At bind, the channel's `route_caller` is `RouteCaller::Principal(Some(p))`, with `p`
  equal to the bind principal.

`Member`, `Phone`, `Refused` and `Principal(None)` never qualify, including a callosum
`fed-` route with its principal-mapping gate off. Relay claims and third-party binds
get no declared grants. `origin` is recorded but does not gate admission.

**Declaration schema and closed operation set.** The top-level object is
`{"v":1,"grants":[entry, ...]}`. Each entry has exactly one of these shapes:

| Selector shape | Allowed `operation` strings |
|---|---|
| `{"category":"<category>","operation":"<operation>"}` | `read`, `list`, `deposit` |
| `{"audience":"<audience>","operation":"account_token"}` | `account_token` |

The operation string is checked against this closed set before other entry validation.
Other strings are skipped with reason `operation`, even when they are valid hand-grant
operations: `sign`, `open`, `seal` and `policy_token` are not declarable, and
`account_token` is declarable only with an audience selector.
Every whitelisted entry must also pass the same full-tuple validation as `ck auth grant`
for the reserved module, selector kind, selector and operation. Category names must satisfy
the vault's category-name grammar; `deposit` is valid only for `browser-session`.
Audiences must be in the vault's account-token audience allowlist (`ACCOUNT_TOKEN_AUDIENCES` in credentials-core).
For example, `{"category":"llm-provider","operation":"deposit"}` grants nothing.

Unknown top-level keys are ignored. A version other than `v:1`, a missing or non-array
`grants`, or more than **32 raw entries** rejects the whole declaration; the cap is
checked before deduplication. Unknown entry fields, non-string entry values, refused
tuples, `exact` selectors and all other entry shapes are skipped whole, because an
unknown field could have been intended to narrow the authority. Duplicates collapse.
A valid empty array grants nothing and does not warn. Rejection or skipped entries never
fail the bind; they produce one WARN per (module, declaration digest) per process,
identifying skipped indices and reasons, or the whole-declaration reason. Apart from
validated category or audience names, entry values are never logged.

**Route lifetime and effective authority.** The admitted set belongs to the route's
bind state: re-bind replaces it and Goodbye drops it. A declaration can change within
one module process. Each change bumps the attestation's `authority_epoch`, and the
daemon closes that module's routes with close reason `authority_changed`. A declared
grant never outlives the bind it came from; it is not process-wide authority.

For each accepted request, the dispatcher captures the route's declared set together
with its caller before spawning the handler. That set joins the principal's hand-made
grants, deduplicated, **only when the request's resolved principal is the same
`reserved:<module>` as the captured bind principal**. A later re-bind cannot lend its
set to an already accepted frame. Enrollment tokens resolve first: a request carrying
`enrollment_token` never sees the declared set, whether the token is valid or invalid.
This also applies to `auth.watch_scoped`.

Under that predicate, declared `read`, `list`, `deposit` and `account_token` grants cover
the same scoped operations as equivalent hand-made grants, including individual
credential-id requests covered by a category and remote records. Before consulting any
grant, the transfer-key fence checks the resolved principal and key use: category coverage
cannot expose vault transfer keys beyond callosum's announcement access, and secret-deposit
keys remain inaccessible. First-use diagnostics remain under the resolved principal.
`sign`, `open` and `seal` still require hand-made grants. For `credential.list_scoped`,
the union replaces the caller's grant list before existing filtering and projection:
`deposit` remains absent from row `operations` and `grant_tuples`,
`grants == grant_tuples.length`, and the view digest follows the resulting rows and
tuples. `auth.watch_scoped` captures the subscribing route's declared set and principal
at subscribe. No new `credential.*` reply field is added. `connectors.list`,
`permissions.list` and `permissions.revoke` are unchanged.

**Last-seen inventory and audit.** Schema step 45 adds `declared_grant_sets`, keyed by
`module_id`, with `declaration_digest`, `approved_declarations_digest`, `origin`,
`grants_json`, `skipped_count` and `first_seen_ms`. `grants_json` is a compact JSON array
of `{"selector_kind":"category","selector":"<selector>","operation":"<op>"}` objects
(`selector_kind` is `category` or `audience`), with keys in that order, sorted by the
text-byte order of `(selector_kind, selector, operation)` and deduplicated. A rejected
declaration stores `[]`; `skipped_count` is advisory, and for a whole-declaration rejection
counts raw entries (zero when `grants` is not an array).

On an admissible bind, a missing row or a change to `(declaration_digest, grants_json)`
writes the whole row and one `declaration_seen` audit row in one transaction before
the bind is acknowledged; `first_seen_ms` is the time of that change. The audit actor is
`reserved:<module>`, target `declaration|<digest>` (or `declaration|none` when cleared),
and `payload_hash` is plain lowercase-hex SHA-256 of the exact canonical `grants_json`
bytes. The audit chain format is unchanged. An unchanged key writes nothing, even when
`approved_declarations_digest` or `origin` differ; those columns describe the last key
change. A store read or write failure leaves the route with no declared grants and a
WARN; the next bind retries.

A first-party bind meeting all other admission conditions with both `declaration` and
`declaration_digest` absent clears an existing non-NULL digest to NULL and stores `[]`,
with the same audit transaction. With no row or an already-cleared row it writes nothing.
Only one of the pair present, or an empty digest, grants nothing, warns and leaves the
stored row untouched. Other inadmissible binds also leave it untouched. The table is
the **last declaration each module presented**, not live authority: an uninstalled
module's row authorizes nothing, and a route bound earlier may have captured an older
set than the inventory shows.

#### Optional `admin.op` grant inventory fields

The existing authenticated admin transcript is unchanged. These are additive reply
fields; no existing Status field changes:

| Admin body (`AdminOpBody` variant) | Addition |
|---|---|
| `admin.status` (`Status`) | Optional `declared_grants`: an array of `{module_id, selector_kind, selector, operation, first_seen_ms}`, sorted by module then canonical tuple order; omitted when empty. |
| `admin.status` (`Status`) | Optional `declared_grants_incomplete: true` if the table cannot be read or any stored `grants_json` fails to parse. Unreadable rows are omitted with a WARN; a table failure omits `declared_grants`, without hiding existing status or hand grants. |
| `admin.status` (`Status`) | Optional `settings_grants`: last-seen rows `{module_id, selector_kind:"exact", selector, operation:"read", first_seen_ms, source:"settings"}`, sorted by module and id; omitted when empty. `first_seen_ms` is the arrival time of the last changed snapshot. |
| `admin.status` (`Status`) | Optional `settings_grants_incomplete: true` if the table cannot be read or a stored snapshot fails validation. Unreadable snapshots are omitted without hiding other status fields. |
| `admin.grant_create_v2` (`GrantCreateV2`) | Optional `declared_covers: true` when the module's last-seen stored set already contains the tuple; the hand grant is still created normally. |
| `admin.grant_revoke_v2` (`GrantRevokeV2`) | Optional success field `declared_still_listed: true` when a matching hand-made row was revoked but the stored declaration still lists the tuple. |

`GrantRevokeV2` of a tuple present only in the stored declared set refuses with
`declared_grant` / `permanent`. The remedy names the module's approved declaration in
the daemon's configuration: change that approval, then let the module re-bind (restart
the module). The stored row is replaced at that bind; a vault-side revoke cannot
override declared authority. An unreadable or unparseable stored row never counts as
covering a create or revoke.

`GrantRevokeV2` of an exact read tuple present only in the settings inventory also
refuses with `declared_grant` / `permanent`. Its remedy says to remove the reference
from the module's approved setting. A matching hand grant can still be revoked normally.

A new CLI with an old daemon sees no declared inventory; an old CLI ignores the new
fields. `ck auth list` (including `--json`) and `ck auth status` output are unchanged.
Plain `ck auth grants` keeps stdout byte-identical, including `no grants`; when declared
rows exist it prints a one-line stderr pointer to `ck auth grants --declared`.
The opt-in command lists only well-formed declared rows, under
`declared grants (last declaration each module presented):`, with columns
`MODULE  SELECTOR KIND  SELECTOR  OP  REACHES  FIRST SEEN`. Category reach comes from
the same credential inventory as hand grants; audience reach is `token`. Zero
well-formed rows produce no declared table. Malformed reply elements are dropped;
incomplete inventory produces one stderr line without interrupting hand-grant output.
Offline mode reads the table read-only; a step-44 store has no declared output or warning.
When available, `--declared` also prints a separate settings inventory with `SOURCE`
set to `settings`; it does not add rows to plain `ck auth grants`.

#### Key references in approved settings

On stamped installs, the supervisor includes `settings_credentials: {generation,
refs}` in the `caller` attestation of `route.bind`. `generation` is the approved
configuration revision (0 to 2^53−1, like the other attestation integers). `refs` contains the sorted,
deduplicated credential ids from the calling module's approved user settings. An
empty list replaces the last list with no keys. An absent member conveys no settings
authority and leaves the last-seen inventory alone.

The vault admits the member only for an `own` claim on the matching `reserved:<module>`
principal route. `first_party` is not required. Relay claims, `fed-` routes, phones and
enrolled consumers do not inherit this authority. A member with over 32 raw refs or
any id that is not 1–256 printable ASCII bytes without spaces grants nothing and does
not fail the bind. The vault warns once per module and generation and logs no ids.

Each listed id supplements hand and declaration grants with exact `read` while its
record is an API key (`apikey`, including gateways). Use is pinned to the checked
incarnation and version. Other kinds answer the same `not_found` as an uncovered id.
No other grant operation is implied, including `list`, `sign`, `open`, `seal`,
`deposit`, `account_token` and `policy_token`. A settings grant adds no category grant.
The daemon closes the module's routes when the approved references change, and a
new bind replaces the earlier route's captured authority.

Schema step 55 stores each module's last-seen generation, canonical refs, their
SHA-256 and seen time. A changed generation or list writes one `settings_refs_seen`
audit row in the same transaction before the bind succeeds. A repeated snapshot
writes nothing. A store failure grants nothing for that member. The inventory is
not consulted when authorizing a read.

#### Approval wording

The code in `crates/credentials-core/src/store_declared_grants.rs` is the source of the wording, pinned with the live category table in `crates/credentials-core/tests/vectors/declared-grants-v2.json` and its companion `declared-grants-v2.SHA256SUMS`. The published `declared-grants-v1.json` remains byte-identical; its parser cases and approval wording are still checked against live code, but its category table is a historical snapshot. Regenerate v2 with `CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-core --features test-support --lib declared_grants_v2_vectors_are_emitted_by_parser_and_wording_code_and_pinned`.

The following is **the vault's approval text** for desktop daemon-approval screens.
Substitute the category's plain name from the table below and the literal audience;
fall back to raw JSON for an unrecognized declaration shape.

| Declarable shape | Vault text |
|---|---|
| Category `read` | Read your &lt;category name&gt; logins and keys |
| Category `list` | See which &lt;category name&gt; logins and keys exist (no secrets) |
| Category `deposit` | Save browser sign-ins into the vault (&lt;category name&gt;) |
| Audience `account_token` | Get short-lived CortexKit account tokens for &lt;audience&gt; |

The table covers the current catalog's purpose categories and native families, plus
its built-in browser-session and GitHub App families (`CredentialCategory`,
`category_defaults` and `native_family_category`). Native families are derived from
adapter names, so they are not a closed vocabulary.
For a category not in the table, show the raw category name unchanged.

| Category | Plain name |
|---|---|
| `llm-provider` | model provider |
| `llm-gateway` | company AI gateway |
| `data-warehouse` | data warehouse |
| `cloud-infrastructure` | cloud infrastructure |
| `web-search` | web search |
| `media-provider` | speech and media |
| `embedding-provider` | embedding models |
| `browser-session` | browser sign-in |
| `antigravity-native` | Antigravity |
| `anthropic-native` | Anthropic |
| `cursor-native` | Cursor |
| `devin-native` | Devin |
| `digitalocean-native` | DigitalOcean |
| `github-app-native` | GitHub bot |
| `github-copilot-native` | GitHub Copilot |
| `gmail-native` | Gmail |
| `google-native` | Google |
| `kimi-native` | Kimi |
| `meta-native` | Meta AI |
| `openai-native` | OpenAI |
| `snowflake-native` | Snowflake |
| `xai-native` | xAI |

## 3. Reading a credential

`credential.get` returns the opaque payload as a JSON array of byte integers, plus
`expires_at_ms` and `record_version`, plus non-secret metadata where the vault has it
(`credential_id`, `account_id`, `email`, `org_name`, and `project_id` for `antigravity`).
Use `credential_id` only to verify a handle-to-manifest binding, never to route: it is an
operator-chosen label. Account routing pools on `account_id` (with the refresh adapter from
`list_scoped`), never on `record_version`: that bumps on every token refresh, so a key that
includes it splits one account into a new pool per refresh.

`credential.get_scoped` also projects an API-key descriptor from this vault's catalog
or provider registry when the credential id resolves to a row with hosts and auth,
including labeled ids such as `apikey:openai:work`. The fixed catalog takes precedence
over registrations. Local gateway settings take precedence over both (see
Company AI gateway credentials below). The three top-level fields are served together:

- `auth: {header, scheme}`: `header` is a lowercase HTTP header name; `scheme` is
  `bearer` (`Bearer <key>`) or `raw` (the key alone).
- `hosts: [..]`: exact lowercase receiving host names, sorted without duplicates,
  with no scheme, port, path or wildcard. A gateway's IPv6 loopback host is the
  bracketed string `[::1]`.
- `invalid_key: {status, error_code, error_code_field} | null`: an observation of
  what a deliberately bogus key returned. `status` is the HTTP status;
  `error_code_field` is an RFC 6901 JSON Pointer to the observed string `error_code`.
  Those two code fields are null together when no string code was observed. The
  vault never evaluates this evidence. `invalid_key: null` means the descriptor is
  known but no invalid-key observation is recorded.

Login records with the following refresh adapters carry `hosts` alone, without
`auth` or `invalid_key`. The lookup uses the refresh adapter, not the credential id.

| Refresh adapter | `hosts` |
| --- | --- |
| `anthropic` | `["api.anthropic.com"]` |
| `openai` (ChatGPT) | `["chatgpt.com"]` |
| `antigravity` | `["cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com"]` |
| `xai` | `["api.x.ai"]` |
| `meta` | `["api.meta.ai"]` |

All three fields are absent for other login providers, no-descriptor catalog rows,
registered providers without hosts, and non-provider records such as cookies or
manual ids. An absent `hosts` means the vault has no host fact, never that any host
is allowed. An absent `invalid_key` is not the same as `invalid_key: null`.
The fields are read-time projections of provider or per-credential gateway settings.
Registered providers with a descriptor always serve `invalid_key: null`. Remote
records use the reading vault's own catalog and registry too; no descriptor fields
cross federation. `credential.get` (and its handle-based batch form) never serves
these fields.

`account_id` IS THE PROVIDER'S ACCOUNT IDENTIFIER AND ITS SHAPE IS THE PROVIDER'S CHOICE.
Treat it as an opaque string. It is stable per account and comparable to itself, and
nothing more: do not validate it against a pattern, do not compare values across
providers, and do not infer from one provider's shape what another's will be. On a live
vault today Anthropic and OpenAI serve UUIDs and Google serves an email address, so a
consumer that assumes UUID shape breaks on a REAL value rather than a missing one — which
presents as a parse error on good data, the least legible failure available.

**A handle survives repair of the credential it names.** An operator repairing a dead
credential (`login --replace`, `put --replace`) resets it to `active` and bumps
`record_version` without touching the handles table, so a handle held across the repair
keeps resolving and starts serving the new secret. A consumer that paused on
`needs_reauth` resumes with the handle it already holds. A handle stops working only by
explicit revocation (`revoke-handle`, `revoke-all-handles`) or when the credential is
taken out of service (`invalidate`, `logout`), so a handle that stops resolving means
someone withdrew it, never that the credential behind it was fixed.

Two optional levers, and they are the same lever pointed differently:

- `force_refresh: true` — exchange before serving if the record has a refresh adapter.
  A record with no refresh adapter still serves its stored secret.
- `min_ttl_ms: <n>` — exchange if the token has less than `n` remaining.

`min_ttl_ms` is evaluated **only when you supply it**. There is no implicit floor, and
the refusal (`ttl_unsatisfiable`) fires only after a real exchange has proven the demand
unmeetable — never speculatively.

**Caching.** Do not keep a persistent fallback copy of a served credential. A consumer may
hold a short-lived in-memory copy of the token it needs for in-flight calls, keyed by
`record_version`, and must discard it when `record_version` changes or a read answers
`needs_reauth`. When the vault is unreachable, retry the route and the read a bounded number
of times, then fail clearly.

### `credential.list_scoped`

`credential.list_scoped` takes `params: {}` for the ambient principal, or
`params: { "enrollment_token": "<token>" }` for an enrolled principal, and returns
`{ "result": { credentials, grants, grant_tuples, view } }`. The only accepted param
is the optional `enrollment_token`; unrelated fields, including filters and `token`,
are `invalid_params`. `token` is not an alias for `enrollment_token`.
Rows are sorted by id. `categories`, lifecycle `state`,
`record_version`, derived `type`/`serves`, and the caller's covering `operations` are
non-secret; no credential payload is returned. Identity and `refresh_adapter` are
projected only when the caller holds `read` or `list` for that row, never for a row it
reaches only through `sign` or `open`. `operations` names every covering operation,
including `list`; decode it as an open set of strings.

`operations` is an **authorization fact**: it says which of this caller's grant rows cover
the id. It does not promise that the sealed record kind or lifecycle state can serve that
operation; record-level refusals such as `kind_not_signable` still apply after coverage.
`grant_tuples` returns the caller's own `{selector_kind, selector, operation}` rows and
`grants == grant_tuples.length`. `view` is the deterministic SHA-256 validator over the
returned rows and tuples; changes outside the caller's visibility do not move it.

`org_id` is an optional top-level string on local API-key rows with read or list
coverage. It is omitted when unknown, not returned as null. It identifies the provider
organization, not the credential's account, and does not change `account_id`.
The daemon learns it for Anthropic API keys from `anthropic-organization-id` on a
successful models probe. The value is 1 to 128 bytes and contains only ASCII
letters, digits, `-`, `_`, `.`, and `:`. The observation applies only to that
credential version and incarnation. It neither rewrites the sealed record nor
changes the credential's state on a failed probe. If the caller can see the learned
organization, `auth.watch_scoped` signals the new `view` and the caller can re-list.
Rust client 0.16.0 exposes `org_id` and TypeScript client 0.23.0 exposes `orgId`.
Both accept omission; a present invalid value (including null) makes the Rust row
undecodable and the TypeScript listing invalid.

### Provider metadata, plan tier and authentication method

Two provider-id fields answer different questions:

| Field | Meaning |
|---|---|
| `provider_ids` | Stored routing ids, per credential, in ascending byte order; `[]` when unset. |
| `fusiform_provider_id` | One Fusiform provider id per provider row, projected at read time from the catalog or registration; omitted when unmapped. |

Apps join to Fusiform's provider card (name, logo and docs) on `fusiform_provider_id`,
not on the routing `provider_ids`. The provider-card mapping is optional; rows omit
it when no provider-card mapping is available. Every `credential.list_scoped` row
carries its stored `provider_ids`.
`ck auth put` and API-key or subscription `ck auth login` store the catalog row's
defaults at creation when no `--provider-id` is given. Explicit ids win over defaults;
replacement preserves an existing set. Existing records are never automatically
remapped. The vault never derives these ids at read time from the credential id,
catalog, adapter, or `serves`. `ck auth provider-report` compares stored ids with the
current table without changing any record, taking no writer lease.
New OpenAI API keys (`apikey:openai` and `apikey:openai:<label>`) default to
`provider_ids: ["openai-platform"]`. ChatGPT sign-ins (`chatgpt:openai` and labeled
variants) still default to `provider_ids: ["openai"]`. The API-key row still lists
`serves: ["openai"]` and `fusiform_provider_id: "openai"`.

The OpenAI and Google API-key rows default to both `llm-provider` and
`media-provider`; ElevenLabs defaults to `media-provider` alone. The 302.AI, Abacus,
AIHubMix, AI/ML API, Alibaba, Alibaba (China), Alibaba Token Plan, Alibaba Token
Plan (China), DigitalOcean, Eden AI, FastRouter, Vertex (express mode), Kenari,
Kilo Gateway, Merge Gateway, NaN, NEAR AI Cloud, Poe, Qiniu, Regolo AI, Requesty and
StepFun (China) rows
(`302ai`, `abacus`, `aihubmix`, `aimlapi`, `alibaba`, `alibaba-cn`,
`alibaba-token-plan`, `alibaba-token-plan-cn`, `digitalocean`, `edenai`,
`fastrouter`, `google-vertex`, `kenari`, `kilo`, `merge-gateway`, `nan`, `nearai`,
`poe`, `qiniu-ai`, `regolo-ai`, `requesty`, `stepfun-cn`) also default to
both. These are the media rows. Routing stops choosing a media key
its consumer reported unfunded, and lifts that after a successful run. Category
defaults apply to creation, not existing records or replacements with stored categories.
Consumers join on exact provider-id equality, with no fallback. `serves` answers which
model vendors are reachable; `provider_ids` answers which catalog providers the operator
assigned to this credential. They are not interchangeable.

List rows carry `hosts` exactly when `credential.get_scoped` would serve `hosts`
for the same record: a nonempty array of exact receiving host names from this vault's
gateway settings, catalog or registry, in served order. Otherwise the field is
omitted, not null or `[]`. This applies equally to local and remote rows, including
labeled ids. Like the descriptor, it is a read-time projection, never a stored
routing fact; no remote descriptor is trusted or sent across federation.

Three additive fields are present on every current row:

- `provider`: the vault's **service name**, not a routing provider id (for
  example `zai`, `kimi-for-coding`, `ollama-cloud`). API-key and login rows use the
  same catalog match that stamps categories, including labeled accounts. API-key
  services registered by the operator with `ck auth provider set` are also named,
  including labeled keys; the fixed catalog always wins. An unregistered unknown
  row is `null`. Consumers must use this field, not split the credential id.
- `incarnation`: the stored random per-row identity. Replacement and refresh keep
  it; removal followed by re-creation changes it, even when other metadata is equal.
  A row this vault reads from its home vault carries this vault's own registration
  of it, so `ck auth remote remove` followed by `ck auth remote add` changes it.
- `plan_tier_observed_at_ms`: the first proven observation of the effective current
  `plan_tier`, in Unix milliseconds, or `null` when unknown. Detection uses the
  detection instant. A Claude profile fetched after token renewal waits in a durable
  side table until the next token commit; its detection time, not that later commit
  time, is the time used when its tier becomes effective.
   Same-value refreshes and date-only operator edits do not move it. An operator tier uses its initial `set-plan` commit
  time; clearing the override restores the detected value's time. Like the tier,
  this time requires read/list coverage; sign/open-only rows carry `null`.

`plan_tier_since_ms` is an optional effective start in Unix milliseconds for an
operator-set tier (migration 44). It is emitted only when the effective tier source
is `operator` and the operator supplied a date, and only on account-identity rows
with read/list coverage. Otherwise the key is omitted. Consumers price from
`plan_tier_since_ms` when present, falling back to `plan_tier_observed_at_ms` when
absent. It is not a detection or token-refresh time. Both clients decode it as an
optional non-negative integer; a present wrong type refuses decoding, as with the
other plan fields (row-local in Rust, whole-reply in TypeScript).

Migration 44 adds nullable `since_ms` columns to both `credential_plan_tiers` and
`remote_record_plan_tiers`, without backfill. Remote operator assertions belong to
this computer and are not sent to the home vault; no federation wire field changes.

Migration 36 adds nullable times for operator assertions and remote detections.
Local current-value detection times are sealed beside the existing detection
metadata. No old time is backfilled: existing records stay unknown until their
tier next changes. Reasserting an unchanged operator value is still a no-op.
Both clients decode these three fields as optional; omission by an older vault and
explicit `null` both mean absent. The TypeScript names for them are `provider`,
`incarnation` and `planTierObservedAtMs`; Rust uses the wire spellings on
`ListedCredential`. The Rust client applies the same null-is-absent rule to
`plan_tier_since_ms`, `org_id` and `github_app`.
`ck auth list --json` includes the same fields (and nulls), including
`plan_tier_since_ms`, in each ordinary row.
Gateway rows additionally carry `base_url` and `headers`.

A local `github_app:<slug>` row covered by `read` or `list` carries
`"github_app": {"app_id": "12345", "slug": "<slug>"}` once a hand-added App's
refresh has recorded these values from the matched installation. A vault-created
App carries the pair from creation, plus `created_by: "vault"`, an integer
`created_at_ms` (Unix epoch milliseconds), and `agent` (the registry agent id).
The three attestation members are either all present or all absent; the Rust
client rejects partial or ill-typed attestations. `app_id` is the App's ID, not
the installation's ID, and is a canonical decimal string (`[1-9][0-9]*`).
`slug` is the suffix of the credential ID. Refresh never changes an attested
identity; for hand-added Apps, refresh without valid App metadata keeps the
recorded pair. The member is omitted before a hand-added App records a pair,
after an admin overwrite until a refresh records a new pair, on rows reached
only through other operations (including `policy_token`), and on remote rows.
The webhook companion does not appear in credential inventory.

`auth_method` is `gateway` when the credential has gateway settings; otherwise it is
derived from the unsealed record's `(CredentialKind, refresh_adapter)`.
It is present only on read/list-covered rows when the table below yields a value; otherwise
the key is omitted, never null or `""`. Sign/open-only rows remain sealed and omit it,
including rows with corrupt envelopes; their stored `provider_ids` are still returned.
A read/list row already quarantined as `state: "corrupt"` is listed the same way, sealed
and without identity, so one quarantined credential never hides the rest of the listing.
An unseal/decode failure on a read/list row still stored as readable fails the whole
snapshot with `store_error`: that is corruption the vault hasn't recorded yet.

The closed values are `apikey`, `chatgpt`, `antigravity`, `oauth`, and `gateway`.
Adding a value is a breaking wire change and requires a breaking client bump
(minor while the client is 0.x).
Unlike the id-derived `type`, this field never parses the id and does not rewrite `type`
or `refresh_adapter`. Both `chatgpt:openai` and `oauth:openai` store adapter `openai` and
report `chatgpt`; antigravity still has `type: "oauth"`.

| Credential kind | Stored refresh adapter | `auth_method` |
|---|---|---|
| `ApiKey` with gateway settings (takes precedence) | absent | `gateway` |
| `ApiKey` | absent or any string | `apikey` |
| `Oauth` | `anthropic` | `oauth` |
| `Oauth` | `openai` | `chatgpt` |
| `Oauth` | `google` | `oauth` |
| `Oauth` | `gmail` (login id `oauth:gmail[:<label>]`) | omitted |
| `Oauth` | `xai` | `oauth` |
| `Oauth` | `kimi` | `oauth` |
| `Oauth` | `meta` | `oauth` |
| `Oauth` | `cursor` | `oauth` |
| `Oauth` | `github-copilot` | `oauth` |
| `Oauth` | `antigravity` | `antigravity` |
| `Oauth` | `github_app` | omitted |
| `Oauth` | `devin` | omitted |
| `Oauth` | `digitalocean` | omitted |
| `Oauth` | `snowflake` | omitted |
| `Oauth` | absent or any other string | omitted |
| `Dsn`, `Cookie`, `Opaque`, `SigningKey`, `KemKey` | anything | omitted |

Gmail login uses the operator's Desktop OAuth client and the `gmail` refresh
adapter. It stores `account_id = email` from Google userinfo and refuses login
without an email or refresh token. Its sole default category is `gmail-native`
(including labeled ids); it has no `serves`. Reads deliver only the current access
token with the existing identity metadata, never the sealed client secret or
refresh token. No wire shape or store schema migration is required.

Provider-id and tier edits do not bump `record_version`: observers use `view`. Its domain stays
`claustrum.list_scoped.view.v1`. Inside each credential frame, immediately after the
`org_name` optional-string frame, append a u32 provider-id count and each string-framed id
in ascending byte order, then `auth_method` as an optional string, then `plan_tier` and `plan_tier_source` as
optional strings, then `provider` as an optional string, `incarnation` as a string,
and `plan_tier_observed_at_ms` as an optional decimal-string frame. Only when
`plan_tier_since_ms` is present, append byte 3 and its length-prefixed decimal
string. No bytes are appended for an absent date, preserving existing undated
views. After the condition extension (byte 4), if present, append byte 5 and
length-prefixed strings for `github_app.app_id` and `github_app.slug`, in that order,
only when `github_app` is visible. If it carries attestation, append byte 6 and
length-prefixed strings for `created_by`, `created_at_ms` in decimal, and `agent`,
in that order. An absent identity or attestation adds no bytes of its own.
Next frame `fusiform_provider_id` as an optional string (byte 0 while unmapped), then `hosts`:
byte 0 when absent, or byte 1, a u32 host count, and each host as a length-prefixed
string in served order. The absent optional frame is used whenever the JSON key is
omitted, never an empty string. After `hosts`, append byte 7 and a length-prefixed
`org_id` string only when `org_id` is present. Rows without `org_id` add no bytes
and retain the same view framing. Adding the provider-id count and the auth-method
presence byte changed every nonempty view once, even when provider ids and methods
were unset. Empty views were unchanged. Subsequent edits move only views whose
returned rows include that credential. A committed registry
hosts change moves the affected view and wakes `auth.watch_scoped` through the store's
committed-write notification path; a token-only refresh does not. Catalog host changes
arrive with a new binary and appear in the watcher's initial snapshot.

The TypeScript client 0.8.0 exposes `providerIds`, optional `authMethod`, optional
`planTier`, and optional `planTierSource` (`operator` or `detected`). An absent source
means unknown, including replies from older vaults. A present null or unknown source
refuses the whole reply. Absent `provider_ids` decodes as `[]` for older vaults; present null, non-array
or non-string-element values refuse the whole reply. Any string element is accepted.
Present null, non-string, empty or unknown `auth_method` also refuses the whole reply.
Absent `plan_tier` means unknown and decodes as `undefined`, including against vaults
without migration 16. Present non-string or syntactically malformed tiers refuse the
whole reply with `invalid_response`, just like malformed provider metadata. The 0.8.0
minor bump changes an exported type.

The Rust client `cortexkit-claustrum-client` 0.1.0 exposes `provider_ids` and optional
`auth_method` on `ListedCredential`. It retains the supervised consumer's row-local
decoding: malformed credentials are skipped into `undecodable_credentials`, not logged
by the library. Grant tuples require non-empty string `selector_kind`, `selector` and
`operation`; malformed tuples are skipped into `undecodable_grants`, leaving healthy
tuples available. This differs from the TypeScript client's whole-reply refusal above.

### Company AI gateway credentials

A gateway credential is one sealed API key and non-secret, per-credential settings.
It is created atomically by the create-only `admin.gateway_create` op, never by an
`admin.store` fallback. Its id is `apikey:<provider-id>[:<label>]`, its kind is
`ApiKey`, and it has no refresh adapter. Its sole provider id is
`<fusiform-id>-gw-<slug>`, equal to the service part of the id. The prefix is one of
the 16 model-vendor Fusiform ids, split at the first `-gw-`; the slug is 1–32 bytes,
starting with a lowercase ASCII letter and continuing with lowercase letters,
digits or hyphens. `serves` is the prefix's model vendor (for example,
`moonshotai-gw-x` serves `["moonshot"]`), not a parsed routing instruction.

Creation assigns exactly `["llm-gateway"]`, never `llm-provider`. **Category
membership is not a gateway discriminator:** operators can also assign an ordinary
API key to `llm-gateway`. Readers select gateway rows by `auth_method: "gateway"`
in listings, and by a present `base_url` in `credential.get_scoped`. A service name
containing `-gw-` alone does not make an ordinary key a gateway.

For a local gateway, `credential.get_scoped` serves these top-level fields together:

- `base_url`: the API root (scheme, host, optional port and path prefix).
- `auth: {header, scheme}`: the configured lowercase header and `bearer` or `raw`.
- `hosts`: exactly the base URL's host without its port, including brackets for
  `[::1]`. `credential.list_scoped` serves the same single host.
- `headers`: a name-to-value object of fixed non-secret headers, in ascending byte
  order by name. It is always present, including `{}` when none were configured.
- `invalid_key: null`: no key-check observation is made at enrollment.

Settings override both catalog and registry descriptors. A read serves settings
only for the incarnation of the record whose key it read; removal and re-creation
cannot pair an earlier key with later settings and instead answers `not_found`.
Non-gateway replies omit `base_url` and `headers` entirely, never sending nulls;
their existing descriptor bytes are unchanged. Remote records retain the catalog
and registry descriptor lookup and never acquire gateway fields. Gateway list rows
have no `fusiform_provider_id`. Admin inventory and `ck auth list --json` append
`base_url` and `headers` only to gateway rows, preserving existing keys and order.
The human list shows the base URL and fixed-header names, not their values.

Normal form is checked by the shared core validator: lowercase URL scheme and host,
no trailing slash, lowercase header names, trimmed header values, and strictly
ascending, unique header names. The CLI normalizes input; the store refuses
non-normal-form input rather than repairing it. The URL is at most 512 bytes,
contains no query, fragment, user info, percent encoding or dot path segments, and
does not end in `/messages` or `/v1/messages` (ASCII-case-insensitive). `https`
accepts a lowercase DNS name or the exact loopback literals `127.a.b.c` and `[::1]`;
`http` accepts only those literals or exact `localhost`. DNS labels follow the
registry's lowercase label grammar, with no empty labels or trailing dot; the last
label cannot be all digits or `0x` followed by zero or more hex digits. IPv4 parts
are decimal 0–255 without leading zero; other IP spellings are refused. A port is
1–65535 in 1–5 decimal digits without leading zero, and an explicit default port
is preserved. Auth and fixed-header names are 1–64-byte lowercase HTTP tokens.
There are 0–8 fixed headers; each value is 1–1,024 bytes of ASCII 0x20–0x7E without
surrounding spaces, and must not parse as a JSON object or array. Fixed headers
cannot use the auth header name, `host`, `content-length`, `transfer-encoding`,
`connection`, `keep-alive`, `proxy-connection`, `te`, `trailer`, `upgrade`, `cookie`,
`authorization`, `proxy-authorization`, or `x-api-key`. These guards do not prove a
value is non-secret; that remains the operator's responsibility.

Settings are fixed until removal and re-creation. Replacing the key keeps settings,
categories and provider ids, but refuses a non-API-key kind or refresh adapter.
Category/provider changes refuse; requests resulting in the current set remain
silent no-ops. Reclassification skips gateways, even when forced. An ordinary
credential cannot acquire a provider id containing `-gw-` through `set` or `add`;
`remove` can repair an old stored id. Registered-provider defaults cannot contain
that marker, nor can a registered service name.

Every refusal below leaves the credential, version, incarnation, settings,
categories, provider ids and audit log unchanged. A refused creation writes none
of them. The admin refusal envelope gains no fields. The first two codes carry
`rule=<token>` in the message and never echo a header value.

| Operation / refused input | Code | Rule or reason |
|---|---|---|
| Creation: wrong id shape | `invalid_gateway_settings` | `rule=credential_id` |
| Creation: non-API-key kind or refresh adapter | `invalid_gateway_settings` | `rule=kind` |
| Replacement: non-API-key kind or refresh adapter | `gateway_fixed` | `rule=kind` |
| URL shape, host or port | `invalid_gateway_settings` | `rule=base_url` |
| URL endpoint suffix | `invalid_gateway_settings` | `rule=base_url_path` |
| URL over 512 bytes | `invalid_gateway_settings` | `rule=base_url_length` |
| Auth header or scheme | `invalid_gateway_settings` | `rule=auth` |
| More than 8 headers | `invalid_gateway_settings` | `rule=header_count` |
| Header name grammar, length, ordering, repeat or refused name | `invalid_gateway_settings` | `rule=header_name` |
| Header value bytes, length or JSON | `invalid_gateway_settings` | `rule=header_value` |
| Category change | `gateway_fixed` | `rule=category` |
| Creation: provider count, shape, prefix, slug or service mismatch | `invalid_gateway_settings` | `rule=provider_id` |
| Provider-id change | `gateway_fixed` | `rule=provider_id` |
| Ordinary key's added id or registered default contains `-gw-` | `invalid_provider_id` | `rule=reserved` |
| Registering a service containing `-gw-` | `invalid_service_name` | none |
| Federation transfer | `transfer_ineligible` | `reason: "gateway"` |

Gateway keys never leave the vault through federation. Remote reads under exact or
category grants answer `not_found` (diagnostic `ineligible`), and peer watch rows
exclude gateways. The transfer refusal is the `Ineligible::Gateway` reason.

`ck auth put` accepts `--gateway-base-url`, `--gateway-auth-header`,
`--gateway-auth-scheme` and repeatable `--gateway-header name=value`, plus exactly
one `--provider-id`. Any gateway flag without the base URL, or with `--replace` or
`--expected-hash`, is a CLI usage error before any op. Without gateway flags,
explicit reserved provider ids, and any `--provider-id` on a marker service, are
also refused before sending an op. Inherited legacy reserved defaults are refused
before storing, naming the registered service and `ck auth provider set` repair.

Creation appends exactly two audit rows: the normal bare-id birth row holding the
keyed payload fingerprint, then `gateway_create` with null `payload_hash` and target
`gateway:<credential-id>|<digest>`. The digest is SHA-256 as 64 lowercase hex digits
over UTF-8 compact JSON of normal-form settings, with keys in this exact order:
`base_url`, `auth` (keys `header`, then `scheme`), `headers` (names ascending by
byte). There is no whitespace; strings use `serde_json` escaping. Provider ids and
the secret key are not digest inputs. The producer-pinned settings sample listed below
contains the input and expected digest.

#### Producer-generated gateway samples

TEST-ONLY samples in `crates/credentials-module/tests/vectors/` are generated by
the vault's real handlers and CLI, with hashes in `SHA256SUMS`:

| File | Coverage |
|---|---|
| `gateway-list-scoped-v1.json` | Gateway listing, including `hosts: ["[::1]"]`. |
| `gateway-get-scoped-v1.json` | Gateway key and descriptor with fixed headers. |
| `gateway-get-scoped-empty-headers-v1.json` | Gateway descriptor with `headers: {}`. |
| `get-scoped-non-gateway-baseline-v1.json` | Ordinary API-key reply, byte-identical to the pre-gateway capture. |
| `list-scoped-non-gateway-baseline-v1.json` | Ordinary listing, byte-identical to the pre-gateway capture. |
| `gateway-list-json-v1.json` | `ck auth list --json` inventory rows. |
| `gateway-refusals-v1.json` | Every refusal row above, with code and rule or reason. |
| `gateway-settings-digest-v1.json` | Normal-form settings input and expected digest. |

Regenerate deliberately with these commands, run serially; never edit sample
bytes or hashes by hand:

```sh
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module --features credentials-core/test-support --bin ck-claustrum tests::scoped_watch::gateway_scoped_vectors_are_producer_generated_and_pinned -- --exact --nocapture
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module --features credentials-core/test-support --bin ck-claustrum admin_surface::tests::gateway_refusal_vectors_are_producer_generated_and_pinned -- --exact --nocapture
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module --features credentials-core/test-support --test cli_admin gateway_list_cli::gateway_list_json_vectors_are_producer_generated_and_pinned -- --exact --nocapture
```

The scoped generator checks ordinary reply bytes against the captured baselines
even in emission mode, so regeneration cannot silently replace the baseline. The release
tag `gateway-keys-vectors-v1` is immutable once created; it is applied only after
gateway credential support and these samples are on master and CI is green.

### `admin.set_providers`

Only the operator's master-key HMAC authorizes this op;
no route op, module,
or enrolled consumer can write provider ids. Request body:

```json
{"op":"admin.set_providers","v":2,"credential_id":"apikey:zai","mode":"add","provider_ids":["zai-coding-plan"]}
```

`mode` is `set`, `add`, or `remove`. Success returns `{"provider_ids":["zai-coding-plan"]}`:
the resulting set, sorted in ascending byte order, even when unchanged or empty.
`set` with `[]` clears; empty `add`/`remove`, adding a stored id, and removing an absent id
are successful no-ops. The set read, validation, write, and transition audit are atomic.
No envelope is opened or re-sealed, and refusals change neither metadata nor audit.

Checks run in this order: each requested id's `charset` then `length`, then request
`duplicate` (naming the second occurrence), then credential existence, then gateway
immutability and reserved-id checks, then resulting-set `count`. Ids must start with
a lowercase ASCII letter and contain only lowercase ASCII
letters, digits, and hyphens; length is 2–64 bytes. At most 32 ids may result. Count names
the first requested addition crossing the cap; removing more than 32 valid ids is allowed.
An unknown credential refuses with `credential not found` live (the store's NotFound
Display offline), including for empty lists. Other refusals use the permanent
`invalid_provider_id` code and exact `rule=`/`value=` text above. The admin error envelope
gains no fields.

Transitions alone write audit op `set_providers` with target
`providers:<credential-id>|<sorted-comma-list>`, with no spaces; clearing leaves the
trailing `|`. Parse this provider target by splitting on the **last** `|`, since provider
ids cannot contain it. An unchanged set writes no audit entry and does not move `view`.

### Operator-asserted `plan_tier` (migration 16)

A credential can hold an operator override in migration 16's plaintext
`credential_plan_tiers` table. Pricing owns its vocabulary; arbitrary valid identifiers,
including future pricing plans, remain allowed. The vault also seals `detected_plan`
beside identity: the mapped tier (possibly absent), raw provider string (possibly absent),
and observation time in Unix milliseconds. No migration or record schema bump is needed:
records are JSON, and the decoder in `4ddc294` ignores unknown fields. Rollback reads them
but discards detection metadata when it rewrites a record.

Detection uses exact known strings only:

- ChatGPT (`openai` adapter): access-token JWT claim
  `https://api.openai.com/auth.chatgpt_plan_type`: `pro` → `pro_200`, `prolite` → `pro_100`,
  `plus` → `plus`. Read every newly minted token at login and refresh; no HTTP call.
- Claude (`anthropic` adapter): bearer `GET https://api.anthropic.com/api/oauth/profile`,
  `organization.rate_limit_tier`: `default_claude_max_20x` → `max_20x`,
  `default_claude_max_5x` → `max_5x`, `default_claude_pro` → `pro`. When that field is
  absent, `organization.organization_type` equal to `claude_pro` maps to `pro`.
  `claude_max` alone cannot distinguish the Max prices. These fields are grounded in
  public Claude Code examples, not an independently captured live profile.

Unknown provider strings, empty or missing claims yield no tier, never a guessed plan
(including a future OpenAI $500 plan). A successful unknown observation clears the old
detected tier. Network, non-200 and malformed profile responses keep the old observation.

Claude login bounds its profile request at five seconds before deposit; failure prints a
note and still deposits tokens. Refresh commits tokens immediately, then starts one
five-second-bounded profile request in the background. Its result is held in a separate
durable table, bound to the credential's version, access-token hash, and identity, and
folded into the **next** refresh commit, never an extra sealed write/version bump or
audit entry. A saved observation survives a restart; a best-effort persistence failure
only loses that observation. Applying it, replacing or removing the credential, or
finding a mismatched binding discards the held row.

Staleness follows token renewal: ChatGPT access tokens live about **10 days**, so a plan
change may take that long to appear. Claude tokens live about **8 hours**; profile work
runs each renewal (roughly three requests per account per day), but folding the result
into the following renewal can add another interval (about **16 hours** after a change
in normal use). Idle accounts or repeated profile failures have no fixed wall-clock bound.
Operator overrides always win until cleared and can remain stale indefinitely.

`credential.list_scoped` emits the effective `plan_tier`: operator override first,
otherwise the detected tier. `plan_tier_source` is `operator` or `detected`, omitted when
there is no tier. Both fields require `read` or `list` authority and follow **identity**,
not `provider_ids`: sign/open-only rows omit both. Absent values are omitted, never null
or empty. Operator edits do not bump `record_version`; detection rides token writes only.
The scoped `view` frames the optional tier then optional source after `auth_method`,
followed by the service, incarnation and current-value observation time above.
Both omitted values contribute absence bytes; switching source changes the view even
when the effective tier stays equal. Deployment changes nonempty views once; empty
inventory views remain unchanged.

Replacement deposits (`put --replace`, compare-and-swap replace, native re-login,
import/picker replacement, and cookie replacement) compare the stored and
resulting normalized `account_id`; `set-identity` also compares those identities. A different account clears the old override and
old detected observation; a fresh observation from the incoming login can be retained.
The override clear is audited in the same transaction as replacement. Equal account ids, including two
absent ids, keep it; a retained identity is compared after preservation. If the previous
envelope cannot be decoded, repair clears any tier because account equality cannot be
established. Refresh never changes account identity and does not touch the assertion.
Removing a credential removes its tier, even without foreign-key enforcement.

`crates/credentials-module/tests/vectors/list-scoped-v2.json` pins real dispatched
list replies for search and Kimi coding keys, a learned organization id, present
and absent `hosts`, lifecycle states and category-filtered visibility, plus the
real watch opening, category-change
and revoked-caller terminal frames. Its unknown-method case is the dispatcher's actual reply to an unsupported
method, standing in for an older vault. Storage incarnations and detection times are
fixed test values; only the process-local watch boot nonce is normalized to zero.
`crates/credentials-module/tests/vectors/get-scoped-v1.json` pins real dispatched
`get_scoped` replies for a catalog row with invalid-key evidence, a catalog row with
`invalid_key: null`, and an OAuth record with `hosts` alone.
Each case carries decoded JSON, base64url reply bytes and a reply hash; `SHA256SUMS`
pins both files. Regenerate both with `CK_EMIT_LIST_SCOPED_VECTORS=1` and the
`list_scoped_v2_vectors_are_emitted_by_real_handlers_and_pinned` test.

### `admin.set_plan`

Gate 2, the operator master-key transcript HMAC, authorizes this v2 admin operation.
Modules and enrolled consumers cannot write tiers. Set and clear request bodies:

```json
{"op":"admin.set_plan","v":2,"credential_id":"oauth:anthropic","plan_tier":"max_20x"}
{"op":"admin.set_plan","v":2,"credential_id":"oauth:anthropic","plan_tier":"max_20x","since_ms":1735689600000}
{"op":"admin.set_plan","v":2,"credential_id":"oauth:anthropic","plan_tier":null}
```

Success returns `{"plan_tier":"max_20x"}` or `{"plan_tier":null}`, also for an unchanged
assertion. Clearing removes **only the operator override**; a detected tier becomes
effective again. A tier must match `[a-z][a-z0-9_]{0,31}`: lowercase ASCII, 1–32 characters,
starting with a letter. Syntax is checked before credential lookup. Bad syntax refuses
with permanent `invalid_plan_tier`; an unknown credential refuses with `credential not
found`, including a clear. Refusals change neither metadata nor audit.

Optional `since_ms` applies only to a tier set in the same operation. It must be a
positive integer no greater than 9007199254740991 (the exact JSON-integer bound)
and no later than the vault's current time. Wrong types, zero, negative, fractional,
out-of-bound or future values, or supplying it without a tier, refuse with the same
permanent `invalid_plan_tier` code. Setting a tier without `since_ms` stores NULL,
never inheriting a previous date. Clearing removes both the override and its date.
Repeating the same tier and date is a no-op; changing only the date is a real edit
with one audit row, updating the row in place and preserving its observation time.
A real tier change resets the observation time to now. `ck auth set-plan --since` accepts a UTC `YYYY-MM-DD` date
(midnight UTC), an RFC 3339 timestamp, or epoch milliseconds. `ck auth list` shows
the supplied date beside the operator tier; JSON lists use `plan_tier_since_ms` or null.

Only actual tier/date transitions write an HMAC audit row with op `set_plan` and target
`plan:<credential-id>|<old-tier>|<new-tier>`. An absent old or new tier is the empty field;
parse by splitting off the **last two** `|` delimiters. Automatic account-change clears
remove the date with the override. A date-only edit retains the same old/new tier
in this target; the audit format does not embed timestamps. Automatic clears
use the replacement actor and the same audit format. Manual tier edits never open or
re-seal the envelope, and never change provider ids or authorization categories.

### `admin.operator_sign` and `ck auth sign`

This operator-only signing path uses the existing admin Gate 1 (direct bind) and
Gate 2 (master-key transcript HMAC), not a capability handle, grant, or enrollment
token. The offline CLI uses the same applier under the single-writer lease.

```json
{"op":"admin.operator_sign","v":1,"id":"signing:account-machine:1","payload_b64":"Y2hhbGxlbmdl"}
```

Only `SigningKey` records with sealed `operator_sign: true` are eligible. Unknown
ids, other kinds, and unflagged keys all refuse with `key is not marked for
operator signing`, before payload validation. Payloads use standard padded base64
and a 64 KiB decoded limit (`MAX_OPERATOR_SIGN_PAYLOAD`), enforced in the shared
admin applier online and offline. The admin envelope limits are unchanged; bus
`credential.sign` retains its separate 1 MiB limit. After validation, the vault commits
a `sign` audit row containing only the payload's plain SHA-256 (never payload bytes), with
actor `route-admin` online or `offline-cli` offline. The append checks the key's
record version inside its transaction. Audit failure returns an error and no
signature; signing happens only after the append succeeds, regardless of the
record's separate `audit_each_signature` value. Signed bytes are published with the
signature; keeping the row's digest plain preserves external payload verification.

The result has exactly three string fields: `key_id` (the first eight bytes of
SHA-256 of the public key, lowercase hex), `public_key_hex` (64 lowercase hex
characters), and `signature_hex` (128 lowercase hex characters, detached Ed25519).

`ck auth mint-signing-key --id signing:account-machine:1 --operator-sign` seals
both `operator_sign = true` and `audit_each_signature = true`. Both flags are
additive schema-1 metadata, omitted when false; older records default to false.
Older decoders can read flagged records but drop `operator_sign` on rewrite,
revoking operator permission. Replacement keys require the flags again.

`ck auth sign --id signing:account-machine:1 --payload-file <path>` signs the exact
file bytes (`-` reads stdin). Success prints exactly one JSON line with the three
fields above. Refusal exits 1 with a diagnostic on stderr and no signature on
stdout. This is the machine-readable interface for operator-terminal account
authentication. Root keys `signing:cortexkit-root:1` and
`signing:gh-manifest-root:1` must never carry `operator_sign` and remain unavailable
through this path. Bus `credential.sign` authorization and unflagged key behavior
are unchanged.

### `admin.signing_public_key` and `ck auth public-key`

This read uses the existing authenticated admin plane when a daemon is running.
It does not authorize a consumer principal, capability handle, or grant.

```json
{"op":"admin.signing_public_key","v":2,"id":"signing:account-machine:1"}
```

The result contains only `public_key_hex` (64 lowercase hex characters) and
`key_id` (the first eight bytes of SHA-256 of the decoded public key, lowercase
hex). The record must be a local `SigningKey`, regardless of its `operator_sign`
flag. An absent id returns `signing_key_not_found/permanent`; another record kind,
including `KemKey`, returns `not_signing_key/permanent`. Quarantined, unreadable,
or malformed records use the existing store-error reply. A daemon without this
operation refuses the unknown discriminator; the CLI does not fall back on that
refusal.

`ck auth public-key --id <id>` prints `public_key_hex <hex>` and `key_id <hex>`,
in that order, like the last two lines of `ck auth mint-signing-key`. Offline it
opens the store read-only without taking the writer lease. Neither path writes
an audit row, modifies a record, or returns any private key material.

### Category and grant audit targets

`admin.store_with_categories` is a create-only operator write. Its body has `v: 1`,
`id`, `record`, and `categories` (a nonempty list of category names). The explicit
set replaces catalog defaults. The write stores the record and categories and
appends `put` followed by `set_category` in one transaction. A refusal leaves all
of them unchanged. The legacy `admin.store` body is unchanged; clients must not
fall back to it when a daemon does not recognize `admin.store_with_categories`.

Category transitions use audit op `set_category` and target
`category:<credential-id>|<sorted-comma-list>`; clearing the set leaves the trailing `|`.
Migration 10's one category backfill row uses audit op `category.migrate`, actor
`migration:10`, and target `category:forge-identity|<sorted-comma-list-of-credential-ids>`.
New grant targets use
`grant:<operation>:<principal-kind>:<principal-id>:<selector-kind>|<stored-selector>`.
The category and grant formats parse by splitting on the first `|`. Historical grant targets without `|`
remain valid audit-chain strings and are never rewritten.

---

## 4. `credential.status` — the cursor surface

`status` answers without minting anything. It is the surface to poll for a local record.
For a remote record it reports B's stored observation only: poll `get_scoped` to observe a
repair at the home (§14).

A store failure while resolving a handle or reading its metadata reports the same
transient `last_error_code` as the other handle reads (`refresh_failed` for an
underlying store outage), never `not_found`. No keys are added to the status reply;
the error code's class determines retry policy. Scoped refusals remain uniform.

| field | meaning |
|---|---|
| `ready` | the vault will attempt to serve this record |
| `credential_id` | resolved operator-chosen label, for verifying an existing binding only |
| `record_version` | monotone change cursor over the stored MATERIAL |
| `stale_pending` | whether a report marked the token stale, so the next `get` pays an upstream exchange (held back while the version is inside the report cooldown, §5) |
| `last_error_code` | the most recent refusal, if any |

`credential_id` is absent for overall readiness and unresolved addresses; verify a held
binding with it, but never route on it—account routing remains `account_id` +
the refresh adapter, never `record_version`. Use `record_version` to invalidate
cached material, not to identify an account pool.

**An unresolved handle is an answer, not an error.** A handle that is unknown or revoked
returns a normal result, `{"ready":false,"last_error_code":"not_found","lease_held":…}`,
with `credential_id`, `record_version` and `stale_pending` all ABSENT (never null, never a
sentinel): an id would tell a probe what exists, a placeholder version would compare as
older than every real one so a poller would chase a change that never comes, and a
defaulted `stale_pending` would assert something about a record the vault never looked
at. Decode each of the three as optional. `@cortexkit/claustrum-client` does so from
0.5.0: `recordVersion` and `credentialId` are optional on `CredentialStatus` and are
omitted from the object when the reply omits them; 0.4.x threw `invalid_status` on this
shape.

The Rust client's `CredentialStatus` retains optional `record_version` and
`last_error_code`; an absent `stale_pending` decodes as `false`. It does not expose
`credential_id` or `lease_held`. Its producer-fixture tests cover both status replies.

The exact reply bytes for a resolved and an unresolved handle, and for `credential.get`
with every optional field present and with every one absent, are pinned in
`crates/credentials-module/tests/fixtures/enrollment_wire_contract.json` by
`handle_read_wire_fixture_pins_get_and_status_replies`, which produces the status rows
from the real status surface. On `get`, `expires_at_ms` is the one optional field sent as
an explicit `null` rather than omitted.

**`record_version` and `ready` move independently, and that is deliberate.**
`record_version` tracks material: it bumps on refresh and on replace. `ready` tracks the
state verdict. So `ck auth reactivate` — the repair for a credential wrongly marked dead
— moves `ready` false→true **without** bumping `record_version`, because no material
changed. A consumer polling only the version cursor will hold a repaired credential dead
indefinitely. **For local records, poll `status`; use `record_version` as the material
cursor and `ready` as the serving verdict.**

**`status` is a cursor, `get` is the authority.** They can legitimately disagree:
`ready` is computed from stored state without decrypting, while `get` also gates on the
sealed record kind. A `SigningKey` reports `ready: true` and refuses `get` with
`kind_not_gettable` — both answers are correct and the codes explain the divergence at
the point of failure.

---

## 5. Reporting a failure you observed

`credential.report_auth_failure { handle, provider_status, record_version, reporter_source? }`

**Report only when you believe the credential itself is invalid** — not because an
endpoint refused a request for resource permissions, rate limits, or a missing repo
selection. A 403 for "this app cannot see that repository" is not a dead credential, and
reporting it as one takes a working credential out of service.

`record_version` is a compare-and-swap fence: a report naming a superseded version is a
state no-op (it still records a diagnostic row, so the report is never invisible). This
is what stops a slow client's stale 401 from invalidating a credential that has since
refreshed.

The effect is **stale-marking, not killing**: a refreshable credential is marked stale so
the next `get` refreshes it, and only a subsequent `invalid_grant` from the provider
latches `needs_reauth`. A non-refreshable credential latches immediately, since there is
no recovery path to attempt.

**A report does not buy a refresh inside the 60 s cooldown.** The report is applied as
above: the token is marked stale, and once the cooldown has passed the next `get`
refreshes it without another report. But a credential whose current `record_version` was
written less than 60 s ago (`REPORT_REFRESH_COOLDOWN_MS`; a refresh writes a new version)
keeps serving its current token until the window passes, with no upstream call. The
cooldown exists because OpenAI, Anthropic and antigravity rotate the refresh token on every
exchange and revoke the whole token family on reuse, so a burst of report-driven refreshes
puts the login itself at risk. An expiring token, or one that cannot meet your
`min_ttl_ms`, still refreshes inside the window.

So the protocol after a report is: re-read, and if `record_version` did not change, pause
before using the credential again. Do not report the same version in a loop. Repeated
reports change nothing inside the window and each one is a diagnostic row; the vault records
the held-back refresh once per version as `auth_events.kind = stale_refresh_deferred`.

`reporter_source` is a closed vocabulary — `direct`, `relay_status_field`,
`relay_message_parse` — recorded for forensics. An unrecognised value is stored as
`unrecognised` rather than persisted verbatim.

### If you gate reports on a provider's error body, gate on the WRONG-REQUEST case

The rule above asks you to report only a credential you believe invalid, and a provider
that answers every case with a bare `401` does not let you tell. Some providers do carry a
discriminating field in the error body, and the direction you gate it in decides which way
the gate fails.

Gate on **"this value means the request was wrong"** and suppress those. Do not gate on
"this value means the token was dead" and report only those — an unrecognised or newly
added value would then suppress a real dead-token report, the vault never learns, and the
credential stays unusable until something else discovers it.

Inverted, an unrecognised value still reports. The version fence absorbs the cost of a
wrong report; nothing absorbs the cost of a suppressed one.

And do not adopt a discriminator you have only observed in one of the two cases. Seeing
`authentication_error` on a dead token does not establish that it is absent when the
request shape is wrong, and a gate built on that half-observation fails open in exactly
the direction above. Over-reporting behind the fence is the correct default until both
cases have been seen side by side.

### A status outside {401, 403} is REFUSED, not ignored

The vault acts only on `401` and `403`. A report carrying any other status, such as
`429`, `402` or a `5xx`, refuses with `report_status_not_credential_death` (`permanent`),
so a consumer that misclassifies quota or server refusals as credential deaths learns so
on its first report instead of receiving a success that changed nothing.

Refusing costs you nothing you can observe: you already hold the credential, and the
report is advisory. That is why this is a refusal where a refused *fetch* would be an
outage.

**`403` is still honoured, and deliberately.** It is genuinely ambiguous across
providers — GitHub uses it for permission refusals on a perfectly live token, and xAI has
used it for a real credential death. This surface sees only the number. Refusing
`403` would fail toward a dead credential that looks healthy, which is the worse
direction, so the judgement stays with you: report only when you believe the credential
itself is invalid.

An out-of-vocabulary status is refused rather than rate-limited because a throttle would
turn a loud classification defect into a quiet one.

---

## 5a. Reporting a quota reading (`usage.report_scoped`)

Plugins can relay quota readings without being attested modules. Parameters are
`{credential_id, reading, enrollment_token?}`. The optional enrollment token resolves
the same way as on `credential.get_scoped`; otherwise the route's reserved principal
is used. The caller must hold an exact or category `read` grant for the credential.
Unknown ids, ungranted callers and revoked enrollments/grants return the byte-identical
`not_found`/`permanent` reply used by `credential.get_scoped`.

`reading` must be a JSON object whose compact serialization is at most **15,360 bytes**.
Top-level `credentialId` and `vouched` keys are forbidden, even if null. Invalid shapes,
reserved keys and oversized readings produce a transport `invalid_params` Error frame,
not a credential verdict. Provider-specific fields are opaque to the vault.

The response means only that the reading was queued in memory, never that insula
accepted it. No audit-chain row is written. First use is recorded once per credential
and principal in `auth_events`, as on the other scoped read operations.

Golden request (a reserved reader can omit `enrollment_token`):

<!-- golden:usage.report_scoped.request -->
```json
{"method":"usage.report_scoped","params":{"credential_id":"oauth:claude:synthetic","reading":{"observedAtMs":1793600000000,"provider":"claude","headers":{"anthropic-ratelimit-unified-5h-utilization":"0.41"}}}}
```

Golden response:

<!-- golden:usage.report_scoped.result -->
```json
{"result":{"accepted":true}}
```

The vault adds `credentialId` from its checked id and
`vouched: {principal: "enrolled:<name>" | "reserved:<module>", credentialId: <checked id>}`.
It sends one `usage.observe` batch to insula about every five seconds over its outbound
module-attested connection as `reserved:claustrum`. The pending queue holds at most 16
credentials and coalesces each credential's readings: the greatest numeric
`observedAtMs` wins, with the latest received winning a tie. If either timestamp is
missing or non-numeric, the latest received wins and insula judges its validity. At
capacity a new credential evicts the least recently received pending credential.

Each batch gets one delivery attempt with a two-second deadline. No retries or disk
storage are involved. Reports and credential reads never wait for insula. Health
metrics include `usageForwardedRows` (rows in batches with a complete insula reply,
including ignored rows), `usageDroppedRows` (coalesced, evicted or failed-delivery rows),
and `usageIgnoredReasons` (insula's ignored counts keyed by reason). Invalid or
incomplete replies count the whole batch as dropped. These counters are process-local.

`usage_report_scoped_wire_contract_goldens_are_checked` checks the golden examples;
`usage_report_scoped_insula_vectors_match_row_and_decode_ignored_reason` checks the
vendored insula contract, including its `unknown_credential` ignored reason.

## 5b. Reporting and clearing a provider login condition

`credential.report_condition` takes `{credential_id, record_version, reason,
provider_status, action_url?, enrollment_token?}`. The strings `reason` and `action_url`
are checked after authorization, not during decoding. `credential.clear_condition`
takes `{credential_id, record_version, enrollment_token?}`. Both operations reject
unknown fields with the `invalid_params` Error frame; neither accepts a handle.

Report checks, in order:

1. The caller must have `read` on the id, exactly as on the id form of
   `credential.report_auth_failure`. Unknown, ungranted and out-of-reach ids are
   indistinguishable (`not_found`). Neither operation invokes the limiter that records
   an alarm when too many requests target one handle.
2. The login must have an admitted refresh adapter. API keys, other record kinds and
   unreadable login envelopes are refused with `condition_not_admitted`. This does not
   quarantine the record. `needs_reauth` and `retired` logins remain eligible.
3. The adapter must admit the reason (`condition_not_admitted`). Currently only
   Antigravity admits conditions: `provider_verification_required` and `provider_ineligible`.
4. `provider_status` must be 403 (`condition_status_refused`).
5. A link is optional for `provider_verification_required`, and forbidden for
   `provider_ineligible`. The absolute URL must use `https` and the exact host
   `accounts.google.com` (case-insensitive); no userinfo, explicit port (even `:443`),
   or fragment. It must be at most 2048 bytes, all printable ASCII `0x21`–`0x7E`.
   Violations give `condition_link_refused`.
6. The stored version must match `record_version` for the report to apply.

On the vault holding the login, checks 2–6 use the same row inside the write transaction.
An id deleted and recreated during an admitted call returns `not_found`. A report sent
after the delete and recreate is complete can land on the new login if its version
matches. An identical repeat or version mismatch returns `{accepted: true}` without
applying a change. A new reason starts a new `since_ms`; replacing only its link keeps
the time. A refusal returns `{accepted: false, error: {code, class}}` inside `result`.

Clear checks authorization and the same incarnation and version fence, not adapter,
reason or login state. The result is `{cleared: true}` if a condition was removed,
`{cleared: false}` if none was set or the version differed, or
`{cleared: false, error: {code, class}}` on refusal.

A condition neither changes the login's state or version nor changes token serving.
An applied report or clear appends one corresponding audit row. Successful validation
and an unchanged incarnation give one applied or unapplied condition diagnostic, with
null `detail`. A refusal adds neither, apart from the existing authorization diagnostics.
The link is stored verbatim, not included in errors, diagnostics, debug output or audit
payloads. Dispatch each mutation once: a lost reply is not grounds to replay it.

### Reading a condition

On `credential.list_scoped`, a row covered by `read` or `list` includes
`condition: {reason, since_ms}` when set. A row covered only by `sign` or `open`
omits the member. Scoped rows never include the link or the reporter. The reason
is an open string when reading; `since_ms` is an integer in `0..=2^53−1`.

For a row with a visible condition, the scoped digest appends byte `4`, then
`push_string(reason)`, then `push_string` of `since_ms` in decimal. This extension
comes after the plan-tier extension (byte `3`), if present, and before the
`fusiform_provider_id` frame. A row without a visible condition adds no bytes.
`auth.watch_scoped` uses the same digest and sends the same notice shape as
before; changing only the link sends no scoped notice.

`admin.status` includes `condition: {reason, since_ms, action_url?}` only on
conditioned credential entries. `ck auth status` and `ck auth list` show the reason,
time in milliseconds, and link when set. The human output shows marked shared
copies with a reminder to clear the condition at the home vault. The v1
`ck auth list --json` inventory still lists only local rows. Every row has a
`condition` field: `null` if unset, otherwise `{reason, since_ms, action_url}`,
with `action_url: null` when absent. The daemon-free inventory can read an older
vault without condition tables; it shows no conditions and does not migrate the
database.

### Operator clear

`admin.op` kind `clear_condition` authenticates the body
`{op: "admin.clear_condition", v: 1, credential_id}`.
`ck auth clear-condition --id <credential id>` calls the same operation. It removes
a local condition and appends one audit row naming the operator, returning
`{cleared: true}`. It returns `{cleared: false}` without an audit row when nothing
was set. An unknown id is refused with `credential not found`; a shared copy is
refused with `condition_home_owned/permanent` because it must be cleared at the
home. These are `admin_refused` route errors, not consumer `result.error` replies.

### Producer samples

The vault's consumer replies are pinned in
`crates/credentials-module/tests/fixtures/login-conditions-v1/consumer-ops.json`.
Regenerate them and their checksum with `CK_EMIT_CONDITION_VECTORS=1 cargo test
--locked -p credentials-module --features credentials-core/test-support --bin ck-claustrum
consumer_condition_producer_replies_and_local_outcomes_are_pinned`.
The scoped (plain, marked, marked with a dated plan, and sign-only) and connector
replies are pinned in the same directory's `surfaces.json`. Use the same command
with `login_condition_surface_samples_are_producer_generated_and_pinned` as the
test filter to regenerate those samples and their checksum.

## 6. Health

The supervisor's health probe reports a cached snapshot recomputed every 5 s off the
probe path, so it never contends with serving. Worst-case staleness is ~35 s when
combined with the prober's own cadence.

`storeReadable: false` **omits** the metric counts rather than reporting zeros — a
database outage must not be plottable as "0 active credentials", which is
indistinguishable from an empty vault.

`auditSeq` and `auditTipMac` publish the global audit chain tip. An external witness that
records the tip over time can detect truncate-and-reappend tampering, which the chain
cannot detect alone: a backward-linked MAC chain verifies its own prefix, so deleting a
suffix leaves a chain that still verifies. **The witness must record the GLOBAL tip** — a
credential-filtered query witnesses only its own slice, and a truncation outside that
slice is invisible to it.

---

## 7. What the vault will not tell you

Stated so nobody waits for it.

- **Which handles exist.** Unknown and revoked are one answer.
- **Whether a provider will still honour a credential.** Only spending a token answers
  that, and for rotating providers spending it invalidates the copy we hold — so no dry
  run exists even in principle. `needs_reauth` is the signal, and it arrives only after
  someone spends a token and reports.
- **Why a credential was refused, over the wire.** The reason is recorded locally in
  `auth_events` for the operator (`ck auth events`); the wire answer stays uniform so it
  cannot be used to enumerate.

---

## 8. Where the source of truth is

If this document and the source disagree, the source wins and this document is a bug.

| fact | source |
|---|---|
| classes and codes | `credentials-module/src/read_surface.rs` (`ErrorClass`, `ErrorBody`) |
| frame envelope shape | pinned by `error_frame_shape_is_pinned` |
| class set | pinned by `error_class_wire_strings_match_pinned_set` |
| status key set | pinned by `the_status_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement` |
| request shapes | pinned by the request-shape tests in `read_surface.rs` |
| `auth_events` vocabulary | `credentials-core/src/audit.rs` (`AuthEventKind`), documented in the operator runbook |
| the class list in §1 | pinned against source by `the_wire_contract_doc_names_every_error_class` |

---

## 9. A daemon restart is silent, so impose a per-call deadline

Every consumer holding a route binding across a restart of this module must impose a
per-call deadline. Without one it hangs forever, and the hang is invisible to both sides.

The mechanism, because the obligation is not guessable from the wire spec: the supervisor
protocol validates every nonzero-channel frame against a per-slot binding epoch installed
at `route.bind`. After this daemon restarts, a consumer reusing its cached binding carries
a pre-restart epoch, and every frame it sends fails that check and is silently dropped.
It is never answered with an `Error` frame, because a module-emitted error would land in
the correlation space of whatever now legitimately holds that channel. The consumer
receives nothing: not a refusal, not a close, not an error.

A rebind-on-error arm is necessary and not sufficient, because no error arrives. The
deadline converts silence into an event that arm can act on:

```
per-call deadline expires  ->  classify as retryable
                           ->  clear the cached binding
                           ->  reconnect and re-bind
                           ->  later attempts can reach the restarted vault
```

The Rust client uses one deadline per unary attempt. It includes the route queue,
the route open, and the reply. A handle read retries transport failures, not a
classified vault refusal. Neither client resends a usage report after losing its
reply.

The vault's diagnostics cannot tell you which happened. Every refusal on the scoped-read
path writes to `auth_events`, so an empty table proves no scoped read reached a refusal
point. It does not prove the call was served: a frame dropped at the epoch check never
reaches the read surface. Empty means arrived-and-succeeded or never-arrived, and only the
consumer's side can distinguish them.

---

## 10. `credential.open`

`credential.open` accepts `{credential_id, enc_b64, ciphertext_b64, info_b64, aad_b64, enrollment_token?}` with no extra fields (including `handle`). All byte fields use `base64::engine::general_purpose::STANDARD`, the same strict, padded standard-alphabet decoder as `credential.sign`. The reply is `{result:{plaintext_b64,key_id}}`; `key_id` equals the same record's `credential.public_key` reply, derived by `credentials_core::signing::key_id_for_public`. A KEM public-key reply has `algorithm: "x25519"` and `public_key_hex`.

Checks run in order:

1. Shape decode (a transport `Error` frame with code `invalid_params` and **no class**, per §1a).
2. Combined encoded length at most `ENC_BOUND = ceil(MAX_SIGN_PAYLOAD / 3) * 4 + 12`,
   then standard base64 decode (malformed byte field: `malformed_encoding`, permanent).
3. Combined decoded length at most `MAX_SIGN_PAYLOAD` (1 MiB), otherwise
   `sign_payload_too_large`, context_overflow.
4. Connection-scoped refusal counter gate (`open_rate_limited`, transient, without delay or disconnect).
5. Scoped authorization for `open` (`not_found` on unknown or unauthorized id).
6. KEM kind fence (`kind_not_openable`, permanent).
7. For `kem:bus-seal:<n>` only, check the decoded `info` domain (`bus_seal_info_domain`, permanent).
8. PKCS#8 parse and fresh RFC 9180 base-mode receiver opening sequence zero
   (`open_failed`, permanent, identically for invalid encapsulation, wrong recipient,
   modified ciphertext, mismatched aad or info, and invalid stored key material).

Each step runs only after its predecessors pass. `not_found` refusals at step 5
alone increment the connection counter; it recovers after 60 seconds.

For bus-seal keys, the vault chooses the required ASCII prefix from the resolved
principal, never from the request: `reserved:ckbus` must use `ck-bus-seal/v1/ckbus/`,
and `reserved:engram` must use `ck-bus-seal/v1/engram/`. At least one byte must
follow that prefix. The vault passes the entire decoded `info` to HPKE unchanged.
Other KEM keys leave `info` uninterpreted. For all keys, `aad` and any bytes after a
required prefix are uninterpreted: the vault does not inspect machine identity or
verify a signature inside the plaintext. See §18 for the bus-seal grant rules.

Example request and reply, taken from the producer's
`crates/credentials-module/tests/fixtures/enrollment_wire_contract.json`:

```json
{"aad_b64":"cm93OjQyfGNvbm46N3xyZWNpcGllbnRzOqChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/","ciphertext_b64":"ZbKhMI+TD2ckFKtRYEc4Au/mxq/Mc2QwtibT12l8LkxNq00=","credential_id":"kem:wire-fixture","enc_b64":"evA98Vni11dRwaiOtanoeYjxONznWW69o61/C7BKhzQ=","info_b64":"cGxleHVzLXNlbnQtdGV4dC92MQ=="}
```

```json
{"result":{"key_id":"a0289810032eb417","plaintext_b64":"SGVsbG8sIFBsZXh1cyEg8J+Riw=="}}
```

This opens to `Hello, Plexus! 👋`. The fixture uses RFC 9180 base mode with
DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (suite IDs
`0x0020 / 0x0001 / 0x0003`) at sequence zero. Its `hpke` block records the
recipient public key, encapsulated ephemeral public key, test-only ephemeral input
keying material (IKM), info (`plexus-sent-text/v1`), aad and plaintext. The aad is the
UTF-8 bytes of `row:42|conn:7|recipients:` followed by these 32 bytes (hex):
`a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf`.
The generator uses publicly known synthetic keys and a fixed ephemeral IKM only for
reproducibility; real senders must use fresh randomness. Regenerate just this fixture
entry with `UPDATE_FIXTURES=1 cargo test -p credentials-module --bin ck-claustrum
tests::key_and_scoped_wire_fixture_pins_real_success_replies -- --exact`, and verify
the independent receiver and sender with `python3 scripts/hpke-independent-open.py`.
The entry's `refusal_cases`, `refusal_requests` and `refusals` arrays correspond by
index and pin the real dispatcher's permanent error replies.

The producer's [`bus-seal-v1` samples](../crates/credentials-module/tests/fixtures/bus-seal-v1/README.md)
also pin successful opens for each principal, refusals when the callers exchange
their `info` domains, and a refusal for a bare prefix.

## 11. Cookie deposit (`credential.deposit_cookie`)

A supervised module identified by its route-bound `reserved:<module>` principal
and granted `category browser-session deposit` may write its own cookies, but not
read them with that grant. It may send:

```json
{"method":"credential.deposit_cookie","params":{"id":"cookie:example.com:work","cookie":"session=abc","consent_ref":"consent-123","email":"me@example.com"}}
```

Only `id`, `cookie`, `consent_ref` and optional `email` are accepted. Missing or null
`email` means no identity on create and preserves identity on replace; present email
is stored as both account_id and email and disclosed to browser-session readers.
Unknown fields (including enrollment_token), missing required fields and wrong types
return a transport Error frame with `invalid_params`, a fixed non-secret detail,
and no writes. Admission order is decode, id grammar, payload grammar, then Deposit
authorization; no grant widens either grammar.

The id matches
`^cookie:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:[A-Za-z0-9._@+-]{1,64}$`
and is at most 255 UTF-8 bytes. Cookie length is 1..=16384 bytes, allowing HTAB,
0x20..0x7E and UTF-8 bytes >=0x80 but excluding all other controls and DEL.
Consent reference is 1..=128 bytes in 0x21..0x7E. Email is 1..=254 bytes,
nonempty after Unicode trim and without control characters; no address syntax is
required. Because the cookie is a JSON string, it is stored as UTF-8. The cap counts
bytes, not characters. Non-UTF-8 obs-text requires operator `ck auth put --payload-file`;
byte identity with operator put holds for UTF-8 input.

Success bodies are exactly:

```json
{"result":{"id":"cookie:example.com:work","outcome":"created","record_version":1}}
{"result":{"id":"cookie:example.com:work","outcome":"replaced","record_version":2}}
```

The cookie is never echoed. A creator can replace only its own record; creator is
write-once, including across operator replaces. Existing operator or NULL-creator
rows are not taken over. Creates assign exactly browser-session; replaces preserve
categories, grants and birth time. Deposit grants authorize no reads, key operations,
or admin operations and are omitted from list_scoped operations, grants, grant_tuples
and view. A best-effort `scoped_first_use` auth_events row records the first committed
deposit for each (credential id, principal, deposit) tuple. It is written only after
commit so an ownership refusal or failed audit cannot appear as successful use.

Every post-decode refusal is a Response frame with
`{"result":{"error":{"class":"permanent","code":"not_found"}}}` shape.
`invalid_id`, `invalid_payload`, `not_found` and `not_permitted` are permanent;
`store_error` is transient (store, lease, I/O, shutdown, audit-append or version-guard
failure). Refusals mutate no credentials, categories, audit or first-use rows.
For each refusal, the vault attempts one bounded diagnostic in the trimmable
`auth_events` table, without secret bytes: invalid_id,
invalid_payload and not_found use subject `credential.deposit_cookie`;
not_permitted and store_error use the validated id. Diagnostic failure never changes
the reply. Authorization uses the scoped diagnostic reason `no_grant`, `not_found`,
`uncategorized`, `wrong_kind` or `store_error`, while always replying `not_found`;
other reasons are
`deposit_cookie_invalid_id`, `deposit_cookie_invalid_payload`,
`deposit_cookie_not_permitted` and `deposit_cookie_store_error`.

A successful write and audit append commit in one transaction. Audit operations are
`deposit_cookie_create` and `deposit_cookie_replace`, actor/source/created_by are the
same `reserved:<module>` string, and alarm is false. First compute a lowercase
hex SHA-256 consent commitment over:

```text
UTF8("ck-deposit-cookie/v1") || u32be(len(UTF8(id))) || UTF8(id)
|| u32be(len(UTF8(consent_ref))) || UTF8(consent_ref) || SHA256(UTF8(cookie))
```

The inner SHA-256 is 32 raw bytes, not hex. Independent vector: id
`cookie:example.com:work`, consent_ref `consent-123`, cookie `session=abc` yields
`4b5a1cb62c56fc15d6dda4e1cd4ded71770ccb9f847e8fe1e254b01ea6837140`.
The persisted `payload_hash` is a keyed fingerprint of the UTF-8 hex commitment,
using the audit payload key described in [the architecture](architecture.md#5-audit-and-diagnostics).
The unkeyed commitment is not persisted in new audit rows: it would let a database
reader test cookie guesses. Historical rows retain their original commitment.

**Trust line:** the vault trusts the depositing module's consent attestation and
cannot see the consent card. The grant is not evidence that a card was shown.
The hand-authored fixture `deposit_cookie_wire_contract.json` pins these bytes;
fixture regeneration requires `UPDATE_FIXTURES=1` and a reviewed diff.

## auth.watch_scoped — held scoped-inventory changes

`auth.watch_scoped` accepts exactly the `credential.list_scoped` params, including
optional `enrollment_token` (token identity takes precedence over the route principal;
a bad token never falls back). It uses the same principal resolution and grants.
Send a route `REQUEST`; SUBSCRIPTION (flag bit 7) is accepted but **not required**,
since the current Rust and TypeScript SDK subscribe methods send ordinary requests.
The watch is an ordinary in-flight request; the manifest remains
`Concurrency::ModuleManaged` with 32 in-flight requests per route.

The vault sends one JSON body per `STREAM_DATA` on the request's correlation id,
route channel and binding epoch. Each notice is sheddable (`ADMISSION=2`):

```json
{"kind":"changed","epoch":"0123456789abcdef0123456789abcdef","seq":1,"view":"<base64>","keys":"<base64>"}
```

- `epoch` is a random 128-bit hex id shared by all watches in one daemon process.
  A restart changes it. `seq` counts emitted notices within this watch, starting at 1.
- Every open or reopen immediately sends seq 1 with the current digests, even if
  the caller previously watched the same route. A change while disconnected is not
  hidden by a remembered cursor.
- `view` is exactly the `credential.list_scoped` view for this caller, computed by
  `list_scoped_view`, not a second digest definition. Learning a visible `github_app`
  pair or attestation changes `view`, not `keys`; recording the same pair again
  changes neither. The webhook companion enters neither digest.
- `keys` is standard padded base64 SHA-256 over the bytes of
  `claustrum.watch_scoped.keys.v1`, byte `1`, a big-endian u32 row count, then each
  reachable signing/KEM row sorted by id bytes: its id as big-endian u32 UTF-8 byte
  length plus bytes, followed by its big-endian u64 `record_version`. Kind follows
  the sealed record, not the id prefix. The material itself never leaves the vault.
  A byte-identical `put --replace` still advances this digest. Token refresh versions
  do not participate in either digest.
- Committed store writes wake recomputation off the async reactor. Bursts coalesce
  over about 250 ms; a notice is sent only if this caller's `view` or `keys` changed.
  Losing grants yields the smaller (possibly empty) view, not an ending.

An unauthorized open, or an open beyond the cap, gets the same `RESPONSE` body as
an unauthorized `credential.list_scoped`:
`{"result":{"error":{"class":"permanent","code":"not_found"}}}`. Revoking the
watcher's enrollment terminates its correlation with a `RESPONSE` carrying those
same body bytes, including after notices have been sent. Domain refusals do not use
the transport `ERROR` lane. No account enumeration is disclosed by a refusal.

There is one watch per route: opening another replaces it and ends the old
correlation with `STREAM_END`. The daemon-wide cap is **64** open watches. `CANCEL`
on the watch correlation and a route close stop the watch and free its slot; route
close is silent. A channel-0 `PUSH` `module.draining` command ends all watches with
`STREAM_END` before routes finish draining and refuses new opens. Graceful daemon
`GOODBYE` also queues `STREAM_END` for every watch before the frame loop exits.

Clients distinguish three endings:

- A `RESPONSE` with a refusal settles the subscription. Decode it with the existing
  `credential.list_scoped` refusal decoder: stop and do not reconnect for that refusal.
- `STREAM_END` means the vault ended the watch (for example, drain or shutdown).
  Re-subscribe and re-read the scoped account list.
- A subscription rejected with `route_closed` means the route was lost. Reconnect,
  re-read the scoped account list and re-watch.

Older vaults answer this unknown operation on the `ERROR` lane with code
`unknown_method`. That unchanged response is the client's fallback signal to poll
`credential.list_scoped` instead. Sheddable notices are not an event journal: on a
route reconnect, reopen for a fresh seq-1 snapshot.

Sample notices emitted by the vault itself (a first notice and a change notice) are in
`crates/credentials-module/tests/fixtures/enrollment_wire_contract.json`. The `epoch`
field in them is replaced with a fixed placeholder, because the real value is random per
process; every other byte is what the vault sent. They are pinned by
`watch_scoped_wire_fixture_is_producer_generated`. Request-path tests in
`watch_scoped_tests.rs` cover both flag forms, metadata/key changes, refresh silence,
coalescing, per-caller visibility, uniform refusals, revocation, immediate snapshots,
replacement/grant loss, the 64/65 boundary and cancellation/close capacity recovery,
and termination before drain/shutdown.

## 12. Account worker token (`credential.account_token`)

The vault exchanges this machine's enrolled account machine key for a short-lived
worker token. A caller receives a bearer JWT for **one granted audience**, never
machine signing access. Request (optional fields may be omitted):

```json
{"method":"credential.account_token","params":{"audience":"cortexkit-runners","enrollment_token":"<consumer token>","min_ttl_ms":60000}}
```

`audience` is an exact string. The supported account-service audiences are
`cortexkit-runners`, `cortexkit-account`, `cortexkit-webhook-relay`, and `cortexkit-hub`.
Authorization uses the same scoped principal resolver as other scoped operations:
an explicitly presented enrollment token takes precedence over the route-bound
reserved principal; a bad token never falls back to ambient authority. Unknown,
uncovered, and unauthenticated callers receive the identical `not_found`/`permanent` body.

`cortexkit-hub` admits only the resolved principal `reserved:ckbus`. Hand grants for
any other principal are refused with `hub_audience_reserved`/`permanent` before any
write or audit row. Approved declarations from modules other than `ckbus` skip the
hub grant with a reason naming that reservation; other valid entries still apply.
At use time every other principal receives the uniform `not_found`/`permanent`,
even if a grant row already exists, without contacting the account service or
touching the token cache. An enrollment token cannot borrow ck-bus's route identity.

The sole grant form is operation `account_token`, selector kind `audience`, selector
exactly equal to the requested audience. Category, prefix, and wildcard coverage do
not apply. A read or sign grant cannot authorize this operation; an account-token
grant cannot sign arbitrary bytes or retrieve the machine key. Example operator grant:

```sh
ck auth grant --principal reserved:ck-motor --selector-kind audience --selector cortexkit-runners --operation account_token
ck auth revoke-grant --principal reserved:ck-motor --selector-kind audience --selector cortexkit-runners --operation account_token
```

Success, inside the ordinary `result` envelope:

```json
{"jwt":"<short-lived bearer>","expires_at_ms":1800000900000,"audience":"cortexkit-runners","account":"01K00000000000000000000080"}
```

The JWT expires 900 seconds after the account service's issuance time; its `exp`
claim supplies `expires_at_ms`. It is kept only in memory, shared across authorized
callers for an audience. A cached token is served only when its remaining life is
strictly greater than `max(min_ttl_ms, 60000)`. Otherwise a single-flight exchange
mints once; concurrent callers share that result, including a failure. `min_ttl_ms`
is a cache-bypass threshold, not a promise to extend the service's fixed lifetime.
Every call is authorized before touching the cache. Re-login/key changes invalidate
cache identity. JWTs are never persisted or logged.

The enrollment pointer is the owner-only, no-follow regular file
`~/.local/state/cortexkit/account/machine.json`. Its account/key id must be enrolled,
and its public key and optional `vault_key_id` must agree with the highest live
`signing:ck-account-machine:<n>` record. Missing, unsafe, malformed, unenrolled or
mismatched state refuses `account_login_required`/`auth_required`: run
`ck account login`. The file cannot grant signing authority or substitute another
private key.

Refusals use the ordinary `result.error` object with `code`, `class`, and optional
`retry_after_ms` (milliseconds, not seconds):

| Code | Class / remedy |
| --- | --- |
| `not_found` | `permanent`; no information about other grants or audiences |
| `account_login_required` | `auth_required`; run `ck account login` |
| `machine_revoked`, `machine_not_found`, `account_not_active` | `auth_required`; re-login |
| `invalid_request`, `auth_failed`, `signature_invalid`, `account_exchange_invalid` | `permanent`; signer/contract mismatch, fixed-text operator warning |
| `challenge_expired`, `challenge_spent`, `issuance_expired` | `transient`; a 409 fetches a new challenge and retries once within this call, then refuses |
| `rate_limited`, `exchange_disabled`, `account_check_unavailable` | `transient`; service `retry_after_s` is converted to `retry_after_ms` |
| `account_exchange_unavailable` | `transient`; network, unusable upstream response, or already-expired delivery |

At either exchange stage, malformed response bodies and unrecognized service error
codes use `account_exchange_unavailable` / `transient`, including HTTP 400 and 403.
An HTTP status alone is not a recognized account-service verdict.

The vault sends no bearer to the account service: challenge POST takes exactly
`{key_id,aud}`, redemption POST exactly `{key_id,aud,challenge,sig_hex}`. Before
signing, the sealed challenge must bind the expected account, key, `worker_token`
purpose, and audience. The full sealed string is signed verbatim in the normative
UTF-8 transcript without a trailing newline. Local vendored vectors and provenance
are in `crates/credentials-module/tests/fixtures/account-machine/`.

`auth_events` records idempotent `scoped_first_use` for each resolved principal /
`account_token` / audience. Each failed exchange attempt, including a retried 409,
records `scoped_read_refusal` with the account-service code and status. These are
trimmable diagnostics, not HMAC-chain appends: periodic mints never grow the
untrimmable audit chain. The chain still records operator grant changes.

## 13. `credential.seal`

`credential.seal` seals one message to a caller-named X25519 public key in RFC 9180
**Auth mode** (mode 2), suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
ChaCha20-Poly1305 (KEM `0x0020`, KDF `0x0001`, AEAD `0x0003`), the same suite as
`credential.open`. The vault-held `KemKey` named by `credential_id` is the sender's
static key (skS); the request's key is the recipient's (pkR). The recipient opens the
message with the vault key's public half, which `credential.public_key` serves, and a
successful open proves the message was sealed by the holder of that key. The private
key never leaves the vault, and there is no operation that returns a raw
Diffie-Hellman value, a derived secret or an exported key: for a caller-chosen public
key that would be a key-agreement oracle.

Request, with no other fields (including `handle`):

```json
{"method":"credential.seal","params":{"credential_id":"kem:push","recipient_public_key_b64":"<32 bytes>","info_b64":"<bytes>","aad_b64":"<bytes>","plaintext_b64":"<bytes>","enrollment_token":"<optional>"}}
```

Every byte field uses the strict, padded standard-alphabet decoder `credential.open`
uses. The reply is `{result:{enc_b64,ciphertext_b64,key_id}}`: `enc_b64` is the 32-byte
encapsulated key, `ciphertext_b64` the AEAD output for sequence zero of a fresh
context, and `key_id` names the sealing key in the same format `credential.open` and
`credential.public_key` return. Every call uses a fresh ephemeral key.

Checks run in order, each only after its predecessors pass:

1. shape decode: an unknown or missing field is a transport `Error` frame with code
   `invalid_params` and **no class** (§1a);
2. size caps on the encoded text, before anything is decoded: a `plaintext_b64`,
   `info_b64` or `aad_b64` longer than its cap can encode to is
   `seal_input_too_large` / context_overflow, and a `recipient_public_key_b64` longer
   than a 32-byte key encodes to is `invalid_recipient_key` / permanent. The caps are
   `plaintext` at most 65536 bytes (`MAX_SEAL_PLAINTEXT`), `info` and `aad` at most 1024
   bytes each (`MAX_SEAL_INFO`, `MAX_SEAL_AAD`, all in `credentials_core::kem`);
3. base64 decode of every field: `malformed_encoding`, permanent;
4. the same caps on the decoded bytes (`seal_input_too_large`), then the recipient key
   must be exactly 32 bytes (`invalid_recipient_key`);
5. the per-connection refusal counter shared with `credential.open`: 16 refusals of
   either operation within 60 seconds refuse further calls `seal_rate_limited`,
   transient, until the window passes. Successful seals do not count;
6. authorization by an **exact** `seal` grant for the resolved principal (enrollment
   token first, then the route-bound reserved principal);
7. the record is read and must be a `KemKey`;
8. the seal. A low-order recipient point, whose shared secret would be all zeros, is
   refused here `invalid_recipient_key` with no ciphertext. A stored key that will
   not parse is `corrupt`;
9. one audit row (below), then the reply.

Steps 2 to 5 run before anything is authorized or read, so a malformed request never
touches a key. **One answer for everything about the key:** an unknown id, no grant, a
revoked grant, a grant for another operation (`read`, `open`, `sign`, `list`), a seal
grant on a record that is not a `KemKey`, and a store fault while checking the grant
or reading the record all return the identical `not_found` / permanent body, and each
counts toward the refusal threshold. A `seal` grant authorizes no other operation, and
no other grant authorizes `seal`.

`kem:vault-transfer:1` is reserved for federation, including hub login lists. No
grant can authorize `credential.seal` with this key: the store refuses such grants,
and the read surface returns the same `not_found` even if a legacy grant exists.

**Every seal is audited.** Before the ciphertext is returned the vault commits one
HMAC-chained row with `audit_log.op = seal`, the credential id, `payload_hash` set to
a keyed fingerprint of the decoded plaintext, and the resolved `reserved:<module>` or
`enrolled:<name>` actor. The plaintext is never recorded; the audit row has no column
for the recipient key, so it is not recorded either. If the row cannot be written, or
the key record was replaced between the read and the audit write, the ciphertext is
discarded and the call returns `store_error` / transient. A refused seal writes no
audit row.

Grants are exact-only, and the CLI and the store both refuse a category or audience
selector:

```sh
ck auth grant --principal reserved:prefrontal --selector-kind exact --selector kem:push --operation seal
ck auth revoke-grant --principal reserved:prefrontal --selector-kind exact --selector kem:push --operation seal
```

The grant operation arrives with store migration 18. A binary older than that
migration cannot read a store that holds a `seal` grant's operation name.


## 14. Federation between computer vaults

A rotating OAuth login stays on one **home** vault A. Vault B keeps a remote record and
fetches only an access token; it never stores the token in its database or receives an
OAuth struct or refresh token. Static credentials instead use an explicitly accepted sealed
transfer. There is no automatic static-credential synchronization or remote-record chaining.

### Callosum vault-sharing switches and member grants

The switch on computer A for peer B means **B may use A's vault**. At daemon start
and on each `callosum.paired_devices_watch` full snapshot, A reconciles grants for
`fed-computer:<B>` at B's current `pairing_id`. An enabled `vault` share on a
`computer` creates `remote_read` on category `llm-provider` and selector-free
`secret_use`, with source `sharing_switch`. Switch-off, disappearance, a non-computer
class or a changed pairing revokes obsolete switch grants. Callosum reports `enabled`
only while at least one operation the operator approved for the switch is still in this
vault's manifest, so a vault build that stops declaring all of them reads as off, and a
later build that declares one again reads as on, with no operator action. The
reconciler handles both exactly like the operator turning the switch off or on.

Existing grants have source `operator`. The reconciler never changes or removes an
operator row, including an identical selector whose pairing is stale. All grant
creates/revokes for one snapshot and their audits commit in one transaction. A failed
read, refusal or undecodable snapshot leaves grants unchanged. A route-channel `Error`
from `paired_devices_read` is a refusal, not a snapshot; the retry warning names its
code. The daemon keeps the watch open, re-reads on every reopen after a close or lost
connection, and cancels the watch on shutdown. The pinned
[Callosum discovery samples](../crates/credentials-module/tests/fixtures/callosum/paired-devices/)
are from `paired-devices-vectors-v1.5`.

When any vault switch is on, the daemon prepares a missing `kem:vault-transfer:1` and
its exact announce `read` for `reserved:callosum` through the same path as
`ck auth transfer init`. It does not change the member-mapping gate or self member id.
`transfer_deliver` grants and every key transfer remain manual operator steps.

`ck auth member list` shows each row's source. `ck auth member revoke` refuses a
switch row with `member_grant_sharing_switch` and directs the operator to
`ck callosum share <device> claustrum/vault off`; manual revocation would be undone
by the next snapshot. Operator rows remain manually revocable.

### Hub login lists

The home writes one authenticated, encrypted value per member to the
`vault-shared-logins` bucket (history 1, maximum value 256 KiB), at
`{home_box}.{member_box}`. Box ids are 32 lowercase hex digits. Each vault gets its
own box id from the bus and maps peer boxes using Callosum's announced machine ids,
joined to its current paired-computer snapshot by fingerprint and pairing id.
No pairing id is included in a hub value. A home publishes a snapshot only while
sharing is enabled and the member holds a current `remote_read` grant; the
projection includes only the logins those grants cover.

The outer JSON object is exactly `{v, enc_b64, ciphertext_b64, aad}`, with `v: 1`.
The seal uses RFC 9180 Auth mode and the suite in §13, with the home's active
`kem:vault-transfer:1` as sender and the member's announced `vault_transfer_x25519`
as recipient. HPKE `info` is UTF-8 `cortexkit/claustrum/hub-logins/v1`. The base64
fields use the strict, padded standard alphabet. The `aad` value is a JSON **string**
containing these fields in order: `home`, `member`, `home_box`, `member_box`,
`generation`, `sender_key_id`, `recipient_key_id`. Authenticate its exact UTF-8
bytes, never reserialize. `home` and `member` are `fed-computer:` ids, and the key
ids derive from the raw 32-byte X25519 public keys. The member checks all identity,
box and key bindings against its local state and the KV key. `generation` is a
decimal JSON string, without sign or leading zero, in `1..=9223372036854775807`.
Compare it numerically (for example, with JavaScript `BigInt`).

The plaintext is exactly `{"kind":"snapshot","logins":[...]}` or `{"kind":"ended"}`.
The envelope, AAD and plaintext wrapper reject missing, duplicate or unknown
fields. The hub-specific seal accepts at most 184320 bytes of plaintext and 1024
bytes of AAD; the public seal limits in §13 are unchanged. A duplicate login id
or a `corrupt` row rejects the entire snapshot without consuming the generation.
Each login row contains:

| Field | Meaning |
|---|---|
| `credential_id` | The login's id on the home. |
| `state` | `active` or `needs_reauth`. |
| `refresh_adapter` | The home's refresh adapter. |
| `identity` | The same identity object as the token reply. |
| `categories` | The home's category set. |
| `provider_ids` | The home's stored provider ids, sorted and deduplicated; always present, `[]` when unset. |
| `detected_plan` | The same detected-plan object as the token reply, or null. |
| `home_version` | The home's record version. |
| `condition` | When set, `{reason, since_ms, action_url?}`; otherwise omitted. The reporter is never sent. |

Members ignore unknown login-row fields. If `provider_ids` is absent, members keep
an existing copy's ids and seed an empty set for a new copy.
When present, the set replaces the ids of a `home_watch` copy in the same transaction
as its other metadata. Invalid provider-id syntax, duplicates, or a set exceeding
the existing per-credential cap reject only that row, retaining any existing copy;
other valid rows still apply. These updates move the member's `credential.list_scoped`
view and `auth.watch_scoped` view just as category changes do.

Condition changes, including a link-only replacement or removal, trigger a snapshot even
without a new home version. A member accepts a reason of 1–64 bytes drawn from
`[a-z0-9_]` (including unknown reasons without a link) and an integer `since_ms` in
`0..=2^53−1`. A link is allowed only for a known reason whose adapter admits the host,
and must pass the URL rules in §5b. `condition: null` and non-object values are malformed.
A malformed condition rejects only its row: the copy is retained unchanged, the rejection
log omits the link, and valid sibling rows apply.

A newly inserted copy stores the condition in the snapshot, even on an insert-only replay.
For an existing copy, a full snapshot applies the new condition or clears it when the key
is absent; an insert-only replay never changes it. The change commits with the usual
`remote_update` audit row. A failed read leaves the copy unchanged. After a restart
the copy's scoped and connectors projections read the locally stored condition without
asking the home.

Snapshots never change hand-added (`operator`) remote copies. The token reply used
by `ck auth remote add` does not carry provider ids, so a hand-added copy starts
without them and keeps its member-local set. Hand-added copies can forward condition
mutations but do not display a condition from the home. Converting a watched copy to
operator ownership removes its condition because it will not receive the home's clears.

The member watches keys ending in `.{member_box}`. It normally applies only a
generation greater than the last it committed for that home. Restoration after
locally re-enabling sharing and insertion of previously blocked copies may use the
same generation from a point read. A valid newer `ended` removes that home's
automatic copies, never operator copies. A missing key, delete, purge, bucket reset,
hub outage, invalid value or failed open is not an `ended`. A snapshot itself grants
no access: every `federation.remote_token` is checked by the home under the current
pairing and grants.

A test-only sealed value and an independent Node verifier are in
[`crates/credentials-module/tests/fixtures/hub-wire-v1/`](../crates/credentials-module/tests/fixtures/hub-wire-v1/).

### Computer-local login sharing opt-out

`<config home>/cortexkit/claustrum.jsonc` can set `login_sharing` to `false` (default
`true`). This is a local live setting, not a new wire operation. While off, no
`sharing_switch` grants or `home_watch` remote copies exist on that vault. The setting
and automatic-state removals commit in one transaction, with a `login_sharing_set`
audit row (actor `config:<path>`) and the existing per-removal audit rows. Reapplying
the current value writes nothing. Operator grants and records are preserved;
operator-granted `remote_token` and `secret_use` behavior is unchanged.

An off home publishes a sealed `ended` for its affected members. An off member
does not apply hub login lists. Turning sharing on rereads Callosum's current
switches and restores copies from the hub when the current binding is available.
Invalid input never enables sharing: startup is off; later invalid edits
retain the applied value. The vault declares `config.review` and opts into
`config.gate` when offered; consumer wire operations and replies are unchanged.

### Channel identity and harness mapping

The canonical member id is `fed-computer:<fp>`, where `<fp>` is 32 lowercase hex characters
(the first 16 bytes of SHA-256 of the member's Noise static public key). The matching route
is `fed:<fp>:claustrum`. The vault's outbound client opens it as `reserved:claustrum`.
Callosum must derive the forwarded harness from the authenticated computer peer, not request
params. Both modules must be reserved in the supervisor configuration. Member mapping must
remain off until the deployed supervisor guarantees that the forwarded harness comes
unchanged from the authenticated opener, and callosum derives it from the authenticated
computer peer rather than request params.

On inbound `reserved:callosum` channels the live `federation.member_mapping` setting controls
this mapping:

| Harness | Gate off (release-1 behavior) | Gate on |
|---|---|---|
| exactly `callosum-self` | ordinary callosum grants | ordinary callosum grants |
| `fed-computer:<32 lowercase hex>` | refused principal | federation member channel |
| exactly `fed-phone:<32 lowercase hex>` | no principal; legacy bearer behavior | phone channel only if `secret.phone_mapping` is also on; otherwise refused |
| any other `fed-` harness, including sim/unknown or malformed hex | refused | refused |
| empty or any other harness | ordinary callosum grants | refused |

A harness starting `fed-` never inherits callosum's grants. Other principals' harnesses are
ignored; direct, enrolled and unattested callers cannot become members. Refused channels
answer uniform `not_found`. Only a federation member channel can invoke these operations:

| Method | Kind | Purpose |
|---|---|---|
| `federation.remote_token` | Query | Fetch an Auth-sealed access-token projection; callosum must not persist query replies. |
| `federation.report_auth_failure` | Mutate | Forward a version-checked 401/403 report to the home. |
| `federation.report_condition` | Mutate | Report a version-checked login condition to the home. |
| `federation.clear_condition` | Mutate | Clear a login condition at the home after a successful use. |
| `federation.transfer_deliver` | Mutate | Deliver an Auth-sealed static credential for operator acceptance. |
| `federation.secret_use` | Query | Forward a member vault's sender `secret.use` to the secret home; the release is Auth-sealed, so callosum must not persist query replies. |
| `federation.secret_request_flow_approval` | Mutate | Record a member vault's flow consent request for a secret this vault holds. |
| `federation.secret_revoke_flow_grants` | Mutate | Revoke a member vault's flow grants for one flow install. |

The manifest read and watch in §17 also use these channels. Other unlisted methods
on member channels answer `not_found`, except for the retired `federation.remote_watch`
and `federation.manifest_report_active`: those answer classless `unknown_method`
on mapped member and ordinary routes and are no longer declared. Refused channels
still answer uniform `not_found` for every method. `handle` or
`enrollment_token` params are `invalid_params`, never resolved. Federation ops
on any non-federation channel (including `callosum-self`, a granted reserved module, or
any channel with the gate off) are `not_found`. `secret.home` is declared beside the
phone ops (§15) and is never on this allowlist: a member channel answers it `not_found`.

Handles and enrollment tokens are **vault-local bearer secrets**, not member identities.
With the gate off, release-1 bearer-scoped reads remain possible even on a refused `fed-`
principal; that rollback boundary does not apply the access-token projection. Do not send
handles or enrollment tokens to another vault.

The phone setting defaults off and must stay off until callosum derives `fed-phone:`
from the authenticated phone peer on **every call**, never from request params. An
unreadable member gate never enables phone mapping, even when the phone setting is on.

### Auth-mode HPKE and exact aad bytes

Both purposes use RFC 9180 Auth mode and the existing X25519/HKDF-SHA256/ChaCha20Poly1305
suite. Each vault uses its own `kem:vault-transfer:1` key; peer keys come only from
`callosum.peer_keys_read` for the role-fixed peer, never from a key or member supplied in
params. This key is not a transport key. `credential.open`/`seal` cannot use it. Its only
scoped grant is the announce `read` to `reserved:callosum` for `credential.public_key`;
handles cannot be minted and active-key mutation is protected.

| Purpose | `info` (UTF-8 bytes) | aad JSON fields, in serialization order |
|---|---|---|
| Token reply | `cortexkit/claustrum/remote-token/v1` | `credential_id`, `requester`, `home`, `nonce`, `recipient_key_id` |
| Transfer | `cortexkit/claustrum/transfer/v1` | `transfer_id`, `credential_id`, `sender`, `receiver`, `recipient_key_id` |
| Secret release | `cortexkit/claustrum/secret-release/v1` | `secret_name?` (omitted only for name-less `secret.use`), `requester`, `home`, `nonce`, `recipient_key_id`, `call_sha256` |

The requester (token, secret release) or sender (transfer) serializes the aad exactly once, as compact JSON
in the listed order, and transmits those bytes. `nonce` (fresh per fetch, per sender call for a secret release) and `transfer_id`
are 16 random bytes encoded as 32 lowercase hex characters. Members fill their own role
from their stored self id. Unknown or missing aad fields are refused. The peer validates
every field and authenticates the **received bytes**, never a rebuilt JSON object. A token
reply is opened only for the requested id and nonce; a transfer is opened only for the
attested sender, this receiver and its current key id. Cross-purpose, cross-id and replayed
nonce envelopes do not open. The plaintext limit is 64 KiB.

### `federation.remote_token`

Request: `{"method":"federation.remote_token","params":{"aad":"<exact JSON string>","min_ttl_ms":62500}}`.
`aad` is required; `min_ttl_ms` is an optional signed 64-bit integer in milliseconds.
After the current-pairing check succeeds, unknown params or malformed aad produce an
`invalid_params` Error frame, not a classified credential refusal; earlier pairing failures
take precedence. Success is `{"result":{"enc":"<standard base64>","ciphertext":"<standard base64>"}}`;
`enc` is the 32-byte encapsulation, and ciphertext is the Auth-sealed JSON plaintext below.
Refusal is `{"result":{"error":{"code":"…","class":"…","remedy_member":"…"}}}`,
with `remedy_member` omitted unless a member-specific remedy applies.

The home checks current pairing, strict aad, requester equality with the harness, its own
self id and active transfer key, `aad.home`, a current-pairing `remote_read` member grant,
local refreshable-record eligibility, and the requester's announced transfer key, in that
order. No grant, stale pairing, unknown/ungranted id, ineligible record and projection
refusal are indistinguishable `not_found`. An authorized `needs_reauth` record keeps
answering `needs_reauth` on subsequent reads, rather than degrading to `not_found`.

Grant admission pins the local row lifetime for eligibility, refresh reads and forwarded
stale-report updates. Removing and re-creating the id before one of those steps answers the
same `not_found` as an unknown credential; the admitted call cannot follow the replacement.

After the normal local get/refresh the home requires a nonempty `oauth.access_token`
equal to `payload` and unequal to every nonempty refresh component (including packed-token
segments, client secret and Meta session identity/refresh tokens). It then audits issuance
before sealing. The opened reply contains only:

| Field | Meaning |
|---|---|
| `payload` | Access token, never a refresh component. |
| `expires_in_ms` | Optional remaining lifetime on the home clock at seal time; absent for no expiry. |
| `recheck_in_ms` | Optional time until a stale-marked refresh deferred by the 60 s cooldown can run. |
| `record_version` | Home material version. |
| `project_id`, `account_id` | Optional local-get projections (including Antigravity project and token-derived account). |
| `identity` | Stored inventory identity: optional `account_id`, `email`, `org_name`; distinct from the get projection. |
| `categories` | Home categories, used only to seed remote add. |
| `refresh_adapter` | Required non-null adapter-name string, registered in the receiving vault's adapter registry. |
| `detected_plan` | Optional object `{tier, raw, observed_at_ms}`; tier/raw may be null. |

B validates payload, identity, detected tier and its own adapter registry before applying
anything. Its ordinary `get_scoped` reply echoes `credential_id`, uses local get fields
(including `expires_at_ms`, `project_id`, `account_id`, `email`, `org_name`) and never exposes
the sealed envelope to an application. Inventory rows retain local shapes: kind `oauth`,
home version/identity/adapter and derived `auth_method`, with B-owned categories, provider
ids and operator tier. No capability handle is available for a remote id.

B forwards caller `min_ttl_ms` (negative or absent means zero) plus 62,500 ms, saturating at
`i64::MAX`. A cached token must have conservative lifetime
`expires_in_ms - 60,000 - monotonic_elapsed_since_fetch_start` positive and at least the
caller's demand. The time origin is fetch-task start, before setup, peer-key lookup and
request transmission; using that earlier origin errs on the side of shorter validity.
Cache residence is at most 300 s from that origin, shortened by
`recheck_in_ms` when present. There is no cross-machine wall-clock comparison; consumer
`expires_at_ms` is B's wall clock at that origin plus `expires_in_ms`. A fresh but insufficient
reply is `ttl_unsatisfiable` after one home fetch. A still-servable cached token works during
a partition; no-expiry tokens are still bounded by the 300 s residence cap.

B's forwarded read/report has a 2.5 s end-to-end budget including route open and flight
wait; the home has 1.5 s including lookups/refresh. A timed-out refresh continues detached
and persists rotated material; the next read can use it. Route failure/deadline drops the
binding so the next call can reconnect. Outbound admin work shares one 10 s budget per op.

### Remote verdicts and recovery

Refusals use the ordinary `result.error` body `{code, class}` with optional
`remedy_member` alongside them. It names the member requiring operator action, never free
text. An Error frame is transport/protocol failure, not a credential-state verdict (§1a).
Every fetch records `last_fetch_outcome`; only authoritative outcomes change list `state`
and status `last_error_code`:

| Outcome | B's error / class | Stored effect |
|---|---|---|
| home `not_found` | `not_found` / permanent | `needs_reauth` |
| home `needs_reauth` | `needs_reauth` / auth_required, `remedy_member` = home | `needs_reauth` |
| home `corrupt` | `corrupt` / permanent | `corrupt` |
| home `refresh_failed`, `vault_locked`, `store_error` | same / transient | outcome only |
| home `refresh_unsupported` | same / permanent | outcome only |
| home `ttl_unsatisfiable` | same / context_overflow | outcome only |
| home setup absent or requester self id/key mismatched | `remote_setup_incomplete` / permanent, `remedy_member` = home or requester respectively | `needs_reauth` |
| home pairing lookup failed, refresh budget spent, or home Error frame | `home_unavailable` / transient | outcome only |
| unreachable, deadline, partition, retry-safe or outcome-unknown callosum failure | `home_unreachable` / transient | outcome only |
| permanent callosum failure | `federation_setup_invalid` / permanent | outcome only |
| B cannot open reply (aad/key/info mismatch) | `remote_seal_invalid` / permanent | `needs_reauth` |
| opened reply fails validation | `remote_reply_invalid` / permanent | outcome only; one diagnostic; stored home fields and cache unchanged |
| B lacks self id or active transfer key | `transfer_key_missing` / permanent, `remedy_member` = B when its self id is known (otherwise omitted) | outcome only |
| B lacks home's announced key | `remote_setup_incomplete` / permanent, `remedy_member` = home | outcome only |

Success stores `active`, clears the home error and updates home-owned fields. Non-active
authoritative outcomes drop the cache; transient failures and invalid replies do not undo
a prior home verdict. Categories, provider ids and operator tiers remain B-owned after add.
A remove/re-add starts a new incarnation; delayed replies from the old home cannot apply.

Remote `credential.status` adds `remote_home` and `last_fetch_outcome`. `record_version`
is the last observed home version; `ready` is true only for `active` when B is not fenced;
`last_error_code` is the last authoritative home error, surviving partitions and restarts;
`stale_pending` reflects B's durable reported-version mark. Status and list/watch make no
home call. **Poll `get_scoped` to observe a home repair**, not status. Reads while the home
is still `needs_reauth` fail fast without upstream refresh. The first successful read
restores active/ready. A home re-create may reset the version downward; treat it as a reset.

**Client reach:** remote status is reachable through the Rust client's `status_scoped`
only for a reserved principal. The Rust client sends no enrollment token. The TS client's
`statusCredential` accepts only a handle and remote ids have none: TS and enrolled consumers
have no remote status API in this release and recover by polling `get_scoped`. Existing
client decoders accept optional remote additions; neither client promises to expose them all.
The Rust resolver's structured error keeps the class-derived `code()` (for example
`credential_permanent`) and includes the wire refusal code in its safe display message;
the TS error's `code` is the wire code. Neither currently exposes `remedy_member` as a typed field.

### Forwarded reports

Request: `{"method":"federation.report_auth_failure","params":{"credential_id":"oauth:anthropic:fixture","record_version":1,"provider_status":401,"reporter_source":"direct"}}`.
The id is a string, version an unsigned integer, status a 16-bit unsigned integer;
`reporter_source` is an optional string using the ordinary report vocabulary (§5).
Success is `{"result":{"accepted":true}}`; home refusal is
`{"result":{"accepted":false,"error":{"code":"…","class":"…"}}}`.
After the current-pairing check succeeds, malformed/unknown params produce an
`invalid_params` Error frame; earlier pairing refusals take precedence.

B accepts only 401/403, evicts a matching-version cache entry (never a newer version),
bumps its flight generation and durably records the largest reported version **before**
forwarding. The home rechecks pairing/grant/eligibility and refuses any other status with
`report_status_not_credential_death` / permanent, without marking stale or refreshing.

| Forward outcome | Consumer result |
|---|---|
| home accepted | success |
| home `not_found` | `not_found` / permanent |
| permanent callosum class | `federation_setup_invalid` / permanent |
| retry-safe/outcome-unknown transport, unreachable or deadline | `home_unreachable` / transient |

A same-version token returned during the per-credential 60 s refresh cooldown carries
`recheck_in_ms`; B keeps `stale_pending` and refetches when it elapses, without a second
report. An applied success above the reported version, one without `recheck_in_ms`, a home
re-create or an authoritative non-success clears the mark. Transient outcomes leave it.

### Forwarded login conditions

`federation.report_condition` takes `{credential_id, record_version, reason,
provider_status, action_url?}`; `federation.clear_condition` takes
`{credential_id, record_version}`. They return the same `accepted` and `cleared`
replies as in §5b. After the current-pairing check, malformed or unknown params
give an `invalid_params` Error frame. No enrollment token or principal is forwarded.

On a shared copy the member checks scoped Read authorization. For a report it also
checks the adapter, reason, status and link against the copy; a clear makes no such
checks. Just before sending either mutation it re-reads the copy. An absent copy or a
different incarnation or home gives `not_found` and nothing is sent. Once admitted,
the request goes only to that captured home, even if the copy changes during connection
setup. The member makes one exchange and never retries after a lost reply.

The home checks the current pairing, the member's `remote_read` grant and the transfer-key
fence. Reports repeat checks 2–6 on the home login in one transaction; clears check the
incarnation and record version, not the serving state or adapter. The authenticated
member is the reporter, audit actor and diagnostic principal at the home. The forward
writes no condition audit row or diagnostic at the member, and leaves its token cache,
fetch generation and reported version unchanged.

The member passes the home's success boolean and the `not_found`,
`condition_not_admitted`, `condition_status_refused` and `condition_link_refused`
refusals through (all `permanent`). Other home refusals and Error frames from the home,
including an older home's `unknown_method`, give `home_unavailable` (`transient`).
Connection loss or no reply gives `home_unreachable` (`transient`), with no replay.

### Forwarded agent secrets: `federation.secret_use`

Request: `{"method":"federation.secret_use","params":{"aad":"<exact JSON string>","sender":"aft","call":{… §15 `secret.use` params, unchanged}}}`.
`sender` is one of `aft`, `cerebellum` or `basal` and names the local sender the asking
vault already admitted; `call` is that sender's `secret.use` params byte for byte. The
kind is Query: callosum keeps no reply body, and the release in it is sealed. A query may
still write home state: the home commits the release receipt and its audit in the same
`fenced_write` transaction that consumes a `once` grant (or marks first release) and
writes the release audit, as `federation.remote_token` commits its issue audit.

The aad binds the release to one secret, one requester, one home, one nonce, one
announced key and one exact call. `nonce` is 16 random bytes in lower hex, one per sender
call: every transport retry of that call resends the same aad, and a new sender call gets
a new nonce. `call_sha256` is the lower-hex SHA-256 of the RFC 8785 encoding of
`{"sender","call"}` (keys sorted at every level, compact JSON, exact-range integers
only). `secret_name` is omitted only when `secret.use` omits `name`; named calls keep
the existing AAD bytes unchanged. The home selects a Basic sign-in secret for a
name-less call, with `call_sha256` binding its unchanged target and scope. Presence
must agree exactly: a named call without `secret_name`, or a name-less call with
`secret_name`, is refused `not_found`. Null is not omission. The asking computer
opens a sealed reply over the exact AAD bytes it sent; any changed AAD refuses the
reply as `remote_seal_invalid`.

Parsing is strict as for the token aad: unknown, duplicate or other missing fields, or
a field that is not well formed (`secret_name` empty, a member id that is not
`fed-computer:<32 lowercase hex>`, a `nonce` that is not 32 lowercase hex, an empty
`recipient_key_id`, a `call_sha256` that is not 64 lowercase hex), refuses the call. After
the pairing and `secret_use` member-grant checks succeed, malformed params or aad produce
an `invalid_params` Error frame; earlier pairing and grant refusals take precedence.

The home runs its checks in order and stops at the first refusal:

1. Home role: only a vault whose secret home is `self` serves forwarded secret ops. A
   single-role (setting unset) or remote-role vault answers `not_found` and writes nothing,
   so a misrouted call ends after one hop and is never re-forwarded.
2. The member's current pairing, then a selector-free `secret_use` member grant stored under
   that pairing. The grant is checked before anything is parsed, so a member without it
   cannot drive the grammar or binding checks below. Re-pairing voids the grant until it is
   made again.
3. Strict parse of the params, the aad and the sender.
4. The aad's `requester` equals the attested harness member; the home's self id and active
   transfer key are read; the aad's `home` equals that self id, its `call_sha256` equals the
   recomputed digest of the received params, and `call.name` equals its `secret_name`
   with the same presence on both sides. Only a name-less `secret.use` omits both.
5. The requester's announced transfer key matches the aad's `recipient_key_id`.
6. The sender's grammar, then the store's grant choice, release receipt and seal, all under
   the asking member. AFT and Cerebellum take the agent path with a required `ScopeStamp`;
   basal takes the flow path whose stamp must carry the flow attributes.

The reply is exactly one of: `{status: "sealed", enc, ciphertext}`, the §15
`approval_required` body (a v2 statement, never material), or a refusal body. `enc` is
the 32-byte encapsulation and ciphertext the Auth-sealed plaintext below, both standard
base64. The plaintext is exactly the §15 `released` object `release()` builds: an API key
or username, password and optional TOTP. The home seals with Auth-mode HPKE
(`kem::seal_auth`) from its `kem:vault-transfer:1` key to the requester's announced X25519
key, info `cortexkit/claustrum/secret-release/v1`, over the received aad bytes. The asking
vault opens it only over the aad bytes it sent, passes the object to the local sender, and
never stores it. A reply sealed to another key, or over aad naming another requester,
home, nonce, secret name or `call_sha256`, does not open and releases nothing. Secret
material crosses computers only sealed in this reply: no recorded request or reply body
holds plaintext secret material, and no mutate reply holds sealed material either.

<!-- golden:federation.secret_use.aad -->
```json
"{\"secret_name\":\"key\",\"requester\":\"fed-computer:11111111111111111111111111111111\",\"home\":\"fed-computer:22222222222222222222222222222222\",\"nonce\":\"0123456789abcdef0123456789abcdef\",\"recipient_key_id\":\"0123456789abcdef\",\"call_sha256\":\"13cdb396de6f9079e66fd0591073f29052fba7a82c3e1a36eccc571bcd524d55\"}"
```

<!-- golden:federation.secret_use.request -->
```json
{"aad":"{\"secret_name\":\"key\",\"requester\":\"fed-computer:11111111111111111111111111111111\",\"home\":\"fed-computer:22222222222222222222222222222222\",\"nonce\":\"0123456789abcdef0123456789abcdef\",\"recipient_key_id\":\"0123456789abcdef\",\"call_sha256\":\"13cdb396de6f9079e66fd0591073f29052fba7a82c3e1a36eccc571bcd524d55\"}","sender":"aft","call":{"name":"key","coverage":"scope","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"scheme":"https","host":"x.test","port":443,"path":"/repos/a/issues/1"}}}
```

A retry with the same aad bytes is answered from the home's release receipt, not released
afresh. The receipt `(requester, nonce)` holds the aad SHA-256, the incarnation, the grant
kind and id, the sealed bytes and a 10-minute expiry. The home returns the stored bytes
unchanged, with no second consumption or audit, only while the receipt is unexpired, the
aad digest matches, the pairing, `secret_use` grant and announced-key checks still pass,
the secret's incarnation is unchanged, and the stored grant is still live (except the
`once` grant the receipt consumed). A same-nonce request the checks authoritatively deny
(expired receipt, other aad bytes including reordered JSON or another `recipient_key_id`,
unpaired member, missing or stale grant, changed incarnation, gone or expired grant) gets
`not_found` plus a refusal audit and never a fresh release. A check that cannot be
performed keeps its transient code and decides nothing: a callosum timeout or
`fed_not_ready` answers `home_unavailable`, and a store failure its mapped transient code.
Such a refusal writes no refusal audit, leaves the receipt untouched, and a later retry with
the same aad is judged afresh. Receipts survive restart and are swept after expiry; the
asking vault's retry deadline is shorter than the receipt lifetime, so a nonce is never
replayed after its sweep.

<!-- golden:federation.secret_use.result.sealed -->
```json
{"status":"sealed","enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","ciphertext":"AA=="}
```

The `enc` and `ciphertext` above are placeholders: a real seal is randomized, so the
contract pins the key set, and the vault's tests seal and open with the real encoders over
the golden aad bytes. `secret_contract_tests.rs` (`federation_secret_use_goldens_match_the_real_encoders`)
pins the request key set, checks the golden call equals the §15 `use.request.api_key`
golden, re-serializes the aad field order with the real field order, recomputes
`call_sha256` with the real digest, and round-trips a seal over the golden aad bytes.

`approval_required` answers an otherwise eligible request with no matching approved grant,
as locally, with a v2 statement naming the asking computer (§15):

<!-- golden:federation.secret_use.result.approval_required -->
```json
{"status":"approval_required","request_id":"01HF7YAT000000000000000001","statement_b64url":"eyJhZ2VudF9pZCI6ImFnZW50LUEiLCJhc2tpbmdfbWVtYmVyX2lkIjoiZmVkLWNvbXB1dGVyOjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwiY292ZXJhZ2UiOiJzY29wZSIsImR1cmF0aW9ucyI6WyJvbmNlIiwiaG91ciIsInNlc3Npb24iLCJwZXJtYW5lbnQiXSwibWVtYmVyX2lkIjoiZmVkLWNvbXB1dGVyOjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyIiwicmVxdWVzdF9leHBpcmVzX2F0X21zIjoxNzAwMDAwNjAwMDAwLCJyZXF1ZXN0X2lkIjoiMDFIRjdZQVQwMDAwMDAwMDAwMDAwMDAwMDEiLCJzY29wZSI6eyJlcG9jaCI6Nywia2luZCI6ImhlYWQiLCJvd25lciI6InJlc2VydmVkOnByZWZyb250YWwtY29yZSIsInJlZiI6IkgifSwic2VjcmV0Ijp7ImluY2FybmF0aW9uIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxNDkiLCJraW5kIjoiYWdlbnRfYXBpX2tleSIsIm5hbWUiOiJrZXkifSwidXNlIjp7Imhvc3QiOiJ4LnRlc3QiLCJsb2NhdGlvbiI6ImhlYWRlcjpYLUFwaS1LZXkiLCJwYXRoX3ByZWZpeCI6Ii9yZXBvcy9hIn0sInYiOiJjay1zZWNyZXQtdXNlLXN0YXRlbWVudC92MiJ9","expires_at_ms":1700000600000}
```

### Forwarded flow consent: `federation.secret_request_flow_approval` and `federation.secret_revoke_flow_grants`

Both carry the §15 params unchanged and answer the §15 reply (never material). They carry
no `sender`, no stamp and no `call`: they are basal's by op name. Everything they create
or remove belongs to the asking member only: the pending request records the asker, the
approval grants that computer's flow only, and a revoke leaves the home's and another
member's grants for that flow identity in place. The home role, pairing and `secret_use`
member-grant checks run before the params are parsed, as for `federation.secret_use`.

<!-- golden:federation.secret_request_flow_approval.request -->
```json
{"name":"key","flow":{"flow_id":"daily-fetch","version":7,"code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","install_id":"install-A"},"target":{"scheme":"https","host":"x.test","port":443,"path":"/repos/a/issues/1"},"methods":["GET"]}
```

<!-- golden:federation.secret_request_flow_approval.result -->
```json
{"status":"approval_required","request_id":"01HF7YAT000000000000000001","statement_b64url":"eyJhc2tpbmdfbWVtYmVyX2lkIjoiZmVkLWNvbXB1dGVyOjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwiZHVyYXRpb25zIjpbInZlcnNpb24iXSwiZmxvdyI6eyJjb2RlX2hhc2giOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIiwiZmxvd19pZCI6ImRhaWx5LWZldGNoIiwiaW5zdGFsbF9pZCI6Imluc3RhbGwtQSIsInZlcnNpb24iOjd9LCJtZW1iZXJfaWQiOiJmZWQtY29tcHV0ZXI6MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJyZXF1ZXN0X2V4cGlyZXNfYXRfbXMiOjE3MDAwMDA2MDAwMDAsInJlcXVlc3RfaWQiOiIwMUhGN1lBVDAwMDAwMDAwMDAwMDAwMDAwMSIsInNlY3JldCI6eyJpbmNhcm5hdGlvbiI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTQ5Iiwia2luZCI6ImFnZW50X2FwaV9rZXkiLCJuYW1lIjoia2V5In0sInVzZSI6eyJob3N0IjoieC50ZXN0IiwibG9jYXRpb24iOiJoZWFkZXI6WC1BcGktS2V5IiwibWV0aG9kcyI6WyJHRVQiXSwicGF0aF9wcmVmaXgiOiIvcmVwb3MvYSJ9LCJ2IjoiY2stc2VjcmV0LWZsb3ctc3RhdGVtZW50L3YyIn0","expires_at_ms":1700000600000}
```

<!-- golden:federation.secret_revoke_flow_grants.request -->
```json
{"flow_install_id":"install-A","flow_version":7}
```

<!-- golden:federation.secret_revoke_flow_grants.result -->
```json
{"status":"revoked","grants":1}
```

The flow federation goldens equal the §15 goldens field for field: the request goldens
carry the same bytes as `request_flow_approval.request.api_key` and
`revoke_flow_grants.request`, and the result goldens the same key sets as
`request_flow_approval.result` and `revoke_flow_grants.result`. `secret_contract_tests.rs`
(`federation_flow_goldens_are_the_unchanged_secret_shapes`) checks the equalities and that
the approval result's statement decodes to the §15 `statement.flow.v2` golden.

### Transfers: delivery, body v1 and sender action

Request: `{"method":"federation.transfer_deliver","params":{"enc":"<standard base64>","ciphertext":"<standard base64>","aad":"<exact JSON string>"}}`.
All three string fields are required; no extra params or outer transfer id are allowed.
Success is `{"result":{"state":"pending"}}`, `accepted` or `rejected`. Errors use
`{"result":{"error":{"code":"…","class":"…"}}}` with optional `remedy_member`;
After pairing and grant checks succeed, malformed envelope fields produce an
`invalid_params` Error frame without a class; those earlier refusals take precedence.
The version-1 sealed plaintext
has this complete closed schema (including closed nested identity/plan objects):

| Field | Type / encoding |
|---|---|
| `version` | JSON integer, exactly `1`. |
| `credential_id` | Valid nonempty store id string equal to aad's id. |
| `kind` | Snake-case kind string: eligible values `api_key`, `dsn`, `cookie`, `opaque`. |
| `payload` | Nonempty bytes encoded as standard base64. |
| `categories` | Array of validated category strings. |
| `identity` | Object with optional string `account_id`, `email`, `org_name`. |
| `provider_ids` | Array of validated provider-id strings. |
| `detected_plan` | Object `{tier, raw, observed_at_ms}` or null; tier/raw optional nullable strings, observation time signed integer milliseconds. |
| `expires_at_ms` | Signed integer milliseconds or null; must be null/absent for Cookie. |

Only `ApiKey`, `Dsn`, `Cookie` and `Opaque` records with neither OAuth data nor adapter are
eligible. A Cookie with `expires_at_ms` is refused. OAuth (rotating or not), signing/KEM
keys, handles and remote records cannot be transferred. Unknown body fields are refused;
identity, id, tier, categories and provider ids are validated at delivery **and** accept.

The sender fixes one transfer id and one envelope. Its outgoing row and `transfer_out`
audit commit atomically **before** delivery. Resume resends identical bytes, never re-seals
and never writes a second outgoing audit. The receiver first checks current pairing and
`transfer_deliver` grant, then deduplicates by (attested sender, SHA-256(`enc || ciphertext`))
before opening or checking ciphertext-size and queue bounds (the aad-size cap is checked
first). Identical bytes return their stored state even after key
replacement, expiry or a full queue. Grant revocation still refuses a resend. New transfers
are limited to 8 pending per sender and 64 total. The authenticated `aad.transfer_id` is the
only transfer id; no separate outer id is accepted. A different body under the same sender
and id is `transfer_conflict`.

| Delivery result | Sender action |
|---|---|
| `{state:"pending"}` | Keep outgoing row; operator accepts/rejects on receiver, then resume. |
| `{state:"accepted"}` or `{state:"rejected"}` | Delete outgoing row. |
| `transfer_queue_full`, `callosum_unavailable`, `home_unavailable`, `home_unreachable` / transient, or a generic home Error frame | Keep row; resume identical envelope. Permanent callosum Error frames map to `federation_setup_invalid` below. |
| `transfer_expired` / permanent | Delete row. |
| `remote_seal_invalid`, `transfer_conflict`, `transfer_too_large`, `transfer_body_invalid`, `federation_setup_invalid`, `not_found` / permanent | Delete row; repair setup or run a fresh send if appropriate. |
| Any other refusal code, including `remote_setup_incomplete` or `store_error` | Keep row for identical resume; only the terminal codes above delete it, not a permanent class by itself. |

The sender also discards outgoing rows at 7 days. Unaccepted pending bodies expire at
7 days, while accepted/rejected/expired ids and hashes remain for dedup. Delivery creates
no credential. Accept requires `--from` because transfer ids are unique per sender;
it reopens against the stored sender's currently announced key, then commits record,
body categories (not catalog defaults), provider ids, accepted marker and `transfer_in`
in one transaction. Receiver assigns version, state and source `transfer`. Key-lookup
failure keeps pending with no rejection audit; a confirmed opening failure rejects it.
Replacing a damaged non-active transfer key rejects pending envelopes and abandons outgoing
envelopes; active replacement is protected. Abandoned resume sends nothing: use a fresh id.

### Callosum refusal classes and additional admin refusals

| Callosum class | Codes | Vault mapping |
|---|---|---|
| permanent | `fed_not_exposed`, `fed_unknown_module`, `fed_bad_call`, every `fed_payload_…` | `federation_setup_invalid` / permanent; never retry unchanged |
| retry-safe | `fed_busy`, `fed_ledger_full`, `fed_target_unavailable`, `fed_internal` without `[effect:…]`, unknown provider | `home_unreachable` / transient |
| outcome-unknown | `fed_partition`, `fed_deadline`, `fed_shutdown`, any `[effect:…]` suffix | `home_unreachable` / transient; transfer dedup makes identical retry safe |

The effect suffix takes precedence. The 90 s callosum reconnect grace does not extend the
vault's shorter deadlines. Token queries and version-gated reports are safe under uncertain
outcomes; transfers rely on durable dedup.

The permanent-code mapping also applies to channel-zero Error frames, whether refusing
`route.open` or a correlated delivery request. A transfer send or resume deletes its outgoing
row on that `federation_setup_invalid` result, just as for a routed permanent refusal.

`invalid_params` is a protocol Error-frame code with no credential class, including for
malformed federation params/member/aad and forbidden bearers. Master-key admin helpers
can also return `invalid_params` / permanent in their separate admin refusal body; that
does not turn the protocol Error into a classified read verdict.
Purpose-bound ck-bus signing refusals likewise use a classless `invalid_params`
Error, as described in § 2.

| Additional refusal code | Class | Meaning |
|---|---|---|
| `transfer_key_reserved` | permanent | A forbidden grant or handle on a transfer-key id. |
| `bus_key_reserved` | permanent | A forbidden grant or bearer handle on any ck-bus signing-key generation. |
| `transfer_key_protected` | permanent | Mutation or replacement of an active transfer key. |
| `remote_record` | permanent | A handle or local-only action requested for a remote record. |
| `member_not_paired` | permanent | Member grant attempted without a current pairing. |
| `member_grant_sharing_switch` | permanent | The grant follows Callosum's vault-sharing switch; turn that switch off instead of manually revoking the row. |
| `callosum_unavailable` | transient | Required admin/transfer pairing or key lookup failed. |
| `federation_requires_daemon` | permanent | Outbound admin op attempted through the synchronous offline path; no write. |
| `transfer_body_invalid` | permanent | Ineligible or invalid transfer body. |
| `transfer_ineligible` | permanent | Send refused an ineligible kind/OAuth payload/adapter or a gateway credential; optional `reason` describes the eligibility failure (`gateway` for a gateway). |
| `transfer_gone` | permanent | Resume names an outgoing row no longer stored. |
| `transfer_abandoned` | permanent | Resume names an envelope abandoned when its sender key was replaced; send afresh. |
| `credential_exists` | permanent | Accept would replace an existing local id without `--replace`. |
| `credential_id_is_remote` | permanent | Accept would collide with a remote id; local/remote replacement is not implicit. |
| `transfer_replace_refused` | permanent | Accept replacement is not an eligible static record of the same kind. |
| `transfer_too_large` | permanent | Body exceeds 64 KiB plaintext bound. |
| `transfer_queue_full` | transient | Receiver's pending queue bound reached. |
| `transfer_conflict` | permanent | Existing sender/id with a different body hash. |
| `transfer_expired` | permanent | Identical resend of an expired transfer. |

### Federation audit targets

The HMAC chain format is unchanged. `payload_hash` is SHA-256 of compact JSON with fields
in the following order; ids/incarnations are lowercase 32-hex, body hashes lowercase 64-hex,
versions JSON numbers, and reasons refusal codes.

| Audit op | Credential target | Actor | Hash object |
|---|---|---|---|
| `remote_issue` | id | member | `{credential_id, record_version}` |
| `transfer_out` / `transfer_in` | id | receiver / sender | `{transfer_id, body_hash}` |
| `transfer_reject` | id | sender on receiver, receiver on abandoned outgoing | `{transfer_id, reason}` |
| `member_grant_create` / `member_grant_revoke` (operator) | exact selector id, otherwise none | member | `{operation, selector_kind, selector, pairing_id}` |
| `member_grant_create` / `member_grant_revoke` (sharing switch) | exact selector id, otherwise none | vault | `{member_id, operation, selector_kind, selector, pairing_id, source}` (`source` is `sharing_switch`) |
| `remote_add` / `remote_remove` | id | home | `{incarnation}` |
| `federation_gate_set` | none | admin | `{value}` |
| `federation_self_set` | none | admin | `{member}` |
| `login_sharing_set` | none | config:&lt;path&gt; | applied boolean (`true` or `false`) |
| `declaration_seen` | `declaration\|<digest>` or `declaration\|none` | `reserved:<module>` | canonical `grants_json` bytes (compact array, tuple text-byte order, deduplicated); `payload_hash` is their lowercase-hex SHA-256 |
| `settings_refs_seen` | `settings_refs\|<generation>` | `reserved:<module>` | canonical `refs_json` bytes (compact array, bytewise sorted and deduplicated); `payload_hash` is their lowercase-hex SHA-256 |

Issuance dedup and audit commit before token release, keyed by member/id/version/encrypted
material digest, so retries/restarts add no row but a recreated id at version 1 is audited
again. Forwarded reports retain the existing `report_auth_failure` hash format and member
actor: every report adds diagnostics, at most the first state-changing report at a version
adds a chain row. B records only diagnostics for its forward.

## 15. Agent secrets

An agent can use a password or API key without the model ever seeing it, and a scheduled
flow run can use one without waking an agent. Three kinds of caller reach this surface:

* **Senders** (`reserved:aft` and `reserved:cerebellum`) call `secret.use` for the agent
  scope they are serving and receive material only for a call a live grant covers.
* **Basal** (`reserved:basal`) asks for a flow grant to be approved at install with
  `secret.request_flow_approval`, releases one with `secret.use` from a flow run, and
  revokes grants with `secret.revoke_flow_grants`. This is the only caller of those three
  operations, and the only caller whose `secret.use` serves a flow.
* **A paired phone** (through callosum, harness `fed-phone:<fp>`) registers its keys,
  deposits sealed secrets, approves or refuses use, lists and deletes secrets, and
  revokes grants with the seven phone operations.

Agent secrets are separate from credentials and cannot be addressed by credential ids,
handles, scoped lists, federation reads or transfers. The reserved `kem:secret-deposit:*`
namespace is inaccessible through every credential operation, even with a seeded grant.

Every key set in this section is **closed**. A request missing a required key, or
carrying any key not shown, is refused with `invalid_params`. A reply carries exactly the
keys shown; a key marked `?` is present only in the case the text names. Each example
marked "golden" is checked by the vault's tests (`secret_*_key_sets_match_the_contract`
in `crates/credentials-module/src/secret_contract_tests.rs`): its key set is pinned, the
vault's parser accepts the request, and the vault's real reply has the same key set.
Examples show the unwrapped result; transport responses wrap it in `{"result": …}`.

### Gates and caller matrix

`ck auth secret phone-gate on|off` sends `admin.secret_phone_gate_set {"v":2,"enabled":true|false}`
through the admin-MAC route online or the leased offline applier. `status` reads the same
persisted settings without changing them and prints `member mapping on|off|unreadable` and
`phone setting on|off|unreadable`. An absent phone setting means off. A Direct caller without
the MAC cannot change it. The phone setting never changes the member gate.

Cells use these answers. Each refusal is exact: the frame type and the body never vary
with the caller, the gates or the stored state.

* **served**: the operation runs and answers per its own section.
* **NF**: a `Response` frame with the uniform body
  `{"result":{"error":{"code":"not_found","class":"permanent"}}}`, byte-identical to an
  unknown credential.
* **IP**: an `Error` frame `{"code":"invalid_params","message":…}` with no class (§1a).
* **POR**: an `Error` frame, no class, with exactly
  `{"code":"permissions_operator_required","message":"permissions operations need reserved:cingulate or the local operator's direct route"}`.

The eight phone operations are `secret.phone_keys_register`, `secret.deposit_keys`,
`secret.deposit`, `secret.approve`, `manifest.approve`, `secret.list`, `secret.delete`
and `secret.revoke_grant`. `policy.approve_action` follows the same routing matrix,
but also requires the exact `production` build mark on a phone route and admits an
unscoped development desktop only while its switch is on (see
[Approve a broker action](#approve-a-broker-action)).
"Credential get" is `credential.get` with a valid `handle`;
"scoped get" is `credential.get_scoped` without `enrollment_token`.

Rows name the route principal and, for `reserved:callosum`, the opener harness. Member gate
is `federation.member_mapping`; phone setting is `secret.phone_mapping`. Each is On, Off or
Unreadable (a store read that fails), so every row below covers all nine combinations.

| Caller | Gates | Eight phone ops | `secret.use` | `permissions.list`, `permissions.revoke` | credential get | scoped get | `connectors.list`, `connectors.watch` |
|---|---|---|---|---|---|---|---|
| callosum, `callosum-self` | any | NF | NF | POR | served | served (callosum's grants) | POR |
| callosum, `fed-phone:<32 lowercase hex>` | member On, phone On | served (phone preflight) | NF | POR | IP | NF | served, unless federated scope (POR) |
| callosum, `fed-phone:<32 lowercase hex>` | member Off, any phone | NF | NF | POR | served (§14 gate-off residual) | NF | NF |
| callosum, `fed-phone:<32 lowercase hex>` | member On with phone Off or Unreadable; member Unreadable | NF | NF | POR | NF | NF | PAO only for member On, phone Off; otherwise NF |
| callosum, malformed `fed-phone:` | member Off | NF | NF | POR | served (§14 gate-off residual) | NF | POR |
| callosum, malformed `fed-phone:` | member On or Unreadable | NF | NF | POR | NF | NF | POR |
| callosum, `fed-computer:<32 lowercase hex>` | member On | NF | NF | POR | NF (a member channel answers only its six federation ops, §14) | NF | POR |
| callosum, `fed-computer:<32 lowercase hex>` | member Off | NF | NF | POR | served (§14 gate-off residual) | NF | POR |
| callosum, `fed-computer:<32 lowercase hex>` | member Unreadable | NF | NF | POR | NF | NF | POR |
| callosum, any other `fed-` harness | member Off | NF | NF | POR | served (§14 gate-off residual) | NF | POR |
| callosum, any other `fed-` harness | member On or Unreadable | NF | NF | POR | NF | NF | POR |
| `reserved:aft` | any | NF | served | POR | served | served (its grants) | POR |
| `reserved:cerebellum` | any | NF | served | POR | served | served (its grants) | POR |
| `reserved:cingulate` | any | NF | NF | served | served | served (its grants) | served |
| `direct` with the admin MAC | any | NF | NF | served only through `admin.op` (below); a plain call is POR | served | NF (Direct holds no read grant) | served only without scope (development admission); otherwise POR |
| `direct` without the admin MAC | any | NF | NF | POR; `admin.op` is refused | served | NF (Direct holds no read grant) | served only without scope (development admission); otherwise POR |
| `direct` with an agent scope | any | NF | NF | POR | served | NF | POR |
| `direct` with a flow scope | any | not reached | not reached | not reached | not reached | not reached | bind refused (`flow_scopes_unsupported`); directly recorded bind gets `permissions_operator_required` from the dispatcher |

Gates are read only on `reserved:callosum` routes; every other principal's harness is
ignored. On a phone channel, bearer params (`handle`, `enrollment_token`) are IP even on
a method the channel otherwise refuses, except `permissions.list` and
`permissions.revoke`, which are POR for every caller other than `reserved:cingulate`
whatever their params. `secret.use` is NF for every caller other than the two senders,
before its params are read, so a non-sender cannot learn the grammar.
`secret_caller_gate_and_op_matrix_matches_the_wire_contract` drives the existing secret,
permission and credential columns through the real route dispatcher. The connectors
column is driven by `connectors_admission_matrix_uses_real_binds_and_route_dispatch`.
**PAO** is a `Response` with
`{"result":{"error":{"code":"phone_access_off","class":"permanent"}}}`.
For connectors, a federated scope on a phone bind is always POR, before gates.
An `operator_app` stamp with `app: "alfonso-desktop"` admits the desktop to connectors
only; a different app stamp or an absent/unverified principal without a stamp is POR.
The development admission requires plain `direct` with no app stamp and no scope
stamp of any kind. Agent- and federated-scoped Direct binds are POR for connectors.
A flow-stamped Direct bind is refused by the existing `flow_scopes_unsupported`
bind fence before any operation runs; the matrix also records that stamp directly
with `record_connector_bind` and checks that the dispatcher independently returns
`permissions_operator_required`.

The operator uses the existing `admin.challenge` / `admin.op` MAC transcript for
permissions operations: the authenticated `op_body` is
`{"op":"permissions.list","v":1,"agent_id":"optional-agent-id"}` (omit `agent_id`
to list all), or `{"op":"permissions.revoke","v":1,"id":"grant-id"}`.
Only the wrapper admits Direct. Plain `permissions.list {agent_id?}` and
`permissions.revoke {id}` keep the `permissions/v1` provider shapes (pinned by the
vendored vectors in `crates/credentials-module/tests/vectors/permissions-v1/`) and admit
only `reserved:cingulate`.

#### Local-program permissions rows

Live sudo releases and SSH signing grants are included in `permissions.list`,
including agent-filtered replies when their stored `agent_id` matches. They use the
existing secret-grant row shape: holder `agent` or `worker` with `scope_ref`, the
secret name or signing-key id as `subject_label`, and the stored `card_ref`,
`granted_at_ms` and `expires_at_ms`. Known agent ids appear on the row and holder.
No command line, secret material or SSH signing data is projected.

The scope tokens are `local_sudo` and `local_ssh_sign`. Readers treat `scope` as
opaque: retain unfamiliar tokens, show `scope_label`, and revoke by `id` as for
other grants. Labels describe the approved target and duration, for example
`run sudo as root on this computer, once` or
`sign SSH logins to git@github.com, port 22, with key SHA256:<fingerprint>, for this session`.
The SSH fingerprint is the vault-authored fingerprint retained from the approval,
not one supplied by the calling program. Once grants disappear after use or expiry;
revocation removes the grant and prevents its next release or signature. The local
approval options (`once`, and SSH's `hour` and `session`) are not danger options,
so these rows omit `group`.

The producer-generated pair is published in
`crates/credentials-core/tests/vectors/permissions-local-grants-v1.json`, with its
companion `permissions-local-grants-v1.SHA256SUMS`. Regenerate it on Linux with
`CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module --features
credentials-core/test-support
permissions_local_grants_dispatcher_pins_real_approval_samples -- --nocapture`.
The existing credential-grant permissions corpus remains byte-identical.

#### Credential-grant permissions rows

An unfiltered `permissions.list {}` also lists the vault's credential grants for
supervised modules and enrolled programs. These rows have no top-level `agent_id`,
no `holder.agent_id`, and no `expires_at_ms`. Like flow grants, they are absent from
every `permissions.list {agent_id}` reply. The plain route
admits only `reserved:cingulate`; the operator uses the authenticated admin wrapper.

Each stored selector/operation grant is one row:

```json
{"id":"cg_<opaque-digest>","holder":{"kind":"module","module_id":"broca"},"module":"claustrum","subject_label":"Model provider logins and keys","scope":"read","scope_label":"can read the secrets of 37 credentials in this group","granted_at_ms":1800000000000}
```

A `reserved:<id>` principal becomes `holder: {kind: "module", module_id: "<id>"}`;
an `enrolled:<name>` principal becomes `holder: {kind: "enrolled", name: "<name>"}`.
When that enrollment has a display name, its holder also includes
`"label":"<display name>"`; otherwise the `label` key is absent. When none was set,
the label may come from a fixed table of CortexKit plugin names. Module holders
never receive a vault label: apps get module names from the module's catalog entry.
Neither holder includes its principal prefix. Other principal kinds are not listed.
The `scope` is the stored operation: `read`, `list`, `sign`, `open`, `seal`,
`deposit`, `account_token`, or `policy_token`. The timestamp is the grant's creation time.

The `subject_label` describes the selector without a reach count. An exact selector
uses the credential id, and an audience selector uses
`CortexKit account tokens for <audience>`. Category labels are:

| Category | Subject label |
| --- | --- |
| `llm-provider` | Model provider logins and keys |
| `llm-gateway` | Company AI gateway keys |
| `web-search` | Web search keys |
| `media-provider` | Speech and media keys |
| `embedding-provider` | Embedding model keys |
| `browser-session` | Browser sign-ins |
| `github-app-native` | GitHub App keys |
| `anthropic-native` | Claude logins |
| `openai-native` | ChatGPT logins |
| `antigravity-native` | Antigravity logins |
| Any other category | Credentials in the &lt;name&gt; group |

The provider supplies the complete `scope_label`; apps display it unchanged. It
distinguishes reading secrets from listing accounts and plans without secrets,
signing, encrypting or decrypting messages, storing browser sign-ins, and getting
CortexKit account tokens. For `policy_token`, the label is `can get GitHub tokens limited by the
signed policy for this credential`. Category scope labels include the number of credentials
reached now, using the same credential/category membership as `ck auth grants`. Adding or
removing a category member changes that count, not the id or subject label. No row
contains secret or token material. All permission rows are sorted by id.

Credential-grant ids are `cg_` followed by lowercase SHA-256 hex. The digest input
is `claustrum-credential-permission/v1\0` followed by the UTF-8 principal kind,
principal id, selector kind, selector and operation, each prefixed by its unsigned
64-bit big-endian byte length. This namespace is separate from secret-grant ids.
The id is deterministic and stable while the identifying columns are unchanged.

Exact grants whose selector starts with `signing:` or `kem:` are never listed or
revocable through permissions: these vault-held runtime keys are not safe to
revoke from the apps. The same holds for an exact grant on a stored secret that
carries the `module-runtime` category, which an operator sets on a secret a module
needs in order to run at all, such as `opaque:broca-deployment:1`
(`ck auth set-category <id> --add module-runtime`). `permissions.revoke {id}` resolves a visible credential
grant and deletes exactly that selector/operation tuple in one transaction guarded
by the vault's writer lease,
using the same `grant_revoke` audit record and grant-generation update as
`ck auth revoke`. Success is `{"outcome":"revoked"}`. Unknown, already-revoked,
and excluded ids return `{"outcome":"not_found"}` without adding an audit entry or
changing the audit chain's final hash.
Existing secret-grant and flow-grant revocation is unchanged.

Published samples, emitted through the real dispatcher, are in the file below.
They include an exact grant whose `subject_label` is one long credential id, so
the apps can check how a long label wraps on screen:
`crates/credentials-core/tests/vectors/permissions-credential-grants-v1.json`.
Regenerate them with
`CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module --bin ck-claustrum --features credentials-core/test-support permissions_credential_grants_dispatcher_lists_and_pins_samples`.

### Secret home: one vault holds every agent secret

One vault holds every agent secret, every grant and every flow grant for the account.
Other computers hold none. A vault knows where the secrets live through the
`secrets.home_member` setting, set by an operator (`ck auth secret home set <member-id>|self`, `ck auth secret home show`). `set self` stores the literal `self`, never a copy of the
self id, so a later `ck auth federation self` change cannot turn a home into a remote.
`set <member-id>` is checked against callosum's pairing the same way `ck auth federation
self` checks the self member, except that a member id equal to the live self id is stored
as `self` without a pairing lookup.
Each secret call resolves the vault's role from the setting and the live federation self id:

| setting | role | local secret ops | inbound `federation.secret_*` | `secret.home` reply |
|---|---|---|---|---|
| unset | single | served locally, exactly as today | `not_found` | `{"home":true,"home_member_id":null}` |
| `self` | home | served locally | served (see §14); needs the self id | `{"home":true,"home_member_id":<self id or null>}` |
| a member id ≠ self id | remote | sender ops forwarded; phone ops and `admin.secret_put` refused `secret_home_elsewhere` | `not_found` | `{"home":false,"home_member_id":"<home id>"}` |
| a member id with self id absent or equal to it, or store unreadable | — | `remote_setup_incomplete` (permanent; `remedy_member` names this vault only when its self id is known) or `store_error` (transient) | same | same refusal |

Unset keeps every existing behaviour and golden vector byte for byte. On a remote-role vault
nothing local is created: `ck auth secret delete`, `revoke-grant`, `list` and `grants` stay
allowed, so leftover state can be inspected and cleaned up.

`secret.home` is a phone-callable query with the same caller admission as `secret.list`:
it needs a current pairing from callosum but no registered phone keys, because the phone
asks it to learn which vault to register with. It is declared beside the phone ops and is
never on the member allowlist. Request `{}`:

<!-- golden:home.request -->
```json
{}
```

Reply `{home, home_member_id}` per the role table above:

<!-- golden:home.result.single -->
```json
{"home":true,"home_member_id":null}
```

<!-- golden:home.result.home -->
```json
{"home":true,"home_member_id":"fed-computer:22222222222222222222222222222222"}
```

<!-- golden:home.result.remote -->
```json
{"home":false,"home_member_id":"fed-computer:44444444444444444444444444444444"}
```

A role that cannot decide answers the same refusal every other phone op gets on that vault,
so the phone never mistakes a broken setup for an answer: `remote_setup_incomplete` with
`remedy_member` naming this vault when its self id is known, otherwise without one, and
`store_error` when the setting is unreadable.

On a remote-role vault the seven phone operations refuse with the home named, before any
registration check or state write, so a stray phone profile cannot split the Secrets page:

<!-- golden:home.refused.elsewhere -->
```json
{"error":{"code":"secret_home_elsewhere","class":"permanent","remedy_member":"fed-computer:44444444444444444444444444444444"}}
```

`admin.secret_put` (online and offline `ck auth secret put`) refuses the same body there.
A remote-role vault holds no secrets it uses, so setting `self` or clearing the setting is
always allowed. Setting another member is refused while this vault holds any agent secret,
grant, flow grant or pending request: the counts that block the change are part of the
refusal (`secret_home_not_empty` with `agent_secrets`, `grants`, `flow_grants` and
`pending_requests`), and the count and the write share one transaction, so a concurrent put
either commits first and is counted, or runs after and is refused itself.

A member computer forwards only with the home's permission: a selector-free `secret_use`
member grant on the home (`ck auth member grant --member <m> --operation secret_use`), recorded
under the member's current pairing id like `transfer_deliver`, so re-pairing cancels it.
Without it the home refuses every forwarded call from that member with the uniform
`not_found`. Storing it needs no selector: `secret_use` with an exact or category selector
is refused.

`secret_contract_tests.rs` (`secret_home_request_and_replies_match_the_contract`) pins the
request and reply key sets, drives the real phone parser and the real store through every
role row and the elsewhere refusal, and checks the refused ops write nothing.

The pinned samples for the phone app's Secrets page are
`crates/credentials-module/tests/vectors/secret-home-v1.json`: six cases, each with its
request (`method`, `params`) and the exact reply bytes as `reply_b64url` with their
`reply_sha256`, covering the unset, `self` and remote rows above, a `secret.list` refused
`secret_home_elsewhere` on the remote vault, the setup refusal, and the uniform
`not_found` reply returned when a non-phone route calls `secret.home`.
`secret_home_vectors_tests.rs` (`secret_home_ckios_vectors_are_emitted_by_vault_code_and_pinned`)
regenerates them on every run, through the phone channel's own serve function with a
fixed pairing answer and through the real route dispatch for the non-phone refusal, and
`CK_EMIT_SECRET_VECTORS=1` rewrites the file.

### Ordered phone preflight and transaction admission

The vault declares `peer-build/v1`. On `route.bind`, the daemon stamps
`peer_build: "production"` only for Callosum sessions whose production app build
passed Callosum's platform attestation (Apple App Attest for the iPhone app; an
Android app needs Callosum's Android counterpart). The vault records this fact per
route, never per phone
fingerprint. An absent mark, `null`, or any value other than exactly `"production"`
is unmarked; an invalid present value also produces one warning at bind.

Before request grammar, pairing lookup or signed-envelope parsing, an unmarked
phone route receives permanent `phone_not_attested` for
`secret.phone_keys_register`, `secret.approve` (agent and flow),
`secret.delete` (both the statement request and signed commit), and
`manifest.approve`. These refusals write nothing, including pairing observations,
diagnostics and audit rows. A valid signature from an already registered key does
not replace the route mark, and a second route from the same fingerprint needs
its own mark.

`secret.list`, `secret.home` and `secret.deposit_keys` remain available without the
mark because they read inventory, home location or public deposit keys rather
than grant authority. `secret.deposit` is unchanged: its authenticated Hybrid
Public Key Encryption (HPKE) deposit creates a secret but grants no access.
`secret.revoke_grant` is also
unchanged: it is unsigned and only removes access. Their existing pairing,
registration, home-role and feature gates still apply.
The phone's `connectors.list` and `connectors.watch` queries are also unchanged:
they expose connector inventory, not signing authority or approvals.

1. Check exact request keys, grammar and sizes. Grammar faults use `invalid_params`
   Error frames with no class, fixed content-free messages. Other exceeded limits use
   `limit_exceeded` result errors.
2. Except for `deposit_keys`, perform an uncached `callosum.paired_devices_read` lookup
   for `fed-phone:<fp>`. No answer/transient refusal gives `pairing_unavailable`; an absent
   device gives `phone_not_registered`. Persist each answered pairing/absence observation
   with its lookup time. `ck auth secret phone-gate status` performs no pairing lookup.
3. Except for `deposit_keys` and registration, require keys under the current
   `(fingerprint, pairing_id)`, otherwise `phone_not_registered`.
4. Run operation checks and mutation in one serializing store write transaction. The
   1,500 ms `PHONE_OP_DEADLINE` applies until transaction admission. At or after the
   deadline, store only the answered observation and answer `pairing_unavailable`.
   An admitted transaction is never cancelled and returns its commit result.

Storage and audit failures answer `store_error` and roll back mutations. Approve and
delete step 2 verify the signed canonical envelope and return ordered per-item results.
Grant revocation is unsigned, but still requires the phone preflight.

### Phone operations: closed key sets and golden examples

All base64url is strict and unpadded and rejects nonzero trailing bits. Names are 1–64
ASCII bytes `[A-Za-z0-9][A-Za-z0-9._-]*`; refused grammar is `invalid_params`, 65 bytes is
`limit_exceeded`. Deposit, request and grant ids are canonical 26-character Crockford
ULIDs. Hex is lowercase.

#### `secret.phone_keys_register`

Request `{deposit_pub, approval_pub}`: 64 hex characters for the X25519 deposit key, 130
for an on-curve uncompressed SEC1 P-256 approval key. Reply `{status}`, `stored` or
`already_stored`.

<!-- golden:phone_keys_register.request -->
```json
{"deposit_pub":"5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22","approval_pub":"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}
```

<!-- golden:phone_keys_register.result -->
```json
{"status":"stored"}
```

Registration is create-only per pairing. An identical retry answers
`{"status":"already_stored"}`. Different keys give `phone_key_conflict`, no chain row,
and one best-effort `secret_use_refusal` diagnostic under `secret-phone|<fp>` with
principal kind `phone`, id `fed-phone:<fp>`, detail `phone_key_conflict`.

#### `secret.deposit_keys`

Request `{}`. Reply `{member_id, keys: [{state, key_id, pub}]}`. `member_id` is this
vault's `federation.self_member`; `key_id` is the first 8 bytes of SHA-256 over the raw
public key; `pub` is the 32-byte X25519 public key. `state` is `current`; no `next` key is
returned in this version. Missing member id, or an inactive, non-KEM or undecodable deposit
key, gives `secret_setup_incomplete` without replacing the key. No pairing lookup is made.

<!-- golden:deposit_keys.request -->
```json
{}
```

<!-- golden:deposit_keys.result -->
```json
{"member_id":"fed-computer:22222222222222222222222222222222","keys":[{"state":"current","key_id":"0123456789abcdef","pub":"57db4b359f23ae5e146e4e2512056704722506348c150c14753d0c933d04d421"}]}
```

#### `secret.deposit`

API key: `{deposit_id, member_id, name, kind: "agent_api_key", host, path_prefix?,
location, enc_b64url, ciphertext_b64url}`. `location` is mandatory:
`authorization_bearer`, `authorization_basic:<user>`, `header:<name>`, `query:<name>`
or `json_pointer:<pointer>`. Basic sign-in creation requires `secret.basic_auth`
to be on; its grammar and reader-first gate are specified below.
`path_prefix` is omitted for "every path".

<!-- golden:deposit.request.api_key -->
```json
{"deposit_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","member_id":"fed-computer:22222222222222222222222222222222","name":"key","kind":"agent_api_key","host":"x.test","path_prefix":"/repos/a","location":"header:X-Api-Key","enc_b64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext_b64url":"AA"}
```

Login: `{deposit_id, member_id, name, kind: "site_login", origin, enc_b64url,
ciphertext_b64url}`, with no host, path-prefix or location keys.

<!-- golden:deposit.request.site_login -->
```json
{"deposit_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","member_id":"fed-computer:22222222222222222222222222222222","name":"login","kind":"site_login","origin":"https://x.test","enc_b64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext_b64url":"AA"}
```

Reply `{status, incarnation?}`: `stored` with the new record's incarnation (32 hex), or
`already_stored` with no incarnation.

<!-- golden:deposit.result.stored -->
```json
{"status":"stored","incarnation":"0123456789abcdef0123456789abcdef"}
```

<!-- golden:deposit.result.already_stored -->
```json
{"status":"already_stored"}
```

Ciphertext is at most 16,384 bytes. HPKE Auth uses the registered phone deposit key and
info `cortexkit/claustrum/secret-deposit/v1`; `enc` is 32 bytes.

Deposit transaction order: validate local key/self member; consult permanent deposit-id
tombstone; require current member and open rebuilt AAD; validate plaintext; refuse any
existing name, corrupt included; store encrypted record and tombstone atomically. A
matching digest/current member/live incarnation answers `already_stored`, otherwise a
used deposit id gives `deposit_conflict`. A new id for an existing name gives `name_exists`.
Invalid plaintext writes no tombstone, so a corrected ciphertext may reuse the id. A
`member_id` that is not the current one, or associated data that does not open, answers
`not_found`.

#### `secret.approve`

Request `{envelope_b64url, signature_b64url, card_ref?}`. The envelope and signature are
described under "Signed statement and envelope" below. `card_ref` is the Cingulate
elicitation id of the card the phone answered, 1–64 ASCII graphic bytes; it is not signed,
takes part in no check, and is stored on each grant only for `permissions.list`. A
malformed `card_ref`, 65 bytes included, is `invalid_params`.

<!-- golden:approve.request -->
```json
{"envelope_b64url":"eyJkZWNpc2lvbiI6ImFsbG93IiwiZGV2aWNlX2ZpbmdlcnByaW50IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJkdXJhdGlvbiI6ImhvdXIiLCJncmFudF9leHBpcmVzX2F0X21zIjoxNzAwMDAzNjAwMDAwLCJpc3N1ZWRfYXRfbXMiOjE3MDAwMDAwMDAwMDAsIml0ZW1zIjpbeyJyZXF1ZXN0X2lkIjoiMDFIRjdZQVQwMDAwMDAwMDAwMDAwMDAwMDEiLCJzdGF0ZW1lbnRfc2hhMjU2IjoiZGUzMTc0ZmViMTRjZjJlMjllYzczMDgwZGY3ODVlZTYxNTc0OWQ2MzhjYzgxYmVkOWFhZTQ4MDc5ZDBjYjgxYiJ9XSwidiI6ImNrLXNlY3JldC11c2UtZW52ZWxvcGUvdjEifQ","signature_b64url":"MEUCIQDKRJk3gvG7EYBPT0xIKvcZn5bmJpnOEmY3t5fkhlkPtAIgBxhQIWr_XOuoTrazb1NrM-ZJ4FLMQhENmjQPQyuSlZw","card_ref":"card-1"}
```

Reply `{results: [{request_id, outcome: "granted"} | {request_id, outcome: "refused",
code}]}`, one entry per envelope item in envelope order. A local-program item is refused
with `secret_local_programs_disabled` when `secret.local_programs` is off or unreadable.
Other item refusals use `approval_invalid` and do not identify the failed check.

<!-- golden:approve.result -->
```json
{"results":[{"request_id":"01HF7YAT000000000000000001","outcome":"granted"},{"request_id":"00000000000000000000000000","outcome":"refused","code":"approval_invalid"}]}
```

A whole-envelope failure (strict parse, non-canonical bytes, an item carrying any key but
`request_id` and `statement_sha256`, duplicate request id, more than `MAX_ENVELOPE_ITEMS`
items, wrong fingerprint, a signature that is not X9.62 DER or does not verify against the
key registered under the current pairing) answers one `approval_invalid` result error
instead of `results`.

An exact resend is answered, not refused. The vault keeps each accepted envelope's reply,
keyed by the SHA-256 of the envelope bytes and scoped to the phone that sent it, until
`issued_at_ms + 120000` — the same skew limit the envelope is checked against. A
byte-identical envelope sent again by that phone in that window, signed again or not,
gets its first `results` back and grants nothing a second time. So a phone whose reply was
lost learns the outcome by resending the exact bytes. This is not a licence to re-sign:
a different envelope naming an already-consumed request is refused `approval_invalid`, and
so is an exact resend after the window, when it is handled as the ordinary duplicate-item
case. The signed delete commit follows the same rule.

#### `secret.list`

Request `{}`. Reply `{secrets: [{name, kind, incarnation, state, host?, path_prefix?,
location?, origin?, grants: [{grant_id, scope: {owner, kind, ref}, coverage, duration,
agent_id, expires_at_ms?, last_use_ms?, local_use?}], flow_grants: [{grant_id, flow: {flow_id,
version, install_id}, duration, methods?, last_use_ms?}]}],
ssh_keys?: [{credential_id, incarnation, fingerprint, grants}]}`. An API key carries `host`,
`location` and `path_prefix` (omitted when it covers every path); a login carries `origin`.
`state` is `active` or `corrupt`. An agent grant always names its `agent_id`, `null` when
the statement named no agent, and omits `expires_at_ms` when its duration is `permanent`.
A flow grant appears in `flow_grants` with `flow` and duration `version` in place of an
asking scope and coverage, and carries `methods` only for an API key. A grant of either
kind omits `last_use_ms` until it has served a call. Material, its digests and requested
paths never appear.

A local-program grant includes `local_use: {program, use, target}`. `ssh_keys` lists
keys with live SSH signing grants and is omitted when none exist. Each key's `grants`
use the same shape as the agent grants in `secrets`, including `local_use`.

<!-- golden:list.request -->
```json
{}
```

<!-- golden:list.result -->
```json
{"secrets":[{"name":"key","kind":"agent_api_key","incarnation":"0123456789abcdef0123456789abcdef","state":"active","host":"x.test","path_prefix":"/repos/a","location":"header:X-Api-Key","grants":[{"grant_id":"01HF7YB0000000000000000001","scope":{"owner":"reserved:prefrontal-core","kind":"head","ref":"H"},"coverage":"scope","duration":"permanent","agent_id":"agent-A","last_use_ms":1700000003000}],"flow_grants":[]},{"name":"login","kind":"site_login","incarnation":"fedcba9876543210fedcba9876543210","state":"active","origin":"https://x.test","grants":[{"grant_id":"01HF7YB0000000000000000002","scope":{"owner":"reserved:prefrontal-core","kind":"worker","ref":"W"},"coverage":"scope","duration":"hour","expires_at_ms":1700003600000,"agent_id":null,"last_use_ms":1700000002000}],"flow_grants":[]}]}
```

Expired grants are swept only after current-pairing registration passes, with one
`secret_grant_expire` chain row per removal.

An API key and a login with live flow grants, neither used yet:

<!-- golden:list.result.flow -->
```json
{"secrets":[{"name":"key","kind":"agent_api_key","incarnation":"0123456789abcdef0123456789abcdef","state":"active","host":"x.test","path_prefix":"/repos/a","location":"header:X-Api-Key","grants":[],"flow_grants":[{"grant_id":"01HF7YB0000000000000000001","flow":{"flow_id":"daily-fetch","version":7,"install_id":"install-A"},"duration":"version","methods":["GET"]}]},{"name":"login","kind":"site_login","incarnation":"fedcba9876543210fedcba9876543210","state":"active","origin":"https://x.test","grants":[],"flow_grants":[{"grant_id":"01HF7YB0000000000000000002","flow":{"flow_id":"daily-fetch","version":7,"install_id":"install-A"},"duration":"version"}]}]}
```

`crates/credentials-core/tests/vectors/secret-list-flow-v1.json` pins four phone samples:
an unused API-key flow grant, a used API-key flow grant with `last_use_ms`, an API key
with both agent and flow grants, and a login flow grant without `methods`. Each case
includes the `secret.list` request, the decoded reply inside the phone route's `result`
envelope, and the exact reply bytes as unpadded base64url with their SHA-256. The vault
emits these samples from real deposits, signed approvals and listing; regenerate them
with `CK_EMIT_SECRET_VECTORS=1` and the
`secret_list_flow_ckios_vectors_are_emitted_by_vault_code_and_pinned` test.

#### `secret.delete`

Two steps, told apart by their key sets. Step 1 is `{name}`; it answers
`{status: "approval_required", request_id, statement_b64url, expires_at_ms}` for a delete
statement. A name with no row answers the uniform `not_found`; an unset self member id
answers `secret_setup_incomplete`. A repeat while a live delete request exists for that
incarnation returns the same request.

<!-- golden:delete.request.name -->
```json
{"name":"key"}
```

<!-- golden:delete.result.statement -->
```json
{"status":"approval_required","request_id":"01HF7YAT000000000000000001","statement_b64url":"eyJtZW1iZXJfaWQiOiJmZWQtY29tcHV0ZXI6MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJyZXF1ZXN0X2V4cGlyZXNfYXRfbXMiOjE3MDAwMDA2MDAwMDAsInJlcXVlc3RfaWQiOiIwMUhGN1lBVDAwMDAwMDAwMDAwMDAwMDAwMSIsInNlY3JldCI6eyJpbmNhcm5hdGlvbiI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTQ5Iiwia2luZCI6ImFnZW50X2FwaV9rZXkiLCJuYW1lIjoia2V5In0sInYiOiJjay1zZWNyZXQtZGVsZXRlLXN0YXRlbWVudC92MSJ9","expires_at_ms":1700000600000}
```

Step 2 is `{envelope_b64url, signature_b64url}` with a `delete` envelope (no `card_ref`).
It answers the same `{results: […]}` shape as `secret.approve`, where `granted` means the
deletion committed.

<!-- golden:delete.request.signed -->
```json
{"envelope_b64url":"eyJkZWNpc2lvbiI6ImRlbGV0ZSIsImRldmljZV9maW5nZXJwcmludCI6IjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwiZHVyYXRpb24iOiJub25lIiwiZ3JhbnRfZXhwaXJlc19hdF9tcyI6MTcwMDAwMDYwMDAwMCwiaXNzdWVkX2F0X21zIjoxNzAwMDAwMDAwMDAwLCJpdGVtcyI6W3sicmVxdWVzdF9pZCI6IjAxSEY3WUFUMDAwMDAwMDAwMDAwMDAwMDAxIiwic3RhdGVtZW50X3NoYTI1NiI6ImRmNjVhZDhjZDYzYjVlYmVlODBkNTg3ZDMwNWM4ZTE5NjExMjFhMzY3MWYxZDY2NTg0MjQyNTJhZTdiZmE1ZjIifV0sInYiOiJjay1zZWNyZXQtdXNlLWVudmVsb3BlL3YxIn0","signature_b64url":"MEUCIDo_hfKhCP8-j278u87PM-UKFEFb_AoGvVbbrjXugL8YAiEA6rbPE4zDISfvxqLF96TioYQoQ__NMZZ3mLqxLZdJyoU"}
```

<!-- golden:delete.result -->
```json
{"results":[{"request_id":"01HF7YAT000000000000000001","outcome":"granted"}]}
```

#### `secret.revoke_grant`

Request `{grant_id}`. Unsigned, because it only removes access. Reply `{outcome}`:
`revoked`, or `not_found` for an unknown or expired grant.

<!-- golden:revoke_grant.request -->
```json
{"grant_id":"01HF7YB0000000000000000001"}
```

<!-- golden:revoke_grant.result -->
```json
{"outcome":"revoked"}
```

### `secret.use`: the sender contract

Only `reserved:aft` and `reserved:cerebellum` may call `secret.use` for an agent scope, and
`reserved:basal` for a flow run (see "Flow secrets" below); every other caller gets the
uniform `not_found` before its params are read. AFT receives only API keys and Cerebellum
only site logins; basal receives both kinds.

**Request** `{name, coverage?, stamp, target}` for an agent caller:

* `name`: the secret name, grammar as above.
* `coverage?`: `"scope"` (the default when omitted) or `"agent_and_workers"`. Coverage
  only shapes a new approval statement: `agent_and_workers` is valid only when the mapped
  asking scope is a Head (an Ephemeral that maps to its Head qualifies) and is offered only
  `permanent`. Grant lookup always uses every live grant.
* `stamp`: the `ScopeStamp` of the call being served, passed on exactly as subc delivered
  it on that call's route bind. The vault cannot verify it and trusts the two senders to
  relay it unchanged; it takes the asking scope from nowhere else.
* `target`: for an API key `{scheme, host, port?, path}`, with `port` an integer that
  defaults to 443; for a login `{origin}`, the frame's origin string.

There is **no agent name parameter**. A sender holds no trusted human-readable name for
an agent, and the approval statement is signed, so the vault names the agent only by the
stamp's `attributes.agent_id`. Showing a person-readable name for the agent is the
approval card's job (Cingulate's), not the vault's. A request that still carries
`display_name` is refused with `invalid_params` as an unknown key.

**Stamp grammar**, from subc-protocol's `ScopeStamp` (`crates/subc-protocol/src/scope.rs`
in the subconscious repository, at the version locked in `Cargo.lock`):

| Field | Required | Shape | Used for |
|---|---|---|---|
| `owner` | yes | principal object: `{"kind":"reserved","module_id":…}`, `{"kind":"direct"}` or `{"kind":"unverified"}` | the asking scope's owner, rendered `reserved:<module_id>`, `direct` or `unverified` |
| `ref` | yes | string | the asking scope's ref |
| `scope_epoch` | yes | integer, at most 2^53 − 1 | the asking scope's epoch |
| `kind` | yes | `"head"`, `"worker"` or `"ephemeral"` | the mapping rule |
| `owner_authorized` | yes | boolean | required by the decoder; grants no authority here |
| `parent` | no | `{owner, ref, scope_epoch}`, with `owner` a principal object as above and `scope_epoch` at most 2^53 − 1 | Ephemeral mapping and Worker-under-Head coverage |
| `parent_state` | no | `"linked"`, `"pending"` or `"ended"`; only `linked` counts as live | as `parent` |
| `attributes` | no | object with optional `agent_id`, `on_behalf_of_agent`, `delegates`, `flow_id`, `run_id`; unknown attribute keys are refused | `agent_id` (or a worker's `on_behalf_of_agent`) names the agent in statements and the permissions listing; a present `flow_id` (a flow-read scope) maps to nothing |
| `workdir`, `project_id`, `expires_at_ms` | no | as subc defines them | ignored |

Other top-level stamp keys are ignored, as subc's decoder does. A stamp missing any required
field answers the uniform `not_found`; a stamp whose fields are present but malformed is
`invalid_params`. Mapping uses only the stamp: a Head or Worker maps to itself; an
Ephemeral maps to its parent (as a Head) only when `parent.owner` is
`reserved:prefrontal` (the module's id before its rename, `reserved:prefrontal-core`, maps
to nothing), `parent_state` is `linked` and `parent.scope_epoch` equals the
stamp's `scope_epoch`; anything else, and every flow-read scope, maps to nothing (uniform
`not_found`). A Worker is also served by an `agent_and_workers` grant on Head H when its
stamp's parent has H's owner and ref, `parent_state` `linked` and an equal epoch.

**Target rules.** A stored API-key scope matches only scheme `https` on port 443. The
scheme's grammar is checked first (lowercase letters, digits, `+`, `-`, `.`; anything else
is `invalid_params`), but another scheme or port is not a grammar error: it can never
match, so it is answered as the uniform `not_found`. The host is lowercase ASCII
(IDN as A-labels), with no trailing dot and no IP literal, and must equal the record's host.
The path starts with `/` and holds only RFC 3986 pchar bytes and `/`. Senders strip the
query and fragment before calling; a path with `?` or `#` is `invalid_params`. Refused,
never normalised: a raw `\`, space, control byte or byte ≥ 0x80; a percent-escape (either
case) that decodes to `/`, `.`, `%`, `\`, `;`, a byte below 0x21 or a byte at or above
0x7F; a segment whose part before the first `;` is `.` or `..`; an empty segment except
one trailing `/`. A path matches a stored prefix when it equals it or starts with prefix +
`/`, compared on raw bytes. A login origin is canonical `https://host` with port 443
omitted, so `https://x.test:443` equals `https://x.test`.

<!-- golden:use.request.api_key -->
```json
{"name":"key","coverage":"scope","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"scheme":"https","host":"x.test","port":443,"path":"/repos/a/issues/1"}}
```

The same call with `coverage` and `port` omitted is equivalent:

<!-- golden:use.request.api_key.defaults -->
```json
{"name":"key","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"scheme":"https","host":"x.test","path":"/repos/a/issues/1"}}
```

A login asked for by a Worker whose parent is a live Head:

<!-- golden:use.request.site_login -->
```json
{"name":"login","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"W","scope_epoch":7,"kind":"worker","parent":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7},"parent_state":"linked","attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"origin":"https://x.test"}}
```

**Replies.** Exactly one of three success shapes, as a `Response` result:

API key released to AFT, `{status: "released", kind: "agent_api_key", key_b64url,
location}`; `location` tells AFT where to put the key and took no part in matching:

<!-- golden:use.result.released.api_key -->
```json
{"status":"released","kind":"agent_api_key","key_b64url":"c2stZXhhbXBsZQ","location":"header:X-Api-Key"}
```

Login released to Cerebellum, `{status: "released", kind: "site_login", username,
password, totp?}`; `totp` is the current code, present only when the record holds a TOTP
seed. The seed itself never leaves the vault.

<!-- golden:use.result.released.site_login -->
```json
{"status":"released","kind":"site_login","username":"alice","password":"correct horse","totp":"123456"}
```

No live grant covers the call, `{status: "approval_required", request_id,
statement_b64url, expires_at_ms}`. The sender shows nothing from it to the model; the
statement goes to the approval card, and the sender retries `secret.use` after the phone
answers. `approval_required` does not mean any phone can currently approve: it is returned
whether or not one is registered and paired. An uncovered call matching a live request on
(incarnation, mapped owner, kind and ref, coverage) gets that request back unchanged,
whatever its path.

<!-- golden:use.result.approval_required -->
```json
{"status":"approval_required","request_id":"01HF7YAT000000000000000001","statement_b64url":"eyJhZ2VudF9pZCI6ImFnZW50LUEiLCJjb3ZlcmFnZSI6InNjb3BlIiwiZHVyYXRpb25zIjpbIm9uY2UiLCJob3VyIiwic2Vzc2lvbiIsInBlcm1hbmVudCJdLCJtZW1iZXJfaWQiOiJmZWQtY29tcHV0ZXI6MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJyZXF1ZXN0X2V4cGlyZXNfYXRfbXMiOjE3MDAwMDA2MDAwMDAsInJlcXVlc3RfaWQiOiIwMUhGN1lBVDAwMDAwMDAwMDAwMDAwMDAwMSIsInNjb3BlIjp7ImVwb2NoIjo3LCJraW5kIjoiaGVhZCIsIm93bmVyIjoicmVzZXJ2ZWQ6cHJlZnJvbnRhbC1jb3JlIiwicmVmIjoiSCJ9LCJzZWNyZXQiOnsiaW5jYXJuYXRpb24iOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDE0OSIsImtpbmQiOiJhZ2VudF9hcGlfa2V5IiwibmFtZSI6ImtleSJ9LCJ1c2UiOnsiaG9zdCI6IngudGVzdCIsImxvY2F0aW9uIjoiaGVhZGVyOlgtQXBpLUtleSIsInBhdGhfcHJlZml4IjoiL3JlcG9zL2EifSwidiI6ImNrLXNlY3JldC11c2Utc3RhdGVtZW50L3YxIn0","expires_at_ms":1700000600000}
```

**Ordered checks and refusals.** Checking stops at the first failure.

| Step | Condition | Answer |
|---|---|---|
| 1 | caller is not AFT or Cerebellum | uniform `not_found` |
| 2 | name, coverage value or target grammar invalid; unknown or missing key; malformed stamp | `invalid_params` Error frame |
| 2 | a name or other length over its limit | `limit_exceeded` (`context_overflow`) |
| 3 | the stamp maps to nothing, or lacks a field the mapping needs | uniform `not_found` |
| 3 | `agent_and_workers` for a mapped scope that is not a Head | `invalid_params` Error frame |
| 4 | unknown name, `corrupt` record, sealed-scope mismatch, kind not released to this sender, or target mismatch | uniform `not_found` |
| 5 | a live grant covers the call | `released` |
| 6 | this vault's member id is unset | `secret_setup_incomplete` (`permanent`) |
| 6 | otherwise | `approval_required`, or `pending_limit` (`transient`) past 8 live requests per mapped scope or 64 in total |
| any | a store failure or failed release-audit commit | `store_error` (`transient`); nothing is released and no `once` grant is consumed |

Steps 1 to 4 create no pending request, and every `not_found` above is byte-identical, so a
sender cannot tell which check refused. `approval_required` confirms to the trusted sender
that the name, kind and target it supplied exist; that is the one accepted disclosure.

### Flow secrets: install approval, run-time use and revocation

A flow grant lets one **installed flow version** use a secret while basal runs it, so a
scheduled flow reads its own API key instead of waking an agent. The holder is the identity
basal's stamp carries — `flow_id`, `flow_version`, `flow_code_hash` and `flow_install_id` —
not an asking scope. All four arrive together and only with `flow_id`. `flow_code_hash` is
core's stored hash: 64 lowercase hex, compared byte for byte and never recomputed here.

Basal is the only caller of `secret.request_flow_approval`, `secret.revoke_flow_grants` and
a flow-run `secret.use`; every other caller gets the uniform `not_found` before its params
are read. Basal's `secret.use` is flow-only: a stamp without the flow attributes is that
uniform `not_found` too, never an asking scope, so basal can never reach an agent grant.
The reverse holds as well — a flow grant never satisfies `reserved:aft` or
`reserved:cerebellum`, whose `secret.use` keeps its closed key set and its
`approval_required` reply byte for byte.

#### The flow identity object

Install requests, flow statements and `secret.list` rows write the same identity as one
nested object, with the stamp's names shortened:

| Stamp attribute (`scope.attributes.flow_*`) | Nested key |
|---|---|
| `flow_id` | `flow_id` |
| `flow_version` | `version` |
| `flow_code_hash` | `code_hash` |
| `flow_install_id` | `install_id` |

`flow_id` is 1–256 printable ASCII bytes; `version` is an integer from 1 to 2^53 − 1;
`code_hash` is exactly 64 lowercase hex characters; `install_id` is 1–256 printable ASCII
bytes (core mints 1–64 of `[A-Za-z0-9_-]`).

**Methods** describe how an API key may be used. Each is 1–16 bytes of `[A-Z]`, compared
byte for byte against the method of the call being served. `methods` belongs to API keys
alone: it is required for an API-key `target` and forbidden for a login `target`, checked
against the caller's own `target` before any secret lookup, so the refusal for a missing or
malformed list never depends on whether the name exists. The list is non-empty, without
duplicates, and stored and signed sorted ascending, so `["POST","GET"]` is accepted and
stored as `["GET","POST"]`, while `[]`, `["GET","GET"]`, `["get"]` and `["A",…]` past
16 bytes are `invalid_params`. A flow-run `secret.use` names its single `method` the same
way, and only for an API key.

#### `secret.request_flow_approval`

Basal calls this once per secret an installed flow version needs, when the flow is
installed. Request `{name, flow, target, methods?}`: `name` has the usual grammar, `flow` is
the identity object above, `target` has the same shapes as `secret.use` (an API key
`{scheme, host, port?, path}` or a login `{origin}`), and `methods` is required with an
API-shaped target and forbidden with a login target. There is no `coverage`, no `stamp` and
no agent name.

<!-- golden:request_flow_approval.request.api_key -->
```json
{"name":"key","flow":{"flow_id":"daily-fetch","version":7,"code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","install_id":"install-A"},"target":{"scheme":"https","host":"x.test","port":443,"path":"/repos/a/issues/1"},"methods":["GET"]}
```

The same ask for a site login, which has no `methods`:

<!-- golden:request_flow_approval.request.site_login -->
```json
{"name":"login","flow":{"flow_id":"daily-fetch","version":7,"code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","install_id":"install-A"},"target":{"origin":"https://x.test"}}
```

Reply `{status: "approval_required", request_id, statement_b64url, expires_at_ms}`, the same
shape `secret.use` answers in the same case:

<!-- golden:request_flow_approval.result -->
```json
{"status":"approval_required","request_id":"01HF7YAT000000000000000001","statement_b64url":"eyJkdXJhdGlvbnMiOlsidmVyc2lvbiJdLCJmbG93Ijp7ImNvZGVfaGFzaCI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJmbG93X2lkIjoiZGFpbHktZmV0Y2giLCJpbnN0YWxsX2lkIjoiaW5zdGFsbC1BIiwidmVyc2lvbiI6N30sIm1lbWJlcl9pZCI6ImZlZC1jb21wdXRlcjoyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsInJlcXVlc3RfZXhwaXJlc19hdF9tcyI6MTcwMDAwMDYwMDAwMCwicmVxdWVzdF9pZCI6IjAxSEY3WUFUMDAwMDAwMDAwMDAwMDAwMDAxIiwic2VjcmV0Ijp7ImluY2FybmF0aW9uIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxNDkiLCJraW5kIjoiYWdlbnRfYXBpX2tleSIsIm5hbWUiOiJrZXkifSwidXNlIjp7Imhvc3QiOiJ4LnRlc3QiLCJsb2NhdGlvbiI6ImhlYWRlcjpYLUFwaS1LZXkiLCJtZXRob2RzIjpbIkdFVCJdLCJwYXRoX3ByZWZpeCI6Ii9yZXBvcy9hIn0sInYiOiJjay1zZWNyZXQtZmxvdy1zdGF0ZW1lbnQvdjEifQ","expires_at_ms":1700000600000}
```

**Ordered checks and refusals.** Checking stops at the first failure.

| Step | Condition | Answer |
|---|---|---|
| 1 | caller is not `reserved:basal` | uniform `not_found` |
| 2 | name, flow identity or target grammar invalid; `methods` missing, forbidden or malformed; unknown or missing key | `invalid_params` Error frame |
| 2 | a name over its limit | `limit_exceeded` (`context_overflow`) |
| 3 | unknown name, `corrupt` record, sealed-scope mismatch, or target mismatch | uniform `not_found` |
| 4 | an identical (incarnation, flow identity, methods) request is still live | the same request id and bytes |
| 4 | 16 live flow requests for this `flow_install_id`, or 256 flow requests in total, counted separately from agent requests | `pending_limit` (`transient`) |
| 4 | this vault's member id is unset | `secret_setup_incomplete` (`permanent`) |
| 4 | otherwise | `approval_required` with a new request |
| any | a store failure | `store_error` (`transient`); no request is created |

The request expiry is a 24-hour pending lifetime for flow requests. Approval grants a duration
`version` grant, which has no expiry of its own; the two are unrelated.

#### `secret.use` from a flow run

Basal's `secret.use` has the key set `{name, stamp, target, method?}`: no `coverage` (an
explicit `coverage` is `invalid_params`), and `method` only with an API-shaped `target`. The
stamp is the flow-run `ScopeStamp` relayed exactly as subc delivered it, and the four
`flow_*` attributes are read from `stamp.attributes`; they are never taken from the vault's
own route binding. A request whose stamp carries no `flow_id`, or whose four attributes are
not all present, is the uniform `not_found` and records the `flow_identity` refusal detail.

<!-- golden:use.request.flow.api_key -->
```json
{"name":"key","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A","flow_code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","flow_id":"daily-fetch","flow_install_id":"install-A","flow_version":7},"owner_authorized":true},"target":{"scheme":"https","host":"x.test","port":443,"path":"/repos/a/issues/1"},"method":"GET"}
```

A flow run serving a site login, which carries no `method`:

<!-- golden:use.request.flow.site_login -->
```json
{"name":"login","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A","flow_code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","flow_id":"daily-fetch","flow_install_id":"install-A","flow_version":7},"owner_authorized":true},"target":{"origin":"https://x.test"}}
```

It releases only when a live flow grant for the secret's current incarnation matches all
four attributes exactly, the target passes the usual scope check, and, for an API key, the
`method` is in the grant's `methods`. The reply is the same three success shapes as an agent
call, and so is every refusal: `not_found` covers an unknown secret, a wrong kind, no grant,
a wrong target and an undeclared method alike. A flow run never creates a pending request
and never gets `approval_required`; only `secret.request_flow_approval` does.

**Refusal details.** Each refusal writes an `auth_events` row whose `detail` is the variant
name only, never an identity value: `unknown_name`, `corrupt`, `sealed_scope`, `kind`,
`target`, and for flow calls `flow_identity` (the stamp is not a complete flow identity),
`flow_no_grant` (a complete identity with no matching grant) and `flow_method` (a grant
exists but does not declare this method).

#### `secret.revoke_flow_grants`

Request `{flow_install_id, flow_version?}`: the install to clear, and optionally one
version of it. Reply `{status: "revoked", grants}`, where `grants` is the number of grants
removed and may be 0; the call is idempotent. In one transaction it deletes the matching
flow grants and the matching unconsumed flow approval requests, so a request signed within
its 24-hour pending lifetime cannot recreate a grant that was just revoked.

<!-- golden:revoke_flow_grants.request -->
```json
{"flow_install_id":"install-A","flow_version":7}
```

<!-- golden:revoke_flow_grants.result -->
```json
{"status":"revoked","grants":1}
```

Without `flow_version` every version of that install is cleared:

<!-- golden:revoke_flow_grants.request.all_versions -->
```json
{"flow_install_id":"install-A"}
```

<!-- golden:revoke_flow_grants.result.none -->
```json
{"status":"revoked","grants":0}
```

Basal revokes on uninstall, and a version's grants once a newer version replaced it and its
last run finished. Deleting a secret also deletes its flow grants and its pending flow
requests. The vault never expires an older version's grants when a newer one is granted, so
a still-running old version is not cut off; only an explicit revoke or a delete removes a
grant.

#### Listing a flow grant

`secret.list` shows a flow grant under a new per-secret array, `flow_grants`, whose
`{grant_id, flow, duration, methods?, last_use_ms?}` names the flow identity object in place
of an asking scope, has no `coverage` and no `expires_at_ms`, and carries `methods` only for
an API key. `ck auth secret list` and `ck auth secret grants` print the holder as
`flow:<flow_id>@<version>/<install_id>`, with duration `version` and
`methods=<A,B>` where the secret has methods, and `expiry=none`.

`permissions.list` lists each flow grant as one row, in the flow holder that Cingulate's
`permissions/v1` contract defines from tag `permissions-v1.1` (cingulate `49fab2ea`; the
vendored provider vectors `grt_06` and `grt_07` pin the shape). The holder is
`{kind: "flow", flow_id, flow_version, flow_install_id}`. The row carries `methods`, a
non-empty list of uppercase HTTP methods, only for an API-key grant, and carries neither
`agent_id` nor `expires_at_ms`. Flow rows appear only in an unfiltered read: a row that
names no agent can never answer `permissions.list {agent_id}`.

#### The flow statement

The flow statement is `ck-secret-flow-statement/v1`: the `ck-secret-use-statement/v1`
fields except that `flow` replaces `scope` and `agent_id`, there is no `coverage`,
`durations` is exactly `["version"]`, and an API key's `use` gains `methods`. `use` is built
from the secret's stored scope as for an agent, so approval binds the stored host and path
prefix (or origin), and any run-time target that passes the scope check is covered. This
statement is the pinned flow vector `flow-version` of
`crates/credentials-core/tests/vectors/secret-flow-approval-v1.json`, decoded:

<!-- golden:statement.flow -->
```json
{"durations":["version"],"flow":{"code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","flow_id":"daily-fetch","install_id":"install-A","version":7},"member_id":"fed-computer:22222222222222222222222222222222","request_expires_at_ms":1700000600000,"request_id":"01HF7YAT000000000000000001","secret":{"incarnation":"00000000000000000000000000000149","kind":"agent_api_key","name":"key"},"use":{"host":"x.test","location":"header:X-Api-Key","methods":["GET"],"path_prefix":"/repos/a"},"v":"ck-secret-flow-statement/v1"}
```

A login's flow statement carries `use: {origin}` and no `methods`.

#### The `version` duration

A flow approval is an `allow` envelope whose `duration` is `version` and whose
`grant_expires_at_ms` is 0. `version` is valid only on an `allow` envelope with that 0, and
every other duration value keeps the meaning it has for agents. The envelope keeps its shape
and its single `grant_expires_at_ms` for the whole batch; `ApprovalItem` stays
`{request_id, statement_sha256}` and an item carrying any other key, `duration` included, is
the whole-envelope `approval_invalid`.

<!-- golden:envelope.flow -->
```json
{"decision":"allow","device_fingerprint":"11111111111111111111111111111111","duration":"version","grant_expires_at_ms":0,"issued_at_ms":1700000000000,"items":[{"request_id":"01HF7YAT000000000000000001","statement_sha256":"bcf3f59a99c0beaa52366c6fa37af6a799460257215252d804ce7474240a7c57"},{"request_id":"01HF7YAT000000000000000002","statement_sha256":"1a912e7090daa30f10111228ae3ef4275fd6faaae754f2aec9c3f6cbc90bb6b8"}],"v":"ck-secret-use-envelope/v1"}
```

<!-- golden:envelope.flow.bytes -->
```json
"eyJkZWNpc2lvbiI6ImFsbG93IiwiZGV2aWNlX2ZpbmdlcnByaW50IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJkdXJhdGlvbiI6InZlcnNpb24iLCJncmFudF9leHBpcmVzX2F0X21zIjowLCJpc3N1ZWRfYXRfbXMiOjE3MDAwMDAwMDAwMDAsIml0ZW1zIjpbeyJyZXF1ZXN0X2lkIjoiMDFIRjdZQVQwMDAwMDAwMDAwMDAwMDAwMDEiLCJzdGF0ZW1lbnRfc2hhMjU2IjoiYmNmM2Y1OWE5OWMwYmVhYTUyMzY2YzZmYTM3YWY2YTc5OTQ2MDI1NzIxNTI1MmQ4MDRjZTc0NzQyNDBhN2M1NyJ9LHsicmVxdWVzdF9pZCI6IjAxSEY3WUFUMDAwMDAwMDAwMDAwMDAwMDAyIiwic3RhdGVtZW50X3NoYTI1NiI6IjFhOTEyZTcwOTBkYWEzMGYxMDExMTIyOGFlM2VmNDI3NWZkNmZhYWFlNzU0ZjJhZWM5YzNmNmNiYzkwYmI2YjgifV0sInYiOiJjay1zZWNyZXQtdXNlLWVudmVsb3BlL3YxIn0"
```

The offered duration is checked per item. In a `version` envelope an agent item is refused
`approval_invalid` and a flow item is granted; in a `once`, `hour`, `session` or `permanent`
envelope a flow item is refused and the batch's other items proceed. The envelope's own
`approval_invalid` results never say which item failed a check.

#### `flow-identity-scopes/v1`

The vault's manifest provides `permissions/v1` and `flow-identity-scopes/v1`. subc-protocol
0.33.2 stamps `flow_version`, `flow_code_hash` and `flow_install_id` on a `ScopeStamp` only
for a reader that declares `flow-identity-scopes/v1`, so a vault without it would see
`flow_id` alone and could not hold a flow to one installed version. The vault needs the
fields themselves, not flow-scoped authority: it reads them from the sender's params and
still refuses a flow-scoped transport route bind. The capability therefore widens what the
stamp carries to this reader and changes nothing about who may use what.

### Forwarded secrets: the member relays the home's answer

Senders do not change. AFT, Cerebellum and basal keep calling their local vault's
`secret.use`, `secret.request_flow_approval` and `secret.revoke_flow_grants` with the same
request and reply shapes. On a remote-role vault the local vault looks nothing up locally:
it forwards the call to the home over the federation channel and relays the home's answer,
mapped to the same §15 reply and refusal shapes. A request from another computer with the
same stamp gets its own v2 approval request, never the other computer's grant: the holder
is the asking computer, and pending reuse never merges requests from different askers. Only
a forwarded flow approval also refuses a flow id equal to a v2 tag; the local check stays
v1-only, so single-computer behaviour is unchanged.

The asking vault's retry deadline is shorter than the home's 10-minute receipt lifetime.
A forwarded call that authoritatively fails (unknown secret, wrong target or flow identity,
unpaired member, missing or stale `secret_use` grant, changed incarnation, gone or expired
grant) is the uniform `not_found`. A check that cannot be performed keeps its transient
code and decides nothing: a callosum timeout or `fed_not_ready` at the home answers
`home_unavailable`, and a home store failure keeps its mapped transient code; neither
writes a refusal audit. The
member maps the home's answer to its consumer as:

| Home answer | Member's `secret.use` code / class | Stored effect |
|---|---|---|
| `approval_required`, `released` (opened) | relayed (§15 shapes) | diagnostics only |
| §15 refusal code | same code, this vault's own class | outcome only |
| `home_unavailable`, or a code this vault does not know | `home_unavailable` / transient | outcome only |
| unreachable, deadline, partition, retry-safe or outcome-unknown callosum failure | `home_unreachable` / transient | outcome only |
| this vault's own self id or transfer key absent | `transfer_key_missing` / permanent, `remedy_member` = this vault when its self id is known | outcome only |
| no announced key for the home, or an unusable role setting | `remote_setup_incomplete` / permanent, `remedy_member` = who must fix it | outcome only |
| permanent callosum class | `federation_setup_invalid` / permanent | outcome only |
| the sealed reply will not open (aad, key or info mismatch) | `remote_seal_invalid` / permanent | outcome only |
| the opened reply fails validation | `remote_reply_invalid` / permanent | outcome only |

Only grants made for the asking computer release, and a release crosses back only sealed.
The asking vault records each forwarded call and its outcome code (never material); the
home records requests, grants and releases as locally, plus `asking_member_id`. A grant
revocation, timed-grant expiry, `secret.revoke_flow_grants` or secret delete ends replay at
once: a same-nonce retry is `not_found`.

#### Forwarded statements are v2

Local statements stay `ck-secret-use-statement/v1` and `ck-secret-flow-statement/v1`, byte
for byte. A forwarded request produces `ck-secret-use-statement/v2` and
`ck-secret-flow-statement/v2`: the v1 object plus one required key,
`"asking_member_id":"fed-computer:…"`, RFC 8785 canonical as today. Approval checks the
statement's `asking_member_id` equals the pending row's, and that the version is v2 exactly
when the row's value is non-empty. The grant inherits the pending row's value. Delete
statements are unchanged. The v2 tags are registered in `docs/domain-separators.txt`. Phone
and Cingulate strict decoders reject v2 until they add it: only after the operator sets
`secrets.home_member` is a v2 statement ever produced, because nothing forwards while the
setting is unset.

The v2 examples are the pinned flow vectors' forwarded cases
(`crates/credentials-core/tests/vectors/secret-approval-v2.json` and
`secret-flow-approval-v2.json`), decoded:

<!-- golden:statement.use.v2 -->
```json
{"agent_id":"agent-A","asking_member_id":"fed-computer:11111111111111111111111111111111","coverage":"scope","durations":["once","hour","session","permanent"],"member_id":"fed-computer:22222222222222222222222222222222","request_expires_at_ms":1700000600000,"request_id":"01HF7YAT000000000000000001","scope":{"epoch":7,"kind":"head","owner":"reserved:prefrontal-core","ref":"H"},"secret":{"incarnation":"00000000000000000000000000000149","kind":"agent_api_key","name":"key"},"use":{"host":"x.test","location":"header:X-Api-Key","path_prefix":"/repos/a"},"v":"ck-secret-use-statement/v2"}
```

<!-- golden:statement.flow.v2 -->
```json
{"asking_member_id":"fed-computer:11111111111111111111111111111111","durations":["version"],"flow":{"code_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","flow_id":"daily-fetch","install_id":"install-A","version":7},"member_id":"fed-computer:22222222222222222222222222222222","request_expires_at_ms":1700000600000,"request_id":"01HF7YAT000000000000000001","secret":{"incarnation":"00000000000000000000000000000149","kind":"agent_api_key","name":"key"},"use":{"host":"x.test","location":"header:X-Api-Key","methods":["GET"],"path_prefix":"/repos/a"},"v":"ck-secret-flow-statement/v2"}
```

A login's v2 statement carries `use: {origin}` and no `methods`, as its v1 does.
`secret_contract_tests.rs` (`forwarded_statements_are_v2_and_match_the_pinned_vectors`)
pins the v2 key sets (each v1 set plus `asking_member_id`), checks the golden text equals
the real encoders' pinned vectors byte for byte, and checks a forwarded approval from the
real store carries the v2 tag naming the asker while the local one stays v1.

### Signed statement and envelope

The approval statement, the delete statement and the envelope are RFC 8785 (JCS)
canonical JSON, carried as unpadded base64url. All integers are JSON numbers no larger
than 2^53 − 1; there are no floats; strings are UTF-8. Their `v` field is their domain
tag, registered in `docs/domain-separators.txt`. The examples below are the pinned phone-app
test vectors (`crates/credentials-core/tests/vectors/secret-approval-v1.json`), decoded.

Approval statement, exactly `{v, request_id, member_id, scope: {owner, kind, ref, epoch},
agent_id, coverage, secret: {name, kind, incarnation}, use, durations,
request_expires_at_ms}`:

* `scope` is the mapped asking scope; `owner` is rendered as in the stamp grammar.
* `agent_id` is `attributes.agent_id` for a `head` stamp. For a `worker` stamp it is
  only `attributes.on_behalf_of_agent`, or `null` when absent; `attributes.agent_id`
  is ignored, with no parent or other identity fallback. Ephemeral and other scopes
  keep the existing `attributes.agent_id`-or-`null` behavior. This is display
  attribution, not authority: the grant stays bound to the mapped asking scope.
  The approval card supplies the human name. Worker v1, forwarded v2, multi-host v3,
  unnamed-worker and grant-listing samples are pinned in
  `crates/credentials-core/tests/vectors/secret-worker-agent-v1.json`.
* `use` is taken from the record's sealed scope: `{host, path_prefix, location}` for an
  API key (`path_prefix` is `""` for every path) or `{origin}` for a login. It never
  carries the requested path.
* `durations` is the offered list in the order once, hour, session, permanent; an
  `agent_and_workers` statement offers only `permanent`.

<!-- golden:statement.use -->
```json
{"agent_id":"agent-A","coverage":"scope","durations":["once","hour","session","permanent"],"member_id":"fed-computer:22222222222222222222222222222222","request_expires_at_ms":1700000600000,"request_id":"01HF7YAT000000000000000001","scope":{"epoch":7,"kind":"head","owner":"reserved:prefrontal-core","ref":"H"},"secret":{"incarnation":"00000000000000000000000000000149","kind":"agent_api_key","name":"key"},"use":{"host":"x.test","location":"header:X-Api-Key","path_prefix":"/repos/a"},"v":"ck-secret-use-statement/v1"}
```

Delete statement, exactly `{v, request_id, member_id, secret: {name, kind, incarnation},
request_expires_at_ms}`:

<!-- golden:statement.delete -->
```json
{"member_id":"fed-computer:22222222222222222222222222222222","request_expires_at_ms":1700000600000,"request_id":"01HF7YAT000000000000000001","secret":{"incarnation":"00000000000000000000000000000149","kind":"agent_api_key","name":"key"},"v":"ck-secret-delete-statement/v1"}
```

Envelope, exactly `{v, items: [{request_id, statement_sha256}], decision, duration,
grant_expires_at_ms, device_fingerprint, issued_at_ms}`. `statement_sha256` is the lowercase
hex SHA-256 of the decoded statement bytes. `decision` is `allow` (durations `once`,
`hour`, `session`, `permanent`) or `delete` (duration `none`). The required
`grant_expires_at_ms` is `issued_at_ms` + 600,000 for `once`, + 3,600,000 for `hour`,
+ 86,400,000 for `session`, 0 for `permanent`, and the delete request's expiry for `none`.
An envelope carries at most `MAX_ENVELOPE_ITEMS` = 16 items. The signature is ECDSA P-256
with SHA-256 over the decoded envelope bytes, by the approval key registered for the
fingerprint under its current pairing, X9.62 DER. The vault parses the envelope strictly:
unknown or duplicate keys, and bytes that differ from the canonical re-encoding of the
parse, are `approval_invalid`. The SHA-256 of the exact accepted envelope bytes is stored
on every grant it creates and is the `payload_hash` of its audit rows.

<!-- golden:envelope.allow -->
```json
{"decision":"allow","device_fingerprint":"11111111111111111111111111111111","duration":"hour","grant_expires_at_ms":1700003600000,"issued_at_ms":1700000000000,"items":[{"request_id":"01HF7YAT000000000000000001","statement_sha256":"de3174feb14cf2e29ec73080df785ee615749d638cc81bed9aae48079d0cb81b"}],"v":"ck-secret-use-envelope/v1"}
```

<!-- golden:envelope.delete -->
```json
{"decision":"delete","device_fingerprint":"11111111111111111111111111111111","duration":"none","grant_expires_at_ms":1700000600000,"issued_at_ms":1700000000000,"items":[{"request_id":"01HF7YAT000000000000000001","statement_sha256":"df65ad8cd63b5ebee80d587d305c8e1961121a3671f1d6658424252ae7bfa5f2"}],"v":"ck-secret-use-envelope/v1"}
```

Per item, after the whole-envelope checks: the request must be live (unconsumed and
before its expiry) and of the envelope's kind (approval or delete); `statement_sha256`
must equal its stored statement digest; `request_expires_at_ms` − pending lifetime ≤
`issued_at_ms` < `request_expires_at_ms`, where the pending lifetime is 86,400,000 ms
for flow requests and 600,000 ms for agent and delete requests;
|vault now − `issued_at_ms`| ≤ 120,000; the statement's `member_id` must equal the current
self member id; the duration must be
offered and `grant_expires_at_ms` exact; a live record must have the statement's
incarnation, and for approval the statement's `secret.kind` and `use` must equal the
record's sealed scope. A pending request the envelope does not list stays pending.

### Binary byte layouts

Every binary field below is prefixed by its u64 little-endian byte length. Text is UTF-8
without normalization; absent optional fields are zero length. In order:

* AAD: `ck-secret-deposit-aad/v1`, deposit_id, member_id, name, kind, then host,
  path_prefix-or-empty, location (API key), or origin (login).
* Plaintext: `ck-secret-deposit-plaintext/v1`, then key bytes, or username, password,
  otpauth URI-or-empty.
* Sealed body: `ck-secret-sealed-body/v1`, kind, scope fields as above, plaintext fields.
* Deposit digest: SHA-256 over framed deposit_id, enc, ciphertext, rebuilt AAD, no tag.

The shared deposit/operator material validator refuses malformed framing/UTF-8/otpauth
without echoing content. Username ≤256 bytes, password ≤1,024, API key ≤8,192. TOTP accepts
SHA1/SHA256/SHA512, digits 6 or 8, period 15–120 inclusive (default 30); HOTP is refused.
Header names are RFC 9110 tokens ≤64 bytes. `Host`, `Cookie`, `Content-Length` and
`Authorization` are refused in every ASCII case; `header:X-Api-Key` is accepted.

### Secret codes

Every refusal the secret operations can give. Result errors are a `Response` frame whose
body is `{"result":{"error":{"code":"…","class":"…"}}}`, for example:

<!-- golden:error.result -->
```json
{"error":{"code":"approval_invalid","class":"permanent"}}
```

<!-- golden:error.phone_not_attested -->
```json
{"error":{"code":"phone_not_attested","class":"permanent"}}
```

Transport errors are an `Error` frame `{"code":"…","message":"…"}` with no class (§1a);
the message is fixed text and never echoes the request.

| Code | Class | Form | Meaning |
|---|---|---|---|
| `invalid_params` | none | transport Error | request grammar or key set, stamp shape, coverage not permitted, malformed `card_ref`, bearer params on a phone channel |
| `not_found` | `permanent` | result error | uniform refusal: not a sender or phone channel, unknown or unusable name, unmapped scope, target mismatch, wrong member id or unopenable deposit |
| `ambiguous` | `permanent` | result error | more than one active Basic sign-in secret covers a name-less web-request target |
| `limit_exceeded` | `context_overflow` | result error | a length or size over its limit |
| `approval_invalid` | `permanent` | result error, or the `code` of a refused `results` item | an envelope or item failed a check; never says which |
| `phone_not_registered` | `permanent` | result error | the phone is absent from callosum, or has no keys under its current pairing |
| `phone_not_attested` | `permanent` | result error | a key registration, secret approval/delete or manifest approval arrived without the route's production build mark |
| `phone_key_conflict` | `permanent` | result error | different keys for an already registered (fingerprint, pairing) |
| `deposit_conflict` | `permanent` | result error | a used deposit id with different bytes, member id or a deleted record |
| `name_exists` | `permanent` | result error | a new deposit for a name that already has a record, corrupt included |
| `secret_setup_incomplete` | `permanent` | result error | this vault's member id is unset, or its deposit key is unusable |
| `secret_multi_host_disabled` | `permanent` | result error | creating an API key with multiple rules or a wildcard, or a login with multiple origins, while `secret.multi_host` is off or unreadable |
| `secret_basic_auth_disabled` | `permanent` | result error | creating a Basic sign-in secret while `secret.basic_auth` is off or unreadable |
| `secret_local_programs_disabled` | `permanent` | result error or refused `secret.approve` item | creating or depositing a local-program secret, or approving a local-program item, while `secret.local_programs` is off or unreadable |
| `pairing_unavailable` | `transient` | result error | callosum did not answer the pairing lookup within the 1,500 ms budget |
| `manifest_setup_incomplete` | `permanent` | result error | `manifest.approve` only (§17): the home lacks an active configured policy root, a stored manifest version or its own federation member id |
| `superseded` | `permanent` | result error | `manifest.approve` only (§17): a newer manifest version was stored after the proposal was made |
| `expired` | `permanent` | result error | `manifest.approve` only (§17): the proposal, or the envelope's `issued_at_ms`, reached `expires_at_ms` |
| `policy_too_large` | `permanent` | result error | `manifest.approve` only (§17): the successor policy exceeds the signing input limit or the policy document limit |
| `policy_binding_conflict` | `permanent` | result error | `manifest.approve` only (§17): a conflicting GitHub App identity, invalid successor policy, or disagreement with the proposed manifest's bindings |
| `policy_identity_agent_mismatch` | `permanent` | result error | `manifest.approve` only (§17): a GitHub App in the successor policy is attested for a different agent |
| `pending_limit` | `transient` | result error | too many live approval requests (8 per mapped scope, 64 in total) |
| `store_error` | `transient` | result error | a store or audit-commit failure; nothing changed and nothing was released |
| `permissions_operator_required` | none | transport Error | `permissions.list` or `permissions.revoke` from a caller other than `reserved:cingulate` or the MAC-authenticated operator; body per `permissions/v1` |

`secret_error_codes_are_golden_and_match_the_doc_table` pins each code's class and body
and checks this table in both directions.

### Phone transition audit

Payload hashes use SHA-256 of the ordered length-prefixed fields above, never plaintext
material or its digest. Vault-global rows have no target.

| Op | Actor | Target | Payload fields |
|---|---|---|---|
| `secret_phone_gate_set` | offline-cli or route-admin | none | enabled (`true`/`false`) |
| `secret_multi_host_set` | offline-cli or route-admin | none | enabled (`true`/`false`) |
| `secret_basic_auth_set` | offline-cli or route-admin | none | enabled (`true`/`false`) |
| `secret_local_programs_set` | offline-cli or route-admin | none | enabled (`true`/`false`) |
| `ssh_key_agent_allow` | offline-cli or route-admin | signing credential id | keyed fingerprint of the resulting enrollment JSON |
| `ssh_key_agent_deny` | offline-cli or route-admin | signing credential id | keyed fingerprint of JSON `null` |
| `secret_phone_register` | fed-phone:<fp> | secret-phone\|<fp> | pairing_id, raw deposit_pub, raw approval_pub |
| `secret_store` | fed-phone:<fp> | secret\|<name> | kind, incarnation, scope fields, deposit_id |
| `secret_grant_expire` | vault | secret\|<name> | grant_id, incarnation, expires_at_ms (u64 LE) |

### Multi-host secret scopes (normative extension)

This extension defines the contract for extended scopes. Until the creation setting is
enabled, readers must still understand these shapes but no new extended secret can be
created. A **legacy scope** is one exact API-key host with an optional prefix and one
location, or one login origin. An **extended scope** is two or more API-key rules, any
wildcard rule (including a lone wildcard), or two or more login origins. All legacy
encodings, published vectors, use requests and replies, delete statements, grant
durations and coverage remain byte-identical. Only extended scopes use the encodings
below. Earlier single-host examples describe legacy scopes, not the extended key sets.

#### Input, emitted and stored shapes

The kind strings remain `agent_api_key` and `site_login`. Scope fields in phone
`secret.deposit` and `admin.secret_put` have exactly one of these forms:

* Legacy API key: `{host, path_prefix?, location}`. A wildcard in `host` is
  `invalid_params`; legacy `--host` never accepts wildcards.
* Extended API key: `{rules: [{host, path_prefix?}, …], location}` with no top-level
  `host` or `path_prefix`. A one-entry array is valid only for a wildcard rule.
* Legacy login: `{origin}`. Extended login: `{origins: [origin, …]}` with no `origin`.
  A one-entry `origins` array is always `invalid_params`.

A rule has exactly `host` and optional `path_prefix`, both strings. Unknown keys,
non-string entries or field values, non-array or empty `rules`/`origins`, mixed legacy
and extended scope fields, and fields for the other kind are `invalid_params`.
Phone field presence is by key, even if its value is null, and its key sets are closed.
For `admin.secret_put` only, the legacy optional fields count as present when non-null:
unused legacy fields serialize as null. New optional `rules` and `origins` fields are
omitted when absent, so a legacy put has exactly its old serialization.

Canonical rules sort bytewise by `(host, path_prefix)`, with an absent prefix sorting
as `""`. Exact duplicate rules are refused. Overlapping distinct rules are accepted:
`*.x.y` with `a.x.y`, or one host with and without a prefix. Origins sort bytewise by
the strings **as sent**, which are stored unchanged. Equal `canonical_origin` results
are duplicates (`https://x.test` and `https://x.test:443`); these are refused.
Canonical order is the stored, listed, signed and approval-card reading order. Core
canonicalizes deposit and put scopes, including crafted admin operations; sorting is
not merely a CLI responsibility. A deposit may arrive in non-canonical order, but the
vault canonicalizes only after verifying the AAD over the sent order.

Every vault-emitted rule object (statement v3, `secret.list`, stored column) has both
`host` and `path_prefix`, with `""` for no prefix. Stored decode maps that empty string
to absent before applying grammar and limits. Explicit `path_prefix: ""` in input is
still `invalid_params`. Stored decode never consults the PSL.

#### Grammar, matching, limits and refusal order

The shared rule crate parses every scope at deposit, put and use, legacy included.
An exact host is nonempty lowercase ASCII DNS text: nonempty dot-separated labels,
each containing only `a`–`z`, digits and `-`, with no edge hyphen, trailing dot or IP
literal. A-labels (`xn--…`) are accepted, U-labels refused. The legacy grammar does not
add a separate label-length cap. Host grammar is checked before its 253-byte cap.
A wildcard host is `*.` followed by that exact-host grammar and matches **exactly one**
additional leftmost label: `*.x.y` matches `a.x.y`, not `x.y` or `a.b.x.y`.
The 253-byte host cap includes `*.`. No other placement of `*` is valid: `*`, `*.`,
`a.*.b`, `*a.b` and `*.*.b` are refused. Login origins never accept wildcards.

Prefixes retain the legacy path grammar and 1,024-byte cap. A path starts with `/`,
contains no `//`, and uses only ASCII alphanumerics or `-._~!$&'()*+,;=:@/%`.
Each `%` must have two hex digits; the decoded byte must be printable ASCII
(`0x21`–`0x7e`) other than `/`, `.`, `%`, `\` or `;`. A segment before its first `;`
must not decode to `.` or `..`. A prefix cannot end in `/`, so `/`, `/repos/a/` and
`""` are refused. Grammar (including the trailing slash check) precedes the byte cap.
The `*` in `/v1/*` is literal: it matches `/v1/*` and `/v1/*/x`, not `/v1/items`.

API-key matching requires HTTPS, port 443, a matching host and either no prefix, an
exact prefix, or a prefix followed by `/`. There is no percent-decoding during match:
`/repos/%7E` does not match prefix `/repos/~`; `/repos/ab` does not match `/repos/a`,
but `/repos/a/` and `/repos/a/x` do. A scope matches if any rule matches. With no prefix,
`/` and `/x/y` match. A login scope origin is exactly `https://<valid-host>` with
optional `:443`; `canonical_origin` removes that suffix, with no URL normalization.
A login target matches an origin with the same host, HTTPS and port 443; HTTP,
another host or port 444 does not match. A login target never matches an API-key scope,
and an API-key target never matches a login scope. Targets remain one concrete URL or
origin in the unchanged `secret.use` shape, never a wildcard or an array.

There are at most **8 rules per API key** and **4 origins per login**. Nine rules or
five origins are `limit_exceeded`. Existing per-field byte caps are unchanged: host
253, prefix 1,024, header name 64, query name 64, JSON pointer 256, username 256,
password 1,024 and API key 8,192 bytes. Location retains its legacy grammar:
`authorization_bearer`, `header:<token>`, `query:<ASCII alphanumeric/._- name>`, or
`json_pointer:<nonempty /-prefixed printable ASCII pointer>` with only `~0`/`~1`
escapes. Header names are RFC 9110 tokens; Host, Cookie, Content-Length and
Authorization are forbidden case-insensitively. Location is required for API keys and
absent for logins. Material and TOTP validation and limits remain as above.
The Basic sign-in extension below also admits `authorization_basic:<user>` for
both single-host and multi-host API-key scopes, behind its separate creation gate.

The **first failing check** decides the refusal, in this order:

1. Transport shape (vault).
2. Entry count: over the maximum is `limit_exceeded`; a one-entry `origins` array is
   `invalid_params`.
3. Each entry in sent order: host grammar, host byte cap, prefix grammar, prefix byte
   cap (or the origin grammar and host cap for login entries).
4. A one-entry exact `rules` array (`invalid_params`).
5. Duplicates (`invalid_params`).
6. The public-suffix check (`invalid_params`).
7. Location grammar and byte cap (vault).

Byte-cap refusals are `limit_exceeded`; all other grammar refusals are
`invalid_params`. The crate owns checks 2–6. At `admin.secret_put`, existing operator
mapping remains: `invalid_params` becomes `invalid_credential_id`, and
`limit_exceeded` becomes a `limit_exceeded:` store message. CLI validation runs first,
names the field, and precedes reading material or contacting the daemon.

#### Public Suffix List and crate capabilities

Input `*.<base>` is refused exactly when `<base>` is itself a public suffix under the
pinned PSL prevailing-rule algorithm: ICANN **and PRIVATE**, wildcard and exception
rules, and the default `*` rule for unknown TLDs. PSL entries are compared after
ToASCII, so a U-label entry governs its A-label form. Thus `*.com`, `*.github.io` and
`*.xn--55qx5d.cn` are refused; `*.foo.github.io` and `*.x.test` are allowed. The PSL's
`*.ck` and `!www.ck` rules refuse `*.a.ck` but permit `*.www.ck`. Use-time matching
and stored decode never consult the PSL: an already stored `*.github.io` rule still
decodes and matches `a.github.io`, even if a newer snapshot would refuse its creation.

The pinned `psl_snapshot` identity is:

* URL: `https://raw.githubusercontent.com/publicsuffix/list/ab73a956765706dc3f42dbac5c7e48df2297e1ac/public_suffix_list.dat`
* Date: `2026-11-09`
* SHA-256: `7bd9c5479d1ac1a4118b982a3a05b65719e3215cb873474f9799af6222006da4`

`aft-secret-rules` (library `secret_rules`) is the single parser and matcher, with
these four capabilities for the vault:

* **Input parse:** all checks from entry count through PSL, with refusals mapping
  one-to-one to `invalid_params` or `limit_exceeded`.
* **Stored decode:** the same grammar and limits without PSL, interpreting emitted
  `path_prefix: ""` as absent.
* **Match:** one parsed scope against one `secret.use` target, for legacy and extended
  scopes alike.
* **Snapshot identity:** the PSL URL, date and SHA-256 above. The vault pins equality
  with the corpus identity, so a dependency update cannot silently change the PSL.

`UseTarget::matches` and `validate_scope` retain their signatures but delegate to this
crate; there is no second rule parser or matcher. The legacy `SecretScope::ApiKey`
and `SiteLogin` fields stay unchanged; extended scopes use new variants.

#### Statements, approval and listings

Extended scopes emit `ck-secret-use-statement/v3` or `ck-secret-flow-statement/v3`,
for both local and forwarded requests. The object retains every v1 field, replacing
`use` with `{rules: [{host, path_prefix}, …], location}` or `{origins: […]}`.
Flow API-key `use` also carries the existing sorted `methods` beside `rules`.
`asking_member_id` is present exactly for forwarded requests, with the asking member's
id, as in v2. Statements are RFC 8785 (JCS) bytes. Approval envelopes and signatures
are unchanged. Legacy local requests still use v1 and legacy forwarded requests v2.

At approval commit, `asking_member_id` presence and value must equal the pending
row's asker exactly. Tag checks happen per item branch after loading the row, not by
assuming that only a `/v2` tag can be forwarded. An agent approve requires exactly
use v1 for a legacy local row, v2 for a legacy forwarded row, or v3 for an extended
row, and compares `use` rebuilt from storage. A flow approve rebuilds and compares
the entire expected statement bytes with the row's v1/v2/v3 builder. Other cases
refuse the item `approval_invalid`.

For extended secrets a flow_id equal to **either v3 statement tag** is
`invalid_params`, local or forwarded. Request-time prechecks run before encoding,
so this is not `store_error`; commit repeats the check. The existing v2-tag rule
remains for every secret: a forwarded flow_id equal to either v2 tag is refused at
request and commit, while a local flow_id equal to a v2 tag remains accepted.

Delete is unchanged: `ck-secret-delete-statement/v1` carries no scope or asker.
Its commit branch decodes no scope and removes even a corrupt extended row, its
grants and pending requests. A corrupt scope on an approve instead takes
`approval_quarantine`: the row becomes `corrupt`, one `SecretQuarantine` audit is
written, and the item is refused. A relaying asking vault still checks only the four
`approval_required` members (`status`, `request_id`, `statement_b64url`,
`expires_at_ms`) and never parses its statement.

An extended `secret.list` row carries `rules` and `location`, or `origins`, instead
of legacy `host`/`path_prefix`/`origin`; other row and grant fields are unchanged.
`permissions.list` renders `scope_label` as `use <name> on <host><prefix>, …` or
`fill <name> on <origin>, …`, in canonical order for **both agent and flow grants**.
Legacy labels are unchanged. `ck auth secret list` prints one `rule=<host><prefix>`
token per canonical rule followed by `location=…`, or one `origin=<origin>` token
per canonical origin. Unreadable scope prints `<name> <kind> <state> scope=unreadable`.

#### Deposit and sealed-body byte encodings

Every field below uses `push_field`: its unsigned u64 little-endian byte length,
then its bytes. Text is UTF-8 without normalization. Extended **deposit AAD v2**
fields, in order, are `ck-secret-deposit-aad/v2`, deposit_id, member_id, name, kind,
entry count as **decimal ASCII**, then:

* API key: each rule's host and prefix-or-empty **in sent order**, then location.
* Login: each origin **in sent order**.

HPKE info (`cortexkit/claustrum/secret-deposit/v1`) and the
`ck-secret-deposit-plaintext/v1` material encoding are unchanged. The tombstone
digest covers the AAD, so reordering entries on a resend is `deposit_conflict`.
An exact resend remains `already_stored` if its original record is still live.

Extended **sealed body v2** fields are `ck-secret-sealed-body/v2`, kind, entry
count as a decimal-ASCII frame, then canonical rule host/prefix pairs and location,
or canonical origins, followed by the unchanged v1 material fields: one API-key
byte field, or username, password and otpauth-URI-or-empty. `record_version` stays
1. A row with `scope_json` set opens only a v2 body; a legacy row opens only a v1
body. A mismatch follows the existing `sealed_scope` refusal path. Master-key
rotation re-seals opened body bytes unchanged without reading scope columns.

#### Creation setting, precedence and persistence

The `settings` key `secret.multi_host` stores `"true"` or `"false"`. A missing row
means off; any other value or failed read is unreadable. Legacy creation never
reads it. Off or unreadable refuses creation of an extended scope on deposit and
put with `secret_multi_host_disabled`: class **permanent**, form **result error**,
body `{"error":{"code":"secret_multi_host_disabled","class":"permanent"}}`.
It means creating a multi-host scope while `secret.multi_host` is off or
unreadable. The new `StoreOpError` for put has that same `wire_code`; its message
names `secret.multi_host` and `ck auth secret multi-host on` as the remedy.

`admin.secret_multi_host_set {v: 2, enabled: boolean}` uses the same schema version
as `admin.secret_phone_gate_set`. A changed value audits once as
`SecretMultiHostSet` (`secret_multi_host_set`), with payload `push_field("true")`
or `push_field("false")`; an unchanged value changes nothing, audits nothing and
replies `changed: false`. CLI `ck auth secret multi-host on|off` prints exactly
`multi-host setting on` or `multi-host setting off`. Lease-free `status` prints
`multi-host setting on|off|unreadable` with one of those final words; no store,
settings table or row means `multi-host setting off`.

Scope refusal order above comes before any transaction. Inside the deposit
transaction, tombstone replay (`already_stored` / `deposit_conflict`) precedes the
creation setting, which precedes member check, HPKE open and `name_exists`. Put
reads the setting inside the insert's `fenced_write` transaction, after the
home-role refusal (`local_create_allowed`) and before `name_exists`. Neither path
uses a cached value or relies on a CLI preflight. A setting refusal writes no
secret row, tombstone or `secret_store` audit: the identical deposit can succeed
once enabled. Disabling later stops new extended creation, not existing use.

Migration 35 appends nullable `scope_json`, rebuilding by create/copy/drop/rename
without rewriting migration 27 or `agent_secrets.sql`. It preserves every old
column and row, the name primary key and UNIQUE incarnation index, and leaves
other tables unchanged. The value is the JCS bytes of the canonical rules array
`[{host, path_prefix}, …]` or origins array; location stays in `location`.
For an API key the CHECK requires nonempty location, NULL origin, and either
non-NULL host with NULL scope_json, or NULL host/path_prefix with non-NULL
scope_json. For a login host/path_prefix/location are NULL, and exactly one of
origin and scope_json is non-NULL. Migration is forward-only, with a pre-migration
snapshot at deployment. No foreign keys, triggers or extra indexes are added.

Every scope reader uses `scope_json`: use load, approval commit, phone list,
permissions agent/flow rows and operator listing. Put and deposit write it. Invalid
JSON, non-canonical bytes or order, duplicates, excess count or an exact-rule or
origin singleton are corrupt. Use refuses `sealed_scope`; phone `secret.list`
and `permissions.list` fail `store_error`; approve quarantines as above. Operator
delete reads no scope and can still delete. `list_agent_secrets_read_only` returns
raw scope_json without decoding (NULL below step 35), so `ck auth secret grants`
still lists and the lease-free operator list can identify unreadable rows. The
extended `secret_store` audit frames kind, incarnation, scope_json, location for
API keys and deposit_id for deposits; legacy payloads are unchanged.

CLI put accepts repeatable `--rule <host[/prefix]>` for API keys. One exact rule
maps to legacy host/prefix; one wildcard or multiple rules maps to `rules`.
`--host`/`--path-prefix` remain and cannot mix with `--rule`. Repeatable `--origin`
maps one login origin to legacy `origin` and multiple to `origins`. Location
handling is unchanged. Help and the verb table must describe these forms.

#### Conformance corpus and its single writer

`scripts/secret-multi-host-vectors.py` is the **only writer** of
`crates/credentials-core/tests/vectors/multi-host/` and its `SHA256SUMS`. Regenerate
only with that generator and the claustrum repository owner's sign-off; never
hand-edit generated files.
The manifest lists the five JSON files in `shasum -a 256` format. Rust tests compare
parsed values reproduced by real encoders and have no multi-host write branch;
even `CK_EMIT_SECRET_VECTORS=1` must leave this directory byte-unchanged. A mismatch
is a code defect, not permission to rewrite the corpus.

`secret-scope-match-v1.json` is `{v, psl_snapshot: {url, date, sha256}, cases}`.
A case is `{case, form, kind, scope, target?, expect}`. `form: "input"` uses deposit
scope fields without location and goes through input parse; `form: "stored"` uses
emitted scope fields and goes through stored decode. `expect` is `"match"` or
`"no_match"`, with target `{scheme, host, port, path}` or `{origin}`, or
`{"scope_refused": "invalid_params"|"limit_exceeded"}` without a target. No gate,
location or store state belongs in this file. A refusal has one fault unless it
explicitly pins precedence. Stored cases include public-private suffix matching,
empty-prefix decoding and a refusal. A vault test stores accepted input cases
with the setting on and matches through use; input refusals must agree between
deposit and put (with operator mapping); stored cases exercise scope_json decode
and the use path's crate match call.

Vault-only cases live in `secret-approval-v3.json`, `secret-flow-approval-v3.json`,
`secret-deposit-v2.json` and `secret-list-v2.json`. Each names `operation` and
`setup`, including the creation setting where relevant; `expect` describes the
outcome or the named projection of a reply. Deposit byte samples carry unencrypted
params, fixed test-only material, AAD hex, plaintext hex and sealed-body hex; HPKE
envelope fields are omitted because the wrap is unchanged. Statement samples carry
the object, `statement_jcs_hex` (exact JCS bytes) and `statement_sha256`. The corpus
pins boundary counts, wildcard depth and PSL rules, legacy grammar and matching,
sent versus canonical order, missing versus empty prefixes, literal path stars,
list/permission labels, local versus forwarded v3 and reserved flow tags.

Implementation of extended-scope vault readers and writers waits until an
`aft-secret-rules` release passes this corpus and provides all four capabilities.
Existing published samples
outside `multi-host/` stay unchanged. New numeric count boundaries require tests
on both sides and registration in `docs/threshold-controls.txt` when implemented.

### Basic sign-in and name-less web requests

Only `agent_api_key` secrets admit `authorization_basic:<user>`. The user-id is
1–128 ASCII bytes from `[A-Za-z0-9._@+-]`; an empty user-id, a colon, a non-ASCII
byte or any other character is `invalid_params`. A valid user-id of 129 bytes or
more is `limit_exceeded`. Single-host and multi-host scopes use the same grammar
and the existing scope matcher. The vault stores and releases the token bytes
unchanged. It never constructs an Authorization header: AFT constructs
`Basic base64(user:token)` from the location and released key bytes.

#### Reader-first creation gate

`secret.basic_auth` is off when missing. Only the exact stored text `true` is on;
malformed values are unreadable and fail closed. While off or unreadable,
`secret.deposit` and `ck auth secret put` refuse a new Basic sign-in secret with
`secret_basic_auth_disabled`, class `permanent`, as a result error. The setting
check and insert share one write transaction: refusal leaves no secret, tombstone
or audit row. Like `secret.multi_host`, this gates creation only. Already-stored
Basic sign-in secrets remain usable after the setting is turned off.

`ck auth secret basic-auth on|off|status` mirrors the multi-host control.
`admin.secret_basic_auth_set {v: 2, enabled: boolean}` returns
`{"basic_auth":boolean,"changed":boolean}`. A real setting change writes one
`secret_basic_auth_set` audit row, no target, with payload `push_field("true")`
or `push_field("false")`; repeated values, including missing-to-off, write none.
Status is read-only and prints `basic-auth setting on|off|unreadable`. The operator
refusal names `ck auth secret basic-auth on` as the remedy. Keep this setting off
until the user's phone can show the location as “Sign in as {user} with this token”.

<!-- golden:basic_auth.disabled -->
```json
{"error":{"code":"secret_basic_auth_disabled","class":"permanent"}}
```

#### Selection without a name

`secret.use` may omit `name` for a web-request target. Only `reserved:aft` in a
non-flow scope is admitted. Cerebellum, basal, other callers and flow scopes get
the existing uniform `not_found` result, never an approval card. Explicit empty
or null names remain `invalid_params`, not selection requests.

<!-- golden:use.request.basic_auth_by_target -->
```json
{"stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"kind":"head","ref":"H","scope_epoch":7,"attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"scheme":"https","host":"x.test","path":"/repos/a/canary-token"}}
```

Inside the same transaction as the grant check, the home vault counts active
`agent_api_key` secrets with a location starting `authorization_basic:` whose
scope covers the target. Only HTTPS on port 443 can match. Bearer, header, query,
JSON-pointer, login and local-program secrets are never candidates. Coverage,
not existing grants, decides ambiguity; overlapping rules on one secret count
as one candidate.

No candidate returns the named path's byte-identical `not_found`. One candidate
continues as a named request for that secret, with byte-identical replies,
pending-card reuse, grant checks, release and audit. More than one returns
`ambiguous`, class `permanent`, as a result error, without creating a card,
consuming a grant or writing a release audit.

<!-- golden:basic_auth.not_found -->
```json
{"error":{"code":"not_found","class":"permanent"}}
```

<!-- golden:basic_auth.ambiguous -->
```json
{"error":{"code":"ambiguous","class":"permanent"}}
```

Paired computers forward the name-less request unchanged to the home vault.
Selection happens only at the home, and `ambiguous` is relayed unchanged to the
asking computer. Approval remains per secret and agent scope, not per git
repository or operation: the card shows the selected secret's own host and path
prefix. An hour or session grant covers every request within that stored scope.

The producer-generated `secret-basic-auth-vectors-v1` pack under
`crates/credentials-core/tests/vectors/` pins deposit HPKE bytes, statements,
signed approvals, releases and refusals, with raw bytes, JSON and SHA-256 records.
Generate it with `CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-core
--features test-support --test secret_basic_auth_vectors` on Linux. Samples must
be available to the phone reader before the creation setting is enabled.

### Local programs and SSH userauth

The local-program feature switch is off by default. Only AFT may use the local
`secret.use` target or call the mutating `secret.ssh_sign` operation. Local targets
are closed objects; sudo requires a nonempty `purpose`, both `expects` and
`undoable`, and offers only `once`. The password is UTF-8, not base64:

<!-- golden:use.request.local_program -->
```json
{"name":"sudo","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"program":"sudo","use":"sudo_password","target":{"user":"root"},"command":"apt upgrade","workdir":"/home/alice","purpose":"update packages","expects":"password prompt","undoable":"no"}}
```

<!-- golden:use.result.released.local_program -->
```json
{"status":"released","kind":"local_program","use":"sudo_password","value":"example password"}
```

SSH signs only a strict RFC 4252 publickey userauth packet for an enrolled
Ed25519 key. The sample packet contains a public-key blob, not private material;
the vault also requires that blob to match the enrolled key. Requests and targets
are closed, and the target's user must equal the packet's user. SSH local-use
members are exactly `program`, `use`, `target`, `command`, and `workdir`.
Neither `secret.ssh_sign` params nor SSH local-use members accept `purpose`,
even an empty string.

<!-- golden:ssh_sign.request -->
```json
{"key":"signing:agent:ssh","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"user":"alice","host":"x.test","port":22},"command":"ssh server","workdir":"/home/alice","data":"AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHMgAAAAVhbGljZQAAAA5zc2gtY29ubmVjdGlvbgAAAAlwdWJsaWNrZXkBAAAAC3NzaC1lZDI1NTE5AAAAMwAAAAtzc2gtZWQyNTUxOQAAACAREREREREREREREREREREREREREREREREREREREREREQ"}
```

<!-- golden:ssh_sign.result.signed -->
```json
{"status":"signed","signature_b64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

The signature above is a 64-byte framing placeholder. Tests verify a real signature
over the exact packet. Without a grant, the reply has the same four members as
`use.result.approval_required`, with a `ck-secret-local-use-statement/v1` statement
carrying the vault-authored key identity and fingerprint, not a secret name.

Every `ck-secret-local-use-statement/v1` statement carries `agent_id`: a string
when the scope names an agent, or `null` otherwise. Sudo statements carry
`secret: {name, kind: "local_program", incarnation}`; SSH statements instead carry
`key: {credential_id, incarnation, fingerprint}`. These identities are supplied by
the vault, not the asking program. SSH statements and stored local-use members
omit `purpose`. Forwarded local-use statements add `asking_member_id` and keep the
`ck-secret-local-use-statement/v1` tag.

Card text (`command`, `workdir`, and sudo-only `purpose` and `expects`)
must be nonempty and contain no Cc, Cf, Zl or Zp characters. UTF-8 byte caps are
2048 for `command`, 1024 for `workdir`, and 512 each for `purpose` and `expects`;
`workdir` must start with `/`. Text is never normalized.

An SSH card's `key.credential_id` must start with `signing:` and have at least
one character after the prefix, be at most 256 UTF-8 bytes in total, contain no
Cc, Cf, Zl or Zp characters, and pass the deposit-id grammar (no `category:`
prefix or `|`). The same rule is checked when enrolling a key with `ssh-key
allow` (`admin.ssh_key_agent_allow`) and when building a local-use SSH statement.
An invalid card key id is refused as `invalid_params`.

Checks stop in this order: AFT admission; closed params and signing-id grammar;
feature switch; stamp and scope-only coverage; target, text and userauth grammar;
key enrollment, target coverage and public-key match; grant or approval. The first
three refusals write no diagnostics. Keys not enrolled with `ssh-key allow`, absent
keys, keys whose enrolled targets do not cover the request, and requests carrying
another public-key blob all answer the same `not_found` bytes. Local
`limit_exceeded` bodies use class `permanent`; the existing HTTPS API-key and
browser-login `secret.use` refusal framing defined above remains unchanged.

`federation.secret_ssh_sign` is a query whose closed params are exactly
`{aad, sender, call}`, with sender `aft` and call equal to `ssh_sign.request`.
Its AAD has the same fields as `federation.secret_use.aad`, but `secret_name`
contains the signing credential id and the digest binds the SSH call. Both computers'
feature switches must be on. The home requires the current pairing's `secret_use`
member grant before parsing, then repeats all local checks before receipt replay.

<!-- golden:federation.secret_ssh_sign.request -->
```json
{"aad":"{\"secret_name\":\"signing:agent:ssh\",\"requester\":\"fed-computer:11111111111111111111111111111111\",\"home\":\"fed-computer:22222222222222222222222222222222\",\"nonce\":\"0123456789abcdef0123456789abcdef\",\"recipient_key_id\":\"0123456789abcdef\",\"call_sha256\":\"f5423b5d919b1bc5cc8536adaaa4dcdfd7bc5d3651bfbfd3b7c71bdc132cf285\"}","sender":"aft","call":{"key":"signing:agent:ssh","stamp":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"H","scope_epoch":7,"kind":"head","attributes":{"agent_id":"agent-A"},"owner_authorized":true},"target":{"user":"alice","host":"x.test","port":22},"command":"ssh server","workdir":"/home/alice","data":"AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHMgAAAAVhbGljZQAAAA5zc2gtY29ubmVjdGlvbgAAAAlwdWJsaWNrZXkBAAAAC3NzaC1lZDI1NTE5AAAAMwAAAAtzc2gtZWQyNTUxOQAAACAREREREREREREREREREREREREREREREREREREREREREQ"}}
```

<!-- golden:federation.secret_ssh_sign.result.sealed -->
```json
{"status":"sealed","enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","ciphertext":"AA=="}
```

The sealed bytes are placeholders as in `federation.secret_use.result.sealed`.
Real SSH replies use HPKE info `cortexkit/claustrum/ssh-sign-release/v1`, never
`secret-release/v1`. Exact lost-reply retries replay the existing release receipt,
including for a consumed `once` grant, without another signature or approval card.

## 16. Vault connectors (`connectors.list`, `connectors.watch`)

Both management operations are queries. `connectors.watch` additionally declares
`delivery: "watch"`, so Callosum relays its held subscription. Parameters for both
are the closed empty object `{}`; admitted callers with other parameters receive
`invalid_params` on the Error lane. Admission precedes parameter decoding.

The vault provides `operator-app/v1` and reads `RouteBindPeer.operator_app` beside
the control-plane bind. It admits the `alfonso-desktop` stamp, `reserved:cingulate`,
and the phone route in the matrix above. The one temporary
`unsigned_desktop_development_admission` also admits plain `direct` so unsigned
builds work, but only when the bind carries no scope stamp of any kind; scoped
tool calls are not unsigned desktop reads. It must be removed in the change that
leaves only the desktop stamp.
Each call using it writes one fixed, secret-free daemon log line naming that
admission. No other operation acquires this admission or its log line.

A phone bind must be `reserved:callosum`, have exactly `fed-phone:` plus 32 lowercase
hex digits as its harness, and carry no `ScopeKind::Federated` stamp. It uses the
same live member-mapping and phone-setting snapshot as the seven phone operations.
With member mapping On and the phone setting Off it receives `phone_access_off`
(permanent); other gate failures receive the phone operations' uniform NF. Every
other non-admitted caller receives exactly the permissions-list POR refusal.

### Listing

`connectors.list {}` returns this envelope inside the usual `result` wrapper:

```json
{
  "version": "<64 lowercase hex SHA-256>",
  "watch": true,
  "computer": "fed-computer:<32 lowercase hex>",
  "rows": []
}
```

`computer` is the vault's recorded federation self member, read as by `ck auth`,
and is omitted when none is recorded. `version` hashes only the canonical rows:
sort rows by `id`, serialize compact UTF-8 JSON with lexicographically ordered object
keys and no whitespace, then lowercase-hex encode SHA-256 of those bytes. Token
bytes, refresh timestamps and record versions do not enter the projection.

One row is emitted for each refresh-adapter OAuth login (except `github_app`),
cookie, static API key, and local `remote_records` login copy. Classification uses
the decoded record's kind and adapter, never its id. Vault-held signing and KEM
keys, opaque values, DSNs, GitHub App records, and the `module-runtime` group are
excluded; the runtime-group filter and credential permission ids share the
permissions-list implementation. An undecryptable quarantined record isn't listed,
because its kind can't be read, and the operator still sees it in `ck auth list`
and the vault's health counts.

| Field | Value |
|---|---|
| `id`, `incarnation` | The credential id and its current incarnation. |
| `kind` | `account` or `api_key`. |
| `name` | Catalog display name using the existing boundary-aware id matcher, otherwise the credential id; capped at 80 characters. |
| `category?` | `llm-provider`, `media-provider` or `embedding-provider` → `ai_models`; otherwise `web-search` → `search`; otherwise `cloud-infrastructure` → `infrastructure`. Otherwise the optional login catalog category (Gmail: `communication`, model logins: `ai_models`). Unknown is absent. |
| `status` | `{state, reason?}` as below. |
| `setup` | Computer-only steps as below. |
| `permissions` | Sorted `cg_…` ids of the visible permissions/v1 credential grants that reach the row by exact id or group; audience grants never reach credentials. |
| `identity?` | Account email, otherwise organization name, as plain text; omitted above 254 UTF-8 bytes. |
| `plan?` | `{tier, source}` from the existing effective plan, with `source` `operator` or `detected`; absent when unknown. |
| `condition?` | `{reason, since_ms, action_url?}` from the stored login condition. Omitted when none is set. |

Access a module has through a key picked in its approved settings is not listed here.

Status maps `active` to `ok`, `needs_reauth` to `needs_sign_in` for accounts and
`key_refused` for API keys, `retired` to `signed_out`, and `corrupt` to `damaged`.
Copies map their last home state the same way. Only non-`ok` rows may carry
`reason`: the newest existing authentication-event reason code, verbatim. No
reason is invented when there is no recorded reason.

Accounts have one setup step `{step:"sign_in", state:"done"|"needed",
where:"computer"}`, with `remedy:"sign_in_again"` only when needed. Keys use
`step:"key"` and `remedy:"replace_key"`. The step is done exactly when status is
`ok`. Copies also have `{step:"home", state:"done"|"needed"|"unknown",
where:"computer"}`: unknown when never fetched, done for the last successful
fetch (`ok`), needed otherwise. Unknown never means done.

Rows carry no `description`, `can`, `usedBy`, `settings`, `counts`, payload, token,
handle, key material or masked fragment. Reading computes stored metadata only:
no refresh, network call, OS permission prompt or background timer is started.
A store failure is `result.error {code:"store_error", class:"transient"}`.

### Watching

`connectors.watch {}` uses the same held watch registry, 64-subscription budget,
blocking-snapshot budget, 250 ms commit-burst coalescing, cancellation, replacement,
route teardown and drain/shutdown behavior as `auth.watch_scoped`. The first
`StreamData` notice has `seq:1`; subsequent notices increment `seq` only if the
projected version changes:

```json
{"kind":"changed","epoch":"<process epoch>","seq":1,"version":"<rows hash>"}
```

Notices never carry rows: read again after a changed version. Refreshes that only
replace token bytes produce no notice; logout changes status/setup and therefore
the version. A change to a condition, including replacing just the link, also
changes the version. Notices may be dropped under load. Process epochs are random
and reset on restart.
Drain finishes the held request with `StreamEnd`; route teardown/shutdown cancels
publication as for `auth.watch_scoped`. Capacity/draining refusal is the same NF.
Admission is rechecked before each watch snapshot; changing the phone setting Off
ends an existing phone watch with the same `phone_access_off` refusal.

Generated samples and their `SHA256SUMS` are in
`crates/credentials-module/tests/vectors/connectors-v1/`. `inventory.json` includes
an account with identity and plan, a refused key and its reason, signed-out and
damaged accounts, a home copy, and the omission of a seeded signing key.
`empty.json`, `watch.json`, and `phone-access-off.json` cover the other shapes.
`CK_EMIT_CONNECTOR_VECTORS=1` regenerates them through the real route handler;
only the random watch epoch is normalized to the sample's fixed value.

## 17. GitHub manifest bindings and activation

This section publishes the contract before its implementation and generated samples.
It adds no golden blocks or vectors. Consumers call these operations by method name
over the ManagementSurface; `packages/client/src/index.ts` remains unextended.

### Admission, kinds and wire forms

| Operation | Kind | Admitted caller | Exact params |
|---|---|---|---|
| `manifest.propose_binding` | Mutate | `reserved:plexus` | `{agent_id, app_id, app_slug, repo}` |
| `manifest.approve` | Mutate | phone route only, through the phone-operation pipeline | `{envelope_b64url, signature_b64url}` |
| `manifest.latest` | Query | `reserved:aft` | `{}` |
| `manifest.watch` | Query, held subscription (`WATCH` delivery) | `reserved:aft`, `reserved:plexus` | `{}` |
| `manifest.report_active` | Mutate | `reserved:aft` | `{version, payload_sha256, verdict, reason}` |
| `manifest.active_status` | Query | `reserved:plexus` | `{version}` |

Callers outside an operation's admitted principal receive the uniform `not_found`,
indistinguishable from an unknown id. Admission precedes parameter decoding. Params
are closed objects: an unknown field, wrong type or invalid grammar is a transport
`Error` frame with `code: "invalid_params"` and **no class**, not a domain refusal.
Every other refusal is a `Response` with `result.error.{code, class}`; additional
fields, such as `remedy_member`, sit beside `code` and `class`. Successes are
`Response` results. The domain-refusal table below does not replace this transport
distinction (§ 1a).

The manifest home is the agent-secret home, not a separate setting. A `Single` or
`Home` vault serves all six operations locally. A `Remote` vault serves report_active
locally and forwards latest and watch. It refuses propose and active_status with `not_found`, and
gives approve the phone pipeline's `secret_home_elsewhere` with `remedy_member`
naming the home, before checking phone registration. `RemoteSetupIncomplete`
refuses latest, watch and report_active with `remote_setup_incomplete`/`permanent`
and `remedy_member`, refuses propose and active_status with `not_found`, and gives
approve the phone pipeline's `remote_setup_incomplete` (with `remedy_member` when
the self id is set). An unreadable role gives `store_error`/`transient`.

For forwarding, the member calls the home's `fed:<fp>:claustrum` surface using
`federation.manifest_latest` (Query, unary) and `federation.manifest_watch` (Query,
held subscription with `WATCH` delivery). The home admits these under the same pairing and `secret_use`
member-grant checks as forwarded secret operations. A caller without membership
or the grant receives uniform `not_found`; for the federation watch this is a
terminal `Error` frame with `detail.class: "permanent"`. An unreachable home gives
`home_unavailable`/`transient`. Both operations are declared in the peer-sharing `vault` share.

`manifest.one_tap` is **off by default**. Missing means off; a malformed setting
is unreadable and treated as off. After the principal check, while the setting is
off, `manifest.propose_binding` refuses `one_tap_disabled`/`transient` before any
outbound call, emitting no statement and writing no row. Every other manifest
operation works regardless, including approval of an already-pending proposal,
latest, watch, report_active, active_status, import and sign. The operator controls
the setting with `ck auth manifest one-tap on|off|status`; a real change writes
one audit row and repeating the current value writes none.

### Proposing one repository

`manifest.propose_binding` accepts exactly:

- `agent_id`: 1–128 bytes from `[A-Za-z0-9_-]`.
- `app_id`: a positive integer.
- `app_slug`: 1–100 bytes from `[a-z0-9-]`, GitHub's App slug alphabet.
- `repo`: `owner/name`, each part 1–100 characters from `[A-Za-z0-9._-]`, neither
  `.` nor `..`.

Grammar is checked before any outbound call. The home needs an active configured
policy root (`policy_root_credential`; legacy `signing:gh-manifest-root:1` on
migrated installs), a stored manifest version and its own federation member id.
Otherwise propose or approve refuses
`manifest_setup_incomplete`/`permanent`.

A proposal has a 60 s deadline. Exhaustion during the identity check gives
`identity_unavailable`; later exhaustion gives `github_unavailable`, with nothing
written. The final write transaction checks the deadline once it holds the writer:
if not admitted it refuses `github_unavailable` without writing; once admitted it
commits and returns its reply even if the deadline passes. The caller awaits that
transaction without a timeout. Checks run in this order, comparing repository
names ASCII-case-insensitively:

1. **Identity.** Call Entorhinal's `agent.github_identity` with `{agent_id}`.
   Only an `app` identity with equal `app_id` and `app_slug` and
   `credential_ref == "github_app:" + app_slug` passes. A null identity,
   `user_token`, mismatched fields, or Entorhinal's `unknown_agent`, `gone` or
   `invalid_request` gives `identity_mismatch`; an unreachable Entorhinal gives
   `identity_unavailable`. The identity reply's per-process `incarnation` is
   decoded, never refused. The vault also refuses `identity_mismatch` if the App
   record is attested to a different agent.
2. **Installation.** Read the active `github_app:<app_slug>` record, mint an
   installation token and read that installation's GitHub `permissions` map from
   the same `/app/installations` record. The token stays in memory; this check
   changes no credential or audit row. Read installation repository pages of 100,
   beginning at page 1. On page 1, selection `all` gives `installation_all` and
   `total_count > 1,000` gives `installation_too_large`, before further pages.
   Stop when the repository is found or the accumulated count equals page 1's
   `total_count`. Only a complete listing establishes absence (`not_installed`),
   as does the adapter's `NotInstalled` outcome. Several installations, a
   mismatched installation or a suspended installation gives
   `installation_unusable`. A present but unusable local App record also gives
   `installation_unusable`. An empty page before completion, a changed
   `total_count`, more entries than that count, repeated repository names that
   prevent proving completeness, or ten pages without either a
   match or completion gives `github_unavailable`. So does any other request,
   transport, timeout or decoding failure, including 401, 403, 404, 429 and 5xx.
   The matched repository's GitHub `full_name` casing is the binding key from
   here on.
3. **Existing binding.** If the newest manifest already binds that repository to
   the same agent, refuse `already_bound` with `{version, manifest_sha256}` of
   that newest version; a binding to another agent gives `bound_to_other_agent`.
4. **Base freshness.** Any non-retired activation reporting a version greater
   than the newest stored version gives `stale_base`.
5. **Reproducibility.** If re-serializing the newest version does not reproduce
   its bytes exactly, refuse `not_reproducible`.

Build N+1 from the newest stored version N by incrementing `manifest_version`,
setting `issued_at_unix_secs` to now and appending `"<full_name>": "<agent_id>"`
as the last key in `bindings`, using the same serialization. No other manifest
content changes. The write transaction rechecks that this vault is still the home.
It refuses `stale_base` without writing if N is no longer newest or an activation
is ahead of N. Return an unexpired pending proposal for the same `(agent_id, repo)`
if the App id, slug and installation permissions are unchanged. If those inputs
changed, supersede the pending proposal and insert a new one. If it reached its
expiry, mark it expired and insert a replacement in the same transaction. Storing any new
manifest version supersedes all pending proposals whose base is older, including
after import or operator signing.

The success result is exactly
`{status: "approval_required", proposal_id, statement_b64url, manifest_version, manifest_sha256, expires_at_ms}`.
`proposal_id` is a ULID. The proposal expires 24 h after creation.

### Statement and proposer-filed consent card

The decoded `statement_b64url` is RFC 8785 JCS (JSON Canonicalization Scheme)
UTF-8 bytes with fields **exactly**
`{v, proposal_id, agent_id, app_slug, repo, installation_permissions, manifest_version, manifest_sha256, prior_version, prior_sha256, expires_at_ms}`.
`v` is `ck-manifest-binding-statement/v1`. `repo` uses GitHub `full_name` casing;
`prior_version` and `prior_sha256` identify the base. `installation_permissions`
is the bot installation's GitHub permission map exactly as returned for that
installation at proposal time. It has **1 to 64 entries**, every name matches
`^[a-z][a-z0-9_]{0,63}$` (1 to 64 ASCII bytes), and every level is exactly `read`,
`write` or `admin`. Keys are sorted as JCS sorts every object. The phone refuses
statements outside these bounds, and the vault refuses to build them. An invalid
map reaching `manifest.propose_binding` is refused before any proposal or audit
row is written. The map is stored with the proposal so the phone
never signs without seeing what the bot may do. The statement has no display
names; the card renders the agent's name from `agent_id`.
The statement and envelope use unpadded base64url; SHA-256 fields are lowercase
hex digests of the exact bytes they name.

The proposer, Plexus, files a Cingulate consent card from the propose reply:
consent kind `manifest_binding`, answer field `manifest_binding_answer`, **one
repository per card**, expiring at the statement's `expires_at_ms` (24 h).
Plexus passes the statement through unchanged. Nothing in the vault calls
Cingulate; the phone's signed envelope commits the vault-built statement and is
the authority.

### Approving the binding

`manifest.approve` takes exactly `{envelope_b64url, signature_b64url}`: base64url
encodings of the envelope bytes and a P-256 ECDSA signature with SHA-256 in DER
form over those bytes. The envelope is JCS with fields **exactly**
`{v, proposal_id, statement_sha256, decision, device_fingerprint, issued_at_ms}`.
`v` is `ck-manifest-binding-envelope/v1`; `decision` is `allow` only. A decline
sends nothing to the vault. `statement_sha256` commits the exact statement bytes.

The phone route must carry the recorded `peer_build: "production"` mark. Otherwise
`phone_not_attested` is returned before parsing the envelope, with no store or
audit changes, even for a valid signature from a registered phone.

Domain separation runs both ways. `manifest.approve` refuses a non-manifest `v`
with `approval_invalid` **before signature verification**.
`secret.approve` refuses a manifest envelope at its strict parse, before its
signature check, using its ordinary parse-failure refusal. Neither operation
accepts the other's envelope even when a signature would otherwise verify.

Approval runs inside the phone pipeline's single serializing write transaction.
Pairing admission, the home-role refusal and the phone-registration check come
first. Once the phone pipeline records when it last saw this phone, it keeps that
record even for an exact replay or a refusal. A replay or refusal does not write proposals,
manifests, policies or audit rows. Next comes `manifest_setup_incomplete`, then
these checks in order:

1. Strictly parse the envelope (including its `v`); require canonical bytes equal
   to the received bytes, `device_fingerprint` equal to the route's fingerprint,
   and a valid P-256 signature over the received bytes using the current pairing's
   registered `approval_pub`. Require `issued_at_ms` within 120,000 ms of now.
   Any failure gives `approval_invalid`.
2. Require a known `proposal_id`, the stored `statement_sha256`, and
   `issued_at_ms >= created_at_ms`. Re-derive the proposal commitments: the
   statement hash matches its bytes; its proposal id, agent id, app slug, repo,
   installation permissions and expiry match the stored proposal; its prior
   version/hash identify the stored base; its new version is base + 1 and matches
   the manifest bytes; and its manifest hash matches both the row and those
   bytes. Require the manifest bytes to equal the build rule applied to the
   stored base, using the proposal's repo and agent id and the new manifest's
   `issued_at_unix_secs`. Even mutually consistent rewritten hashes, statement
   and manifest must not authorize a second binding or any other change. Any
   failure gives `approval_invalid`, before superseded/expired checks.
3. For an already-approved proposal, only the stored envelope SHA-256 and device
   fingerprint pair is an exact resend. With `now <= issued_at_ms + 120,000`,
   return the first reply, including after a restart. Any other
   envelope, or a resend after the window, gives `approval_invalid`.
4. A superseded proposal, or a base version that is no longer newest, gives
   `superseded`.
5. An expired proposal, `now >= expires_at_ms`, or
   `issued_at_ms >= expires_at_ms` gives `expired`.
6. If a policy is stored, build the successor of the newest stored policy. If it
   exceeds the signing input limit or the policy document limit, return
   `policy_too_large`. Otherwise, a conflicting GitHub App identity, an invalid
   successor policy or a mismatch with the proposed manifest's bindings gives
   `policy_binding_conflict`. Both refusals leave the proposal pending.

On success, the transaction signs the manifest with the configured policy root,
writes the approval, signing and storage audit rows, stores the version with
source `one_tap` and signed time now, marks the proposal approved with the envelope
hash/fingerprint pair, and supersedes older-base pending proposals. The result
is exactly `{status: "approved", proposal_id, version, manifest_sha256}`. A failed
commit gives `store_error`; no signature is returned from approve. The root key
signs only through this path or `ck auth manifest sign`; `credential.sign` refuses
the root id in every address mode with uniform `not_found`, while
`credential.public_key` still works. An exact Sign grant naming the root id cannot
be created.

### Reading and watching the newest version

`manifest.latest {}` returns exactly
`{version, envelope: {key_id, manifest_bytes, signature}}` for the newest stored
version. These are the existing hand-off encodings: `key_id` is 16 lowercase hex
digits, `manifest_bytes` is the manifest's UTF-8 text as a JSON string (not
base64), and `signature` is standard base64 Ed25519 over those manifest bytes.
Nothing stored gives `not_found`/`permanent`.

`manifest.watch {}` holds a subscription. Its notices are exactly
`{kind: "changed", epoch, seq, version, manifest_sha256}`. It sends `seq: 1`
immediately with the newest version; `version` and `manifest_sha256` are both
null when nothing is stored. Later notices occur only when a new version is
stored. Epochs, sequence numbers, endings, one watch per route and the 64-watch
cap follow `auth.watch_scoped` above: a process restart changes the epoch,
sequence gaps require a fresh read, and normal held-stream endings use
`STREAM_END`.

A member holds one upstream `federation.manifest_watch` per home, opening it on
the first local watch. It answers local `seq: 1` from the upstream's current
notice and relays later notices under its own epoch and sequence numbers. If
the upstream cannot be opened, the local watch ends with a terminal `Response`
`home_unavailable`/`transient`. If the upstream is lost later, local watches end
with `STREAM_END`; AFT then re-subscribes and reads `manifest.latest`. Older
vaults answer `unknown_method` for manifest operations.

### Reporting activation and checking readiness

`manifest.report_active` takes exactly `{version, payload_sha256, verdict, reason}`:

- `version`: a positive integer.
- `payload_sha256`: 64 lowercase hex digits.
- `verdict`: `valid` or `invalid`.
- `reason`: a string of at most 512 characters for `invalid`, otherwise `null`.

The reporting computer is the local vault's own federation member id, **never a
param**. With no self member id, the report gives `secret_setup_incomplete`/`permanent`.
The report commits both the vault's latest local report and its own activation row
with `reported_at_ms`, without waiting for a hub connection. A lower
version than its current one is still recorded and logs a tracing warning.
Retired computers' reports are recorded without clearing `retired_at_ms`.

Only the first `(member_id, version, verdict)` for a **stored** version writes
an activation audit row, together with its deduplication row in the same
transaction. Changes to reason or hash, repeats, and reports of unstored versions
update the activation table only. There are at most two activation audit rows per
member per stored version. The success result is exactly
`{status: "recorded", member_id, version}`. Hub publication is separate from that
reply. Retrying the same report writes no additional activation audit.

#### Signed hub activation reports

Each vault publishes its latest local report to `vault-manifest-active`, key
`{computer_box}` (history 1, maximum value 16 KiB). The outer JSON is exactly
`{v, body, signature_b64, key_id}` with `v: 1`. The `body` is a JSON string with
exactly `box`, `member`, `version`, `manifest_sha256`, `verdict`, `reason`, and `seq`.
The hash and verdict follow `manifest.report_active`; `reason` is `null` for
`valid` and `"reported_invalid"` for `invalid`. The free-text reason and the local
timestamp never appear in the hub value. `seq` is a JSON integer token in
`1..=9007199254740991`, with no sign, fraction, or exponent. The sequence is durable
and increases for each new signed publication. The envelope and body reject
unknown, missing or duplicate fields.

The vault signs the UTF-8 bytes of `ck-vault-hub/manifest-active/v1`, followed by
one `0x00` byte and the exact UTF-8 bytes of the `body` string, with the current
`signing:fleet-record:1` Ed25519 key. The signature uses strict padded standard
base64. A verifier uses the writer's announced `fleet_record_ed25519` only: the
outer `key_id` must match that raw 32-byte public key, the KV key must equal
`body.box`, and `body.member` must be the member currently bound to that box.
Caller-directed `credential.sign` cannot sign decoded inputs starting with
`ck-vault-hub/` on a fleet-record key.

The Home records an authenticated report only for a currently paired, non-retired
computer with a `secret_use` grant, and only for a `seq` newer than the last it
accepted for that member and box under the current pairing. Losing admission,
a confirmed delete or purge, or definite verification failure clears the derived
report fields. A bucket reset clears the other computers' fields and uses the
same watch to process the relist. A failed hub read or a watch with no value on
open is not evidence of absence. The Home's own slot is never cleared by the
hub collector. See the signed report and Node verifier in the
[test samples](../crates/credentials-module/tests/fixtures/hub-wire-v1/).

`manifest.active_status` takes exactly `{version}`. A version that is not stored
refuses `unknown_version`/`transient`. Its success result has the following members:
`{version, manifest_sha256, ready, computers: [{member_id, version, payload_sha256, verdict, reason, reported_at_ms}]}`.
Once any agent policy has been stored, the result also includes `policy`: the
policy paired with the requested manifest version as `{version, policy_sha256}`,
or `null` if that manifest has no pair. The pair is reported whether or not the
queried manifest is ready. While no policies are stored, `policy` is omitted.
There is one entry per expected computer sorted by `member_id` bytes. A computer
without a report has null report fields, not a missing entry. The expected set
is the home's own member id, all members holding a `secret_use` grant and all
members with an activation row, minus retired members. `ready` is true only for
a non-empty set whose every entry reports exactly the requested version, its
stored SHA-256 and `valid`. A non-self report counts only while the computer
holds `secret_use`; a grant revoke makes its entry not ready at commit.

Operator retirement removes a computer from this readiness population and is
final; reporting never un-retires it. Retirement does not revoke delivery: a
retired computer retaining `secret_use` can still read and watch. It may still
record its own report locally, but the Home ignores it. Revoke the grant to stop delivery.

### Domain refusals

All codes below are `Response` `result.error` refusals with the indicated class.
In addition, callers outside each operation's admitted principal receive uniform
`not_found`/`permanent`. Params-shape failures remain classless transport
`invalid_params` errors, not entries in this table.

| Operation | Class | Codes and conditions |
|---|---|---|
| `manifest.propose_binding` | `permanent` | `not_found` (not the home); `manifest_setup_incomplete`; `identity_mismatch`; `not_installed`; `installation_all`; `installation_unusable`; `installation_too_large`; `installation_permissions_invalid` (permission map outside the statement grammar or bounds); `already_bound` with `{version, manifest_sha256}`; `bound_to_other_agent`; `not_reproducible` |
| `manifest.propose_binding` | `transient` | `one_tap_disabled`; `identity_unavailable`; `github_unavailable`; `stale_base`; `store_error` |
| `manifest.approve` — phone preflight | `permanent` | `phone_not_registered`; `secret_home_elsewhere` with `remedy_member`; `remote_setup_incomplete` (with `remedy_member` when known), exactly as `secret.approve` |
| `manifest.approve` — phone preflight | `transient` | `pairing_unavailable`; `store_error`, exactly as `secret.approve` |
| `manifest.approve` — after preflight | `permanent` | `manifest_setup_incomplete`; `approval_invalid`; `superseded`; `expired`; `policy_too_large`; `policy_binding_conflict`; `policy_identity_agent_mismatch` |
| `manifest.approve` — after preflight | `transient` | `store_error` |
| `manifest.latest` | `permanent` | `not_found` (nothing stored, or forwarded without a grant at the home); `remote_setup_incomplete` |
| `manifest.latest` | `transient` | `home_unavailable`; `store_error` |
| `manifest.watch` — terminal `Response` | `permanent` | `not_found`; `remote_setup_incomplete` |
| `manifest.watch` — terminal `Response` | `transient` | `home_unavailable` (a member's upstream could not be opened) |
| `manifest.report_active` | `permanent` | `secret_setup_incomplete`; `remote_setup_incomplete` |
| `manifest.report_active` | `transient` | `store_error` |
| `manifest.active_status` | `permanent` | `not_found` (not the home) |
| `manifest.active_status` | `transient` | `unknown_version` (version not stored); `store_error` |

A refusal decided by the answering vault leaves `gh_manifests`,
`gh_manifest_proposals`, `gh_manifest_activations`,
`gh_manifest_activation_audits` and `audit_log` unchanged. Shared paths may still
write the phone pipeline's pairing observation before a phone-op refusal, or the
home's diagnostic row for a forwarded `not_found`; neither is a manifest state
change.

### Audit rows

Every manifest state change writes its audit row in the same transaction. The
subject is recorded in `credential_id`; `payload_hash` is lowercase SHA-256.
Except for signing, the commitment frames each field in the listed order with
its UTF-8 byte length as a little-endian u64 followed by its bytes (`push_field`);
integers use decimal text.

| Audit op | Records and subject | `payload_hash` commits |
|---|---|---|
| `gh_manifest_propose` | Proposal insertion; `gh-manifest-proposal\|<proposal_id>` | Framed `agent_id, repo, base_version, manifest_sha256, statement_sha256` |
| `gh_manifest_proposal_state` | A proposal leaving pending; same proposal subject | Framed `from, to` |
| `gh_manifest_sign` | One root-key signature; the configured policy root id | Plain manifest SHA-256, without field framing |
| `gh_manifest_store` | Stored version; `gh-manifest\|<version>` | Framed `source, manifest_sha256` |
| `agent_policy_sign` | One root-key signature; the configured policy root id | Plain policy SHA-256, without field framing |
| `agent_policy_store` | Stored policy version; `gh-manifest\|<manifest_version>` | Framed `version, manifest_version, source, policy_sha256` |
| `gh_manifest_activation` | First audited report of a stored `(version, verdict)` per member; `gh-manifest-activation\|<member_id>` | Framed `version, verdict` |
| `gh_manifest_retire` | Operator retirement; same activation subject | Framed `retired_at_ms` |
| `gh_manifest_one_tap_set` | A real change to `manifest.one_tap`; no subject | Framed `true` or `false` |

### Producer-generated manifest samples

These TEST-ONLY samples use fixed Ed25519 and P-256 keys, a fixed clock and
proposal ULID. Process epochs and report timestamps are normalized to fixed
values after validating their wire types. Regenerate only with
`CK_EMIT_MANIFEST_VECTORS=1 cargo test --locked -p credentials-module
--features credentials-core/test-support --bin ck-claustrum
manifest_binding_vectors_and_wire_goldens_are_producer_pinned`.
The writer also updates `tests/vectors/manifest-binding-v1.json` and its
`SHA256SUMS` entry. No sample key is trusted outside tests.

<!-- manifest-binding-generated:start -->

<!-- golden:manifest.active_status.not_ready -->
```json
{
  "result": {
    "computers": [
      {
        "member_id": "fed-computer:22222222222222222222222222222222",
        "payload_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
        "reason": null,
        "reported_at_ms": 1794355300123,
        "verdict": "valid",
        "version": 29
      },
      {
        "member_id": "fed-computer:33333333333333333333333333333333",
        "payload_sha256": null,
        "reason": null,
        "reported_at_ms": null,
        "verdict": null,
        "version": null
      }
    ],
    "manifest_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
    "ready": false,
    "version": 29
  }
}
```

<!-- golden:manifest.active_status.ready -->
```json
{
  "result": {
    "computers": [
      {
        "member_id": "fed-computer:22222222222222222222222222222222",
        "payload_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
        "reason": null,
        "reported_at_ms": 1794355300123,
        "verdict": "valid",
        "version": 29
      },
      {
        "member_id": "fed-computer:33333333333333333333333333333333",
        "payload_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
        "reason": null,
        "reported_at_ms": 1794355300123,
        "verdict": "valid",
        "version": 29
      }
    ],
    "manifest_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
    "ready": true,
    "version": 29
  }
}
```

<!-- golden:manifest.approve.reply -->
```json
{
  "result": {
    "manifest_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
    "proposal_id": "01HF7YAT000000000000000001",
    "status": "approved",
    "version": 29
  }
}
```

<!-- golden:manifest.approve.request -->
```json
{
  "method": "manifest.approve",
  "params": {
    "envelope_b64url": "eyJkZWNpc2lvbiI6ImFsbG93IiwiZGV2aWNlX2ZpbmdlcnByaW50IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJpc3N1ZWRfYXRfbXMiOjE3OTQzNTUzMDAxMjMsInByb3Bvc2FsX2lkIjoiMDFIRjdZQVQwMDAwMDAwMDAwMDAwMDAwMDEiLCJzdGF0ZW1lbnRfc2hhMjU2IjoiZWFmNjA4ZmU2YWM5NDBkOTNmMjg5Yjg2YWUwNTE3YTM2ODM4YTVkOWQ4NGVlMTE5YmUxNDk1Y2YwZjViMTRlNiIsInYiOiJjay1tYW5pZmVzdC1iaW5kaW5nLWVudmVsb3BlL3YxIn0",
    "signature_b64url": "MEQCIAZF7e1xy2QYfTHt43uKDjXtDfmdhMM9IVUPQ8Dw3H1pAiBZvyBy94PV9_AjDd9k8yMkXO9wuJQUo7G9FeqE63JWXg"
  }
}
```

<!-- golden:manifest.approve.resend -->
```json
{
  "result": {
    "manifest_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
    "proposal_id": "01HF7YAT000000000000000001",
    "status": "approved",
    "version": 29
  }
}
```

<!-- golden:manifest.cross.manifest_to_secret -->
```json
{
  "reply": {
    "result": {
      "error": {
        "class": "permanent",
        "code": "approval_invalid"
      }
    }
  },
  "request": {
    "method": "secret.approve",
    "params": {
      "envelope_b64url": "eyJkZWNpc2lvbiI6ImFsbG93IiwiZGV2aWNlX2ZpbmdlcnByaW50IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJpc3N1ZWRfYXRfbXMiOjE3OTQzNTUzMDAxMjMsInByb3Bvc2FsX2lkIjoiMDFIRjdZQVQwMDAwMDAwMDAwMDAwMDAwMDEiLCJzdGF0ZW1lbnRfc2hhMjU2IjoiZWFmNjA4ZmU2YWM5NDBkOTNmMjg5Yjg2YWUwNTE3YTM2ODM4YTVkOWQ4NGVlMTE5YmUxNDk1Y2YwZjViMTRlNiIsInYiOiJjay1tYW5pZmVzdC1iaW5kaW5nLWVudmVsb3BlL3YxIn0",
      "signature_b64url": "MEQCIAZF7e1xy2QYfTHt43uKDjXtDfmdhMM9IVUPQ8Dw3H1pAiBZvyBy94PV9_AjDd9k8yMkXO9wuJQUo7G9FeqE63JWXg"
    }
  }
}
```

<!-- golden:manifest.cross.secret_to_manifest -->
```json
{
  "reply": {
    "result": {
      "error": {
        "class": "permanent",
        "code": "approval_invalid"
      }
    }
  },
  "request": {
    "method": "manifest.approve",
    "params": {
      "envelope_b64url": "eyJkZWNpc2lvbiI6ImFsbG93IiwiZGV2aWNlX2ZpbmdlcnByaW50IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJkdXJhdGlvbiI6Im9uY2UiLCJncmFudF9leHBpcmVzX2F0X21zIjowLCJpc3N1ZWRfYXRfbXMiOjE3OTQzNTUzMDAxMjMsIml0ZW1zIjpbeyJyZXF1ZXN0X2lkIjoiMDFIRjdZQVQwMDAwMDAwMDAwMDAwMDAwMDEiLCJzdGF0ZW1lbnRfc2hhMjU2IjoiZWFmNjA4ZmU2YWM5NDBkOTNmMjg5Yjg2YWUwNTE3YTM2ODM4YTVkOWQ4NGVlMTE5YmUxNDk1Y2YwZjViMTRlNiJ9XSwidiI6ImNrLXNlY3JldC11c2UtZW52ZWxvcGUvdjEifQ",
      "signature_b64url": "MEYCIQDDDWb9MS6QQpePnL-LikCFsRQyD3aE2G8vX648DUMsAQIhAO2etZbnlxx-zUkWJhkm8noT5mGSGLtQd48RtMKwVFG9"
    }
  }
}
```

<!-- golden:manifest.envelope -->
```json
{
  "approval_public_key_sec1_hex": "041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3",
  "envelope": {
    "decision": "allow",
    "device_fingerprint": "11111111111111111111111111111111",
    "issued_at_ms": 1794355300123,
    "proposal_id": "01HF7YAT000000000000000001",
    "statement_sha256": "eaf608fe6ac940d93f289b86ae0517a36838a5d9d84ee119be1495cf0f5b14e6",
    "v": "ck-manifest-binding-envelope/v1"
  },
  "envelope_b64url": "eyJkZWNpc2lvbiI6ImFsbG93IiwiZGV2aWNlX2ZpbmdlcnByaW50IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJpc3N1ZWRfYXRfbXMiOjE3OTQzNTUzMDAxMjMsInByb3Bvc2FsX2lkIjoiMDFIRjdZQVQwMDAwMDAwMDAwMDAwMDAwMDEiLCJzdGF0ZW1lbnRfc2hhMjU2IjoiZWFmNjA4ZmU2YWM5NDBkOTNmMjg5Yjg2YWUwNTE3YTM2ODM4YTVkOWQ4NGVlMTE5YmUxNDk1Y2YwZjViMTRlNiIsInYiOiJjay1tYW5pZmVzdC1iaW5kaW5nLWVudmVsb3BlL3YxIn0",
  "envelope_utf8": "{\"decision\":\"allow\",\"device_fingerprint\":\"11111111111111111111111111111111\",\"issued_at_ms\":1794355300123,\"proposal_id\":\"01HF7YAT000000000000000001\",\"statement_sha256\":\"eaf608fe6ac940d93f289b86ae0517a36838a5d9d84ee119be1495cf0f5b14e6\",\"v\":\"ck-manifest-binding-envelope/v1\"}",
  "signature_b64url": "MEQCIAZF7e1xy2QYfTHt43uKDjXtDfmdhMM9IVUPQ8Dw3H1pAiBZvyBy94PV9_AjDd9k8yMkXO9wuJQUo7G9FeqE63JWXg",
  "test_only_private_scalar_hex": "0707070707070707070707070707070707070707070707070707070707070707"
}
```

<!-- golden:manifest.latest.reply -->
```json
{
  "result": {
    "envelope": {
      "key_id": "56fae12f77164627",
      "manifest_bytes": "{\n  \"artifact_id\": \"gh-routing-manifest\",\n  \"manifest_version\": 29,\n  \"schema_floor\": 1,\n  \"issued_at_unix_secs\": 1794355300,\n  \"detectors\": [\n    {\n      \"name\": \"café 🦀\",\n      \"enabled\": true,\n      \"fallback\": null,\n      \"weight\": 1.5\n    }\n  ],\n  \"tiers\": {\n    \"write\": [\n      \"push\"\n    ],\n    \"read\": []\n  },\n  \"api_rules\": [],\n  \"canonicalization\": {\n    \"z_last\": false,\n    \"a_first\": \"line\\nfeed\"\n  },\n  \"repository_sections\": [],\n  \"bindings\": {\n    \"Zulu/Existing\": \"agent_1111111111111111\",\n    \"Alpha/Other\": \"agent_2222222222222222\",\n    \"cortexkit/opencode-sidebar\": \"agent_3333333333333333\",\n    \"Octo-Owner/New-Repo\": \"agent_4444444444444444\"\n  },\n  \"worker_reads\": []\n}\n",
      "signature": "iAD7y8ZFicBY9GkwqxcjiPE4QcROuTZ3Cc7NR5vILApdY5BR6jUEMCOzNTaZ5gCXuhWodNffXAUm8rAGa15dAQ=="
    },
    "version": 29
  }
}
```

<!-- golden:manifest.propose.reply -->
```json
{
  "result": {
    "expires_at_ms": 1794441700123,
    "manifest_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
    "manifest_version": 29,
    "proposal_id": "01HF7YAT000000000000000001",
    "statement_b64url": "eyJhZ2VudF9pZCI6ImFnZW50XzQ0NDQ0NDQ0NDQ0NDQ0NDQiLCJhcHBfc2x1ZyI6InBsZXgtYWxmb25zbyIsImV4cGlyZXNfYXRfbXMiOjE3OTQ0NDE3MDAxMjMsImluc3RhbGxhdGlvbl9wZXJtaXNzaW9ucyI6eyJjb250ZW50cyI6InJlYWQiLCJpc3N1ZXMiOiJ3cml0ZSIsIm1ldGFkYXRhIjoicmVhZCIsInB1bGxfcmVxdWVzdHMiOiJ3cml0ZSJ9LCJtYW5pZmVzdF9zaGEyNTYiOiI5NGNmODk0ZTE3NDYyY2VjMDljNzM3YjA0MmUzZjJjNDJkYmRkOTVmZmRjYWUxMDdiN2IwMGJjN2Q5ZTZjOGYzIiwibWFuaWZlc3RfdmVyc2lvbiI6MjksInByaW9yX3NoYTI1NiI6IjkxMjQ0ODkxYzQ5OGIzZTUxOTk3NjA0ZTllZGYzMGY3NWI2YmYxMGVkZmQyMDIxYzVmZWZlZWY1MTgzODRiYjUiLCJwcmlvcl92ZXJzaW9uIjoyOCwicHJvcG9zYWxfaWQiOiIwMUhGN1lBVDAwMDAwMDAwMDAwMDAwMDAwMSIsInJlcG8iOiJPY3RvLU93bmVyL05ldy1SZXBvIiwidiI6ImNrLW1hbmlmZXN0LWJpbmRpbmctc3RhdGVtZW50L3YxIn0",
    "status": "approval_required"
  }
}
```

<!-- golden:manifest.propose.request -->
```json
{
  "method": "manifest.propose_binding",
  "params": {
    "agent_id": "agent_4444444444444444",
    "app_id": 4617236,
    "app_slug": "plex-alfonso",
    "repo": "octo-owner/new-repo"
  }
}
```

<!-- golden:manifest.refusal.already_bound -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "already_bound",
      "manifest_sha256": "3551b398de3c6bd38903c49abc3d7b975b716b9f6b69fb4f8ce5316caa50cdf4",
      "version": 30
    }
  }
}
```

<!-- golden:manifest.refusal.approval_invalid -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "approval_invalid"
    }
  }
}
```

<!-- golden:manifest.refusal.bound_to_other_agent -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "bound_to_other_agent"
    }
  }
}
```

<!-- golden:manifest.refusal.expired -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "expired"
    }
  }
}
```

<!-- golden:manifest.refusal.github_unavailable -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "github_unavailable"
    }
  }
}
```

<!-- golden:manifest.refusal.home_unavailable -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "home_unavailable"
    }
  }
}
```

<!-- golden:manifest.refusal.identity_mismatch -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "identity_mismatch"
    }
  }
}
```

<!-- golden:manifest.refusal.identity_unavailable -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "identity_unavailable"
    }
  }
}
```

<!-- golden:manifest.refusal.installation_all -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "installation_all"
    }
  }
}
```

<!-- golden:manifest.refusal.installation_too_large -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "installation_too_large"
    }
  }
}
```

<!-- golden:manifest.refusal.installation_unusable -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "installation_unusable"
    }
  }
}
```

<!-- golden:manifest.refusal.invalid_params -->
```json
{
  "code": "invalid_params",
  "message": "params not decodable: invalid manifest proposal parameters"
}
```

<!-- golden:manifest.refusal.manifest_setup_incomplete -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "manifest_setup_incomplete"
    }
  }
}
```

<!-- golden:manifest.refusal.not_found -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "not_found"
    }
  }
}
```

<!-- golden:manifest.refusal.not_installed -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "not_installed"
    }
  }
}
```

<!-- golden:manifest.refusal.not_reproducible -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "not_reproducible"
    }
  }
}
```

<!-- golden:manifest.refusal.one_tap_disabled -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "one_tap_disabled"
    }
  }
}
```

<!-- golden:manifest.refusal.pairing_unavailable -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "pairing_unavailable"
    }
  }
}
```

<!-- golden:manifest.refusal.phone_not_registered -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "phone_not_registered"
    }
  }
}
```

<!-- golden:manifest.refusal.remote_setup_incomplete -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "remote_setup_incomplete"
    }
  }
}
```

<!-- golden:manifest.refusal.remote_setup_incomplete.forwarded -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "remote_setup_incomplete"
    }
  }
}
```

<!-- golden:manifest.refusal.remote_setup_incomplete.forwarded_with_remedy -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "remote_setup_incomplete",
      "remedy_member": "fed-computer:33333333333333333333333333333333"
    }
  }
}
```

<!-- golden:manifest.refusal.remote_setup_incomplete.with_remedy -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "remote_setup_incomplete",
      "remedy_member": "fed-computer:33333333333333333333333333333333"
    }
  }
}
```

<!-- golden:manifest.refusal.secret_home_elsewhere -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "secret_home_elsewhere",
      "remedy_member": "fed-computer:33333333333333333333333333333333"
    }
  }
}
```

<!-- golden:manifest.refusal.secret_setup_incomplete -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "secret_setup_incomplete"
    }
  }
}
```

<!-- golden:manifest.refusal.stale_base -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "stale_base"
    }
  }
}
```

<!-- golden:manifest.refusal.store_error -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "store_error"
    }
  }
}
```

<!-- golden:manifest.refusal.superseded -->
```json
{
  "result": {
    "error": {
      "class": "permanent",
      "code": "superseded"
    }
  }
}
```

<!-- golden:manifest.refusal.unknown_version -->
```json
{
  "result": {
    "error": {
      "class": "transient",
      "code": "unknown_version"
    }
  }
}
```

<!-- golden:manifest.report.reply -->
```json
{
  "result": {
    "member_id": "fed-computer:22222222222222222222222222222222",
    "status": "recorded",
    "version": 29
  }
}
```

<!-- golden:manifest.report.request -->
```json
{
  "method": "manifest.report_active",
  "params": {
    "payload_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
    "reason": null,
    "verdict": "valid",
    "version": 29
  }
}
```

<!-- golden:manifest.statement -->
```json
{
  "statement": {
    "agent_id": "agent_4444444444444444",
    "app_slug": "plex-alfonso",
    "expires_at_ms": 1794441700123,
    "installation_permissions": {
      "contents": "read",
      "issues": "write",
      "metadata": "read",
      "pull_requests": "write"
    },
    "manifest_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
    "manifest_version": 29,
    "prior_sha256": "91244891c498b3e51997604e9edf30f75b6bf10edfd2021c5fefeef518384bb5",
    "prior_version": 28,
    "proposal_id": "01HF7YAT000000000000000001",
    "repo": "Octo-Owner/New-Repo",
    "v": "ck-manifest-binding-statement/v1"
  },
  "statement_b64url": "eyJhZ2VudF9pZCI6ImFnZW50XzQ0NDQ0NDQ0NDQ0NDQ0NDQiLCJhcHBfc2x1ZyI6InBsZXgtYWxmb25zbyIsImV4cGlyZXNfYXRfbXMiOjE3OTQ0NDE3MDAxMjMsImluc3RhbGxhdGlvbl9wZXJtaXNzaW9ucyI6eyJjb250ZW50cyI6InJlYWQiLCJpc3N1ZXMiOiJ3cml0ZSIsIm1ldGFkYXRhIjoicmVhZCIsInB1bGxfcmVxdWVzdHMiOiJ3cml0ZSJ9LCJtYW5pZmVzdF9zaGEyNTYiOiI5NGNmODk0ZTE3NDYyY2VjMDljNzM3YjA0MmUzZjJjNDJkYmRkOTVmZmRjYWUxMDdiN2IwMGJjN2Q5ZTZjOGYzIiwibWFuaWZlc3RfdmVyc2lvbiI6MjksInByaW9yX3NoYTI1NiI6IjkxMjQ0ODkxYzQ5OGIzZTUxOTk3NjA0ZTllZGYzMGY3NWI2YmYxMGVkZmQyMDIxYzVmZWZlZWY1MTgzODRiYjUiLCJwcmlvcl92ZXJzaW9uIjoyOCwicHJvcG9zYWxfaWQiOiIwMUhGN1lBVDAwMDAwMDAwMDAwMDAwMDAwMSIsInJlcG8iOiJPY3RvLU93bmVyL05ldy1SZXBvIiwidiI6ImNrLW1hbmlmZXN0LWJpbmRpbmctc3RhdGVtZW50L3YxIn0",
  "statement_sha256": "eaf608fe6ac940d93f289b86ae0517a36838a5d9d84ee119be1495cf0f5b14e6",
  "statement_utf8": "{\"agent_id\":\"agent_4444444444444444\",\"app_slug\":\"plex-alfonso\",\"expires_at_ms\":1794441700123,\"installation_permissions\":{\"contents\":\"read\",\"issues\":\"write\",\"metadata\":\"read\",\"pull_requests\":\"write\"},\"manifest_sha256\":\"94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3\",\"manifest_version\":29,\"prior_sha256\":\"91244891c498b3e51997604e9edf30f75b6bf10edfd2021c5fefeef518384bb5\",\"prior_version\":28,\"proposal_id\":\"01HF7YAT000000000000000001\",\"repo\":\"Octo-Owner/New-Repo\",\"v\":\"ck-manifest-binding-statement/v1\"}"
}
```

<!-- golden:manifest.watch.empty -->
```json
{
  "epoch": "00112233445566778899aabbccddeeff",
  "kind": "changed",
  "manifest_sha256": null,
  "seq": 1,
  "version": null
}
```

<!-- golden:manifest.watch.stored -->
```json
{
  "epoch": "00112233445566778899aabbccddeeff",
  "kind": "changed",
  "manifest_sha256": "94cf894e17462cec09c737b042e3f2c42dbdd95ffdcae107b7b00bc7d9e6c8f3",
  "seq": 1,
  "version": 29
}
```
<!-- manifest-binding-generated:end -->

### Agent SSH enrollment admin operations

`admin.ssh_key_agent_allow` takes `{v: 2, id, targets}`; `id` names a local
`signing:` Ed25519 credential. Each target contains only `{host, user?, port?}`:
canonical lowercase DNS, IPv4 or canonical unbracketed IPv6 host, optional ASCII
login name, and optional integer port 1–65535. There must be 1–16 unique targets.
The operation replaces, never unions, the complete set inside the sealed record's
additive `agent_ssh: {targets}` member. `admin.ssh_key_agent_deny` takes
`{v: 2, id}` and removes that member. Both return `{targets: [...]}`; deny returns
an empty array. An identical repeat changes nothing and writes no audit row.
Allow requires `secret.local_programs` on (`secret_local_programs_disabled` when
off or unreadable); deny works in either state. Both use the existing online
admin authentication or offline writer lease. Online, the credential's lock
serializes enrollment changes with other operations on the same key.

CLI forms are `ck auth ssh-key allow <id> --target [user@]host[:port]...` (repeat
the target flag) and `ck auth ssh-key deny <id>`. IPv6 must be bracketed on the
CLI even without a port: `[2001:db8::1]`, `root@[2001:db8::1]:22`. Brackets are
not stored. Both print the resulting target object as JSON.

Generic create and overwrite operations refuse incoming `agent_ssh` with
`invalid_params`. Every successful `signing:` overwrite stores an unenrolled key.
Enrollment changes, signing-key replacement and removal atomically delete grants
and pending requests addressed to the credential id, regardless of whether the old
envelope can be decoded. Receipts for its incarnation remain until expiry with
`aad_sha256 = "invalidated"` and empty `enc` and `ciphertext`, keeping the old
requester/nonce occupied. Re-enrollment never restores old authority.

## 17a. Signed agent policies

### Reading and watching the active policy

`policy.active {}` and `policy.watch {}` admit only `reserved:plexus` and
`reserved:aft`. Both serve on Single and Home vaults only and never relay. Other
callers, and admitted callers on Remote or RemoteSetupIncomplete vaults, receive
`not_found`/`permanent`. A role or store read failure is `store_error`/`transient`
for an admitted caller. Parameters must be an empty object.

`policy.active` returns `{version, policy_sha256, manifest_version, policy_text}`.
The vault checks every non-retired expected computer's current report for a valid
verdict and the exact digest of its stored manifest. The lowest such reported
manifest version is the fleet floor. The active (ready) policy is the one paired
with the newest stored manifest at or below that floor. No reports, a missing or
invalid report, or a mismatched digest establishes no floor. The serving role and
selection are read in one snapshot. `manifest_version` is the paired manifest
version; `policy_text` is the exact UTF-8 JSON string from the signed policy
envelope. When there is no ready pair, all four members are null. This selection
does not change what `manifest.active_status` reports for each specific version.

During a rollout, `policy.active` also returns
`"rollout": {"manifest_version": <u64>, "policy_version": <u64>}`, naming the
newest stored **paired** manifest and policy. The member is absent when that
pair is ready or no stored pair exists. An unpaired newest manifest is not a
rollout pair. If a stored pair exists but none is ready, the four ready members
are null and `rollout` still names the newest stored pair.

`policy.watch` uses WATCH delivery and the shared local inventory watch contract:
one subscription per route, a shared maximum of 64, `STREAM_END` on replacement or
drain, and silent cancellation or route close. An open that fails caller or
parameter validation does not replace an existing watch. An admitted open with
valid parameters registers before its first snapshot; a subsequent role refusal
ends that new watch with one `RESPONSE`, not `STREAM_DATA` or `STREAM_END`.

Each `STREAM_DATA` body is exactly
`{"version": <int|null>, "policy_sha256": <hex|null>, "kind": "changed", "epoch": "<32 lowercase hex>", "seq": <int>}`.
Sequence 1 is the snapshot at open, with both policy members null when none is
active. Later notices are sent when the ready pair or the pair named by `rollout`
changes. A rollout-only notice can repeat the previous ready metadata; use
its new sequence number to re-read `policy.active`. Notices never carry a
`rollout` member. Commits that can affect policy pairing, readiness, reporter
admission or the serving role wake the watch.
Writes coalesce over approximately 250 ms; intermediate changes may not be observed.
A later non-serving role ends the subscription with one `RESPONSE`
`not_found`/`permanent`. A transient snapshot failure after sequence 1 retains the
last sent value and retries on the next commit. Notices are sheddable; to confirm
the current value, read `policy.active` or reopen for a fresh sequence 1.
`manifest.watch` retains its existing new-versions-only behavior.

### Policy read samples

These examples use a test-only signed policy. The watch epoch is fixed for the
examples; a running daemon chooses its own epoch.

The exact `policy.active` reply bytes with and without `rollout` are pinned under
[`tests/vectors/agent-policy-v1/`](../crates/credentials-module/tests/vectors/agent-policy-v1/)
with `SHA256SUMS`. They come from the real query handler. Regenerate with
`CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module --features credentials-core/test-support --bin ck-claustrum policy_active_rollout_samples_and_watch_changes`.

<!-- golden:policy.active.none -->
```json
{
  "result": {
    "version": null,
    "policy_sha256": null,
    "manifest_version": null,
    "policy_text": null
  }
}
```

<!-- golden:policy.active.ready -->
```json
{
  "result": {
    "version": 1,
    "policy_sha256": "85f93cc525185d7b40916c2800c0baccf00602262d0766c15f208c5b9e4c1df8",
    "manifest_version": 41,
    "policy_text": "{\"bindings\":[{\"agent\":\"agent\",\"identity\":\"github_app:agent\",\"resources\":[\"org/r\"],\"service\":\"github\"}],\"issued_at_unix_secs\":1,\"root_key_id\":\"56fae12f77164627\",\"rule_sets\":{},\"schema\":\"ck-agent-policy/v1\",\"version\":1}"
  }
}
```

<!-- golden:policy.watch.initial -->
```json
{
  "version": null,
  "policy_sha256": null,
  "kind": "changed",
  "epoch": "00112233445566778899aabbccddeeff",
  "seq": 1
}
```

<!-- golden:policy.watch.changed -->
```json
{
  "version": 1,
  "policy_sha256": "85f93cc525185d7b40916c2800c0baccf00602262d0766c15f208c5b9e4c1df8",
  "kind": "changed",
  "epoch": "00112233445566778899aabbccddeeff",
  "seq": 2
}
```

### Policy-narrowed GitHub token

`credential.policy_token` is a Query, not a watch. It takes a closed object
`{identity, service, kind, resource, policy_version, approval_request_id?, request_sha256?}`.
The version is an integer; the other members are strings. `identity` is a
credential ID, not a handle.
`kind` names one request kind, not an action. Only `reserved:plexus` and
`reserved:aft` may call it. It serves on Single and Home vaults only and is never
relayed. Other callers and non-serving vaults receive `not_found`/`permanent`.

Before using the cache or making any GitHub request, the vault checks, in order:

1. The attested caller has a persisted exact `policy_token` grant on `identity`.
   A `read` grant does not suffice, and `policy_token` does not grant `read`.
2. `service` is `github`.
3. If either approval member is present, both must be present: the 26-character
   uppercase request ID (ULID) returned by `policy.request_action` and the leg's
   digest of 64 lowercase hexadecimal digits. A missing partner or a malformed
   value, including explicit `null`, gets transport `invalid_params`. If the supplied
   version is active and that kind exists there with approval other than `once`,
   the pair gets `invalid_params` without looking up the approval.
4. With the pair, the request must exist, be approved and unexpired, and belong
   to the minting module. Its policy version must still be active. Its identity
   and the next unissued leg's kind, resource and digest must match the call.
   This call carries no `stamp` member: unlike `policy.request_action`, it
   names no daemon-attested agent and scope. The vault checked the agent when it
   minted the approval request, and it binds the issue to the minting module and
   identity under the same policy.
5. `policy_version` equals the ready policy version from `policy.active`. If the
   newest stored manifest or any currently reported manifest has no paired policy,
   minting refuses with `policy_version_not_active`, even with a ready pair.
6. The ready policy, every distinct currently reported pair, and the newest stored
   pair bind that service and App identity to the same agent.
7. Each pair's rule set contains `kind`, with identity `agent`, a credential, and a
   class other than `denied`. The permission map keeps only names that all pairs
   allow, at the lowest allowed level (`read`, `write`, `admin`); an empty map
   refuses with `policy_token_scope_unavailable`.
8. `resource` exactly matches a canonical lowercase repository in every binding.
   Only `node_repository` may instead use `"binding"`. It selects the intersection
   of the bindings' repository sets, which must contain 1–500 repositories.
9. The local App credential exists and is active, and any attested agent matches
   the binding. A remote copy does not count.
10. If any pair requires `approval: once` and neither member was supplied, the
     vault returns `approval_required`. Proofs remain bound to the ready policy:
     a newly gated kind cannot release a token until the ready policy also
     requires approval. An approval from the ready pair still works if a newer
     pair allows the same step without approval.

An offline computer with a valid older report delays new bindings, not tokens
for unchanged ones. A removal, move or App identity change stops issuing tokens
for the old binding immediately; the new binding waits for reports. An
intermediate report that removed a repository still excludes it even if the
newest pair adds it back. A manual manifest ceremony pauses token issuance if
it stores a manifest without a policy; complete it with `ck auth policy sign`.

Success is `{token, expires_at_ms, repositories, permissions}`. `token` is a
GitHub installation bearer token, `expires_at_ms` is a Unix timestamp in
milliseconds, `repositories` is the sorted lowercase selected set, and
`permissions` is the intersection of the kind's `credential.github_permissions`
maps, or the same map unchanged if all pairs agree. The vault
checks the exchange reply against the requested repositories and permissions;
unrequested `metadata: read` is allowed and omitted from the returned map. The
token does not enforce the kind's individual request matcher; the caller does.
The vault never falls back to a broad token.

Token storage is in memory only. Requests with the same credential identity,
incarnation (a random value the vault assigns each time a credential is created, so a
deleted and re-created credential with the same id is a different one), record
version, sealed-record digest, repository set and permissions can share one mint
and can reuse the result until five minutes before expiry.
The shared mint has 30 seconds for installation discovery and token exchange
together. It returns `github_unavailable` if the deadline passes.
Before handing out any token, the vault rechecks its role, the accepted caller's
exact grant, any approval for the prepared leg, the ready policy version, the
current intersection of repository and permission scopes, the credential row and
token expiry. A candidate whose scope no longer matches is not released. The
token-release transaction records the caller's first use of the credential, the
same scoped first-use row a
`credential.get_scoped` read writes. For an approved leg it also advances the issue count
and appends one `broker_action_issue` audit row with the leg digest. Cached
tokens go through the same checks. No refusal spends a leg. The write
fails if this vault process no longer holds the store's single-writer lock (the
lease that keeps the daemon and an offline `ck auth` from writing at once).
If the active row was replaced or changed during mint, the vault retries with
the new row once; an unusable row or a failed authorization is not retried.

| Class | Code | Meaning |
|---|---|---|
| `permanent` | `not_found` | Caller, role, grant, service, binding, kind, or resource refused |
| `permanent` | `approval_required` | An otherwise eligible local request names a `once` kind but carries no approval; request one with `policy.request_action` and have the person approve it on an approving device |
| `permanent` | `approval_invalid` | No live approved request matches this caller, identity, and next leg; check the approval status and leg order, and file a new card if the approval expired or was spent |
| `permanent` | `approval_policy_changed` | The approval's policy is no longer active; request a new approval under the active policy |
| `permanent` | `policy_version_not_active` | No policy is ready, the supplied version is not ready, or a reported/newest manifest is unpaired |
| `permanent` | `not_installed` | No local App credential |
| `auth_required` | `needs_reauth` | Credential needs reauthentication or is retired |
| `permanent` | `corrupt` | Credential is corrupt or its material cannot be decoded |
| `transient` | `vault_locked` | Credential was sealed under a different master key |
| `permanent` | `installation_unusable` | App material or the installation does not support the mint |
| `permanent` | `installation_suspended` | GitHub marks the installation as suspended |
| `permanent` | `policy_token_scope_unavailable` | Empty intersection, selected set exceeds the binding limit, the prepared scope no longer matches, or GitHub cannot issue the requested scope |
| `permanent` | `policy_token_scope_mismatch` | The GitHub reply does not confirm the exact scope |
| `transient` | `github_unavailable` | GitHub is unavailable, the reply is unusable or expired, or the row changed again |
| `transient` | `store_error` | A store check or release commit failed |

Application refusals use only `{"error":{"code","class"}}`. For transport
`invalid_params`, correct the request shape; omit both approval members for a
kind that does not require approval. No refusal returns a token or a provider
response body. An unreadable credential is not quarantined by this method,
and mint failures do not change its state.

For a `once` kind, mint the statement with
[`policy.request_action`](#request-broker-action-approval) and file it as a
broker action card in Cingulate. An approving device calls
[`policy.approve_action`](#approve-a-broker-action) before recording its allow
in Cingulate. A Cingulate answer alone cannot release a token. If the vault
refuses the token, do not send the request. For a multi-leg action that stopped
partway through, any retry after fresh reads needs a new card for the unsent
legs only.

### Request broker action approval

`policy.request_action` is a Mutate operation on the Single or Home vault. It
is never relayed and never contacts GitHub. Only `reserved:aft` and
`reserved:plexus` may call it, with a persisted exact `policy_token` grant on the
`github_app:<slug>` identity. The request is one of two closed objects:

- One leg: `{identity, service, action, kind, method, host, resource, request_sha256, fields, stamp, context?}`.
  `action` must equal `kind`.
- Explicit legs: `{identity, service, action, host, legs, fields, stamp, context?}`.
  `legs` holds 1–16 closed `{kind, method, resource, request_sha256}` objects in
  send order. The statement's top-level `resource` is the first leg's resource.

`fields` holds up to 16 closed `{name, value}` objects. Values are JSON, with
only integers in ±(2^53−1) as numbers, including inside arrays and objects.
`service` and `action` are nonempty strings. Each method is one or more ASCII
uppercase letters. The host uses the policy host grammar and may have a port in
1–65535 without a leading zero; `:443` is not permitted. If present, `context`
is nonempty display-only text of at most 200 characters with no Unicode Cc,
Cf, Zl or Zp character. Mask secret values before supplying it.

The enforcer computes each `request_sha256` before adding the credential
header. Hash the ASCII tag `ck-broker-request/v1` followed by a zero byte and
four parts, each prefixed with its 32-bit big-endian byte length: uppercase
ASCII method, lowercase ASCII host (port only when non-default), exact request
target (path and, if present, `?` and raw query), and exact body (zero bytes if
absent). Send the SHA-256 as 64 lowercase hexadecimal digits. The vault checks
the digest's shape, not the underlying request bytes.

The sender relays the daemon's `stamp` verbatim using the `secret.use` stamp
grammar. The vault trusts the two senders to relay it unchanged. It takes
`agent_id` from `attributes.on_behalf_of_agent` for workers and
`attributes.agent_id` otherwise. The statement's `{owner, kind, ref, epoch}`
comes from the stamp itself, with `epoch` set to `scope_epoch`. An ephemeral
stamp does not map to its parent, and a stamp with `flow_id` may be used.

Checks run in order. Every refusal writes nothing. Application refusals are
`{"error":{"code","class"}}`; `invalid_params` is a transport error.

1. A non-serving role or a caller outside the allowlist gets `not_found`
   (permanent). For an allowed caller, a missing or malformed `identity` is
   `invalid_params`; a well-formed identity without a covering grant gets
   `not_found` before any remaining parameter checks. A missing top-level
   `stamp` is `invalid_params`. Missing required members *inside* the stamp or
   no attributed agent get `not_found`.
2. A malformed stamp (including a scope or parent epoch above 2^53−1), an
   unknown or missing request member, or another shape defect is `invalid_params`.
3. No active policy is `policy_absent` (permanent).
4. The service must be `github`; its host list must contain the exact `host`
   string, so a host with a port cannot match. The active binding must list the
   identity, stamped agent and every resource. Every kind must exist with
   identity `agent` and a class other than `denied`. The local credential must
   exist, and any App creation attestation must match the binding's agent.
   A failure is `not_found` (permanent).
5. Any leg whose kind does not require `approval: once` returns
   `approval_not_required` (permanent).
6. Field names must match the kinds' `consent.fields` exactly, with no
   duplicates, or the result is `consent_fields_invalid` (permanent). The
   statement uses template order; for explicit legs the vault takes the union
   of fields in leg order, keeping the first occurrence of each name.
7. A statement that fails the `ck-broker-action-statement/v1` grammar or exceeds
   524,288 decoded bytes returns `invalid_params`.
8. More than 16 pending requests for the stamped agent or more than 256 total
   returns `approval_pending_limit` (transient). A request is pending until
   expiry or until all its legs have issued. Wait for a slot before retrying.

For `policy_absent`, check that a signed policy is active before retrying.
For `not_found`, check routing, the stamp's agent attribution, and the grant
and policy binding; the refusal does not identify which check failed. For
`approval_not_required`, follow the token path without approval for a kind
that does not require it; for explicit legs, only include kinds requiring
`once` in the card. For `consent_fields_invalid`, rebuild the field list from
the active policy's consent template. For `invalid_params`, correct the body,
including values that would exceed the statement limits.

Success is `{request_id, statement_b64url, statement_sha256, expires_at_ms}`.
The request id is a fresh ULID, and expiry is exactly ten minutes after minting.
The statement is unpadded base64url of the exact RFC 8785 JSON bytes.
`statement_sha256` is the lowercase SHA-256 of those decoded bytes. The statement
carries the active policy version and digest, and the request details in the
shape above, except it replaces `stamp` with `agent_id` and `scope` and adds
`v: "ck-broker-action-statement/v1"`, `request_id`, `policy_version`,
`policy_sha256` and `expires_at_ms`. The statement is closed: with `legs`,
its top-level `kind`, `method` and `request_sha256` are absent. No approval or
token is issued by the mint.
A successful mint commits one `broker_action_request` audit row. Its credential
is the App identity, its actor is the calling reserved module, and its
`payload_hash` is `statement_sha256`. It has no alarm.
A store failure returns `store_error` (transient), without committing a request
or its audit row.

### Approve a broker action

`policy.approve_action` is a Mutate operation on the Single or Home vault. It
admits only an authenticated `fed-phone:` route marked `peer_build: "production"`
or the unscoped direct development desktop while its approval switch is on.
Other routes get `not_found` (permanent) before parameter checks. The phone must
have a current pairing and a registered approval key for that pairing.

The closed body is `{card_ref?, envelope_b64url, signature_b64url}`. The base64url
values are strict and unpadded. If present, `card_ref` is 1–64 ASCII graphic bytes;
the vault validates it but does not use or store it. On the development route the
signature member must be absent (even `null` is refused), and the device
fingerprint is 32 zeroes. A malformed body returns transport `invalid_params`.

The decoded envelope is exact RFC 8785 JSON, with only these members:
`{v, request_id, statement_sha256, decision, device_fingerprint, issued_at_ms}`.
`v` is `ck-broker-action-envelope/v1`, `request_id` is a ULID, `statement_sha256`
is 64 lowercase hexadecimal digits, and `decision` is `allow`. The fingerprint
must match the route. On the phone route the registered P-256 key must verify a
DER signature over the exact decoded envelope. The unsigned `issued_at_ms` must
be a safe JSON integer within the same clock-skew window as `manifest.approve`.

The request must exist, match the statement digest, and have been created no
later than `issued_at_ms`. A first approval must be recorded before the request's
expiry, and its `issued_at_ms` must also precede expiry. An already recorded
approval returns the same reply only for an exact envelope hash and fingerprint
match, after signature and time-window verification. It does not extend the
request or write another row. Any other refusal on an admitted route with a
well-formed body returns `{"error":{"code":"approval_invalid","class":"permanent"}}`.
No refusal writes an approval, audit row, or phone observation.

For `not_found`, use the serving vault and an admitted approval route. For
`invalid_params`, correct the body for that route. For `approval_invalid`,
check the phone pairing and approval key, the device clock, and the exact
request ID and digest on the card. An expired card cannot take a new approval;
file a new card if the action still needs to be sent. Do not record an allow
in Cingulate when the vault refuses the approval.

Success is `{status: "approved", request_id, statement_sha256}`. The first
success records the approval and one `broker_action_approve` audit row together.
The row names the App identity, uses SHA-256 of the decoded envelope as
`payload_hash`, and uses the same actor format as a manifest approval, with no
alarm. A decline is not sent to the vault.

### Document and signature

An agent policy defines which service identity belongs to each agent, the repositories
bound to that identity, and the request kinds and actions available on the service. A
version is immutable. The top-level members, all required, are:

| Member | Value |
|---|---|
| `schema` | `"ck-agent-policy/v1"` |
| `version` | A positive integer |
| `issued_at_unix_secs` | An integer Unix timestamp in seconds |
| `root_key_id` | 16 lowercase hexadecimal digits |
| `rule_sets` | Object mapping service names to rule sets; only `github` is supported |
| `bindings` | Array of binding objects, in the order specified below |

The document is UTF-8 RFC 8785 JSON Canonicalization Scheme (JCS) JSON. Object keys
sort by UTF-16 code units; array order is preserved. There is no trailing newline.
Duplicate object members, unknown members, and positional arrays in place of objects
are refused. Every JSON number is an integer in ±(2^53−1); fractions and exponents
are refused, including `1.0` and `1e0`. The document limit is 1 MiB.

The signature envelope is:

```json
{"v":1,"policy":"<exact canonical JSON text>","key_id":"<16 lowercase hex digits>","signature_b64":"<base64 Ed25519 signature>"}
```

`policy` is a JSON string, not a nested object or base64. The Ed25519 signature is
over the ASCII bytes `ck-agent-policy/v1`, one zero byte, and the exact UTF-8 bytes of
the decoded `policy` string, with no additional framing. `signature_b64` encodes the
64-byte signature in standard padded base64. `key_id` and `root_key_id` must both
match the signing root's id: the first eight bytes of SHA-256 over the raw 32-byte
public key, in lowercase hex. A verifier checks the signature on the received bytes
under its trusted root and then parses the document; it never verifies a rewritten
document.

Signing refuses `policy_too_large` if the 19-byte separator plus the policy exceeds
1 MiB, even when the document alone fits the model limit. This check precedes
parsing and writing. The limit on the serialized online admin operation is separate.
General `credential.sign` refuses any payload beginning with the complete 19-byte
separator, even for a key that otherwise signs arbitrary bytes.

### Rule sets, kinds and actions

A GitHub rule set has `rule_set: "github"`, an integer `revision`, `source`,
`extractor: "github-rest-graphql/v1"`, `hosts`, `redirect_hosts`, `kinds` and
`actions`. All members are required. `source` is an object containing `release`
(1–64 ASCII characters from `[a-z0-9._-]`) and `sha256` (64 lowercase hex digits).
The model validates the shape. To check narrowing, the signer finds the service's
default rule set embedded in the vault release named by `source.release` and checks
its identity against `source.sha256`. The identity is the SHA-256 of the default's
RFC 8785 JSON Canonicalization Scheme bytes with the `source` member omitted.
The vault embeds the release artifacts from `crates/credentials-core/policy-defaults/`
at build time and adds `source` when loading one. A narrowed rule set keeps the
default's release name and digest, not a digest of the narrowed rules.

| Revision | Release | Artifact | SHA-256 | Kinds |
|---|---|---|---|---|
| 2 (current default) | `cortexkit-defaults-2026.11.2` | `github-2026.11.2.json` | `c67bdaaeec7e2c86d3672afc1e7056b0dffecb3b37e9ab17b36414640d1599db` | 45 |
| 1 (still accepted) | `cortexkit-defaults-2026.11` | `github-2026.11.json` | `aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7` | 39 |

Revision 2 adds six repository reads: issue timelines, commit check runs and
status, matching Git refs, Actions runs, and Actions run jobs. `github.repo.get`
still matches only the repository root, and the action list is unchanged. Policies
that cite revision 1 are still checked against its unchanged rules.

Narrowing may remove kinds or actions, change an approval from
`none` to `once`, remove permission entries or lower their level (`admin` → `write`
→ `read`), or remove request alternatives. Other changes are refused as narrowing.

`hosts` and `redirect_hosts` are sorted, unique and disjoint arrays of exact lowercase
DNS names. Each has at least two labels, each of 1–63 ASCII lowercase letters, digits
or hyphens, with no leading or trailing hyphen. A host is at most 253 bytes. Ports,
wildcards and IP literals are refused. Redirect hosts are for GET requests only and
never receive a credential.

A kind has the required members `kind` (a unique non-empty name), `class`, `approval`,
`identity`, `credential`, `ownership`, `requests` and `consent`.

- `class` is `read`, `speech`, `operator` or `denied`. `approval` is `none` or
  `once`; `operator` requires `once`. A `denied` kind only names a refusal, so it
  has an empty `requests` array and null `credential`, `ownership` and `consent`.
- `identity` is `agent` or `anonymous`. Anonymous non-denied kinds are public reads
  and have no credential. `credential` is null or `{ "github_permissions": {...} }`.
  The map must have 1–64 entries; permission names match `[a-z][a-z0-9_]{0,63}`
  and levels are `read`, `write` or `admin`.
- `ownership` is null or `{ "check": "<name>", "reads": ["<kind>", ...] }`.
  Each pre-read names a `read` kind in this rule set and uses that kind's token.
  In order, there is one pre-read for `own_comment`, `own_issue`, `own_pull_request`,
  `own_pull_requests`, `own_stack_pull_requests` or `thread_in_repository`, and two
  for `own_last_comment` or `own_thread_pull_request`. Other checks are refused.
- `consent` is null unless `approval` is `once`. A non-null value is
  `{ "fields": ["<name>", ...] }`. The kind must declare each name as a path
  parameter or a required, optional or fixed body field. The approval prompt uses
  its own labels; the policy cannot supply the text displayed next to a value.
- `requests` holds the request alternatives for one kind. A non-denied kind must
  have at least one. An entry has exactly one member: `rest` or `graphql`.

An action is `{ "action": "<name>", "legs": [{ "kind": "<name>" }, ...] }`.
Each action name is non-empty and unique. Legs run in array order. A leg may include
`"optional": true`; omission means false. Every leg must name an existing,
non-denied kind. At least one leg is required. An action derives its class (the
highest of `read` < `speech` < `operator`) and approval (the stricter of `none` and
`once`) from all its legs, including optional ones. These values are not stored on
the action.

### REST and GraphQL request alternatives

A `rest` object has `method` (an HTTP token, matched exactly), `host` (one of
`hosts`) and `path`, with optional `body` and `query` constraint objects. Paths start
with `/`. Literal template segments are in decoded form, matched byte for byte and
case-sensitively. For an incoming path, split on `/` and percent-decode each segment
exactly once as UTF-8. Empty segments, `.` and `..`, `/` or backslash within a
segment (even if encoded), and ASCII control characters are refused. A decoded `%`
is literal, not another escape. Braces in a template delimit typed segments.

| Segment | Decoded values |
|---|---|
| `{owner}` | `[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?`, optionally followed by `_[A-Za-z0-9]{1,16}` |
| `{repo}` | 1–100 ASCII characters from `[A-Za-z0-9._-]`, except `.` and `..` |
| `{number}` | Positive decimal with no leading zero, at most 2,147,483,647 |
| `{id}` | Positive decimal with no leading zero, at most 9,007,199,254,740,991 |
| `{sha}` | Exactly 40 or 64 lowercase hexadecimal digits |
| `{name}` | 1–255 UTF-8 bytes of one normalized segment |
| `{param*}` | One or more `name` segments, at most 1,024 bytes joined by `/` |

A tail is allowed once, at the end only. Its parameter name matches
`[a-z][a-z0-9_]{0,31}`. The names `owner` and `repo` may each appear at most
once, including as a tail parameter. A typed `{owner}` without a typed `{repo}`
is allowed only in an anonymous read. REST templates
that can match `/graphql` at `api.github.com` are refused.

For a REST kind whose path has no `{owner}/{repo}` pair, the resource comes only
from the partner call. The token is still narrowed to the single bound repository
named in that call. The v1 HTTP broker cannot infer a repository for such requests
and does not broker them. A caller that already knows the bound repository can
invoke the kind by name, as it does for the GitHub search kinds.

`body` and `query` use the same object shape. Every member is optional:

| Member | Meaning | Default |
|---|---|---|
| `required` | List of names that must appear | `[]` |
| `optional` | List of names that may appear | `[]` |
| `fixed` | Object mapping names that must appear to their only allowed values | `{}` |
| `forbidden` | List of names that must not appear | `[]` |
| `additional` | `deny` rejects every unlisted name; `allow` permits names not listed as forbidden | `"deny"` |

The four name groups are disjoint and contain no duplicates. The `fixed` values for
`query` must be strings. Those for `body` are strings, booleans, null or exact
integers. A read with no `query` permits any query parameters; all other kinds with
no `query` permit none. Query names are percent-decoded once and repeated names
count once for name matching. A kind with no `body` does not inspect the body.
A `body` constraint requires an uncompressed `application/json` object, at most
1 MiB, with constraints applied to its top-level members. A non-read kind cannot
set `body.additional` to `allow`.

A `graphql` object has `operation` (`query` or `mutation`), `fields` (a non-empty
array of unique GraphQL root field names), and optional `arguments` (an object
mapping dotted argument paths to predicates). The request is a `POST` to
`api.github.com/graphql` with a JSON object containing a `query` string of at most
256 KiB, optional object `variables` and optional `operationName`. No batching or
subscriptions. When there is more than one operation the name must select exactly
one. The enforcer expands root fragments, resolves aliases, rejects root directives
and matches the exact set of root field names. It evaluates arguments from literals
or supplied variables and follows dotted paths into input objects. The only
predicates are:

- `repository_in_scope`, on the root `repository` field: lowercased `owner` and
  `name` must name a bound repository.
- `node_in_scope`, on an ID argument: the `node_repository` pre-read must resolve
  the node to a bound repository; any failure rejects the match.

When any alternative uses `node_in_scope`, the rule set must contain
`node_repository`. Wherever present, that kind must have class `read`, approval
`none`, identity `agent`, null ownership and consent, and exactly one alternative,
`{"graphql":{"operation":"query","fields":["node"]}}`, with no argument
predicates. Its permission map is exactly `metadata: read`, `issues: read` and
`pull_requests: read`. It is the only kind allowed a token scoped to the binding's
whole repository list, so the enforcer can query `repository { nameWithOwner }`
before it knows the repository.

The signer refuses overlap between distinct kinds. REST alternatives overlap when
their methods and hosts agree, there is a normalized path both templates can match,
and no body or query constraint makes the pair disjoint. Path overlap compares
literal equality, whether a literal satisfies a type, or whether two types share a
possible segment, including the tail's segment and total length limits. A required
or fixed name that the other constraint does not permit, or different fixed values
for the same name, makes constraints disjoint. For example, a kind forbidding
`state` is disjoint from one fixing `state` to `"closed"`. GraphQL alternatives
from distinct kinds overlap when their operation and exact root field sets agree,
unless their kinds are equivalent for that request. Equivalent kinds must both
be class `read`, approval `none`, and have null ownership. Their identities,
credentials and argument predicates must be identical. Argument predicates do
not otherwise make alternatives disjoint. No match, or multiple matches that
are not equivalent, is a denial at enforcement time. Equivalent matches do not
change the partner call's resource rules for a named kind.

### Bindings and signing-time checks

Each binding is an object with `service: "github"`, a non-empty `agent` name,
`identity: "github_app:<slug>"` and `resources`. The slug is 1–100 lowercase ASCII
letters, digits or hyphens. Each pair of service and agent appears at most once,
and no two agents share an identity. `resources` is a non-empty, sorted array of
unique lowercase `owner/repo` strings, using the `owner` and `repo` types above.
No repository appears in two bindings. Resources sort by byte comparison and
bindings by (`service`, `agent`) in ascending byte order; JCS doesn't reorder them.

For a policy paired to a GitHub manifest, the two repository-to-agent maps must
agree after ASCII-lowercasing the manifest's repository names. A manifest with
keys that collide after lowercasing cannot be paired. Signing checks the canonical
document, its root id and version, the pairing and the binding projection before
committing a version. The minting service checks which version, binding and kind
permit a credential; the enforcer still checks the request match, ownership and
consent. A token is not bound to a single HTTP request.

### Policy administration

The master-key admin surface provides four operations with `v: 2`, except when
derive explicitly selects a rules release:

| Operation | Parameters besides `v` | Result |
|---|---|---|
| `admin.agent_policy_sign` | `policy_bytes` (canonical JSON text), `manifest_version`, `approver` | `{version, policy_sha256, envelope}` |
| `admin.agent_policy_list` | None | `{policies, head, active}` from one store snapshot |
| `admin.agent_policy_export` | `version` | Retained envelope for that version, or `not_found` |
| `admin.agent_policy_derive` | `manifest_version`, `identities`; `rules_release` (string, required for `v: 3`, omitted for `v: 2`) | Canonical policy text (unsigned) |

Only the operator's `ck auth github bindings` ceremony can remove or move a
repository or change an agent's App identity. It uses the same master-key admin
challenge and MAC, or the same offline lease, as manifest and policy signing:

| Operation (`v: 2`) | Parameters besides `v` | Result |
|---|---|---|
| `admin.github_binding_preview` | `change` | `{base, old, new}`; no writes |
| `admin.github_binding_commit` | `change`, `base` | `{change, manifest, policy}` |

`change` is one of `{action:"remove", repo}`, `{action:"move", repo, to}` or
`{action:"app", agent, slug}`. `repo` names `owner/name` (case-insensitive), `to`
and `agent` name agents with existing GitHub bindings, and `slug` names an active
`github_app:<slug>` record. Preview returns the full changed bindings in `old`
and `new` (arrays of policy bindings) and the exact signed base pair as
`base: {manifest_version, policy_version}`. An emptied binding is dropped.

The CLI shows the preview and sends the commit only after confirmation. The
commit recomputes the exact change under the store's writer transaction and
refuses `stale_base` if either base version changed. It signs and stores the
manifest and policy successors together with both ceremonies' approval, sign
and store audit rows and one `gh_binding_change` row. The result's `change`
is the committed preview. `manifest` and `policy` have the same result shapes
as their respective sign operations. Neither document nor any audit row from
the change is retained on refusal. The CLI writes both derived envelope files
only after commit.

These operations use `admin_refused` messages in `<code>/permanent: <why>` form:
`not_found` for a missing pair, repo or agent, `stale_base` for a concurrent
change, `policy_binding_conflict` for a no-op, duplicate App, cross-owner move
or unpaired newest manifest, `policy_identity_not_active_github_app` for an
unusable App record, and `policy_identity_agent_mismatch` for an App attested to
a different agent. The ordinary signing paths still require unchanged
bindings. One-tap approval can only add a repository.

Two master-key operations with `v: 1` manage the install's signing root:

| Operation | Parameters besides `v` | Result |
|---|---|---|
| `admin.policy_root_init` | None | `{credential_id, key_id, public_key_hex, fingerprint}` |
| `admin.policy_root_show` | None | Same public identity, without any write |

Init mints the first unused `signing:policy-root:<n>` (starting at 1 and skipping
both local and remote rows). It refuses `policy_root_exists` if the setting is
already present or `policy_root_established` if any signed manifest or policy
version exists. Show refuses `policy_root_absent` if there is no usable configured
root. These refusals have class `permanent`. The public key is 64 lowercase hex
characters. The key id is the first eight bytes of the SHA-256 of the raw public
key, in lowercase hex; the fingerprint is the first 16 bytes of the same digest
in eight space-separated groups of four lowercase hex characters.

The `signing:policy-root:` namespace and the legacy `signing:gh-manifest-root:1`
do not admit exact `Sign` grants, and `credential.sign` refuses them by handle
and by grant. Public-key reads still use `Read` authorization.
Incoming transfers to either root id shape refuse `policy_root_protected` at
delivery and acceptance. Store creation, replacement, invalidation and removal
refuse the same permanent code for the reserved namespace and for the legacy id
when it is the configured root.

These `admin_op` operations use the master-key challenge and MAC above. They
use `v: 1` and create an agent's GitHub App or manage its webhook relay:

| Operation | Parameters besides `v` | Result |
|---|---|---|
| `admin.github_app_manifest_prepare` | `agent` | `{name, default_permissions, default_events}` |
| `admin.github_app_relay_slot_open` | None | `{slot, webhook_url, expires_at}` |
| `admin.github_app_create_complete` | `code`, `agent`, optional `slot` | `{outcome: "created", slug, app_id, install_url}` or a result with a failure outcome (below) |
| `admin.github_app_relay_retry` | `slug` | `{slug}` |
| `admin.github_app_webhook_rotate` | `slug` | `{slug, repeated_put}` |

Prepare writes nothing. It refuses `agent_invalid` unless `agent` is `agent_`
followed by 16 lowercase hexadecimal digits, `github_app_agent_exists` if a
stored App already holds the agent, and `policy_unavailable` if the policy
read fails. It uses the [current default GitHub rules](#rule-sets-kinds-and-actions)
only when no active policy exists.

Slot open requires the serving daemon, which makes the relay request after
admin admission. It only confirms a `201` reply that supplies a valid slot,
the exact webhook URL for that slot, and an expiry. Its refusals use the
`admin_refused` message shape `<code>/<class>: <why>`:

| Code | Class | Condition |
|---|---|---|
| `relay_unavailable_for_account` | permanent | No machine key, or the relay returns `401`, `403` or `404` |
| `relay_slot_limit` | permanent | The relay returns `409` |
| `relay_unavailable` | transient | Token mint, transport, deadline, redirect, `429` or server failure |
| `relay_request_refused` | permanent | Other client errors |
| `relay_reply_invalid` | permanent | Unexpected success status or invalid slot reply |
| `audit_write_failed` | permanent | The relay opened a slot but recording the audit row failed; the unused slot expires |

Create complete requires the serving daemon. It validates the agent and optional
relay slot and checks that the agent has no App before POSTing the manifest code
to GitHub's conversion endpoint. The code is 1–128 ASCII letters, digits,
underscores or hyphens. A conversion reply over 64 KiB is not accepted. The reply
must contain a positive integer `id`, a valid App `slug`, a usable RSA App PEM,
and a non-empty `client_id`. A non-empty `webhook_secret` is required if a slot
was supplied; otherwise it is ignored. No private material or manifest code is
returned. `app_id` is a canonical decimal string.

The following failures return `admin_refused`:

| Code | Class | Condition |
|---|---|---|
| `agent_invalid` | permanent | Agent id is not in registry form |
| `invalid_params` | permanent | Malformed code or relay slot; reported inside the `admin_refused` transport Error |
| `github_app_agent_exists` | permanent | An App already holds the agent before conversion |
| `relay_unavailable` | transient | The precheck could not finish; no conversion was attempted |
| `github_app_code_invalid` | permanent | GitHub returned a client error other than a rate limit |
| `github_app_conversion_unknown` | permanent | GitHub conversion was not confirmed, including `429` and `403` with `Retry-After` or `X-RateLimit-Remaining: 0`. Check GitHub before deleting the App. Do not reuse the code. |

After a success HTTP status from GitHub, a failure returns a normal response
frame so the caller can distinguish whether the App was saved:

| Outcome | Fields besides `outcome` | `cause` |
|---|---|---|
| `github_app_unsaved` | `cause`, optional validated `slug` and `app_id` | `reply_invalid`, `busy` (App lock deadline), `github_app_exists` (App or companion id already exists locally or remotely), `github_app_agent_exists` (agent already claimed at commit), or `store_failed` |
| `relay_registration_failed` | `slug`, `app_id`, `install_url`, `cause` | `relay_unavailable` (mint, deadline, transport, redirect, `429` or server failure), `relay_unavailable_for_account` (missing machine key, `401` or `403`), `relay_slot_expired` (`404`), `relay_app_mismatch` (`409`), `relay_request_refused` (other client error), or `relay_reply_invalid` (unexpected or oversized success reply) |

Once GitHub returns the key, a daemon that acquires the App lock finishes the
store write even if the App lock's deadline passes. With a slot, it keeps the lock through the
initial relay `PUT`. Only a `200` reply within the 8 KiB reply limit confirms
registration. A failed `PUT` does not roll back the App. Only the cause
`relay_unavailable` offers a same-slot retry.

The webhook secret is held only by the vault, in `opaque:github-app-webhook:<slug>`.
Scoped reads, signing, handle use and attempts to grant access to that id resolve
as `not_found`. Operator operations on the companion and incoming transfers to
that id refuse `github_app_companion_protected` (permanent). Invalidating the
App preserves its attestation and agent claim. Replacing it clears the App's
attestation and slot; removing it also frees the slug. Either write deletes the
companion in the same transaction if the outgoing App was attested and had a
relay slot. A hand-added App has no managed companion to delete.

Retry and rotation require the serving daemon. They check the App's state and
run under the `github_app:<slug>` lock, using the App id and slot recorded at
creation. An invalid slug refuses `invalid_params`; a missing row refuses
`not_found`; an inactive row refuses `github_app_inactive`; an App without a
vault attestation or slot refuses `github_app_no_relay`. Retry refuses
`github_app_rotation_pending` when a rotation is in progress. These permanent
refusals make no outbound call.

Retry repeats only the same-slot `PUT` with the current secret. Retry and
rotation use the relay `PUT` refusals listed under `relay_registration_failed`
as `<code>/<class>: <why>` messages in `admin_refused` errors. Only
`relay_unavailable` is transient. If a confirmed retry cannot be audited it
refuses `audit_write_failed` (permanent); a rerun sends the same `PUT`.

Rotation first stores a candidate, confirms it with the relay (only a `200`
`PUT` confirms), then updates GitHub's hook config with an App JWT. The GitHub
`PATCH` response must have a success status and be no larger than 8 KiB. Only
then does the candidate become current. A confirmation write, GitHub update,
or final store failure returns `github_app_hook_update_failed` (transient). A
rerun resumes the same candidate, skipping `PUT` if its confirmation was
already saved. The boolean `repeated_put` is true when this run re-sent a
pending secret that an earlier run may already have sent. Each committed
rotation step records a keyed digest in its audit row. Relay-token mints do not
write an `account_token` audit row.

Sign and derive require the newest manifest to have no paired policy. Sign requires
the next policy version and, if a policy is stored, the same bindings as the head,
including identities. Derive copies the head policy's rules if one exists;
otherwise it uses the [current embedded GitHub rule set](#rule-sets-kinds-and-actions)
(revision 2). To override that choice, `ck auth policy derive --rules-release <release>`
requests a named embedded release. The returned rule set contains all rules from
that release and cites its name and SHA-256 in `source`. Derive still requires its
`identities` object to map exactly the manifest's agents to distinct active GitHub
App credentials, and preserves the head's bindings and identities when a head exists.

Derive uses `v: 2` without `rules_release` and requires `v: 3` with it. The vault
refuses either version with the wrong shape. Older daemons refuse derive `v: 3`
as an unsupported version; use matching `ck auth` and daemon builds to select a
release. An unknown release returns `rules_release_unknown` (`permanent`) and
lists the known release names.

Sign and derive refuse `policy_identity_agent_mismatch` (permanent) when a
binding names a vault-created App attested for a different agent.
After the first policy, manifest import is refused and manifest ceremony signing
must keep the head policy's repository-to-agent map.

List orders rows by ascending `version`. Each row contains `version`,
`policy_sha256`, `key_id`, `signed_at_ms`, `source`, `approval_seq` and
`manifest_version` only. `head` and `active` are version numbers or `null`.
The active version is the newest policy whose manifest is ready. List, export and
derive never write a policy or an audit row.

## 18. Fleet epoch operations

These ten management operations use the attested caller identity, never a caller
name from parameters or a credential grant:

| Caller | Admitted operations |
|---|---|
| `reserved:entorhinal` | All ten operations below |
| `reserved:prefrontal` | `fleet.epoch_seal`, `fleet.epoch_open`, `fleet.epoch_seal_batch`, `fleet.epoch_open_batch` only |
| `reserved:magic-context` | `fleet.epoch_seal`, `fleet.epoch_open`, `fleet.epoch_seal_batch`, `fleet.epoch_open_batch` only |
| Every other caller, including `reserved:prefrontal-core` | None |

An unadmitted caller receives exactly
`{"error":{"code":"not_found","class":"permanent"}}`, even for malformed
parameters. Admission is method-specific and precedes parameter decoding.
The four seal/open operations and `fleet.epoch_status` are queries; the other
five operations mutate state. Epoch secrets never leave the vault in plaintext.
Self below means the vault's local fleet-member identity.

All objects below reject unknown fields. Epochs are JSON integers in
`1..=4294967295`. Bytes are canonical unpadded base64url. `mint_id` is exactly 16
bytes (22 characters). Member ids are `fed-computer:<32 lowercase hex>`.
Malformed values and decoded byte-cap overflows use the existing `invalid_params`
error frame, not the domain-refusal body. Member-count overflow uses the domain
refusal stated below, not `invalid_params`.

| Operation | Parameters | Successful body |
|---|---|---|
| `fleet.epoch_seal` | `{aad, plaintext}` | `{epoch, nonce, ciphertext}` |
| `fleet.epoch_open` | `{epoch, nonce, ciphertext, aad}` | `{plaintext}` |
| `fleet.epoch_seal_batch` | `{items:[{aad, plaintext},...]}` | `{items:[{epoch, nonce, ciphertext},...]}` |
| `fleet.epoch_open_batch` | `{items:[{epoch, nonce, ciphertext, aad},...]}` | `{items:[{plaintext}\|{error:{code,class}},...]}` |
| `fleet.epoch_status` | `{}` | `{current, held, pending, sealing_blocked_by}` |
| `fleet.epoch_mint` | `{members:[member_id,...], excluded?:[member_id,...]}` | `{epoch, mint_id, wraps:[{member_id, wrap},...]}` |
| `fleet.epoch_commit` | `{epoch, mint_id}` | `{epoch, state:"current"}` |
| `fleet.epoch_discard` | `{epoch, mint_id}` | `{epoch, state:"discarded"}` |
| `fleet.epoch_import` | `{wrap}` | `{epochs:[epoch,...], already_held}` |
| `fleet.epoch_wrap_for` | `{member_id}` | `{wrap}` |

`seal` uses XChaCha20-Poly1305 under the current epoch with a random 24-byte nonce.
`aad` is required but may be empty; it and `plaintext` each decode to at most 1 MiB.
AEAD associated data is RFC 8785 JSON
`{"aad":<caller aad base64url>,"epoch":e,"v":<caller domain>}`. The vault
chooses the domain solely from the attested caller:

| Caller | Domain (`v`) |
|---|---|
| `reserved:entorhinal` | `ck-fleet-epoch-aad/v1` (unchanged bytes) |
| `reserved:prefrontal` | `ck-fleet-epoch-aad/prefrontal/v1` |
| `reserved:magic-context` | `ck-fleet-epoch-aad/magic-context/v1` |

There is no domain parameter. Under the same epoch key, nonce, ciphertext and
caller aad, opening in a different caller's domain refuses `fleet_epoch_open_failed`.
`open` accepts any held epoch (current or retired), a 24-byte nonce, ciphertext
of 16 through 1 MiB + 16 bytes, and at most 1 MiB of aad. If the vault has no row
for the requested epoch or holds it only as pending, opening refuses
`fleet_epoch_unavailable` (transient). For a held epoch, a bad tag, wrong aad or
different caller's domain refuses `fleet_epoch_open_failed` (permanent).
Pending epochs are never used to seal, open or export history.

Both batch operations require 1 through 256 items. Each item obeys the single
operation's closed grammar and decoded field caps. In addition, the sum of decoded
aad plus plaintext bytes (seal batch), or aad plus ciphertext bytes (open batch,
including authentication tags but excluding nonces), must be at most 8 MiB.
Any malformed item, unknown field or limit violation refuses the whole call with
the existing `invalid_params` error frame before any store access. Results preserve
input order. The same caller-domain rule applies to every item in a batch.

`seal_batch` uses one store read and the same usable current epoch for every item,
with a separate fresh random 24-byte nonce per item. A missing usable epoch, pending
removal or store failure refuses the whole call with the same body as single seal;
no items are returned. `open_batch` returns a plaintext or the single open's exact
error code and class for each item. If the vault has no epoch rows at all, each
item returns `fleet_epoch_unavailable`. An unset self member ID still refuses the
whole call with `fleet_epoch_unavailable`. A failed store read or a store error
after processing has begun also refuses the whole call, never a partial list.
Single and batch seal/open write no audit rows.

`status` returns `current: int|null`, ascending `held` including current,
`pending: {epoch,mint_id}|null`, and ascending unique `sealing_blocked_by` member
ids (empty when current is null). A lost mint response is recovered by reading
status after restart, discarding its pending mint, then minting again.

`mint` defines the live set as Self plus every currently paired fleet peer,
minus permanently removed members. `excluded` is optional and defaults to an
empty array. Each exclusion must be a live peer other than Self. `members` must
contain Self and equal the live set minus `excluded`. Duplicate or malformed ids
in either list are `invalid_params`; an ineligible exclusion or an unequal member
set refuses `fleet_members_mismatch`.

The new pending epoch is one above the highest held epoch, or 1. It returns a
rotation wrap for each member other than Self. Excluded peers receive no wrap
and do not appear in the stored or wrapped holder lists. Once the epoch is
committed, an excluded peer can receive it via `wrap_for` under the normal join
rules. An existing pending epoch refuses `fleet_epoch_pending`. The vault
refuses `fleet_epoch_capacity` for more than 64 exclusions (before peer lookup),
more than 64 live or supplied members, or 256 held epochs. The live-member cap
applies before exclusions are subtracted.

`commit` matches both epoch and mint id. It makes that pending row current and
retires the previous current, but refuses `fleet_members_mismatch` if its holders
lack the current Self or contain a removed member. An already committed matching
mint remains an idempotent success, including after retirement. `discard` deletes
only a matching pending row and records its mint id and epoch; an exact repeat
is an idempotent success. Other commit/discard mismatches refuse
`fleet_epoch_not_pending`. Delayed retries cannot act on a later mint of the same
number.

`wrap_for` exports every held epoch in a join wrap to a currently paired fleet
peer other than Self, not removed; an invalid recipient refuses
`fleet_members_mismatch`. It adds the recipient to each exported holder set and
always writes one audit row, including retries. Holder sets never shrink. Adding
a 65th holder to any retained epoch refuses `fleet_epoch_capacity` without writes.

A wrap is exactly
`{"ct":<base64url>,"enc":<base64url>,"from":<member_id>,"to":<member_id>,"v":"ck-fleet-epoch-wrap/v1"}`.
`enc` is 32 bytes; `ct` is at most 1 MiB + 16 bytes. HPKE auth mode uses
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, empty HPKE aad,
and RFC 8785 info `{"from":..,"to":..,"v":"ck-fleet-epoch-wrap/v1"}`. Only the
paired sender's vault-held wrap key authenticates it. The canonical plaintext,
at most 1 MiB, is
`{"keys":[{"epoch":k,"key":<32 bytes base64url>,"members":[ids],"minter":<id>},...],"kind":"rotation"|"join","v":"ck-fleet-epoch-wrap/v1"}`.
It has 1–256 strictly increasing epochs and 1–64 sorted unique holders per key.
A rotation has one key, with minter equal to from and named among the holders.
A join carries all sender-held epochs with their stored holders plus to.

`import` refuses `fleet_epoch_pending` while a local mint is pending. Otherwise
all failed wrap conditions are the uniform `fleet_wrap_refused`: the recipient
must be Self; the authenticated sender must be a nonremoved fleet peer; all keys
must name Self; the highest key must name no removed member; rotation must be
newer than every held epoch or already held byte-identically; any already-held
join key must be byte-identical; and the resulting store must fit 256 held epochs
and 64 holders per key. Stored holders union with carried holders. Historical
join keys may name removed members. Newly stored epochs are returned ascending;
`already_held` is true exactly when no epoch is new. The highest imported epoch
becomes current only when newer than every held epoch. An import with no new key
or holder writes nothing; ciphertext randomization does not change key identity.

Every operation except status refuses `fleet_epoch_unavailable` while Self is
unset. Seal and wrap-for also refuse it without a current epoch, while its
holders lack Self, or while any current holder is removed. Opening history is
unaffected by removals or a changed Self. Self may change without rewriting
holder sets: recover by discarding a stale pending mint, then mint and commit for
the new Self. Retired history is exported with its stored holders plus recipient,
not with Self silently added.

Removal follows account tombstones on the existing Callosum
`paired_devices_watch`, never local unpair. Tombstones are optional for older
Callosum versions; when present they contain unique lowercase fingerprints and
nonempty opaque removal ids. Invalid snapshots record nothing. New
`(member_id, removal_id)` observations are durable and audited; replays write
nothing, and later absence never deletes a removal. A holder not yet aware of a
join can keep sealing until it imports the enlarged holder set or learns a
relevant removal. A computer exporting before observing a tombstone can export
the then-held keys. With no history-dropping operation, 256 retained epochs
prevent rotation and a retained 64-holder epoch prevents further joins.

Domain refusals are bodies `{"error":{"code":code,"class":class}}`:

| Class | Codes |
|---|---|
| `transient` | `fleet_epoch_unavailable`, `fleet_epoch_pending`, `fleet_peer_keys_unavailable`, `store_error` |
| `permanent` | `not_found`, `fleet_members_mismatch`, `fleet_epoch_not_pending`, `fleet_epoch_open_failed`, `fleet_wrap_refused`, `fleet_epoch_capacity`, `corrupt` |

A refused, malformed or duplicate-fingerprint peer read refuses
`fleet_peer_keys_unavailable` and writes nothing. Only computer entries with a
valid, non-low-order 32-byte lowercase-hex `fleet_epoch_wrap_x25519.pub` supply a
fleet peer. `corrupt` means a stored epoch envelope will not open. No error
contains epoch keys, wraps or plaintext.

At startup the vault creates missing `signing:fleet-record:1`,
`kem:fleet-epoch-wrap:1` and `kem:bus-seal:1`, each with one `fleet_key_create`
audit row; existing keys are never replaced. Private halves are never returned
by get. Fleet wrap-key public reads and held-version status/watch announcements
are restricted to `reserved:callosum`. Fleet record-key public reads admit
Callosum and Entorhinal; held-version announcements admit only Callosum, and
signing admits only Entorhinal. Other accesses, including handles, are
`not_found`. Operator grants are required: wrap-key read to Callosum; record-key
read to Callosum and Entorhinal and sign to Entorhinal. Other grants refuse
`fleet_key_reserved`.

For every `kem:bus-seal:<n>` key, the only admitted operator grants are exact
`read` to `reserved:callosum` (public-key and held-version announcements) and
exact `open` to `reserved:ckbus` and `reserved:engram` (caller-specific domains
in §10). Other grants and handle minting refuse `fleet_key_reserved`. At runtime,
bearer handles and category grants do not authorize access, and unauthorized
calls receive `not_found`. Rotations use new numbered keys alongside existing ones.

## 19. Module-owned secrets (`module_secret.*`)

Each daemon-attested module has a private space, separate from credentials. Admission
runs before caller routing and parameter decoding. Only a route-bound
`Principal::Reserved` with a present caller attestation whose claim is `own`, a module
id matching `^[a-z0-9][a-z0-9._-]{0,63}$`, and no bearer parameter is admitted. The
attestation's `first_party` mark is not required. Relay, missing-attestation, direct,
enrolled, handle, member, phone and refused callers all receive the same `not_found`
body, even with malformed parameters. The owner comes only from the route, never a
parameter. No grant can expose another module's items.

All four operations use closed parameter objects. A name matches
`^[a-z0-9][a-z0-9._-]{0,63}$`. Values use canonical standard base64 with padding, no
whitespace and canonical trailing bits, and decode to 1–65,536 bytes. An
`expected_version`, when present, is an integer of at least 1. Unknown fields, wrong
types, bad names, invalid base64 and out-of-range values return
`invalid_params`/`permanent` before any store access or write.

| method | params | success body |
|---|---|---|
| `module_secret.put` | `{name, value, expected_version?, protected?}` | `{name, version, created}` |
| `module_secret.get` | `{name}` | `{name, version, value, protected}` |
| `module_secret.delete` | `{name, expected_version?}` | `{deleted: true}` |
| `module_secret.list` | `{}` | `{items: [{name, version, protected, state, updated_at_ms}]}` |

These bodies appear inside `result`. Get and list are Query operations; put and delete
are Mutate operations. Lists are sorted by name and contain no values; state is
`active` or `corrupt`. A module can hold at most 64 items. Creates start at version 1;
replacement increments the version and restores state to `active`.

Put checks an existing item's protection first, then an expected-version mismatch,
then refuses `protected: true` with `invalid_params` (protection is create-only).
Otherwise it replaces the item without changing protection. For an absent item,
expected-version presence refuses before the item-count limit is checked. Delete
checks absence, protection, then expected-version mismatch, in that order. Refused
writes change neither items nor audit rows. Successful writes and their audit row
commit atomically.

Get returns `corrupt` for an already quarantined row without opening it. Key mismatch
returns `vault_locked` without a write. Other open failures quarantine only the exact
observed active row and return `corrupt`; failed quarantine returns `store_error`.

### Module-secret refusals

Every refusal is a `Response` with `result.error.{code, class}`, never a classless
transport `Error`. The fixture `module_secret_wire_contract.json` is generated from
the daemon code and pins every success body and refusal. The refusal table is checked
against `ModuleSecretError` in both directions.

| code | class | meaning |
|---|---|---|
| `invalid_params` | `permanent` | Closed-object decoding or input validation failed; also an attempt to protect an existing item. |
| `not_found` | `permanent` | Caller not admitted, or the caller's item is absent. |
| `module_secret_protected` | `permanent` | A protected item cannot be replaced or deleted by its module. |
| `module_secret_version_conflict` | `permanent` | Compare-and-replace/delete did not match, or compare-and-replace named an absent item. |
| `module_secret_limit` | `permanent` | Creating another item would exceed 64 items. |
| `corrupt` | `permanent` | The stored item is quarantined or failed to open. |
| `vault_locked` | `transient` | The master key cannot be resolved or does not match the envelope. |
| `store_error` | `transient` | A store transaction, audit append or quarantine failed. |

## Development desktop approvals

Development only; remove this unsigned approval path before the next public
release. It exists so the development desktop can approve the same pending agent,
flow and bot-repository manifest cards as the phone, without desktop keys or a
daemon stamp identifying a signed desktop app. It is not a production approval
authority.

The persisted `secret.dev_desktop_approvals` switch defaults to off. The operator
changes it through `ck auth secret dev-desktop-approvals on|off|status`; writes use
`admin.secret_dev_desktop_approvals_set` with `{v:2, enabled:true|false}` on the
existing authenticated admin path. Changes are audited as
`secret_dev_desktop_approvals_set`; repeating the current value writes nothing.

With the switch on, `secret.approve` and `manifest.approve` also accept
`{envelope_b64url, card_ref?}` on an unscoped `direct` route admitted by
`unsigned_desktop_development_admission`. A forwarded federation route, whose
harness label starts with `fed-`, is never admitted.
There is no signature field: `signature_b64url`, even empty, is `invalid_params`.
`card_ref` has the same optional display-reference grammar as phone secret
approvals; it is not used for manifest approvals.

Decode `envelope_b64url` to the exact canonical phone envelope bytes:
`ck-secret-use-envelope/v1` for agent and flow requests, or
`ck-manifest-binding-envelope/v1` for a manifest proposal. Set
`device_fingerprint` to `00000000000000000000000000000000` (32 zeros). The vault
uses the existing approval transactions and all their canonical-form, statement
hash, item, duration, issue-time, expiry and request/proposal-state checks, skipping
only signature verification. Responses and stored grant columns are the phone's;
approval audit rows name `desktop-development` rather than a phone. Each admitted
request emits one INFO line with fixed development-admission text and no ids or
envelope data. Disabling the switch does not revoke already-issued grants.

The switch off, a scoped route, a `reserved:*` caller, a `fed-` harness or any
other non-admitted caller receives the uniform `not_found` before any write or
parameter diagnosis. On an admitted route, a wrong fingerprint is
`approval_invalid`; other envelope and proposal refusals retain the phone's
existing error precedence. The phone's pairing, production-build and signature
requirements are unchanged, even while this switch is on.

Vault-generated request/reply samples, including refusals, are in
`crates/credentials-core/tests/vectors/desktop-dev-approval-vectors-v1/`.
