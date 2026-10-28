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

Every read-surface error body carries `class` alongside `code`, nested under
`result.error`. **Branch on `class`, never on `code`** — codes are added as new
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
| `kind_not_openable` | permanent | authorized `credential.open` on a record that is not a `KemKey` |
| `open_failed` | permanent | KEM payload or HPKE opening failed; all crypto faults have the same reply |
| `open_rate_limited` | transient | this connection has reached the scoped-open refusal threshold |
| `malformed_encoding` | permanent | a `credential.sign` payload or a `credential.open` or `credential.seal` byte field failed strict standard base64 decoding |
| `invalid_recipient_key` | permanent | a `credential.seal` recipient key is not 32 bytes, or is a low-order X25519 point |
| `seal_rate_limited` | transient | this connection has reached the scoped refusal threshold `credential.open` and `credential.seal` share |
| `corrupt` | permanent | the record failed to decrypt or parse and has been quarantined |
| `refresh_unsupported` | permanent | a refresh was demanded of a record with no refresh adapter |
| `needs_reauth` | auth_required | the credential is latched dead, or deliberately retired |
| `refresh_failed` | transient | the provider refused or the exchange failed |
| `vault_locked` | transient | the master key could not be resolved |
| `store_error` | transient | `credential.list_scoped` could not read one complete snapshot |
| `invalid_category_name` | permanent | a category is outside `^[a-z][a-z0-9-]{1,31}$` |
| `invalid_provider_id` | permanent | provider metadata fails `charset`, `length`, `duplicate`, or resulting-set `count`; text is `invalid_provider_id/permanent: rule=<rule> value=<value>` |
| `invalid_credential_id` | permanent | an id begins with reserved `category:` or contains `|` |
| `invalid_principal` | permanent | a grant principal is not `reserved` or contains `|` |
| `invalid_plan_tier` | permanent | a plan tier set with `ck auth set-plan` is outside `^[a-z][a-z0-9_]{0,31}$` |
| `report_status_not_credential_death` | permanent | `report_auth_failure` carried a `provider_status` outside {401, 403} |
| `too_many_items` | context_overflow | a batch exceeded the per-request cap |
| `sign_payload_too_large` | context_overflow | a sign payload or the combined `credential.open` fields exceeded 1 MiB (`MAX_SIGN_PAYLOAD`) |
| `seal_input_too_large` | context_overflow | a `credential.seal` plaintext over 64 KiB, or info or aad over 1 KiB |
| `ttl_unsatisfiable` | context_overflow | a freshly minted token still cannot satisfy your `min_ttl_ms` |

**Codes from the admin write path, not the read surface:** `invalid_category_name`,
`invalid_provider_id`, `invalid_credential_id`, `invalid_principal` and `invalid_plan_tier` are store-taxonomy
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
| the credential answered no | `Response` | `result.error.{code, class}` | yes |
| the request never got that far | `Error` | `{code, message}` | **no** |

The second shape is the transport refusal: a malformed frame, an unknown operation, or
params that failed to decode (`invalid_params`). It is emitted by `send_route_error` in
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
state, do not mark anything `needs_reauth`, and do not delete client state on it. Treat
an unrecognised `Error` code as retryable, because the alternative is letting a
transport condition masquerade as a permanent verdict about a credential that is fine.

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
  `module_timeout` instead, and those stay retryable.

`admin_refused` is also sent on this lane, but only by the admin operations, never by a
credential read. Treat every other `Error` code as retryable, as above; connection loss
and route churn (`route_closed`, `unknown_channel`, `stale_route_epoch`) are the common
ones.

The TypeScript client (`@cortexkit/claustrum-client` 0.13.0 and later) reports the
definitive codes, plus its own pre-send `missing_identity`, as
`ClaustrumCredentialError(code, 'permanent', 'gone')` and never reconnects for them;
every other transport failure stays `transient`/`retry`. The Rust client returns them
unclassified and not retryable (`unknown_module` excepted, which it treats as a
transport failure and redials).

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
It is NOT ambient on a connection: a supervised module's calls to
another module's route surface carry `Principal::Reserved { module_id }` only when its
`route.open` presents the `consumer_identity` (`SUBC_MODULE_ID`, `SUBC_LAUNCH_NONCE`) that
the daemon injected at spawn; the daemon verifies the nonce against the live supervisor and
stamps the principal into the `route.bind` it relays here. A `route.open` WITHOUT it is
`Direct` regardless of who sent it, and a mismatched nonce is refused
`bad_consumer_identity` rather than downgraded. The auth handshake proves connection-file
access and carries no identity at all.

`subc-client-rs` attaches the pair for you (`ConnectOptions.consumer_identity` reads both
variables when non-empty). A HAND-ROLLED CLIENT MUST SEND IT, and that is the entire
difference between a scoped call that works and one that answers `not_found`: a consumer
dialling over a raw socket plus `authenticate_client` arrives `Direct` and every scoped op
refuses it correctly.

One precondition that bites silently: the nonce lives only in the environment of the
process the daemon SPAWNED. A child process, a pool that scrubbed the environment, or
anything after an `env_clear` has lost it, and the open arrives `Direct` with nothing said.
That is deliberate — the nonce is kept out of grandchildren so a module cannot lend
`Reserved` to a helper it spawned.

A host-launched plugin has no nonce and can never have one; it uses an enrollment token.

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
reach. Present it in the params (`enrollment_token`) on `credential.get_scoped` and
`credential.list_scoped`; see § 2.1.

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
| `read` | `get_scoped` (the token), scoped `status`, `public_key`, `report_auth_failure`; identity in `list_scoped` | `sign`, `open` |
| `sign` | `credential.sign` with a signing key; the row (without identity) in `list_scoped` | the token, `public_key`, `open` |
| `open` | `credential.open` with a KEM key; the row (without identity) in `list_scoped` | the token, `sign` |
| `list` | the row in `list_scoped` WITH its identity (`account_id`, `email`, `org_name`) and `refresh_adapter` | every other operation: no token, no status, no key use, no report |
| `seal` | `credential.seal` with a KEM key; the row (without identity) in `list_scoped`. **Exact selector only** | the token, `public_key`, `sign`, `open` |

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
| `credential.sign` | yes | yes (`sign`) | — |
| `credential.open` | — | yes (`open`) | yes |
| `credential.seal` | — | yes (`seal`) | yes |
| `credential.public_key` | yes | yes (`read`) | — |
| `credential.status` | yes | yes (`read`) | — |
| `credential.report_auth_failure` | yes | yes (`read`) | — |

A request carries exactly one address. `credential.status` with both a handle and a
`credential_id` is refused as `invalid_params`
(`tests::scoped_status_rejects_both_addressing_forms_as_invalid_params`). A report carrying
both addresses or neither is refused as a malformed request
(`tests::a_report_supplying_both_addresses_or_neither_is_refused`).
`credential.status` with neither address is the overall vault-health probe.

Signing keys minted with `ck auth mint-signing-key --audit-each-signature` opt
into a permanent per-signature history. After key and payload validation, but
before signing, the vault commits one HMAC-chained row with `audit_log.op = sign`,
the credential id, the SHA-256 of the exact decoded payload, and the resolved
`reserved:<module>` or `enrolled:<name>` actor. Anonymous handle holders use the
existing `conn-N` channel attribution. Payload bytes are never recorded. A failed
audit write (including a lost writer fence) returns `store_error` / `transient`
and no signature; refused payloads write no signature row. Keys without this
sealed flag (including existing keys) retain the no-write signing path.

The public key id is derived from the signing key and returned with the signature,
not stored in an extra audit column. A sign row belongs to the key generation
installed by the most recent `put`/`overwrite` row for that credential id; the
chain orders signatures around replacements. Normal rotation uses a new id.
Older record decoders ignore the additive flag; rollback reads remain compatible,
but older binaries do not enforce this policy and drop it when rewriting a record.

### 2.1 Enrollment, for a consumer with no supervised identity

The ceremony is `auth.enroll_propose` → operator approval → `auth.enroll_poll`, with
`auth.enroll_rotate` for later rotation.

1. **Propose.** You mint a 32-byte request secret, send only its hash, and receive a
   request id. **Persist both before you send**, so a crash between the call and its reply
   does not leave you unable to poll a request that exists.
2. **Wait.** An operator approves with the master key (`ck auth enroll approve`).
   Approval admits a NAME and mints nothing — which is what stops a squatter who proposed
   a name it does not hold from collecting a token even if approval is granted by mistake.
3. **Poll.** The first successful poll, authenticated by your request secret, mints the
   token. Only `pending` means keep polling; every other outcome is terminal.
4. **Persist at `0600`** with a parent directory that is not group- or world-writable.

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

The § 1a rule holds here too: an `Error` frame from an enrollment op means the request
never reached the module (for example params that failed to decode) and is never an
enrollment verdict. Do not treat it as `not_found`, `superseded` or any other refusal.

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

## 3. Reading a credential

`credential.get` returns the opaque payload as a JSON array of byte integers, plus
`expires_at_ms` and `record_version`, plus non-secret metadata where the vault has it
(`credential_id`, `account_id`, `email`, `org_name`, and `project_id` for `antigravity`).
Use `credential_id` only to verify a handle-to-manifest binding, never to route: it is an
operator-chosen label. Account routing pools on `account_id` (with the refresh adapter from
`list_scoped`), never on `record_version`: that bumps on every token refresh, so a key that
includes it splits one account into a new pool per refresh.

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

- `force_refresh: true` — exchange before serving, unconditionally.
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

`credential.list_scoped` takes exactly `params: {}` and returns
`{ credentials, grants, grant_tuples, view }`. Unknown fields, including filters and
`token`, are `invalid_params`. Rows are sorted by id. `categories`, lifecycle `state`,
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

### Provider metadata, plan tier and authentication method

Every `credential.list_scoped` row has `provider_ids`, an array of operator-assigned
Fusiform catalog provider ids in ascending byte order, including `[]` when unset.
The vault never derives them from the credential id, catalog, adapter, or `serves`.
Consumers join on exact provider-id equality, with no fallback. `serves` answers which
model vendors are reachable; `provider_ids` answers which catalog providers the operator
assigned to this credential. They are not interchangeable.

`auth_method` is derived only from the unsealed record's `(CredentialKind, refresh_adapter)`.
It is present only on read/list-covered rows when the table below yields a value; otherwise
the key is omitted, never null or `""`. Sign/open-only rows remain sealed and omit it,
including rows with corrupt envelopes; their stored `provider_ids` are still returned.
A read/list row already quarantined as `state: "corrupt"` is listed the same way, sealed
and without identity, so one quarantined credential never hides the rest of the listing.
An unseal/decode failure on a read/list row still stored as readable fails the whole
snapshot with `store_error`: that is corruption the vault hasn't recorded yet.

The closed values are `apikey`, `chatgpt`, `antigravity`, and `oauth`. Adding a value is a
breaking wire change and requires a breaking client bump (minor while the client is 0.x).
Unlike the id-derived `type`, this field never parses the id and does not rewrite `type`
or `refresh_adapter`. Both `chatgpt:openai` and `oauth:openai` store adapter `openai` and
report `chatgpt`; antigravity still has `type: "oauth"`.

| Credential kind | Stored refresh adapter | `auth_method` |
|---|---|---|
| `ApiKey` | absent or any string | `apikey` |
| `Oauth` | `anthropic` | `oauth` |
| `Oauth` | `openai` | `chatgpt` |
| `Oauth` | `google` | `oauth` |
| `Oauth` | `gmail` (login id `oauth:gmail[:<label>]`) | omitted |
| `Oauth` | `xai` | `oauth` |
| `Oauth` | `kimi` | `oauth` |
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
optional strings. The absent optional
frame is used whenever the JSON key is omitted, never an empty string. Deployment leaves
an empty inventory's view unchanged but changes every nonempty visible inventory's view
once, even if all provider-id arrays are empty and all methods omitted. Subsequent edits
move only views whose returned rows include that credential.

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
`duplicate` (naming the second occurrence), then credential existence, then resulting-set
`count`. Ids must start with a lowercase ASCII letter and contain only lowercase ASCII
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
five-second-bounded profile request in the background. Its result is held in memory,
bound to the credential's version, token, and identity, and folded into the **next**
refresh commit, never an extra write/version bump. A restart loses held observations.

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
The scoped `view` frames the optional tier then optional source after `auth_method`.
Both omitted values contribute absence bytes; switching source changes the view even
when the effective tier stays equal. Deployment changes nonempty views once; empty
inventory views remain unchanged.

Replacement deposits (`put --replace`, CAS replace, native re-login, import replace,
OpenCode migration/picker replacement, and cookie replacement) compare the stored and
resulting normalized `account_id`; `set-identity` also compares those identities. A different account clears the old override and
old detected observation; a fresh observation from the incoming login can be retained.
The override clear is audited in the same transaction as replacement. Equal account ids, including two
absent ids, keep it; a retained identity is compared after preservation. If the previous
envelope cannot be decoded, repair clears any tier because account equality cannot be
established. Refresh never changes account identity and does not touch the assertion.
Removing a credential removes its tier, even without foreign-key enforcement.

### `admin.set_plan`

Gate 2, the operator master-key transcript HMAC, authorizes this v2 admin operation.
Modules and enrolled consumers cannot write tiers. Set and clear request bodies:

```json
{"op":"admin.set_plan","v":2,"credential_id":"oauth:anthropic","plan_tier":"max_20x"}
{"op":"admin.set_plan","v":2,"credential_id":"oauth:anthropic","plan_tier":null}
```

Success returns `{"plan_tier":"max_20x"}` or `{"plan_tier":null}`, also for an unchanged
assertion. Clearing removes **only the operator override**; a detected tier becomes
effective again. A tier must match `[a-z][a-z0-9_]{0,31}`: lowercase ASCII, 1–32 characters,
starting with a letter. Syntax is checked before credential lookup. Bad syntax refuses
with permanent `invalid_plan_tier`; an unknown credential refuses with `credential not
found`, including a clear. Refusals change neither metadata nor audit.

Only actual old-to-new transitions write an HMAC audit row with op `set_plan` and target
`plan:<credential-id>|<old-tier>|<new-tier>`. An absent old or new tier is the empty field;
parse by splitting off the **last two** `|` delimiters. Automatic account-change clears
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
a `sign` audit row containing only the payload SHA-256 (never payload bytes), with
actor `route-admin` online or `offline-cli` offline. The append checks the key's
record version inside its transaction. Audit failure returns an error and no
signature; signing happens only after the append succeeds, regardless of the
record's separate `audit_each_signature` value.

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

### Category and grant audit targets

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
`record_version`.

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
                           ->  the restart heals in one call
```

The vault's diagnostics cannot tell you which happened. Every refusal on the scoped-read
path writes to `auth_events`, so an empty table proves no scoped read reached a refusal
point. It does not prove the call was served: a frame dropped at the epoch check never
reaches the read surface. Empty means arrived-and-succeeded or never-arrived, and only the
consumer's side can distinguish them.

---

## 10. `credential.open`

`credential.open` accepts `{credential_id, enc_b64, ciphertext_b64, info_b64, aad_b64, enrollment_token?}` with no extra fields (including `handle`). All byte fields use `base64::engine::general_purpose::STANDARD`, the same strict, padded standard-alphabet decoder as `credential.sign`. The reply is `{result:{plaintext_b64,key_id}}`; `key_id` equals the same record's `credential.public_key` reply, derived by `credentials_core::signing::key_id_for_public`. A KEM public-key reply has `algorithm: "x25519"` and `public_key_hex`.

Checks run in order: (1) shape decode (a transport `Error` frame with code `invalid_params` and **no class**, per §1a); (2) combined encoded length at most `ENC_BOUND = ceil(MAX_SIGN_PAYLOAD / 3) * 4 + 12`, then standard base64 decode (malformed byte field: the in-result code `malformed_encoding`, class permanent); (3) combined decoded length at most `MAX_SIGN_PAYLOAD` (1 MiB), otherwise `sign_payload_too_large`, context_overflow; (4) connection-scoped refusal counter gate (`open_rate_limited`, transient, without delay or disconnect); (5) scoped authorization for `open` (`not_found` on unknown or ungranted id); (6) KEM kind fence (`kind_not_openable`, permanent); (7) PKCS#8 parse and fresh RFC 9180 base-mode receiver opening sequence zero (`open_failed`, permanent, identically for invalid encapsulation, wrong recipient, modified ciphertext, wrong aad or wrong info and corrupt stored payload). Each step runs only after its predecessors pass. Refusals at step 5 alone increment the connection counter; it recovers after 60 seconds. Authorized opens do not increment it. `info_b64` and `aad_b64` are uninterpreted associated bytes: the vault does not inspect machine identity or verify a signature inside the plaintext.

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
same `reserved:<module>` string, and alarm is false. The payload_hash is lowercase
hex SHA-256 of:

```text
UTF8("ck-deposit-cookie/v1") || u32be(len(UTF8(id))) || UTF8(id)
|| u32be(len(UTF8(consent_ref))) || UTF8(consent_ref) || SHA256(UTF8(cookie))
```

The inner SHA-256 is 32 raw bytes, not hex. Independent vector: id
`cookie:example.com:work`, consent_ref `consent-123`, cookie `session=abc` yields
`4b5a1cb62c56fc15d6dda4e1cd4ded71770ccb9f847e8fe1e254b01ea6837140`.
The payload_hash commitment can be verified by recomputing the outer SHA-256 over
the documented id, consent_ref and raw cookie digest layout and comparing the hex
result. Verifying a replaced cookie requires retaining its digest outside the vault.

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
  `list_scoped_view`, not a second digest definition.
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
`cortexkit-runners`, `cortexkit-account`, and `cortexkit-webhook-relay`. Authorization
uses the same scoped principal resolver as other scoped operations: an explicitly
presented enrollment token takes precedence over the route-bound reserved principal;
a bad token never falls back to ambient authority. Unknown, uncovered, and
unauthenticated callers receive the identical `not_found`/`permanent` body.

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

**Every seal is audited.** Before the ciphertext is returned the vault commits one
HMAC-chained row with `audit_log.op = seal`, the credential id, `payload_hash` set to
the SHA-256 of the decoded plaintext, and the resolved `reserved:<module>` or
`enrolled:<name>` actor. The plaintext is never recorded; the audit row has no column
for the recipient key, so it is not recorded either. If the row cannot be written, or
the key record was replaced between the read and the audit write, the ciphertext is
discarded and the call returns `store_error` / transient. A refused seal writes no
audit row.

Grants are exact-only, and the CLI and the store both refuse a category or audience
selector:

```sh
ck auth grant --principal reserved:prefrontal-core --selector-kind exact --selector kem:push --operation seal
ck auth revoke-grant --principal reserved:prefrontal-core --selector-kind exact --selector kem:push --operation seal
```

The grant operation arrives with store migration 18. A binary older than that
migration cannot read a store that holds a `seal` grant's operation name.


## 14. Federation between computer vaults

A rotating OAuth login stays on one **home** vault A. Vault B keeps a remote record and
fetches only an access token; it never stores the token in its database or receives an
OAuth struct or refresh token. Static credentials instead use an explicitly accepted sealed
transfer. There is no automatic credential synchronization and no remote-record chaining.

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
| `federation.transfer_deliver` | Mutate | Deliver an Auth-sealed static credential for operator acceptance. |
| `federation.secret_use` | Query | Forward a member vault's sender `secret.use` to the secret home; the release is Auth-sealed, so callosum must not persist query replies. |
| `federation.secret_request_flow_approval` | Mutate | Record a member vault's flow consent request for a secret this vault holds. |
| `federation.secret_revoke_flow_grants` | Mutate | Revoke a member vault's flow grants for one flow install. |

Every other op on that channel is `not_found` before dispatch. `handle` or
`enrollment_token` params are `invalid_params`, never resolved. The six federation ops
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
| Secret release | `cortexkit/claustrum/secret-release/v1` | `secret_name`, `requester`, `home`, `nonce`, `recipient_key_id`, `call_sha256` |

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
| `refresh_adapter` | Optional adapter-name string. |
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
only). Parsing is strict as for the token aad: unknown, missing or duplicate fields, or
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
   recomputed digest of the received params, and `call.name` equals its `secret_name`.
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

`invalid_params` is a protocol Error-frame code with no credential class, including for
malformed federation params/member/aad and forbidden bearers. Master-key admin helpers
can also return `invalid_params` / permanent in their separate admin refusal body; that
does not turn the protocol Error into a classified read verdict.

| Additional refusal code | Class | Meaning |
|---|---|---|
| `transfer_key_reserved` | permanent | A forbidden grant or handle on a transfer-key id. |
| `transfer_key_protected` | permanent | Mutation or replacement of an active transfer key. |
| `remote_record` | permanent | A handle or local-only action requested for a remote record. |
| `member_not_paired` | permanent | Member grant attempted without a current pairing. |
| `callosum_unavailable` | transient | Required admin/transfer pairing or key lookup failed. |
| `federation_requires_daemon` | permanent | Outbound admin op attempted through the synchronous offline path; no write. |
| `transfer_body_invalid` | permanent | Ineligible or invalid transfer body. |
| `transfer_ineligible` | permanent | Send refused an ineligible kind/OAuth payload/adapter; optional `reason` describes the eligibility failure. |
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
| `member_grant_create` / `member_grant_revoke` | exact selector id, otherwise none | member | `{operation, selector_kind, selector, pairing_id}` |
| `remote_add` / `remote_remove` | id | home | `{incarnation}` |
| `federation_gate_set` | none | admin | `{value}` |
| `federation_self_set` | none | admin | `{member}` |

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

The seven phone operations are `secret.phone_keys_register`, `secret.deposit_keys`,
`secret.deposit`, `secret.approve`, `secret.list`, `secret.delete` and
`secret.revoke_grant`. "Credential get" is `credential.get` with a valid `handle`;
"scoped get" is `credential.get_scoped` without `enrollment_token`.

Rows name the route principal and, for `reserved:callosum`, the opener harness. Member gate
is `federation.member_mapping`; phone setting is `secret.phone_mapping`. Each is On, Off or
Unreadable (a store read that fails), so every row below covers all nine combinations.

| Caller | Gates | Seven phone ops | `secret.use` | `permissions.list`, `permissions.revoke` | credential get | scoped get |
|---|---|---|---|---|---|---|
| callosum, `callosum-self` | any | NF | NF | POR | served | served (callosum's grants) |
| callosum, `fed-phone:<32 lowercase hex>` | member On, phone On | served (phone preflight) | NF | POR | IP | NF |
| callosum, `fed-phone:<32 lowercase hex>` | member Off, any phone | NF | NF | POR | served (§14 gate-off residual) | NF |
| callosum, `fed-phone:<32 lowercase hex>` | member On with phone Off or Unreadable; member Unreadable | NF | NF | POR | NF | NF |
| callosum, malformed `fed-phone:` | member Off | NF | NF | POR | served (§14 gate-off residual) | NF |
| callosum, malformed `fed-phone:` | member On or Unreadable | NF | NF | POR | NF | NF |
| callosum, `fed-computer:<32 lowercase hex>` | member On | NF | NF | POR | NF (a member channel answers only its six federation ops, §14) | NF |
| callosum, `fed-computer:<32 lowercase hex>` | member Off | NF | NF | POR | served (§14 gate-off residual) | NF |
| callosum, `fed-computer:<32 lowercase hex>` | member Unreadable | NF | NF | POR | NF | NF |
| callosum, any other `fed-` harness | member Off | NF | NF | POR | served (§14 gate-off residual) | NF |
| callosum, any other `fed-` harness | member On or Unreadable | NF | NF | POR | NF | NF |
| `reserved:aft` | any | NF | served | POR | served | served (its grants) |
| `reserved:cerebellum` | any | NF | served | POR | served | served (its grants) |
| `reserved:cingulate` | any | NF | NF | served | served | served (its grants) |
| `direct` with the admin MAC | any | NF | NF | served only through `admin.op` (below); a plain call is POR | served | NF (Direct holds no read grant) |
| `direct` without the admin MAC | any | NF | NF | POR; `admin.op` is refused | served | NF (Direct holds no read grant) |

Gates are read only on `reserved:callosum` routes; every other principal's harness is
ignored. On a phone channel, bearer params (`handle`, `enrollment_token`) are IP even on
a method the channel otherwise refuses, except `permissions.list` and
`permissions.revoke`, which are POR for every caller other than `reserved:cingulate`
whatever their params. `secret.use` is NF for every caller other than the two senders,
before its params are read, so a non-sender cannot learn the grammar.
`secret_caller_gate_and_op_matrix_matches_the_wire_contract` drives every row,
gate combination and column above through the real route dispatcher.

The operator uses the existing `admin.challenge` / `admin.op` MAC transcript for
permissions operations: the authenticated `op_body` is
`{"op":"permissions.list","v":1,"agent_id":"optional-agent-id"}` (omit `agent_id`
to list all), or `{"op":"permissions.revoke","v":1,"id":"grant-id"}`.
Only the wrapper admits Direct. Plain `permissions.list {agent_id?}` and
`permissions.revoke {id}` keep the `permissions/v1` provider shapes (pinned by the
vendored vectors in `crates/credentials-module/tests/vectors/permissions-v1/`) and admit
only `reserved:cingulate`.

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
`authorization_bearer`, `header:<name>`, `query:<name>` or `json_pointer:<pointer>`.
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
code}]}`, one entry per envelope item in envelope order. `code` is always
`approval_invalid` and never says which check failed.

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
agent_id, expires_at_ms?, last_use_ms?}], flow_grants: [{grant_id, flow: {flow_id,
version, install_id}, duration, methods?, last_use_ms?}]}]}`. An API key carries `host`,
`location` and `path_prefix` (omitted when it covers every path); a login carries `origin`.
`state` is `active` or `corrupt`. An agent grant always names its `agent_id`, `null` when
the statement named no agent, and omits `expires_at_ms` when its duration is `permanent`.
A flow grant appears in `flow_grants` with `flow` and duration `version` in place of an
asking scope and coverage, and carries `methods` only for an API key. A grant of either
kind omits `last_use_ms` until it has served a call. Material, its digests and requested
paths never appear.

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

**Stamp grammar**, from subc-protocol 0.33.0 `ScopeStamp` (`crates/subc-protocol/src/scope.rs`
in the subconscious repository; the version is the one locked in `Cargo.lock`):

| Field | Required | Shape | Used for |
|---|---|---|---|
| `owner` | yes | principal object: `{"kind":"reserved","module_id":…}`, `{"kind":"direct"}` or `{"kind":"unverified"}` | the asking scope's owner, rendered `reserved:<module_id>`, `direct` or `unverified` |
| `ref` | yes | string | the asking scope's ref |
| `scope_epoch` | yes | integer, at most 2^53 − 1 | the asking scope's epoch |
| `kind` | yes | `"head"`, `"worker"` or `"ephemeral"` | the mapping rule |
| `owner_authorized` | yes | boolean | required by the decoder; grants no authority here |
| `parent` | no | `{owner, ref, scope_epoch}`, with `owner` a principal object as above and `scope_epoch` at most 2^53 − 1 | Ephemeral mapping and Worker-under-Head coverage |
| `parent_state` | no | `"linked"`, `"pending"` or `"ended"`; only `linked` counts as live | as `parent` |
| `attributes` | no | object with optional `agent_id`, `on_behalf_of_agent`, `delegates`, `flow_id`, `run_id`; unknown attribute keys are refused | `agent_id` names the agent in statements and the permissions listing; a present `flow_id` (a flow-read scope) maps to nothing |
| `workdir`, `project_id`, `expires_at_ms` | no | as subc defines them | ignored |

Other top-level stamp keys are ignored, as subc's decoder does. A stamp missing any required
field answers the uniform `not_found`; a stamp whose fields are present but malformed is
`invalid_params`. Mapping uses only the stamp: a Head or Worker maps to itself; an
Ephemeral maps to its parent (as a Head) only when `parent.owner` is
`reserved:prefrontal-core`, `parent_state` is `linked` and `parent.scope_epoch` equals the
stamp's `scope_epoch`; anything else, and every flow-read scope, maps to nothing (uniform
`not_found`). A Worker is also served by an `agent_and_workers` grant on Head H when its
stamp's parent has H's owner and ref, `parent_state` `linked` and an equal epoch.

**Target rules.** The scheme must be `https` and the port 443. The host is lowercase ASCII
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
* `agent_id` is the stamp's `attributes.agent_id`, or `null` when the stamp has none. It
  is an identifier, not a display name: the approval card supplies the human name.
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

Transport errors are an `Error` frame `{"code":"…","message":"…"}` with no class (§1a);
the message is fixed text and never echoes the request.

| Code | Class | Form | Meaning |
|---|---|---|---|
| `invalid_params` | none | transport Error | request grammar or key set, stamp shape, coverage not permitted, malformed `card_ref`, bearer params on a phone channel |
| `not_found` | `permanent` | result error | uniform refusal: not a sender or phone channel, unknown or unusable name, unmapped scope, target mismatch, wrong member id or unopenable deposit |
| `limit_exceeded` | `context_overflow` | result error | a length or size over its limit |
| `approval_invalid` | `permanent` | result error, or the `code` of a refused `results` item | an envelope or item failed a check; never says which |
| `phone_not_registered` | `permanent` | result error | the phone is absent from callosum, or has no keys under its current pairing |
| `phone_key_conflict` | `permanent` | result error | different keys for an already registered (fingerprint, pairing) |
| `deposit_conflict` | `permanent` | result error | a used deposit id with different bytes, member id or a deleted record |
| `name_exists` | `permanent` | result error | a new deposit for a name that already has a record, corrupt included |
| `secret_setup_incomplete` | `permanent` | result error | this vault's member id is unset, or its deposit key is unusable |
| `pairing_unavailable` | `transient` | result error | callosum did not answer the pairing lookup within the 1,500 ms budget |
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
| `secret_phone_register` | fed-phone:<fp> | secret-phone\|<fp> | pairing_id, raw deposit_pub, raw approval_pub |
| `secret_store` | fed-phone:<fp> | secret\|<name> | kind, incarnation, scope fields, deposit_id |
| `secret_grant_expire` | vault | secret\|<name> | grant_id, incarnation, expires_at_ms (u64 LE) |
