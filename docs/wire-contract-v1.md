# claustrum wire contract v1 — the consumer's reference

**Status: this describes SHIPPED behaviour.** Every statement here was read off the
source or measured against the running daemon on 2026-09-04. Where a claim is pinned by
a test, the test is named — those cannot drift silently. Where it is not, treat it as
documentation and check the source if it is load-bearing for you.

This exists because consumers in other repositories branch on the values below, and
until now the only canonical statement of them was Rust source in two files. A consumer
cannot vendor a `.rs` file.

**What this is not:** the design rationale and threat model live in
`cortexkit-credentials-contract.md`. This document is the surface, not the argument.

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
| `corrupt` | permanent | the record failed to decrypt or parse and has been quarantined |
| `refresh_unsupported` | permanent | a refresh was demanded of a record with no refresh adapter |
| `needs_reauth` | auth_required | the credential is latched dead, or deliberately retired |
| `refresh_failed` | transient | the provider refused or the exchange failed |
| `vault_locked` | transient | the master key could not be resolved |
| `store_error` | transient | `credential.list_scoped` could not read one complete snapshot |
| `invalid_category_name` | permanent | a category is outside `^[a-z][a-z0-9-]{1,31}$` |
| `invalid_credential_id` | permanent | an id begins with reserved `category:` or contains `|` |
| `invalid_principal` | permanent | a grant principal is not `reserved` or contains `|` |
| `report_status_not_credential_death` | permanent | `report_auth_failure` carried a `provider_status` outside {401, 403} |
| `too_many_items` | context_overflow | a batch exceeded the per-request cap |
| `sign_payload_too_large` | context_overflow | a sign payload exceeded 1 MiB (`MAX_SIGN_PAYLOAD`) |
| `ttl_unsatisfiable` | context_overflow | a freshly minted token still cannot satisfy your `min_ttl_ms` |

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

**A supervised module principal** is the supervisor's attestation, stamped at route-bind —
but it is NOT ambient, and that sentence used to say it was. A supervised module's calls to
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

The earlier wording here said this principal was "ambient on your connection", which is
true of what the vault SEES and false about what a caller must DO. A consumer read it,
dialled correctly, and could not understand why every scoped call refused.

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

`read` and `sign` are distinct: a `read` grant does not authorize signing, and a `sign`
grant does not authorize `credential.public_key`.

| operation | handle | credential_id | enrollment token |
|---|---|---|---|
| `credential.get` | yes | — | — |
| `credential.get_many` | yes | — | — |
| `credential.get_scoped` | — | yes (`read`) | yes |
| `credential.list_scoped` | — | principal-addressed; all of the caller's grants | yes |
| `credential.sign` | yes | yes (`sign`) | — |
| `credential.public_key` | yes | yes (`read`) | — |
| `credential.status` | yes | yes (`read`) | — |
| `credential.report_auth_failure` | yes | yes (`read`) | — |

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
operator-chosen label, while account routing joins on `account_id` + `record_version`.

`account_id` IS THE PROVIDER'S ACCOUNT IDENTIFIER AND ITS SHAPE IS THE PROVIDER'S CHOICE.
Treat it as an opaque string. It is stable per account and comparable to itself, and
nothing more: do not validate it against a pattern, do not compare values across
providers, and do not infer from one provider's shape what another's will be. On a live
vault today Anthropic and OpenAI serve UUIDs and Google serves an email address, so a
consumer that assumes UUID shape breaks on a REAL value rather than a missing one — which
presents as a parse error on good data, the least legible failure available.

Reported by a consumer whose ledger holds one email in a column where every other row is a
UUID.

Two optional levers, and they are the same lever pointed differently:

- `force_refresh: true` — exchange before serving, unconditionally.
- `min_ttl_ms: <n>` — exchange if the token has less than `n` remaining.

`min_ttl_ms` is evaluated **only when you supply it**. There is no implicit floor, and
the refusal (`ttl_unsatisfiable`) fires only after a real exchange has proven the demand
unmeetable — never speculatively.

### `credential.list_scoped`

`credential.list_scoped` takes exactly `params: {}` and returns
`{ credentials, grants, grant_tuples, view }`. Unknown fields, including filters and
`token`, are `invalid_params`. Rows are sorted by id. `categories`, lifecycle `state`,
`record_version`, derived `type`/`serves`, and the caller's covering `operations` are
non-secret; no credential payload is returned. Identity is projected only when the caller
holds `read` for that row, never for a sign-only row.

`operations` is an **authorization fact**: it says which of this caller's grant rows cover
the id. It does not promise that the sealed record kind or lifecycle state can serve that
operation; record-level refusals such as `kind_not_signable` still apply after coverage.
`grant_tuples` returns the caller's own `{selector_kind, selector, operation}` rows and
`grants == grant_tuples.length`. `view` is the deterministic SHA-256 validator over the
returned rows and tuples; changes outside the caller's visibility do not move it.

### Category and grant audit targets

Category transitions use audit op `set_category` and target
`category:<credential-id>|<sorted-comma-list>`; clearing the set leaves the trailing `|`.
Migration 10's one category backfill row uses audit op `category.migrate`, actor
`migration:10`, and target `category:forge-identity|<sorted-comma-list-of-credential-ids>`.
New grant targets use
`grant:<operation>:<principal-kind>:<principal-id>:<selector-kind>|<stored-selector>`.
Both formats parse by splitting on the first `|`. Historical grant targets without `|`
remain valid audit-chain strings and are never rewritten.

---

## 4. `credential.status` — the cursor surface

`status` answers without minting anything. It is the surface to poll.

| field | meaning |
|---|---|
| `ready` | the vault will attempt to serve this record |
| `credential_id` | resolved operator-chosen label, for verifying an existing binding only |
| `record_version` | monotone change cursor over the stored MATERIAL |
| `stale_pending` | whether the next `get` will pay an upstream exchange |
| `last_error_code` | the most recent refusal, if any |

`credential_id` is absent for overall readiness and unresolved addresses; verify a held
binding with it, but never route on it—account routing remains `account_id` +
`record_version`.

**`record_version` and `ready` move independently, and that is deliberate.**
`record_version` tracks material: it bumps on refresh and on replace. `ready` tracks the
state verdict. So `ck auth reactivate` — the repair for a credential wrongly marked dead
— moves `ready` false→true **without** bumping `record_version`, because no material
changed. A consumer polling only the version cursor will hold a repaired credential dead
indefinitely. **Poll `status`, join on `record_version`, decide on `ready`.**

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

*(Contributed by a consumer seat, 2026-09-17, after a real 401 cluster where the vault
could not name the reporting consumer and the fence was the only thing that held.)*

### A status outside {401, 403} is REFUSED, not ignored

The vault has only ever acted on `401` and `403`. A report carrying `429`, `402` or a
`5xx` was accepted and its mark silently did nothing — so a consumer classifying quota
refusals as credential deaths got back success and no signal, and the defect survived in
the one place it could not be seen. Those now refuse with
`report_status_not_credential_death` (`permanent`), so a wrong classification is
diagnosed on its first report.

Refusing costs you nothing you can observe: you already hold the credential, and the
report is advisory. That is why this is a refusal where a refused *fetch* would be an
outage.

**`403` is still honoured, and deliberately.** It is genuinely ambiguous across
providers — GitHub uses it for permission refusals on a perfectly live token, and xAI has
used it for a real credential death (measured: one such report, followed by an operator
re-login, then clean refreshes ever since). This surface sees only the number. Refusing
`403` would fail toward a dead credential that looks healthy, which is the worse
direction, so the judgement stays with you: report only when you believe the credential
itself is invalid.

*(The refusal was proposed by a consumer seat arguing that a rate bound would convert a
loud classification defect into a quiet one. That argument is right and is why this is a
refusal rather than a throttle. Their stronger version — refuse everything but `401` —
was refuted by the one real `403`.)*

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
