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
| `too_many_items` | context_overflow | a batch exceeded the per-request cap |
| `sign_payload_too_large` | context_overflow | a sign payload exceeded 1 MiB (`MAX_SIGN_PAYLOAD`) |
| `ttl_unsatisfiable` | context_overflow | a freshly minted token still cannot satisfy your `min_ttl_ms` |

**On an unknown class:** render a generic degraded state. Do not fall back to the
nearest known class — each known class carries an actionable remedy, and applying the
wrong one (prompting a human for a transient network failure) is worse than saying
"something is wrong and I do not know what".

---

## 2. Addressing

Two ways to name a credential, and they authorize differently.

**A capability handle** (`ckh_…`) is a bearer token. Possession is the authorization;
there is no principal check. Treat it as a secret: it belongs in a `0600` file, never in
a log line, an error message, or a shell history. The vault never logs one.

**A credential id under a grant** (`credential_id`) is principal-scoped. An operator
mints a grant over an id PREFIX for a named reserved module principal, per operation:

    ck auth grant --principal <module> --prefix <prefix> --op read
    ck auth grant --principal <module> --prefix <prefix> --op sign

`read` and `sign` are distinct: a `read` grant does not authorize signing, and a `sign`
grant does not authorize `credential.public_key`. Prefix matching is a literal
`starts_with`, so `signing:agent-assertion:1` also covers `…:10` — grant at family
level deliberately, not at a leaf you expect to be exact.

| operation | handle | credential_id |
|---|---|---|
| `credential.get` | yes | — |
| `credential.get_many` | yes | — |
| `credential.get_scoped` | — | yes (`read`) |
| `credential.sign` | yes | yes (`sign`) |
| `credential.public_key` | yes | yes (`read`) |
| `credential.status` | yes | yes (`read`) |
| `credential.report_auth_failure` | yes | — |

---

## 3. Reading a credential

`credential.get` returns the opaque payload as a JSON array of byte integers, plus
`expires_at_ms` and `record_version`, plus non-secret routing metadata where the vault
has it (`account_id`, `email`, `org_name`, and `project_id` for `antigravity`).

Two optional levers, and they are the same lever pointed differently:

- `force_refresh: true` — exchange before serving, unconditionally.
- `min_ttl_ms: <n>` — exchange if the token has less than `n` remaining.

`min_ttl_ms` is evaluated **only when you supply it**. There is no implicit floor, and
the refusal (`ttl_unsatisfiable`) fires only after a real exchange has proven the demand
unmeetable — never speculatively.

---

## 4. `credential.status` — the cursor surface

`status` answers without minting anything. It is the surface to poll.

| field | meaning |
|---|---|
| `ready` | the vault will attempt to serve this record |
| `record_version` | monotone change cursor over the stored MATERIAL |
| `stale_pending` | whether the next `get` will pay an upstream exchange |
| `last_error_code` | the most recent refusal, if any |

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
