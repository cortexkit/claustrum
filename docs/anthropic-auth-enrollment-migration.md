# Migrating `anthropic-auth` from capability handles to consumer enrollment

Written for the seat implementing `anthropic-auth`. Everything here is measured
against this repository, not recalled, and the dates say when.

<!-- built-when: crates/credentials-module/src/read_surface.rs::enrollment_token -->
**Status: the ceremony is BUILT, spending the token is NOT BUILT (2026-09-19).** A
consumer can complete `propose -> approve -> poll` today and receive a token it cannot
yet spend: `enrollment_token` appears zero times in `read_surface.rs`, so no scoped
operation accepts one. That is a later slice of the same campaign. The marker above
names the symbol whose appearance falsifies this line, and this document goes red in
the gate on the day it ships.

Also, and separately: none of this is on `master` or on any running vault. It lives on
the integration branch `campaign/enrollment-selectors`, and the vault on this machine
is still at store schema 8. Build against the contract, do not expect the daemon to
answer yet.

## What does not change, and will not

Read this first, because it is most of the answer to "when do I have to move".

`credential.get` by capability handle is **unchanged and not deprecated**. It is
anonymous by design: no principal, no grant, no enrollment. Your current path — read
the 0600 handle file, resolve a handle, serve the payload, report a 401 with
`record_version` — keeps working across every release in this line. Nothing in this
migration breaks a handle you already hold.

So this is an additive capability, not a cutover with a deadline. You can adopt it
when it buys you something, and the thing it buys is below.

## What it buys: accounts you did not have to be told about

Today each Anthropic account needs a handle, and a handle is minted per credential by
an operator with the master key. Add a fifth account and somebody must mint a fifth
handle and write it into your file before you can see it. That is the coupling this
removes.

After enrollment you hold **one** bearer token, and an operator grants that token a
**category** rather than a list:

```
ck auth grant --principal enrolled:anthropic-auth-opencode \
              --selector-kind category --selector llm-provider --operation read
```

A credential assigned `llm-provider` is then in reach the moment it exists. No mint,
no file edit, no restart.

## Names: one per host process, not one per plugin

If the same core is bundled into more than one host — an OpenCode plugin and a Pi
extension, say — **each host enrolls under its own name**:

```
anthropic-auth-opencode
anthropic-auth-pi
```

The deciding property is revocation granularity: one must be revocable without killing
the other, and a shared name is a shared identity. The cost is real and it is one extra
approval per machine: the operator approves twice and grants twice for what they think
of as one plugin. That is the trade, taken deliberately, against a revocation whose
blast radius you cannot bound.

The name is a **label**; the **token is the identity**. So a name collision is not an
authentication bypass — it is refused at the vault by a unique index over live
enrollments. One further rule exists to stop a subtler failure: a name with live grant
rows cannot be re-enrolled until those rows are revoked, so a new consumer can never
silently inherit a revoked one's reach.

## The ceremony

```
propose   you POST a proposed name and the SHA-256 of a secret you mint
approve   an operator approves it under the master key (Gate 2), and may rename
poll      you present (request_id, request_secret) and receive the token ONCE
```

### Persist before you POST

`request_secret` is the **only** value needed to resume a pending request. Poll takes
`(request_id, request_secret)` and nothing else. So write both under lock *before*
sending the propose, and a crash between propose and poll resumes instead of wedging
your name — an editor restart mid-enrollment is an ordinary event, not an edge case.

Pending rows also expire, so `pending_exists` is temporary rather than permanent, but
a consumer that has to wait out a TTL is only marginally better off than one that is
stuck. Persist the secret.

### The wire, byte for byte

Do not transcribe from this document. The fixture is the contract and it is asserted
in the suite:

```
crates/credentials-module/tests/fixtures/enrollment_wire_contract.json
```

Reproduced here so you can see the shape, current at the commit that added it:

```jsonc
// auth.enroll_propose
request  {"proposed_name":"consumer","request_secret_hash":"<64 hex>"}
success  {"result":{"request_id":"request-id"}}

// auth.enroll_poll
request  {"request_id":"request-id","request_secret":"<64 hex>"}
success  {"result":{"status":"pending"}}
         {"result":{"status":"denied"}}
         {"result":{"status":"approved","name":"consumer","token":"<64 hex>", ...}}

// auth.enroll_rotate
request  {"token":"<64 hex>","expected_token_generation":1}
success  {"result":{"token":"<64 hex>","token_generation":2}}
```

**Token grammar:** exactly 64 lowercase hex characters, no prefix, 32 CSPRNG bytes.
The vault stores only `token_hash`, the lowercase-hex SHA-256 of the decoded 32 bytes.

### Refusals are transport errors, never a further `status`

Every non-success outcome carries the shipped `(code, disposition)` pair. Your poll
loop branches on these and on nothing else:

| op | outcome | code | disposition |
|---|---|---|---|
| propose | the name already has a live request | `pending_exists` | permanent |
| propose | 16 live rows | `pending_queue_full` | transient |
| propose | malformed name or hash | `invalid_params` | permanent |
| poll | unknown `request_id` **or** wrong secret | `not_found` | permanent |
| poll | malformed secret | `invalid_params` | permanent |
| poll | already delivered | `already_consumed` | permanent |
| poll | revoked, reissued past, or expired-approved | `superseded` | permanent |
| rotate | wrong `expected_token_generation` | `stale_generation` | permanent |
| rotate, scoped ops | unknown, revoked or rotated-away token | `not_found` | permanent |

Two of those rows are load-bearing for how you write the loop:

- **`pending_queue_full` is the only transient one.** A full queue REFUSES rather than
  evicting, deliberately: eviction would let a flood silently displace the legitimate
  request a bound exists to protect. Back off and retry; do not treat it as fatal.
- **An unknown `request_id` and a wrong-but-well-formed secret answer identically.**
  That is on purpose, so poll is not an existence oracle. You cannot use it to discover
  whether a request exists, and you should not try.

`superseded` and `already_consumed` both mean stop and tell the operator. `pending`
means keep polling.

## Discovery, once spending exists

<!-- built-when: crates/credentials-module/src/read_surface.rs::enrollment_token -->
**Status: NOT BUILT (2026-09-19).** The section below describes the shape agreed with
`openai-auth` and folded into the campaign spec. It is here so you can design against
it, not so you can call it.

`credential.list_scoped` returns one row per credential your grants cover — id,
categories, type, served vendors, lifecycle state, `record_version`, allowed
operations, and non-secret identity (`account_id`, `email`, `org_name`).

### `view` is your change cursor, and it folds in identity

The reply carries `view`: a SHA-256 over exactly your visible credentials and your
grant tuples. `record_version` is deliberately excluded, so **a routine token refresh
does not move it**.

Identity IS in the digest. So a credential re-authenticated to a *different* account
under the *same* id moves `view` — which is what gives a consumer-side declined set
its teeth. All three transitions move it, because an absent field is tagged
distinctly from an empty one:

```
known -> known     moves
known -> absent    moves
absent -> known    moves
absent -> absent   DOES NOT MOVE      <- the one blind spot
```

That last row is not closable from the vault: it cannot manufacture an identity the
provider does not put in the token. Measured on the live llm-provider inventory on
2026-09-19, seven of nine credentials carry an identity — every Anthropic account and
every ChatGPT account does; `oauth:cursor` and `oauth:xai` do not. So for your
provider it is complete, and the statement is "complete where the adapter yields an
account claim, partial otherwise".

There is deliberately **no** vault-wide generation counter on the reply. A global
counter would let a caller with little reach infer vault-wide administrative activity,
which is an authorization leak dressed as a convenience, and `view` already answers
the question precisely for you.

### The declined set is yours, and it keys on identity

If you offer an account to the operator and they decline it, keep that decision keyed
on `(credential_id, account_identity)` — **never** on `record_version`, because a
refresh bumps that and would resurface every declined account on every refresh. When
identity is absent, stay declined. Invalidate the decision only when both identities
are known strings and differ.

`created_at_ms` is **not on the row yet** and is specified for a later slice. Measured
2026-09-19: `ListScopedCredential` carries id, categories, type, serves, state,
`record_version`, operations, `account_id`, `email`, `org_name` — and no timestamp.

This one deliberately does NOT get its own `built-when` marker. The falsifier would be
a struct FIELD rather than a symbol, the checker matches symbols, and
`created_at_ms` already appears once in that file in an unrelated test fixture — so a
marker naming it could never fire, and a check that cannot fail is worse than no check
because it reads as one. It rides the `enrollment_token` marker above instead, since
nothing here is callable until that lands anyway.

When it does land, treat rows **at or above** your high-water mark as new, never
strictly above: strictly-above makes a same-millisecond twin permanently invisible —
not declined, never offered, and nobody files a bug about an account they do not know
exists.

## What stays the same in your failure reporting

Report HTTP **401** on a served token, with the `record_version` you were served and a
`reporter_source`. Do not report 403, 429, or a malformed request: those are refusals
of an *operation*, not evidence the credential is dead, and a report on them marks a
healthy credential stale.

## Suggested order of work

1. **Nothing, for now.** Your handle path is unaffected and this is on a branch.
2. Build the ceremony against the fixture: propose, persist-before-POST, poll loop on
   the nine outcomes, 0600 token file. This is testable today against the contract.
3. Decide your names (`anthropic-auth-opencode`, `anthropic-auth-pi`) and write the
   0600 token file path into your own docs.
4. Wait for the spending half. This document goes red in the repo's doc-status gate on
   the day `enrollment_token` appears in `read_surface.rs`, which is the signal.
5. Then: `list_scoped` for discovery, `get_scoped` for the payload, `view` as the
   cursor, declined set keyed on identity.

## Questions that are mine, not yours

Ask rather than working around:

- Whether a credential should carry `llm-provider` — category assignment is
  master-key-gated (`set-category`) and operator-owned.
- Anything where the vault's answer and your map disagree. A consumer that reports
  observed-versus-expected lets me pick the repair; a consumer that reports a remedy
  has already chosen one, and has usually chosen from less evidence than I have.
