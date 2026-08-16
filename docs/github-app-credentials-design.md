# `github_app` credentials — design

**Status: DESIGN ACCEPTED, NOTHING IS BUILT.** No code exists, no records exist,
no adapter is registered. Measured 2026-08-15. Replace this line with a list of
what has actually shipped as pieces land — a detailed design reads as an
existing system to anyone who did not write it, and that mistake has cost this
fleet real debugging time twice.

## Why this is designed and not built

Everything below is specified: wire verified against GitHub's docs, crypto
chosen, handle shape settled, registry fields agreed with ALF. Nothing blocks an
implementation except material.

**It waits for a real key on purpose.** This repo's refresh adapters are built to
the fidelity rule -- conformance tests assert against RECORDED provider
responses, never invented ones. Without a real GitHub App there is no recorded
`access_tokens` response to test against, only the shape the documentation
describes. An adapter tested against a documented shape passes exactly as
convincingly as one tested against a real one, and discovers nothing the docs
already said.

So the sequencing is deliberate rather than idle: when the PEM batch lands, mint
one token against real GitHub, record the response, and build against that. The
design work done ahead of it is the part that pays -- it has already killed a bad
dependency and corrected a registry field before ~20 rows existed.

## What it is

One GitHub App per CortexKit head Alfonso (~20 apps). The vault custodies each
app's **private key (PEM)**, handed over once at mint, and serves short-lived
**installation tokens** on demand:

1. Sign a JWT with the app key (`iss` = client id, ≤10 min).
2. `POST /app/installations/{installation_id}/access_tokens` with it,
   `Authorization: Bearer <jwt>`.
3. Receive an installation token, **1h** expiry.

## Wire facts, verified against GitHub's docs 2026-08-15

Read before implementing; three of these contradict what a reasonable person
would assume, and one contradicts an earlier version of this note.

- **The JWT MUST be RS256.** Not ES256. The `p256` signer already in this repo
  (`apns.rs`, for APNs provider tokens) **cannot produce it** — different curve,
  different algorithm family. WHICH RSA implementation to use is its own section
  below, because the obvious choice is the wrong one.
- **`iss` should be the CLIENT ID, not the app id.** GitHub's current guidance
  recommends the client id; the numeric app id still works. This corrects the
  registry-field statement made to ALF: carry the client id.
- **`iat` should be backdated 60 seconds** against clock drift, and **`exp` may
  be at most 10 minutes ahead**. A JWT minted with a longer window is refused,
  so the mint is not a place to be generous.
- **Installation tokens last 1 hour** and do not rotate — minting a new one does
  not invalidate the old.
- **NEVER ASSUME A 40-CHARACTER TOKEN.** From April 2026 GitHub is rolling out a
  stateless installation-token format (`ghs_APPID_JWT`), so tokens are no longer
  a fixed length. Any length check, column width, or regex pinned to 40 breaks
  on rollout — and it breaks *per token*, as the rollout is staged, so it will
  look intermittent. The vault stores payloads as opaque bytes and has no such
  check; this is recorded for consumers.
- The `permissions` body parameter can scope a minted token BELOW the
  installation's grant. Not used initially, but it is the mechanism if a
  consumer should hold less than the app does.

Consumers: PLEX first (reactions, GitHub writes as the agent identity), later
commit and PR surfaces. The exchange lives here so it exists **once** rather
than per-consumer — the same argument that put the OAuth refresh adapters here.

## The decision worth recording: it rides the OAuth path

A GitHub App key is stored in `OAuthCredential.refresh_token` and the
installation token in `access_token`, with `kind: Oauth` and
`refresh_adapter: "github_app"`.

**This looks wrong at first reading, and a future maintainer will want to
"fix" it. Do not, without reading the rest of this section.**

### Why it is not a lie

GitHub App authentication is a **JWT-bearer assertion flow** — the shape
RFC 7523 standardises. The stored key is the credential from which a bearer
token is derived; the intermediate JWT is a detail of the exchange, exactly as
a client assertion is in RFC 7523. `refresh_token` holding assertion-signing
key material is unusual **naming**, not an unusual **relationship**: it is the
long-lived secret exchanged for a short-lived access token, which is what that
field means.

### Why the alternative was rejected

The honest-types alternative is `CredentialKind::SigningKey` plus a dedicated
credential struct and a parallel mint path. Adding the enum variant is cheap —
it is additive serde. The expensive part is that `RefreshEngine::do_refresh`
is typed on `OAuthCredential` end to end: intent hashing, the two-transaction
commit boundary, version-CAS on commit, the `invalid_grant` → `needs_reauth`
rule, and the fenced-write handling.

That path is the most heavily proven code in this repo — a kill-9 suite, four
rotation crash cuts, and a real-daemon boot-gate arm. A parallel path either
duplicates it (two crash-safe implementations, one of them unproven) or
refactors it generically (invalidating the proofs that currently hold).

**Behavioural correctness over elegant abstraction where the two conflict.**
Naming looseness costs a reader one paragraph; a second crash-safe path costs
a class of bugs that only appear on power loss.

### What riding the OAuth path buys, concretely

NOT the signing — no existing signer here produces RS256, though the right RSA
choice adds no new compiled crate (see the section above). What IS inherited is
the *custody and lifecycle* machinery, which is the expensive half:

- **Serve-from-cache-until-near-expiry**, which is exactly the agreed contract.
  `is_stale` already triggers on expiry-with-skew, so "mint on demand, cache
  until near-expiry" is the existing behaviour with no new logic.
- **Single-flight**: twenty consumers reading one app's token at once produce
  one exchange, not twenty.
- **Crash safety**: the intent log and two-transaction commit already handle a
  power cut mid-exchange.
- **Revocation shape**: a revoked installation returns 401 at the exchange,
  which maps to `invalid_grant` → `needs_reauth` — the correct end state, and
  it surfaces in `ck auth status` like any other dead credential.

### Where it differs from every other credential here, and what that changes

**Installation tokens do not rotate.** Minting a new one does not invalidate
the old, and the PEM is never replaced by the exchange.

Two consequences:

1. `RefreshedTokens` returns the stored key unchanged. The existing optional-
   rotation handling covers this; nothing new is required.
2. **A stale copy in a consumer's hands stays valid until it expires.** This is
   the first credential here where that is true. It is why `credential.get` is
   the only interface and consumers must not cache: a cached installation token
   silently outlives any revocation, and neither the vault nor the operator can
   see that it is still in use. Agreed fleet-wide with ALF and PLEX.

## Use `ring` for the RS256 signature, NOT the `rsa` crate

The obvious pick is RustCrypto's `rsa`, since this repo already uses `p256` from
the same family. **Do not.**

`rsa` carries **RUSTSEC-2023-0071** (Marvin attack: potential private-key
recovery through timing sidechannels). As of 2026-08-15 the advisory still reads
*"no patch is yet available"* — reported 2023-11, last modified 2026-04. The
upstream tracking issue shows constant-time modexp landed, while padding-mode and
default-path blinding remain open. Its own stated workaround is to avoid the
crate where an attacker can observe timing.

A case can be made that our use sits outside the attack: Marvin is a
chosen-ciphertext oracle against *decryption*, and we only ever *sign* a payload
we construct ourselves — no attacker-supplied input, no oracle. That argument is
probably correct. **It is also unnecessary, and that is what settles it:**
accepting an unpatched advisory on a credential path in exchange for nothing is a
bad trade even when the reasoning holds.

**`ring` is already compiled into this workspace.** `ring 0.17.14`, pulled by
`rustls` via `reqwest`, confirmed in `Cargo.lock`; `rsa` is not in the tree at
all. So the real choice is between ADDING a crate with an open advisory and
DECLARING one already built, audited, and constant-time by design.

API confirmed present at the pinned version rather than recalled
(`ring-0.17.14/src/rsa/keypair.rs`, `src/signature.rs`):

- `RsaKeyPair::from_der` — PKCS#1 DER, which is what a GitHub App `.pem` holds
  (`BEGIN RSA PRIVATE KEY`). PEM to DER is base64 over the body: no extra
  dependency.
- `RsaKeyPair::from_pkcs8` — for a key already converted.
- `signature::RSA_PKCS1_SHA256` — exactly the encoding GitHub requires.

`ring`'s signing API takes an RNG, so the blinded path is the default rather than
an opt-in.

**Cost correction.** The signer is therefore NO NEW COMPILED DEPENDENCY, only a
direct declaration of one already present. An earlier revision of this note, and
a message to ALF, said a new RSA dependency was required: true of the naive
choice, false of the right one.

## Handle shape

- Credential id: `github_app:<slug>` (`:<n>` if slugs ever collide).
- One capability handle per consumer, as with every other credential, so
  revocation stays per-consumer.
- `credential.get` returns the **installation token**. The PEM never leaves the
  vault, exactly as no refresh token does.

## A handle may mint a token weaker than the installation it names

GitHub's `access_tokens` endpoint takes an optional `permissions` body parameter
that scopes the minted token **below** the installation's own grant. A handle
therefore carries an optional permission subset, and `credential.get` mints
against that subset rather than against everything the App was granted.

**Why this earns its place.** A consumer that only needs to comment should not
hold a credential that can merge. If that token leaks, is misused by a confused
agent, or is reached by something that should not have had it, the damage is
bounded by what GitHub issued rather than by what our code remembered to check.
That is least privilege, and it does not depend on any policy layer above it
being correct.

Cost is nothing extra: handles are already the unit of grant, so one per
(consumer, capability set) is the same minting path with a different subset
recorded.

A STRONGER CLAIM ONCE LIVED HERE AND DID NOT SURVIVE CONTACT — see the next
section. It is kept rather than deleted because the reason it failed is more
reusable than the claim was.

### Why the subset is least-privilege, NOT tier enforcement

THE TIER RATIONALE THIS SECTION ORIGINALLY CARRIED IS DEAD, and the way it died
is worth keeping. I pitched scoped handles as making a trust tier physical:
comment-tier tokens that cannot merge. The fleet then established that MERGE IS
ALREADY AGENT-DRIVEN -- twenty agents merge their own pull requests with `gh pr
merge` today, ungated. So a tier that elevates merge does not raise a floor; it
raises the cost of the governed path while the ungoverned one stays open, which
makes the governed path the slow way to do something already done freely.

The exportable rule, which is the chair's: BEFORE DESIGNING A GATE, MEASURE WHAT
THE UNGOVERNED PATH ALREADY PERMITS. Blast radius tells you what a gate is
WORTH; current practice tells you whether it is a GATE AT ALL. Five seats
reasoned about merge from its blast radius and none asked what happens today.

WHAT SURVIVES, on different grounds: a handle that only needs to comment should
not carry the power to merge, because a leaked or misused token can then only do
what its holder needed. That is least privilege, and it stands whatever the
tiers do.

The granularity detail below is retained for whoever mints handles, because it
still decides what a minimal subset CAN be -- but it no longer decides a
security posture, and the measurement it once justified is NOT worth pilot time:

| permission | covers |
| --- | --- |
| `issues:write` | issues and their comments, assignees, labels, milestones |
| `pull_requests:write` | pull requests and their comments, assignees, labels, milestones, **and merges** |

So an ISSUE comment is cleanly separable from a merge, and a PR COMMENT IS NOT:
the same `pull_requests:write` that lets an agent comment on a pull request also
lets it merge one. For that pair the floor is not physical and we are back to
policy -- manifest tier plus the enumeration test.

**GitHub's merge endpoint documents a second requirement.** `PUT /repos/{owner}/{repo}/pulls/{number}/merge` carries:

> If making a request on behalf of a GitHub App you must also have permissions
> to write the contents of the head repository.

So for an App -- our exact case -- merge needs `contents:write` ON TOP of
`pull_requests:write`. Withholding `contents` therefore yields a token that can
comment on a PR and cannot merge it, and the arithmetic floor covers the pair
after all.

DOCUMENTED, NOT MEASURED, AND NO LONGER WORTH CHASING. Read off GitHub's
endpoint docs; a documented shape is not a recorded response. When this mattered
for tiers it was worth a pinned pilot measurement, and it is not any more --
record the answer if it falls out of the pilot for free, do not spend a step on
it.

The instrument, if it is ever wanted: GitHub returns
`X-Accepted-GitHub-Permissions` on REST responses, naming what the endpoint
actually required.

ONE EDGE THE NOTE IMPLIES: it says the HEAD repository. For a same-repo PR head
and base coincide, so `contents:write` on the one installation is the whole
story. For a PR FROM A FORK the head repo is the fork, which our App is probably
not installed on -- so a fork PR may be unmergeable by an App token regardless
of tier. That is a capability question, not a security one, and it should be
discovered at pilot rather than at first use.

SECOND DIMENSION, from the same source check: `repositories` /
`repository_ids` (up to 500) scopes a minted token to named repos. Orthogonal to
permissions, and it maps onto per-repo write-enabling filters -- so a handle can
be arithmetic in two dimensions, not one.

OPEN, and deliberately not decided here: whether the subset lives on the handle
row or on a per-consumer grant record. The handle is the natural home because it
is already what gets revoked, but nothing is built yet and the first real
consumer should shape it.

## Registry fields

`{client_id, installation_id}` is sufficient to serve: `client_id` is the JWT
`iss` (see the wire facts above — the numeric `app_id` still works, but GitHub's
current guidance is the client id), and `installation_id` selects the exchange
endpoint.

### `installation_id` does not exist when the App is created

Worth stating because it looks like a registry field and is not obtainable like
one. App CREATION and app INSTALLATION are separate events: the manifest flow
returns `{id, slug, client_id, pem}` and no installation id, because nothing is
installed yet. Someone then installs the App on an org, and that is what mints
one.

So a ceremony that captures everything the conversion response offers still
cannot supply the one field serving needs. Measured against a real ceremony
(prefrontal's, 2026-08-16): its decoder captures exactly `{id, slug, client_id,
pem}` -- correct, complete for that step, and one short of servable.

RESOLVE IT HERE RATHER THAN IN THE CEREMONY. `GET /app/installations` is
authenticated by the App JWT itself, so the vault can discover the id with the
key it already holds -- no operator step and no browser. Prefer discovering it
lazily at mint time and caching, over storing it at ingest: an uninstall and
reinstall mints a NEW installation id, so a stored one silently becomes a 404,
which is exactly the incident this section's diagnostic fields exist to make
legible. Self-healing beats stored-and-stale for a value the platform can
re-issue behind our back.

Also stored, diagnostic rather than functional: the app **slug** and the
**installation's org/account**. A revoked installation returns 404, and 404
against a bare numeric id is a poor thing to hand an operator during an
incident.

## The revocation asymmetry, stated because it is not the usual one

If an app key is exposed, the vault can **stop serving** it. It cannot revoke
it. Recovery is a portal action plus a re-mint — unlike an OAuth credential
whose refresh token the vault can kill by invalidating it upstream.

Twenty of these will exist. The incident procedure belongs in the mint
ceremony runbook (ALF owns that) and is recorded here so the asymmetry is
visible from the custody side too.
