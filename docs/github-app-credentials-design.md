# `github_app` credentials — design

**Status: DESIGN ACCEPTED, NOTHING IS BUILT.** No code exists, no records exist,
no adapter is registered. Measured 2026-08-15. Replace this line with a list of
what has actually shipped as pieces land — a detailed design reads as an
existing system to anyone who did not write it, and that mistake has cost this
fleet real debugging time twice.

## What it is

One GitHub App per CortexKit head Alfonso (~20 apps). The vault custodies each
app's **private key (PEM)**, handed over once at mint, and serves short-lived
**installation tokens** on demand:

1. Sign a JWT with the app key (`iss` = app id, ≤10 min).
2. `POST /app/installations/{installation_id}/access_tokens` with it.
3. Receive an installation token, ~1h expiry.

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

Every one of these is inherited rather than rebuilt:

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

## Handle shape

- Credential id: `github_app:<slug>` (`:<n>` if slugs ever collide).
- One capability handle per consumer, as with every other credential, so
  revocation stays per-consumer.
- `credential.get` returns the **installation token**. The PEM never leaves the
  vault, exactly as no refresh token does.

## Registry fields

`{app_id, installation_id}` is sufficient to serve: `app_id` is the JWT `iss`,
`installation_id` selects the exchange endpoint.

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
