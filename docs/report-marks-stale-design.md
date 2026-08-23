# A consumer report marks the token stale, it does not declare the credential dead

**Status: DESIGNED, NOT BUILT (2026-08-22).** No code implements this. The shipped
behaviour is still that a report at the current version latches `needs_reauth`
immediately. Read this as what is intended, not as what happens.

Consumer consultation is COMPLETE: BROCA, plexus and prefrontal-core have each
answered at source and cleared it. Two tests are co-signed as requirements, in §5.

## 1. The defect

`RefreshEngine::is_stale` returns true on exactly three conditions:

- the access token is empty
- it is expired within skew
- it breaches the caller's `min_ttl_ms`

**All three are expiry-based.** A token that the provider has REVOKED while it is
still unexpired locally is never seen as stale. So `get` serves it, the consumer is
refused, the consumer reports, and `report_auth_failure` latches `needs_reauth`.

Once latched, `EncryptedStore::get` matches stored state before decrypting, so **no
later read attempts the refresh that might have recovered it.** The vault surrenders
without finding out whether it could have.

The external operator who found this put it best:

> the recovery trigger and the death mode do not intersect

### The evidence, which is not a tail case

Measured on `oauth:anthropic` in a third-party deployment (`cortexkit/claustrum#7`):
**twenty consecutive cycles of `import -> report_auth_failure -> import`, with zero
`refresh_commit` rows in the entire retained chain.** The vault has never once
refreshed that credential. `ck auth usable` reports it serviceable, not stranded —
the refresh material is present and the path to it is simply never reached.

One cycle in detail: imported 12:35:03, reported dead 13:24:35, with 66 minutes of
TTL still on the clock. Forty-nine minutes, and the token was nowhere near expiry
when the provider stopped honouring it.

A second instance in this deployment: `oauth:xai` latched by a report at 11:05 on
2026-08-21, **93 minutes after the vault had refreshed it successfully** and having
refreshed cleanly every ~6h for days. Seven hours dark, ended by a human `login`.

## 2. The change

A report at the CURRENT record version marks the access token **stale** instead of
latching:

```
report (current version)   ->  token stale, record stays ACTIVE
next get                   ->  sees stale, refreshes
    refresh ok             ->  new token served; the consumer's retry works
    invalid_grant          ->  needs_reauth, through the path that already exists
    transient failure      ->  intent cleared, still stale, next get tries again
```

**Non-refreshable records are unaffected.** A static API key has no recovery path, so
a report against one must still latch immediately — marking it stale would be a lie
about a credential nothing can renew.

### Why the report path does not itself refresh

The obvious alternative is to attempt a refresh inside `report_auth_failure`. Rejected
for two reasons, and NOT for the reason first given to the reporter:

- it puts network I/O inside what is currently a single fenced database transaction
- it forces an answer for the transient-failure case that has no good one: the
  consumer says the served token is bad, the refresh could not confirm it, and the
  choice is between latching (possibly killing a live grant) and leaving it active
  (serving a token we have been told is dead). Marking stale answers this cleanly —
  the token is known-bad and will be replaced before it is served again.

**A withdrawn argument, recorded because it was wrong in a way worth remembering.** I
first told the reporter that refreshing on a report would let any bearer-handle holder
drive unbounded provider traffic. That capability already exists on the read path,
and I had documented it myself in `read_surface.rs`:

> a GRANTED consumer can drive `force_refresh` without limit, and each one is a real
> upstream token exchange

`credential.get { force_refresh: true }` is available to exactly the same caller with
exactly the same authority. The objection described a door that is already open three
feet to the left. Third instance in a month of reasoning about a gate without first
measuring what the ungoverned path already permits — and this time the measurement was
already written down, by me, in the file I was reasoning about.

## 3. Why the change is safe for this fleet's consumers

The change opens one new window: **between a report and the next get, `credential.status`
would say `ready` for a credential that has just been refused.** That window does not
exist today.

All three consumers were asked the same three questions and answered at source:

| | reads `status`? | does a get follow a report? | counts transitions? |
|---|---|---|---|
| **BROCA** | no | yes — `evict_for_provider_rejection` drops the rejected token from its cache before reporting | no |
| **plexus** | no | yes — no token cache at all; fresh zeroizing resolution per dispatch, and a 60s health probe resolves if no agent calls | no |
| **prefrontal-core** | no | yes — no cache; every call is a fresh `get_scoped` | no (and it never reports) |

**Nobody reads `credential.status`.** Three independent seats, and the one window this
change opens is invisible to all of them. That is a stronger result than three separate
yeses: the risk is absent from the consumer population, not merely tolerated by it.

The precondition — that a get follows a report — holds by three DIFFERENT mechanisms,
none of them built for this change. The fleet already resolves credentials at the point
of use.

### The second-hand blast radius, which is the case that reads wrong

prefrontal-core never calls `report_auth_failure` at all: it reads App PEMs and mints
JWTs and installation tokens itself, so a GitHub 403 lands in its own classification.
Its exposure is entirely second-hand — **a DIFFERENT consumer reporting against a shared
record takes its PEM reads dark for a credential whose key is fine.**

Worth stating separately because "a consumer reports a failure" reads like a
self-contained loop and is not one: the seat that suffers need not be the seat that
observed anything. That is the `oauth:xai` shape.

### Why this matters most for short-lived-token credentials

plexus's framing, taken verbatim into the design:

> 1-hour installation tokens: an expired-but-refreshable token is the NORMAL state,
> not a death

A credential whose entire design is short-lived tokens over a durable key is the last
thing that should be latched dead by a single refusal.

## 4. What this does NOT fix

- **It is not a fix for the reporter's own treadmill, and that is the correct
  outcome rather than a shortfall.** Confirmed from the reporting seat: their deaths
  are FAMILY revocations — the imported refresh token dies with its family, so the
  get-triggered refresh returns `invalid_grant` and latches exactly as today, **one
  round trip later**. The change costs them one extra exchange and buys them nothing,
  because there is nothing to recover.

  What it buys is the DISTINCTION. Today the vault cannot tell a revoked-but-
  refreshable credential from a dead one, at the time or retroactively, because it
  never asks. After this it always asks, and the answer is recorded. The population
  that gains is the one `cortexkit/insula#10` names — 403-latched and transiently-
  refused credentials that are alive and currently die anyway.

  Worth stating plainly because the headline case and the beneficiary are different
  populations: **the operator who found this defect is not the operator it helps.**
- **It does not make a status code interpretable.** The vault still cannot know whether
  a 403 means a dead credential or a forbidden endpoint. The contract rule stands:
  report only when you believe the credential is invalid, never merely because a call
  was refused. plexus has already narrowed its own reporting to 401 for this reason;
  insula's 403 arm is tracked at `cortexkit/insula#10`.

## 5. The two tests, co-signed as requirements

Both are mutation-verified, not comments.

**`invalid_grant` must still latch `needs_reauth` terminally.** BROCA's caution, and
their reasoning for why it must be a test is better than the requirement itself: a
stale state that absorbed `invalid_grant` **would look like the fix working.** No more
pauses is exactly the observable that success produces — right up until someone notices
callers retrying into a dead credential in a loop. Every consumer's recovery path is
gated on reaching this state, so if it becomes unreachable one dead credential becomes
an infinite retry across the fleet. plexus adds that the vector must be a real refresh
outcome rather than a synthesised one.

**A report naming a STALE version must not re-stale the fresh token that replaced it.**
prefrontal-core's mirror. The first test guards the forward direction only; this guards
the reverse. A consumer racing a rotation would otherwise mark a just-minted token stale
and drive a pointless refresh. The version-CAS property that already protects
`needs_reauth` has to protect the stale path identically, and nothing in the first test
would notice if it did not.

## 6. Open

- **How the token is marked stale.** Setting `expires_at_ms` to now is the obvious
  mechanism and re-uses the existing vocabulary, but it OVERWRITES a real provider
  fact with a local assertion, and that fact is what `ck auth usable` reports. A
  separate flag does not have that problem and does not compose with `is_stale`'s
  three existing conditions for free. Decide at implementation, and whichever is
  chosen, `usable` must not report a locally-staled token as though the provider said
  so.
- **Whether `status` should expose the stale-pending state.** No consumer reads
  `status` today, so nothing forces the question, and adding a field nobody consumes is
  how a surface accumulates. Left out unless a consumer asks.
- **Measurement owed.** plexus predicts self-healing within a minute and will re-run
  its `auth_required` recovery test against the deployed vault. That prediction is not
  evidence; whatever their run measures is the number that belongs in the runbook.
