# Serving a harness hot-path consumer: the claustrum-mode serve contract

**Status: DESIGN HALF, NOT BUILT (2026-08-24).** No code implements this. This is the
vault-side half of a two-part design; the plugin-side half (detection, migration,
cache behaviour) belongs to the anthropic-auth seat. Neither half is a contract until
both are reconciled and the maintainer has answered §8.

**Status lines rot.** This one describes a machine state that can change without a
commit in this repository, which is how the `report-marks-stale` doc came to read
`NOT BUILT` for six hours after it was deployed and serving traffic. Anyone reading
this after 2026-08-24 should verify against the running module, not against this line.

**Provenance of the numbers in this document.** Every measured count here — refresh
commits, record versions, audit rows, latencies — is a **snapshot of a live vault that
keeps advancing**, not a constant. They were taken on `icebox` between 2026-08-24T12:00Z
and 2026-08-25T11:00Z; by the time anyone reads this the refresh counts will be higher and
the version numbers will have moved. Two rules follow, and both were learned the hard way
here:

1. **A count is scoped to the deployment it came from.** An earlier version of §7 said the
   anthropic adapter had "zero successful commits **all-time**". It had zero *in this
   chain*; the maintainer's deployment had 128. The measurement was well controlled and the
   sentence silently changed population — a control arm validates the measurement, not the
   inference drawn from it. Read every figure below as *on this host, at that time*.
2. **Code claims are pinned; counts are not.** Assertions about behaviour (`is_stale` is
   unclamped, `check_limiter` holds a global lock before handle resolution, the report path
   writes `conn-N`) were re-verified at **`560c1b5`**, the tip this document is written
   against. Re-check those against the tip you are reading at; re-measure the counts
   yourself rather than trusting these.

## 1. What changes, in one sentence

Today the vault holds a *mirror* of a credential the harness owns. Under claustrum
mode the vault holds *the* credential, and the harness plugin becomes a consumer of
it — which reframes issue #4 from **vault-watches-source** to **vault-IS-source**.

That reframing is the whole point, and it is worth being explicit about why it kills
the treadmill rather than mitigating it. The treadmill exists because two copies of
one token family exist: the harness rotates its copy, the upstream revokes the family,
and the vault's copy dies holding a refresh token that can no longer be exchanged —
measured on this host, `refresh_failed / invalid_grant`, conclusive at one instance.
**With no mirror there is no second copy, so there is nothing for a rotation to
orphan.** The failure mode is removed by construction, not defended against.

## 1A. Scope: which accounts claustrum mode covers

The first draft of this document assumed claustrum mode applies uniformly to a
plugin's accounts. The plugin-side enumeration refuted that, and the refutation
improves the design rather than shrinking it.

**The blocker:** a plugin cannot be made refresh-token-blind for its MAIN account.
Main tokens live in the host's auth store and reach the plugin through a `getAuth`
callback that returns `{access, refresh, expires}` unbidden at 13 call sites. The
plugin cannot decline to receive them. This is a property of the HOST, not of the
plugin, so no plugin-side discipline can fix it.

That matters because §4.2's "a consumer must never hold a refresh token" is the
construction that makes the vault the sole refresher (§5A.1). Where the guarantee
cannot hold, claustrum mode does not deliver what it promises.

### 1A.1 Main is FROZEN. Shadow-serve alone does not carry it.

**This section has been rewritten twice. Both prior generations are preserved below,
because the reason a design changed is the part a later reader needs most.**

The host-source findings stand and are not in dispute. The OAuth schema requires
`refresh: Schema.String` but constrains nothing; a placeholder decodes (runtime-verified,
§1A.3); and **nothing in host core ever uses main's refresh token** — the only `.refresh`
reference under `packages/opencode/src/provider/` is the post-login write, with no reader,
and `grant_type=refresh_token` appears nowhere for Anthropic.

**Those findings answered the wrong question.** The host is not the only consumer of the
host's store. **The plugin re-reads `refresh` from `getAuth()` at six live entrypoints**
— `auth.loader` install, background refresh, the request-expiry gate, the sticky-401
retry, CacheKeep, and Prime — and calls the token endpoint with it. A placeholder
presented to the refresh grant returns **400 `invalid_grant`**, which is precisely the
one condition the plugin's own classifier marks `permanent: true`.

So shadow-serve as originally specified does not make main inert. **It makes main
self-inflict a permanent death on its first refresh attempt** — dropped from routing,
marked needs-relogin, Prime-ineligible. The vault would hold a live family while the
plugin independently concluded the account was dead.

**What survives.** Main is vaultable in principle, but only with an explicit persisted
**`mainCredentialSource: 'local' | 'vault'`** marker that all six entrypoints consult and
bypass. Custody must be **declared, never inferred from credential contents** — no
magic-value detection, no sniffing for a known placeholder string. Under that design the
placeholder demotes to *schema compliance only*: it exists so the record decodes, and it
is load-bearing for nothing.

| account class | mechanism | custody |
|---|---|---|
| **fallback accounts** | claustrum-mode migration | vault-authoritative; tokens live in the plugin's own sidecar, host nowhere in the path |
| **main account** | **FROZEN** — pending the declared-custody marker, §1A.6 rollback semantics, and the identity-sequencing fix | undecided; do not migrate main |

**Superseded rows, kept visible with their retiring evidence** — a design doc that hides
what it used to say cannot be audited for why it changed:

| ~~retired row~~ | why it retired |
|---|---|
| ~~main-account metering → vault-native grant~~ | shadow-serve made main a normally migrated credential; no separate grant needed |
| ~~main-account harness custody → host-side, out of scope~~ | the placeholder view was to be the host-side story; no host change required |
| ~~main account → shadow-serve, vault-authoritative, placeholder view~~ | **the plugin itself consumes `refresh` at six entrypoints; a placeholder returns `invalid_grant`, the plugin's one `permanent: true` classification. Host-inertness was established and mistaken for consumer-inertness.** |

**The generalisable error, recorded because it will recur.** Each generation of this table
was derived from a correct reading of a real artifact. The defect was scope: "the host
never reads this field" was verified in host source and then generalised to "nothing reads
this field", when the plugin writing the store is also a reader of it. **A field's
consumers are not enumerated by reading the schema's owner** — they are enumerated by
searching every component that holds the file, including the one asking the question.

### 1A.2 Why this kills the mechanism rather than mitigating it

The treadmill exists because **two parties hold copies of one family**. Measured
tonight, end to end: the harness rotated `auth.json` at 19:26:45Z, the upstream revoked
the family, the consumer's next fetch got 401 forty-nine seconds later, and the vault's
refresh returned `invalid_grant`.

Shadow-serve does not give the host a *better* copy. **It gives the host a non-copy.**
A placeholder cannot be rotated, cannot be exchanged, and cannot orphan anything. The
failure mode is not defended against — it becomes inexpressible.

### 1A.3 Q1b is a hard gate, and the thing it must actually assert

**Boot the host against a placeholder record on a throwaway profile. MUST PASS before
main migrates.**

**Update — the decode gate has since been executed, not read.** Against opencode
v1.18.21's real exported `Info` union, through the exact `Schema.decodeUnknownOption`
call `Auth.all()` makes:

| `refresh` value | result |
|---|---|
| `opencode-oauth-dummy-key` | **decodes** |
| `""` (empty string) | **decodes** |
| absent / `null` | **filtered — silently dropped** |

Corroborated at consumer level: the only `.refresh` reference under
`packages/opencode/src/provider/` is the post-login *write* (`auth.ts:211-220`, no
reader), and `grant_type=refresh_token` appears nowhere for Anthropic. So shadow-serve
is proven at the decode gate **and** at the consumer, from the repo rather than on relay.

What remains load-bearing is the second finding: **a non-decoding record is silently
filtered, and the provider then reads unauthenticated.** No error, no log line — a
fail-open. So Q1b's residual — a full boot serving a live request against a placeholder
record — must still assert on **observed authenticated behaviour**, not on a clean boot:
a placeholder that fails to decode produces exactly the same clean boot as one that
works, and the difference only shows up as an unauthenticated provider call later.

This is the §5A.10 class again — protective state absent without an error — and it is
why the gate's assertion matters more than the gate's existence.

**Normative consequence for the view writer (§4).** Because a malformed record fails
quiet, the writer MUST NOT treat a successful write as a successful *install*. Absence
of a write error is not evidence the record is readable: the writer's own view and the
consumer's view differ precisely in the case that matters. After every view write the
writer MUST read the record back **through the same decode path the host uses** and
require a positive result. Two corollaries:

- The proven-decoding placeholder literal is pinned, not free-form. `opencode-oauth-dummy-key`
  and `""` are proven; *any other* placeholder is unproven and MUST be re-gated before use.
- Omitting `refresh` is not a safe simplification. Absent and `null` are the two values
  that silently drop the whole record, so the failure mode of "leave it out" is total and
  invisible — strictly worse than a placeholder.

One bounded exposure to record: interactive login briefly writes a real credential into
the host's store before the import replaces it with the view.

## 2. The consumer class is new, and that is the risk

Every consumer the vault has served so far is a *background* reader: insula polls on
a 60s sweep, tolerates a 300s backoff, and degrades to a stale quota reading when the
vault is unavailable. Nothing in the current design was built for a caller whose
failure is visible to a human in the same second.

A harness auth plugin is the opposite:

- it is called **on the model-call path**, so its latency is user-perceived
- it has **no useful degraded mode of its own** — a request either carries a valid
  token or fails
- its failures are **loud and immediate**, not a stale number in a status table

Everything below follows from that difference.

## 3. What `credential.get` guarantees at model-call latency

### 3.1 Measured, on this host, 2026-08-24

```
spawn only (ck-auth help)                     median  0ms   n=12, 0 failures
offline store: open + lease + decrypt + list  median  1ms   n=10, 0 failures (max 34ms cold)
live loopback admin round-trip (ck-auth status)median 42ms   n=12, 0 failures (max 60ms)
```

**The store read is not the cost.** A decrypt-and-return is ~1ms.

### 3.2 What those numbers do NOT establish

The 42ms figure is an admin round-trip. It **includes** a master-key
challenge-response the plugin path would never perform, and **excludes** the
handle-resolve and limiter admission the plugin path always performs. It is neither
an upper nor a lower bound on the plugin's per-call cost — it measures a different
operation over the same transport.

Reporting 42ms as "the serve latency" would be exactly the error this codebase's own
measurement discipline exists to prevent: a real number, correctly obtained, applied
to the wrong population. **The plugin path is unmeasured, and it cannot be measured
because it does not exist yet.**

### 3.3 The benchmark this design requires before implementation

A number must exist before the fail-open policy in §4 can be tuned, because the
cache TTL and the retry budget are both sized against it.

```
harness:   a persistent route connection, handle-keyed, warm daemon
operation: credential.get on a live oauth:anthropic record with a NON-stale token
report:    n >= 200, median / p95 / p99 / max, with exit status checked per call
compare:   the same distribution while a second connection drives concurrent gets,
           to expose the limiter mutex in §3.4
```

The handle must reach the probe **from a file or an inherited fd, never argv** — a
capability handle is a bearer secret and `ps` is world-readable.

### 3.4 Two hot-path hazards visible in the current code

**The limiter is a single global mutex, taken on every get, before handle
resolution** (`read_surface.rs`, `check_limiter`). Every concurrent get serializes
through `self.limiter.lock().await` for the duration of an admission decision. For
insula's one-connection 60s sweep this is invisible. For a plugin issuing bursts of
concurrent model calls it is a shared contention point, and it is taken *before* the
work it guards. This needs the concurrent measurement in §3.3 before anyone claims it
is fine.

**The refresh is synchronous and inside the call.** `RefreshEngine::get` returns the
stored record immediately when the token is fresh, but when `is_stale` is true it
takes the single-flight lock, writes a durable intent, and **makes an upstream OAuth
call** before returning. The staleness skew is `DEFAULT_EXPIRY_SKEW_MS = 60_000`, so
every token crosses this boundary once per token lifetime.

The single-flight design means N concurrent gets produce one upstream call rather
than N — good — but the N callers all wait for it. **On a model-call path that is a
user-visible stall of one provider round-trip, once per token lifetime, and it is not
optional today.**

Two candidate answers, and this is a maintainer decision rather than mine:

- **`min_ttl_ms` from the plugin.** The parameter already exists on `GetParams`. A
  plugin asking for a token with, say, 5 minutes of life left moves the refresh
  *earlier* but does not stop it landing on some unlucky call.
- **Proactive refresh.** The engine has no background expiry sweep — verified at
  source; every refresh happens on-demand inside a `get`. Adding one would take the
  stall off the hot path entirely, at the cost of a new scheduled writer and the
  lease/fencing questions that come with it.

I do not think this design should choose. I think it should refuse to ship the plugin
path without one of them being chosen deliberately, because the default is a
periodic user-visible stall that nobody decided on.

## 4. Fail-open: what the plugin may cache, and the distinction that matters most

The requirement is that a claustrum reload must never brick a model call. The
mechanism is a plugin-side last-known-token cache. The **hard part is not the cache,
it is knowing when the cache is allowed to answer.**

### 4.1 The rule

> **A cache may substitute for an ABSENT vault. It may never override a REFUSING
> one.**

Unreachable and refusing are different facts, and they arrive over the same wire:

| vault says | meaning | plugin may serve cache? |
|---|---|---|
| connection refused / timeout / reload in progress | **absent** — no verdict was reached | **yes**, per §4.2 |
| `credential_unusable` / `needs_reauth` | **verdict** — the token is dead | **no**, fail the call |
| `not_found` | **verdict** — no such credential | **no**, fail the call |
| `corrupt` / `refresh_failed` | **verdict** — do not retry blind | **no**, fail the call |

Serving a cached token past a `needs_reauth` is not resilience. It is sending a token
the vault has already established is dead, to a provider that has already refused it,
and converting one clean failure into a retry storm against an upstream that may rate
limit the account.

This distinction is not hypothetical on this host. A latched credential and an
unreached one presented **identically** on the consumer wire until `a760391` — the
absent-entry defect — and the module's own contract read absence as "not fetched yet."
A cache policy keyed on "did I get an answer" rather than "what did the answer say"
would have served a dead token for the entire 10-minute latch window measured
tonight.

### 4.2 What may be cached, and for how long

**What:** the served access token, its `expires_at_ms`, and its `record_version`.
Never the refresh token — the plugin has no refresh path in claustrum mode, so
holding one is pure blast radius.

**How long:** until the token's own `expires_at_ms`, and no longer. **No arbitrary
TTL.** The token carries its own bound and the provider enforces it; inventing a
second, shorter number adds a failure mode without adding safety, and inventing a
longer one serves a token the provider will reject.

**Encrypted at rest**, if written to disk at all. A plugin cache file is a token
sitting in the harness's data directory with no vault protecting it; the case for
memory-only is strong and I would like the plugin half to argue it explicitly rather
than default to a file.

### 4.3 Rejoin

On reconnect the plugin issues a `get` with `min_ttl_ms` set, which forces the
engine's staleness path and returns a token guaranteed to outlive the caller's
window. The `record_version` in the response is the rejoin signal: **a version
different from the cached one means the vault repaired or replaced the credential
while the plugin was away**, and the cache must be dropped rather than merged.

A version *equal* to the cached one is not proof of health — it is proof the record
did not change, which is also what a quiet, unexercised, revoked credential looks
like. The plugin should treat a successful `get` as the health signal and the version
purely as a cache-invalidation key.

### 4.4 Reload specifically

A reload is planned absence. The daemon knows it is going down; the plugin does not.
The current health surface reports `lease_held` and `ready`, and a fenced-out daemon
already reports `ready=false` — but a plugin that polls readiness is not on the hot
path, and one that does not poll learns about the reload from a failed call.

The design should state whether claustrum owes consumers a **drain signal** before a
planned restart. I believe it does — it already supports `--drain-ms` on restart,
which is what kept insula's samples unbroken across two module restarts today — but
"the drain happened to cover it" is not a contract.

## 5. The auth.json view, and a consequence nobody has raised

Legacy readers need a file. Subconscious ruled that rename semantics are required and
that no daemon path rails exist, so claustrum writes the view itself: write to a
temporary file in the same directory, `fsync`, then `rename(2)` over the target. A
reader either sees the whole old file or the whole new one, never a partial write.

**The view is a projection, never a source.** Claustrum must never read it back to
learn anything, and the design should say so in a way that survives someone later
adding a "reconcile from auth.json" convenience.

### 5.1 Writing the view destroys a diagnostic signal that is in use today

This is the part I would not have seen a week ago, and it is worth stating carefully
because it is a real cost being paid for a real benefit.

`auth.json`'s **mtime is currently the only available evidence of an upstream
rotation.** Tonight, deciding whether a credential surviving past its recorded
maximum was a meaningful result or a quiet night, the discriminator was exactly this:

```
auth.json mtime   2026-08-24T15:33:58Z
credential seal   2026-08-24T15:42:12Z
→ no rotation since the seal; the credential is UNTESTED, not proven durable
```

If claustrum begins writing `auth.json` on every credential change, that mtime becomes
**a record of claustrum's own writes**, and it will move on refreshes, imports and
view rewrites that have nothing to do with an upstream rotation. The signal does not
degrade — it inverts, because the file will look most recently rotated exactly when
the vault has been busiest.

Three honest options, and I lean to the third:

1. **Accept the loss.** In claustrum mode the mirror is gone, so upstream rotation
   stops being the failure mechanism, and the signal it feeds stops mattering. True —
   but only *after* migration, and the migration period is precisely when both
   mechanisms coexist and someone will need to tell them apart.
2. **Write the view elsewhere** and leave `auth.json` to the harness. Preserves the
   signal, defeats the purpose — legacy readers read `auth.json`.
3. **Record provenance in the audit chain.** Claustrum already writes an append-only
   chain with exact `ts_ms` for every credential change. If every view write appends a
   `view_write` row, then "did the harness rotate, or did we write?" is answerable by
   comparing the file's mtime to the chain, instead of being unanswerable. This costs
   one audit row per write and turns a signal we are about to break into one that is
   strictly better than what exists — mtime records only the most recent rotation,
   while the chain records all of them.

That last point generalises beyond this file: **when a system takes over writing an
artifact that something else was reading as evidence, it inherits an obligation to
publish the evidence it displaced.**

## 5A. Two consumers on one family: what the vault does and does not guarantee

The consuming module raised this at source and it is the sharpest objection to the
design. Answered here against the code rather than against intent.

### 5A.1 Sole-refresher is structural, but only for the COMMIT

A consumer cannot commit a refresh. `do_refresh` is vault-side, single-flight per
credential, and its commit is CAS-gated on `record_version`. **No path exists for a
consumer to write a rotated token into the vault.**

But `GetParams` carries `force_refresh: bool`, and it is unbounded. The limiter
alarms and deliberately does not refuse, and its own comment records the consequence:
a granted consumer can drive `force_refresh` without limit, each one a real upstream
token exchange, bounded only by an audit entry nobody reads in real time.

With independent families that is one consumer's problem. **With a shared family, one
looping consumer rotates the family for every other holder** — not by committing, but
by asking the vault to. "The vault is the sole refresher" remains true and stops being
sufficient.

Two requirements follow, and the first is why §4.2 forbids caching the refresh token:

- **A consumer must never hold a refresh token.** With no refresh token a consumer
  has no out-of-band rotation path, so the vault is the only actor that can move the
  family — by construction rather than by convention.
- **`force_refresh` needs a bound** once more than one consumer holds a handle to the
  same record. An alarm is not a bound.

### 5A.2 A consumer report is a hint; the vault's refresh is the verdict

This is already the shipped behaviour for refreshable records, and today's
measurement is the proof:

```
15:26:56Z  consumer report (401)  ->  marked STALE, record stays ACTIVE
15:31:57Z  vault's own refresh    ->  invalid_grant -> needs_reauth
```

With one consumer that was a nicety. With two it is load-bearing: a plugin 401 on
`/v1/messages` and a quota consumer's 401 on `/api/oauth/usage` are not necessarily
the same fault, and a plugin-side misconfiguration can produce a 401 that says nothing
about the credential. Under latch-on-report, one consumer's bug kills a healthy
credential for every other consumer.

**The invariant is not currently true as stated.** A report against a NON-refreshable
record still latches immediately (`consumer_report_latch` → `invalidate_if_version_reported`).
Today's measurement exercised the refreshable arm only. Anyone writing the
second-consumer decision must state this as a change, and must say what a
non-refreshable record's alternative is — for a static api-key there is genuinely no
recovery the vault can attempt.

Also: **the surface accepts 403 as well as 401.** The 2026-08-17 incident is recorded
in situ at the report site — a consumer reported GitHub's 403 ("valid token, missing
one permission"), which killed a seconds-old healthy credential, after which every
subsequent call refused at resolution and disabled the logging built to diagnose the
403. Its conclusion is the contract rule the second-consumer decision should cite:
**report only when you believe the credential is invalid, never merely because a call
was refused.**

### 5A.3 Attribution does not survive a second consumer

`report_auth_failure` writes `actor = format!("conn-{connection_id}")`. That names the
**route channel, not the consumer**: numbers are assigned per route binding and reused
as bindings come and go, so two rows sharing `conn-1` are not evidence of the same
reporter, and one reporter across reconnects appears under several numbers.

With one consumer this cost nothing. With two, "which consumer reported this" becomes
the first question of every incident review, and the chain answers it plausibly and
wrongly.

The identity is **already arriving and already discarded**: `Principal::Reserved`
carries a `module_id`, the daemon stamps it at route-bind time, this module keeps it
per channel for the admin gate, and the report path does not look. Wiring it is a
separate decision from recording the failure — and the launch nonce is explicitly not
the value to store, since these columns are non-secret by construction. A per-bind,
derived, non-secret incarnation tag is the shape.

**This is a blocker for the second-consumer decision, not a nice-to-have.**

#### Field instance, 2026-08-24: three actors, two labels, and both attributions arrived by testimony

This stopped being an argument the same evening it was written. Two imports landed
three minutes apart on the credential under measurement:

```
474 | 20:55:21Z | import | route-admin
473 | 20:52:03Z | import | offline-cli
465 | 15:42:12Z | import | route-admin   <- this seat's own re-seal, SAME LABEL as 474
```

Three candidate actors, and the chain separated only two paths. Resolution took two
rounds of chat: the coordinating seat claimed 473 (an emergency re-seal, its runbook
command takes the offline path by construction), and 474 turned out to be a THIRD seat
running a connected re-seal from a runbook it held from before this credential had a
designated custodian.

**Both attributions arrived as testimony. Neither came from the chain.** That is the
failure stated at full strength: an audit chain exists precisely so that "who did this"
does not depend on someone volunteering it afterwards.

474 is the sharper half. `route-admin` is the label **this seat's own writes carry**.
Had the reader been less than certain of his own actions, he could not have excluded
himself as the author of a write to a credential in his custody.

**A field that cannot exclude the reader is not attribution.** The chain records a
*path*, and a path is shared by every actor who takes it — including whoever reads the
row. That is stronger than "the actor names a channel rather than an identity," and it
holds for WRITES, not just reports: the `conn-N` case at worst mislabels who
complained; this one cannot establish who changed the credential.

The collateral coordination finding is worth recording separately, because it is a
fleet hazard rather than a schema one: **a runbook outlives the custody map it was
written against.** The third actor acted correctly by the procedure it knew; the
procedure predated the existence of the seat that now owns the credential.

### 5A.4 Refresh triggering has two entry points, and only one is named

`force_refresh: bool` is the obvious one. **`min_ttl_ms` is the other**, and it triggers a
real refresh through the identical path:

```rust
// engine.rs:232
let wants_refresh = force_refresh || stale_pending || self.is_stale(&initial, min_ttl_ms);
// engine.rs:277  (inside is_stale)
if let (Some(min_ttl), Some(exp)) = (min_ttl_ms, oauth.expires_at_ms) {
    return now.saturating_add(min_ttl) >= exp;
}
```

Same single-flight lock, same durable intent, same upstream exchange. It does not fail
closed.

**Under a shared family this makes the refresh schedule a function of the most
demanding reader.** The consuming module today passes `min_ttl_ms = 120_000` from six
separate call sites as a bare literal — no named constant, no doc comment, no test
asserting the value. Six identical numbers that look like six independent decisions.
Under claustrum mode that literal is the rotation cadence for every credential the
vault holds, expressed nowhere as a schedule.

**A TTL floor is bounded only while `min_ttl < token_lifetime`, and nothing enforces
that.** `min_ttl_ms` is caller-supplied and unvalidated — no clamp, no cap, no
validation anywhere between `GetParams` and `is_stale`. A caller passing 24h against
an 8h token makes `now + min_ttl >= exp` permanently true: every get refreshes. That is
`force_refresh` with no boolean to grep for, no name suggesting force, and identical
upstream cost.

So the attractive proposal — replace the boolean with a TTL floor, which is
self-limiting because a token can only near expiry once per lifetime — needs a bound.
Unclamped it is strictly worse than the boolean: same blast radius, less visible.

**Correction — my proposed bound was unsound, and the maintainer's replacement removes the
proxy entirely.** I proposed clamping against *the record's own lifetime*. The only lifetime
proxy available pre-refresh is `expires_at_ms - updated_at_ms`, and `updated_at_ms` is the
last record **write**, not the token's issue time. For an imported credential those differ
by however long the token had already lived before import, so the computed lifetime is an
underestimate and the clamp would **refuse satisfiable requests** — failing in the one
direction a caller cannot route around, which is worse than the footgun it was meant to fix.

The sound form is **post-refresh**:

> A freshly minted token that **still** fails the caller's demand proves the demand is
> unsatisfiable for this credential.

One exchange, then a definite answer, and no proxy anywhere in it. Cost is bounded at one
refresh per unsatisfiable caller rather than one per get.

**And the sharper half of this finding is not the missing bound at all** — it is that the
audit which produced the `force_refresh` trade-off never enumerated its own surface:

```
force_refresh   documented as unbounded, with the DoS trade-off stated at the limiter
min_ttl_ms      reaches the SAME exchange, with no such note anywhere
```

A reviewer who finds the documented lever reads the reasoning and moves on, with no cue that
a second door exists. So this is not "a clamp was forgotten" but "a completed analysis was
scoped to one of two callers of the same code path" — the same failure shape as the
all-time/scope error in §7, one layer up.

The module's own header already groups them:

> Refresh-triggering reads (`force_refresh` / a tight `min_ttl_ms`) and
> `report_auth_failure` are the rate-sensitive paths the limiter watches.

The limiter's detailed comment then analyses only `force_refresh`. **The surface names
the hazard in one place and analyses half of it in another**, so a reader who finds
either believes they have the whole picture. Worth fixing in the same change.

### 5A.5 The TTL path is exercised — and never by anthropic

Measured, because the obvious supporting evidence turned out to prove something else.

**The mechanism works.** `antigravity:google`, from this host's audit chain:

```
383 refresh_commit intervals
min 58.0  p25 58.1  median 58.5  p75 58.8  max 1150.8 minutes
382/383 (100%) inside a 57-63 minute band
```

A ~60-minute token refreshed ~2 minutes early, 383 consecutive times. That is the
120s TTL demand firing on a metronome; the single 1150-minute outlier is an outage gap.

**For anthropic it has never fired and could not have:**

```
anthropic token lifetime       8.0h     (expires_in 28800, recorded provider response)
TTL demand fires at            7.97h    after seal
harness rotation interval      4.00h    fixed cron, revokes the family
shortfall                      3.97h    the credential is killed at half the trigger
```

The live record's expiry is inside the encrypted envelope and is not published by
`ck-auth status`, so 28800 comes from the adapter's recorded provider fixture rather
than tonight's record. The conclusion tolerates a wide error margin: anything above
~4.05h gives the same answer.

**Correction — an earlier version of this table said `max credential lifetime EVER 3.95h`,
and that figure was an artifact of our own behaviour.** It came from a seal→verdict series
which decomposes as `I + 301s − L`, where `I` is the rotation interval and `L` is the
operator's re-seal lag. A death cannot be *diagnosed* before the 301s non-transient backoff
verdict, so `L ≥ 301s` always — meaning that series measured **our own response latency,
inverted**: a fast re-seal produced a long apparent lifetime, a slow one a short one. The
"0.18h shortest lifetime" was a credential sealed 3.8h after its rotation, not an
11-minute token.

Recovered from lanes that cancel `L` — consumer-report timestamps (± one poll cycle) and
verdict-to-verdict deltas (which cancel both `L` and the 301s exactly):

```
25 death episodes, 2026-08-14 -> 08-24
24 inter-episode intervals, ALL integer multiples of 4.00h
23 of 24 within +/-4 min of exact; larger gaps are MISSED rotations, not long intervals
live predictions since:  +11s  ·  +14s  ·  +21s
```

So the mechanism is a **fixed 4.00h cron**, not a distribution with a tail, and the
conclusion here gets sharper rather than weaker: the TTL path is not unreached because
tokens die young, it is unreached because an external schedule revokes the family at half
the trigger point. Post-migration that schedule stops being what kills the credential, so
the TTL path goes live at a **predictable** time rather than a probabilistic one — which is
what makes §3.3's benchmark schedulable.

The seal (import) lane is the one lane that can never be used for this: it is the only one
that carries `L`.

**So "zero forced refreshes across every version to date" (42 as of 2026-08-25T11:00Z, and
still climbing by one per re-seal) is evidence of the treadmill, not
evidence that the TTL is well-behaved.** The credential has always died long before its
token neared expiry. The google series is the evidence that actually supports the
shape — and it is stronger.

**Migration risk, in its own right:** post-migration, anthropic reaches its 8h expiry
for the first time, and the consuming module's TTL demand becomes live on a path that
has never run for this credential. The treadmill has been *masking* that path, not
exercising it.

The reassuring half: google demonstrates the destination state 383 times over, in the
same engine, without incident. What remains unknown is anthropic's own adapter on that
path — §7, still zero successful commits.

### 5A.6 429 is never a report, for two different reasons

The plugin surface has two distinct 429s and collapsing them would ship a dangerous
rule.

**On the quota poller (`/api/oauth/usage`)** — the same endpoint the quota module
polls — a 429 is a *cross-consumer* effect: two consumers drawing on one account's
bucket. The operator has attested this endpoint rate-limits **per account**, so sharing
a token family does not change the numbers. Reporting here would let one consumer's
polling kill a credential for the other.

**On the hot path (`/v1/messages`)** a 429 is quota-window exhaustion or model-tier
rate limiting — **not** the usage bucket. This is high-volume routine operation: a
five-hour window running out is expected, drives fallback-account routing, and happens
by design. **A plugin reporting on hot-path 429 would kill the credential every time a
window ran out.**

**The operator's per-account attestation covers `/api/oauth/usage` only.** It must not
be silently extended to `/v1/messages`, which is a different endpoint with different
limiting semantics.

Rule: **429 never reports, on either surface** — with both reasons recorded, because a
reader who knows only the cross-consumer reason will not recognise the hot-path case,
and the hot-path case is the one that fires constantly.

### 5A.7 Migration removes the only thing exercising the failure paths

The treadmill is currently the sole regular exerciser of every credential-failure path
in production, across both modules: the consumer's report path, its 300s backoff, its
identity-unverified rendering, the recovery transition, and this vault's
report-marks-stale sequence.

Killing the treadmill removes that fault injector. The paths do not become correct;
they become **unexercised** — and "unexercised" is a claim about **a deployment**, never
about the code. On this host the anthropic refresh adapter has zero successful commits and
has only ever been exercised in the failure direction; in the maintainer's deployment the
same path has committed 128 times (§7). Both are true, and only the first is about this box.

A path that runs only on a rare event, and has not run since its last edit, is the
delayed-fuse class at production scale: correct until a specific sequence occurs, then
confidently wrong, with no observation in between to contradict it. **A gate or guard placed
after every other check is the same shape** — `scripts/gate.sh` carried a broken test-count
summation from 2026-08-11 until 2026-08-25 because every failing run short-circuited before
reaching it, so its first real execution was two weeks after it was written (fixed in
`560c1b5`; found only because an unrelated fix let control flow arrive there).

The consequence for migration is the uncomfortable one: **the instrument that will validate
claustrum mode cannot itself be validated before claustrum mode exists.** The most that can
be done in advance is to prove an arm's *mechanics* without its event — that the producer's
emitted token matches what the consumer greps for, that the extraction parses a real row,
that the branch literal matches the parsed value — which excludes typos and dead signals but
is not the same as having fired.

**Migration should ship with a deliberate way to exercise these paths** — a
fault-injection surface, a scratch credential that can be revoked on demand, or a
periodic drill. The alternative is discovering the fixes are broken during the incident
they were written for.

### 5A.8 Capability handles are shareable across processes

Asked by the plugin half, because they run multiple concurrent host processes and
needed to know whether handle acquisition must join their cross-process lease
registry.

```sql
CREATE TABLE handles (
  handle_hash    TEXT PRIMARY KEY,
  credential_id  TEXT NOT NULL,
  created_at_ms  INTEGER NOT NULL,
  revoked        INTEGER NOT NULL DEFAULT 0
);
```

```rust
// store.rs resolve_handle
SELECT credential_id FROM handles WHERE handle_hash = ?1 AND revoked = 0
```

**No pid, no owner, no connection binding, no lease.** A handle is a bearer capability
scoped to one `credential_id`; any process presenting it resolves it, concurrently,
with no coordination.

- **Per-credential-id, not per-process.** N processes share one handle per migrated
  account.
- **Acquisition needs no cross-process locking.** Nothing in resolution serializes.
- **The limiter is per-connection**, keyed `(connection_id, handle)`. N processes are
  N connections with independent budgets — permissive rather than restrictive, and a
  misbehaving process is not masked by well-behaved siblings.
- **Revocation is shared fate.** `revoked = 1` kills the handle for every process at
  once; there is no per-process revoke.

Security consequence: **possession is authorization.** A handle has no holder binding,
must not transit argv (`ps` is world-readable), and one leaked from any process is
leaked for all of them.

**Consumer obligation — handle-blindness.** Because possession is authorization, a
consumer must keep handles out of every surface that persists or exports process
state: diagnostic dumps, cross-process shared state, logs, crash reports. The plugin
half mandates exactly this in its dump subsystem and its cross-process sidebar state,
which is the correct consequence of the bearer-secret property rather than extra
caution. Stated here it becomes a two-sided contract term: **the vault issues a bearer
capability with no holder binding, so the consumer owes it blindness.**

#### 5A.8.1 Publishing a handle identifier: what may be joined on, and the invariant that keeps it safe

Asked when a snapshot feed needed to name a credential for join purposes. Composing
"carry the handle in snapshots" with "write snapshots as world-readable JSON" publishes a
**bearer capability with no holder binding** into a readable file — the property above,
reached by a transport nobody had composed yet. So: **the raw handle never publishes.**

**Join on `credential_id`.** It is the publishable half by construction — unredacted in
`Debug`, while the capability sits behind a redacting `Debug` — and it introduces no new
identifier, no correlation surface, and no invariant to maintain.

**`handle_hash` is also safe, and is the second lane** where a handle rather than a
credential must be named:

- **Not a preimage risk.** `mint_handle` draws 32 bytes from `getrandom` — 256 CSPRNG bits
  behind a domain-separated SHA-256 (`cortexkit-credentials/handle/v1`). Nothing to search.
- **Structurally unusable on the wire.** Every handle-consuming path — `resolve_handle`,
  `revoke_handle` — takes the **raw** handle and hashes it internally. A presented hash is
  hashed *again* and matches nothing, so it cannot read and cannot revoke.
- **Already assumed leakable.** The store persists only the hash precisely so that a
  database compromise yields no usable handle. Publishing it grants exactly what a full
  read of `store.db` grants — an exposure the threat model already accepts.

> **CUSTODIAL INVARIANT.** No wire route, admin op, or CLI verb may accept a
> `handle_hash` as an **input**. Handle-consuming paths take the raw handle and hash it
> server-side. Publishing hashes is safe ONLY while this holds.

That invariant is written down because **the safety is an absence**, and this file already
argues (see `revoke_handle`'s own note on the missing un-revoke verb) that an absent
mechanism cannot be found by reading code: no symbol, no failing test, nothing to grep.
The concrete way it breaks is a reasonable feature: someone adds
`ck-auth revoke-handle --hash <h>` for operator ergonomics — defensible in isolation,
since an operator can already read hashes out of the DB — and **every previously published
snapshot retroactively becomes a revocation DoS list.** Safe alone, unsafe only in
composition with a decision made in another repo months earlier.

Two properties to accept explicitly rather than discover: the hash is a **stable
correlator** (an observer can link snapshots over time and confirm two entries name the
same handle — metadata, not capability), and a **possession oracle** (holding hash `H`
confirms it belongs to a handle you already hold). Truncation is *not* recommended: it buys
little and creates a length a future reader will mistake for the full value.

**Preference, stated as a rule rather than a taste:** `credential_id` wins not because
`handle_hash` is unsafe but because its safety is **unconditional**, while `handle_hash`'s
is conditional on an invariant being maintained. Prefer the option that cannot be broken
by a later well-intentioned change — invariants decay, and absences are invisible.

### 5A.9 The hot path should not report at all

The plugin's own classifier defines `permanent` as `400 + invalid_grant` body, and
treats **401 as never permanent** — it is access-token rejection, answered by
refresh-and-retry. So "report on 401" and "gate reports on the permanent classifier"
cannot both hold: gating on the classifier means the plugin essentially never reports.

**That is the correct outcome, and it is a decision rather than an accident of two
rules failing to compose.**

- The vault learns credential death from **its own refresh attempt**. Measured today:
  the consumer's 401 marked the record stale, and the vault's own refresh returned
  `invalid_grant` and produced the verdict.
- A consumer report is an **accelerator, not an oracle** — it saves the vault at most
  one token-lifetime of delay before it discovers the death itself.
- On a hot path that accelerator is worth little and costs a great deal: a hot-path
  consumer sees 401s for reasons unrelated to credential validity, and 2026-08-17 is
  what that costs.

So the rule is **the hot path does not report** — not "reports carefully". This also
dissolves the two-consumer risk in §5A.2: if the hot-path consumer never reports, the
remaining reporter is the quota poller, whose 401 genuinely does concern the
credential.

Related, from the plugin's own audit of its code: `isPermanentRefreshError` has a
legacy rule treating bare `status == 400` as permanent **without body inspection** —
the 2026-08-17 shape exactly. Fixed or excluded before any report integration.

### 5A.10 Refresh-outcome signals: the vault holds the facts and does not publish them

The plugin machinery that RETIRES under claustrum mode is larger than the refresh call
site. Several pieces **consume refresh outcomes** without performing refreshes, and
they need vault-sourced equivalents or they degrade silently.

What the read surface exposes today:

```
credential.status -> ready, last_error_code {NeedsReauth|Corrupt|None}, lease_held, record_version
credential.get    -> payload, expires_at_ms, record_version, project_id, account_id, email, org_name
```

| plugin machinery | vault signal today | verdict |
|---|---|---|
| permanent-invalid classification | `status.last_error_code = NeedsReauth` | **available** |
| pool completeness / re-login guidance | same latch, per credential id | **available** |
| last refresh result (reason) | — | **absent from the surface** |
| transient-vs-permanent distinction | — | **absent from the surface** |
| 429 backoff state | — | **no vault equivalent exists** |

**This is the board ask's lead motivation, in the plugin half's words: without
published refresh outcomes a migrated account degrades SILENTLY — the plugin keeps
routing to an account the vault knows is failing.**

It is the only instance of the publish-gap pattern with a live traffic consequence.
Today the treadmill masks it: a dead credential is dead for every consumer inside a
minute, so "failing but unpublished" has no time to exist. Post-migration, with the
vault repairing what it can, a failing-but-unpublished account is one the plugin will
keep selecting.

**The vault HAS the missing facts.** `auth_events` records `kind`, `provider_status`
and `detail` for every refresh outcome — `refresh_failed / invalid_grant` is exactly
the row measured tonight. It is simply not on the read surface.

The 429 row is different in kind: **the vault has no backoff concept at all.** The
engine refreshes strictly on demand inside a `get`, with no scheduler and no retry
state. A consumer's backoff is entirely the consumer's, so if the plugin's 429
machinery retires, nothing replaces it. That must be an explicit decision, not a
discovery.

#### The pattern, stated once

This is the third instance of one shape: **the vault holds the fact and the surface does
not publish it.**

1. ~~`record_version` — not on the consumer wire~~ — **RETRACTED, this entry was wrong.**
   `record_version` IS on the consumer wire: `get` has always returned it and `status`
   returns it too. Corrected below — the real defect is different and sharper.
2. `module_id` — arriving at route-bind, discarded by the report path, so attribution
   fails (§5A.3).
3. Refresh outcomes — recorded in `auth_events`, absent from the read surface (here).
4. **`stale_pending` — measured, and the cleanest specimen of the shape** (§5A.10.1).

Each was invisible while there was one consumer. **A second consumer converts them from
unused to load-bearing at once**, which is why they should be decided together rather than
one incident at a time.

#### 5A.10.1 Measured: what `credential.status` publishes across a real episode

Everything above was reasoning about the surface. This is a reading of it — taken 2026-08-25
during a real treadmill episode with a probe built for the purpose, because
`credential.status` had **no caller anywhere on the box**: no CLI verb, and the only in-repo
references were the route constant, one e2e test, and the module's own health poll. A claim
about what a consumer would see had no way to be checked.

```
vault-side truth              what credential.status publishes
active       stale=0    ->    ready=true   err=null            v=43
active       stale=1    ->    ready=true   err=null            v=43   <- 12 samples, 5 min
needs_reauth stale=1    ->    ready=false  err="needs_reauth"   v=43
active       stale=0    ->    ready=true   err=null            v=44   (after re-seal)
```

**The verdict IS published.** `ready:false` + a typed `last_error_code` land within one
sample of the chain row. Any consumer polling `status` learns a latch happened.

**`stale_pending` is NOT published.** For the entire five-minute stale window the surface
reports a healthy credential while the vault has already recorded a consumer's 401 and
marked the record stale. `StatusResult` has no field for it.

Defensible in isolation — `ready` answers *"would a get succeed"*, and that is still true
until the forced refresh is attempted. The consequence is structural: **a second consumer,
or the same one after a restart, cannot learn that a stale mark is outstanding.**

And the reason it has never been reported is the part worth carrying into any
"does this matter" conversation. The current consumer calls only `credential.get`, and
report-marks-stale keeps the record ACTIVE *precisely so the next `get` forces the refresh* —
so a `get`-path consumer receives the stale mark's entire benefit without ever needing to see
it. The gap bites only consumers that poll `status` to DECIDE.

> **The missing representation is invisible to the consumer whose path makes it
> unnecessary — and that consumer is the one who will be asked whether the gap matters.**
> Asked from its own vantage it would answer "no impact", be right about itself, and wrong
> about the surface. (Established by the insula seat checking my claim against its own code
> rather than accepting it.)

A claustrum-mode plugin is exactly a `status`-polling consumer for its health surface, so
this moves from theoretical to load-bearing the moment §1 ships.

#### 5A.10.2 `record_version` is exposed — and is not a state cursor

Correcting the retracted entry above, since the correction matters more than the error.

The field is published on both `get` and `status`. But per `read_surface.rs:412-428`, and
confirmed by the measurement above:

```
bumps on    refresh, replace
NOT on      invalidate   -- a version-GATED compare-and-set would defeat itself by
                            moving the version it matched on
NOT on      reactivate   -- clears a wrong verdict WITHOUT touching stored material
```

Measured: **the version stayed at 43 across the entire death and latch**, moving only on the
re-seal. So the original entry's *conclusion* survives its wrong premise — a consumer cannot
distinguish a latch from a recovery by the version — but for the opposite reason. The field
is there; it does not move.

> **Join on `record_version`. Decide on `ready`.**

The failure mode of getting this wrong is unusually quiet: a version-only poller keeps a
`reactivate`-repaired credential marked dead **indefinitely**, and it does so while
observing a *stable* value. Nothing errors. The consumer sees an unchanging number and
concludes nothing changed — true about the material, false about the verdict.

This is a real constraint rather than an oversight: `record_version` is bound into the
envelope's AAD, so moving it means re-sealing the record, and re-sealing on the **repair**
path would put a decrypt-and-encrypt cycle on the one route that exists to recover from a
wrong verdict — with a halfway failure leaving a corrupt record where a recoverable one
stood. The version tracks the MATERIAL; `ready` tracks the VERDICT; a repair can move either
alone.

**Bearing on the maintainer's Q13 answer** (claustrum#9), which recommends `record_version`
as the clock-free join key a consumer should log: that advice is right for *"which serve
produced these bytes"* and silent on this. Both halves belong together, or the join key gets
adopted as a state cursor by the next reader.

### 5A.11 The fourth bucket: plugin state keyed on token VALUES

A class the vault-side analysis missed entirely, found by the plugin enumeration.

Several pieces of plugin machinery stay plugin-side but are **keyed on the token
itself** — refresh backoff by `tokenHash`, quota cache, profile binding, hydration
dedup by `tokenFingerprint`. Under claustrum mode the vault rotates on its own
schedule, so every one of those keys changes without warning and **the protective
state silently evaporates**. No error, no log line: the backoff that was suppressing a
retry storm simply has no entry for the new token.

That is the delayed-fuse class again, at integration scope: correct until a rotation
occurs, then quietly absent.

**Re-key on a stable identity before migration.** The plugin's `authLineageId`
corresponds to this vault's declared `account_ref`, and this is the strongest argument
for declaring `account_ref` at import (§6): it gives every consumer a rotation-stable
key, which `oauth:anthropic` currently lacks entirely.

It also feeds §5A.4: the more expensive a rotation is for consumers, the more the
`min_ttl` floor matters — rotation cost is an input to that choice, not a side effect
of it.

## 6. The write path: an import a plugin can call

Interactive login stays plugin-side. The plugin completes the OAuth flow, holds the
resulting grant, and imports it. What does not exist today is an import a
non-operator can perform.

Today's path is `ck-auth import --key-path /etc/cortexkit/master.key` — it
authenticates with the **master key**, it audits as `actor=route-admin`, and it raises
an `admin_write` alarm on every use (47 of 47 alarms in this host's chain are exactly
this). A plugin cannot hold the master key. If it could, claustrum mode would be
strictly worse than the mirror it replaces.

So the import op needs an authorization that is **not** the master key:

- a **write-capable capability handle**, distinct from the read handles consumers hold
  today, or
- a **login-completion capability** that authorizes exactly one import for one
  `credential_id` and is consumed by it

`account_ref` is **declared at import** per commons#13, which matters for a reason
specific to this credential: `oauth:anthropic` has no `account_id`, and its absence is
what makes insula's `observations_differ` fall back to `record_version` and suppress
an entry for one cycle. A declared `account_ref` at import time removes that fallback
for every future consumer.

Open questions for the maintainer in §8.

## 7. Refresh custody: the anthropic adapter must work on plugin-sourced grants

Claustrum's refresh engine becomes the single refresh path. On **this host** it has 396
committed refreshes against `antigravity:google` and **zero** against `oauth:anthropic`,
because the mirrored token was always already revoked by the time it was exercised; every
exercise returned `invalid_grant` on a token that deserved it.

**Correction — an earlier version of this section said the adapter was "effectively
untested in the success direction" and that tonight was "the first time that path was
exercised at all". Both were scope errors and the maintainer refuted them from their own
deployment:**

```
maintainer's vault (different deployment, 47 credentials, keychain-resolved master key)
oauth:anthropic    refresh_commit 128    import 11    invalidate 8
```

The measurement behind my claim was sound — same-subject filter control (84 rows match, so
the filter works and the zero belongs to the predicate), cross-subject control in identical
query form, `op` strings enumerated rather than recalled. It established **0 in this chain**
and nothing about the adapter. Every control was inside one deployment while the sentence
quietly changed population; "all-time" was load-bearing and had no referent.

> **A control arm validates the measurement, not the inference drawn from it.** The tell is
> a quantifier doing work no control covers — *all-time*, *ever*, *never*, *the adapter*.
> Name the population the measurement covers, then check the sentence has not widened it.

**What this does to the requirement: it narrows, it does not disappear.** The 128 rows
establish that the exchange, the fenced commit and the intent-clear work end to end — so
this is no longer "is the path known to work". The maintainer's own bound on those rows is
the part worth carrying: the audit op does **not** record whether the response carried a new
refresh token, so the rotation-persist arm is not individually witnessed by any of them.

So the open item is a claim about **grant provenance**, not about adapter health: has the
exchange ever succeeded against a **plugin-sourced** grant?

Before claustrum mode carries real anthropic traffic:

- confirm `client_id` and flow parity between claustrum's anthropic adapter and what
  `anthropic-auth` performs today — the Anthropic Auth seat knows the wire and should
  answer at source, not from documentation
- exercise a **successful** anthropic refresh end-to-end against a plugin-sourced
  grant, in a scratch record, before any migration
- confirm that a plugin-sourced grant carries whatever the adapter's refresh requires
  (scopes, audience, redirect binding), since a grant minted for one client is not
  automatically exchangeable by another

Migration is the moment this matters: a credential imported into claustrum with an
unexchangeable refresh token is a credential with **no** recovery path — worse than
today's mirror, which at least has an operator re-seal.

## 8. What the maintainer needs to answer before implementation

1. **The refresh stall.** `min_ttl_ms` from the plugin, a proactive refresh sweep, or
   an accepted periodic user-visible stall? The default today is the third by
   omission.
2. **The limiter mutex.** Is a global lock on every get acceptable for a bursty hot-path
   consumer, or does admission need to move off the shared path?
3. **Import authorization.** Write-capable handle, single-use login-completion
   capability, or something else? A plugin must not hold the master key.
4. **The auth.json view's displaced signal.** Accept the loss, or publish `view_write`
   rows in the audit chain (§5.1)?
5. **Drain contract.** Does claustrum owe consumers an explicit pre-restart drain
   signal, or is `--drain-ms` sufficient by convention?
6. **Anthropic adapter parity.** Who confirms it, and does migration block on a
   demonstrated successful refresh?
7. **Bound refresh TRIGGERING, not just `force_refresh`.** Two entry points reach the
   same upstream exchange, and `min_ttl_ms` is caller-supplied with no clamp anywhere
   (§5A.4). A TTL floor is self-limiting only while `min_ttl < token_lifetime`;
   unclamped it is `force_refresh` with no boolean to grep for. Clamp against the
   record's lifetime, and does the plugin get `force_refresh` at all?
8. **Attribution — for WRITES as well as reports.** `actor` names a path, not an
   identity, and the 2026-08-24 field instance shows two writes under two labels
   requiring two rounds of testimony to attribute (§5A.3). `module_id` already arrives
   at route-bind and the main consumer already attaches `consumer_identity` on every
   `route.open`, so the identity is reachable in production today and this code does
   not look. Wire it before the second consumer, or accept that incident review cannot
   attribute a change to a credential?
9. **Non-refreshable latch — INVARIANT WITHDRAWN, the fork is the real question.** I wrote
   "consumer reports must never latch" as though today's behaviour were an oversight. It is
   not: it is the arm the maintainer built, and the reason the *refreshable* arm can decline
   to latch is that the vault can **verify** the consumer's claim by attempting a refresh.
   For a static key there is nothing to attempt, so the actual question is whether to act on
   an **unverifiable** claim. Both answers cost something real and neither is obviously right:

   | arm | cost |
   |---|---|
   | **latch** (today) | a misclassified refusal — a 403 that meant a permission or a rate limit — stops serving a live credential until an operator intervenes. Measured: `oauth:xai`, 21 Aug, dead **seven hours**, 93 minutes after a clean refresh, recovered by hand |
   | **record, do not latch** | the vault never learns the key is dead, keeps serving it, and the failure moves out of the vault into every consumer's error path |

   `ck auth reactivate` exists because the first arm was wrong often enough to need a
   one-command repair — which is evidence about the frequency, not an argument that the arm
   is wrong. Worth recording that the plugin's own `400 + invalid_grant -> permanent: true`
   rule is the same trade-off from the other side of the wire, and it also has an incident.
   **This wants a design note with every consumer answering at source, not a resolution in a
   thread**, which is the treatment the stale-marking change got.
10. **Fault injection after migration.** How do the failure paths get exercised once
   the treadmill stops providing free production faults (§5A.7)?
11. **Publish refresh outcomes.** Without them a migrated account degrades silently and
   the plugin keeps routing to an account the vault knows is failing (§5A.10). The
   facts are already in `auth_events`. Publish last-refresh result and a
   transient-vs-permanent distinction on the read surface — and decide explicitly what
   replaces the plugin's 429 backoff, since the vault has no backoff concept at all.
12. **Q1b assertion.** The placeholder-boot gate must assert on observed authenticated
   behaviour, not a clean boot, because a non-decoding record is silently filtered and
   the provider then reads unauthenticated (§1A.3). Who owns that gate, and does main
   migration block on it? **Narrowed:** the decode gate has since been executed against
   the real exported union, so the residual is one full-boot serving check — but see §1A.1,
   because the placeholder is no longer load-bearing and main is frozen for a different
   reason entirely.
13. **A rollback/export op, and whether custody de-escalation should exist at all.**
   *This one is ours, not the maintainer's — raised here because the answer decides
   whether main can ever migrate.* Post-migration the plugin is refresh-blind by design,
   so **no mechanical rollback for main exists**: `credential.get` cannot reconstruct a
   refresh token, and C2 ("the mode is a flag") is therefore not merely hard for main but
   impossible (§9.1). The options are a vault op whose whole purpose is to hand a refresh
   token back out — inverting the property the vault exists to provide — or documenting
   flag-off as a deliberate outage ending in interactive re-login.

   If such an op is built, it needs its security semantics decided up front rather than
   inherited: admin-gated by MAC challenge rather than handle-gated (a read capability
   must not escalate into an export), whether it revokes the vault's own copy in the same
   transaction (a de-escalation that leaves two copies has re-created the treadmill
   deliberately), whether it is audited as an alarm rather than an ordinary op, and
   whether it is refused outright for credentials whose adapter has never demonstrated a
   successful refresh. **Our current recommendation is option 2 — document the outage —**
   on the grounds that an export route is a permanent weakening bought to serve a rare
   operation, and the honest alternative costs one interactive login.

## 9. Rollback

### 9.1 The asymmetry: "the mode is a flag" is true for fallback and false for main

**Fallback rows roll back free.** Flag off, the plugin reads its own sidecar again,
nothing was displaced.

**Main does not.** Under shadow-serve the host's store holds a placeholder, so
flag-off must **restore a real credential into the host's store** or the provider is
dead until re-login.

**Correction — the restore step does not exist, and I previously wrote as though it did.**
An earlier generation of this section said the vault "holds the real family and can supply
it, but that is a restore step, not the absence of one." That is wrong in the way that
matters: **there is no vault operation that supplies a refresh token.** `credential.get`
returns the payload the consumer is entitled to for *use*, and a claustrum-mode consumer
is deliberately refresh-blind (§5A.1) — that blindness is the entire mechanism. So
post-migration the plugin holds no refresh token and **cannot obtain one**, which means:

> **C2 ("the mode is a flag") and rollback-by-flag-off are mutually impossible for main.**
> Not difficult — impossible. Requiring "rollback must restore a real credential" is
> restating an impossibility as a requirement, which is how a missing primitive hides
> inside a plan that reads as complete.

Main migration therefore requires **exactly one of** the following to be chosen
deliberately, and none of them is free:

1. **A vault rollback/export op** (`credential.export`, or equivalent). This is a
   deliberate **custody de-escalation** — a route whose entire purpose is to hand a
   refresh token back out of the vault — and it inverts the property the vault exists to
   provide. It needs its own security semantics: who may call it, whether it is
   admin-gated (MAC challenge) rather than handle-gated, whether it revokes the vault's
   own copy in the same transaction, and how it is audited. **This is a vault-side design
   question and it is mine, not the plugin's** — tracked as Q6 for the board.
2. **Mandatory interactive re-login, documented as non-automatic.** Cheapest and most
   honest: flag-off for a migrated main is a *deliberate outage* ending in a re-login,
   stated up front rather than discovered during an incident.
3. **A different custody model for main** — e.g. vault-authoritative with the plugin
   retaining a sealed escrow copy, which weakens sole-refresher and needs its own analysis.

Until one is chosen, **flag-off for a migrated main is a deliberate outage.** That is an
acceptable answer; silently assuming a restore path is not.

So a rollback plan that does not say which row it is talking about is not a rollback
plan. Stated plainly:

| row | flag-off cost |
|---|---|
| fallback accounts | free — plugin resumes reading its sidecar |
| main account | **no mechanical rollback exists.** Either build a custody-de-escalating export op (Q6), or document flag-off as an outage ending in interactive re-login |

### 9.2 Migration is crash-safe but NOT race-safe

The migration sequence — write-vault → read-back → drop-local — is crash-safe: an
interruption at any point leaves either the local copy or both copies, never neither.

**It is not race-safe.** A concurrent `refreshAccountNow` can persist a rotated refresh
token back into local state *after* the drop, resurrecting the second custody holder the
migration existed to eliminate — and doing so silently, since both writes succeed. The
migration must therefore take **the same per-account refresh lock** the plugin's own
refresh path takes, and **CAS on generation/fingerprint** so a rotation that lands mid-
migration is detected rather than overwritten.

This is the single-flight argument from §5A.1 applied one layer out: serialising the
vault's refreshes does nothing if the *migration* races the plugin's refresh.

### 9.3 Identity must be minted BEFORE the refresh token is dropped

A sequencing constraint that is invisible until it has already cost an account:
`getOrCreatePrimeAuthLineageId` returns `undefined` with no live refresh token, because
the lineage id is derived from the token family. So **migrate-first-rekey-second yields an
account with no identity and no way to compute one** — the input needed to mint the
identifier is exactly what migration removes.

Order is therefore fixed: **mint the stable identity, verify it persisted, then drop the
local refresh token.** And note the deeper problem this exposes, which §5A.11 already
flags from the other side: an identity *derived from* a credential cannot be invariant
under that credential's rotation. A rotation-invariant account identifier has to be minted
independently of the token family — which makes it a vault-side primitive, and therefore
also mine.


The mode is a flag. `auth.json` remains intact and written. Disabling claustrum mode
returns the plugin to reading its own file, and the vault reverts to holding a mirror
— the treadmill returns, which is a known and survivable state rather than an
unknown one.

The rollback that is **not** cheap is migration itself: once a credential's only copy
lives in the vault and the harness has stopped maintaining its own, reverting means
re-authenticating. §7's untested-refresh concern is what makes this sharp, and it is
the reason migration should follow a demonstrated successful anthropic refresh rather
than precede it.
