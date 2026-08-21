# Principal-scoped read grants

**Status: DESIGN ONLY. NOTHING IN THIS FILE IS BUILT.** No grant table exists, no
route op exists, and no principal authorizes any read today. Read this as what is
proposed, not as what the vault does. Measured 2026-08-21.

This file exists to be argued with before the code lands, because it relaxes a
property this module has held since it shipped.

## 1. The problem, and why the obvious answer was refused

21 `github_app:*` credentials are deposited, correct, and **unreachable**. Each holds
one fleet agent's GitHub App private key. Exactly one has a capability handle
(`plex-alfonso`), minted by hand during an incident.

The obvious answer is to mint 20 more handles and write them into the holder's
config. That was refused, and the refusal is the design constraint:

- A capability handle carries **no holder metadata**. Once minted, the vault cannot
  say who holds it, so 20 handles in a file are 20 bearer tokens with no
  accountability and no way to revoke one holder without revoking a credential.
- Revocation is per-handle, so withdrawing the holder's access means 20 operations,
  each of which must find the right handle.

A grant names its holder and is one row.

## 2. What it is

One durable row: **a principal may read a family of credentials.**

```
principal          Reserved { module_id: "prefrontal-core" }
credential_prefix  "github_app:"
```

A caller bound under that principal may read any credential whose id starts with the
prefix, **without presenting a handle**. Nothing else changes: handles keep working
exactly as they do, on exactly the path they use now.

## 3. What this changes about the module, stated as a change

**The read plane has been anonymous by design.** A capability handle is the entire
authorization; the vault never asks who is calling, and that is deliberate — an
anonymous bearer surface cannot leak identity it never learns. Admin operations do
check a principal, but only as Gate 1, always behind a master-key MAC. **Principal
alone has never authorized anything here.**

This makes it the first thing that does. That is defensible now that reservation is
mechanically enforced, and it means **the vault has begun trusting supervisor
attestation for reads.** If that attestation is ever forgeable, this grant is the
blast radius.

The property is not abandoned; it is split. There are two read paths with different
authorization models, and the anonymous one is untouched. That split is the reason
§5 puts the grant on its own operation rather than adding a mode to `credential.get`.

## 4. The security argument, and the honest non-goal

### The non-goal, named rather than discovered

**A same-uid local adversary is outside what this defends against.** Verified on this
host 2026-08-21: `SUBC_LAUNCH_NONCE` is readable from an ordinary shell via
`ps eww` against the live daemon. Supervisor attestation is trustworthy against
remote and cross-account claimants; against a same-uid process it is an **integrity
signal, not a secret** (subconscious `docs/evidence/reserved-proof-prefrontal-core-2026-08-20.md`,
§ Nonce forgery surface, commit `2bcffb5a`).

There is no second gate on this path. The master-key MAC guards admin mutations
only.

### Why the grant is still the stronger option

"Is attestation strong?" is the wrong question, and it has no comfortable answer.
The question that decides it is **what does the grant replace**, against the *same*
attacker:

```
STATUS QUO   ~20 bearer handles in a consumer config file, mode 0600.
             A same-uid process reads the file. ALWAYS available, no window,
             no race, and the stolen handles keep working afterwards.

GRANT        a same-uid process must read the nonce AND claim the name during a
             window where the holder is NOT the live bind -- while it is
             connected, the duplicate-id gate refuses the impostor.
```

The grant requires a window that does not normally exist, where the file requires
only a read. **Strictly stronger against the identical attacker**, and smaller than
the accountability argument that motivated it.

## 5. Wire shape

A **new** operation rather than a mode on `credential.get`:

```
credential.get_scoped   { credential_id }  ->  same body as credential.get
```

Three reasons, and the third is the one that matters later:

1. The anonymous path stays byte-identical, so nothing about handle-authorized reads
   can regress while this is added.
2. Handles address by an opaque token; a grant addresses by credential id. One
   operation taking either is an operation whose authorization depends on which
   field was populated, and that is a shape defects hide in.
3. **"Which requests used principal authority" becomes answerable by operation
   name**, in logs and in code, without inspecting arguments.

Refusals reuse the existing vocabulary: an unknown id and a covered-but-absent
credential both answer `NotFound`/`permanent`. A caller whose principal has no
covering grant answers `NotFound` as well — **not a distinct "no grant" code**,
because a caller who can distinguish "exists but you may not have it" from "does not
exist" can enumerate the vault's contents by asking.

### The wire is uniform; the vault's own record is not

A uniform refusal buys enumeration resistance and **spends diagnosability**, and
this repo has already paid that bill once: a refusal carrying no cause is what turned
a fabricated capability handle into hours of unfalsifiable debugging at the far end.
Paying it again at every misconfigured deposit is not acceptable.

So the two live in different places. **Enumeration resistance belongs on the wire;
diagnosability belongs in the vault's own record, where only an operator reads it.**
Every grant refusal records the discriminated truth — `no_grant` versus `not_found`,
naming the resolved principal and the requested id — in `auth_events`, reachable
via `ck auth events` without taking the write lease.

That distinction is load-bearing because **a refused caller and an absent credential
have different owners.** One is the holder's configuration, one is this vault's
contents, and a surface that records neither makes every future misconfiguration a
two-party guessing game.

`auth_events` is the right home rather than the audit chain: it is trimmable
(64 rows per credential, trimmed in the insert's own transaction), and a route
operation reachable in a loop must never append to the untrimmable chain.

**The residual, stated because the cap has a sharp edge:** a caller driving refusals
against one credential can evict that credential's genuine diagnostic history within
the cap. That hazard sits entirely inside the same-uid non-goal of §4 — driving
refusals at all requires a route bind — so it is accepted here rather than solved. If
it ever needs solving, the fix is a per-principal cap rather than a bigger one: bound
the noisy caller's own history, never the subject's.

## 6. The hazard a prefix grant carries

A prefix grant's blast radius **grows silently**. Every credential deposited under
`github_app:` becomes readable by the holder with no grant change, no review, and
nothing in either artifact to show it moved.

That is the same shape as the gh-shim delta (`compiled_vocabulary` minus
`honestly_routed`): a bound that is invisible in either half alone. It is also, for
this use, the *point* — a new fleet agent's key should not need a grant edit.

So it is accepted deliberately, with the same mitigation that worked there:

- The grant's covered set is **enumerated in the admin status output**, so "what does
  this grant currently reach" is one command rather than a mental prefix match.
- Depositing a credential under a granted prefix is a **security-review trigger**,
  recorded at the grant's definition.

What must NOT happen is a prefix that is broader than its purpose. `github_app:` is
one credential family with one holder. A grant on `apikey:` would cover every static
secret in the vault, and no accountability argument justifies that.

Two hardenings that make the mitigation mechanical rather than attentive:

- **The holder's grant is exactly `github_app:` and nothing else, and a SECOND
  prefix on the same principal is itself a review trigger.** Widening by adding a
  grant row looks like ordinary configuration; widening by adding a prefix to an
  existing principal looks like nothing at all.
- **The covered-set enumeration must be pinnable — sorted and diffable**, so a
  widening shows up as a diff a test can redden on rather than as a status page a
  human might read. That is the gh-shim delta-test shape, and the reason it is worth
  copying is that it converts "someone will notice" into "something fails".

## 7. Revocation and audit

- Grant creation and revocation are **admin operations**, so they carry the
  master-key MAC and append to the HMAC audit chain. They are transitions, and
  bounded by human action.
- A grant-authorized **read writes nothing**, for the same reason `credential.sign`
  writes nothing: a route operation reachable by a caller in a loop must not append
  to an untrimmable chain. **An untrimmable log takes transitions only; a trimmable
  table takes every observation.**
- Revoking the grant is one row and takes effect on the next request. It does not
  touch handles, and revoking handles does not touch the grant — two independent
  authorization paths, deliberately.

## 8. What is owed before this lands

- The grant table and its admin operations (create, revoke, list).
- `credential.get_scoped` with the principal check, and a test pair proving a
  covered id succeeds while an uncovered id refuses **identically to an unknown id**.
- Enumeration of the covered set in admin status (§6 is not optional; the mitigation
  is what makes the prefix acceptable).
- Negative tests that a grant issued to `Reserved { prefrontal-core }` is refused
  for BOTH a `Direct` principal (the CLI's own bind, a different KIND) and a
  DIFFERENT reserved module (same kind, wrong id). A check that compares kind but
  not id passes the first test and fails in production; a check that compares id but
  not kind does the reverse. Only the pair discriminates.
- A test that a refused read leaves a discriminated `auth_events` row while the wire
  body stays uniform — the property in §5 is two claims, and a test asserting only
  the wire half would let the server-side record silently disappear.
