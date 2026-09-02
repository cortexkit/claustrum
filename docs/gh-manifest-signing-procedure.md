# `gh` routing manifest — signing procedure

**Status: PROCEDURE WRITTEN, NEVER EXERCISED.** No manifest has been signed. The
signer described in §4 does not exist as code yet. Read this as what will happen,
not as what has happened; the first real signature is also the first test of every
step below.

The root exists: `apikey:gh-manifest-root`, Ed25519, minted 2026-08-20 into vault
custody, key id `c0342216a1b8edb0` (derived — first 8 bytes of SHA-256 over the
public key, so any holder of the public half can recompute and check it).

## 1. What this key actually gates

Stating it precisely, because the custody bar follows from it and an earlier draft
of this chain overstated it by one link.

The manifest governs **routing selection** on the shim side: which `gh` invocations
get routed to the holder daemon versus passed through. It does **not** define what
the holder will execute — that vocabulary is compiled into the holder's binary and
no signed file can widen it.

So the blast radius of a compromised root is:

```
compiled_vocabulary  MINUS  what the honest manifest routes
```

the set of operations the holder would execute that the honest manifest declined to
route. Not unbounded, and not nothing.

**That set is invisible in either artifact alone** — the vocabulary lives in one
repo's binary, the routed set in a signed file. It is pinned as an explicit sorted
list in a holder-side test, so a vocabulary addition names what it exposed rather
than moving a count.

## 2. The approval question, and why the obvious one is wrong

Every signature requires a named approver. The question they must answer is:

> **What does this manifest stop routing, and am I content that a key compromise
> re-enables exactly that set?**

Not "does this look tighter". **Narrowing a manifest widens the compromise
surface** — route fewer operations and the honest system does less, which reads as
strictly safer, while the set a compromised key could re-enable grows by exactly
what was removed. Safety and blast radius move in opposite directions here, and
nobody reviewing a narrower manifest would expect that.

This is the whole reason the approval is a question rather than a checkbox.

## 3. The approver approves BYTES

There is no canonicalization step in this envelope: it carries the manifest as the
exact bytes the signer published, and the verifier verifies received bytes and only
then parses. That removes the classic signer/verifier canonicalization mismatch
completely — there is no rule to specify and therefore none to get wrong.

**It moves one hazard onto this procedure.** If the approver is shown a
pretty-printed or summarised rendering of the manifest, and that rendering is
produced by a different parser than the verifier's, the approver approves what they
saw and signs something else. A duplicate key, an unexpected escape, a field the
renderer drops — each is a way for the reviewed artifact and the signed artifact to
differ while both look right.

So: **the approver sees the bytes, or a rendering produced by the same parser the
verifier uses.** A convenience renderer written on this side is exactly the wrong
kind of help.

Residual, stated rather than discovered: verify-then-parse is safe while there is
**one** verifier implementation. A second one makes parser differences a live
hazard — two verifiers disagreeing about the same validly-signed bytes — and the
answer then is a parsing conformance suite, not a canonicalization rule.

## 4. The ceremony

**The private key never leaves the daemon.** Signing is a route operation
(`credential.sign`): handle and bytes in, signature out. The caller never receives
key material.

1. **Approver records the decision** against the §2 question, naming the manifest
   version and what it stops routing.
2. **Mint a capability handle** for the root. The key sits with zero live handles
   between signings, so it is unreachable except during one.
3. **Call `credential.sign`** with the exact published manifest bytes. Returns a
   detached Ed25519 signature plus `key_id`. **It writes nothing.**
4. **Revoke the handle immediately.** Its lifetime is one signing.
5. **Verify before publishing**: the signature must verify under the public half in
   the trust set, using the consumer's own fixture as the control.

### `credential.sign` must NOT write an audit entry, and I argued the opposite first

When the in-vault signing shape was agreed, I told the consumer that the vault
performing the signature meant "the approval entry and the signing can be appended in
the same transaction, so no signature exists without its approval". That is a better
property than meeting-at-the-hash and it is **wrong**, for a reason that is easy to
miss because the operation looks so rare.

`credential.sign` is a ROUTE operation reachable by any holder of a live capability
handle, and it can be called in a loop. A durable write per call therefore lets a
handle holder grow the HMAC audit chain without bound -- and that chain is the one
structure here that can never be trimmed, because trimming is the exact thing tamper
evidence is defined against. The rule this repo already carries: **an untrimmable log
takes transitions only; a trimmable table takes every observation.** A signature is
an observation of a request, not a state transition.

The procedural rarity of signing is not a defence. Signing is rare BY POLICY (a human
approves each one); nothing in the mechanism bounds it, and a bound that lives only in
a procedure is not a bound.

**So the ordering evidence comes from the mint/revoke pair instead**, which is
genuinely bounded because minting and revoking are admin operations under the
master-key gate:

```
approval entry   payload_hash = SHA-256(manifest bytes), actor = approver
mint_handle      opens the signing window
  ... signatures happen here, unrecorded and unbounded ...
revoke_handle    closes it
```

The approval and the signature **meet at the hash**: the chain proves who approved
bytes H before the window opened, and the published signature proves the key signed
bytes H. A signature whose hash has no approval entry is visible as an absence rather
than merely undocumented.

### What the approval row asserts, and the evidence it now requires

An `approval` row is not a receipt for bytes received. It is **this seat's assertion
that the artifact was worth activating**, written under the master-key gate, in a chain
that cannot be edited afterwards. So the question before appending one is not "did the
payload arrive intact" — the hash answers that — but "is there any reason to believe
this will work when installed".

**Measured 2026-09-03, on v12.** The payload was correct, the diff against retained v11
held on every claim, the signature verified, and the consumer's own verifier accepted it
at activation. The first governed operation then refused at the **holder** with `missing
field action`: a wire-shape mismatch one layer below the classifier. Reproduced from
this seat on an already-closed issue, so no state could change either way:

```
gh issue close 15 --reason completed    error: "missing field `action`"
GH_SHIM_BYPASS=operator + same command  error: "missing field `action`"
```

The audited bypass lifts a **tier**; that refusal is downstream of authorization, so it
does not help. Which makes the failed state fully blocking, and leaves a pressed seat
one escape — raw upstream `gh`, skipping the shim entirely, with no classification, no
audit row and no operator attribution. Strictly wider than the hole the tier existed to
close.

**Why the sequencing did not catch it:** the two parties were coordinated (signer,
classifier) and the third was a precondition. The holder's readiness had been reported
as *"LIVE, inode 1118660513"* — a **placement** fact. An inode proves which image is
mapped and says nothing about whether it executes the tuple sent to it. That is the same
distinction as `accept-deploy.sh` leg (d) versus the health probe, one layer up:
placement is not service.

**So before appending an approval row, require an EXECUTED ROUND TRIP through the
holder** — one real operation per declared verb, on a scratch thread in a repo the seat
owns — not a placed image and not a version string. Ask for it; do not infer it from a
successful placement. Without it the chain asserts *"signed what was sent"* while
reading as *"worth activating"*, and those come apart exactly when a capability is
declared that nothing downstream can perform.

### The chain proves the fact and cannot replay the artifact

`payload_hash` is a commitment to bytes, not a copy of them. So the chain answers *what
was approved* forever and **cannot answer *what did it say***. Those come apart the
moment nobody holds the payload, and a signature over bytes nobody holds is
unverifiable for the rest of time — not repudiated, just uncheckable, which is a worse
position than an unsigned artifact because it reads as verified.

**This already happened, and it is not recoverable.** Manifest v7 was approved at
audit seq 4700 and signed; its bytes were never retained here, because this store did
not exist until the consumer asked for canonical v10 bytes two ceremonies later. The
consumer could not supply them either: its state directory keeps only the *current*
signed artifact and overwrote each previous version in place. So both the signer and
the consumer held a commitment to bytes that neither could produce.

**Retention is therefore part of the ceremony, not housekeeping:**

```
<data_dir>/signed-payloads/gh-routing-manifest-v<N>.json   0600
```

admitted **only** when its SHA-256 equals the `payload_hash` of an `approval` row. That
filter is the whole value: a store that accepted whatever was lying in `/tmp` would be
worse than no store, because it would look like provenance.

**Audit it in the direction that can find absence.** Scanning retained files against
the chain is honest, complete, and structurally blind — it iterates what exists, so a
missing artifact is not expressible. It returned a clean 5-of-5 while v7 was gone. The
scan that finds the gap is the reverse one, chain against files:

```sql
SELECT seq, substr(payload_hash,1,16) FROM audit_log
WHERE op='approval' AND credential_id='signing:gh-manifest-root:1' ORDER BY seq;
```

then check each hash has a file. The two scans read almost identically when written and
answer different questions.

What this deliberately does NOT give: proof that the number of signatures inside a
window was one. An unrevoked handle is the gap, which is why step 4 is immediate and
why **a mint with no matching revoke is an unfinished ceremony** rather than a
harmless leftover.

### Why the vault signs rather than serving the key

An earlier draft of this file said "read the key over the route plane and sign in
the CLI". **That was inherited, not decided.** This vault serves bytes because that
is what it does — and the precedent was the APNs key, where serving was FORCED: the
signer is an edge Worker with no route to a daemon that has zero inbound network
surface. **That constraint does not exist here.** The signer is on the same machine,
holding a route.

The general test, worth more than this instance: **an inherited decision is one
whose original constraint you cannot state.** Ask what forced it. If the answer is
"it has always been this way", it was inherited rather than chosen.

Signing in the daemon buys three things:

- **No second-process window.** Serving puts the private key in CLI memory for the
  duration of a signing. That window is the only reason step 3 would need a
  "read into memory, use, drop" discipline to get wrong.
- **Zero new authority.** A readable handle already IS signing power — whoever can
  read the bytes can sign with any Ed25519 library. This exercises the same
  privilege without copying the material.
- **The approval becomes a precondition rather than a correlation.** Serving lets
  the vault record a handle mint and *trust* that a signature followed; signing lets
  it append approval and signature in one transaction. "No signature exists without
  its approval" is what §2 was reaching for, and only this shape has it.

### The fence, and why it is a kind rather than a list

`credential.sign` is served ONLY for records whose kind is a signing key, refusing
everything else with `kind_not_signable`. Without that, the vault becomes a general
signing oracle over every stored secret — which would let a handle for an API key
produce signatures under it.

Enforced in the type, not documented in prose, and **not** derived from the
credential id: a prefix is not authoritative (this repo already rejected
prefix-parsing for adapter selection, because the stored adapter can be overridden
at write time).

**This cost a fresh keypair, and the reason is a custody rule working correctly.**
The root was first minted as `ApiKey` — `put`'s default. Changing a record's kind
means writing the record, writing means supplying the payload, and the mint ceremony
deliberately keeps no second copy of it. So the kind could not be changed in place
and the root was re-minted as a signing-kind record.

Free while nothing consumed it; impossible once a public half is compiled into a
release trust set. **Dead ids, never to enter a trust set: `da51c38d1ea9a1b4`
(unverifiable first attempt), `c0342216a1b8edb0` (wrong kind).**

## 5. Proving the signer against someone else's bytes

The signer is proved against **the consumer's fixture**, never one generated here.

This is not process. A fixture generated on the signing side agrees with whatever
the signing side expected, by construction — which is how this repo shipped a
GitHub App adapter that demanded PKCS#8 when GitHub only ever issues PKCS#1. Every
test passed. The gate was on recorded provider *responses* and the *input artifact*
was synthetic, so nothing in the suite could see it.

The consumer publishes exact signed manifest bytes (sha256-pinned), keypair
references, and the expected signature. The signer must reproduce that signature
byte-for-byte before it is trusted with a real manifest.

## 6. Rotation, and what the standby slot does not buy

The trust set is an array carrying two keys from day one: a live root and a cold
standby. The standby's value is that **deployed builds already trust it**, so
rotating does not require shipping a release under pressure.

**It does not double custody safety, and the difference matters.** Both keys live
in this vault under the same master key, so:

```
live key compromised through a signing operation   standby helps: rotate, no release
this vault compromised                             standby helps NOTHING: both are in it
```

The standby is a *rotation* mechanism, not a *custody* mechanism. Anyone reading
"two keys" as defence in depth against vault compromise is reading it wrong, and
the fix for that threat is not a third key.

**Revocation remains bounded by upgrade adoption.** A compiled-in trust set cannot
be revoked faster than users take a release. That is the worst property in the
design, it is not repairable from this side, and it is the reason the approval gate
in §2 exists at all — the cheapest place to stop a bad manifest is before it is
signed, because after it is signed there is no channel to take it back.

## 7. What is owed before the first signature

- The signer (§4) as code, proved against the consumer's fixture (§5).
- A standby mint, same ceremony, second key id.
- A decision on where the approval record lives, so a signature can be traced to the
  question it answered.
