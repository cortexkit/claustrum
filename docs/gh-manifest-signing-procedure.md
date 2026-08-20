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

Mirrors the mint ceremony: the private half is read into memory, used, and dropped.
It does not touch disk, argv, or an environment variable at any point.

1. **Approver records the decision** against the §2 question, naming the manifest
   version and what it stops routing.
2. **Mint a capability handle** for the root. The key sits with zero live handles
   between signings, so it is unreachable except during a signing.
3. **Read the key over the route plane**, sign the exact published manifest bytes,
   emit a detached Ed25519 signature plus `key_id`.
4. **Revoke the handle immediately.** Its lifetime is one signing.
5. **Verify before publishing**: the signature must verify under the public half in
   the trust set, using the consumer's own fixture as the control.

Steps 2 and 4 are why the audit chain shows a mint/revoke pair per signature —
that pair IS the signing record, and a mint with no matching revoke is an
unfinished ceremony.

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
