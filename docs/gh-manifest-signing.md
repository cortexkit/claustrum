# `gh` routing manifest signing

The `gh` routing manifest tells the `gh` shim which invocations to route to the holder
daemon and which to pass through. Each manifest version is signed by a root Ed25519 key held
in this vault. This guide is the procedure for signing one, with the reasons that make each
step necessary.

The root is `signing:gh-manifest-root:1`, a `SigningKey` record minted inside the vault with
`ck auth mint-signing-key`, so its private half never leaves it. Its `key_id` is the first 8
bytes of SHA-256 over the public key, so any holder of the public half can recompute and check
it. `scripts/audit-signed-payloads.sh` lists every approval row and the retained bytes it binds.

## 1. What the root key gates

The manifest governs **routing selection** on the shim side. It does **not** define what the
holder will execute: that vocabulary is compiled into the holder's binary, and no signed file
can widen it. So the blast radius of a compromised root is:

```
compiled_vocabulary  MINUS  what the honest manifest routes
```

the set of operations the holder would execute that the honest manifest declined to route.
That set is invisible in either artifact alone, so the holder pins it as an explicit sorted
list in a holder-side test; a vocabulary addition names what it exposed rather than moving a
count.

## 2. The approval question

Every signature requires a named approver, who must answer:

> **What does this manifest stop routing, and am I content that a key compromise re-enables
> exactly that set?**

Not "does this look tighter". **Narrowing a manifest widens the compromise surface**: route
fewer operations and the honest system does less, which reads as safer, while the set a
compromised key could re-enable grows by exactly what was removed.

## 3. The approver approves bytes

The envelope carries the manifest as the exact bytes the signer published, and the verifier
verifies the received bytes before parsing them. There is no canonicalization step, so there
is no canonicalization rule to get wrong.

That moves one hazard onto this procedure: if the approver is shown a pretty-printed or
summarised rendering produced by a different parser than the verifier's, the approver approves
what they saw and signs something else (a duplicate key, an unexpected escape, a dropped field).
So **the approver sees the bytes, or a rendering produced by the same parser the verifier
uses.**

Verify-then-parse is safe while there is one verifier implementation. A second verifier would
make parser differences a live hazard, and the answer then is a parsing conformance suite.

## 4. Envelope forms

The consumer's active file is:

```
{artifact_id, envelope_version: 2, fetched_at_unix_secs, key_id, manifest_bytes, signature}
```

and the retained per-version files are `{key_id, manifest_bytes, signature}`.
**`manifest_bytes` is the raw JSON string, not base64.** Hand off in the form the consumer
already stores, so activation is a copy rather than a transform. A container mismatch presents
as an invalid signature; if the two sides ever disagree, compare the wrapper before re-checking
the signature.

## 5. The ceremony

The private key never leaves the daemon. Signing is a route operation (`credential.sign`):
handle and bytes in, signature out.

1. **The approver answers the section 2 question**, naming the manifest version and what it
   stops routing.
2. **Require an executed round trip through the holder** before recording approval: one real
   operation per declared verb, on a scratch thread in a repository you own. A placed image or a
   version string proves placement, not that the holder executes what the manifest declares.
3. **Record the approval** under the master key:

   ```sh
   ck auth approve --id signing:gh-manifest-root:1 --file <manifest.json> --approver <name>
   ```

   The `approval` audit row binds the approver, the artifact's SHA-256 and the signing
   credential. It signs nothing.
4. **Mint a capability handle** for the root (`ck auth mint-handle --id signing:gh-manifest-root:1`).
   The key sits with zero live handles between signings.
5. **Call `credential.sign`** with the exact approved bytes. It returns a detached Ed25519
   signature plus `key_id`, and writes nothing.
6. **Revoke the handle immediately** (`ck auth revoke-handle --handle <ckh_...>`). Its lifetime is
   one signing. A mint with no matching revoke is an unfinished ceremony.
7. **Verify before publishing**: the signature must verify under the public half in the trust
   set, using the consumer's own fixture as the control.
8. **Retain the bytes** (section 6).

The chain proves the order: the `approval` row (with `payload_hash = SHA-256(manifest bytes)`),
then `mint_handle` opening the window, then `revoke_handle` closing it. Approval and signature
meet at the hash: the chain proves who approved bytes H before the window opened, and the
published signature proves the key signed bytes H. A signature whose hash has no approval row is
visible as an absence. What this does not prove is that exactly one signature was made inside the
window, which is why step 6 is immediate.

### Why `credential.sign` writes no audit entry

`credential.sign` is reachable by any holder of a live handle and can be called in a loop. A
durable write per call would let a handle holder grow the audit chain without bound, and that
chain can never be trimmed, because trimming is what tamper evidence is defined against. The
rule: **an untrimmable log takes transitions only; a trimmable table takes every observation.**
A signature is an observation of a request. Minting and revoking are admin operations under the
master-key gate, so they bound the window instead.

### Why the vault signs rather than serving the key

A readable handle would already be signing power: whoever can read the key bytes can sign with
any Ed25519 library. Signing in the daemon exercises the same privilege without copying the
private key into another process's memory, and without a "read, use, drop" discipline to get
wrong.

### The kind fence

`credential.sign` is served only for records whose kind is `SigningKey`, refusing everything else
with `kind_not_signable`, so the vault is not a general signing oracle over every stored secret.
The fence is enforced on the stored kind, not derived from the credential id. A record's kind
cannot be changed in place without re-supplying its payload, and the mint keeps no second copy,
so a key minted with the wrong kind must be re-minted under a new key id before any trust set
includes it.

## 6. Retention and audit

`payload_hash` is a commitment to bytes, not a copy of them. The chain answers *what was approved*
forever and cannot answer *what did it say*; a signature over bytes nobody holds is uncheckable
while still reading as verified. **Retention is therefore part of the ceremony:**

```
<data_dir>/signed-payloads/gh-routing-manifest-v<N>.json   0600
```

A file is admitted **only** when its SHA-256 equals the `payload_hash` of an `approval` row. The
hand-off envelope (`{key_id, manifest_bytes, signature}`) is not an approved payload, so keep it
beside the store, not in it:

```
<data_dir>/signed-envelopes/v<N>-envelope.json   0600
```

Both directories are backed up through the descriptor the daemon writes at every start
(`ENGRAM_CATALOG_JSON` in `crates/credentials-module/src/main.rs`). A new directory kept beside
them needs an entry there; otherwise it is not backed up and nothing warns.

**Audit in the direction that can find absence.** Scanning retained files against the chain
iterates what exists, so a missing artifact is not expressible. The scan that finds a gap goes
from the chain to the files:

```sql
SELECT seq, substr(payload_hash,1,16) FROM audit_log
WHERE op='approval' AND credential_id='signing:gh-manifest-root:1' ORDER BY seq;
```

then check each hash has a file. `scripts/audit-signed-payloads.sh [<data_dir>]` runs both
directions and also checks that the `manifest_version` inside each file matches the version in
its filename, which a content hash cannot see. Exit 0 means every arm is clean, 1 a finding, and 2
that the audit could not run (not the same as clean).

## 7. Proving the signer against someone else's bytes

The signer is proved against **the consumer's fixture**, never one generated on the signing
side: a fixture generated here agrees with whatever this side expected, by construction. The
consumer publishes exact signed manifest bytes (sha256-pinned), keypair references and the
expected signature, and the signer must reproduce that signature byte for byte before it is
trusted with a real manifest. `crates/credentials-core/tests/gh_manifest_signer_proof.rs` does
this against vendored fixtures with recorded provenance.

## 8. Rotation, and what the standby key does not buy

The trust set is an array with room for two keys: a live root and a cold standby, minted by the
same ceremony under a second key id. The standby's value is that **deployed builds already trust it**, so rotating does not
require shipping a release under pressure.

It does not double custody safety. Both keys live in this vault under the same master key:

```
live key compromised through a signing operation   standby helps: rotate, no release
this vault compromised                             standby helps nothing: both are in it
```

**Revocation is bounded by upgrade adoption.** A compiled-in trust set cannot be revoked faster
than users take a release, which is why the approval gate exists: the cheapest place to stop a bad
manifest is before it is signed.
