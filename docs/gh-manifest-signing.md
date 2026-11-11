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

The private key stays in vault custody. Use the master-key-gated manifest admin operation,
not `credential.sign`: the root is refused by that general signing surface, even through
a capability handle, principal grant or enrollment token. Its public key remains readable.

1. **The approver answers the section 2 question**, naming the manifest version and what it
   stops routing.
2. **Require an executed round trip through the holder** before recording approval: one real
   operation per declared verb, on a scratch thread in a repository you own. A placed image or a
   version string proves placement, not that the holder executes what the manifest declares.
3. **Approve, sign and retain the version** under the master key:

   ```sh
    ck auth manifest sign --file <manifest.json> --approver <name>
   ```

   The version must exceed the newest stored version, and parsing and re-serializing must
   reproduce its bytes exactly. One transaction writes the `approval` row (binding the
   approver, root credential and SHA-256), `gh_manifest_sign`, `gh_manifest_store`, the
   `gh_manifests` row with source `ceremony`, and pending-proposal supersede transitions.
   Signing succeeds only when that transaction commits; no signature is returned on a
   failed commit. No temporary handle or separate `ck auth approve` is needed.
4. **Check the command's result.** After commit it writes
   `<data_dir>/signed-envelopes/v<N>-envelope.json` at mode `0600`, using a temporary
   sibling and an atomic rename. If publication fails, the command exits non-zero and
   names the stored version. Do not sign again: recover the retained version with
   `ck auth manifest export --version <N>`.
5. **Verify before publishing**: the envelope's detached Ed25519 signature must verify
   over its exact `manifest_bytes` under the public half in the trust set, using the
   consumer's own fixture as the control.

The approval, signature audit and retained bytes now commit together. The same root signer
serves phone-approved binding proposals, whose source is `one_tap`. Turning one-tap off
blocks only new proposals: already-pending approvals, delivery, reporting, import and
ceremony signing still work. `ck auth manifest one-tap on|off|status` controls that setting;
missing is off, and unreadable values are treated as off.

### Transitions, not observations

**An untrimmable log takes transitions only; a trimmable table takes every observation.**
The root signer writes once per committed version under the ceremony or phone-approval
gate, not once per unrestricted signing request. Activation reports update a table on
every observation, but audit only the first `(member, stored version, verdict)` tuple.
General `credential.sign` for other signing keys retains its existing audit policy; it
cannot sign with this root.

### Why the vault signs rather than serving the key

A readable handle would already be signing power: whoever can read the key bytes can sign
with any Ed25519 library. The manifest admin operation signs within the vault's write
transaction without handing the private key to the caller or requiring a "read, use, drop"
discipline.

### The kind fence

The manifest signer requires an active root record of kind `SigningKey`. The root does
not need, and must not acquire, the general `operator_sign` flag. Other keys keep their
existing kind and operator-signing fences.

## 6. Retention and audit

`payload_hash` is a commitment to bytes, not a copy of them. The chain answers *what was approved*
forever and cannot answer *what did it say*; a signature over bytes nobody holds is uncheckable
while still reading as verified. **The `gh_manifests` row is the retained copy of every
version stored from now on**, whether imported, ceremony-signed or phone-approved. It
holds the exact manifest bytes, their SHA-256, key id, signature, signed time, source and
approval reference (nullable only for import), and cannot be updated or deleted.

At deployment, import the existing signed version once:

```sh
ck auth manifest import --envelope <file>
ck auth manifest list
```

Import verifies the root key id and Ed25519 signature, requires an increasing version and
byte-identical re-serialization, and preserves the signed bytes. `list` shows versions,
sources, hashes and signed times, followed by expected computers and activation rows.
`ck auth manifest retire-machine --member <member-id>` permanently removes a computer
from readiness; it does not revoke delivery grants.

Keep the existing legacy payload files in their current directory:

```
<data_dir>/signed-payloads/gh-routing-manifest-v<N>.json   0600
```

A legacy file is admitted **only** when its SHA-256 equals the `payload_hash` of an
`approval` row. New versions need no second payload file there. The hand-off envelope
(`{key_id, manifest_bytes, signature}`) is a derived delivery file, not the approved payload:

```
<data_dir>/signed-envelopes/v<N>-envelope.json   0600
```

`ck auth manifest export --version <N>` rewrites that envelope byte-identically from the
stored row at `0600`, even after a restart. It signs nothing and writes no database row.
The database and both existing directories are covered by the backup descriptor the
daemon writes at every start (`ENGRAM_CATALOG_JSON` in
`crates/credentials-module/src/main.rs`). No new backup directory is introduced.

**Audit in the direction that can find absence.** Scanning retained files against the chain
iterates what exists, so a missing artifact is not expressible. The scan that finds a gap goes
from the chain to retained bytes, in the database or legacy files:

```sql
SELECT seq, substr(payload_hash,1,16) FROM audit_log
WHERE op='approval' AND credential_id='signing:gh-manifest-root:1' ORDER BY seq;
```

For each hash, first check for an equal `gh_manifests.manifest_sha256`; a stored row is
retained even if its envelope file is absent. Otherwise require a matching legacy file.
`scripts/audit-signed-payloads.sh [<data_dir>]` runs both directions and also checks that
the `manifest_version` inside each legacy file matches the version in its filename,
which a content hash cannot see. Old stores without `gh_manifests` still use the legacy
file check. Exit 0 means every arm is clean, 1 a finding, and 2 that the audit could not
run (not the same as clean). Missing bytes for legacy payloads remain findings, not exceptions.

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
