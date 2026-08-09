# Inbound contract dependencies

Facts this repository does not own but must agree with. Each row is a value that is
declared HERE and specified SOMEWHERE ELSE, where no compiler spans the two copies.

The point of the table is not the copy — it is knowing that a copy exists. A fact
with three copies and something comparing them is better instrumented than a fact
with one copy, because a single copy cannot disagree with anything. What makes
multiple copies dangerous is that nobody diffs them.

| fact | declared here | owned by | checked by |
| --- | --- | --- | --- |
| APNs payload key for the sealed blob (`cks`) | `crates/credentials-core/src/apns_submit.rs` `SEALED_BLOB_KEY` | `subconscious/docs/specs/push-sealed-payload.md` | `scripts/check-inbound-contracts.sh`, in CI |
| `aps` member that runs the notification extension (`mutable-content`) | same file, `MUTABLE_CONTENT_KEY` | same spec | same |
| Minimum sealed-envelope length (version + encapsulated key + tag) | same file, `MIN_SEALED_LEN` | same spec | same |

## What the check does not cover, stated so it is not mistaken for coverage

**The iOS client declares its own copy of the payload key** — a third transcription,
in another language, which this repository's CI cannot see because that repository is
not checked out here. It is the copy that actually READS the field at runtime, so it
is the authority in practice: if the three ever disagree, the client is right by
definition and the other two are wrong.

That copy is therefore named here and verified by nobody. Recorded because an
unchecked dependency that appears in a table reads as covered, and this one is not.

## When the check fails

It reports which side holds which value and refuses to say which is correct. That is
deliberate: the spec is normative, but a spec edit can itself be the mistake, and a
check that told you to reconcile toward one side would be right most of the time and
catastrophic the rest. Find out which side moved before changing anything.

An unreadable side — an anchor that moved, a missing file — is also a refusal rather
than a pass. A check that cannot read its input has not agreed with it.
