# claustrum

A credential vault that runs as a supervised daemon. It holds OAuth tokens, API
keys and signing keys encrypted at rest, refreshes OAuth credentials before they
expire, and serves each consumer only the credential it is entitled to.

The problem it exists to solve is credential sprawl: every tool that talks to a
provider ends up with its own copy of a token, its own refresh logic, and its own
way of going wrong. Two processes refreshing the same OAuth grant will eventually
race, and the provider's reuse detection revokes the whole token family. One
custody home removes the race by construction.

## The parts worth reading about

**Possession-only capability handles.** Consumers do not name credentials. They
present an unguessable handle — `ckh_…` — that the vault resolves to a credential
internally. A handle is a bearer token, so it can be given to one consumer and
revoked without touching any other holder, and a consumer never learns the id of
anything it was not given.

The consequence is a deliberate silence: an unknown handle and a *revoked* handle
return the identical refusal. That is not vagueness, it is the point — anything
that distinguished them would be an oracle for enumerating which handles exist.
The cost is that a refusal cannot be read as proof a handle is dead, so no
refusal on this surface licenses a consumer to destroy its own configuration.

**Value-level encryption.** Each record is sealed individually with
XChaCha20-Poly1305 under a master key that lives in the OS keychain or an
operator-held file. The record's version is bound into the AAD, so a record
cannot be silently rolled back to an earlier version of itself. A record that
fails to decrypt is quarantined alone; the rest of the vault keeps serving.

**Crash-safe refresh.** A token exchange is not atomic with the database write
that stores its result, so a crash in between can strand a credential. The vault
writes a durable intent *before* calling the provider and clears it in the same
fenced transaction that commits the new token. On boot, a surviving intent means
the process died mid-exchange, and the credential is reconciled rather than
silently served stale. This is tested by actually SIGKILLing the daemon at each
cut point, not by simulating it.

**A tamper-evident audit chain.** Every mutation appends an HMAC-chained entry
binding its predecessor, so no interior edit, reorder or insert survives
verification without the audit key. What it does *not* do on its own is resist
truncation: an attacker with database write access can delete a suffix and the
remaining prefix still verifies. The vault therefore publishes its chain tip
(sequence plus MAC) in its health snapshot, so an external witness can detect a
tail that vanished. The MAC matters as much as the sequence — a truncation
followed by fresh appends returns the sequence to its old value, and only the MAC
at that sequence reveals it is a different entry.

**Single-writer leasing.** The daemon and the CLI can both write, so writes are
fenced by an epoch-checked lease. A writer that loses the lease latches
permanently rather than clearing on its next success: having lost the fence once
means another writer took it, and a process that re-enabled itself would be
asserting authority it no longer holds.

## Layout

- `crates/credentials-core` — custody logic, wire-agnostic. Records, envelope,
  master-key resolution, refresh adapters, the audit chain, in-vault Ed25519
  signing, APNs provider-token minting.
- `crates/credentials-module` — the daemon and the operator CLI. Read surface,
  master-key-gated admin surface, capability handles, health probing.

## Using it

`ck-claustrum` is the daemon; it is launched by a supervisor and has no inbound
network surface of its own. `ck-auth` is the operator CLI — bootstrap a vault,
log in to a provider, mint and revoke handles, inspect state, verify the audit
chain. Most write verbs commit through the running daemon with zero downtime;
the offline path exists for bootstrap and master-key rotation.

- [`docs/cortexkit-credentials-contract.md`](docs/cortexkit-credentials-contract.md)
  — the normative security contract.
- [`docs/operator-runbook.md`](docs/operator-runbook.md) — provisioning, wiring a
  consumer, and the forensic queries worth knowing before you need them.

## Development

Two sibling repos are path-dependencies and must be checked out alongside this
one: [`subconscious`](https://github.com/cortexkit/subconscious) (the supervisor
wire) and [`commons`](https://github.com/cortexkit/commons) (storage libraries).

```
cargo check --workspace --locked
./scripts/gate.sh          # everything CI runs, on the working tree
```

The gate is exact rather than approximate: it asserts test counts per suite, so a
suite that silently stops running fails the gate instead of passing quietly.

## License

MIT — see [LICENSE](LICENSE).
