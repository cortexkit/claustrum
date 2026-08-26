# A deliberate retirement should not raise the same alarm as a failure

<!-- built-when: crates/credentials-core/src/record.rs::Retired -->

**Status: BUILT (2026-08-26).** `logout` writes `Retired`; health keeps intentionally
parked credentials visible without treating them as `Degraded`. The transition table
and deliberately excluded changes below describe the shipped behavior.

## The defect, with its field instance

`ck auth logout` is deliberately reversible: it stops serving and revokes handles but
keeps the record, so `login --replace` revives it without a fresh ceremony. `remove` is
the permanent one. That part is right and is not changing.

But logout writes `NeedsReauth`, which is also where a *failure* lands — and
`VaultHealth::summarize` counts any `NeedsReauth` as `Degraded`. So an operator
retiring a credential on purpose makes the vault report itself impaired, in a state
indistinguishable from one the world imposed.

That is not cosmetic. On 2026-08-24 an operator logged out `apikey:alibaba-token-plan`
because the subscription had ended. The vault went `Degraded`. Another seat read the
degraded line as a fault and attached it to two unrelated mason session deaths from
that morning as their cause — a causal story built on a signal that described a
deliberate action. The audit chain refuted it in one query (`invalidate` was stamped
hours *after* the deaths, and the credential had zero `auth_events` in its lifetime),
but the narrative had already been relayed.

**A gauge that cannot distinguish an intended state from a fault will have faults
attributed to it.**

## The shape

A fourth `RecordState`: `Retired`. Written only by `logout`. Never written by a
consumer report, a refresh refusal, boot reconciliation, or a quarantine — every path
that discovers a problem keeps writing `NeedsReauth` or `Corrupt`.

```
NeedsReauth  the world refused this credential      -> Degraded
Corrupt      this vault cannot read its own bytes   -> Degraded
Retired      an operator stopped it on purpose      -> Ok
```

## The load-bearing simplification: the consumer wire does not change

A retired credential refuses reads exactly as a needs-reauth one does, with the same
code and the same `auth_required` class. That is not a shortcut, it is correct: from a
consumer's side the two states are the same fact — *this credential is not being
served and an operator must act* — and the remedy is identical. Inventing a second
refusal would ask every consumer to learn a distinction that changes nothing they do.

So the change is confined to the two surfaces where the difference is real:

- **Health arithmetic.** `Retired` does not contribute to `Degraded`. It gets its own
  count and its own id list, so an operator can still see what is parked.
- **Operator rendering.** `ck auth list` shows `retired` distinctly, and `ck auth
  status` reports it as a separate line rather than folding it into needs-reauth.

Because no consumer-observable behaviour changes, this needs no consumer consultation
— unlike the report-marks-stale change, which altered what every consumer could see and
was gated on three of them answering at source. Stating the difference explicitly so
the precedent is not misread: consultation was required there because the *wire* moved.

## Transitions

```
Active      --logout-->     Retired
Retired     --login --replace-->  Active     (the ordinary revival)
Retired     --reactivate-->      Active     (clears the parking, material untouched)
Retired     --remove-->          gone
NeedsReauth --logout-->     Retired          (see below)
```

`reactivate` accepting `Retired` is right for the same reason it accepts
`NeedsReauth`: it contradicts a verdict without touching material, and the vault
re-verifies on next use, so a wrong assertion costs one failed request. It must
continue to refuse `Corrupt`, which is a claim about our own bytes rather than about
the world.

**`NeedsReauth -> Retired` is deliberate and worth its own sentence.** An operator
retiring a credential that has already failed is a real action — "this one is dead and
I am not renewing it" — and it should clear the alarm, because the alarm has been
acknowledged. Today the only way to silence that is `remove`, which destroys the row
and every handle with it. That is the destructive verb being reached for as an alarm
control, which is exactly the trap the logout/remove wording fix was written to
prevent.

## What is deliberately not done

**No migration of existing `NeedsReauth` rows.** They are genuinely ambiguous — the
chain records `invalidate` for both a logout and an admin invalidate, and the actor
field names a path rather than an intent. Reclassifying them would be guessing, and a
guess written into a state column is indistinguishable from a fact afterwards. They
stay as they are and age out naturally.

**No new health status value.** `Ok / Degraded / Failing` is unchanged; only the
inputs to `Degraded` move. A new status would be a wire change for every prober.

## Open

**Does `status` on a retired credential report a distinct `last_error_code`?** The
argument for: an operator debugging through the read surface gets the same
`auth_required` for two different situations. The argument against: that surface is
anonymous and bearer-reachable, so any distinction it draws is available to a stranger
holding a handle, and "this credential was deliberately retired" is an operational
fact about the deployment rather than about the caller's request. Leaning against, on
the same reasoning that makes revoked and unknown handles indistinguishable.

**Announce obligation.** The supervisor seat asked that the `VaultHealth` wire delta be
announced when this lands, and that the distinction stay visible in `list` *text*
rather than only in the health arithmetic. Both are in the shape above; the
announcement is owed at merge, not at design.
