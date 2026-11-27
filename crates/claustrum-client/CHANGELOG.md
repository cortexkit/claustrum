# Changelog

## 0.17.3

- On SDK-backed routes, daemon `route_busy` refusals that prove non-delivery
  are `Transient`. The client does not reopen the route or replay the request.
  Watch starts still use the SDK's deadline-bounded resend for verified busy
  refusals.
- An SDK deadline waiting for route credit is also `Transient` when the SDK
  reports that it never sent the request. If the public resolver's own
  10-second deadline expires first, the error is still `Transport`.

## 0.17.2

- The `consumer` feature uses `subc-client-rs` 0.43.0 and follows its route-death
  verdict. Retrying calls still reopen and resend once; held watches report
  route death as transport loss. Callers of `with_consumer` need the same SDK line.

## 0.17.1

- 0.17.0 treated `unknown_channel` and `stale_route_epoch` on an open route as
  permanent failures. For retrying calls, 0.17.1 restores the 0.16 behavior:
  reopen the route and resend once. Held watches report these errors as
  transport loss.

## 0.17.0

- The `consumer` feature now uses `subc-client-rs` 0.42.1, which supports call
  keepalives. Callers of `ClaustrumCredentialResolver::with_consumer` must use
  the same SDK version so their `SubcConsumer` type matches.

## 0.16.0

- `ListedCredential::org_id` exposes the organization learned for an API key. An
  older vault can omit the field. An invalid value makes only that row
  undecodable; other rows remain available.

For earlier releases, see the Changes section in [README.md](README.md#changes).
