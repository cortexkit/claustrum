# Changelog

## 0.17.0

- The `consumer` feature now uses `subc-client-rs` 0.42.1, which supports call
  keepalives. Callers of `ClaustrumCredentialResolver::with_consumer` must use
  the same SDK version so their `SubcConsumer` type matches.

## 0.16.0

- `ListedCredential::org_id` exposes the organization learned for an API key. An
  older vault can omit the field. An invalid value makes only that row
  undecodable; other rows remain available.

For earlier releases, see the Changes section in [README.md](README.md#changes).
