# Changelog

## 0.16.0

- `ListedCredential::org_id` exposes the organization learned for an API key. An
  older vault can omit the field. An invalid value makes only that row
  undecodable; other rows remain available.

For earlier releases, see the Changes section in [README.md](README.md#changes).
