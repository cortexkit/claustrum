# Vendored golden fixture — the daemon's data-home resolution rule

AUTHORED BY THE AUTHORITY, not by this repo. The subc daemon resolves every
module's storage descriptor with its own `default_data_home`, so its rule is the
one that decides which directory this vault actually lives in. This repo keeps a
duplicate of that rule (the CLI must derive the same path offline, with no daemon
to ask) and therefore owes conformance to it.

A conformance fixture hosted by the MATCHER drifts into testing what the matcher
does. Authored by the authority, consumers inherit the obligation instead of
negotiating it.

Never edit: re-copy from source and re-run the test.

| file | source | commit | sha256 |
|---|---|---|---|
| `data_home_resolution.json` | `cortexkit/subconscious` `crates/subc-core/tests/golden/` | `c5084e40` | `0390a2734f3e4ca9f853f23839e017b774b0319b9f47a39fa7dd44e47d436d09` |
