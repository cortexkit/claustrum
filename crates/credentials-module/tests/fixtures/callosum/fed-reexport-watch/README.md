# Local re-export watch shapes, version 1

`local.json` records the frames a local caller receives while holding a
management watch on `fed:<peer>:fixture-module`. The module id is synthetic.
These are **local module-protocol frames**, not fed-wire headers.

The generator opens real origin subscriptions through the production
`ReexportHandler`, feeds fed-wire replies over a Noise session, and captures
the resulting frames from subc-client-rs 0.38.2's production module serve path.
It does not duplicate the terminal encoder. `body_hex` preserves the exact
body, including the notice's whitespace; `body_json` is a convenience decode
or null for an empty/non-JSON body. Routing channel, epoch and correlation are
omitted because a caller chooses them.

Cases cover the cap refusal, opening, one notice, every known end reason,
session loss, and an unknown future reason. An `open` produces **no local
frame**: the local SDK holds the request open and delivers subsequent
`StreamData`. The open row records that request and the observed empty frame
list, rather than inventing an extra open event. Clean completion and local
unsubscribe both yield one empty `StreamEnd`. Other endings use the mapping
in fed-wire §8.9. Unknown reason bodies are opaque and are not added to the
local error detail.

Verification (Linux build server, from the repository root):

```sh
cargo test --locked -p fed-module --lib origin_watch_local_vectors_match_production_relay_and_sdk
```

Generation into this new version, before it is published:

```sh
CK_GENERATE_REEXPORT_WATCH_VECTORS=1 cargo test --locked -p fed-module --lib origin_watch_local_vectors_match_production_relay_and_sdk
```

Return `local.json` and `SHA256SUMS` from the remote job, then update their
pins in `test-vectors/scan-vendored-ids.py`. Once tagged, publish changed
shapes under a new version directory; do not regenerate this release in place.
`SHA256SUMS` covers the generated payload.
