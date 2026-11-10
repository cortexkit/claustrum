# Vendored fixtures: callosum's reply vectors

Copied byte-for-byte from `cortexkit/callosum`, so the vault's decoders for callosum's
replies are tested against the bytes callosum's production code emits. Fixtures written
on this side would only agree with this side's own reading of the format. Never edit
these files: to refresh them, copy again from a new callosum tag and update the table and
the pins in `tests/federation/callosum_vectors.rs`.

| file | source | tag | commit | sha256 |
|---|---|---|---|---|
| `paired-devices/cases.json` | `test-vectors/paired-devices/cases.json` | `paired-devices-vectors-v1.5` | `e1dd0eb8` | `9bf5afa89ce776252e8a0e7bbadefe83799bda111da97748dce6349414f30901` |
| `paired-devices/README.md` | `test-vectors/paired-devices/README.md` | `paired-devices-vectors-v1.5` | `e1dd0eb8` | `3e1e757f5676ec002ad5ce3cb12356d22da5c581ee7ef73c08928ae8c2743b06` |
| `peer-keys/cases.json` | `test-vectors/peer-keys/cases.json` | `peer-keys-vectors-v1.0` | `48f2198f` | `8b23d3ab3a9827e4d83584ca441ea84201979ca61cbcbf1560be0fca320ef805` |
| `fed-reexport-watch/local.json` | `test-vectors/fed-reexport-watch-v1/local.json` | `fed-reexport-watch-v1.0` | `1c9d715d` | `d235fcedee29caaf257c984edaa0c4883e19951585acd11a4a8a0991eb19d647` |
| `fed-reexport-watch/README.md` | `test-vectors/fed-reexport-watch-v1/README.md` | `fed-reexport-watch-v1.0` | `1c9d715d` | `322215e1f2c654fae79aed04468cbbe75e1176e5c9b3651da1b80761b0c4435b` |

The paired-devices fixture's own static key is `8520f009…4e6a`, and its documented
member id is `fed-computer:300c9c9603b92a4b39ed3958bf924011` (the first 16 bytes of
SHA-256 over the decoded 32-byte key). The peer-keys fixture's transfer key `pub` is
deliberately short (`cc03`): callosum only bounds-checks it, and the vault must refuse
anything but exactly 64 lowercase hex.

The fed-reexport-watch fixture records the frames a local caller receives while it holds
a watch on another computer's module through callosum. Its module id is callosum's
synthetic `fixture-module`, not the vault, so only the ending shapes apply to the
vault's own watch: which endings mean access was withdrawn, and which only mean try again.
