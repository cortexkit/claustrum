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
| `paired-devices-v2/cases.json` | `test-vectors/paired-devices-v2/cases.json` | `paired-devices-vectors-v2.0` | `d9326506be991ab9514b1b15b47034cf1e6c2d07` | `118d4257915d6bbaa82c496e57f41dd84522f128ac406e2012d5dc14f7964102` |
| `paired-devices-v2/README.md` | `test-vectors/paired-devices-v2/README.md` | `paired-devices-vectors-v2.0` | `d9326506be991ab9514b1b15b47034cf1e6c2d07` | `e05047504fc4d4bdf8c83efbfe617261638621848cc82fd809232f17ef036522` |
| `paired-devices-v2/SHA256SUMS` | `test-vectors/paired-devices-v2/SHA256SUMS` | `paired-devices-vectors-v2.0` | `d9326506be991ab9514b1b15b47034cf1e6c2d07` | `f8bd11a8ee65c2c214c7c8da28313245b040c010e58b2979839c6cd576109097` |
| `peer-keys-v3/cases.json` | `test-vectors/peer-keys-v3/cases.json` | `peer-keys-vectors-v3.1` | `6e9e1337570ca9e94a382f44b46bc5011ea81135` | `b5243386c46b0551c21f24f45dd696fb8edaa2dcb260b71e0d4f7da7e880979c` |
| `peer-keys-v3/README.md` | `test-vectors/peer-keys-v3/README.md` | `peer-keys-vectors-v3.1` | `6e9e1337570ca9e94a382f44b46bc5011ea81135` | `eaecef1ceec27a38bc542de7f17c71db7f368725dbc6b528f8107d985dfbd2ea` |
| `peer-keys-v3/SHA256SUMS` | `test-vectors/peer-keys-v3/SHA256SUMS` | `peer-keys-vectors-v3.1` | `6e9e1337570ca9e94a382f44b46bc5011ea81135` | `d9a3774670b45e1a81f69b738564fa0a5496d6de0b145477a6aa799ebfc71d16` |
| `peer-keys-watch-v1/cases.json` | `test-vectors/peer-keys-watch-v1/cases.json` | `peer-keys-watch-vectors-v1.0` | `e1405776952bb476618fbec3be5fe3f94a43dace` | `11e987c87f461a3179ff096b1ccd457dab74ff2327e09eac6b754df762811ecd` |
| `peer-keys-watch-v1/README.md` | `test-vectors/peer-keys-watch-v1/README.md` | `peer-keys-watch-vectors-v1.0` | `e1405776952bb476618fbec3be5fe3f94a43dace` | `4e4e890b5a984a70e5ec72c7f5c565da1cfe4a981e20fd7bc2dbd77524d5ea28` |
| `peer-keys-watch-v1/SHA256SUMS` | `test-vectors/peer-keys-watch-v1/SHA256SUMS` | `peer-keys-watch-vectors-v1.0` | `e1405776952bb476618fbec3be5fe3f94a43dace` | `9bd33a0c087a164505369b04d104e349d5b08739e7a678f6554f082edab522e5` |
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
