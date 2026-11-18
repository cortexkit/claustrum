# Bus-seal v1 samples

`cases.json` contains five `credential.open` calls on `kem:bus-seal:1`.
The `principal` is the authenticated caller, not part of the request body.
The `request_utf8` and `reply_utf8` strings contain the exact JSON body bytes,
without a transport frame or a trailing newline. The other fields expose the
raw HPKE inputs as hex for comparison with a local sender.

The suite is RFC 9180 base mode (0): DHKEM(X25519, HKDF-SHA256) (`0x0020`),
HKDF-SHA256 (`0x0001`), and ChaCha20-Poly1305 (`0x0003`). These fixtures use
public synthetic test material only. The recipient scalar is the bytes 32
through 63 inclusive. Each distinct message uses fixed ephemeral input keying
material (`ephemeral_ikm_hex`) for reproducibility. Real senders must generate
fresh ephemeral keys.

- `engram_open` seals a 32-byte sample archive key with info
  `ck-bus-seal/v1/engram/A|B|cut_id`.
- `ckbus_open` uses info `ck-bus-seal/v1/ckbus/A|B`.
- `ckbus_with_engram_info` and `engram_with_ckbus_info` replay the other
  module's exact, valid HPKE request. Both are refused with
  `bus_seal_info_domain`.
- `bare_prefix` uses valid HPKE inputs but has no bytes after the ck-bus
  prefix; it is also refused with `bus_seal_info_domain`.

From the repository root, `python3 scripts/hpke-independent-open.py` uses a
separate RFC 9180 implementation to open and reseal both success cases.

The `ck-claustrum` test `bus_seal_open_samples_are_producer_generated_and_pinned`
constructs the ciphertext using the Rust HPKE sender, executes the real daemon
dispatcher, and checks both `cases.json` and `SHA256SUMS`. To regenerate both
files, run this from the repository root; the `--return-path` flags copy them
back from the build server into this folder:

```sh
F=crates/credentials-module/tests/fixtures/bus-seal-v1
ck motor run --cwd "$PWD" --return-path "$PWD/$F/cases.json" \
  --return-path "$PWD/$F/SHA256SUMS" -- sh -c \
  'CK_EMIT_BUS_SEAL_VECTORS=1 cargo test --locked -p credentials-module \
     --bin ck-claustrum bus_seal_open_samples_are_producer_generated_and_pinned'
```

Review the diff, then run the same `cargo test` command without
`CK_EMIT_BUS_SEAL_VECTORS=1`; it passes only if the files match what the code
produces. The checksum file covers `cases.json` and this README, so editing the
README means regenerating it the same way.
