# Fleet epoch v1 samples

`cases.json` is the vault-produced sample set intended for the
`fleet-epoch-vectors-v1` tag. All private keys, epoch keys and plaintext here are
synthetic public test material, never deployment keys. Bytes use canonical
base64url without padding; JSON strings ending in `_utf8` contain the exact UTF-8
bytes, not a recipe for reordering or pretty-printing the JSON.

## Contents and provenance

The producer is `tests/fleet_epoch_vectors.rs`. It uses real encrypted stores,
the real fleet management adapter, and the existing Callosum wire stand-in.

- `fixture_keys` contains the sender's X25519 scalar (`11` repeated 32 times in
  hex), the recipient's scalar (`22` repeated 32 times), and their public keys.
  Sender and recipient are `fed-computer:00000000000000000000000000000001`
  and `fed-computer:00000000000000000000000000000002` respectively.
- `seal_open` pins epoch 1, its synthetic epoch key (`31` repeated 32 times in
  hex), the seal request and response, the exact associated data for authenticated
  encryption with associated data (AEAD), and the open request and response.
  The epoch key is installed through the real authenticated import path, not a
  raw table insertion. The sample opens through
  `fleet.epoch_open` on both vaults.
- `wraps` contains a rotation, a one-key join and a two-key join. Their plaintext
  shapes come from production `fleet_epoch_mint` and `fleet_epoch_wrap_for`
  outputs. For the rotation, the producer validates the randomly generated
  32-byte epoch key and substitutes the documented synthetic epoch key. Join
  plaintexts need no normalization because their fixed epoch keys were imported
  first. The producer then re-encapsulates each plaintext through the existing
  `kem::seal_auth_with_ephemeral_ikm` test helper, sharing the production auth
  sealer. Each sample records its ephemeral input key material (IKM). All three
  wraps pass the real import path, and their import responses are pinned in
  `import_responses`.
- `refusals` covers all 12 codes: `invalid_params`, `not_found`,
  `fleet_epoch_unavailable`, `fleet_epoch_pending`,
  `fleet_peer_keys_unavailable`, `fleet_members_mismatch`,
  `fleet_epoch_not_pending`, `fleet_epoch_open_failed`, `fleet_wrap_refused`,
  `fleet_epoch_capacity`, `corrupt`, and `store_error`. The test drives the real
  adapter for every refusal. `not_found` uses caller `reserved:other`; all other
  calls use `reserved:entorhinal`. Causes include an unknown parameter, no current
  epoch, an existing pending mint, no Callosum client, a mismatched live set, an
  absent pending mint, an unknown opening epoch, a damaged HPKE ciphertext, 65
  proposed members, a damaged stored envelope, and a missing database table.
  `response` is the adapter result body except `invalid_params`, where
  `transport_error` identifies the protocol Error payload: the adapter returns
  `Answer::InvalidParams` rather than an in-result refusal. That payload is
  serialized with the shared protocol `ErrorBody` constructor and the daemon's
  fleet invalid-parameters message; it is not a captured transport frame.
  `fleet_key_reserved` belongs to the operator grant path, not Entorhinal's
  `fleet.*` contract; the core key-fence tests pin that refusal separately.
- `statuses` pins empty, one-held, two-held, pending and removal-blocked shapes.
  Only the pending status's random mint ID is normalized: the real status must
  return the actual mint's canonical 16-byte ID before replacing it with `55`
  repeated 16 times. No other status field is changed.

### Seal nonce provenance and exact recomputation

The committed nonce was **drawn by the production sealer once at generation;
replay is by opening**. No deterministic nonce hook is added to the vault.
On ordinary runs the test opens the committed sample and also seals the same
plaintext afresh. The fresh response opens to the same plaintext and differs
only in `nonce` and `ciphertext`.

To reproduce the exact committed ciphertext independently:

1. Decode `seal_open.epoch_key` to the 32-byte XChaCha20-Poly1305 key.
2. Decode `seal_open.response.nonce` to the 24-byte nonce.
3. Decode `seal_open.request.plaintext` to the plaintext bytes.
4. Use the exact UTF-8 bytes in `seal_open.record_aad_utf8` as the AEAD associated
   data, with no trailing newline. Its RFC 8785 JSON layout is
   `{"aad":<request aad base64url>,"epoch":1,"v":"ck-fleet-epoch-aad/v1"}`.
   Do not pass only the caller's decoded `aad` bytes to the AEAD.
5. Encrypt with XChaCha20-Poly1305. Ciphertext followed by the 16-byte tag, encoded
   as unpadded base64url, must equal `seal_open.response.ciphertext`.

## Independent HPKE check

`verify-hpke.cjs` opens all three committed wraps with **hpke-js**, independent of
the vault's Rust `hpke` implementation. The suite is RFC 9180 Auth mode (2),
DHKEM(X25519, HKDF-SHA256) (`0x0020`), HKDF-SHA256 (`0x0001`), and
ChaCha20-Poly1305 (`0x0003`). Each context uses the fixture recipient private key,
sender public key, `wrap.enc`, exact `info_utf8` bytes and empty HPKE AAD.
Decrypted bytes must equal `plaintext_utf8` byte for byte.

From the repository root, on the Linux build server:

```sh
npm install --prefix target/fleet-hpke-check --no-save --package-lock=false \
  @hpke/core@1.9.0 @hpke/dhkem-x25519@1.8.0 @hpke/chacha20poly1305@1.7.0
NODE_PATH="$PWD/target/fleet-hpke-check/node_modules" \
  node crates/credentials-module/tests/fixtures/fleet-epoch-v1/verify-hpke.cjs
```

Verified with Node `v24.21.0` and those exact dependency versions: `rotation`,
`one-key-join` and `multi-key-join` all opened to the exact recorded plaintext;
the verifier reported **3 independent HPKE wrap checks passed**. Dependencies
are installed only under `target/`; repository manifests and lockfiles are not
changed.

## Pin check and deliberate regeneration

Run through the Linux build server, serializing Cargo commands:

```sh
cargo test --locked -p credentials-module --features credentials-core/test-support \
  --test fleet_epoch_vectors fleet_epoch_samples_are_producer_generated_and_pinned
```

The test compares the full generated JSON bytes to `cases.json`. To regenerate
deliberately, set `CK_EMIT_FLEET_VECTORS=1` on the same command and return
`crates/credentials-module/tests/fixtures/fleet-epoch-v1/cases.json` from the
build-server job. This emits a newly drawn seal nonce/ciphertext; the three
deterministic HPKE wraps remain byte-identical. Review the generated differences,
then run the pin check without the environment variable and the independent
HPKE verifier. Never hand-edit `cases.json`.

The additive `mint-excluded.json` sample mints with one excluded live peer and
one rotation-wrap recipient, using the same sender and recipient keys as
`cases.json`. It pins the request, response and wrap plaintext, with the random
epoch key, mint ID and HPKE input replaced by synthetic bytes. To regenerate
it and `SHA256SUMS` without rewriting the original samples, set
`CK_EMIT_FLEET_EXCLUDED_MINT_VECTOR=1` on the command above, replace the test
filter with `fleet_mint_exclusion_omits_the_peer_from_wraps_and_stored_holders`,
and return `mint-excluded.json` and `SHA256SUMS` from the build-server job.
