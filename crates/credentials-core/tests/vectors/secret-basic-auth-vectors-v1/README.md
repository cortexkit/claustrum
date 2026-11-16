# secret-basic-auth-vectors-v1

Producer-generated Basic sign-in samples for phone readers and AFT. All keys and
material in this directory are fixed, public **test-only** values. Do not use them
for a real vault or account. Keep `secret.basic_auth` off until the user's phone
can display `authorization_basic:<user>` as “Sign in as {user} with this token”.

## Contents and byte encoding

`vectors.json` indexes every record with its raw filename, unpadded base64url
bytes, SHA-256 digest (lowercase hex), and parsed `json` for JSON records. The raw
`.json` files are compact UTF-8 JSON, without a trailing newline. The `.bin` files
and `.der` signatures contain binary bytes, not a text encoding. `SHA256SUMS` pins
all generated files, including `vectors.json`; it excludes itself and this README.
The test compares every generated file byte-for-byte with the committed copy.

The pack contains:

- `deposit.*`: a real phone `secret.deposit` with Auth-mode HPKE, its authenticated
  additional data, plaintext framing, encapsulation, ciphertext, sealed-body
  framing and successful result. Receiver, phone-deposit and approval public keys
  are provided as raw binary records.
- `named.*` and `nameless.*`: the two request shapes, their shared approval card
  statement and `approval_required` reply, canonical approval envelope, P-256 DER
  signature, phone approval result and unchanged-byte token release. Both requests
  use the same scope, so the pending request and card are reused; after approval
  their releases are byte-identical. The setting is turned off before release to
  demonstrate that it gates creation, not use.
- `not-found.*` and `ambiguous.*`: actual target-only store replies. Ambiguity is
  produced after adding a second covering Basic sign-in secret while the first
  already has an hour grant. The producer asserts that ambiguity changes no audit,
  secret, tombstone, pending-request or grant counts.
- `disabled-deposit.*` and `disabled-put.*`: creation requests refused with the
  default-off setting. Deposit uses the actual phone operation; put uses the actual
  operator store entry point and its stable wire code. Both leave all counts above
  unchanged. The put record is the typed store input, not a shell command.
- `grammar-*`: colon, empty user-id, 129-byte user-id and non-ASCII user-id requests
  with real `SecretScope::from_input` and `SecretPut::scope_and_material` validation
  results. As in `secret-local-use-vectors-v1`, these do not invent a transport
  reply: `invalid_params` is a module transport Error, while `limit_exceeded` is a
  result error with class `context_overflow`.

Module transport mapping is pinned by
`basic_auth_phone_location_grammar_preserves_transport_refusals` and
`nameless_secret_use_parses_only_absence_and_reuses_the_named_card`.
`basic_auth_goldens_pin_target_only_request_and_permanent_refusals` checks the new
wire-contract golden blocks; `secret_error_codes_are_golden_and_match_the_doc_table`
checks refusal classes and forms. The existing golden digest pin is unchanged.

## Reproduction and independent checks

Run on Linux from the repository root:

```sh
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-core \
  --features test-support --test secret_basic_auth_vectors
cargo test --locked -p credentials-core --features test-support \
  --test secret_basic_auth_vectors
(cd crates/credentials-core/tests/vectors/secret-basic-auth-vectors-v1 && sha256sum -c SHA256SUMS)
```

The producer uses the real deposit opening, sealed record opening, selection,
shared named grant/card path, signed phone approval and release code. Only random
fixture identities are normalized before the store replays its own card, matching
the existing local-use generator: incarnation `000000000000000000000000000000ab`
and request id `01HF7YAT000000000000000100`. Sealed record ciphertext is not a
published artifact. The deposit result's incarnation is normalized to the same
fixed identity. No production randomness is replaced.

Fixed inputs for an independent implementation:

- Clock: 1,700,000,000,000 ms; hour grant expires at 1,700,003,600,000 ms.
- Home: `fed-computer:22222222222222222222222222222222`.
- Phone fingerprint: `11111111111111111111111111111111` (32 lowercase hex
  characters); pairing: `pair-A`.
- Master key: 32 bytes of `0x1d` (only for internal test record sealing).
- X25519 receiver scalar: 32 bytes of `0x09`; phone sender scalar: 32 bytes of
  `0x03`; HPKE ephemeral IKM: 32 bytes of `0x04`.
- P-256 approval signing scalar: 32 bytes of `0x07`. The DER signature verifies
  against the exact `named.envelope.json`/`nameless.envelope.json` bytes, with
  ECDSA/SHA-256 and `approval-public.sec1.bin` as uncompressed SEC1 public key.
- Location: `authorization_basic:git`, host `x.test`, prefix `/repos/a`.
- Token: hex `00ff3a0a746f6b656e`. The colon, NUL, non-UTF-8 byte and newline are
  intentionally released unchanged. The vault never constructs a Basic header.

HPKE uses the repository's `kem::seal_auth_with_ephemeral_ikm` suite and
`agent_secret::DEPOSIT_INFO`; the exact info string and framing are defined in the
wire contract. Approval statements and envelopes use their existing v1 formats;
Basic sign-in adds a location value, not a new statement version.
