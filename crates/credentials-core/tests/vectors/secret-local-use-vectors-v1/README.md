# secret-local-use-vectors-v1

`vectors.json` is a vault-produced sample pack for `sudo`/`sudo_password` and
`ssh`/`ssh_sign`. It is generated and byte-pinned by
`tests/secret_local_use_vectors.rs`, not edited by hand. The existing
`crates/credentials-core/tests/vectors/** -text` rule in `.gitattributes` disables
line-ending translation for this pack.

## Contents and byte encoding

Every byte record has unpadded base64url `b64url` and a lowercase SHA-256 `sha256`.
A JSON record additionally has `json`, the decoded object. Its encoded bytes are
compact RFC 8785 JSON, not the indented representation in the pack. Compare decoded
`b64url` bytes or their digest, not a consumer's reserialization of `json`.

- `cases`: four local/forwarded statement, approval-required, approval-envelope,
  approval-result and release/signature cases. Statements come from real store
  requests and are checked against the production statement builder. Optional
  `agent_id` is both present and absent across the samples; `asking_member_id` is
  present only on the forwarded statements. Sudo approvals choose `once`; SSH
  approvals demonstrate `hour` and `session`. The offered SSH durations also
  include `once`.
- `deposit`: the sent-order sudo targets, authenticated Hybrid Public Key
  Encryption (HPKE) request, additional authenticated data (AAD), plaintext,
  canonical stored scope and sealed-body plaintext. The actual phone
  deposit is opened by the store and its non-ASCII password is later released
  byte for byte. HPKE uses the existing Auth mode and deposit info, with test-only
  phone scalar `03` repeated 32 times, recipient scalar `09` repeated 32 times and
  ephemeral IKM `04` repeated 32 times. The sent targets are deliberately unsorted.
- `list`: the real phone listing before release, with two sudo grants and two SSH
  grants. Even the `once` grants expose only their program/use/target triple, not
  the command or purpose. SSH fingerprint and incarnation are vault-authored.
- `userauth_data` and `ssh_public_blob_b64url`: an RFC 4252 userauth packet and
  RFC 8709 public-key blob. Both signed replies cover these exact packet bytes.
  The test-only Ed25519 seed is `0b` repeated 32 times. The independent OpenSSL
  verification test verifies the pinned signature and rejects changed packet or
  signature bytes; it requires `openssl pkeyutl` with Ed25519 support.
- `approval_public_sec1_b64url`: the P-256 approval verification key, in uncompressed
  SEC1 form. Envelope signatures are DER ECDSA, encoded as unpadded base64url.
  The test-only P-256 private scalar is `07` repeated 32 times. Envelopes use the
  existing exact duration-to-expiry contract and are accepted by `secret.approve`.
- `sudo_hour_refused`: a correctly signed envelope with the normal hour expiry,
  refused by the real approval path because sudo offers only `once`.
- `refusals`: off-grammar sudo and SSH targets, command containing a Unicode
  control character (general category `Cc`), purpose containing a Unicode format
  character (general category `Cf`), first
  over-cap command (2,049 bytes), non-userauth data, wrong user, unmarked key, and
  setting-off sudo, SSH and identical deposit replay. The last accepted command
  size (2,048 bytes) is also checked by the producer. Refusals create no approval
  card, grant or release audit; setting-off calls also leave diagnostics unchanged.

Only the two approved program/use pairs are sampled. The held git program/use,
git target/path grammar, git token release and git remembered-target samples are
deliberately absent.

## Refusal framing and forwarded calls

Each refusal pins the exact request bytes and the typed error from the real core
parser/store. The `not_found` and setting-off cases additionally pin their actual
`SecretError::body()` bytes. The `over-cap-command` case intentionally has no
`reply`: the shared core `LimitExceeded` body uses `context_overflow`, but local
over-limit wire bodies use class `permanent`. That local framing is documented
in `docs/wire-contract-v1.md` under "Local programs and SSH userauth" and pinned
for SSH by the module test
`local_ops_ssh_decoded_size_boundary_and_trailing_packet_bytes` in
`crates/credentials-module/src/secret_contract_tests.rs`. The producer rejects
any local-use or SSH refusal sample that publishes a `context_overflow` body.

There is also intentionally no invented JSON body for `InvalidParams`: that
error uses the generic transport Error lane, without a class, described in
`docs/wire-contract-v1.md` §1a and the §15 error-code table. The existing
`secret_error_codes_are_golden_and_match_the_doc_table` test pins that distinction.
The related request golden blocks are `use.request.local_program`,
`ssh_sign.request` and `federation.secret_ssh_sign.request`; their contract tests
exercise grammar refusals through the transport adapter. `error.result` pins an
in-result permanent refusal, not an `invalid_params` body.

Forwarded samples use the core's authenticated-asking-member entry points. Their
requests and final replies are the inner AFT call and plaintext reply. Federation
AAD, pairing checks, sealed transport framing and receipt replay remain covered
by the existing forwarding tests and the `federation.secret_ssh_sign.request`,
`federation.secret_ssh_sign.result.sealed` and `federation.secret_use.*` goldens.

## Reproduction

Run on the Linux build server, returning the generated JSON to the checkout:

```sh
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-core --features test-support --test secret_local_use_vectors secret_local_use_vectors_are_producer_generated_and_pinned -- --exact --nocapture
cargo test --locked -p credentials-core --features test-support --test secret_local_use_vectors
```

The generator fixes the clock, keys and fixture identities. After a real deposit
it reseals the already-verified material with a fixed incarnation; after real
card generation it replaces only the random request id and its bound digest,
then obtains the card again from the store. After real approval it fixes the
random grant id before listing. All other statement members, approval decisions,
listing projections, signatures and refusal bodies come unchanged from the
production paths. Audit-chain keys and at-rest ciphertext stay random and are
not published in the pack.
