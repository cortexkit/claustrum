# Federation producer fixture

`federation_wire_contract.json` contains synthetic, non-secret messages. No key or token in
this fixture is suitable for production. The two X25519 private scalars are repeated bytes
`01` (home/sender) and `02` (requester/receiver), wrapped by the core test-only PEM helper.

The fixture is checked by:

- `federation_token_and_report_fixtures_match_the_home_producer`: actual `HomeVault::serve`
  calls, opened with the requester's transfer key, pin token plaintexts, request aad bytes,
  accepted reports and refusals. Anthropic has an expiry; Antigravity does not and projects
  the managed project from its packed refresh token. Both include stored identity. Cooldown
  replies pin the optional `recheck_in_ms` field.
- `federation_transfer_fixture_matches_the_sender_and_receiver`: actual send prepare/commit/
  dispatch, opened transfer body, receiver delivery/accept/reject and identical resends pin
  aad order, body version 1, envelope field names and state replies. The refusal examples use
  the production `TransferRefusal::body` serializer and `DeliveryReply::keeps_row` policy.
- `remote_client_fixtures_match_the_read_surface_producer`: the real request dispatcher on B
  performs remote get/list/status and a setup refusal, with a real home behind the callosum
  stand-in. Neither the producer test nor the clients reimplement a reply serializer.
- `a_forced_open_grant_cannot_open_a_real_federation_token_reply`: a deliberately forced
  `open` grant is present, and the committed home envelope opens under Auth HPKE before
  `credential.open` must refuse it with `not_found`.

The Rust and TypeScript client tests consume the same `clients` section through their
current decoders. They check both adapters, inventory identity/authentication method, status
compatibility and a structured error carrying an optional `remedy_member`. Decoding a
status fixture in TS is not a remote-status API: its live method is handle-only.

## Updating a deliberate wire change

Run through the repository's Linux runner (see [the contributing gate](../../../../CONTRIBUTING.md#the-gate)),
serializing cargo commands:

```sh
cargo test --locked --offline -p credentials-module --test federation federation_producer -- --nocapture
cargo test --locked --offline -p credentials-module --bin ck-claustrum federation_read_fixture -- --nocapture
cargo test --locked --offline -p cortexkit-claustrum-client --test federation_fixtures
```

The producer assertions print `HOME_FIXTURE`, `TRANSFER_FIXTURE` and `CLIENT_FIXTURE` JSON
from the left-hand side. Review those differences before updating the corresponding sections.
`SEALED_SAMPLE` is a real Anthropic home reply for the fixed synthetic keys, copied once into
`sealed_sample`; subsequent runs open it rather than comparing randomized encapsulations.
A sample update must remain Auth-openable with the exact pinned token aad.

Only volatile values are normalized: B's actual transmitted token aad has only its validated
32-lowercase-hex nonce replaced by the fixed sample, without rebuilding its JSON. The
transfer id in the aad is replaced by the fixed
32-hex sample after verifying the actual id's encoding and byte-for-byte reserialization;
`expires_in_ms` is normalized to 3,600,000 only after checking [3,500,000, 3,600,000], and
`recheck_in_ms` to 60,000 only after checking [50,000, 60,000]. Field names, presence, other
values and aad order are compared unchanged. Exact clock arithmetic and nonce binding have
separate federation behavior tests.

After updating, run both consumer test files plus the repository build/typecheck/test gates.
A fixture-only field rename and a producer-only field rename must each fail the home producer
fixture test; neither client-written JSON nor a renamed expectation alone proves compatibility.
