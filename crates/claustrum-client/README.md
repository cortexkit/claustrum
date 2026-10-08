# cortexkit-claustrum-client

Rust client for the claustrum credential vault, used by subc-supervised CortexKit
modules. The vault owns this client alongside its TypeScript client so the wire
decoders can be tested against the producer's serialized replies.

```toml
[dependencies]
cortexkit-claustrum-client = "0.1.0"
```

Construct `ClaustrumCredentialResolver::new(connection_file_path, project_root,
consumer_module_id)` and import the `CredentialResolver` trait to call it. The
resolver lazily opens a route to `claustrum`, presenting the reserved consumer
identity and launch nonce obtained through `subc_os`. Scoped calls require a
supervised process with that nonce and the corresponding vault grants; the
client does not acquire grants or enroll a consumer.

`resolve` reads a credential through a capability handle. `get_scoped` and
`status_scoped` address a credential by its vault ID under the route's
principal. `sign` and `public_key` use vault-held signing keys, which never
leave the vault. `list_scoped` lists the credentials the caller's grants cover.
Handle reads, signing and public-key reads retry transient and transport
failures a bounded number of times; scoped reads return the first error and
leave the redial to the caller. `auth_required` and permanent refusals always
return at once. Listing failures are row-local: callers
should check `undecodable_credentials` and `undecodable_grants`, because the
library does not log them. A grant tuple with a missing, empty or non-string
field is skipped and reported there, never turned into an empty-string grant.

## Contract tests

The reply decoders are tested against real bytes the vault serialises: the
tests read `../credentials-module/tests/fixtures/enrollment_wire_contract.json`
at run time, so they run from a checkout of the vault repository and the fixture
is not part of the published package:

```sh
cargo test --locked -p cortexkit-claustrum-client
```

The fixture holds real `list_scoped`, `credential.get` and `credential.status`
replies. `get` and `get_scoped` serialise the same vault type, so the `get` bytes
cover `get_scoped` too. `sign` and `public_key` replies are not in the fixture
yet; their decoders are covered by hand-written replies in the unit tests.

License: MIT.
