# cortexkit-claustrum-client

Rust client for the claustrum credential vault, used by subc-supervised CortexKit
modules. The vault owns this client alongside its TypeScript client so the wire
decoders can be tested against the producer's serialized replies.

```toml
[dependencies]
cortexkit-claustrum-client = "0.7.0"
```

The default `transport` feature provides the resolver and live watch connection.
If you already own a bus connection, use `cortexkit-claustrum-client = { version =
"0.7.0", default-features = false }` for the public `decode_*_reply` functions,
`decode_wire_error`, record/error types, `WatchNotice`, and `WatchTracker` without
`subc-transport`, `subc-os`, or Tokio. `subc-protocol` remains for the reply error
codes; no socket or authentication code is built in this mode.

Construct `ClaustrumCredentialResolver::new(connection_file_path, project_root,
consumer_module_id)` and import the `CredentialResolver` trait to call it. The
resolver lazily opens a route to `claustrum`, presenting the reserved consumer
identity and launch nonce obtained through `subc_os`. Scoped calls require a
supervised process with that nonce and the corresponding vault grants; the
client does not acquire grants or enroll a consumer.

`resolve` reads a credential through a capability handle. `get_scoped` and
`status_scoped` address a credential by its vault ID under the route's
principal. Use `get_scoped_with_min_ttl(credential_id, min_ttl_ms)` when the
served token must remain valid for a bounded request duration; ordinary
`get_scoped` omits `min_ttl_ms` from the wire request. Successful reads expose
optional `account_id`, `email`, and `org_name` metadata on `ResolvedCredential`
when the vault has captured those identity fields. These values are non-secret;
the credential payload remains redacted in `Debug` output.

`report_auth_failure(credential_id, record_version, provider_status)` sends a
version-fenced report for the credential version that was used. The client
rejects statuses other than 401 and 403 before sending. Its boolean result is the
vault's `accepted` answer, not proof that state changed: a stale version is
accepted and ignored. After reporting, read again; if the version did not move,
stop rather than looping. For a static API key, a 401 means the key is dead.

`sign` uses vault-held signing keys, which never leave the vault. `public_key` returns
the public half of a vault-held key: an Ed25519 signing key or an X25519 KEM key.
`CredentialPublicKey::algorithm` is a `PublicKeyAlgorithm` (`Ed25519` or `X25519`);
check it before use, because a KEM key cannot verify a signature. The decoder refuses
any other algorithm, and a `key_id` that is not the first 8 bytes of SHA-256 over
the public key.
`seal(SealRequest { credential_id, recipient_public_key, info, aad, plaintext })`
seals one message in HPKE Auth mode (RFC 9180 mode 2) under a vault-held KEM key,
for a recipient that opens it with that key's public half. It needs an exact `seal`
grant; the vault audits every call, so a retried seal is recorded once per attempt.
`list_scoped` lists the credentials the caller's grants cover. Handle reads,
signing, sealing and public-key reads retry transient and transport failures a bounded
number of times; scoped reads return the first error and leave the redial to the
caller. `auth_required` and permanent refusals always return at once. Listing
failures are row-local: callers should check `undecodable_credentials` and
`undecodable_grants`, because the library does not log them. A grant tuple with
a missing, empty or non-string field is skipped and reported there, never turned
into an empty-string grant.

A transport `Error` frame (`{code, message}`, no class) whose code a retry cannot
change, such as `unknown_method`, `invalid_params`, `invalid_request`,
`flow_scopes_unsupported` or `invalid_control_body`, comes back as
`CredentialErrorClass::Unclassified` with the vault's code in `code()`. It is not
`retryable()`, so it returns at once and is never retried. One that answers a call on
an established route keeps that connection rather than redialing; one that refuses the
route itself (`flow_scopes_unsupported`, `invalid_control_body`) fails the connect, so
the next call dials again. `unknown_method` from a vault means the vault
predates the operation: update the vault. A scoped watch is the exception: there
`unknown_method` ends the watch as `Unsupported`, the signal to poll instead. `unknown_module` and the other daemon
routing refusals are the exception: they are `Transport`, so the next call redials and
the reads that retry transport failures retry them, because they say the credential
module was not reachable rather than anything about the request.

## Watching for changes

`CredentialResolver::watch_scoped(enrollment_token)` opens one dedicated raw
transport connection so a held watch cannot block ordinary resolver calls. Its
`ScopedWatch` yields typed notices with `next().await`; drain those before awaiting
`closed().await`. `stop()` (or dropping the handle) sends best-effort CANCEL. The
32-notice queue is bounded: a slow reader ends with `TransportLost`, not silent
loss inside the client. The client never reconnects or re-subscribes on its own.

`ScopedWatchOutcome` distinguishes `Refused(error)` (including revocation after
notices), `Ended` (STREAM_END after notices), `TransportLost(error)` (including
`route_closed`), `Unsupported` (`unknown_method`, so poll), and `Stopped`.
`InvalidNotice` and `InvalidResponse(error)` are typed protocol failures. A
zero-notice STREAM_END confirms `list_scoped` once with the same token: a refusal
is terminal, success is `NotAccepting` (retry only after caller backoff/reconnect).
Raw Response refusals are decoded directly, without that confirming read.

### Reusing an existing SubcConsumer

No second connection or SDK dependency is needed to use the public transport-free
`WatchNotice::decode(bytes)` and `WatchTracker`. The decoder denies unknown fields,
requires `kind: "changed"`, a nonempty epoch, a positive safe-integer sequence, and
string view/key digests. The tracker is synchronous and pure: no IO, timers, clocks,
or async work. Feed it observations from your own `SubcConsumer::subscribe` or
`subscribe_route` and execute the returned `WatchAction` in your existing loop.

Read `list_scoped` on connect and call `tracker.inventory_read(listing.view)` only
after that read succeeds. Key-announcing callers likewise call `keys_read(digest)`
after re-reading held public keys. Do not acknowledge a hint as a completed read.
Call `opened()` for every new subscription, then feed each decoded notice to
`notice(&notice)`. The decision table is pinned row by row by `tracker_*` tests:

| Observation | Action |
| --- | --- |
| First notice / new epoch / noncontiguous seq | `Reread { inventory: true, keys: <digest differs> }` |
| Changed view vs last successful list read | Re-read inventory (even if an earlier hint asked for the same read). |
| Only keys changed | `Reread { inventory: false, keys: true }` |
| Contiguous notice, acknowledged view and keys unchanged | `Reread { inventory: false, keys: false }` |
| Subscription closes after notices | `ResubscribeAndReread` once; duplicate close observations return `Stop`. |
| Subscription closes with zero notices | `ReadListOnce`, never re-subscribe blindly. |
| Confirming list succeeds | `list_result(true)` → `RetryLater`; caller supplies backoff/reconnect. |
| Confirming list refuses | `list_result(false)` → `Stop`. |
| Route lost (including `route_closed`) | `route_lost()` → `ReconnectAndReread`; duplicate loss after closure → `Stop`. |
| `unknown_method` | `unknown_method()` → named `Fallback` (keep polling). |
| A visible Response refusal | `refused()` → `Stop`. |
| Notice after closure | `Stop`. |

For an SDK that erases terminal Response bodies, feed a successful `closed()` to
`tracker.closed()`. A revoked mid-watch enrollment first returns
`ResubscribeAndReread`; on the new zero-notice watch, `ReadListOnce` discovers the
terminal refusal. Never loop after that zero-notice close. For each close after
notices, perform at most one re-read/re-subscribe action, then call `opened()`.

```rust,ignore
let mut tracker = WatchTracker::default();
tracker.inventory_read(list_scoped_on_existing_consumer().await?.view);
tracker.opened();
let mut subscription = consumer.subscribe_route(route, watch_request, options).await?;
while let Some(bytes) = subscription.events().recv().await {
    let notice = WatchNotice::decode(&bytes)?;
    let action = tracker.notice(&notice);
    // Execute action with the same consumer; acknowledge completed reads above.
    apply_watch_action(action).await?;
}
let action = match subscription.closed().await {
    Ok(()) => tracker.closed(),
    Err(error) if error.code() == Some("unknown_method") => tracker.unknown_method(),
    Err(_) => tracker.route_lost(),
};
apply_watch_action(action).await?;
```

`view` compares the inventory last read; `keys` is independent and only matters to
callers announcing vault-held public keys. After reconnecting a route, reopen the
watch: its first notice has seq 1 and current digests, covering changes that may
have happened while disconnected. Neither digest is an event journal, and refresh-only writes do
not change them.

## Contract tests

The reply decoders are tested against real bytes the vault serialises: the
tests read `../credentials-module/tests/fixtures/enrollment_wire_contract.json`
at run time, so they run from a checkout of the vault repository and the fixture
is not part of the published package:

```sh
cargo test --locked -p cortexkit-claustrum-client
```

The fixture holds real `list_scoped`, `credential.get`, `credential.get_scoped`,
`credential.status`, `credential.sign`, `credential.public_key`, `credential.seal`
and `credential.report_auth_failure` replies. The Rust tests decode producer-generated
account identity metadata when present, verify absence when omitted, and decode
the report's `accepted` answer. The signing and scoped successes run through the
vault's real read surface and request dispatcher with synthetic test material.
Rust tests pin the decoded Ed25519 key ID, algorithm and exact signature and
public-key hex, and verify the signature over the fixture's message with `ring`.
They also decode the X25519 public-key reply for the vault KEM key that produced
the seal sample.
The seal tests pin that the client sends exactly the producer's accepted request
and decodes its reply's exact bytes.

## Changes

- 0.7.0 (breaking): `CredentialPublicKey::algorithm` is now the
  `PublicKeyAlgorithm` enum instead of a `String`, and `decode_public_key_reply`
  accepts X25519 KEM public keys as well as Ed25519 signing keys. Callers that
  compared the field to `"ed25519"` should match `PublicKeyAlgorithm::Ed25519`.

License: MIT.
