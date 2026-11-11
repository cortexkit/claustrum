# Served agent GitHub identity v1

`github-identity.json` pins the `agent.github_identity` replies that claustrum
decodes. Every read comes from entorhinal's real `ProjectsHandler`, through an
admitted route and `handle_served_request`. The fixture binds the reader to
`Reserved(claustrum)`, recorded as
`{"kind":"reserved","moduleId":"claustrum"}`. This exercises handler
admission and dispatch; it does not grant or test a deployed peer's module router
permission.

The file is an ordered array of `{op, request, principal, reply}` records.
`request` is the operation's params object. Successful `reply` values embed the
handler's exact UTF-8 JSON bytes, including the `{"result":…}` envelope, without
parsing and re-serializing them. Each success result has `github_identity`,
`agent_generation`, `generation`, and `incarnation`. A project-bound agent also
has the camel-case `projectId`; agents without a project omit it.

## Records, in order

1. **App, all fields**: live head Mira (`agent_0000000000000001`) has
   `kind: "app"`, `app_id: 314159`, `app_slug: "fern-bot"`,
   `installation_id: 271828`, `client_id: "Iv23syntheticFernBot"`,
   `credential_ref: "github_app:fern-bot"`, and
   `coauthor_line: "Co-authored-by: fern-bot[bot] <314159+fern-bot[bot]@users.noreply.github.com>"`.
   The result includes `projectId: "served-project"`.
2. **App, common live shape**: live assistant Neri
   (`agent_0000000000000002`) has the same app identity without `installation_id`
   or `client_id`. These optional app fields are absent, not `null`.
3. **User token**: live assistant Tavi (`agent_0000000000000003`) has
   `kind: "user_token"`, `login: "fern-gardener"`,
   `credential_ref: "github_user:fern-gardener"`, and an explicit
   `coauthor_line: null`.
4. **Unset identity**: live assistant Sora (`agent_0000000000000602`) has
   `github_identity: null`. The whole identity is null, not an object with a
   null `kind` or an omitted `github_identity` member.
5. **Unknown agent**: unseeded `agent_ffffffffffffffff` refuses with
   `code: "unknown_agent"`, `message: "unknown agent agent_ffffffffffffffff"`,
   and `detail: null`.
6. **Retired agent**: Ivo (`agent_0000000000000004`) refuses with `code: "gone"`,
   `message: "agent is gone"`, and `detail: {"reason":"deleted","at":700}`.
7. **Merged agent**: Luma (`agent_0000000000000601`), merged into Sora, refuses
   with `code: "gone"`, `message: "agent is gone"`, and
   `detail: {"reason":"merged","at":700,"into_agent_id":"agent_0000000000000602"}`.

`kind` has exactly two values today: `app` and `user_token`. The app's
`coauthor_line` is required and non-null; the user-token variant allows a null
`coauthor_line`. Credential references name synthetic vault entries; they are
not credentials. All ids, names, app identifiers, and coauthor addresses in
these samples are invented.

Refusals are handler outcomes, not response bytes. They are recorded as
`{code, message, detail}`, with `null` when no detail was supplied, and do not
have a `result` envelope. In particular, an unknown or gone agent is a refusal,
not a successful null-identity read.

## Fixture and decoder boundary

Project registration uses an empty roots list, so the project has no filesystem
root. Both registration and `agent.import` are real handler requests; the import
transfers agent identity authority from the core snapshot to entorhinal's store.
The snapshot supplies fixed live agent ids and timestamps (`10`);
it does not seed GitHub identities or terminal state. All three identities are
set through `agent.set_github_identity` on the admitted
`Reserved(prefrontal-core)` route. Retirement and merge also use real handler
writes on that route. The fixed serving clock is `700` and the process
incarnation is `0123456789abcdef`. No temporary path or platform-specific path
enters the captured replies.

The non-ignored
`served_vectors::github_identity_records_match_published_file` test regenerates
the records and byte-compares them with this file. The adjacent
`served_vectors::github_identity_published_records_decode` test decodes each
success `result` with a test-local, two-variant, `kind`-tagged serde enum using
`deny_unknown_fields`. It checks the identity values, optional-field omissions,
nulls, project binding, and the three refusal codes and details. A reply-shape
change therefore requires an explicit update to the published decoder boundary.

## Reproduce and verify

From the repository root, regenerate only this JSON file:

```sh
ENTO_WRITE_SERVED_VECTORS=1 cargo test --workspace --all-targets --locked served_vectors::github_identity_records_match_published_file -- --exact --nocapture
```

On PowerShell, set `$env:ENTO_WRITE_SERVED_VECTORS = '1'` before the cargo
command and remove it afterwards. Without that variable, run both named checks:

```sh
cargo test --workspace --all-targets --locked served_vectors::github_identity_
```

`SHA256SUMS` covers the JSON and this README, with filenames relative to this
directory. After regeneration or a README edit, refresh it from the repository
root:

```sh
python3 - <<'PY'
import hashlib
from pathlib import Path
root = Path('test-vectors/agent-github-identity-v1')
names = ['github-identity.json', 'README.md']
root.joinpath('SHA256SUMS').write_text(''.join(
    f'{hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest()}  {name}\n'
    for name in names), encoding='utf-8')
PY
```
