# Machine-key exchange vectors

Normative source: `.cortexkit/internal-docs/designs/device-credential-exchange.md`, reviewed
revision 6, **“B.10 Required vectors and races”**, with the reviewed campaign overrides.
The revision-5 GitHub corpus stays pinned. The separate revision-6 corpus exercises passkey,
Apple, email and Google enrollment and step-up behind off-by-default method enables.
These fixtures do not authorize cutover or certify client, real-browser or operator support.

## Files

| File | Purpose | SHA-256 |
| --- | --- | --- |
| `vectors.json` | Real account-route requests/replies, raw proof transcripts and UTF-8 hex, Ed25519 signatures, JWT headers/claims and refusals. | `1018385d6b632d74fe6c6d63ed1ec07554889483bbe628da6e7a1cf27b5380f1` |
| `refusals.json` | Error/status catalogue copied from the design's B.8 wire contract, independent of route implementation; checked against live enrollment, exchange, relay mint and step-up replies (including exact body fields and retry headers). | `98041300fda819e6ffd526460ada9731140541b5c33780538a9e42dd4543c4ce` |
| `r6-methods.json` | New-method enrollment and all three operation ceremonies: route requests/replies, completion proofs and unchanged attestation claims. | `85d9cce5822df3910e49c42252610aabaa5445f4f92c05519418f8749c0d61cc` |

This README is the checksum index, not a hashed artifact (a self-hash would be circular).
The independent rendezvous device-token renewal corpus is [`test-vectors/rendezvous/renewal.json`](../rendezvous/renewal.json).
Its SHA-256 is `db64c094b196eff84e75b1b411cf6b86b8e3c8c356baf0d1e877fe6773356edf`.
The machine-key generator never reads it as a generation input or writes it.

## Generation and checks

From `workers/account`:

```sh
bun x vitest run test/machine-vectors.test.ts --max-workers=1 --no-isolate
UPDATE_MACHINE_KEY_VECTORS=1 bun x vitest run test/machine-vectors.test.ts --max-workers=1 --no-isolate
bun run vitest run test/machine-vectors-r6.test.ts --max-workers=1 --no-isolate
UPDATE_MACHINE_KEY_VECTORS=1 bun run vitest run test/machine-vectors-r6.test.ts --max-workers=1 --no-isolate
```

The normal test compares newly generated **bytes** to the committed file. A separate test hashes
the committed file and compares it to this README, not to the generator's output. Update mode in
`test/machine-vectors.test.ts` rewrites `vectors.json` and its SHA-256 here, and no other corpus
(including `r6-methods.json`, `refusals.json` and rendezvous renewal). Review changes before pinning;
an update is not a way to approve a changed security outcome.

`test/machine-vectors-r6.test.ts` updates only `r6-methods.json`, `refusals.json` and their two
SHA-256 cells. Its ordinary mode regenerates both byte-for-byte, independently hashes the
committed corpora against this README, and checks the unchanged revision-5 checksum. The new
corpus uses the same fixed time and per-ceremony seeded entropy as the original. Only provider
network/JWKS and mail delivery are stubbed; WebAuthn assertions and completion proofs are signed
and verified through registered routes with real D1. The Ed25519 authenticator uses public
RFC 8032 test material so assertion signatures are reproducible. Provider signing keys are
ephemeral; the Apple/Google token and JWKS network replies are not pinned. GitHub configuration is deliberately wrong
throughout the new-method ceremonies to check that shared routes do not depend on its pins.

`workers/account/test/machine-vectors.test.ts` calls the registered Worker routes with real D1
transactions. Only the GitHub network boundary is stubbed; it checks the pinned redirect URI
at authorization and code exchange. A fake Date and a substituted SQLite clock fix Unix time at
`1800000000000` ms without replacing admission predicates or transaction behavior. Entropy is seeded independently for each operation. Public RFC 8032 test key material makes
requests, sealed challenges, signatures and compact JWTs byte-stable. The keys, OAuth code, cookies and other credentials in this corpus are
**public test material**, never deployment secrets. No production randomness or clocks change.

The `observations` array contains exact request and response bodies plus relevant headers.
`proofs` contains the independently assembled no-newline transcript, its UTF-8 bytes as hex and
signature. `artifacts` decodes signed route output, retaining its compact representation.
Replay ledger counts are independently asserted, but race schedules and outcomes are never pinned
as bytes. Concurrency tests in `machine-enrollment.test.ts` and `machine-exchange.test.ts` run
alongside this file: enrollment exact retries share one registration/spend; worker replay has
one success and one `challenge_spent`. Expected security outcomes are literal assertions,
not derived from the response under test.

## Client vector index

| Proof or artifact | Vector name |
| --- | --- |
| Enrollment raw-code completion | `enrollment:complete` |
| Enrollment possession / attestation | `enroll` / `enrollment:attestation` |
| Possession-bound result recovery, including disabled issuance | `recover` |
| Worker exchange, account audience | `worker:cortexkit-account` |
| Worker exchange, relay audience | `worker:cortexkit-webhook-relay` |
| Worker exchange, runners audience | `worker:cortexkit-runners` |
| Relay credential authorization / permit | `relay-permit` |
| Other-machine retirement step-up | `machine_revoke_other:complete` / `machine_revoke_other:attestation` |
| Other-machine child revoke step-up | `relay_credential_revoke_other:complete` / `relay_credential_revoke_other:attestation` |
| Installation unlink step-up | `relay_installation_unbind:complete` / `relay_installation_unbind:attestation` |
| New-method enrollment | `r6:<method>:machine_enroll:{auth,confirm,complete,attestation}` |
| New-method dangerous-action step-up | `r6:<method>:<operation>:{auth,confirm,complete,attestation}` |

Enrollment itself uses `machine_enroll`, not a generic step-up operation. The three generic
step-ups use the same possession-bound completion transcript with distinct attestation purposes,
audiences and exact targets. Relay consumer/mutation and lifecycle race tests are separate from
these account-issued wire artifacts; their proof index follows below.
The new-method corpus covers `passkey`, `apple`, `email` and `google`, each with enrollment
and `machine_revoke_other`, `relay_credential_revoke_other` and `relay_installation_unbind`.
`auth`, `confirm` and `complete` name route observations;
`attestation` names a decoded artifact retaining its compact JWT. These fixtures use paste
hand-back; the adapter suites separately cover loopback. No `ck account` client changes or
client-support claims are implied.

## B.10 rule-to-proof index

The rows name security rules from the normative design's rule-to-vector checklist;
their names are copied verbatim from **“B.10 Required vectors and races”**. `proven` names
an executable guard regression and its reviewed implementation commit, not a claim of live
browser/CLI interoperability. `follow-up` is an explicit unfulfilled release obligation. Every follow-up has an owner:
`server` and `rendezvous` are **cutover blockers**; non-GitHub methods are required **before any
outside user**. Client/operator obligations need their corresponding integration or deployment
checks, not inference from a similar passing test. In particular, this index is not a blanket
certification of every subcase in the design checklist. Prior relay/verifier mutation evidence
is accepted from the reviewed implementation deliveries; it is not re-run to inflate coverage.

The short prefixes in the Proof column identify these repository-relative test files and
full implementation commit IDs. The existing proofs below are reviewed commits on main;
the newly added closure commit is listed separately for review:

- `E`: `workers/account/test/machine-enrollment.test.ts`, `624468f129d13831cd61657cbb1904714965ec27`.
- `X`: `workers/account/test/machine-exchange.test.ts`, `624468f129d13831cd61657cbb1904714965ec27`.
- `L`: `workers/account/test/machine-lifecycle.test.ts`, `31ecff5aa8324e9d07a6b583702c59257932dba9`.
- `K`: `workers/account/test/machine-key-store.test.ts`, `0edea27b634544bf755694b30dff8320ad4f4767`.
- `O`: `workers/account/test/machine-outbox.test.ts`, `0edea27b634544bf755694b30dff8320ad4f4767`.
- `M`: `workers/webhook-relay/test/machine-lifecycle.test.ts`, `fc991d297e5edabdb5b6d129fece6a00f635be42`.
- `C`: `workers/webhook-relay/test/credential.test.ts`, `624468f129d13831cd61657cbb1904714965ec27`.
- `S`: `workers/webhook-relay/test/machine-step-up.test.ts`, `1160b5ad08369afe9b354d7148b33be0c51e3cbb`.
- `V`: `packages/account-auth/test/worker-verifier.test.ts`, `4ac1eac6c6db7514bb8ad1121dda3837867ad3af`.
- `P`: `packages/account-auth/test/relay-permit-verifier.test.ts`, `624468f129d13831cd61657cbb1904714965ec27`.
- `H`: `workers/account/test/machine-challenge.test.ts`, `b3d3a1ae37890d2abe9292284eae77022ec2a17b`.
- `D`: `workers/rendezvous/test/device-renewal.test.ts` and `device-renewal-vectors.test.ts`, unchanged at `1160b5ad08369afe9b354d7148b33be0c51e3cbb`.
- `new`: expanded enrollment-write, permanent-fingerprint, possession-budget, self-revocation race,
  own-child DELETE and pinning regressions. Their evidence is pinned by the first commit adding this README.
- The five former server/rendezvous cutover blockers are proved by commit
  `459cfcc5a83b88d73a99dd3815bc6e15ecb513ce`, with exact test names in their rows below.
  Its file references are `R/E`: `workers/account/test/machine-enrollment.test.ts`;
  `R/X`: `workers/account/test/machine-exchange.test.ts`;
  `R/C`: `workers/webhook-relay/test/credential.test.ts`;
  `R/M`: `workers/webhook-relay/test/machine-lifecycle.test.ts`;
  `R/S`: `workers/webhook-relay/test/machine-step-up.test.ts`;
  `R/D`: `workers/rendezvous/test/device-renewal.test.ts`.

| Rule | Status | Proof / remaining obligation | Owner |
| --- | --- | --- | --- |
| B.1 Active-human eligibility; independent inventories | proven | E `completion repeats account eligibility after possession verification`; L `exit to service class retires machine authority`; R/D `rendezvous removal and account machine retirement preserve independent inventories`: the same Ed25519 public key is rostered in both inventories; device removal preserves account authority/fences, and machine retirement preserves the device row and successful renewal through the real account Worker binding. | |
| B.2 Immutable approval tuple | proven | E `enrolls only with the dedicated attestation and exact possession-bound tuple`; `confirmation is native form-only and CSRF-bound with no tuple substitutions`. |
| B.2 Human confirmation and safe rendering | proven | E `requires explicit confirmation with safe text and the terminal comparison phrase`. |
| B.2 Browser claim and callback binding | follow-up | E `refuses flow-id-only opens and foreign browser claims and replayed callback state`; `refuses another flow or session and the relay OAuth state namespace`. Real-browser fixation, authenticated two-tab/ambient-session and frame/callback continuity scenarios remain. | client |
| B.2 Two GitHub callbacks | follow-up | E `pins the CortexKit enrollment callback at authorization and token exchange`; relay `test/consent.test.ts` `two registered callbacks route ordinary relay connect and install return to the relay default` at 624468f129d13831cd61657cbb1904714965ec27. Actual App callback registration/default ordering and live cross-endpoint exercise are operator obligations. | operator |
| B.2 Existing GitHub account only | proven | E `unlinked GitHub subject creates neither an account nor an identity`. |
| B.2 Supported methods and intents | follow-up | E `strict start formats refuse duplicate or unknown fields and unsupported methods` preserves the default-disabled observations. Four new adapters now have separate revision-6 vectors; merge-gate review must attach exact regression names and commits before promoting their server subcases. Method enables remain off and no client support is inferred. | server |
| B.2 Loopback binding and scope | follow-up | E `loopback is a literal bound 303 and refuses foreign origin or port hand-backs`. Exclusive local listener, duplicate/refused callback handling, off-host behavior and other OS-user scope require client tests. | client |
| B.2 Paste reverse binding; no downgrade | proven | E `paste reveals a code only after the terminal user code and enforces attempts`; `strict start formats refuse duplicate or unknown fields and unsupported methods`. |
| B.2/B.8 Raw code, not hash, proves hand-back | proven | E `raw completion code is required at both endpoints even with a captured valid proof`; `completion requires possession and spends code and proof exactly once`. |
| B.2/B.8 Fresh-auth deadline | proven | E `fresh authentication expiry cannot be reset by confirmation or handoff`; `completion challenge is bound to the flow and code with an earlier deadline`. |
| B.2 URL residue and logging | follow-up | E `requires explicit confirmation with safe text and the terminal comparison phrase`; account `test/preflight-deploy.node.mjs` at b3d3a1ae37890d2abe9292284eae77022ec2a17b. CLI local query/history/Referer/error-residue and instrumentation inspection remain. | client |
| B.2 Enrollment cap and replacement credit | proven | E `two replacements have one winner; losing admission leaves its attestation and fingerprint untouched`; `the twentieth live key has one winner with no loser spend or cap eviction`. |
| B.2 Permanent fingerprint retirement | proven | new E `retired fingerprint survives roster cleanup and refuses enrollment in the same or another account`; L `raw operational deletion retires keys and preserves permanent evidence`; E `absorbed enrollment recovery returns nothing and exchange never mints under the primary`. |
| B.2 Possession-bound result recovery | proven | E `recovery requires exact tuple and fresh possession, is single-use, and works with issuance disabled`; `expired attestation is not new enrollment authority, but possession recovers the permanent live result`. |
| B.2/B.3/B.5/B.6/B.8 One-use spends | proven | E `completion requires possession and spends code and proof exactly once`; X `stateless challenges do not reserve rows and proof spend has only one concurrent winner`; S `credential concurrent step-up replay has one mutation and one spend`; `installation concurrent step-up replay has one mutation and one spend`. |
| B.3 Guarded batch rollback | proven | new E `a required enrollment %s write failure rolls back replacement, successor and spend` for spend, result, successor, replacement, fingerprint, fence, outbox; E `required proof write failure rolls completion back`. |
| B.3 Commit clock and token lifetime | proven | X `worker challenge expiry uses D1 statement time after asynchronous proof verification`; new X `mint versus self revocation has a bounded token or no spend in both commit orders`; R/X `worker mint versus other-revoke in both commit orders preserves the commit clock and bounded residual` and `permit authorization versus other-revoke in both commit orders preserves the commit clock and bounded residual`, each also instantiated for replacement, status, class, merge and delete. R/X `delayed worker signing by 300001 ms returns status 200 without renewing a spent proof`; `delayed worker signing by 900000 ms returns status 409 without renewing a spent proof`; `delayed permit signing by 60000 ms returns status 409 without renewing a spent proof`; `delayed permit signing by 300001 ms returns status 409 without renewing a spent proof` pin immutable spend time, exact expiry boundaries and lost-reply replay. | |
| B.3/B.8 Abuse budgets | proven | new X `challenge flooding and invalid proof leave the sixty-proof possession budget intact with equal retry delay`; X `stateless challenges do not reserve rows and proof spend has only one concurrent winner`. |
| B.4 Worker verifier and human refusal | proven | V `requires exactly the six claims, with no issuer or payload type additions`; `requires a positive lifetime no longer than 900 seconds`; `refuses worker headers on the human path even with human audience and claims`; X `mints exactly six claims for one worker audience using the account signing key and commit time`. |
| B.4 Public-edge principal integrity | proven | E `rebuilds principals from bearer tokens and refuses bodies on DELETE`; C `permit mint positive control: human and shared-verifier worker paths insert only parented credentials`. |
| B.5 Closed route and internal-mint gates | proven | C `valid permit still cannot mint while the Part B switch is missing or false`; new C `machine deletion names only its own child, rejects bodies, and needs no step-up with switch %s` for true/false. |
| B.5 Permit tuple and verifier | proven | C `relay permit tuple rejects principal, device, source and request substitutions before insertion`; P `permit rejects changed claim inventory`; `permit rejects untrusted kid`. |
| B.5 Source cap and lost bearer reply | proven | C `relay permit replay has exactly one winner and the four-source cap leaves loser permits unspent`; permit replay cannot recover plaintext. |
| B.5/B.7 Child/fence commit ordering | proven | C `a fence acknowledged during the fresh-check await prevents a late child`; R/C `replacement across fresh check and child commit leaves no child after acknowledgment`; `merge across fresh check and child commit leaves no child after acknowledgment`; `delete across fresh check and child commit leaves no child after acknowledgment`. Each covers before-check, during-check, after-check fence-before-insert, after-check insert-before-fence and after-insert. Real account mutations produce the events; acknowledged fences leave no live child, and old permits create no later child/spend. R/X's permit-authorization commit-order cases cover retirement during authorization. | |
| B.7 Fresh primary mint check replaces fallback | proven | C `each permit mint needs a fresh primary check, and higher fences refuse without spending`; `mint refuses lookup outage even with previously installed live fences`; M `fresh checks install maxima without advancing unseen event heads and never cache mint authority`. |
| B.7 Admission despite stuck outbox | proven | M `fail-open admission arms five-minute retry; recovered service refuses a revoked bearer before supersession`. |
| B.7 Pending-interval exposure | proven | M `failed alarm pull keeps forwarding without a lease and retries in five minutes`; R/M `pending interval unreachable permits supersession and ack deletion only until fence installation` and `pending interval revoke-after-read permits supersession and ack deletion only until fence installation` demonstrate the accepted takeover, continued forwarding and buffered-event deletion while the outbox is pending, then refusal after durable installation/acknowledgment even on lookup failure. R/M `healthy admission during pending propagation blocks takeover and preserves another parent's buffered events` supplies the healthy control. | |
| B.7 Alarm pull and no lease | proven | M `fresh mint and admission reads cannot postpone an existing connected parent's pull`; `alarm visits every connected parent and a failed key cannot defer another key's pull`; `bad MAC and stored secret never drive a parent fence read`. |
| B.7 Durable socket enforcement | proven | M `frames and pumps enforce durable fences even if socket closure after commit was lost`; `local fence checks independently block frames when a durable credential row still looks live`. |
| B.7 Per-account drainer liveness | proven | O `two concurrent drainers cannot hold a live per-account claim`; `scheduled rescue after a commit crash makes progress for another account despite relay outage`; `retry backoff is durable, jittered and capped without a retry-count cutoff`. |
| B.7 Head ordering independent of installation | proven | M `gap installs immediately; later contiguous event advances a check-installed sequence`; `real account outbox binding reconciles gaps, acknowledges committed fences, and covers duplicate heads`. |
| B.7 Consistent source snapshot and atomic restore | proven | K `a revocation racing snapshot delivery cannot attach a newer head to older fences`; M `invalid snapshot tuples cannot advance a covered head or install partial keys`. Source snapshots are unpaginated complete cuts. |
| B.7 Effective-maximum sweeps | proven | M `effective maximum sweeps old generations across sources but preserves new children on delayed events and snapshots`. |
| B.7 Lifecycle paths and safe triggers | proven | L `50 returning logins leave every machine ledger and fence count unchanged`; `populated-ledger trigger predicates use indexed account searches`; `live machine physical cleanup refuses but retired cleanup succeeds`. |
| B.7/B.8 Permanent security state | proven | O `pruning preserves permanent security state, pending payloads and spends through expiry plus 60 seconds`; L `terminal retirement still refuses authority after status reactivation`; M `pruning revoked credentials leaves permanent fence sequences and heads intact`. |
| B.7 Security-state loss | proven | M `missing local security state cannot fail open and complete reconciliation restores it`. |
| B.6 Mutation-local step-up binding | proven | S `credential parent substitution refuses without burning the exact step-up`; `bodyless DELETE binding rejects added mutation parameters at both public routes`; E `a completed revocation ceremony authorizes exactly one public machine-key retirement`. |
| B.6 DO RPC and statement-time expiry | proven | S `credential expiry at SQLite statement time leaves mutation and spend unchanged`; `installation expiry at SQLite statement time leaves mutation and spend unchanged`; zero-row rollback/reuse and concurrent replay tests. |
| B.6 Unlink generation and loss warning | proven | S `installation unlink rebind invalidates the old generation without a spend`; `installation generation is rechecked after the alarm await`; E `issues relay_installation_unbind only after human confirmation without enrolling the channel key`. |
| B.6 Scope and existing controls | proven | Account `test/index.test.ts` `service create rejects an attestation from a different admin account`; `mint-service attestations cannot be reused between enrollment and rotation` at 1160b5ad08369afe9b354d7148b33be0c51e3cbb; machine allowlist remains closed. |
| B.8 Exact format and refusal fixtures | proven | R/E `every account JSON endpoint rejects unknown, duplicate, missing, wrong-type and oversized fields before mutation`; `canonical identifiers, keys, secrets, labels and nested step-up targets refuse without normalization`; `browser query and confirmation fields are exact and byte-bounded`; `all five possession transcripts use exact UTF-8 separators and no trailing newline`. R/C `relay mint exact field and refusal fixtures reject malformed bodies without a child or spend`; `relay refusal fixtures pin permit expiry, principal mismatch, cap, fence and service failure statuses`. R/E, R/X and R/S also apply the independent `refusals.json` catalogue to existing live refusal scenarios, checking exact statuses/fields/header equality; existing relay DELETE `not_found` remains separate. Pinned route/proof/JWT bytes remain unchanged. | |
| B.8 Envelope/MAC and deadlines | proven | H `refuses noncanonical JSON and tampered MACs`; `rotates issuance to the current key and refuses previous after retention`; X statement-time challenge expiry; S statement-time step-up expiry. |
| B.9 Additive deploy and rollback floor | proven | Account `test/rollback-compat.test.ts` `previous resolve, guarded merge DELETE and status UPDATE work with populated machine state` at 31ecff5aa8324e9d07a6b583702c59257932dba9; relay `test/machine-lifecycle.test.ts` `closed gate preserves delivery for connected null-parent and parented credentials` at fc991d297e5edabdb5b6d129fece6a00f635be42. Closed-gate deployment and null-parent retirement remain coordinated operator steps. |
| B.9 Off-by-default kill switch | proven | X `new authority remains off by default under missing and false switches`; E `revocation step-up login and completion remain usable while machine issuance is off`; C `valid permit still cannot mint while the Part B switch is missing or false`. |
| Delivery/Part A carry-overs | proven | D renewal regression set and `workers/rendezvous/test/verifier.test.ts`, unchanged; Part A byte/SHA comparison and the account/relay missing-switch gates rerun in this delivery. |
| B.2 Ordinary-login intent refusal | follow-up | Review POST `/v1/login/start`, `/v1/login/email/start`, `/v1/login/apple/start`, `/v1/login/passkey/prepare` and `/v1/login/passkey/start` for `machine_enroll`, `step_up` and unknown-intent refusal with both switch states; preserve poll, verify and existing callbacks. Attach named tests and implementation commit. | server |
| B.2 Confirm CSRF timing | follow-up | Review preauth/Confirm token separation and rotation, fresh-cookie binding, and no CSRF write before fresh auth or after Confirm/completion. Attach named tests and implementation commit. | server |
| B.2 r6 Shared method and identity binding | follow-up | Review closed method/kind/attempt binding, linked active-human identity only, no account/identity/credential creation and no fallback. Attach named tests and implementation commit. | server |
| B.2 r6 Apple claimed rejoin | follow-up | Review cookie-free encrypted ingress, bounded receipts, claimed-browser Continue and one-use state/receipt spending. Synthetic ingress is not a live SameSite check. Attach named tests and implementation commit. | server |
| B.2 r6 Apple identity and redirect | follow-up | Review verified `sub`, nonce, issuer/audience, code-only pinned callback and denial/configuration failures. Attach named tests and implementation commit. | server |
| B.2 r6 Passkey isolated WebAuthn | follow-up | Review authenticate-only linked credentials, UV, RP/origin, CSP and script-free explicit Confirm. Attach named tests and implementation commit. | server |
| B.2 r6 Passkey spend and counter races | follow-up | Review attempt/challenge spends, counter ownership races, retries and unchanged fresh-auth deadlines. Attach named tests and implementation commit. | server |
| B.2 r6 Email verified delivery and ownership | follow-up | Review linked normalized email identity, non-enumerating delivery outcomes, mailbox acknowledgement and code namespace isolation. Attach named tests and implementation commit. | server |
| B.2 r6 Email expiry resend and locks | follow-up | Review 300-second expiry, resend budgets, fifth-guess flow lock and address cooldown on a fake clock. Attach named tests and implementation commit. | server |
| B.2 r6 Google pinned browser OAuth | follow-up | Review browser-client pinned redirects, S256/verifier, OIDC subject/nonce/issuer/audience/azp and denial/configuration failures. Attach named tests and implementation commit. | server |
| B.2 r6 Method change and weaker identity | follow-up | Review method substitution refusals and allowed linked-method approval, including email. This is not an owner decision to enable email. Attach named tests and implementation commit. | server |
| B.2 r6 Per-method abuse budgets | follow-up | Review rolling route caps, flow/identity budgets, shared ordinary-email buckets and receipt bounds with fake clocks. Attach named tests and implementation commit. | server |
| B.6 r6 All-method dangerous-action matrix | follow-up | Review each method and operation through account-issued attestation, both hand-back modes, master-off step-up and account target rechecks. Relay credential/installation Confirm-time target rechecks remain deferred; mutation-time relay checks do not prove them. Attach named tests and implementation commit. | server |
| B.8 r6 Browser wire and refusals | follow-up | Review exact route schemas, new refusal status/body/retry fields and deterministic `r6-methods.json`/`refusals.json` bytes. Attach named tests and implementation commit. | server |
| B.9 r6 Adapter deploy and rollback | follow-up | Review additive backfill, secret/receipt retention, cleanup triggers, per-method gates, preflight and adapter drain preserving machine authority ledgers. Attach named tests and implementation commit. | server |

All revision-6 rows above start as `follow-up`; the presence of vectors alone does not promote
their security subcases. Independent release obligations remain:

| Obligation | Status | Required evidence | Owner |
| --- | --- | --- | --- |
| Apple claimed rejoin in a real browser | follow-up | Cross-site form POST omits the Lax claim cookie; following first-party resume GET carries it, and explicit Continue is required. | browser/client |
| Isolated passkey page and explicit hand-back | follow-up | A real browser executes the nonce-CSP WebAuthn page and reaches script-free Confirm without auto-confirmation; hand-back follows explicit Confirm only. Client paste/loopback support needs client evidence. | browser/client |
| Provider callback registration and Google Web identity | follow-up | Live Apple/Google callback registration; pinned Google authorize/exchange redirect and S256, correct/wrong verifier behavior, and equality of Web-client/device-flow `sub`. | operator |
| Method enablement and email approval policy | follow-up | Record server merge-gate and live checks separately before any enable; email additionally requires the owner's pending decision on whether any linked method, including email, may approve a machine or the strongest linked method is required (decision record `ask_59782f621d035620`). | operator |
| Relay targets at Confirm time | follow-up | Credential/installation metadata recheck is deferred; unchanged relay mutation-local checks are not evidence of a Confirm-time lookup. | server |
