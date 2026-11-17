# Development desktop approval vectors v1

Development only; remove before the next public release. No desktop signing key
is used. The device fingerprint is 32 zeros. Agent, flow and manifest requests
and replies are produced by the real vault approval transactions. Refusals are
produced by the real daemon route dispatcher, without changing audit, pending
request, grant, replay, phone-observation or manifest tables.
The fixed timestamps are test inputs, not valid approval times today.

Regenerate agent.json and flow.json with the core test
`desktop_dev_agent_and_flow_approvals_share_phone_grants_and_emit_vectors`,
manifest.json with `desktop_dev_manifest_approval_uses_shared_commitments_and_emits_vector`,
and refusals.json with the module test
`desktop_dev_route_refusals_write_nothing_and_emit_vectors`. Set
`CK_EMIT_SECRET_VECTORS=1`, then run
`desktop_dev_vector_inventory_is_generated_and_byte_pinned` last with the same
setting to generate this README and SHA256SUMS. Normal runs byte-compare samples.

SHA256SUMS covers this README and every JSON sample. Existing phone vectors are
unchanged. No production keys, secret material or grant bearer values are stored.
