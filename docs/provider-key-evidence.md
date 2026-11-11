# Provider key evidence

The catalog records observations from deliberately bogus API keys, not rules that the
vault evaluates. Requests used the existing login check, with redirects disabled, on a
network-enabled Linux build server on 2026-11-10. Cloudflare Workers AI used the dummy
account id `00000000000000000000000000000000`. No real provider key was used.

A dash means that no string-valued error code was observed. Numeric codes are not
coerced to strings. Where an API uses an error type or structured reason as its code,
the pointer identifies that exact string. Only provider authentication refusals go
in the evidence table. Other observed replies are listed below and leave the row's
`invalid_key` as `None`. The existing check assignments and response classification
are unchanged.

| row | url | date | status | error_code | code field |
| --- | --- | --- | --- | --- | --- |
| 302ai | https://api.302.ai/v1/models | 2026-11-11 | 401 | - | - |
| abacus | https://routellm.abacus.ai/v1/chat/completions | 2026-11-11 | 403 | GenericPermissionDeniedError | /errorType |
| abliteration | https://api.abliteration.ai/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| above | https://api.above.dev/v1/chat/completions | 2026-11-11 | 401 | - | - |
| agnes | https://apihub.agnes-ai.com/v1/chat/completions | 2026-11-11 | 401 | - | - |
| ai-router | https://api.ai-router.dev/models | 2026-11-11 | 401 | INVALID_API_KEY | /code |
| ai21 | https://api.ai21.com/studio/v1/library/files | 2026-11-11 | 401 | - | - |
| aiand | https://api.aiand.com/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| aihubmix | https://aihubmix.com/v1/chat/completions | 2026-11-11 | 401 | - | - |
| aimlapi | https://api.aimlapi.com/v2/billing | 2026-11-11 | 401 | UnauthorizedException | /error/name |
| ainetcafe | https://microquickjs.com/v1/models | 2026-11-11 | 401 | - | - |
| aixy | https://api.aixy-gateway.com/v1/models | 2026-11-11 | 401 | invalid_gateway_api_key | /error/code |
| aki-io | https://aki.io/openai/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| alibaba | https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| alibaba-cn | https://dashscope.aliyuncs.com/compatible-mode/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| alibaba-coding-plan | https://coding-intl.dashscope.aliyuncs.com/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| alibaba-coding-plan-cn | https://coding.dashscope.aliyuncs.com/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| alibaba-token-plan | https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/models | 2026-11-11 | 401 | InvalidApiKey | /code |
| alibaba-token-plan-cn | https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/models | 2026-11-11 | 401 | InvalidApiKey | /code |
| ambient | https://api.ambient.xyz/v1/assistants | 2026-11-11 | 401 | authentication_error | /error/type |
| amd | https://developer.amd.com.cn/radeon/api/v1/models | 2026-11-11 | 401 | - | - |
| anthropic | https://api.anthropic.com/v1/models | 2026-11-10 | 401 | authentication_error | /error/type |
| anyapi | https://api.anyapi.ai/v1/models | 2026-11-11 | 401 | 401 | /error/code |
| arcee | https://api.arcee.ai/api/v1/models | 2026-11-11 | 401 | - | - |
| auriko | https://api.auriko.ai/v1/me | 2026-11-11 | 401 | invalid_api_key | /error/code |
| baseten | https://inference.baseten.co/v1/models | 2026-11-10 | 401 | - | - |
| charm-hyper | https://hyper.charm.land/v1/credits | 2026-11-10 | 401 | authentication_error | /error/type |
| cloudflare-workers-ai | https://api.cloudflare.com/client/v4/accounts/00000000000000000000000000000000/ai/models/search?per_page=1 | 2026-11-10 | 400 | - | - |
| deepinfra | https://api.deepinfra.com/v1/openai/chat/completions | 2026-11-10 | 401 | invalid_api_key | /error/code |
| deepseek | https://api.deepseek.com/chat/completions | 2026-11-10 | 401 | invalid_request_error | /error/code |
| elevenlabs | https://api.elevenlabs.io/v1/user | 2026-11-11 | 401 | unauthorized | /detail/code |
| firecrawl | https://api.firecrawl.dev/v2/team/credit-usage | 2026-11-10 | 401 | - | - |
| fireworks-ai | https://api.fireworks.ai/v1/accounts/fireworks/models?filter=supports_serverless%3Dtrue&pageSize=1 | 2026-11-10 | 401 | UNAUTHORIZED | /error/code |
| google | https://generativelanguage.googleapis.com/v1beta/models | 2026-11-10 | 400 | API_KEY_INVALID | /error/details/0/reason |
| huggingface | https://huggingface.co/api/whoami-v2 | 2026-11-10 | 401 | - | - |
| inception | https://api.inceptionlabs.ai/v1/chat/completions | 2026-11-10 | 401 | invalid_api_key | /error/code |
| kiro | https://q.us-east-1.amazonaws.com/ListAvailableModels?origin=AI_EDITOR | 2026-11-10 | 403 | - | - |
| meta | https://api.meta.ai/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| minimax-code | https://api.minimax.io/v1/chat/completions | 2026-11-10 | 401 | authorized_error | /error/type |
| minimax-code-cn | https://api.minimax.cn/v1/chat/completions | 2026-11-10 | 401 | authorized_error | /error/type |
| mistral | https://api.mistral.ai/v1/models | 2026-11-10 | 401 | - | - |
| moonshot | https://api.moonshot.ai/v1/chat/completions | 2026-11-10 | 401 | invalid_authentication_error | /error/type |
| openai | https://api.openai.com/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| openrouter | https://openrouter.ai/api/v1/auth/key | 2026-11-10 | 401 | - | - |
| perplexity | https://api.perplexity.ai/chat/completions | 2026-11-10 | 401 | invalid_api_key | /error/type |
| qwen-portal | https://portal.qwen.ai/v1/chat/completions | 2026-11-10 | 401 | invalid_api_key | /error/code |
| siliconflow | https://api.siliconflow.com/v1/models | 2026-11-10 | 401 | - | - |
| siliconflow-cn | https://api.siliconflow.cn/v1/models | 2026-11-10 | 401 | - | - |
| singularityapi-dev | https://api.singularityapi.dev/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| singularityapi-tech | https://api.singularityapi.tech/v1/models | 2026-11-10 | 401 | 401 | /error/code |
| stepfun | https://api.stepfun.ai/v1/chat/completions | 2026-11-10 | 401 | invalid_api_key | /error/type |
| umans | https://api.code.umans.ai/v1/messages | 2026-11-10 | 401 | authentication_error | /error/type |
| venice | https://api.venice.ai/api/v1/chat/completions | 2026-11-10 | 401 | - | - |
| wafer-serverless | https://pass.wafer.ai/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| xai | https://api.x.ai/v1/models | 2026-11-10 | 400 | invalid-argument | /code |
| xiaomi-token-plan-ams | https://token-plan-ams.xiaomimimo.com/v1/chat/completions | 2026-11-10 | 401 | 401 | /error/code |
| xiaomi-token-plan-cn | https://token-plan-cn.xiaomimimo.com/v1/chat/completions | 2026-11-10 | 401 | 401 | /error/code |
| xiaomi-token-plan-sgp | https://token-plan-sgp.xiaomimimo.com/v1/chat/completions | 2026-11-10 | 401 | 401 | /error/code |
| zai | https://api.z.ai/api/coding/paas/v4/chat/completions | 2026-11-10 | 401 | 401 | /error/code |
| zhipu-coding-plan | https://open.bigmodel.cn/api/coding/paas/v4/chat/completions | 2026-11-10 | 401 | 401 | /error/code |

## ElevenLabs key check

On 2026-11-11 a network-enabled Linux build server sent a deliberately bogus key
in the raw `xi-api-key` header to `GET https://api.elevenlabs.io/v1/user`. The
response was HTTP 401 with `detail.code` equal to `unauthorized`,
`detail.status` equal to `invalid_api_key`, and the message `Invalid API key`.
The authentication documentation at
<https://elevenlabs.io/docs/api-reference/authentication> specifies the header and
the fixed `api.elevenlabs.io` host. The read-only user endpoint is documented at
<https://elevenlabs.io/docs/api-reference/user/get>.

## Rows added from the Fusiform provider list

On 2026-11-11 a network-enabled Linux build server sent each new row's key check by
hand with curl, redirects not followed: the check's method and URL, the row's
`Authorization: Bearer` header carrying a deliberately bogus key, and for chat checks
the login check's one-token request body. Keys for `above` (`sk-gw-`) and `aixy`
(`gak_`) carried the documented prefix; an unprefixed key got a format refusal
(`above`) or a missing-key code (`aixy`) instead. Generic error types that every API
error carries (302.AI `api_error`, AIHubMix `Aihubmix_api_error`, Agnes AI
`AgnesAI_error`) and empty `code` strings (Agnes AI, ainetcafe) are not recorded as
codes. A request without any key was also sent; where it got the same reply as the
bogus key (`anyapi`, `ambient`, `auriko`, `ainetcafe`), the line still records only
the bogus-key reply.

Hosts and key presentation were taken from these provider pages:

- `302ai`: <https://help.302.ai/docs/ji-cheng-dao-OpenAI-guan-fang-SDK> sets
  `https://api.302.ai/v1` as the OpenAI SDK base URL; key page
  <https://dash.302.ai/apis/list>.
- `abacus`: <https://abacus.ai/help/route-llm/> documents the self-serve
  `routellm.abacus.ai` host and Bearer keys. Enterprise workspaces use a
  per-workspace host that the row does not cover. `/v1/models` answered a bogus
  key with 200, so the check is a `route-llm` chat.
- `above`: <https://above.dev/docs>. `/v1/models` answered a bogus key with 200,
  so the check is a chat.
- `agentrouter`: <https://agentrouter.org/docs/opencode.html> documents
  `agentrouter.org` and Bearer keys for the OpenAI protocol. Its Claude app guide
  sends users to <https://ps.air-outer.com/console/token> for tokens. Every probe,
  with or without a key, got 401 `unauthorized_client_error` ("unauthorized client
  detected"), so the row is stored unchecked and has no evidence line.
- `agnes`: <https://agnes-ai.com/doc> documents `apihub.agnes-ai.com` and Bearer
  keys. `/v1/models` answered a bogus key with 200, so the check is a chat.
- `ai-router`: <https://ai-router.dev/docs/getting-started/first-request/> documents
  `https://api.ai-router.dev/models` (no `/v1`) with a Bearer key.
- `ai21`: <https://docs.ai21.com/reference/authentication> documents Bearer keys for
  `api.ai21.com`. `/studio/v1/models` answered a bogus key with 200 and an empty
  list, so the check is the documented library file list.
- `aihubmix`: <https://docs.aihubmix.com/cn/quick-start> documents `aihubmix.com` and
  the `api.inferera.com` fallback. `/v1/models` answered a bogus key with 200, so
  the check is a chat.
- `aimlapi`: <https://docs.aimlapi.com/readme-1> documents `api.aimlapi.com`. Its
  model list answered a bogus key with 200, so the check is the documented
  `/v2/billing` balance read.
- `ainetcafe`: <https://ainetcafe.com/k3/guides/> and
  <https://ainetcafe.com/k3/guides/codewhale.html> send `sk-` keys to
  `microquickjs.com`.
- `aixy`: <https://docs.aixy-gateway.com/integrations/overview>.
- `aki-io`: <https://aki.io/docs/compatibility/openai-api-compatibility/> documents
  the `https://aki.io/openai/v1/models` request.
- `alibaba`, `alibaba-cn`, `alibaba-coding-plan`, `alibaba-coding-plan-cn`,
  `alibaba-token-plan` and `alibaba-token-plan-cn`:
  <https://www.alibabacloud.com/help/en/model-studio/base-url> and
  <https://help.aliyun.com/zh/model-studio/base-url> list the Singapore and Beijing
  hosts; <https://www.alibabacloud.com/help/en/model-studio/coding-plan> and
  <https://help.aliyun.com/zh/model-studio/coding-plan> list the Coding Plan hosts.
  Model Studio keys belong to one region; keys from other regions and
  workspace-specific hosts are not covered. Coding Plan `/v1/models` answered a bogus
  key with 200, so those checks are chats.
- `ambient`: <https://ambient.xyz/docs/build/api> documents that `/v1/models` needs
  no key, so the check is the documented assistant list.
- `amd`: <https://amd-aim.github.io/radeon-cloud-docs/api/authentication/> and
  <https://amd-aim.github.io/radeon-cloud-docs/guides/token-factory/> document `rc-`
  keys sent as Bearer to `https://developer.amd.com.cn/radeon/api/v1`. Without a key
  the model list answered 401 "Login required"; with a bogus key, "Invalid bearer
  token".
- `anyapi`: <https://docs.anyapi.ai/guides/authentication>.
- `arcee`: <https://docs.arcee.ai/api-reference/your-first-api-call>.
- `auriko`: <https://docs.auriko.ai/api-reference/authentication>; the check is the
  documented key-identity read `/v1/me`.

## Probes without a response

All 50 existing rows with a check were probed; 37 supplied authentication-refusal
evidence. `tinyfish` received no HTTP response:
DNS lookup of `api.tinyfish.ai` failed with "No address associated with hostname".
Its `invalid_key` stays `None`. The 16 existing `Unvalidated` rows were not probed
and also keep `invalid_key: None`.

## Checks to replace

These responses were obtained on 2026-11-10, but are not invalid-key evidence.
Each of these rows keeps `invalid_key: None`. Their checks are not changed here.

- `nanogpt`: <https://nano-gpt.com/api/v1/models> returned 200, a public model
  list. Its login check accepts a bogus key, so the check proves nothing.
- `synthetic`: <https://api.synthetic.new/openai/v1/models> returned 200, a public
  model list. Its login check accepts a bogus key, so the check proves nothing.
- `zenmux`: <https://zenmux.ai/api/v1/models> returned 200, a public model list.
  Its login check accepts a bogus key, so the check proves nothing.
- `nvidia`: <https://integrate.api.nvidia.com/v1/chat/completions> returned 410,
  stating that the probe model had reached end of life.
- `firepass`: <https://api.fireworks.ai/inference/v1/chat/completions> returned
  404, "Model not found, inaccessible, and/or not deployed".
- `cerebras`: <https://api.cerebras.ai/v1/chat/completions> returned a bot-block
  403, plain-text "error code: 1010".
- `gmi-cloud`: <https://api.gmi-serving.com/v1/models> returned the same bot-block
  403, plain-text "error code: 1010".
- `groq`: <https://api.groq.com/openai/v1/models> returned the same bot-block 403.
- `novita`: <https://api.novita.ai/openai/v1/chat/completions> returned the same
  bot-block 403.
- `together`: <https://api.together.xyz/v1/models> returned the same bot-block 403.
- `yolo-auto`: <https://yolo-auto.com/v1/models> returned the same bot-block 403.
- `sakana`: <https://api.sakana.ai/v1/models> returned an HTML 403 Forbidden,
  not a provider authentication error.
- `tinyfish`: <https://api.tinyfish.ai/v1/wallet> did not resolve in DNS.

## No-descriptor rows

- `searxng`: self-hosted instances have no fixed receiving hosts or universal client
  key header. See <https://docs.searxng.org/dev/search_api.html>.
- `typesafe`: a key can belong to a deployment at a custom base URL. The public
  service's Bearer API does not describe those deployments; see
  <https://docs.typesafe.ai/introduction/quickstart>.
- `kagi` (added to the no-descriptor list): the API portal documents
  `Authorization: Bot <key>`, which is neither supported scheme. See
  <https://help.kagi.com/kagi/api/api-portal.html>. The search page now also shows
  Bearer for the same route, so the conflicting documentation is not a reason to
  silently change the existing integration's presentation.

No scheme was added: the descriptor supports only Bearer and raw header values.

## Fusiform provider skips

This table mirrors `FUSIFORM_PROVIDER_SKIPS` in the catalog. An uncovered provider
stays a gap until its documentation is reviewed; an empty key-variable list alone is
not a reason to skip it.

- `amazon-bedrock`: Bedrock API keys are bound to the AWS Region they were created
  in, and each Region has its own `bedrock-runtime` host. See
  <https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html>.
- `atomic-chat`: <https://atomic.chat> describes a local desktop app that works
  offline with no cloud service, so there is no hosted API key.

Only these reasons are permitted:

- OAuth only
- no API key in its documentation
- a duplicate offering of an existing row
- a second secret or a per-account host in the style of Azure, Bedrock or Vertex

| Fusiform id | reason |
| --- | --- |
| amazon-bedrock | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| atomic-chat | no API key in its documentation |

## Hosts without provider documentation

These existing check hosts are retained because login already sends the key there.
The closest official page is recorded in `hosts_doc`; it is not evidence for a
host that the page does not document. Searches below were made on 2026-11-10.
Documented receiving hosts are included alongside the retained aliases.

- `kiro`, `q.us-east-1.amazonaws.com`: searched the official authentication/API-key
  guide at <https://kiro.dev/docs/getting-started/authentication/>. It documents
  `KIRO_API_KEY`, not the HTTP header or Amazon Q origin.
- `qwen-portal`, `portal.qwen.ai`: searched
  <https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/> and the
  portal. Current Qwen Code documentation describes different QwenCloud hosts,
  not this existing portal origin.
- `sakana`, `api.sakana.ai`: searched the official <https://sakana.ai/> site and
  likely documentation roots. No public API-key host/header reference was found.
- `singularityapi-tech`, `api.singularityapi.tech`: searched
  <https://singularityapi.tech/> and the available
  <https://docs.singularityapi.dev/> quickstart. The latter documents only `.dev`.
- `xiaomi-token-plan-ams`, `token-plan-ams.xiaomimimo.com`;
  `xiaomi-token-plan-cn`, `token-plan-cn.xiaomimimo.com`; and
  `xiaomi-token-plan-sgp`, `token-plan-sgp.xiaomimimo.com`: searched
  <https://platform.xiaomimimo.com/docs> and its API, quickstart and API-reference
  routes. They yielded no readable provider-owned host/header documentation.
- `together`, `api.together.xyz`: searched the official quickstart,
  authentication, OpenAI-compatibility and chat-completions reference. Current
  pages name `api.together.ai`, `api-inference.together.ai` and `us-api.together.ai`,
  all included in the row. The existing `.xyz` check alias was not documented.
  See <https://docs.together.ai/docs/inference/openai-compatibility> and
  <https://docs.together.ai/reference/chat-completions>.
- `tinyfish`, `api.tinyfish.ai`: searched the official authentication, wallet,
  browser, fetch and search references. The current wallet server is
  `agent.tinyfish.ai`; the old wallet host was not found. Both hosts and the
  documented `api.browser.tinyfish.ai`, `api.fetch.tinyfish.ai` and
  `api.search.tinyfish.ai` endpoints are included. See
  <https://docs.tinyfish.ai/authentication> and
  <https://docs.tinyfish.ai/api-reference/wallet>.
- `siliconflow-cn`, `api.siliconflow.cn`: searched
  <https://docs.siliconflow.cn/api-reference/chat-completions/chat-completions>.
  It documents Bearer authentication but the inspected API reference did not
  establish the `.cn` server host.

## Additional host and presentation sources

Some providers document more than one API surface in separate pages. The rows
include their fixed key-receiving hosts, not just the validation host:

- Hugging Face: <https://huggingface.co/docs/huggingface_hub/en/package_reference/hf_api>
  documents the Hub API at `huggingface.co`; the row's inference-provider guide
  documents `router.huggingface.co` with the same HF Bearer token.
- Jina: <https://docs.jina.ai/> documents embeddings, reader and search, including
  `eu.r.jina.ai` and `eu.s.jina.ai` alongside the default reader/search hosts.
- GMI Cloud: <https://docs.gmicloud.ai/inference-engine/api-reference/llm-api-reference>
  documents `api.gmi-serving.com`; the Cloud API introduction documents key-bearing
  API calls to `console.gmicloud.ai`, not merely its dashboard.
- NanoGPT: <https://docs.nano-gpt.com/api-reference/miscellaneous/api-hosts>
  documents `api.nano-gpt.com` and the `nano-gpt.com` fallback.
- MiniMax: the international and China M Plan FAQ pages document Bearer usage
  checks at `www.minimax.io` and `www.minimax.cn`; their companion tool guides
  document the model-call hosts. See
  <https://platform.minimax.io/docs/m-plan/other-tools> and
  <https://platform.minimaxi.com/docs/m-plan/other-tools>.
- Kimi Code: <https://www.kimi.com/code/docs/en/kimi-code/models> documents China
  and overseas API hosts. The Codex guide configures a Bearer-key compatible
  client; the inspected docs do not state the literal header or promise that a
  regional key works in both regions. See
  <https://www.kimi.com/code/docs/en/third-party-tools/codex>.
- Fire Pass and OpenCode Go: their plan guides configure compatible clients;
  the explicit Bearer examples are in the parent API's documentation, at
  <https://docs.fireworks.ai/api-reference> and <https://opencode.ai/docs/zen/>.
