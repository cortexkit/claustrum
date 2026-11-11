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
| bee | https://api.bee.heossi.com/bee/chat/completions | 2026-11-11 | 401 | unauthorized | /error |
| berget | https://api.berget.ai/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| blueclaw | https://openai.blueclaw.network/v1/models | 2026-11-11 | 401 | - | - |
| bothub | https://openai.bothub.chat/v1/models | 2026-11-11 | 401 | UNAUTHORIZED | /error/code |
| boundless | https://api.inference.boundless.network/v1/credits | 2026-11-11 | 401 | authentication_error | /error/type |
| charm-hyper | https://hyper.charm.land/v1/credits | 2026-11-10 | 401 | authentication_error | /error/type |
| chutes | https://api.chutes.ai/users/me | 2026-11-11 | 401 | - | - |
| claudinio | https://api.claudin.io/v1/models | 2026-11-11 | 401 | token_not_found_in_db | /error/type |
| cloudferro-sherlock | https://api-sherlock.cloudferro.com/openai/v1/models | 2026-11-11 | 403 | - | - |
| cloudflare-workers-ai | https://api.cloudflare.com/client/v4/accounts/00000000000000000000000000000000/ai/models/search?per_page=1 | 2026-11-10 | 400 | - | - |
| cohere | https://api.cohere.com/v1/models | 2026-11-11 | 401 | - | - |
| coralbricks | https://inference.coralbricks.ai/v1/quota | 2026-11-11 | 401 | invalid_api_key | /error/code |
| cortecs | https://api.cortecs.ai/v1/chat/completions | 2026-11-11 | 401 | auth_error | /error/type |
| crossmodel | https://api.crossmodel.ai/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| crusoe | https://api.inference.crusoecloud.com/v1/models | 2026-11-11 | 401 | - | - |
| daoxe | https://api.daoxe.com/v1/models | 2026-11-11 | 401 | - | - |
| deepinfra | https://api.deepinfra.com/v1/openai/chat/completions | 2026-11-10 | 401 | invalid_api_key | /error/code |
| deepseek | https://api.deepseek.com/chat/completions | 2026-11-10 | 401 | invalid_request_error | /error/code |
| digitalocean | https://inference.do-ai.run/v1/models | 2026-11-11 | 401 | Unauthorized | /id |
| dinference | https://api.dinference.com/v1/models | 2026-11-11 | 401 | token_not_found_in_db | /error/type |
| edenai | https://api.edenai.run/v3/chat/completions | 2026-11-11 | 401 | - | - |
| elevenlabs | https://api.elevenlabs.io/v1/user | 2026-11-11 | 401 | unauthorized | /detail/code |
| empiriolabs | https://api.empiriolabs.ai/v1/account/usage?limit=1 | 2026-11-11 | 401 | invalid_api_key | /error/code |
| engy | https://api.engy.ai/v1/chat/completions | 2026-11-11 | 401 | authentication_error | /error/type |
| evroc | https://models.think.evroc.com/v1/models | 2026-11-11 | 401 | authentication_error | /error/type |
| fastrouter | https://api.fastrouter.ai/api/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| firecrawl | https://api.firecrawl.dev/v2/team/credit-usage | 2026-11-10 | 401 | - | - |
| fireworks-ai | https://api.fireworks.ai/v1/accounts/fireworks/models?filter=supports_serverless%3Dtrue&pageSize=1 | 2026-11-10 | 401 | UNAUTHORIZED | /error/code |
| freemodel | https://api.freemodel.dev/v1/chat/completions | 2026-11-11 | 401 | - | - |
| friendli | https://api.friendli.ai/serverless/v1/chat/completions | 2026-11-11 | 401 | - | - |
| frogbot | https://app.frogbot.ai/api/v1/models | 2026-11-11 | 401 | Unauthorized | /error |
| google | https://generativelanguage.googleapis.com/v1beta/models | 2026-11-10 | 400 | API_KEY_INVALID | /error/details/0/reason |
| greenpt | https://api.greenpt.ai/v1/models | 2026-11-11 | 401 | - | - |
| helicone | https://ai-gateway.helicone.ai/chat/completions | 2026-11-11 | 401 | - | - |
| hopper | https://api.withhopper.com/v1/balance | 2026-11-11 | 401 | invalid_api_key | /error/code |
| hpc-ai | https://api.hpc-ai.com/inference/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| huggingface | https://huggingface.co/api/whoami-v2 | 2026-11-10 | 401 | - | - |
| impossibl | https://api.impossibl.com/v1/requests?limit=1 | 2026-11-11 | 401 | authentication_error | /error/type |
| inception | https://api.inceptionlabs.ai/v1/chat/completions | 2026-11-10 | 401 | invalid_api_key | /error/code |
| inceptron | https://api.inceptron.io/v1/chat/completions | 2026-11-11 | 401 | unauthorized | /error/code |
| inco | https://api.inco.ai/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| infer | https://infer.flow7.org/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| inference | https://api.inference.net/v1/chat/completions | 2026-11-11 | 401 | InvalidApiKey | /error/type |
| infomaniak | https://api.infomaniak.com/1/ai | 2026-11-11 | 401 | not_authorized | /error/code |
| io-net | https://api.intelligence.io.solutions/api/v1/chat/completions | 2026-11-11 | 401 | - | - |
| iteracompute | https://api.iteracompute.com/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| jalapeno | https://api.jalapeno-cloud.ai/v1/chat/completions | 2026-11-11 | 401 | - | - |
| jiekou | https://api.jiekou.ai/openai/v1/chat/completions | 2026-11-11 | 401 | FAILED_TO_AUTH | /reason |
| kenari | https://kenari.id/v1/chat/completions | 2026-11-11 | 401 | - | - |
| kilo | https://ai-gateway.kilo.ai/api/v1/chat/completions | 2026-11-11 | 401 | INVALID_TOKEN | /error/code |
| kimi-code-plan-cn | https://api.kimi.com/coding/v1/models | 2026-11-11 | 401 | invalid_authentication_error | /error/type |
| kiro | https://q.us-east-1.amazonaws.com/ListAvailableModels?origin=AI_EDITOR | 2026-11-10 | 403 | - | - |
| klokintegration | https://ai.klok.ipaas.se/proxy/kloker-key/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| kosmik | https://api.koscompute.com/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| liquid | https://router.inference.ai.exchange/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| llmgateway | https://api.llmgateway.io/v1/key | 2026-11-11 | 401 | invalid_api_key | /error/code |
| llmgateway-providers | https://api.llmgateway.io/v1/key | 2026-11-11 | 401 | invalid_api_key | /error/code |
| llmtr | https://llmtr.com/v1/chat/completions | 2026-11-11 | 401 | auth_error | /error/type |
| longcat | https://api.longcat.chat/openai/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| lowrouter | https://api.lowrouter.ai/v1/chat/completions | 2026-11-11 | 401 | api_key_not_registered | /error/code |
| lucidquery | https://api.lucidquery.com/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| meganova | https://api.meganova.ai/v1/chat/completions | 2026-11-11 | 401 | token_not_found | /error/type |
| melious | https://api.melious.ai/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| merge-gateway | https://api-gateway.merge.dev/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/type |
| meta | https://api.meta.ai/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| minimax | https://api.minimax.io/v1/models | 2026-11-11 | 401 | authorized_error | /error/type |
| minimax-cn | https://api.minimax.cn/v1/models | 2026-11-11 | 401 | authorized_error | /error/type |
| minimax-code | https://api.minimax.io/v1/chat/completions | 2026-11-10 | 401 | authorized_error | /error/type |
| minimax-code-cn | https://api.minimax.cn/v1/chat/completions | 2026-11-10 | 401 | authorized_error | /error/type |
| mistral | https://api.mistral.ai/v1/models | 2026-11-10 | 401 | - | - |
| mixlayer | https://mixlayer.ai/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| moark | https://api.moark.com/v1/chat/completions | 2026-11-11 | 401 | 401 | /error/code |
| model-oracle-ai | https://api.modeloracle.com/api/v1/chat/completions | 2026-11-11 | 401 | Unauthorized | /error/type |
| modular | https://api.modular.com/v1/chat/completions | 2026-11-11 | 401 | - | - |
| moonshot | https://api.moonshot.ai/v1/chat/completions | 2026-11-10 | 401 | invalid_authentication_error | /error/type |
| moonshotai-cn | https://api.moonshot.cn/v1/models | 2026-11-11 | 401 | invalid_authentication_error | /error/type |
| morph | https://api.morphllm.com/v1/chat/completions | 2026-11-11 | 401 | - | - |
| munito | https://api.munito.ai/inference/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| munito-eu | https://api.eu.munito.ai/inference/v1/models | 2026-11-11 | 401 | invalid_api_key | /error/code |
| nan | https://api.nan.builders/v1/models | 2026-11-11 | 401 | 401 | /error/code |
| nearai | https://cloud-api.near.ai/v1/attestation/report | 2026-11-11 | 401 | invalid_api_key | /error/type |
| nebius | https://api.tokenfactory.nebius.com/v1/models | 2026-11-11 | 401 | - | - |
| neuralwatt | https://api.neuralwatt.com/v1/chat/completions | 2026-11-11 | 401 | invalid_api_key | /error/code |
| ofox | https://api.ofox.ai/v1/user/balance | 2026-11-11 | 401 | unauthorized | /error |
| openai | https://api.openai.com/v1/models | 2026-11-10 | 401 | invalid_api_key | /error/code |
| openrouter | https://openrouter.ai/api/v1/auth/key | 2026-11-10 | 401 | - | - |
| opper | https://api.opper.ai/v3/compat/models | 2026-11-11 | 401 | - | - |
| orcarouter | https://api.orcarouter.ai/v1/models | 2026-11-11 | 401 | orcarouter_api_error | /error/type |
| ovhcloud | https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions | 2026-11-11 | 403 | - | - |
| pareto | https://api.paretoinference.com/v1/chat/completions | 2026-11-11 | 401 | 401 | /error/code |
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

## Second batch from the Fusiform provider list

The second batch took the next 25 ids that `ck auth provider-report --missing` printed,
`azure` through `echo`. 19 got rows, 4 are recorded skips (listed under "Fusiform
provider skips" below), and 2 stay uncovered (see the end of this section).

On 2026-11-11 a network-enabled Linux build server sent each new row's key check by
hand with curl, redirects not followed. Each request used the check's method and URL,
the row's `Authorization: Bearer` header carrying a deliberately bogus key, and for chat
checks the login check's one-token request body. Keys carried the documented prefix
where one is documented: `bee_sk_live_` for `bee`, `sk_ber_` for `berget`, `bc_` for
`blueclaw`, `cpk_` for `chutes`, `cb_` for `coralbricks` and `cm-` for `crossmodel`.
A request without any key was also sent. Where it got the same reply as the bogus key
(`bee`, `blueclaw`, `bothub`, `cortecs`, `crusoe`, `daoxe`, `digitalocean`), the line still
records only the bogus-key reply. A generic error type that every DaoXE error carries
(`new_api_error`), an empty `code` string (DaoXE) and numeric-looking `code` strings
(`"401"` from the LiteLLM-based APIs) are not recorded as codes; where those APIs give
a structured reason in `type`, that is recorded instead.

Hosts and key presentation were taken from these provider pages:

- `bailing`: <https://alipaytbox.yuque.com/org-wiki-knowledgepie-mvkzao/pxit93/get_started>
  documents `POST https://api.ant-ling.com/v1/chat/completions` with a Bearer token
  and the token page <https://chat.ant-ling.com/platform/api>. Both the model list and
  the chat route answered the build server with an HTML 405 block page, with or
  without a key, so the row is stored unchecked and has no evidence line. The
  `api.tbox.cn` host listed by models.dev is not in the provider's current guide and
  is not included.
- `bee`: <https://bee.heossi.com/docs/sdks> documents base URL
  `https://api.bee.heossi.com/bee` and Bearer keys; its OpenAPI document
  (<https://api.bee.heossi.com/openapi.json>) marks the model list public, so the check
  is a chat on `bee-cell`.
- `berget`: <https://docs.berget.ai/quickstart> documents `https://api.berget.ai/v1` and
  Bearer keys. Its OpenAPI document marks the model list public, so the check is a
  chat. The stage server in that document is not a consumer host and is not included.
- `blueclaw`: <https://blueclaw.network/quickstart.html> documents
  `https://openai.blueclaw.network/v1` and `bc_` Bearer keys. The quickstart does not
  document a model list; `/v1/models` answered 401 with or without a key.
- `bothub`: <https://bothub.ru/free> configures the OpenAI SDK with base URL
  `https://openai.bothub.chat/v1` and the access token as its API key.
- `boundless`: <https://inference.boundless.network/docs/api-compatibility> documents
  `api.inference.boundless.network` and Bearer or `x-api-key` keys;
  <https://inference.boundless.network/docs/billing> documents the `/v1/credits` read.
- `chutes`: <https://chutes.ai/docs/getting-started/authentication> documents `cpk_`
  Bearer keys for the platform API at `api.chutes.ai`; the starter guide
  <https://chutes.ai/docs/guides/starter-guide> documents inference at
  `https://llm.chutes.ai/v1`. The docs index (<https://chutes.ai/llms.txt>) calls the
  model list a public catalog and `/users/me` the authenticated account read.
- `claudinio`: <https://claudin.io/docs/api-reference/> documents `api.claudin.io`,
  Bearer or `x-api-key` keys, and `GET /v1/models`.
- `cloudferro-sherlock`:
  <https://docs.cloudferro.com/en/latest/sherlock/Package-installation-and-examples-of-Sherlock-AI-code-on-CloudFerro-Cloud.html>
  documents `https://api-sherlock.cloudferro.com/openai/v1` and Bearer keys. A bogus
  key got a plain-text 403 `forbidden`; no key got a plain-text 401 `unauthorized`.
- `cohere`: <https://docs.cohere.com/reference/list-models> documents Bearer keys at
  `api.cohere.com`; <https://docs.cohere.com/docs/compatibility-api> documents the
  compatibility API at `https://api.cohere.ai/compatibility/v1` with the same key.
  `POST /v1/check-api-key` answered 200 `{"valid":false}` for a bogus key and for no
  key, so the check is the model list.
- `coralbricks`: <https://www.coralbricks.ai/docs> documents
  `https://inference.coralbricks.ai/v1`, Bearer keys and the `/v1/quota` balance read.
- `cortecs`: <https://docs.cortecs.ai/api/api-compatibility> documents
  `https://api.cortecs.ai/v1` and Bearer keys. Its model list makes the key optional
  and answered a bogus key with 200, so the check is a chat on `glm-5.3-flash`.
- `crossmodel`: <https://www.crossmodel.ai/docs/authentication> and
  <https://www.crossmodel.ai/docs/api-reference/models> document `api.crossmodel.ai`,
  `cm-` Bearer keys and the model list. The docs give no direct key-page URL, so the
  row's key page is the authentication guide.
- `crusoe`:
  <https://docs.crusoe.ai/quickstart/getting-started-with-serverless-inference/>
  configures the OpenAI SDK with `https://api.inference.crusoecloud.com/v1` and the
  key as its API key. The guide does not document a model list; `/v1/models` answered
  401 with or without a key.
- `daoxe`: <https://daoxe.com/docs/start/quickstart> documents
  `GET https://api.daoxe.com/v1/models` with `sk-` Bearer keys. Its base-URL guide
  (<https://daoxe.com/docs/guide/base-url>) allows other route hosts returned at run
  time; those are not covered.
- `digitalocean`:
  <https://docs.digitalocean.com/products/inference/how-to/si-endpoints/> documents
  `https://inference.do-ai.run` and Bearer keys;
  <https://docs.digitalocean.com/products/inference/how-to/retrieve-available-models/>
  documents the model list. Model access keys and personal access tokens are both
  accepted.
- `dinference`: <https://dinference.com/docs> configures the OpenAI SDK with
  `https://api.dinference.com/v1` and the key as its API key. The site offers sign-in
  at <https://panel.dinference.com/login>.
- `drun`: <https://docs.d.run/en/models/api-call> documents `https://chat.d.run` for
  pay-per-token use and per-region `<region>.d.run` hosts for dedicated instances,
  which the row does not cover; <https://docs.d.run/en/models/apikey> documents
  `Authorization: Bearer`. `chat.d.run` reset every connection from the build server,
  so the row is stored unchecked and has no evidence line.
- `echo`: <https://echo.tracerml.ai/docs/api> documents host `echo.tracerml.ai` and
  `Authorization: Bearer` workspace keys. Every documented path, including the model
  list, sits under a workspace base URL copied from the console, so the row is stored
  unchecked and has no evidence line.

Two ids from this batch have neither a row nor a skip; `--missing` still prints them:

- `clarifai`: on 2026-11-11 `api.clarifai.com` and `docs.clarifai.com` did not resolve
  in DNS, and `clarifai.com` resolved to a parking address, so the provider's
  documentation could not be read and no request could be sent.
- `ebcloud`: <https://docs.ebtech.com/ai/model-api.html> says to create a key in the
  console and copy sample code from a model's API-call page there. The page does not
  state the API host or how the key is sent. models.dev lists
  `https://maas-api.ebcloud.com/v1`, where `GET /v1/models` answered a bogus Bearer key
  with 401 (`error.type` `token_not_found_in_db`) and no key with a different 401, but
  a third-party listing is not provider documentation, so no row was added.

## Third batch from the Fusiform provider list

After the second batch, `ck auth provider-report --missing` printed 138 ids. It still
begins with `clarifai` and `ebcloud`, which the second batch left uncovered (see the
end of that section), so the third batch took the next 25 ids after them, `edenai`
through `io-net`. 21 got rows, 3 are recorded skips (`github-copilot`, `gitlab` and
`google-vertex-anthropic`, listed under "Fusiform provider skips" below), and
`hetzner` stays uncovered (see the end of this section). On 2026-11-11
`api.clarifai.com` and `docs.clarifai.com` still did not resolve in DNS and
`clarifai.com` still resolved to a parking address.

On 2026-11-11 a network-enabled Linux build server sent each new checked row's key
check by hand with curl, redirects not followed: the check's method and URL, the row's
key header carrying a deliberately bogus key, and for chat checks the login check's
one-token request body. Keys carried the documented prefix where one is documented:
`sk-empiriolabs-` for `empiriolabs`, `sk-engy-` for `engy`, `fe_oa_` for `freemodel`,
`flp_` for `friendli`, `sk_hopper_` for `hopper` and `sk-inco-` for `inco`. Every
checked row got a 401. A request without any key was also sent; it got the same reply
as the bogus key for `friendli`, `frogbot`, `greenpt` and `hetzner`, and a reply naming the
missing key for the others. Numeric `code` values (`engy`, `evroc`) and messages
(`edenai`, `freemodel`, `friendli`, `io-net`, and the plain-text replies of `greenpt`
and `helicone`) are not recorded as codes; where a reply gives a structured reason in
`type`, that is recorded instead.

Where a model list answered without a key, the check is a chat on a model that list
named on 2026-11-11 (`edenai`, `engy`, `fastrouter`, `freemodel`, `friendli`,
`helicone`, `inceptron`, `inco`, `inference`, `io-net`). The `inco`, `inference` and
`io-net` model lists refuse a bogus key but answer a missing key with the public
catalog, so they too use a chat.

Hosts and key presentation were taken from these provider pages:

- `edenai`: <https://www.edenai.co/docs/v3/data-governance/eu-endpoint> documents the
  global host `https://api.edenai.run` and the EU host `https://api.eu.edenai.run`,
  one key for both, and `Authorization: Bearer`. It calls `/v3/models` public.
- `empiriolabs`: <https://docs.empiriolabs.ai/authentication> documents
  `api.empiriolabs.ai`, `sk-empiriolabs-` Bearer keys and the
  `GET /v1/account/usage?limit=1` read used as the check.
- `engy`: <https://engy.ai/docs/api-reference/inference-api/overview> documents base
  URL `https://api.engy.ai`, `sk-engy-` Bearer keys and a model list that needs no
  key. The management API on `engy.ai/api/v1` takes separate account tokens and is not
  covered.
- `evroc`: <https://docs.evroc.com/products/think/openai-compatibility.html> documents
  `https://models.think.evroc.com/v1`, Bearer keys and `GET /v1/models` with a key.
  Dedicated model instances are not covered.
- `fastrouter`: <https://docs.fastrouter.ai/> documents
  `https://api.fastrouter.ai/api/v1/chat/completions` with `Authorization: Bearer`.
  models.dev lists `go.fastrouter.ai`, which the provider's documentation does not
  name, so it is not included. The docs give no direct key-page URL.
- `freemodel`: the site's own sample at <https://freemodel.dev> (documentation at
  <https://freemodel.dev/docs>, rendered in the browser) configures the OpenAI SDK with
  `https://api.freemodel.dev/v1` and an `fe_oa_` key as its API key. Its Claude Code
  guide uses `https://cc.freemodel.dev` with the key as `ANTHROPIC_API_KEY`, which
  Claude Code sends in another header; that host is not covered.
- `friendli`: <https://friendli.ai/docs/guides/introduction/get-started> documents
  `https://api.friendli.ai/serverless/v1`, `Authorization: Bearer` and the key page;
  <https://friendli.ai/docs/guides/suite/usage-and-costs> documents `flp_` keys.
- `frogbot`: <https://docs.frogbot.ai/api-keys> documents
  `https://app.frogbot.ai/api/v1` with the key in `Authorization: Bearer` or
  `x-api-key`.
- `google-vertex`: the express-mode page
  <https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/start/express-mode/overview>
  documents the global endpoint
  `https://aiplatform.googleapis.com/v1/publishers/google/models/MODEL_ID:...` with the
  key in `x-goog-api-key`. The row covers express-mode keys only, which reach the Gemini
  models that page lists; Vertex used through a Google Cloud project and region is not
  covered. A bogus key sent to the model read and to `generateContent` got 401 "API
  keys are not supported by this API" (`CREDENTIALS_MISSING`), the reply for a call
  that takes no API keys at all, so the row is stored unchecked and has no evidence
  line.
- `greenpt`: <https://docs.greenpt.ai/get-started> documents `https://api.greenpt.ai/v1`,
  `Authorization: Bearer`, `GET /v1/models` and the key page.
- `helicone`: <https://docs.helicone.ai/getting-started/quick-start> documents the AI
  gateway at `https://ai-gateway.helicone.ai`, `Authorization: Bearer` and the key page.
- `hopper`: <https://docs.withhopper.com> documents `https://api.withhopper.com/v1`,
  `sk_hopper_` Bearer keys and the key page; <https://docs.withhopper.com/models>
  documents the free `GET /v1/balance` read.
- `hpc-ai`:
  <https://www.hpc-ai.com/doc/docs/Model-APIs/API-Reference/OpenAI-Compatible-API/OpenAI-SDK>
  documents `https://api.hpc-ai.com/inference/v1` and `Authorization: Bearer`. The
  documented model list's page does not print its path; `/inference/v1/models` refused
  bogus and missing keys alike.
- `impossibl`: <https://impossibl.com/docs/quickstart> documents
  `https://api.impossibl.com/v1`, Bearer keys and the
  `GET /v1/requests?limit=1` read. Its model list answered a bogus key with 200.
- `inceptron`: <https://docs.inceptron.io> documents `https://api.inceptron.io/v1`
  and `Authorization: Bearer`.
- `inco`: <https://platform.inco.ai/docs> documents `https://api.inco.ai/v1`,
  `sk-inco-` Bearer keys and a model list that is public without a key.
- `infer`: <https://infer.flow7.org/docs> documents `https://infer.flow7.org/v1` and
  `Authorization: Bearer`. The docs give no direct key-page URL, so the row's key page
  is that guide.
- `inference`: <https://docs.inference.net/api/api-quickstart> documents
  `https://api.inference.net/v1`, the US-only `https://us.api.inference.net/v1`, and
  Bearer keys.
- `inferx`: <https://inferx.net/docs/authentication> documents Bearer keys, and
  <https://inferx.net/docs/quickstart> documents `https://model.inferx.net/v1` while
  saying production URLs "can be tenant- and endpoint-specific". Without a key
  `/v1/models` answered "no tenant context: set a default tenant or use a
  tenant-restricted API key", so a fixed check could refuse a good key; the row is
  stored unchecked and has no evidence line.
- `infomaniak`:
  <https://developer.infomaniak.com/docs/api/post/2/ai/%7Bproduct_id%7D/openai/v1/chat/completions>
  documents `https://api.infomaniak.com/2/ai/{product_id}/openai/v1` and
  `Authorization: Bearer`. Requests carry the account's AI Tools product id, which
  consumers must supply, as `echo` consumers supply a workspace id. The check is
  `GET /1/ai` (<https://developer.infomaniak.com/docs/api/get/1/ai>), which needs no
  product id.
- `io-net`:
  <https://io.net/docs/reference/ai-models/get-started-with-io-intelligence-api>
  documents `https://api.intelligence.io.solutions/api/v1` and `Authorization: Bearer`.

One id from this batch has neither a row nor a skip; `--missing` still prints it:

- `hetzner`: Fusiform's documentation link,
  <https://experiments.hetzner.com/docs/inference>, is a browser app behind Hetzner
  account sign-in, so its text could not be read. The app's configuration names
  `https://inference.hetzner.com/v1`, and models.dev lists
  `https://inference.hetzner.com/api/v1`, where `GET /api/v1/models` answered bogus and
  missing Bearer keys alike with a plain-text 401. Neither is readable provider
  documentation, so no row was added.

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

## Fourth batch from the Fusiform provider list

After the third batch, `ck auth provider-report --missing` printed 114 ids. The
fourth batch left the earlier gaps (`clarifai`, `ebcloud`, `hetzner`) for separate
review and took the next 25, `iteracompute` through `minimax-cn`. 20 got rows and
2 are recorded skips (`lmstudio`, `lynkr`, listed below). Three remain uncovered:
`kuae-cloud-coding-plan`, `lilac`, `llmtech`. The report now prints 92 uncovered ids.

On 2026-11-11 a network-enabled Linux build server sent the new rows' checks using
Python's HTTP client with redirects disabled. Every request used the row's
`Authorization: Bearer` header with a deliberately bogus key; chat requests used the
login check's one-token body. All 20 returned 401. A no-key request was also sent.
Documented prefixes were used for Kenari (`kn-`), Liquid (`sk-liquid-`), LLM Gateway
(`llmgtwy_`), LLMTR (`llmtr-`), LowRouter (`sk-lr-`), LucidQuery
(`sk_lucidquery_`), Melious (`sk-mel-`) and Merge (`mg_`). LowRouter's fabricated
key body had the documented 43 characters and Melious's had 121 after the prefix,
so those checks reached unknown-key refusals rather than only format checks.
Jalapeno's numeric `code` and message-valued `type` are not recorded as an error
code. Meganova's structured `token_not_found` type is recorded instead of its
status-like `"401"` code. Kenari's refusal is plain text.

Hosts and key presentation were taken from these provider pages:

- `iteracompute`: <https://iteracompute.com/docs.html> documents
  `https://api.iteracompute.com/v1`, Bearer keys, the key page and free `Auto` chat.
  The model list is public, so the check is a chat.
- `jalapeno`: <https://www.jalapeno-cloud.ai/docs/> documents
  `https://api.jalapeno-cloud.ai/v1`, Bearer keys, the key page and `DeepSeek-V4-Pro`.
  The model-list route returned a generic 403 access block with or without a key;
  the documented chat route instead returned an authentication refusal.
- `jiekou`: <https://docs.jiekou.ai/docs/model/llm.md> documents Bearer keys, the
  compatible chat API and `deepseek/deepseek-r1`;
  <https://docs.jiekou.ai/docs/announcement/announcement.md> names the fixed domestic
  `api.highwayapi.ai` and original/overseas `api.jiekou.ai` hosts. The model list
  answered bogus and missing keys alike with 200, so the check is a chat.
- `kenari`: <https://kenari.id/docs/quickstart> documents `https://kenari.id/v1`,
  `kn-` Bearer keys and the free `step-3-7-flash:free` model. Authentication docs
  (<https://kenari.id/docs/authentication>) identify the model list as public.
- `kilo`: <https://docs.kilo.ai/docs/gateway/authentication> documents
  `https://ai-gateway.kilo.ai/api/v1` and Bearer keys from the personal profile at
  <https://app.kilo.ai>. The models guide
  (<https://docs.kilo.ai/docs/gateway/models-and-providers>) documents `kilo-auto/free`.
  Its catalog and free chat accept no key, but a supplied bogus key was refused by
  the chat. The old exclusion of `kilo` as a custom-login-only provider no longer
  describes this documented Gateway key flow.
- `kimi-code-plan-cn`: <https://www.kimi.com/code/docs/en/third-party-tools/codex.html>
  pairs `https://api.kimi.com/coding/v1` with `experimental_bearer_token`; the Code
  overview (<https://www.kimi.com/code/docs/en/>) links the key console and identifies
  this as the China endpoint. The model-list read refused a bogus Bearer key.
  This row is separate from the existing global Coding Plan row, which is unchanged.
- `klokintegration`: <https://klokintegration.se/docs/ai-api> documents
  `https://ai.klok.ipaas.se/proxy/kloker-key/v1`, the older fixed alias
  `api-gw.klok.ipaas.se`, Bearer keys and `GET /models` when enabled on the key.
  The check uses the documented `Kloker` chat instead, so optional model-list access
  is not required. The docs direct users to the platform for a token, without a
  direct key-page URL.
- `kosmik`: <https://api.koscompute.com/docs/overview/quickstart/> documents
  `https://api.koscompute.com/v1` with Bearer keys; the docs home
  (<https://api.koscompute.com/docs/>) uses `qwen/qwen3.8-27b` for chat. The model
  list is public without a key (though a bogus key is refused), so the check is a
  chat. No key-creation page is given; the row links to the quickstart.
- `liquid`: <https://inference.ai.exchange/docs/api.md> documents
  `router.inference.ai.exchange` with `sk-liquid-` Bearer keys or raw `x-api-key`.
  The quickstart (<https://inference.ai.exchange/docs/quickstart>) uses
  `gpt-oss-120b`. Its model list is public, so the check is a chat. The row links to
  the quickstart's workspace/key instructions rather than guessing a dashboard path.
- `llmgateway` and `llmgateway-providers`:
  <https://docs.llmgateway.io/developers/devpass-usage> documents
  `GET https://api.llmgateway.io/v1/key` with `llmgtwy_` Bearer keys, and explicitly
  says it works for both DevPass and pay-as-you-go keys, even when usage is exhausted.
  Both offerings keep their own Fusiform id and routing default. The quickstart
  (<https://docs.llmgateway.io/quick-start>) describes the dashboard and project key
  flow without a direct key-page URL, so the rows link to the API-key guide.
- `llmtr`: <https://llmtr.com/docs/en/quickstart/> documents `https://llmtr.com/v1`,
  `llmtr-` Bearer keys and chat model `openai/gpt-6-luna`. Its model list is public;
  the row links to the API-key instructions, which name the dashboard's API Keys page.
- `longcat`: <https://longcat.chat/platform/docs/> documents
  `https://api.longcat.chat/openai/v1/chat/completions`, Bearer keys, the key page and
  `LongCat-2.5`. Its model list answered a bogus key with 200, so the check is a chat.
- `lowrouter`: <https://lowrouter.ai/docs/integrations/openai-compatible> documents
  `https://api.lowrouter.ai/v1` with `sk-lr-` Bearer keys; the first-completion guide
  (<https://lowrouter.ai/docs/getting-started/first-completion>) uses
  `auto/mistralai/mistral-large-2512`. Its model list is public without a key, so the
  check is a chat. The key guide links <https://lowrouter.ai/app/keys>.
- `lucidquery`: <https://lucidquery.com/docs> documents `https://api.lucidquery.com/v1`,
  Bearer keys, the key page and `lucidquery-agi-01-swift`. The auth section names
  `sk_lucidquery_` keys, while an SDK example uses `lq_live_`; the probe followed the
  auth section. Its model list is public, so the check is a chat.
- `meganova`: <https://docs.meganova.ai/inference-models.md> documents
  `https://api.meganova.ai/v1` and Bearer keys from <https://console.meganova.ai>;
  <https://docs.meganova.ai/enterprise/enterprise-endpoint.md> documents the same key
  at `enterprise.api.meganova.ai`. The free-model guide names `meganova-ai/manta-mini-1.0`.
  Its model list is public, so the check is a chat.
- `melious`: <https://melious.ai/docs/get-started/quickstart> documents
  `https://api.melious.ai/v1`, Bearer keys and the key page. The authentication guide
  (<https://melious.ai/docs/concepts/authentication>) gives the `sk-mel-` key shape.
  Chat requires `inference.chat`, while model listing needs a separate
  `inference.models` scope; the check uses the chat reference's `qwen3.6-35b-a3b`
  example (<https://melious.ai/docs/reference/chat-completions>) rather than
  rejecting an inference key that cannot list models.
- `merge-gateway`: <https://docs.merge.dev/merge-gateway/api-overview> documents
  `api-gateway.merge.dev`, `mg_` Bearer inference keys and `GET /v1/models`. The
  separate management key and optional credentials supplied for an upstream provider
  are not needed for ordinary inference.
- `minimax` and `minimax-cn`: the OpenAI model-list references
  (<https://platform.minimax.io/docs/api-reference/models/openai/list-models>,
  <https://platform.minimaxi.com/docs/api-reference/models/openai/list-models>)
  document Bearer keys at `api.minimax.io` and `api.minimax.cn` respectively and
  `GET /v1/models`. The quickstarts link their respective key pages. These ordinary
  API-key offerings are separate from the existing Coding Plan rows.

Three ids from this batch have neither a row nor a skip; `--missing` still prints them:

- `kuae-cloud-coding-plan`: the provider's page
  <https://docs.mthreads.com/kuaecloud/kuaecloud-doc-online/coding_plan/> yielded only
  a heading and footer, not an API host or key presentation. Published Markdown URL
  variants did not yield instructions either. No third-party host was substituted.
- `lilac`: its provider-owned quickstart and model guide still document Bearer keys
  at `api.getlilac.com`, but the model-list endpoint returned HTTP 410,
  `Lilac inference has been discontinued.`, with bogus and missing keys alike.
  No row was added for the discontinued service, and the docs do not support one of
  the approved skip reasons.
- `llmtech`: <https://llmtech.eu/docs/> still documents Bearer keys at
  `api.llmtech.eu`, but its model-list endpoint returned HTTP 410 with
  `error.code: service_closed`, saying the API shut down on 31 October 2026 and
  keys no longer work. No row or invented skip reason was added.

## Fifth batch from the Fusiform provider list

The selected 25 ids are `mixlayer` through `pareto`, sorted by provider id from
`ck auth provider-report --missing`. The six earlier gaps (`clarifai`, `ebcloud`,
`hetzner`, `kuae-cloud-coding-plan`, `lilac` and `llmtech`), whose documentation or
service limitations are recorded above, are excluded from this batch and remain
visible in `--missing`.
Seventeen selected ids now have rows, four have the documented skips below, and
four remain gaps. All new rows use Bearer authentication. Their bogus-key requests
ran on a network-enabled Linux build server on 2026-11-11 with redirects disabled;
chat probes requested at most one output token. No real provider key was used.

The provider-owned sources for the row fields and checks are:

- `mixlayer`: <https://docs.mixlayer.com/quickstart> gives `https://mixlayer.ai/v1`,
  an explicit `Authorization: Bearer` example and the console's API-key page.
  <https://docs.mixlayer.com/models> documents `GET /v1/models`; that read rejected
  the bogus key.
- `moark`: <https://moark.com/docs/getting-started> shows Bearer authentication at
  `api.moark.com` and the `DeepSeek-R1` chat example used for the check. The
  token guide (<https://moark.com/docs/account/access-token>) describes free
  experience tokens; <https://moark.com/docs/products/apis> links the token page.
- `model-oracle-ai`: <https://modeloracle.com/setup/> documents the hosted
  `https://api.modeloracle.com/api/v1` URL, Bearer platform key and `auto` chat
  request. The row covers that hosted offering, not private deployments. Upstream
  provider keys managed inside the dashboard are not additional client headers.
- `modular`: <https://docs.modular.com/quickstart> documents the common API at
  `api.modular.com`, Bearer authentication, the key page and `minimax/minimax-m3`.
  <https://docs.modular.com/administration/api-keys> gives the `sk-mod-` format.
  The check is a one-token chat, not an undocumented key-status route.
- `moonshotai-cn`: <https://platform.moonshot.cn/docs/get-api-key.md> documents
  `api.moonshot.cn`, a literal Bearer example and the key-page link at
  `platform.kimi.com`. <https://platform.moonshot.cn/docs/api/list-models.md>
  documents the authenticated `GET /v1/models` read and warns that keys from
  the China and international platforms are not interchangeable.
- `morph`: <https://docs.morphllm.com/general-inference> documents
  `api.morphllm.com`, Bearer authentication and `morph-glm53-744b`. The key page
  is linked from <https://docs.morphllm.com/endpoints.md>. Although its model
  list returned HTTP 200 for the bogus key, the documented chat rejected it, so
  the check uses chat. Deployment-specific dedicated endpoints are not included.
- `munito` and `munito-eu`: <https://docs.munito.ai/quickstart> documents Bearer
  inference keys and their creation page. <https://docs.munito.ai/regions> lists
  the fixed global, EU and US hosts (`api.munito.ai`, `api.eu.munito.ai`,
  `api.us.munito.ai`) and says the same key works across regions. Both rows include
  those hosts; their checks use their respective global or EU base URL.
  <https://docs.munito.ai/api/listModels> says a supplied invalid key gets 401
  even though anonymous callers can list public models. Admin keys are separate
  from these inference keys.
- `nan`: <https://nan.builders/docs/getting-started> documents `api.nan.builders`,
  Bearer `sk-` keys, the key portal and `GET /v1/models`. That read rejected the
  bogus key. Its pinned Fusiform output modalities also assign the media group.
- `nearai`: <https://docs.near.ai/cloud/quickstart.md> documents
  `cloud-api.near.ai`, Bearer authentication and the key dashboard.
  <https://docs.near.ai/api-reference/attestation/get-attestation-report.md>
  explicitly describes the attestation read as non-billable and says a supplied
  key must be valid. The live refusal confirms that it can check a bogus key
  without inference. Its pinned Fusiform modalities also assign the media group.
- `nebius`: <https://docs.tokenfactory.nebius.com/quickstart> documents
  `api.tokenfactory.nebius.com` and Bearer keys; the introduction links the key
  page. <https://docs.tokenfactory.nebius.com/api-reference/models/list-models.md>
  documents the authenticated model-list route used for the check.
- `neuralwatt`: <https://portal.neuralwatt.com/docs> documents
  `api.neuralwatt.com`, Bearer keys and `glm-5.3`. The key guide is
  <https://docs.neuralwatt.com/authentication.md>. Because the docs allow anonymous
  model listing, the check uses the documented chat instead.
- `ofox`: <https://ofox.ai/docs/develop/authentication> and
  <https://ofox.ai/docs/api> document the unified key at `api.ofox.ai` and its
  Bearer presentation for the OpenAI-compatible API. The key page and
  `GET /v1/user/balance` are documented at
  <https://ofox.ai/docs/api/openapi/balance>. The live bogus-key request returned
  HTTP 401 rather than a successful balance response.
- `opper`: <https://docs.opper.ai/overview/quickstart> documents Bearer runtime
  keys, their creation page and `api.opper.ai`.
  <https://docs.opper.ai/build/gateway/drop-in-sdks> also documents the same key at
  `gw.opper.ai` and `eu.gw.opper.ai`.
  <https://docs.opper.ai/v3-api-reference/compatibility/list-models> requires
  authentication on `GET /v3/compat/models`; the public `/v3/models` and health
  routes would not check a key. The organization management key is not used.
- `orcarouter`: <https://docs.orcarouter.ai/getting-started/get-api-key> documents
  `api.orcarouter.ai`, `sk-orca-` Bearer keys and the console. The model-list guide
  and <https://docs.orcarouter.ai/routing/free-models> say a supplied key is
  authenticated strictly even when anonymous model-list reads are permitted.
  The observed `/error/code` was empty; the evidence records the nonempty
  `/error/type` instead of inventing a code.
- `ovhcloud`: the official model example at
  <https://www.ovhcloud.com/en/public-cloud/ai-endpoints/catalog/qwen-guard-gen-06b/>
  documents Bearer access tokens at `oai.endpoints.kepler.ai.cloud.ovh.net` and
  `Qwen3Guard-Gen-0.6B`. The catalog marks that model free. The key-creation guide
  (<https://help.ovhcloud.com/csm/en-public-cloud-ai-endpoints-getting-started?id=kb_article_view&sysparm_article=KB0062908>)
  describes the Public Cloud project's AI Endpoints API-keys tab. The check sends
  the key even though the service also permits limited anonymous calls.
- `pareto`: <https://docs.paretoinference.com/> links the key dashboard and gives
  the fixed base URL. <https://docs.paretoinference.com/api-reference> documents
  Bearer authentication and `z-ai/glm-5.3-flash`. Its model list is public, so
  the check uses the documented one-token chat request instead.

Four selected ids remain uncovered rather than receiving invented skip reasons:

- `modelis`: <https://modelishub.com/pricing> documents direct Bearer keys at
  `https://modelishub.com/v1` and `modelis-auto`, but two live bogus-key chat
  probes returned HTTP 502, not an authentication refusal. The separate RapidAPI
  offering uses a different key and was not substituted for the direct offering.
- `modelscope`: <https://modelscope.cn/docs/model-service/API-Inference/intro.md>
  documents `https://api-inference.modelscope.cn/v1/` and an Access Token passed
  as the OpenAI SDK's `api_key`, but the inspected documentation did not give the
  literal HTTP key header. SDK compatibility alone was not used to infer it.
- `neosmith`: <https://neosmith.ai/docs> documents Bearer keys at
  `https://router.neosmith.ai/v1`, but two live requests could not resolve that
  hostname. No invalid-key observation was obtained.
- `nova`: <https://nova.amazon.com/dev/documentation>, its Markdown variant and
  the quickstart yielded no readable API instructions; `/llms.txt` returned an
  Amazon sign-in page. No host or key header was inferred from other AWS products.

## Fusiform provider skips

This table mirrors `FUSIFORM_PROVIDER_SKIPS` in the catalog. An uncovered provider
stays a gap until its documentation is reviewed; an empty key-variable list alone is
not a reason to skip it.

- `amazon-bedrock`: Bedrock API keys are bound to the AWS Region they were created
  in, and each Region has its own `bedrock-runtime` host. See
  <https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html>.
- `atomic-chat`: <https://atomic.chat> describes a local desktop app that works
  offline with no cloud service, so there is no hosted API key.
- `azure`: Azure OpenAI sends each key to its own resource's host,
  `https://YOUR-RESOURCE-NAME.openai.azure.com`. See
  <https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/responses>.
- `azure-cognitive-services`: Fusiform links the same Azure OpenAI documentation, and
  its keys likewise need the resource name (`AZURE_COGNITIVE_SERVICES_RESOURCE_NAME`)
  that sets the host.
- `cloudflare-ai-gateway`: requests go to
  `https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/...`, so a key needs
  the account and gateway ids. See
  <https://developers.cloudflare.com/ai-gateway/usage/chat-completion/>.
- `databricks`: model serving is reached at each workspace's own host,
  `https://<workspace_host>.databricks.com`. See
  <https://docs.databricks.com/aws/en/machine-learning/model-serving/query-chat-models>.
- `github-copilot`: Copilot takes a GitHub account token (an OAuth sign-in or a
  personal access token), not an inference key, and requires a Copilot license. The
  Copilot runtime uses the token at a host chosen per account: github.com, or the
  enterprise's own hostname under GitHub Enterprise Cloud with data residency
  (`copilot login --host HOSTNAME`). The documentation does not publish the model API's
  host. See
  <https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli>.
- `gitlab`: GitLab Duo Agent Platform runs on GitLab.com, GitLab Self-Managed and
  GitLab Dedicated instances, and uses "a multi-token authentication chain before
  requests reach a model provider": the user's token goes to their own instance, which
  issues short-lived tokens for the AI gateway. See
  <https://docs.gitlab.com/user/duo_agent_platform/authentication/>.
- `google-vertex-anthropic`: Claude models on Vertex AI are not in the express-mode
  model list ("Only the models listed in the preceding table are supported in express
  mode"), so they are reached at
  `https://LOCATION-aiplatform.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/...`
  with Google Cloud credentials. See
  <https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/start/express-mode/overview>
  and <https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/partner-models/claude>.
- `lmstudio`: LM Studio serves models at the user's own local server address and
  configurable port (default `http://localhost:1234`), not a fixed provider API host.
  Its optional Bearer token is created in that local server's token manager. See
  <https://lmstudio.ai/docs/developer/core/server/settings> and
  <https://lmstudio.ai/docs/developer/core/authentication>.
- `lynkr`: the provider's self-hosted proxy docs use `http://localhost:8081` for
  development and `https://your-domain.com` for production. They say any `sk-`
  placeholder works and real authentication happens between Lynkr and its configured
  upstream provider. No Lynkr provider API key is documented. See
  <https://github.com/Fast-Editor/Lynkr/blob/main/documentation/api.md>.
- `modal`: <https://modal.com/docs/guide/webhook-proxy-auth> requires a proxy token
  ID and token secret, either in separate headers or combined as a Bearer value.
  <https://modal.com/docs/guide/endpoints> also documents dedicated inference
  endpoint URLs chosen per deployment. The combined two-component token is not
  represented as a single pasted API-key row.
- `neon`: <https://neon.com/docs/ai-gateway/get-started.md> documents an AI Gateway
  URL scoped to a branch, with the pattern
  `br-<name>-api.ai.<cell>.<region>.aws.neon.tech`. A runtime token is not usable
  without that branch's base URL, so no provider-wide host is substituted.
- `oci`: <https://docs.oracle.com/en-us/iaas/Content/generative-ai/api-keys.htm>
  documents GenAI Bearer keys bound to a region, with the regional inference host
  `inference.generativeai.<region-identifier>.oci.oraclecloud.com`. As with Bedrock,
  a regional key is not represented by a single fixed-host row. The two alternate
  secrets Oracle issues for a key are interchangeable, not two required headers.
- `openreason`: the current site explicitly says "OpenReason is not a proxy" and
  model requests go straight to Anthropic and OpenAI. Its only documented key is
  `OR_API_KEY` (`or_ingest_...`) for telemetry ingestion at
  `api.openreason.app/otlp`, not a model API key. It must not be catalogued as an
  LLM-provider key. See <https://openreason.app>, <https://docs.openreason.app>
  and <https://docs.openreason.app/quickstart/or-otel>.

Only these reasons are permitted:

- OAuth only
- no API key in its documentation
- a duplicate offering of an existing row
- a second secret or a per-account host in the style of Azure, Bedrock or Vertex

| Fusiform id | reason |
| --- | --- |
| amazon-bedrock | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| atomic-chat | no API key in its documentation |
| azure | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| azure-cognitive-services | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| cloudflare-ai-gateway | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| databricks | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| github-copilot | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| gitlab | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| google-vertex-anthropic | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| lmstudio | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| lynkr | no API key in its documentation |
| modal | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| neon | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| oci | a second secret or a per-account host in the style of Azure, Bedrock or Vertex |
| openreason | no API key in its documentation |

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
