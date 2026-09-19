#!/usr/bin/env bash
# Prove that the config hook owns SDK fetches without allowing a stale OAuth
# fixture to hide a shipped-loader refresh attempt.
set -euo pipefail

umask 077
mkdir -p /tmp/opencode
ROOT="$(mktemp -d /tmp/opencode/oc-spike.XXXXXX)"
export XDG_CONFIG_HOME="$ROOT/config"
export XDG_DATA_HOME="$ROOT/data"
export XDG_CACHE_HOME="$ROOT/cache"
export XDG_STATE_HOME="$ROOT/state"

mkdir -p "$XDG_CONFIG_HOME/opencode" "$XDG_DATA_HOME/opencode" "$XDG_CACHE_HOME" "$XDG_STATE_HOME"

STUB_PID=""
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$STUB_PID" ]]; then
    kill "$STUB_PID" >/dev/null 2>&1 || true
    wait "$STUB_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$ROOT"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

failures=0
fail() {
  failures=$((failures + 1))
  printf 'SPIKE FAIL %s\n' "$*" >&2
}
finish() {
  printf '%s fail\n' "$failures"
}
count_lines() {
  local pattern="$1"
  local path="$2"
  local count
  count="$(grep -c -- "$pattern" "$path" 2>/dev/null || true)"
  printf '%s\n' "${count:-0}"
}

OPENCODE_BIN="${OPENCODE_BIN:-opencode}"
version="$($OPENCODE_BIN --version 2>/dev/null || true)"
if [[ -z "$version" ]]; then
  fail 'stock_version=empty'
  finish
  exit 1
fi
printf 'SPIKE stock=%s\n' "$version"
printf '%s\n' "$version" > "$ROOT/stock-version"

cat > "$ROOT/stub.ts" <<'EOF'
const root = Bun.argv[2]
if (!root) throw new Error("stub root is required")

const portFile = `${root}/port`
const requestLog = `${root}/stub-requests.log`
const headerLog = `${root}/stub-headers.log`
let requests: string[] = []
let headers: string[] = []

async function append(path: string, line: string, current: string[]) {
  current.push(line)
  await Bun.write(path, current.join("\n") + "\n")
}

function json(value: unknown) {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  })
}

function openaiStream() {
  const body = [
    `data: ${JSON.stringify({ id: "spike-chat", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`,
    `data: ${JSON.stringify({ id: "spike-chat", object: "chat.completion.chunk", choices: [{ index: 0, delta: { content: "SPIKE_OK" }, finish_reason: null }] })}\n\n`,
    `data: ${JSON.stringify({ id: "spike-chat", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ].join("")
  return new Response(body, { headers: { "content-type": "text/event-stream" } })
}

function responsesStream() {
  const item = { id: "spike-item", type: "message", status: "completed", role: "assistant", content: [{ type: "output_text", text: "SPIKE_OK", annotations: [] }] }
  const pendingItem = { ...item, status: "in_progress", content: [] }
  const part = { type: "output_text", text: "SPIKE_OK", annotations: [] }
  const body = [
    `event: response.created\ndata: ${JSON.stringify({ type: "response.created", response: { id: "spike-response", object: "response", status: "in_progress", output: [] } })}\n\n`,
    `event: response.output_item.added\ndata: ${JSON.stringify({ type: "response.output_item.added", item: pendingItem, output_index: 0 })}\n\n`,
    `event: response.content_part.added\ndata: ${JSON.stringify({ type: "response.content_part.added", item_id: item.id, output_index: 0, content_index: 0, part: { type: "output_text", text: "", annotations: [] } })}\n\n`,
    `event: response.output_text.delta\ndata: ${JSON.stringify({ type: "response.output_text.delta", item_id: item.id, output_index: 0, content_index: 0, delta: "SPIKE_OK" })}\n\n`,
    `event: response.output_text.done\ndata: ${JSON.stringify({ type: "response.output_text.done", item_id: item.id, output_index: 0, content_index: 0, text: "SPIKE_OK" })}\n\n`,
    `event: response.content_part.done\ndata: ${JSON.stringify({ type: "response.content_part.done", item_id: item.id, output_index: 0, content_index: 0, part })}\n\n`,
    `event: response.output_item.done\ndata: ${JSON.stringify({ type: "response.output_item.done", item, output_index: 0 })}\n\n`,
    `event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: { id: "spike-response", object: "response", status: "completed", output: [item] } })}\n\n`,
    "data: [DONE]\n\n",
  ].join("")
  return new Response(body, { headers: { "content-type": "text/event-stream" } })
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    const url = new URL(request.url)
    const body = await request.text()
    const record = JSON.stringify({ method: request.method, path: url.pathname, headers: Object.fromEntries(request.headers), body })
    await append(headerLog, record, headers)

    if (url.pathname.endsWith("/models")) return json({ object: "list", data: [] })
    if (url.pathname.endsWith("/chat/completions")) {
      await append(requestLog, url.pathname, requests)
      return openaiStream()
    }
    if (url.pathname.endsWith("/responses")) {
      await append(requestLog, url.pathname, requests)
      return responsesStream()
    }
    return new Response("not found", { status: 404 })
  },
})

await Bun.write(portFile, String(server.port))
EOF

cat > "$ROOT/plugin.ts" <<'EOF'
const root = process.env.XDG_STATE_HOME?.replace(/\/state$/, "") ?? "/tmp/opencode/oc-spike"
const providers = ["deepseek", "xai"]
const refreshOrigin = "https://auth.x.ai"
const refreshPath = "/oauth2/token"

type ProviderConfig = { options?: Record<string, unknown> }
type OpenCodeConfig = { provider?: Record<string, ProviderConfig> }
type FetchState = { original: typeof globalThis.fetch }
type FetchGlobal = typeof globalThis & { __claustrumSpikeFetchState?: FetchState }

function authorization(input: RequestInfo | URL, init?: RequestInit) {
  const source = init?.headers ?? (input instanceof Request ? input.headers : undefined)
  return new Headers(source).get("authorization") ?? ""
}

function requestUrl(input: RequestInfo | URL) {
  if (input instanceof Request) return new URL(input.url)
  return new URL(typeof input === "string" ? input : input.toString())
}

async function log(path: string, line: string) {
  const prior = await Bun.file(path).text().catch(() => "")
  await Bun.write(path, prior + line + "\n")
}

const fetchGlobal = globalThis as FetchGlobal
if (!fetchGlobal.__claustrumSpikeFetchState) {
  const original = globalThis.fetch.bind(globalThis)
  fetchGlobal.__claustrumSpikeFetchState = { original }
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = requestUrl(input)
    if (url.origin === refreshOrigin && url.pathname === refreshPath) {
      await log(`${root}/refresh.log`, "SHIPPED_REFRESH_ATTEMPT")
      return new Response(JSON.stringify({ error: "invalid_grant" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      })
    }
    if (url.hostname !== "127.0.0.1" && url.hostname !== "localhost" && url.hostname !== "[::1]") {
      throw new Error("spike blocked non-loopback egress")
    }
    return original(input, init)
  }
}

if (process.env.SPIKE_PROBE_REFRESH_COUNTER === "1") {
  await globalThis.fetch(`${refreshOrigin}${refreshPath}`, { method: "POST" })
}

export const SpikePlugin = async (_input: unknown) => ({
  config: async (cfg: OpenCodeConfig) => {
    for (const provider of providers) {
      const configured = cfg.provider?.[provider]
      if (!configured) continue
      configured.options = { ...(configured.options ?? {}) }
      configured.options.apiKey = `claustrum-tombstone:v1:${provider}`
      if (process.env.SPIKE_DISABLE_CUSTOM_FETCH === "1") continue
      if (provider === "xai" && process.env.SPIKE_COVERAGE_ARM === "1") continue
      const upstream = fetchGlobal.__claustrumSpikeFetchState.original
      configured.options.fetch = async (request: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(request)
        if (url.pathname.endsWith("/chat/completions") || url.pathname.endsWith("/responses")) {
          await log(`${root}/fetch.log`, `SPIKE_FETCH provider=${provider} auth=${authorization(request, init)}`)
        }
        return upstream(request, init)
      }
    }
  },
})
EOF

bun "$ROOT/stub.ts" "$ROOT" &
STUB_PID=$!
for _ in {1..100}; do
  [[ -s "$ROOT/port" ]] && break
  sleep 0.01
done
if [[ ! -s "$ROOT/port" ]]; then
  fail 'stub_not_ready'
  finish
  exit 1
fi
PORT="$(< "$ROOT/port")"
BASE_URL="http://127.0.0.1:${PORT}/v1"

cat > "$XDG_CONFIG_HOME/opencode/opencode.json" <<EOF
{
  "plugin": ["file://${ROOT}/plugin.ts"],
  "provider": {
    "deepseek": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "${BASE_URL}" },
      "models": { "spike": { "name": "Spike", "id": "spike", "limit": { "context": 4096, "output": 256 }, "modalities": { "input": ["text"], "output": ["text"] } } }
    },
    "xai": {
      "npm": "@ai-sdk/xai",
      "options": { "baseURL": "${BASE_URL}" },
      "models": { "spike": { "name": "Spike", "id": "spike", "limit": { "context": 4096, "output": 256 }, "modalities": { "input": ["text"], "output": ["text"] } } }
    }
  }
}
EOF

write_auth() {
  local access="$1"
  local refresh="$2"
  local expires="$3"
  cat > "$XDG_DATA_HOME/opencode/auth.json" <<EOF
{
  "deepseek": { "type": "api", "key": "claustrum-tombstone:v1:deepseek" },
  "xai": { "type": "oauth", "access": "${access}", "refresh": "${refresh}", "expires": ${expires} }
}
EOF
  chmod 600 "$XDG_DATA_HOME/opencode/auth.json"
}

write_auth '' 'claustrum-tombstone:v1:xai' 0
cp "$XDG_DATA_HOME/opencode/auth.json" "$ROOT/canonical-auth.json"

run_child() {
  local name="$1"
  local provider="$2"
  local coverage="$3"
  local output status
  set +e
  output="$(env -i \
    PATH="$PATH" HOME="$HOME" USER="${USER:-}" \
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" XDG_DATA_HOME="$XDG_DATA_HOME" \
    XDG_CACHE_HOME="$XDG_CACHE_HOME" XDG_STATE_HOME="$XDG_STATE_HOME" \
    SPIKE_COVERAGE_ARM="$coverage" SPIKE_DISABLE_CUSTOM_FETCH="${SPIKE_DISABLE_CUSTOM_FETCH:-0}" \
    timeout 60 "$OPENCODE_BIN" run --title spike -m "${provider}/spike" 'Return the stub response.' 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output" > "$ROOT/run-${name}.log"
  printf '%s\n' "$status" > "$ROOT/run-${name}.status"
}

probe_refresh_counter() {
  : > "$ROOT/refresh.log"
  set +e
  env -i PATH="$PATH" HOME="$HOME" USER="${USER:-}" \
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" XDG_DATA_HOME="$XDG_DATA_HOME" \
    XDG_CACHE_HOME="$XDG_CACHE_HOME" XDG_STATE_HOME="$XDG_STATE_HOME" \
    SPIKE_PROBE_REFRESH_COUNTER=1 bun "$ROOT/plugin.ts" > "$ROOT/probe.log" 2>&1
  local status=$?
  set -e
  local count vendor
  count="$(count_lines '^SHIPPED_REFRESH_ATTEMPT$' "$ROOT/refresh.log")"
  vendor="$(count_lines 'auth.x.ai' "$ROOT/stub-headers.log")"
  printf 'SPIKE probe shipped_refresh=%s vendor_requests=%s exit=%s\n' "$count" "$vendor" "$status"
  if [[ "$status" != 0 || "$count" != 1 || "$vendor" != 0 ]]; then
    fail "probe shipped_refresh=${count} vendor_requests=${vendor} exit=${status}"
  fi
}

run_control() {
  local provider="$1"
  : > "$ROOT/fetch.log"
  : > "$ROOT/stub-headers.log"
  : > "$ROOT/stub-requests.log"
  run_child "control-${provider}" "$provider" 0
  local status fetch_count ok
  status="$(< "$ROOT/run-control-${provider}.status")"
  fetch_count="$(count_lines "^SPIKE_FETCH provider=${provider} " "$ROOT/fetch.log")"
  ok="$(count_lines 'SPIKE_OK' "$ROOT/run-control-${provider}.log")"
  printf 'SPIKE %s control custom_fetch=%s stub_ok=%s exit=%s\n' "$provider" "$fetch_count" "$ok" "$status"
  if [[ "$fetch_count" != 1 || "$ok" == 0 || "$status" != 0 ]]; then
    fail "${provider} control custom_fetch=${fetch_count} stub_ok=${ok} exit=${status}"
  fi
}

coverage_fixture=""
coverage_count=0
run_coverage_fixture() {
  local name="$1"
  local access="$2"
  : > "$ROOT/refresh.log"
  write_auth "$access" 'spike-dummy-refresh' 1
  run_child "coverage-${name}" xai 1
  coverage_count="$(count_lines '^SHIPPED_REFRESH_ATTEMPT$' "$ROOT/refresh.log")"
  local status outcome
  status="$(< "$ROOT/run-coverage-${name}.status")"
  outcome='silent_failure'
  [[ "$status" == 124 ]] && outcome='provider_wedged'
  printf 'SPIKE coverage fixture=%s count=%s outcome=%s exit=%s\n' "$name" "$coverage_count" "$outcome" "$status"
  if (( coverage_count >= 1 )); then
    coverage_fixture="$name"
  fi
}

run_tombstone() {
  : > "$ROOT/fetch.log"
  : > "$ROOT/refresh.log"
  : > "$ROOT/stub-headers.log"
  : > "$ROOT/stub-requests.log"
  cp "$ROOT/canonical-auth.json" "$XDG_DATA_HOME/opencode/auth.json"
  run_child tombstone xai 0
  local status fetch_count refresh_count ok
  status="$(< "$ROOT/run-tombstone.status")"
  fetch_count="$(count_lines '^SPIKE_FETCH provider=xai ' "$ROOT/fetch.log")"
  refresh_count="$(count_lines '^SHIPPED_REFRESH_ATTEMPT$' "$ROOT/refresh.log")"
  ok="$(count_lines 'SPIKE_OK' "$ROOT/run-tombstone.log")"
  if ! cmp -s "$ROOT/canonical-auth.json" "$XDG_DATA_HOME/opencode/auth.json"; then
    fail 'xai auth_fixture_mutated=1'
  fi
  if [[ "$refresh_count" != 0 ]]; then
    local outcome='silent_failure'
    [[ "$status" == 124 ]] && outcome='provider_wedged'
    printf 'SPIKE xai refresh_attempted=1 %s\n' "$outcome" >&2
    fail "xai shipped_refresh=${refresh_count} ${outcome}"
  fi
  if [[ "$status" != 0 || "$ok" == 0 || "$fetch_count" != 1 ]]; then
    fail "xai tombstone custom_fetch=${fetch_count} stub_ok=${ok} exit=${status}"
  fi
  printf 'SPIKE xai custom_fetch=%s shipped_refresh=%s stock=%s\n' "$fetch_count" "$refresh_count" "$version"
}

if [[ "${SPIKE_PROBE_REFRESH_COUNTER:-0}" == 1 ]]; then
  probe_refresh_counter
  finish
  if (( failures != 0 )); then exit 1; fi
  exit 0
fi

selected="${SPIKE_CONTROL_PROVIDER:-all}"
case "$selected" in
  all)
    run_control deepseek
    ;;
  deepseek)
    run_control deepseek
    finish
    if (( failures != 0 )); then exit 1; fi
    exit 0
    ;;
  xai)
    run_control xai
    finish
    if (( failures != 0 )); then exit 1; fi
    exit 0
    ;;
  *)
    fail "unknown_control_provider=${selected}"
    finish
    exit 1
    ;;
esac

run_coverage_fixture empty-access ''
if (( coverage_count == 0 )); then
  run_coverage_fixture stale-access 'spike-dummy-access'
fi
if [[ -z "$coverage_fixture" ]]; then
  printf 'SPIKE STOP coverage=unverified fixtures=empty-access,stale-access\n' >&2
  fail 'coverage=unverified'
  finish
  exit 2
fi
printf 'SPIKE coverage=fired fixture=%s count=%s\n' "$coverage_fixture" "$coverage_count"
run_tombstone
finish
if (( failures != 0 )); then exit 1; fi
