import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CustodyPlacementError } from "../errors";
import { OUR_PLUGIN_ID } from "../handles";
import { createFileLogSink, type CustodyLogEntry } from "../log";
import { sentinel } from "../tombstone";
import type { Cleanup, ModelHookOptions, PluginContext, SessionHttpRequest, SessionHttpResponse, SessionWebSocketHandshake } from "../v2/host-types";
import { resetCustodyRegistryForTests } from "../v2/registry";
import { createOpencodeClaustrumPluginV2 } from "../v2/setup";
import { redirectFetch } from "./v2-helpers";

type Event = SessionHttpRequest & SessionHttpResponse & SessionWebSocketHandshake;
type Hook = { name: "http.request" | "http.response" | "experimental.ws.handshake"; callback: (event: Event) => Promise<void> | void; options?: ModelHookOptions; active: boolean };
function context() {
  const registrations: Hook[] = [];
  const ctx: PluginContext = { session: { hook: async (name, callback, options) => {
    const registration: Hook = { name, callback, options, active: true };
    registrations.push(registration);
    return { dispose: async () => { registration.active = false; } };
  } } };
  return { ctx, registrations };
}
async function run(host: ReturnType<typeof context>, name: Hook["name"], event: SessionHttpRequest | SessionWebSocketHandshake) {
  for (const registration of host.registrations) {
    if (!registration.active || registration.name !== name) continue;
    if (registration.options?.providerID !== undefined && registration.options.providerID !== event.model.providerID) continue;
    await registration.callback(event as Event);
  }
}

const MATERIAL = "vault-placement-test-material";
const scope = { sessionID: "session", agent: "agent", model: { providerID: "deepseek", id: "model" }, kind: "generate" };
const cleanups: Cleanup[] = [];
const roots: string[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
  resetCustodyRegistryForTests();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

test.each([
  { transport: "http", location: "x-api-key", code: "x_api_key" },
  { transport: "ws", location: "x-api-key", code: "x_api_key" },
  { transport: "ws", location: "X-Api-Key", code: "x_api_key" },
  { transport: "http", location: "url", code: "url" },
  { transport: "http", location: "x".repeat(40), code: "other_header" },
  { transport: "http", location: "x.api.key", code: "other_header" },
  { transport: "http", location: "cafe", code: "other_header" },
])("V2 placement file log names $transport $location as $code without secrets", async ({ transport, location, code }) => {
  const root = mkdtempSync(join(tmpdir(), "v2-placement-log-"));
  roots.push(root);
  const path = join(root, "custody.jsonl");
  const host = context();
  const cleanup = await createOpencodeClaustrumPluginV2({
    handleReader: async () => ({ version: 1, providers: [{ provider: "deepseek", shape: "api", serve: OUR_PLUGIN_ID,
      accounts: [{ label: "main", handle: `ckh_${"a".repeat(43)}`, credential_id: "apikey:deepseek:main" }] }] }),
    detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
    clientFactory: async () => ({
      getCredential: async () => ({ material: MATERIAL, recordVersion: 17, expiresAtMs: null, credentialId: "apikey:deepseek:main" }),
      reportAuthFailure: async () => {},
    }) as never,
    fetch: redirectFetch(), logSink: createFileLogSink({ path }),
  })(host.ctx);
  cleanups.push(cleanup);
  const marker = sentinel("deepseek");
  const headers = { authorization: `Bearer ${marker}`, ...(location === "url" ? {} : { [location]: marker }) };
  const refusal = transport === "ws"
    ? run(host, "experimental.ws.handshake", { ...scope, url: "wss://provider.example/socket", headers })
    : run(host, "http.request", { ...scope, request: new Request(`https://provider.example/messages${location === "url" ? `?key=${marker}` : ""}`, { headers }) });
  await expect(refusal).rejects.toBeInstanceOf(CustodyPlacementError);
  const contents = readFileSync(path, "utf8");
  expect(contents).not.toContain(marker);
  expect(contents).not.toContain(MATERIAL);
  const rows: CustodyLogEntry[] = contents.trim().split("\n").map((line) => JSON.parse(line));
  const refusals = rows.filter((row) => row.errorClass === "CustodyPlacementError");
  expect(refusals).toHaveLength(1);
  expect(refusals[0]).toMatchObject({ level: "error", provider: "deepseek", errorCode: code });
});
