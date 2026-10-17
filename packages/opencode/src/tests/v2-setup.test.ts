import { afterEach, beforeEach, expect, mock, spyOn, test, type Mock } from "bun:test";
import type { ServedCredential } from "@cortexkit/claustrum-client";

import { CustodyExhaustionError, CustodyOrphanError, CustodyOwnershipError, CustodyPlacementError, CustodyRedirectUnsafeError, CustodyRequestError, CustodySplitError, HandleFileValidationError } from "../errors";
import { FreshnessController } from "../freshness";
import { OUR_PLUGIN_ID, type OpenCodeHandleFileV1 } from "../handles";
import type { CustodyLogEntry } from "../log";
import plugin from "../opencode-plugin-v2";
import { sentinel, TOMBSTONE_PREFIX } from "../tombstone";
import type { Cleanup, ModelHookOptions, PluginContext, SessionHttpRequest, SessionHttpResponse, SessionWebSocketHandshake } from "../v2/host-types";
import { getCustodyRegistry, resetCustodyRegistryForTests } from "../v2/registry";
import { createOpencodeClaustrumPluginV2, type SetupDependencies } from "../v2/setup";
import { deferred, redirectFetch } from "./v2-helpers";

type Event = SessionHttpRequest & SessionHttpResponse & SessionWebSocketHandshake;
type Hook = { name: "http.request" | "http.response" | "experimental.ws.handshake"; callback: (event: Event) => Promise<void> | void; options?: ModelHookOptions; active: boolean; dispose: Mock<() => Promise<void>> };
function context(beforeRegister?: () => Promise<void>) {
  const registrations: Hook[] = [];
  const ctx: PluginContext = { session: { hook: async (name, callback, options) => {
    await beforeRegister?.();
    const registration: Hook = { name, callback, options, active: true, dispose: mock(async () => { registration.active = false; }) };
    registrations.push(registration);
    return registration;
  } } };
  return { ctx, registrations };
}

// OpenCode 2.0.32 packages/core/src/plugin/hooks.ts:88-95.
async function run(host: ReturnType<typeof context>, name: Hook["name"], event: SessionHttpRequest | SessionHttpResponse | SessionWebSocketHandshake, reverse = false) {
  for (const registration of reverse ? [...host.registrations].reverse() : host.registrations) {
    if (!registration.active || registration.name !== name) continue;
    if (registration.options?.providerID !== undefined && registration.options.providerID !== event.model.providerID) continue;
    await registration.callback(event as Event);
  }
}
const HANDLE = `ckh_${"a".repeat(43)}`;
const SECOND_HANDLE = `ckh_${"b".repeat(43)}`;
const MATERIAL = "vault-main-test-material";
const OTHER_MATERIAL = "vault-second-test-material";
const scope = { sessionID: "session", agent: "agent", model: { providerID: "deepseek", id: "model" }, kind: "generate" };
function handles(shape: "api" | "oauth" = "api", serve = OUR_PLUGIN_ID, two = false): OpenCodeHandleFileV1 {
  return { version: 1, providers: [{ provider: "deepseek", shape, serve, accounts: [
    { label: "main", handle: HANDLE, credential_id: "apikey:deepseek:main" },
    ...(two ? [{ label: "second", handle: SECOND_HANDLE, credential_id: "apikey:deepseek:second" }] : []),
  ] }] };
}
function client(material = MATERIAL) {
  return {
    getCredential: mock(async (handle: string, _minTtlMs?: number): Promise<ServedCredential> => ({ material: handle === HANDLE ? material : OTHER_MATERIAL, recordVersion: handle === HANDLE ? 17 : 23, expiresAtMs: null, credentialId: handle === HANDLE ? "apikey:deepseek:main" : "apikey:deepseek:second" })),
    reportAuthFailure: mock(async (_input: Parameters<import("../serve").ServeClient["reportAuthFailure"]>[0]) => {}),
  };
}
const cleanups: Cleanup[] = [];
const logs: CustodyLogEntry[] = [];
let upstream: ReturnType<typeof Bun.serve>;
let requests: { main: boolean; second: boolean; placeholder: boolean; body: string }[];
let consoleSpies: ReturnType<typeof spyOn>[];
let disable: string | undefined;
beforeEach(() => {
  disable = process.env.CLAUSTRUM_CUSTODY_DISABLE;
  delete process.env.CLAUSTRUM_CUSTODY_DISABLE;
  logs.length = 0;
  requests = [];
  consoleSpies = (["log", "warn", "error", "info", "debug"] as const).map((method) => spyOn(console, method).mockImplementation(() => {}));
  upstream = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const authorization = request.headers.get("authorization");
    requests.push({ main: authorization === `Bearer ${MATERIAL}`, second: authorization === `Bearer ${OTHER_MATERIAL}`, placeholder: request.url.includes(TOMBSTONE_PREFIX) || [...request.headers.values()].some((value) => value.includes(TOMBSTONE_PREFIX)), body: await request.text() });
    return new Response("round-trip");
  } });
});
afterEach(async () => {
  try {
    for (const cleanup of cleanups.splice(0)) await cleanup();
    resetCustodyRegistryForTests();
    await upstream.stop(true);
    for (const spy of consoleSpies) expect(spy.mock.calls.length).toBe(0);
    const serialized = JSON.stringify(logs);
    expect([MATERIAL, OTHER_MATERIAL, HANDLE, SECOND_HANDLE, sentinel("deepseek")].some((value) => serialized.includes(value))).toBe(false);
  } finally {
    for (const spy of consoleSpies) spy.mockRestore();
    if (disable === undefined) delete process.env.CLAUSTRUM_CUSTODY_DISABLE;
    else process.env.CLAUSTRUM_CUSTODY_DISABLE = disable;
  }
});
async function install(host = context(), overrides: SetupDependencies = {}) {
  const vault = client();
  const manifest = handles();
  const handleReader = mock(async () => manifest);
  const cleanup = await createOpencodeClaustrumPluginV2({
    handleReader, detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }), clientFactory: async () => vault as never,
    fetch: redirectFetch(), logSink: (entry) => { logs.push(entry); }, ...overrides,
  })(host.ctx);
  cleanups.push(cleanup);
  return { ...host, vault, manifest, handleReader, cleanup, registry: getCustodyRegistry() };
}
function httpEvent(providerID = "deepseek", key = sentinel(providerID)): SessionHttpRequest {
  return { ...scope, model: { ...scope.model, providerID }, request: new Request(`${upstream.url}messages`, { method: "POST", headers: { authorization: `Bearer ${key}` }, body: "request-body" }) };
}
function wsEvent(): SessionWebSocketHandshake { return { ...scope, url: "wss://provider.example/socket", headers: { authorization: `Bearer ${sentinel("deepseek")}`, "x-kept": "untouched" } }; }
function responseEvent(event: SessionHttpRequest, status: number, headers?: HeadersInit): SessionHttpResponse { return { ...event, response: new Response("host-body", { status, headers }) }; }

test("V2 entry installs hooks without opening a serving listener", async () => {
  const serve = spyOn(Bun, "serve");
  const host = context();
  try {
    const cleanup = await plugin.setup(host.ctx);
    cleanups.push(cleanup!);
    expect(host.registrations.length).toBeGreaterThan(0);
    expect(serve.mock.calls.length).toBe(0);
  } finally { serve.mockRestore(); }
});

test("API requests substitute Authorization in place without changing the destination", async () => {
  const host = await install();
  expect(host.handleReader.mock.calls.length).toBe(1);
  const event = httpEvent();
  const destination = event.request.url;
  await run(host, "http.request", event);
  expect(event.request.url === destination).toBe(true);
  expect(event.request.headers.get("authorization") === `Bearer ${MATERIAL}`).toBe(true);
  expect(event.request.url.includes(TOMBSTONE_PREFIX) || [...event.request.headers.values()].some((value) => value.includes(TOMBSTONE_PREFIX))).toBe(false);
  expect(await (await fetch(event.request)).text()).toBe("round-trip");
  expect(requests).toEqual([{ main: true, second: false, placeholder: false, body: "request-body" }]);
  await run(host, "http.request", httpEvent());
  expect(logs.filter((entry) => entry.level === "info" && entry.state === "serving").length).toBe(1);
  expect(logs.filter((entry) => entry.state === "served").length).toBe(1);
});

test.each(["raw", "percent-encoded"])("URL placeholders fail placement before resolving material (%s)", async (mode) => {
  const host = await install();
  const event = httpEvent();
  const marker = mode === "percent-encoded" ? encodeURIComponent(sentinel("deepseek")) : sentinel("deepseek");
  event.request = new Request(`${upstream.url}?key=${marker}`, event.request);
  const original = event.request;
  await expect(run(host, "http.request", event)).rejects.toBeInstanceOf(CustodyPlacementError);
  expect(event.request === original).toBe(true);
  expect(host.vault.getCredential.mock.calls.length).toBe(0);
  expect(requests.length).toBe(0);
});
test.each(["x-api-key", "x-goog-api-key"])("placeholder in %s is refused without partial substitution", async (header) => {
  const host = await install();
  const event = httpEvent();
  event.request.headers.set(header, sentinel("deepseek"));
  let failure: unknown;
  try { await run(host, "http.request", event); } catch (error) { failure = error; }
  expect(failure instanceof CustodyPlacementError).toBe(true);
  expect(failure instanceof Error && failure.message.includes(header)).toBe(true);
  expect(failure instanceof Error && failure.message.includes(sentinel("deepseek"))).toBe(false);
  expect(event.request.headers.get("authorization")?.includes(sentinel("deepseek"))).toBe(true);
  expect(host.vault.getCredential.mock.calls.length).toBe(0);
});
test("a request with no placeholder fails split with both remedies", async () => {
  const host = await install();
  await expect(run(host, "http.request", httpEvent("deepseek", "ordinary"))).rejects.toBeInstanceOf(CustodySplitError);
  await expect(run(host, "http.request", httpEvent("deepseek", "ordinary"))).rejects.toThrow("bun run enroll -- --oc2 --provider deepseek");
  await expect(run(host, "http.request", httpEvent("deepseek", "ordinary"))).rejects.toThrow("handle manifest");
});
test("body placeholders are not inspected or substituted", async () => {
  const host = await install();
  const event = httpEvent();
  event.request = new Request(event.request, { body: sentinel("deepseek") });
  await run(host, "http.request", event);
  expect((await event.request.text()) === sentinel("deepseek")).toBe(true);
});
test("OAuth requests keep minimum TTL and request cancellation", async () => {
  const host = await install(undefined, { handleReader: async () => handles("oauth"), oauthMinTtlMs: 123_000 });
  const controller = new AbortController();
  const event = httpEvent();
  event.request = new Request(event.request, { signal: controller.signal });
  await run(host, "http.request", event);
  expect(host.vault.getCredential.mock.calls[0]?.[1]).toBe(123_000);
  controller.abort();
  expect(event.request.signal.aborted).toBe(true);
});
test("orphan HTTP and WS placeholders refuse but unmanaged requests pass untouched", async () => {
  const host = await install();
  await expect(run(host, "http.request", httpEvent("absent"))).rejects.toBeInstanceOf(CustodyOrphanError);
  const ws = { ...wsEvent(), model: { ...scope.model, providerID: "absent" } };
  await expect(run(host, "experimental.ws.handshake", ws)).rejects.toBeInstanceOf(CustodyOrphanError);
  const event = httpEvent("absent", "ordinary"); const original = event.request;
  await run(host, "http.request", event); expect(event.request === original).toBe(true);
});
test("other owners' HTTP and WS placeholders remain untouched and unclaimed", async () => {
  const first = await install();
  await install(first, { handleReader: async () => handles("api", "other-plugin") });
  const event = httpEvent(); const original = event.request;
  const ws = wsEvent();
  await run(first, "http.request", event); await run(first, "experimental.ws.handshake", ws);
  expect(event.request === original).toBe(true);
  expect(ws.headers.authorization?.includes(sentinel("deepseek"))).toBe(true);
  expect(first.registry.claim(event)).toBe(true); expect(first.registry.claim(ws)).toBe(true);
  expect(first.vault.getCredential.mock.calls.length).toBe(0);
});
test("unreadable manifests fail closed without exposing the reader's message", async () => {
  const host = await install(undefined, { handleReader: async () => { throw new HandleFileValidationError(MATERIAL); } });
  await expect(run(host, "http.request", httpEvent())).rejects.toThrow("handle file unavailable: HandleFileValidationError");
  expect(host.vault.getCredential.mock.calls.length).toBe(0);
});
test("disable switch logs owned providers and installs nothing", async () => {
  process.env.CLAUSTRUM_CUSTODY_DISABLE = "1";
  const host = await install();
  expect(host.registrations.length).toBe(0);
  expect(logs.some((entry) => entry.errorCode === "custody_disabled" && entry.errorMessage?.includes("Owned providers: deepseek"))).toBe(true);
});

test("401 reports the served handle and version, invalidates, and the next request can use account two", async () => {
  const vault = client(); let rejected = false;
  const original = vault.getCredential.getMockImplementation()!;
  vault.getCredential.mockImplementation(async (handle, ttl) => {
    if (rejected && handle === HANDLE) throw new Error("reported credential unavailable");
    return original(handle, ttl);
  });
  vault.reportAuthFailure.mockImplementation(async () => { rejected = true; });
  const invalidate = spyOn(FreshnessController.prototype, "invalidate");
  try {
    const host = await install(undefined, { handleReader: async () => handles("api", OUR_PLUGIN_ID, true), clientFactory: async () => vault as never });
    const event = httpEvent(); await run(host, "http.request", event);
    const response = responseEvent(event, 401); const body = response.response.body;
    await run(host, "http.response", response);
    expect(vault.reportAuthFailure.mock.calls.length).toBe(1);
    const report = vault.reportAuthFailure.mock.calls[0]?.[0];
    expect(report?.handle === HANDLE).toBe(true); expect(report?.recordVersion).toBe(17); expect(report?.reporterSource).toBe("direct");
    expect(invalidate.mock.calls.length).toBe(1); expect(invalidate.mock.calls[0]?.[0].handle === HANDLE).toBe(true);
    expect(response.response.body === body).toBe(true); expect(response.response.bodyUsed).toBe(false);
    expect(await response.response.text()).toBe("host-body");
    expect(vault.getCredential.mock.calls.length).toBe(1);
    const next = httpEvent(); await run(host, "http.request", next);
    expect(next.request.headers.get("authorization") === `Bearer ${OTHER_MATERIAL}`).toBe(true);
    expect(requests.length).toBe(0);
  } finally { invalidate.mockRestore(); }
});
test.each(["seconds", "date", "invalid", "payment"])("response cooldown selects the next account until expiry (%s)", async (kind) => {
  let now = 1_700_000_000_000;
  const duration = kind === "payment" ? 3_600_000 : kind === "invalid" ? 60_000 : 3_000;
  const retry = kind === "seconds" ? "3" : kind === "date" ? new Date(now + duration).toUTCString() : "invalid";
  const host = await install(undefined, { handleReader: async () => handles("api", OUR_PLUGIN_ID, true), now: () => now });
  const event = httpEvent(); await run(host, "http.request", event);
  const response = responseEvent(event, kind === "payment" ? 402 : 429, { "Retry-After": retry });
  await run(host, "http.response", response); expect(response.response.bodyUsed).toBe(false);
  const next = httpEvent(); await run(host, "http.request", next);
  expect(next.request.headers.get("authorization") === `Bearer ${OTHER_MATERIAL}`).toBe(true);
  now += duration;
  const after = httpEvent(); await run(host, "http.request", after);
  expect(after.request.headers.get("authorization") === `Bearer ${MATERIAL}`).toBe(true);
});
test("unmatched responses and duplicate response hooks do not report twice", async () => {
  const host = await install();
  await run(host, "http.response", responseEvent(httpEvent(), 401));
  await run(host, "http.response", responseEvent(httpEvent(), 401));
  expect(host.vault.reportAuthFailure.mock.calls.length).toBe(0);
  expect(logs.filter((entry) => entry.errorCode === "unmatched_response").length).toBe(1);
  const event = httpEvent(); await run(host, "http.request", event);
  await run(host, "http.response", responseEvent({ ...event, request: event.request.clone() }, 401));
  expect(host.vault.reportAuthFailure.mock.calls.length).toBe(0);
  const response = responseEvent(event, 401); await run(host, "http.response", response); await run(host, "http.response", response);
  expect(host.vault.reportAuthFailure.mock.calls.length).toBe(1);
});
test("binding mismatches skip accounts for both HTTP and WS", async () => {
  const vault = client();
  vault.getCredential.mockImplementation(async (handle) => ({ material: handle === HANDLE ? MATERIAL : OTHER_MATERIAL, recordVersion: 1, expiresAtMs: null, credentialId: handle === HANDLE ? "wrong-binding" : "apikey:deepseek:second" }));
  const host = await install(undefined, { handleReader: async () => handles("api", OUR_PLUGIN_ID, true), clientFactory: async () => vault as never });
  const event = httpEvent(); await run(host, "http.request", event);
  const ws = wsEvent(); await run(host, "experimental.ws.handshake", ws);
  expect(event.request.headers.get("authorization") === `Bearer ${OTHER_MATERIAL}`).toBe(true);
  expect(ws.headers.authorization === `Bearer ${OTHER_MATERIAL}`).toBe(true);
  expect(logs.filter((entry) => entry.errorCode === "binding_mismatch").length).toBe(2);
});
test.each(["forward", "reverse"])("reload hooks substitute each event once via current in either order (%s)", async (order) => {
  const first = await install(); const newer = client(OTHER_MATERIAL);
  await install(first, { clientFactory: async () => newer as never });
  const track = spyOn(first.registry, "track");
  try {
    const event = httpEvent(); await run(first, "http.request", event, order === "reverse");
    const ws = wsEvent(); await run(first, "experimental.ws.handshake", ws, order === "reverse");
    expect(event.request.headers.get("authorization") === `Bearer ${OTHER_MATERIAL}`).toBe(true);
    expect(ws.headers.authorization === `Bearer ${OTHER_MATERIAL}`).toBe(true);
    expect(track.mock.calls.length).toBe(1); expect(first.vault.getCredential.mock.calls.length).toBe(0);
  } finally { track.mockRestore(); }
});
test("stale hooks delegate during the new instance's hook-installation window", async () => {
  const first = await install(); const entered = deferred(); const release = deferred(); const newer = client(OTHER_MATERIAL);
  const host = context(async () => { entered.resolve(); await release.promise; });
  const pending = install(host, { clientFactory: async () => newer as never });
  await entered.promise;
  try {
    const event = httpEvent(); await run(first, "http.request", event);
    const ws = wsEvent(); await run(first, "experimental.ws.handshake", ws);
    expect(event.request.headers.get("authorization") === `Bearer ${OTHER_MATERIAL}`).toBe(true);
    expect(ws.headers.authorization === `Bearer ${OTHER_MATERIAL}`).toBe(true);
  } finally { release.resolve(); await pending; }
});
test("responses go to the serving instance across reloads and drop after its disposal", async () => {
  const first = await install(); const event = httpEvent(); await run(first, "http.request", event);
  const newer = client(OTHER_MATERIAL); const second = await install(first, { clientFactory: async () => newer as never });
  await run(first, "http.response", responseEvent(event, 401));
  expect(first.vault.reportAuthFailure.mock.calls.length).toBe(1); expect(newer.reportAuthFailure.mock.calls.length).toBe(0);
  const secondEvent = httpEvent(); await run(first, "http.request", secondEvent);
  await second.cleanup();
  const third = await install(first);
  await run(third, "http.response", responseEvent(secondEvent, 401));
  expect(newer.reportAuthFailure.mock.calls.length).toBe(0);
  expect(logs.some((entry) => entry.errorCode === "disposed_response")).toBe(true);
});
test("absent credential ids warn only once across HTTP and WS selection", async () => {
  const vault = client();
  vault.getCredential.mockImplementation(async () => ({ material: MATERIAL, recordVersion: 1, expiresAtMs: null }));
  const host = await install(undefined, { clientFactory: async () => vault as never });
  await run(host, "http.request", httpEvent());
  await run(host, "experimental.ws.handshake", wsEvent());
  expect(logs.filter((entry) => entry.errorCode === "credential_id_absent").length).toBe(1);
});
test("WS preserves header substitution and refuses URL placeholders, splits and exhaustion", async () => {
  const host = await install(); const ws = wsEvent(); await run(host, "experimental.ws.handshake", ws);
  expect(ws.headers.authorization === `Bearer ${MATERIAL}`).toBe(true); expect(ws.headers["x-kept"]).toBe("untouched");
  const url = wsEvent(); url.url += `?key=${encodeURIComponent(sentinel("deepseek"))}`;
  await expect(run(host, "experimental.ws.handshake", url)).rejects.toBeInstanceOf(CustodyRequestError);
  const split = wsEvent(); split.headers = {};
  await expect(run(host, "experimental.ws.handshake", split)).rejects.toBeInstanceOf(CustodySplitError);
  const bad = client(); bad.getCredential.mockImplementation(async () => { throw new Error("vault unavailable"); });
  await install(host, { clientFactory: async () => bad as never });
  await expect(run(host, "experimental.ws.handshake", wsEvent())).rejects.toBeInstanceOf(CustodyExhaustionError);
});
test.each(["forward", "timeout", "bind"])("unsafe redirect probes fail HTTP and WS closed (%s)", async (kind) => {
  const fetch = kind === "forward" ? redirectFetch(true) : Object.assign(async () => new Promise<Response>(() => {}), { preconnect: globalThis.fetch.preconnect });
  const host = await install(undefined, { fetch, redirectProbe: kind === "bind" ? { serve: (() => { throw new Error(MATERIAL); }) as typeof Bun.serve } : { timeoutMs: 10 } });
  const event = httpEvent(); const original = event.request;
  await expect(run(host, "http.request", event)).rejects.toBeInstanceOf(CustodyRedirectUnsafeError);
  await expect(run(host, "experimental.ws.handshake", wsEvent())).rejects.toBeInstanceOf(CustodyRedirectUnsafeError);
  expect(event.request === original).toBe(true); expect(host.vault.getCredential.mock.calls.length).toBe(0);
  expect(logs.filter((entry) => entry.errorClass === "CustodyRedirectUnsafeError").length).toBe(1);
});
test("ownership changes refuse before material resolution", async () => {
  let manifest = handles(); const host = await install(undefined, { handleReader: async () => manifest });
  manifest = handles("api", "other-plugin");
  await expect(run(host, "http.request", httpEvent())).rejects.toBeInstanceOf(CustodyOwnershipError);
});
test("cleanup is idempotent and disposes every hook, registration and controller", async () => {
  const dispose = spyOn(FreshnessController.prototype, "dispose"); const clearInterval = mock(() => {});
  try {
    const host = await install(undefined, { handleReader: async () => handles("oauth"), setInterval: () => ({ unref() {} }), clearInterval });
    await host.cleanup(); await host.cleanup();
    for (const hook of host.registrations) expect(hook.dispose.mock.calls.length).toBe(1);
    expect(host.registry.current).toBeUndefined(); expect(dispose.mock.calls.length).toBe(1); expect(clearInterval.mock.calls.length).toBe(1);
  } finally { dispose.mockRestore(); }
});
