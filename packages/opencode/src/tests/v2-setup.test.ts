import { afterEach, beforeEach, expect, mock, spyOn, test, type Mock } from "bun:test";

import { CustodyExhaustionError, CustodyOrphanError, CustodyOwnershipError, CustodyRequestError, CustodySplitError, HandleFileValidationError } from "../errors";
import { FreshnessController } from "../freshness";
import { OUR_PLUGIN_ID, type OpenCodeHandleFileV1 } from "../handles";
import type { CustodyLogEntry } from "../log";
import plugin from "../opencode-plugin-v2";
import { sentinel, TOMBSTONE_PREFIX } from "../tombstone";
import { getCustodyEndpoint, resetCustodyEndpointForTests } from "../v2/endpoint";
import type { Cleanup, ModelHookOptions, PluginContext, SessionHttpRequest, SessionWebSocketHandshake } from "../v2/host-types";
import { createOpencodeClaustrumPluginV2, type SetupDependencies } from "../v2/setup";

type Hook = {
  name: "http.request" | "experimental.ws.handshake";
  callback: (event: SessionHttpRequest & SessionWebSocketHandshake) => Promise<void> | void;
  options?: ModelHookOptions;
  dispose: Mock<() => Promise<void>>;
  active: boolean;
};

function context() {
  const registrations: Hook[] = [];
  const ctx: PluginContext = { session: { hook: async (name, callback, options) => {
    const registration: Hook = {
      name, callback, options, active: true,
      dispose: mock(async () => { registration.active = false; }),
    };
    registrations.push(registration);
    return registration;
  } } };
  return { ctx, registrations };
}

// OC2 2.0.32 hooks.ts:88-95 keeps insertion order, including unscoped callbacks,
// and passes the same mutable event to every matching callback.
async function runHttpHooks(registrations: Hook[], event: SessionHttpRequest) {
  for (const registration of registrations) {
    if (!registration.active || registration.name !== "http.request") continue;
    if (registration.options?.providerID !== undefined && registration.options.providerID !== event.model.providerID) continue;
    await registration.callback(event as SessionHttpRequest & SessionWebSocketHandshake);
  }
}

async function runWsHooks(registrations: Hook[], event: SessionWebSocketHandshake) {
  for (const registration of registrations) {
    if (!registration.active || registration.name !== "experimental.ws.handshake") continue;
    if (registration.options?.providerID !== undefined && registration.options.providerID !== event.model.providerID) continue;
    await registration.callback(event as SessionHttpRequest & SessionWebSocketHandshake);
  }
}

const HANDLE = `ckh_${"a".repeat(43)}`;
const SECOND_HANDLE = `ckh_${"b".repeat(43)}`;
const MATERIAL = "vault-main-test-material";
const NEW_MATERIAL = "vault-new-test-material";
const scope = { sessionID: "session", agent: "agent", model: { providerID: "deepseek", id: "model" }, kind: "generate" };

function handles(shape: "api" | "oauth" = "api", serve = OUR_PLUGIN_ID): OpenCodeHandleFileV1 {
  return { version: 1, providers: [{
    provider: "deepseek", shape, serve,
    accounts: [{ label: "main", handle: HANDLE, credential_id: "apikey:deepseek:main" }],
  }] };
}

function fakeClient(material = MATERIAL) {
  const getCredential = mock(async (_handle: string, _minTtlMs?: number) => ({ material, recordVersion: 1, expiresAtMs: null }));
  const reportAuthFailure = mock(async (_input: Parameters<import("../serve").ServeClient["reportAuthFailure"]>[0]) => {});
  return { getCredential, reportAuthFailure };
}

const cleanups: Cleanup[] = [];
const logs: CustodyLogEntry[] = [];
let upstream: ReturnType<typeof Bun.serve>;
let requests: { material: boolean; newestMaterial: boolean; sentinel: boolean; body: string; path: string }[];
let respond: (request: Request) => Response | Promise<Response>;
let consoleSpies: ReturnType<typeof spyOn>[];
let disable: string | undefined;

beforeEach(() => {
  disable = process.env.CLAUSTRUM_CUSTODY_DISABLE;
  delete process.env.CLAUSTRUM_CUSTODY_DISABLE;
  logs.length = 0;
  requests = [];
  consoleSpies = (["log", "warn", "error", "info", "debug"] as const).map((method) => spyOn(console, method).mockImplementation(() => {}));
  respond = () => new Response("round-trip");
  upstream = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const authorization = request.headers.get("authorization");
    requests.push({
      material: authorization === `Bearer ${MATERIAL}`,
      newestMaterial: authorization === `Bearer ${NEW_MATERIAL}`,
      sentinel: [...request.headers.values()].some((value) => value.includes(TOMBSTONE_PREFIX)),
      body: await request.text(), path: new URL(request.url).pathname,
    });
    return respond(request);
  } });
});

afterEach(async () => {
  try {
    for (const cleanup of cleanups.splice(0)) await cleanup();
    await resetCustodyEndpointForTests();
    await upstream.stop(true);
    for (const spy of consoleSpies) expect(spy.mock.calls.length).toBe(0);
  } finally {
    for (const spy of consoleSpies) spy.mockRestore();
    if (disable === undefined) delete process.env.CLAUSTRUM_CUSTODY_DISABLE;
    else process.env.CLAUSTRUM_CUSTODY_DISABLE = disable;
  }
});

async function install(host = context(), overrides: SetupDependencies = {}) {
  const manifest = handles();
  const client = fakeClient();
  const handleReader = mock(async () => manifest);
  const endpoint = getCustodyEndpoint({ graceMs: 0 });
  const dependencies: SetupDependencies = {
    handleReader,
    detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
    clientFactory: async () => client as never,
    logSink: (entry) => { logs.push(entry); },
    endpoint,
    ...overrides,
  };
  const cleanup = await createOpencodeClaustrumPluginV2(dependencies)(host.ctx);
  cleanups.push(cleanup);
  return { ...host, client, cleanup, endpoint, handleReader, manifest };
}

function httpEvent(providerID = "deepseek", key = sentinel(providerID)): SessionHttpRequest {
  return { ...scope, model: { ...scope.model, providerID }, request: new Request(`${upstream.url}messages`, {
    method: "POST", headers: { authorization: `Bearer ${key}` }, body: "request-body",
  }) };
}

function wsEvent(): SessionWebSocketHandshake {
  return { ...scope, url: "wss://provider.example/socket", headers: { authorization: `Bearer ${sentinel("deepseek")}`, "x-kept": "untouched" } };
}

test("V2 entry installs custody's request guard", async () => {
  let registrations = 0;
  const ctx: PluginContext = { session: { hook: async () => {
    registrations++;
    return { dispose: async () => {} };
  } } };
  const cleanup = await plugin.setup(ctx);
  try {
    expect(registrations).toBeGreaterThan(0);
  } finally {
    await cleanup?.();
  }
  expect(requests.length).toBe(0);
});

test("arm 1 api happy path routes to V1 serve with material and round-trips the body", async () => {
  const host = await install();
  expect(host.handleReader.mock.calls.length).toBe(1);
  const event = httpEvent();
  await runHttpHooks(host.registrations, event);
  expect(host.endpoint.isEndpointUrl(event.request.url)).toBe(true);
  const response = await fetch(event.request);
  expect(response.status).toBe(200);
  expect(await response.text()).toBe("round-trip");
  expect(requests.length).toBe(1);
  expect(requests[0]).toEqual({ material: true, newestMaterial: false, sentinel: false, body: "request-body", path: "/messages" });
  const again = httpEvent();
  await runHttpHooks(host.registrations, again);
  expect(logs.filter((entry) => entry.level === "info" && entry.provider === "deepseek" && entry.state === "serving").length).toBe(1);
  expect(logs.filter((entry) => entry.provider === "deepseek" && entry.state === "served").length).toBe(1);
});

test("arm 2 oauth happy path asks the refreshable client for minimum TTL", async () => {
  const manifest = handles("oauth");
  const client = fakeClient();
  const host = await install(undefined, { handleReader: async () => manifest, clientFactory: async () => client as never, oauthMinTtlMs: 123_000 });
  const event = httpEvent();
  await runHttpHooks(host.registrations, event);
  const response = await fetch(event.request);
  expect(await response.text()).toBe("round-trip");
  expect(client.getCredential.mock.calls.length).toBe(1);
  expect(client.getCredential.mock.calls[0]?.[1]).toBe(123_000);
  expect(requests.length).toBe(1);
  expect(requests[0]?.material).toBe(true);
  expect(requests[0]?.sentinel).toBe(false);
});

test("arm 3 split refuses a real local key before upstream", async () => {
  const host = await install();
  const event = httpEvent("deepseek", "local-looking-key");
  await expect(runHttpHooks(host.registrations, event)).rejects.toBeInstanceOf(CustodySplitError);
  await expect(runHttpHooks(host.registrations, event)).rejects.toThrow("bun run enroll -- --oc2");
  await expect(runHttpHooks(host.registrations, event)).rejects.toThrow("handle manifest");
  expect(requests.length).toBe(0);
});

test("arm 4 orphan guard refuses any sentinel on unowned providers and leaves unmanaged requests alone", async () => {
  const host = await install();
  await expect(runHttpHooks(host.registrations, httpEvent("unowned"))).rejects.toBeInstanceOf(CustodyOrphanError);
  const urlEvent = httpEvent("unowned", "ordinary");
  urlEvent.request = new Request(`${upstream.url}?key=${sentinel("different")}`);
  await expect(runHttpHooks(host.registrations, urlEvent)).rejects.toBeInstanceOf(CustodyOrphanError);
  const unmanaged = httpEvent("unowned", "ordinary");
  const original = unmanaged.request;
  await runHttpHooks(host.registrations, unmanaged);
  expect(unmanaged.request === original).toBe(true);
  expect(requests.length).toBe(0);
});

test("arm 5 another owner's provider has no scoped hooks and remains untouched", async () => {
  const host = await install(undefined, { handleReader: async () => handles("api", "other-plugin") });
  expect(host.registrations.some((hook) => hook.options?.providerID === "deepseek")).toBe(false);
  const event = httpEvent("deepseek", "ordinary");
  const original = event.request;
  await runHttpHooks(host.registrations, event);
  expect(event.request === original).toBe(true);
  expect(logs.some((entry) => entry.provider === "deepseek" && entry.state === "other_owner")).toBe(true);
  expect(requests.length).toBe(0);
});

test("arm 6 unreadable manifest installs only the fail-closed orphan guard", async () => {
  const host = await install(undefined, { handleReader: async () => { throw new HandleFileValidationError("handle file invalid"); } });
  expect(host.registrations.length).toBe(1);
  expect(host.registrations[0]?.options).toBeUndefined();
  await expect(runHttpHooks(host.registrations, httpEvent())).rejects.toBeInstanceOf(CustodyOrphanError);
  await expect(runHttpHooks(host.registrations, httpEvent())).rejects.toThrow("handle file invalid");
  const unmanaged = httpEvent("unowned", "ordinary");
  const original = unmanaged.request;
  await runHttpHooks(host.registrations, unmanaged);
  expect(unmanaged.request === original).toBe(true);
  expect(requests.length).toBe(0);
});

test("arm 7 disable switch installs nothing and warns with the V2 remedies", async () => {
  process.env.CLAUSTRUM_CUSTODY_DISABLE = "1";
  const host = await install();
  expect(host.registrations.length).toBe(0);
  const warning = logs.find((entry) => entry.errorCode === "custody_disabled");
  expect(warning?.level).toBe("warn");
  expect(warning?.errorMessage?.includes("enroll --remove")).toBe(true);
  expect(warning?.errorMessage?.includes("unsetting")).toBe(true);
  expect(requests.length).toBe(0);
});

test.each([false, true])("arm 8 overlap rewrites once and newest instance serves while old cleanup preserves the stream (reversed=%p)", async (reverse) => {
  const first = await install();
  const secondClient = fakeClient(NEW_MATERIAL);
  await install(first, { clientFactory: async () => secondClient as never });
  const route = spyOn(first.endpoint, "route");
  let release!: () => void;
  const barrier = new Promise<void>((resolve) => { release = resolve; });
  respond = () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode("first-")); },
    async pull(controller) {
      await barrier;
      controller.enqueue(new TextEncoder().encode("last"));
      controller.close();
    },
  }));
  try {
    const event = httpEvent();
    await runHttpHooks(reverse ? [...first.registrations].reverse() : first.registrations, event);
    expect(route.mock.calls.length).toBe(1);
    const response = await fetch(event.request);
    const reader = response.body!.getReader();
    const start = await reader.read();
    expect(new TextDecoder().decode(start.value)).toBe("first-");
    await first.cleanup();
    release();
    const end = await reader.read();
    expect(new TextDecoder().decode(end.value)).toBe("last");
    expect((await reader.read()).done).toBe(true);
    expect(requests.length).toBe(1);
    expect(requests[0]?.newestMaterial).toBe(true);
    expect(requests[0]?.sentinel).toBe(false);
  } finally {
    release();
    route.mockRestore();
  }
});

test("arm 8 cleanup between rewrite and connect still dispatches to the newest instance", async () => {
  const first = await install();
  const event = httpEvent();
  await runHttpHooks(first.registrations, event);
  const newer = fakeClient(NEW_MATERIAL);
  await install(first, { clientFactory: async () => newer as never });
  await first.cleanup();
  const response = await fetch(event.request);
  expect(response.status).toBe(200);
  await response.text();
  expect(requests.length).toBe(1);
  expect(requests[0]?.newestMaterial).toBe(true);
});

test.each([false, true])("arm 9 WS only current instance substitutes; URL sentinels and split headers refuse (reversed=%p)", async (reverse) => {
  const first = await install();
  const newer = fakeClient(NEW_MATERIAL);
  await install(first, { clientFactory: async () => newer as never });
  const oldHook = first.registrations.find((hook) => hook.name === "experimental.ws.handshake")!;
  const oldEvent = wsEvent();
  await oldHook.callback(oldEvent as SessionHttpRequest & SessionWebSocketHandshake);
  expect(oldEvent.headers.authorization?.includes(sentinel("deepseek"))).toBe(true);
  expect(first.client.getCredential.mock.calls.length).toBe(0);
  const event = wsEvent();
  const ordered = reverse ? [...first.registrations].reverse() : first.registrations;
  await runWsHooks(ordered, event);
  expect(event.headers.authorization === `Bearer ${NEW_MATERIAL}`).toBe(true);
  expect(event.headers["x-kept"]).toBe("untouched");
  const urlSentinel = wsEvent();
  urlSentinel.url += `?key=${sentinel("deepseek")}`;
  await expect(runWsHooks(ordered, urlSentinel)).rejects.toBeInstanceOf(CustodyRequestError);
  const split = wsEvent();
  split.headers = { authorization: "ordinary" };
  await expect(runWsHooks(ordered, split)).rejects.toBeInstanceOf(CustodySplitError);
  expect(logs.filter((entry) => entry.provider === "deepseek" && entry.state === "served").length).toBe(1);
  expect(requests.length).toBe(0);
});

test("arm 9 WS refuses exhausted credentials with V1's exhaustion class", async () => {
  const client = fakeClient();
  client.getCredential.mockImplementation(async () => { throw new Error("vault unavailable"); });
  const host = await install(undefined, { clientFactory: async () => client as never });
  await expect(runWsHooks(host.registrations, wsEvent())).rejects.toBeInstanceOf(CustodyExhaustionError);
  expect(requests.length).toBe(0);
});

test("arm 10 upstream 401 reports auth failure and tries the next account", async () => {
  const manifest = handles();
  manifest.providers[0]!.accounts.push({ label: "second", handle: SECOND_HANDLE, credential_id: "apikey:deepseek:second" });
  const client = fakeClient();
  client.getCredential.mockImplementation(async (handle) => ({ material: handle === HANDLE ? MATERIAL : NEW_MATERIAL, recordVersion: 1, expiresAtMs: null }));
  const host = await install(undefined, { handleReader: async () => manifest, clientFactory: async () => client as never });
  respond = () => new Response("round-trip", { status: requests.length === 1 ? 401 : 200 });
  const event = httpEvent();
  await runHttpHooks(host.registrations, event);
  const response = await fetch(event.request);
  expect(response.status).toBe(200);
  await response.text();
  expect(requests.length).toBe(2);
  expect(requests[0]?.material).toBe(true);
  expect(requests[1]?.newestMaterial).toBe(true);
  expect(client.reportAuthFailure.mock.calls.length).toBe(1);
  const report = client.reportAuthFailure.mock.calls[0]?.[0];
  expect(report?.handle === HANDLE).toBe(true);
  expect(report?.providerStatus).toBe(401);
  expect(report?.reporterSource).toBe("direct");
});

test("arm 11 cleanup disposes every hook, endpoint registration and controller exactly once", async () => {
  const dispose = spyOn(FreshnessController.prototype, "dispose");
  const clearInterval = mock(() => {});
  const setInterval = mock(() => ({ unref() {} }));
  try {
    const host = await install(undefined, { handleReader: async () => handles("oauth"), setInterval, clearInterval });
    expect(host.registrations.length).toBe(3);
    expect(host.endpoint.current !== undefined).toBe(true);
    await host.cleanup();
    await host.cleanup();
    for (const registration of host.registrations) expect(registration.dispose.mock.calls.length).toBe(1);
    expect(host.endpoint.current).toBeUndefined();
    expect(dispose.mock.calls.length).toBe(1);
    expect(clearInterval.mock.calls.length).toBe(1);
    expect(setInterval.mock.calls.length).toBe(1);
    expect(requests.length).toBe(0);
  } finally {
    dispose.mockRestore();
  }
});

test("ownership changes refuse HTTP and WS without forwarding material", async () => {
  let manifest = handles();
  const host = await install(undefined, { handleReader: async () => manifest });
  manifest = handles("api", "other-owner");
  const event = httpEvent();
  await runHttpHooks(host.registrations, event);
  const response = await fetch(event.request);
  expect(response.status).toBe(502);
  await response.text();
  await expect(runWsHooks(host.registrations, wsEvent())).rejects.toBeInstanceOf(CustodyOwnershipError);
  expect(requests.length).toBe(0);
});

test("arm 12 client diagnostics go to the sink, never to the console", async () => {
  const client = fakeClient();
  const host = await install(undefined, { clientFactory: async (options) => {
    options?.logger?.("unknown_wire_class");
    return client as never;
  } });
  const event = httpEvent();
  await runHttpHooks(host.registrations, event);
  const response = await fetch(event.request);
  expect(response.status).toBe(200);
  await response.text();
  expect(logs.some((entry) => entry.level === "warn" && entry.errorClass === "unknown_wire_class")).toBe(true);
  expect(requests.length).toBe(1);
  for (const spy of consoleSpies) expect(spy.mock.calls.length).toBe(0);
});

test("serve forwards the endpoint's cancellation signal and disables Bun's timeout", async () => {
  const abort = new AbortController();
  let propagatedSignal: AbortSignal | undefined;
  let timeoutDisabled = false;
  let redirectManual = false;
  const fetch = Object.assign(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    propagatedSignal = request.signal;
    timeoutDisabled = (init as RequestInit & { timeout?: false })?.timeout === false;
    redirectManual = request.redirect === "manual";
    return new Response("transport-check");
  }, { preconnect: globalThis.fetch.preconnect });
  const host = await install(undefined, { fetch });
  const response = await host.endpoint.current!.serve("deepseek", httpEvent().request, abort.signal);
  expect(await response.text()).toBe("transport-check");
  expect(timeoutDisabled).toBe(true);
  expect(redirectManual).toBe(true);
  abort.abort();
  expect(propagatedSignal?.aborted).toBe(true);
  await expect(host.endpoint.current!.serve("unknown", httpEvent().request, new AbortController().signal)).rejects.toBeInstanceOf(CustodyOwnershipError);
  expect(requests.length).toBe(0);
});
