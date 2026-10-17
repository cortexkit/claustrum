import { afterEach, expect, mock, test } from "bun:test";

import { CustodyRedirectUnsafeError } from "../errors";
import { createLogger, type CustodyLogEntry } from "../log";
import { checkRedirectSafety } from "../v2/redirect-self-test";
import { getCustodyRegistry, resetCustodyRegistryForTests } from "../v2/registry";
import { redirectFetch } from "./v2-helpers";

afterEach(() => { resetCustodyRegistryForTests(); });

test("a stripping fetch reaches all five redirect targets with POST source probes", async () => {
  const methods: string[] = [];
  const statuses: number[] = [];
  const strip = redirectFetch();
  const fetch = Object.assign(async (input: RequestInfo | URL, init?: RequestInit) => {
    methods.push(init?.method ?? "");
    statuses.push(Number(new URL(String(input)).pathname.slice(1)));
    return strip(input, init);
  }, { preconnect: globalThis.fetch.preconnect });
  expect(await checkRedirectSafety({ fetch })).toEqual({ safe: true });
  expect(methods).toEqual(["POST", "POST", "POST", "POST", "POST"]);
  expect(statuses).toEqual([301, 302, 303, 307, 308]);
});

test("forwarded Authorization fails with the status, never the probe value", async () => {
  expect(await checkRedirectSafety({ fetch: redirectFetch(true) })).toEqual({ safe: false, status: 301 });
});

test("a fetch that never reaches the target cannot pass the instrument", async () => {
  const fetch = Object.assign(async () => new Response("not sent"), { preconnect: globalThis.fetch.preconnect });
  expect(await checkRedirectSafety({ fetch })).toEqual({ safe: false, status: 301 });
});

test("a hung probe times out and aborts its transport", async () => {
  let signal: AbortSignal | undefined;
  const fetch = Object.assign(async (_input: RequestInfo | URL, init?: RequestInit) => {
    signal = init?.signal ?? undefined;
    return new Promise<Response>(() => {});
  }, { preconnect: globalThis.fetch.preconnect });
  expect(await checkRedirectSafety({ fetch, timeoutMs: 10 })).toEqual({ safe: false, status: "timeout" });
  expect(signal?.aborted).toBe(true);
});

test("bind failures close an already-open probe listener and return a safe discriminator", async () => {
  let first: ReturnType<typeof Bun.serve> | undefined;
  const serve = ((options: Parameters<typeof Bun.serve>[0]) => {
    if (first) throw new Error("bind canary must not escape");
    first = Bun.serve(options);
    return first;
  }) as typeof Bun.serve;
  expect(await checkRedirectSafety({ serve })).toEqual({ safe: false, status: "bind" });
  let reachable = true;
  try { await fetch(first!.url); } catch { reachable = false; }
  expect(reachable).toBe(false);
});

test("the real Bun fetch strips Authorization for all five cross-origin redirects", async () => {
  expect(await checkRedirectSafety({ fetch: globalThis.fetch })).toEqual({ safe: true });
});

test("the process holder caches the self-test across reload module copies", async () => {
  const registry = getCustodyRegistry();
  const fetch = Object.assign(mock(redirectFetch()), { preconnect: globalThis.fetch.preconnect });
  const log = createLogger(() => {});
  await registry.ensureRedirectSafe({ fetch }, log);
  const path = `../v2/registry.ts?reload=${crypto.randomUUID()}`;
  const reloaded = await import(path);
  expect(reloaded.getCustodyRegistry() === registry).toBe(true);
  await reloaded.getCustodyRegistry().ensureRedirectSafe({ fetch }, log);
  expect(fetch.mock.calls.length).toBe(5);
  const event = {};
  expect(registry.claim(event)).toBe(true);
  expect(reloaded.getCustodyRegistry().claim(event)).toBe(false);
});

test("a failed self-test stays failed and logs once across reloads", async () => {
  const entries: CustodyLogEntry[] = [];
  const log = createLogger((entry) => { entries.push(entry); });
  const registry = getCustodyRegistry();
  await expect(registry.ensureRedirectSafe({ fetch: redirectFetch(true) }, log)).rejects.toBeInstanceOf(CustodyRedirectUnsafeError);
  await expect(registry.ensureRedirectSafe({ fetch: redirectFetch() }, log)).rejects.toBeInstanceOf(CustodyRedirectUnsafeError);
  expect(entries.length).toBe(1);
  expect(entries[0]?.errorMessage).toBe("custody redirect safety self-test failed: status=301; Authorization substitution refused");
});
