import { afterEach, describe, expect, test } from "bun:test";

import { createLogger, type CustodyLogEntry } from "../log";
import { sentinel } from "../tombstone";
import {
  createUpstreamFetch,
  CustodyEndpointError,
  getCustodyEndpoint,
  resetCustodyEndpointForTests,
  type CustodyEndpoint,
  type EndpointDeps,
  type EndpointInstance,
} from "../v2/endpoint";

const PROVIDER = "deepseek";
const MATERIAL = "fixture-material-never-log";
const servers: Array<ReturnType<typeof Bun.serve>> = [];
const logs: CustodyLogEntry[] = [];
const privatePaths: string[] = [];

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function within<T>(promise: Promise<T>, ms = 2_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("deadline exceeded")), ms); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

type Recorded = { method: string; path: string; headers: Headers; bodyLength: number };

function upstream(respond: (request: Request) => Response | Promise<Response> = () => new Response("round-trip")) {
  const requests: Recorded[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1", port: 0, idleTimeout: 0,
    async fetch(request) {
      requests.push({
        method: request.method,
        path: new URL(request.url).pathname,
        headers: request.headers,
        bodyLength: (await request.arrayBuffer()).byteLength,
      });
      return respond(request);
    },
  });
  servers.push(server);
  return { url: server.url, requests };
}

function endpoint(deps: EndpointDeps = {}) {
  return getCustodyEndpoint({ ...deps, log: createLogger((entry) => logs.push(entry)) });
}

function instance(id = "A"): EndpointInstance {
  return { id, serve: (_provider, request, signal) => createUpstreamFetch(signal)(request) };
}

function route(holder: CustodyEndpoint, url: string | URL, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has("authorization")) headers.set("authorization", `Bearer ${sentinel(PROVIDER)}`);
  const request = holder.route(PROVIDER, new Request(url, { ...init, headers }));
  privatePaths.push(...new URL(request.url).pathname.split("/").filter(Boolean));
  return request;
}

function sse() {
  const release = deferred();
  const aborted = deferred();
  const stub = upstream((request) => {
    request.signal.addEventListener("abort", aborted.resolve, { once: true });
    let event = 0;
    return new Response(new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (event++ === 0) {
          controller.enqueue(new TextEncoder().encode("data: first\n\n"));
          return;
        }
        await release.promise;
        controller.enqueue(new TextEncoder().encode("data: second\n\n"));
        controller.close();
      },
    }), { headers: { "content-type": "text/event-stream" } });
  });
  return { ...stub, release, aborted };
}

afterEach(async () => {
  await resetCustodyEndpointForTests();
  for (const server of servers.splice(0)) await server.stop(true);
  const serialized = JSON.stringify(logs.splice(0));
  const leaked = privatePaths.splice(0).some((part) => serialized.includes(part));
  expect(leaked).toBe(false);
  expect(serialized.includes(MATERIAL)).toBe(false);
});

describe("OC2 loopback custody endpoint", () => {
  test("a: round-trips the recorded destination, streamed body and safe headers", async () => {
    const stub = upstream();
    const holder = endpoint();
    holder.register(instance());
    const original = new URL("/original/path", stub.url);
    const request = route(holder, original, {
      method: "POST",
      body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("payload")); controller.close(); } }),
      headers: { connection: "x-private", "x-private": MATERIAL, "proxy-authorization": MATERIAL, host: "untrusted.invalid" },
    });
    expect(holder.isEndpointUrl(request.url)).toBe(true);
    expect(holder.isEndpointUrl(`${request.url}extra`)).toBe(true);
    expect(holder.isEndpointUrl(`${stub.url}wrong`)).toBe(false);
    const response = await fetch(request);
    expect(await response.text()).toBe("round-trip");
    expect(stub.requests.length).toBe(1);
    const recorded = stub.requests[0]!;
    expect(recorded.method).toBe("POST");
    expect(recorded.path).toBe("/original/path");
    expect(recorded.bodyLength).toBe(7);
    expect(recorded.headers.get("authorization") === `Bearer ${sentinel(PROVIDER)}`).toBe(true);
    expect(recorded.headers.get("host") === original.host).toBe(true);
    expect(recorded.headers.has("x-private")).toBe(false);
    expect(recorded.headers.has("proxy-authorization")).toBe(false);
  });

  test("b: consumed ids cannot be replayed", async () => {
    const stub = upstream();
    const holder = endpoint();
    holder.register(instance());
    const request = route(holder, stub.url);
    const replay = request.clone();
    expect(await (await fetch(request)).text()).toBe("round-trip");
    expect((await fetch(replay)).status).toBe(404);
    expect(stub.requests.length).toBe(1);
  });

  test("b: unknown ids and wrong tokens are indistinguishable", async () => {
    const stub = upstream();
    const holder = endpoint();
    holder.register(instance());
    const request = route(holder, stub.url);
    const unknown = new URL(request.url);
    unknown.pathname = unknown.pathname.replace(/[^/]+$/, "unknown");
    const wrong = new URL(request.url);
    wrong.pathname = `/wrong/${wrong.pathname.split("/")[2]}`;
    for (const url of [unknown, wrong]) {
      const response = await fetch(url);
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({ error: "not_found" });
    }
    expect(stub.requests.length).toBe(0);
  });

  test("c: method mismatch and absent sentinel consume without dispatch", async () => {
    const stub = upstream();
    const holder = endpoint();
    holder.register(instance());
    const mismatch = route(holder, stub.url);
    expect((await fetch(mismatch.url, { method: "POST", headers: mismatch.headers })).status).toBe(409);
    expect((await fetch(mismatch)).status).toBe(404);
    const absent = route(holder, stub.url);
    expect((await fetch(absent.url)).status).toBe(403);
    expect((await fetch(absent)).status).toBe(404);
    expect(stub.requests.length).toBe(0);
  });

  test("d: body cap covers content-length and chunked reads", async () => {
    const stub = upstream();
    const holder = endpoint({ maxBodyBytes: 4 });
    holder.register(instance());
    expect((await fetch(route(holder, stub.url, { method: "POST", body: "12345" }))).status).toBe(413);
    const chunked = route(holder, stub.url, {
      method: "POST",
      body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("12345")); controller.close(); } }),
    });
    expect((await fetch(chunked)).status).toBe(413);
    expect(stub.requests.length).toBe(0);
  });

  test("d: concurrency stays occupied until the response body ends", async () => {
    const stub = sse();
    const holder = endpoint({ maxInFlight: 1 });
    holder.register(instance());
    const response = await fetch(route(holder, stub.url));
    const reader = response.body!.getReader();
    expect((await reader.read()).done).toBe(false);
    expect((await fetch(route(holder, stub.url))).status).toBe(503);
    expect(stub.requests.length).toBe(1);
    stub.release.resolve();
    while (!(await reader.read()).done) {}
    const next = await fetch(route(holder, stub.url));
    await next.text();
    expect(stub.requests.length).toBe(2);
  });

  test("e: reload dispatches an older route through the newest live instance", async () => {
    const stub = upstream();
    const holder = endpoint();
    holder.register(instance("A"));
    const request = route(holder, stub.url);
    const registration = holder.register({
      id: "B",
      serve: (_provider, outbound, signal) => {
        outbound.headers.set("x-instance", "B");
        return createUpstreamFetch(signal)(outbound);
      },
    });
    await (await fetch(request)).text();
    expect(stub.requests.length).toBe(1);
    expect(stub.requests[0]!.headers.get("x-instance") === "B").toBe(true);
    registration.dispose();
    await (await fetch(route(holder, stub.url))).text();
    expect(stub.requests.length).toBe(2);
    expect(stub.requests[1]!.headers.has("x-instance")).toBe(false);
  });

  test("f: last dispose preserves an in-flight SSE until completion then grace closes", async () => {
    const stub = sse();
    const holder = endpoint({ graceMs: 30 });
    const registration = holder.register(instance());
    const request = route(holder, stub.url);
    const response = await fetch(request);
    const reader = response.body!.getReader();
    await reader.read();
    registration.dispose();
    await Bun.sleep(60);
    expect(holder.isEndpointUrl(request.url)).toBe(true);
    stub.release.resolve();
    const second = await reader.read();
    expect(new TextDecoder().decode(second.value)).toBe("data: second\n\n");
    expect((await reader.read()).done).toBe(true);
    expect(stub.requests.length).toBe(1);
    await Bun.sleep(60);
    expect(() => route(holder, stub.url)).toThrow(CustodyEndpointError);
    expect(holder.isEndpointUrl(request.url)).toBe(false);
  });

  test("g: quiet SSE survives eleven seconds without a server idle timeout", async () => {
    const stub = sse();
    const holder = endpoint();
    holder.register(instance());
    const response = await fetch(route(holder, stub.url));
    const reader = response.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("data: first\n\n");
    await Bun.sleep(11_000);
    stub.release.resolve();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("data: second\n\n");
    expect((await reader.read()).done).toBe(true);
    expect(stub.requests.length).toBe(1);
  }, 30_000);

  test("h: client abort reaches the upstream request signal within two seconds", async () => {
    const stub = sse();
    const holder = endpoint();
    holder.register(instance());
    const abort = new AbortController();
    const response = await fetch(route(holder, stub.url), { signal: abort.signal });
    const reader = response.body!.getReader();
    await reader.read();
    abort.abort();
    try { await within(stub.aborted.promise); } finally { stub.release.resolve(); }
    expect(stub.requests.length).toBe(1);
    await reader.cancel().catch(() => {});
  });

  test("g: explicit short idle timeout is a live cut positive control", async () => {
    const stub = sse();
    const holder = endpoint({ idleTimeoutSeconds: 2 });
    holder.register(instance());
    const response = await fetch(route(holder, stub.url));
    const reader = response.body!.getReader();
    await reader.read();
    // OC2 embeds a different Bun; pair the quiet-stream guard with an actual idle-cut control.
    try {
      const outcome = await Promise.race([
        reader.read().then(() => "data", () => "closed"),
        Bun.sleep(6_000).then(() => "open"),
      ]);
      expect(outcome).toBe("closed");
      expect(stub.requests.length).toBe(1);
    } finally {
      stub.release.resolve();
    }
  }, 10_000);

  test("i: decoded gzip is not advertised as compressed to the loopback client", async () => {
    const stub = upstream(() => new Response(Bun.gzipSync(new TextEncoder().encode("plain text")), {
      headers: { "content-encoding": "gzip", "content-length": "30" },
    }));
    const holder = endpoint();
    holder.register(instance());
    const response = await fetch(route(holder, stub.url));
    expect(response.headers.has("content-encoding")).toBe(false);
    expect(await response.text()).toBe("plain text");
    expect(stub.requests.length).toBe(1);
  });

  test("M3: attacker-supplied query destination never reaches a second upstream", async () => {
    const stub = upstream();
    const attacker = upstream();
    const holder = endpoint();
    holder.register(instance());
    const request = route(holder, new URL("/pinned", stub.url));
    const tampered = new URL(request.url);
    tampered.searchParams.set("url", attacker.url.href);
    await (await fetch(tampered, { headers: request.headers })).text();
    expect(stub.requests.length).toBe(1);
    expect(attacker.requests.length).toBe(0);
    expect(stub.requests[0]!.path).toBe("/pinned");
  });

  test("j: rejection logs contain codes and class names, never request material", async () => {
    const stub = upstream();
    const holder = endpoint();
    holder.register({ id: "throwing", serve: async () => { throw new TypeError(MATERIAL); } });
    const response = await fetch(route(holder, stub.url, { headers: { "x-material": MATERIAL } }));
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({ error: "serve_failed" });
    expect(logs).toEqual([{ level: "warn", errorCode: "serve_failed", provider: PROVIDER, errorClass: "TypeError" }]);
    expect(stub.requests.length).toBe(0);
  });

  test("expired entries, table cap, no instance and process-wide identity", async () => {
    const stub = upstream();
    let now = 0;
    const holder = endpoint({ now: () => now, ttlMs: 10, maxEntries: 1 });
    expect(getCustodyEndpoint()).toBe(holder);
    expect(() => route(holder, stub.url)).toThrow(CustodyEndpointError);
    const registration = holder.register(instance());
    const expired = route(holder, stub.url);
    expect(() => route(holder, stub.url)).toThrow(CustodyEndpointError);
    now = 11;
    expect((await fetch(expired)).status).toBe(404);
    const request = route(holder, stub.url);
    registration.dispose();
    expect((await fetch(request)).status).toBe(503);
    expect(stub.requests.length).toBe(0);
  });
});
