import { timingSafeEqual } from "node:crypto";

import { CustodyEndpointError } from "../errors";
import { createLogger, type CustodyLogger } from "../log";
import { sentinel } from "../tombstone";
import type { SessionWebSocketHandshake } from "./host-types";

export { CustodyEndpointError } from "../errors";

export type EndpointInstance = {
  readonly id: string;
  serve(provider: string, request: Request, signal: AbortSignal): Promise<Response>;
  ownership(provider: string): "owned" | "other" | "absent" | "unknown";
  handshake(provider: string, event: SessionWebSocketHandshake): Promise<void>;
};

export type EndpointDeps = {
  now?: () => number;
  ttlMs?: number;
  graceMs?: number;
  maxBodyBytes?: number;
  maxInFlight?: number;
  maxEntries?: number;
  idleTimeoutSeconds?: number;
  log?: CustodyLogger;
};

type Entry = { provider: string; method: string; url: string; expiresAt: number; consumed: boolean };
export type BunRequestInit = RequestInit & { timeout: false };
const HOLDER_KEY = Symbol.for("cortexkit.claustrum.custody.v2/1");
const holders = globalThis as typeof globalThis & { [HOLDER_KEY]?: CustodyEndpoint };
const HOP_HEADERS = [
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
  "transfer-encoding", "upgrade", "host", "content-length",
];

function randomId(bytes: number): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function outboundHeaders(input: Headers): Headers {
  const headers = new Headers(input);
  const connectionHeaders = (headers.get("connection") ?? "").split(",");
  for (const name of [...HOP_HEADERS, ...connectionHeaders]) {
    if (name.trim()) headers.delete(name.trim());
  }
  return headers;
}

export function createUpstreamFetch(signal: AbortSignal, upstreamFetch: typeof fetch = fetch): typeof fetch {
  return Object.assign((input: RequestInfo | URL, init?: RequestInit) => {
    const options: BunRequestInit = {
      ...init,
      signal: AbortSignal.any([...(init?.signal ? [init.signal] : []), signal]),
      timeout: false,
    };
    return upstreamFetch(input, options);
  }, { preconnect: upstreamFetch.preconnect });
}

// In-process plugins already share manifest/vault access; this is not an isolation boundary.
// Runtime-private state prevents accidental reflection/serialization, not a hostile plugin's vault use.
export class CustodyEndpoint {
  readonly #token = randomId(32);
  readonly #entries = new Map<string, Entry>();
  readonly #instances: EndpointInstance[] = [];
  readonly #handledHandshakes = new WeakSet<object>();
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #graceMs: number;
  readonly #maxBodyBytes: number;
  readonly #maxInFlight: number;
  readonly #maxEntries: number;
  readonly #idleTimeoutSeconds: number;
  readonly #log: CustodyLogger;
  #server: ReturnType<typeof Bun.serve> | undefined;
  #closeTimer: ReturnType<typeof setTimeout> | undefined;
  #inFlight = 0;

  constructor(deps: EndpointDeps = {}) {
    this.#now = deps.now ?? Date.now;
    this.#ttlMs = deps.ttlMs ?? 30_000;
    this.#graceMs = deps.graceMs ?? 30_000;
    this.#maxBodyBytes = deps.maxBodyBytes ?? 32 * 1024 * 1024;
    this.#maxInFlight = deps.maxInFlight ?? 64;
    this.#maxEntries = deps.maxEntries ?? 4096;
    this.#idleTimeoutSeconds = deps.idleTimeoutSeconds ?? 0;
    this.#log = deps.log ?? createLogger();
  }

  get current(): EndpointInstance | undefined {
    return this.#instances.at(-1);
  }

  claimHandshake(event: object): boolean {
    if (this.#handledHandshakes.has(event)) return false;
    this.#handledHandshakes.add(event);
    return true;
  }

  register(instance: EndpointInstance): { dispose(): void } {
    this.cancelClose();
    this.#server ??= Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      // Provider SSE streams may be silent for longer than Bun's ten-second default.
      idleTimeout: this.#idleTimeoutSeconds,
      // The handler owns the cap so over-limit responses have the same safe JSON/log shape.
      maxRequestBodySize: Number.MAX_SAFE_INTEGER,
      fetch: (request) => this.handle(request),
    });
    this.#instances.push(instance);
    let disposed = false;
    return { dispose: () => {
      if (disposed) return;
      disposed = true;
      const index = this.#instances.lastIndexOf(instance);
      if (index >= 0) this.#instances.splice(index, 1);
      this.scheduleClose();
    } };
  }

  route(provider: string, request: Request): Request {
    this.prune(true);
    if (!this.#server) throw new CustodyEndpointError("no_server");
    if (this.#entries.size >= this.#maxEntries) throw new CustodyEndpointError("entries_full");
    let id: string;
    do { id = randomId(16); } while (this.#entries.has(id));
    const routed = new Request(`${this.origin()}/${this.#token}/${id}`, request);
    this.#entries.set(id, {
      provider, method: request.method, url: request.url, expiresAt: this.#now() + this.#ttlMs, consumed: false,
    });
    return routed;
  }

  isEndpointUrl(url: string): boolean {
    if (!this.#server) return false;
    try {
      const parsed = new URL(url);
      // not-a-path: a WHATWG URL pathname always uses "/" separators, on every platform.
      const parts = parsed.pathname.split("/");
      return parsed.origin === this.origin() && !parsed.username && !parsed.password && !parsed.search && !parsed.hash &&
        parts.length === 3 && parts[1] === this.#token && /^[A-Za-z0-9_-]{22}$/.test(parts[2]!);
    } catch {
      return false;
    }
  }

  private origin(): string {
    return `http://127.0.0.1:${this.#server!.port}`;
  }

  private prune(includeConsumed = false): void {
    const now = this.#now();
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt <= now || includeConsumed && entry.consumed) this.#entries.delete(id);
    }
  }

  private tokenMatches(candidate: string): boolean {
    const actual = Buffer.alloc(this.#token.length);
    actual.write(candidate);
    return timingSafeEqual(actual, Buffer.from(this.#token)) && candidate.length === this.#token.length;
  }

  private reject(status: number, errorCode: string, provider?: string, errorClass?: string): Response {
    this.#log.warn({ errorCode, ...(provider ? { provider } : {}), ...(errorClass ? { errorClass } : {}) });
    return Response.json({ error: errorCode }, { status });
  }

  private async handle(request: Request): Promise<Response> {
    try {
      return await this.handleRequest(request);
    } catch {
      // Even a broken sink must not hand Bun an exception containing the loopback path.
      try { this.#log.warn({ errorCode: "internal" }); } catch {}
      return Response.json({ error: "internal" }, { status: 500 });
    }
  }

  private async handleRequest(request: Request): Promise<Response> {
    this.cancelClose();
    this.prune();
    try {
      if (request.headers.get("host") !== `127.0.0.1:${this.#server?.port}`) return this.reject(404, "not_found");
      // not-a-path: a WHATWG URL pathname always uses "/" separators, on every platform.
      const parts = new URL(request.url).pathname.split("/");
      if (parts.length !== 3 || !this.tokenMatches(parts[1]!)) return this.reject(404, "not_found");
      const entry = this.#entries.get(parts[2]!);
      if (!entry || entry.consumed) return this.reject(404, "not_found");
      // Every attempt with a live id consumes it, including method/sentinel rejections.
      entry.consumed = true;
      if (request.method !== entry.method) return this.reject(409, "method_mismatch", entry.provider);
      if (![...request.headers.values()].some((value) => value.includes(sentinel(entry.provider)))) {
        return this.reject(403, "sentinel_absent", entry.provider);
      }
      if (this.#inFlight >= this.#maxInFlight) return this.reject(503, "busy", entry.provider);
      this.#inFlight++;
      let released = false;
      const finish = () => {
        if (released) return;
        released = true;
        this.#inFlight--;
        this.scheduleClose();
      };
      let streaming = false;
      try {
        const length = request.headers.get("content-length");
        if (length !== null && Number(length) > this.#maxBodyBytes) return this.reject(413, "too_large", entry.provider);
        const chunks: Uint8Array[] = [];
        let size = 0;
        if (request.body) {
          const reader = request.body.getReader();
          try {
            while (true) {
              const chunk = await reader.read();
              if (chunk.done) break;
              size += chunk.value.byteLength;
              if (size > this.#maxBodyBytes) {
                await reader.cancel();
                return this.reject(413, "too_large", entry.provider);
              }
              chunks.push(chunk.value);
            }
          } finally {
            reader.releaseLock();
          }
        }
        const current = this.current;
        if (!current) return this.reject(503, "no_instance", entry.provider);
        const rebuilt = new Request(entry.url, {
          method: entry.method,
          headers: outboundHeaders(request.headers),
          body: entry.method === "GET" || entry.method === "HEAD" ? undefined : Buffer.concat(chunks, size),
          signal: request.signal,
        });
        const response = await current.serve(entry.provider, rebuilt, request.signal);
        // OC2 follows redirects; only V1 serve may resolve one while credential material is present.
        if (response.status >= 300 && response.status < 400 && response.headers.has("location")) {
          try { await response.body?.cancel(); } catch {}
          return this.reject(502, "redirect_refused", entry.provider);
        }
        const headers = outboundHeaders(response.headers);
        for (const name of [...headers.keys()]) {
          if (name === "set-cookie" || name === "set-cookie2" || name.startsWith("access-control-")) headers.delete(name);
        }
        headers.delete("content-encoding");
        headers.delete("content-length");
        if (!response.body) return new Response(null, { status: response.status, statusText: response.statusText, headers });
        const reader = response.body.getReader();
        const body = new ReadableStream<Uint8Array>({
          async pull(controller) {
            try {
              const chunk = await reader.read();
              if (chunk.done) { controller.close(); finish(); }
              else controller.enqueue(chunk.value);
            } catch (error) {
              controller.error(error);
              finish();
            }
          },
          async cancel(reason) {
            try { await reader.cancel(reason); } finally { finish(); }
          },
        });
        const relayed = new Response(body, { status: response.status, statusText: response.statusText, headers });
        streaming = true;
        return relayed;
      } catch (error) {
        return this.reject(502, "serve_failed", entry.provider, error instanceof Error ? error.constructor.name : "Error");
      } finally {
        if (!streaming) finish();
      }
    } finally {
      this.scheduleClose();
    }
  }

  private cancelClose(): void {
    clearTimeout(this.#closeTimer);
    this.#closeTimer = undefined;
  }

  private scheduleClose(): void {
    if (this.#instances.length || this.#inFlight || !this.#server || this.#closeTimer) return;
    this.#closeTimer = setTimeout(() => {
      this.#closeTimer = undefined;
      if (this.#instances.length || this.#inFlight) return;
      const server = this.#server;
      this.#server = undefined;
      this.#entries.clear();
      void server?.stop();
    }, this.#graceMs);
    this.#closeTimer.unref();
  }

  /** Test-only: force-closes even active streams; production cleanup uses register().dispose(). */
  async resetForTests(): Promise<void> {
    this.cancelClose();
    this.#instances.length = 0;
    this.#entries.clear();
    const server = this.#server;
    this.#server = undefined;
    await server?.stop(true);
  }
}

export function getCustodyEndpoint(deps?: EndpointDeps): CustodyEndpoint {
  return holders[HOLDER_KEY] ??= new CustodyEndpoint(deps);
}

/** Test-only isolation: closes the process-wide server and forgets its holder. */
export async function resetCustodyEndpointForTests(): Promise<void> {
  const endpoint = holders[HOLDER_KEY];
  delete holders[HOLDER_KEY];
  await endpoint?.resetForTests();
}
