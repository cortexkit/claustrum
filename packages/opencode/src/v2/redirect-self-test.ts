type ProbeSocket = Pick<WebSocket, "addEventListener" | "close">;
type ProbeSocketConstructor = new (url: string, options: { headers: Record<string, string> }) => ProbeSocket;
export type RedirectProbeResult = { safe: true } | { safe: false; status: number | "bind" | "timeout" | "ws" };
export type RedirectProbeDependencies = {
  fetch?: typeof fetch;
  serve?: typeof Bun.serve;
  timeoutMs?: number;
  WebSocket?: ProbeSocketConstructor;
};

const STATUSES = [301, 302, 303, 307, 308] as const;

// This measures runtime fetch and WebSocket, not OpenCode's own redirect transport.
// Each supported OpenCode version still needs a live redirect-carry check.
export async function checkRedirectSafety(dependencies: RedirectProbeDependencies = {}): Promise<RedirectProbeResult> {
  const fetch = dependencies.fetch ?? globalThis.fetch;
  const serve = dependencies.serve ?? Bun.serve;
  // Bun supports header options, but its declarations prefer the DOM-only overload when lib.dom is present.
  const WebSocket = dependencies.WebSocket ?? globalThis.WebSocket as unknown as ProbeSocketConstructor;
  const servers: Array<ReturnType<typeof Bun.serve>> = [];
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let settleTimer: ReturnType<typeof setTimeout> | undefined;
  let status: number | "bind" | "ws" = "bind";
  let socket: ProbeSocket | undefined;
  let sourceUpgraded = false;
  let targetAuthorization = false;
  const hits = new Map<number, { count: number; authorization: boolean }>();
  try {
    const deadline = new Promise<RedirectProbeResult>((resolve) => {
      timer = setTimeout(() => resolve({ safe: false, status: status === "ws" ? "ws" : "timeout" }), Math.min(dependencies.timeoutMs ?? 2_000, 2_000));
    });
    const probe = (async (): Promise<RedirectProbeResult> => {
      try {
        const target = serve({ hostname: "127.0.0.1", port: 0, fetch(request) {
          if (new URL(request.url).pathname === "/ws") {
            targetAuthorization ||= request.headers.has("authorization");
            return new Response("probe");
          }
          const code = Number(new URL(request.url).pathname.slice(1));
          const hit = hits.get(code);
          if (hit) { hit.count++; hit.authorization ||= request.headers.has("authorization"); }
          return new Response("probe");
        } });
        servers.push(target);
        const source = serve({ hostname: "127.0.0.1", port: 0, fetch(request) {
          if (new URL(request.url).pathname === "/ws") {
            sourceUpgraded ||= request.headers.get("upgrade")?.toLowerCase() === "websocket";
            const location = new URL("/ws", target.url); location.protocol = "ws:";
            return new Response(null, { status: 302, headers: { location: location.href } });
          }
          const code = Number(new URL(request.url).pathname.slice(1));
          return new Response(null, { status: code, headers: { location: new URL(`/${code}`, target.url).href } });
        } });
        servers.push(source);
        const authorization = `Bearer claustrum-probe-${crypto.randomUUID()}`;
        for (const code of STATUSES) {
          status = code;
          hits.set(code, { count: 0, authorization: false });
          const response = await fetch(new URL(`/${code}`, source.url), {
            method: "POST", body: "probe", headers: { authorization }, signal: controller.signal,
          });
          await response.body?.cancel();
          const hit = hits.get(code)!;
          if (hit.count !== 1 || hit.authorization) return { safe: false, status: code };
        }
        status = "ws";
        const location = new URL("/ws", source.url); location.protocol = "ws:";
        await new Promise<void>((resolve) => {
          socket = new WebSocket(location.href, { headers: { authorization } });
          socket.addEventListener("close", () => resolve(), { once: true });
          socket.addEventListener("error", () => resolve(), { once: true });
        });
        // Some clients report an error before starting a redirected handshake.
        await new Promise<void>((resolve) => { settleTimer = setTimeout(resolve, 150); });
        if (!sourceUpgraded || targetAuthorization) return { safe: false, status: "ws" };
        return { safe: true };
      } catch {
        return { safe: false, status };
      }
    })();
    return await Promise.race([probe, deadline]);
  } finally {
    clearTimeout(timer);
    clearTimeout(settleTimer);
    controller.abort();
    try { socket?.close(); } catch { /* Closing a failed handshake must not replace the safety verdict. */ }
    await Promise.allSettled(servers.map((server) => server.stop(true)));
  }
}
