export type RedirectProbeResult = { safe: true } | { safe: false; status: number | "bind" | "timeout" };
export type RedirectProbeDependencies = {
  fetch?: typeof fetch;
  serve?: typeof Bun.serve;
  timeoutMs?: number;
};

const STATUSES = [301, 302, 303, 307, 308] as const;

// This measures the runtime fetch, not OpenCode's own redirect transport.
// Each supported OpenCode version still needs a live redirect-carry check.
export async function checkRedirectSafety(dependencies: RedirectProbeDependencies = {}): Promise<RedirectProbeResult> {
  const fetch = dependencies.fetch ?? globalThis.fetch;
  const serve = dependencies.serve ?? Bun.serve;
  const servers: Array<ReturnType<typeof Bun.serve>> = [];
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let status: number | "bind" = "bind";
  const hits = new Map<number, { count: number; authorization: boolean }>();
  try {
    const deadline = new Promise<RedirectProbeResult>((resolve) => {
      timer = setTimeout(() => resolve({ safe: false, status: "timeout" }), Math.min(dependencies.timeoutMs ?? 2_000, 2_000));
    });
    const probe = (async (): Promise<RedirectProbeResult> => {
      try {
        const target = serve({ hostname: "127.0.0.1", port: 0, fetch(request) {
          const code = Number(new URL(request.url).pathname.slice(1));
          const hit = hits.get(code);
          if (hit) { hit.count++; hit.authorization ||= request.headers.has("authorization"); }
          return new Response("probe");
        } });
        servers.push(target);
        const source = serve({ hostname: "127.0.0.1", port: 0, fetch(request) {
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
        return { safe: true };
      } catch {
        return { safe: false, status };
      }
    })();
    return await Promise.race([probe, deadline]);
  } finally {
    clearTimeout(timer);
    controller.abort();
    await Promise.allSettled(servers.map((server) => server.stop(true)));
  }
}
