export function redirectFetch(forwardAuthorization = false): typeof fetch {
  return Object.assign(async (input: RequestInfo | URL, init?: RequestInit) => {
    const response = await fetch(input, { ...init, redirect: "manual" });
    const location = response.headers.get("location");
    if (!location) return response;
    await response.body?.cancel();
    const headers = new Headers(init?.headers);
    if (!forwardAuthorization) headers.delete("authorization");
    return fetch(location, { method: "GET", headers, signal: init?.signal });
  }, { preconnect: fetch.preconnect });
}

export function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

export function followingWebSocket(afterErrorDelayMs?: number) {
  const state = { forwarded: 0 };
  const completed = deferred();
  class Socket extends EventTarget {
    constructor(url: string, options: { headers: Record<string, string> }) {
      super();
      void (async () => {
        try {
          const source = new URL(url); source.protocol = "http:";
          const response = await fetch(source, { redirect: "manual", headers: { ...options.headers, upgrade: "websocket" } });
          const target = new URL(response.headers.get("location")!); target.protocol = "http:";
          await response.body?.cancel();
          if (afterErrorDelayMs !== undefined) {
            this.dispatchEvent(new Event("error"));
            await new Promise<void>((resolve) => setTimeout(resolve, afterErrorDelayMs));
          }
          const followed = await fetch(target, { headers: options.headers });
          await followed.body?.cancel();
          state.forwarded++;
        } finally { this.dispatchEvent(new Event("error")); completed.resolve(); }
      })().catch(() => {});
    }
    close() {}
  }
  return { Socket, state, completed: completed.promise };
}
