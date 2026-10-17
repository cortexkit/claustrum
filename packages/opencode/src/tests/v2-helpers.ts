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
