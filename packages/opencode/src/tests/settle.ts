// Bun's promise matchers run a nested event loop that can stop a socket client from
// servicing I/O on Windows, leaving requests stuck until their timeout. Await the
// promise directly so Bun's normal test loop continues to process network activity.
//
// Rewrite table:
// - expect(await p).toEqual(x) replaces .resolves.toEqual(x).
// - expect(await rejectionOf(p)).toMatchObject(x) replaces .rejects.toMatchObject(x).
// - expect(await throwerOf(p)).toThrow(x) replaces .rejects.toThrow(x).
// - For other resolve matchers, await p inside expect; for other rejection matchers,
//   await rejectionOf(p) inside expect. Preserve matchers such as toBeInstanceOf,
//   toHaveProperty, toBe, toContain, toBeDefined, toBeUndefined, and toHaveLength.
// A generic call may need an explicit type argument inside expect(await …).
export async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  let value: unknown;
  try {
    value = await promise;
  } catch (reason) {
    return reason;
  }
  throw new Error(`expected the promise to reject, but it resolved with ${formatValue(value)}`);
}

export async function throwerOf(promise: Promise<unknown>): Promise<() => never> {
  const reason = await rejectionOf(promise);
  return () => {
    throw reason;
  };
}

function formatValue(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}
