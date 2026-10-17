// packages/plugin/src/promise/plugin.ts:57-66 (OpenCode 2.0.32)
export type Cleanup = () => Promise<void> | void;

// packages/plugin/src/promise/plugin.ts:57-66 (OpenCode 2.0.32)
export type Plugin = { readonly id: string; readonly setup: (context: PluginContext) => Promise<Cleanup | void> | Cleanup | void };

// packages/plugin/src/promise/plugin.ts:26-55 (OpenCode 2.0.32)
export type PluginContext = { readonly options?: unknown; readonly session: { readonly hook: SessionHook } };

// packages/plugin/src/promise/session.ts:72-78 (OpenCode 2.0.32)
export type SessionHttpRequest = { readonly sessionID: string; readonly agent: string; readonly model: { readonly providerID: string; readonly id: string }; readonly kind: string; request: Request };

// packages/plugin/src/promise/session.ts:93-100 (OpenCode 2.0.32)
export type SessionWebSocketHandshake = { readonly sessionID: string; readonly agent: string; readonly model: { readonly providerID: string; readonly id: string }; readonly kind: string; url: string; headers: Record<string, string> };

// packages/plugin/src/promise/registration.ts:1-9 (OpenCode 2.0.32)
export type ModelHookOptions = { readonly providerID?: string };

// packages/plugin/src/promise/registration.ts:1-9 (OpenCode 2.0.32)
export type Registration = { readonly dispose: () => Promise<void> };

// packages/plugin/src/promise/session.ts:145 and 367-379 (OpenCode 2.0.32)
export type SessionHook = {
  (name: "http.request", callback: (input: SessionHttpRequest) => Promise<void> | void, options?: ModelHookOptions): Promise<Registration>;
  (name: "experimental.ws.handshake", callback: (input: SessionWebSocketHandshake) => Promise<void> | void, options?: ModelHookOptions): Promise<Registration>;
};
