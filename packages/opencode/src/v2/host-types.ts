// OpenCode 2.0.32 packages/plugin/src/promise/plugin.ts:57-66
export type Cleanup = () => Promise<void> | void;

// OpenCode 2.0.32 packages/plugin/src/promise/plugin.ts:57-66
export type Plugin = { readonly id: string; readonly setup: (context: PluginContext) => Promise<Cleanup | void> | Cleanup | void };

// OpenCode 2.0.32 packages/plugin/src/promise/plugin.ts:26-55
export type PluginContext = { readonly options?: unknown; readonly session: { readonly hook: SessionHook } };

// OpenCode 2.0.32 packages/plugin/src/promise/session.ts:72-78
export type SessionHttpRequest = { readonly sessionID: string; readonly agent: string; readonly model: { readonly providerID: string; readonly id: string }; readonly kind: string; request: Request };

// OpenCode 2.0.32 packages/plugin/src/promise/session.ts:93-100
export type SessionWebSocketHandshake = { readonly sessionID: string; readonly agent: string; readonly model: { readonly providerID: string; readonly id: string }; readonly kind: string; url: string; headers: Record<string, string> };

// OpenCode 2.0.32 packages/plugin/src/promise/registration.ts:1-9
export type ModelHookOptions = { readonly providerID?: string };

// OpenCode 2.0.32 packages/plugin/src/promise/registration.ts:1-9
export type Registration = { readonly dispose: () => Promise<void> };

// OpenCode 2.0.32 packages/plugin/src/promise/session.ts:145,367-379
export type SessionHook = {
  (name: "http.request", callback: (input: SessionHttpRequest) => Promise<void> | void, options?: ModelHookOptions): Promise<Registration>;
  (name: "experimental.ws.handshake", callback: (input: SessionWebSocketHandshake) => Promise<void> | void, options?: ModelHookOptions): Promise<Registration>;
};
