import { randomUUID } from "node:crypto";

import { ClaustrumClient, detectClaustrumConnection } from "@cortexkit/claustrum-client";

import {
  CustodyOrphanError,
  CustodyOwnershipError,
  CustodyPlacementError,
  CustodyRequestError,
  CustodySplitError,
  HandleFileValidationError,
} from "../errors";
import { FreshnessController, PAYMENT_REQUIRED_COOLDOWN_MS } from "../freshness";
import { defaultHandleFilePath, handleFileRevision, OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "../handles";
import { createLogger, serializedLogSink } from "../log";
import type { ConfigHookDependencies } from "../plugin";
import { cooldownFromRetryAfter, exhaustion, reportWithinBudget, type ServeAccount, type ServeClient } from "../serve";
import { sentinel, TOMBSTONE_PREFIX } from "../tombstone";
import type { Cleanup, PluginContext, Registration, SessionHttpRequest, SessionHttpResponse, SessionWebSocketHandshake } from "./host-types";
import { getCustodyRegistry, type CustodyInstance, type CustodyRegistry, type ServedRequest } from "./registry";
import type { RedirectProbeDependencies } from "./redirect-self-test";
import { containsSentinel } from "./sentinel";

export type SetupDependencies = Pick<ConfigHookDependencies,
  "handleReader" | "handleVersionReader" | "detect" | "clientFactory" | "fetch" | "logSink" | "log" |
  "now" | "setInterval" | "clearInterval" | "oauthMinTtlMs"
> & { registry?: CustodyRegistry; redirectProbe?: Omit<RedirectProbeDependencies, "fetch"> };

export function createOpencodeClaustrumPluginV2(dependencies: SetupDependencies = {}): (ctx: PluginContext) => Promise<Cleanup> {
  const handleReader = dependencies.handleReader ?? readHandleFile;
  const log = createLogger(dependencies.logSink ?? (dependencies.log ? serializedLogSink(dependencies.log) : undefined));
  const detection = dependencies.detect ?? detectClaustrumConnection;
  const clientFactory = dependencies.clientFactory ?? ClaustrumClient.connect;
  const fetch = dependencies.fetch ?? globalThis.fetch;
  const handleVersionReader = dependencies.handleVersionReader
    ?? (dependencies.handleReader ? async (path: string) => JSON.stringify(await handleReader(path)) : handleFileRevision);

  return async (ctx) => {
    if (process.env.CLAUSTRUM_CUSTODY_DISABLE === "1") {
      const warning = "Custody is deliberately off; any tombstoned provider WILL FAIL with a 401 while CLAUSTRUM_CUSTODY_DISABLE=1 sends the tombstone to the wire as the key. To restore custody, unset CLAUSTRUM_CUSTODY_DISABLE.";
      try {
        const owned = (await handleReader(defaultHandleFilePath())).providers
          .filter((provider) => provider.serve === OUR_PLUGIN_ID).map((provider) => provider.provider);
        log.warn({ errorCode: "custody_disabled", errorMessage: `${warning} Owned providers: ${owned.join(", ") || "none"}.` });
      } catch {
        log.warn({ errorCode: "custody_disabled", errorMessage: `${warning} Handle ownership was not read.` });
      }
      return () => {};
    }

    const registrations: Registration[] = [];
    const controllers: FreshnessController[] = [];
    let registryRegistration: { dispose(): void } | undefined;
    let disposed = false;
    let cleanupPromise: Promise<void> | undefined;
    const cleanup = () => cleanupPromise ??= (async () => {
      disposed = true;
      try {
        await Promise.all(registrations.map((registration) => registration.dispose()));
      } finally {
        registryRegistration?.dispose();
        for (const controller of controllers) controller.dispose();
      }
    })();
    const logError = (error: Error, provider: string) => log.error({
      provider, errorClass: error.name, errorCode: (error as NodeJS.ErrnoException).code,
      errorMessage: `${error.name}: custody operation refused`,
    });

    let handles: OpenCodeHandleFileV1 | undefined;
    let handleError: HandleFileValidationError | undefined;
    try {
      handles = await handleReader(defaultHandleFilePath());
    } catch (error) {
      handleError = error instanceof HandleFileValidationError
        ? error
        : new HandleFileValidationError(`handle reader failed: ${error instanceof Error ? error.name : "unknown error"}`);
      logError(handleError, "handle-file");
    }
    const owned = new Map((handles?.providers ?? []).filter((handle) => handle.serve === OUR_PLUGIN_ID)
      .map((handle) => [handle.provider, handle]));
    const ownership = (provider: string) => !handles ? "unknown" as const
      : owned.has(provider) ? "owned" as const
      : handles.providers.some((handle) => handle.provider === provider) ? "other" as const : "absent" as const;
    for (const handle of handles?.providers ?? []) {
      if (handle.serve === OUR_PLUGIN_ID) continue;
      log.debug({ provider: handle.provider, errorClass: "other_owner", errorCode: handle.serve });
      log.info({ provider: handle.provider, state: "other_owner" });
    }

    let connected: Promise<ClaustrumClient> | undefined;
    async function connect(): Promise<ClaustrumClient> {
      if (connected) return connected;
      const pending = (async () => {
        const result = await detection();
        if (result.status !== "available") throw new Error(`Claustrum connection ${result.status}`);
        return clientFactory({ logger: (errorClass: string) =>
          log.warn({ errorClass: typeof errorClass === "string" ? errorClass : "invalid_shape" }) });
      })();
      connected = pending;
      try {
        return await pending;
      } catch (error) {
        if (connected === pending) connected = undefined;
        throw error;
      }
    }
    const client: ServeClient = {
      async getCredential(handle, minTtlMs) { return (await connect()).getCredential(handle, minTtlMs); },
      async reportAuthFailure(input) { await (await connect()).reportAuthFailure(input); },
    };

    try {
      const registry = dependencies.registry ?? getCustodyRegistry();
      const instanceId = randomUUID();
      const requests = new Map<string, (event: SessionHttpRequest) => Promise<void>>();
      const handshakes = new Map<string, (event: SessionWebSocketHandshake) => Promise<void>>();
      const responses = new Map<string, (served: ServedRequest, event: SessionHttpResponse) => Promise<void>>();
      const announcedProviders = new Set<string>();
      const servingProviders = new Set<string>();
      const debugged = new Set<string>();
      const debugOnce = (errorCode: string) => {
        if (debugged.has(errorCode)) return;
        debugged.add(errorCode);
        log.debug({ errorCode });
      };
      const orphan = (provider: string, reason: "absent" | "unknown" | "no_instance") => {
        const remedy = `run bun run enroll -- --oc2 --provider ${provider}`;
        const error = new CustodyOrphanError(reason === "no_instance"
          ? "no live claustrum custody instance in this process; reload OpenCode"
          : reason === "unknown"
            ? `handle file unavailable: ${handleError?.name ?? "custody handle ownership is unknown"}; tombstone ownership cannot be proven; ${remedy}`
            : `credential is a claustrum tombstone but no handle serves this provider; ${remedy}`);
        logError(error, provider);
        log.info({ provider, state: "orphan" });
        return error;
      };
      for (const [provider, handle] of owned) {
        const freshness = new FreshnessController({
          provider, shape: handle.shape, accounts: handle.accounts, client,
          minTtlMs: dependencies.oauthMinTtlMs, now: dependencies.now,
          handleVersion: () => handleVersionReader(defaultHandleFilePath()), log,
          setInterval: dependencies.setInterval, clearInterval: dependencies.clearInterval,
        });
        controllers.push(freshness);
        const verifyOwnership = async () => {
          let current: OpenCodeHandleFileV1;
          try {
            current = await handleReader(defaultHandleFilePath());
          } catch (error) {
            throw new CustodyOwnershipError(`could not verify custody handle ownership: ${error instanceof Error ? error.name : "unknown error"}`);
          }
          const currentProvider = current.providers.find((candidate) => candidate.provider === provider);
          if (currentProvider?.serve !== OUR_PLUGIN_ID || JSON.stringify(currentProvider) !== JSON.stringify(handle)) {
            throw new CustodyOwnershipError(`custody handle record changed for provider=${provider}; reload OpenCode after bun run enroll -- --oc2 --provider ${provider}`);
          }
        };
        const onServed = (account: ServeAccount, recordVersion: number) => {
          if (announcedProviders.has(provider)) return;
          announcedProviders.add(provider);
          log.info({ provider, label: account.label, credentialId: account.credential_id, recordVersion, state: "served" });
        };
        const split = () => {
          const error = new CustodySplitError(`request for ${provider} carries no claustrum placeholder while custody handles remain; re-run bun run enroll -- --oc2 --provider ${provider} to re-tombstone, or remove the provider from the handle manifest to hand it back to OpenCode`);
          logError(error, provider);
          log.info({ provider, state: "split" });
          return error;
        };
        const select = async () => {
          await verifyOwnership();
          await registry.ensureRedirectSafe({ ...dependencies.redirectProbe, fetch }, log);
          if (disposed) throw new CustodyOwnershipError("serving custody instance was disposed; reload OpenCode");
          for (const account of handle.accounts) {
            if (freshness.state(account) !== "available") continue;
            const served = await freshness.resolve(account);
            if (!served?.material) continue;
            if (served.credentialId !== undefined && served.credentialId !== account.credential_id) {
              log.warn({ provider, label: account.label, boundCredentialId: account.credential_id,
                servedCredentialId: served.credentialId, recordVersion: served.recordVersion, state: "refusing", errorCode: "binding_mismatch" });
              continue;
            }
            if (served.credentialId === undefined && registry.warnMissingCredentialId(account.handle)) {
              log.warn({ provider, label: account.label, boundCredentialId: account.credential_id,
                recordVersion: served.recordVersion, state: "serving", errorCode: "credential_id_absent" });
            }
            if (disposed) throw new CustodyOwnershipError("serving custody instance was disposed; reload OpenCode");
            return { account, served };
          }
          throw exhaustion(provider, handle.accounts.map((account) => ({ account })), freshness);
        };
        requests.set(provider, async (evt) => {
          const marker = sentinel(provider);
          if (containsSentinel(evt.request.url, [], marker)) throw new CustodyPlacementError("url");
          for (const [name, value] of evt.request.headers) {
            if (name !== "authorization" && value.includes(marker)) throw new CustodyPlacementError(name);
          }
          if (!evt.request.headers.get("authorization")?.includes(marker)) throw split();
          // The body is never inspected or substituted: a body placeholder can only reach the wire as a placeholder.
          const { account, served } = await select();
          const headers = new Headers(evt.request.headers);
          headers.set("authorization", headers.get("authorization")!.split(marker).join(served.material));
          evt.request = new Request(evt.request, { headers });
          registry.track(evt.request, { instance, provider, account, recordVersion: served.recordVersion });
          onServed(account, served.recordVersion);
          if (!servingProviders.has(provider)) {
            servingProviders.add(provider);
            log.info({ provider, state: "serving" });
          }
        });
        handshakes.set(provider, async (evt) => {
          if (containsSentinel(evt.url, [], sentinel(provider))) {
            throw new CustodyRequestError("custody placeholder in WebSocket URL refused; credentials may only be substituted in handshake headers");
          }
          if (!Object.values(evt.headers).some((value) => value.includes(sentinel(provider)))) throw split();
          const { account, served } = await select();
          for (const [name, value] of Object.entries(evt.headers)) evt.headers[name] = value.split(sentinel(provider)).join(served.material);
          onServed(account, served.recordVersion);
        });
        responses.set(provider, async (served, evt) => {
          const { account, recordVersion } = served;
          const status = evt.response.status;
          if (status === 401) {
            log.warn({ provider, label: account.label, credentialId: account.credential_id, recordVersion, httpStatus: status });
            try {
              await reportWithinBudget(client.reportAuthFailure({ handle: account.handle, providerStatus: 401, recordVersion, reporterSource: "direct" }),
                (errorClass, errorCode) => log.warn({ provider, label: account.label, credentialId: account.credential_id, errorClass, errorCode }));
            } finally { freshness.invalidate(account); }
          } else if (status === 429 || status === 402) {
            freshness.cooldown(account, status === 402 ? PAYMENT_REQUIRED_COOLDOWN_MS
              : cooldownFromRetryAfter(evt.response.headers.get("Retry-After"), (dependencies.now ?? Date.now)()));
            log.warn({ provider, label: account.label, credentialId: account.credential_id, httpStatus: status });
          }
        });
      }
      const instance: CustodyInstance = {
        id: instanceId, ownership,
        async request(provider, event) {
          const request = requests.get(provider);
          if (!request) throw new CustodyOwnershipError("no serving custody handle for provider");
          await request(event);
        }, async handshake(provider, event) {
          const handshake = handshakes.get(provider);
          if (!handshake) throw new CustodyOwnershipError("no serving custody handle for WebSocket provider");
          await handshake(event);
        },
        async response(served, event) {
          if (disposed) { debugOnce("disposed_response"); return; }
          await responses.get(served.provider)?.(served, event);
        },
      };
      registryRegistration = registry.register(instance);
      const dispatch = async (evt: SessionHttpRequest | SessionWebSocketHandshake) => {
        const provider = evt.model.providerID;
        const target = registry.current;
        const verdict = target?.ownership(provider) ?? "no_instance";
        // Other owners must retain the event claim; every other path claims before inspecting placeholders.
        if (verdict === "other") return;
        if (!registry.claim(evt)) return;
        if (verdict !== "owned") {
          const url = "request" in evt ? evt.request.url : evt.url;
          const values = "request" in evt ? evt.request.headers.values() : Object.values(evt.headers);
          if (containsSentinel(url, values, TOMBSTONE_PREFIX)) throw orphan(provider, verdict);
          return;
        }
        if ("request" in evt) await target!.request(provider, evt);
        else await target!.handshake(provider, evt);
      };
      for (const providerID of owned.keys()) {
        registrations.push(await ctx.session.hook("http.request", dispatch, { providerID }));
        registrations.push(await ctx.session.hook("experimental.ws.handshake", dispatch, { providerID }));
      }
      registrations.push(await ctx.session.hook("http.request", dispatch));
      registrations.push(await ctx.session.hook("experimental.ws.handshake", dispatch));
      registrations.push(await ctx.session.hook("http.response", async (evt) => {
        const served = registry.take(evt.request);
        if (!served || served.provider !== evt.model.providerID) { debugOnce("unmatched_response"); return; }
        await served.instance.response(served, evt);
      }));
      return cleanup;
    } catch (error) {
      try { await cleanup(); } catch { /* Preserve the setup error if teardown also fails. */ }
      throw error;
    }
  };
}
