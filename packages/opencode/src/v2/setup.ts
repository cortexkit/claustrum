import { randomUUID } from "node:crypto";

import { ClaustrumClient, detectClaustrumConnection } from "@cortexkit/claustrum-client";

import {
  CustodyOrphanError,
  CustodyOwnershipError,
  CustodyRequestError,
  CustodySplitError,
  HandleFileValidationError,
} from "../errors";
import { FreshnessController } from "../freshness";
import { defaultHandleFilePath, handleFileRevision, OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "../handles";
import { createLogger, serializedLogSink } from "../log";
import type { ConfigHookDependencies } from "../plugin";
import { createServeFetch, exhaustion, type ServeAccount, type ServeClient } from "../serve";
import { sentinel, tombstoneFor, TOMBSTONE_PREFIX } from "../tombstone";
import { createUpstreamFetch, getCustodyEndpoint, type CustodyEndpoint } from "./endpoint";
import type { Cleanup, PluginContext, Registration, SessionWebSocketHandshake } from "./host-types";

export type SetupDependencies = Pick<ConfigHookDependencies,
  "handleReader" | "handleVersionReader" | "detect" | "clientFactory" | "fetch" | "logSink" | "log" |
  "now" | "setInterval" | "clearInterval" | "oauthMinTtlMs"
> & { endpoint?: CustodyEndpoint };

const missingCredentialIdWarnings = new Set<string>();

function containsSentinel(url: string, values: Iterable<string>, marker: string): boolean {
  return url.includes(marker) || [...values].some((value) => value.includes(marker));
}

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
    let endpointRegistration: { dispose(): void } | undefined;
    let cleanupPromise: Promise<void> | undefined;
    const cleanup = () => cleanupPromise ??= (async () => {
      try {
        await Promise.all(registrations.map((registration) => registration.dispose()));
      } finally {
        endpointRegistration?.dispose();
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
      const endpoint = dependencies.endpoint ?? getCustodyEndpoint();
      const instanceId = randomUUID();
      const serves = new Map<string, ReturnType<typeof createServeFetch>>();
      const handshakes = new Map<string, (event: SessionWebSocketHandshake) => Promise<void>>();
      const installHooks: Array<() => Promise<void>> = [];
      const announcedProviders = new Set<string>();
      const servingProviders = new Set<string>();
      const orphan = (provider: string, reason: "absent" | "unknown" | "no_instance") => {
        const remedy = `run bun run enroll -- --oc2 --provider ${provider}`;
        const error = new CustodyOrphanError(reason === "no_instance"
          ? "no live claustrum custody instance in this process; reload OpenCode"
          : reason === "unknown"
            ? `handle file unavailable: ${handleError?.message ?? "custody handle ownership is unknown"}; tombstone ownership cannot be proven; ${remedy}`
            : `credential is a claustrum tombstone but no handle serves this provider; ${remedy}`);
        logError(error, provider);
        log.info({ provider, state: "orphan" });
        return error;
      };
      const guard = (provider: string, url: string, values: Iterable<string>) => {
        const verdict = endpoint.current?.ownership(provider) ?? "no_instance";
        if (verdict === "owned" || verdict === "other") return;
        if (containsSentinel(url, values, TOMBSTONE_PREFIX)) throw orphan(provider, verdict);
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
        serves.set(provider, createServeFetch({
          provider, accounts: handle.accounts, client, shape: handle.shape, freshness,
          verifyOwnership,
          readAuthEntry: async () => tombstoneFor(handle.shape, provider),
          upstreamFetch: (input, init) => {
            const signal = init?.signal ?? (input instanceof Request ? input.signal : AbortSignal.any([]));
            return createUpstreamFetch(signal, fetch)(input, init);
          },
          onServed, log,
        }));
        const split = () => {
          const error = new CustodySplitError(`request for ${provider} carries no claustrum placeholder while custody handles remain; re-run bun run enroll -- --oc2 --provider ${provider} to re-tombstone, or remove the provider from the handle manifest to hand it back to OpenCode`);
          logError(error, provider);
          log.info({ provider, state: "split" });
          return error;
        };
        handshakes.set(provider, async (evt) => {
          if (evt.url.includes(sentinel(provider))) {
            throw new CustodyRequestError("custody sentinel in WebSocket URL refused; credentials may only be substituted in handshake headers");
          }
          if (!Object.values(evt.headers).some((value) => value.includes(sentinel(provider)))) throw split();
          await verifyOwnership();
          for (const account of handle.accounts) {
            if (freshness.state(account) !== "available") continue;
            const served = await freshness.resolve(account);
            if (!served?.material) continue;
            if (served.credentialId !== undefined && served.credentialId !== account.credential_id) {
              log.warn({ provider, label: account.label, boundCredentialId: account.credential_id,
                servedCredentialId: served.credentialId, recordVersion: served.recordVersion, state: "refusing", errorCode: "binding_mismatch" });
              continue;
            }
            if (served.credentialId === undefined && !missingCredentialIdWarnings.has(account.handle)) {
              missingCredentialIdWarnings.add(account.handle);
              log.warn({ provider, label: account.label, boundCredentialId: account.credential_id,
                recordVersion: served.recordVersion, state: "serving", errorCode: "credential_id_absent" });
            }
            for (const [name, value] of Object.entries(evt.headers)) {
              evt.headers[name] = value.split(sentinel(provider)).join(served.material);
            }
            onServed(account, served.recordVersion);
            return;
          }
          throw exhaustion(provider, handle.accounts.map((account) => ({ account })), freshness);
        });
        installHooks.push(async () => {
          registrations.push(await ctx.session.hook("http.request", (evt) => {
            if (endpoint.isEndpointUrl(evt.request.url)) return;
            const verdict = endpoint.current?.ownership(provider) ?? "no_instance";
            if (verdict === "other") return;
            if (verdict !== "owned") throw orphan(provider, verdict);
            if (!containsSentinel(evt.request.url, evt.request.headers.values(), sentinel(provider))) throw split();
            evt.request = endpoint.route(provider, evt.request);
            if (servingProviders.has(provider)) return;
            servingProviders.add(provider);
            log.info({ provider, state: "serving" });
          }, { providerID: provider }));
          registrations.push(await ctx.session.hook("experimental.ws.handshake", async (evt) => {
            // Stale hooks must leave other owners' events unclaimed for their serving plugin.
            const target = endpoint.current;
            if (!target) throw orphan(provider, "no_instance");
            const verdict = target.ownership(provider);
            if (verdict === "other") return;
            if (verdict !== "owned") throw orphan(provider, verdict);
            if (!endpoint.claimHandshake(evt)) return;
            await target.handshake(provider, evt);
          }, { providerID: provider }));
        });
      }
      endpointRegistration = endpoint.register({
        id: instanceId, ownership,
        async serve(provider, request, signal) {
          const serve = serves.get(provider);
          if (!serve) throw new CustodyOwnershipError("no serving custody handle for provider");
          return serve(new Request(request, { signal }));
        }, async handshake(provider, event) {
          const handshake = handshakes.get(provider);
          if (!handshake) throw new CustodyOwnershipError("no serving custody handle for WebSocket provider");
          await handshake(event);
        },
      });
      for (const install of installHooks) await install();
      registrations.push(await ctx.session.hook("http.request", (evt) => {
        guard(evt.model.providerID, evt.request.url, evt.request.headers.values());
      }));
      registrations.push(await ctx.session.hook("experimental.ws.handshake", (evt) => {
        guard(evt.model.providerID, evt.url, Object.values(evt.headers));
      }));
      return cleanup;
    } catch (error) {
      try { await cleanup(); } catch { /* Preserve the setup error if teardown also fails. */ }
      throw error;
    }
  };
}
