import { randomUUID } from "node:crypto";

import { ClaustrumClient, detectClaustrumConnection } from "@cortexkit/claustrum-client";

import {
  CustodyOrphanError,
  CustodyOwnershipError,
  CustodyRequestError,
  CustodySplitError,
  CustodyWarmTimeoutError,
  HandleFileValidationError,
  ReportedCustodyExhaustionError,
} from "../errors";
import { FreshnessController } from "../freshness";
import { defaultHandleFilePath, handleFileRevision, OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "../handles";
import { createLogger, serializedLogSink } from "../log";
import type { ConfigHookDependencies } from "../plugin";
import { createServeFetch, type ServeAccount, type ServeClient } from "../serve";
import { sentinel, tombstoneFor, TOMBSTONE_PREFIX } from "../tombstone";
import { getCustodyEndpoint, type CustodyEndpoint } from "./endpoint";
import type { Cleanup, PluginContext, Registration } from "./host-types";

export type SetupDependencies = Pick<ConfigHookDependencies,
  "handleReader" | "handleVersionReader" | "detect" | "clientFactory" | "fetch" | "logSink" | "log" |
  "now" | "setInterval" | "clearInterval" | "oauthMinTtlMs"
> & { endpoint?: CustodyEndpoint };

type BunRequestInit = RequestInit & { timeout: false };

function containsSentinel(url: string, values: Iterable<string>, marker: string): boolean {
  return url.includes(marker) || [...values].some((value) => value.includes(marker));
}

// serve.ts keeps exhaustion private; WS must retain its typed snapshots without
// changing the V1 module or invoking an HTTP attempt just to construct an error.
function exhaustion(provider: string, accounts: ServeAccount[], freshness: FreshnessController) {
  const accountStates = accounts.map((account) => ({
    label: account.label, state: freshness.state(account), warmTimedOut: freshness.warmTimedOut(account),
  }));
  const states = accountStates.map((snapshot) => `${snapshot.label}:${snapshot.state}`).join(", ");
  const anyGone = accountStates.some((snapshot) => snapshot.state === "gone");
  if (accountStates.length > 0 && accountStates.every((snapshot) => snapshot.warmTimedOut)) {
    return new CustodyWarmTimeoutError(`custody credential warm timed out: provider=${provider} accounts=${states}`, accountStates);
  }
  const migrate = anyGone ? "; run ck auth migrate-opencode for gone handles" : "";
  return new ReportedCustodyExhaustionError(
    `custody accounts exhausted: provider=${provider} accounts=${states}${migrate}`, accountStates, anyGone,
  );
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
      log.warn({
        errorCode: "custody_disabled",
        errorMessage: "Custody is deliberately off; any tombstoned provider WILL FAIL with a 401 while CLAUSTRUM_CUSTODY_DISABLE=1 sends the tombstone to the wire as the key. Real credentials return only via enroll --remove or unsetting the switch.",
      });
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
      const endpoint = handles ? dependencies.endpoint ?? getCustodyEndpoint() : undefined;
      const instanceId = randomUUID();
      const serves = new Map<string, ReturnType<typeof createServeFetch>>();
      const installHooks: Array<() => Promise<void>> = [];
      const announcedProviders = new Set<string>();
      const servingProviders = new Set<string>();
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
            throw new CustodyOwnershipError(`custody handle record changed for provider=${provider}; reload OpenCode after bun run enroll -- --oc2`);
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
            const options: BunRequestInit = { ...init, timeout: false };
            return fetch(input, options);
          },
          onServed, log,
        }));
        const split = () => {
          const error = new CustodySplitError(`local credential is real while custody handles remain; re-run bun run enroll -- --oc2 --provider ${provider} to re-tombstone, or remove the provider from the handle manifest to hand it back to OpenCode`);
          logError(error, provider);
          log.info({ provider, state: "split" });
          return error;
        };
        installHooks.push(async () => {
          registrations.push(await ctx.session.hook("http.request", (evt) => {
            if (endpoint!.isEndpointUrl(evt.request.url)) return;
            if (!containsSentinel(evt.request.url, evt.request.headers.values(), sentinel(provider))) throw split();
            evt.request = endpoint!.route(provider, evt.request);
            if (servingProviders.has(provider)) return;
            servingProviders.add(provider);
            log.info({ provider, state: "serving" });
          }, { providerID: provider }));
          registrations.push(await ctx.session.hook("experimental.ws.handshake", async (evt) => {
            if (endpoint!.current?.id !== instanceId) return;
            if (evt.url.includes(sentinel(provider))) {
              throw new CustodyRequestError("custody sentinel in WebSocket URL refused; credentials may only be substituted in handshake headers");
            }
            if (!Object.values(evt.headers).some((value) => value.includes(sentinel(provider)))) throw split();
            await verifyOwnership();
            for (const account of handle.accounts) {
              if (freshness.state(account) !== "available") continue;
              const served = await freshness.resolve(account);
              if (endpoint!.current?.id !== instanceId) return;
              if (!served?.material) continue;
              if (served.credentialId !== undefined && served.credentialId !== account.credential_id) {
                log.warn({ provider, label: account.label, boundCredentialId: account.credential_id,
                  servedCredentialId: served.credentialId, recordVersion: served.recordVersion, state: "refusing", errorCode: "binding_mismatch" });
                continue;
              }
              for (const [name, value] of Object.entries(evt.headers)) {
                evt.headers[name] = value.split(sentinel(provider)).join(served.material);
              }
              onServed(account, served.recordVersion);
              return;
            }
            throw exhaustion(provider, handle.accounts, freshness);
          }, { providerID: provider }));
        });
      }
      if (endpoint) {
        endpointRegistration = endpoint.register({ id: instanceId, async serve(provider, request, signal) {
          const serve = serves.get(provider);
          if (!serve) throw new CustodyOwnershipError("no serving custody handle for provider");
          return serve(new Request(request, { signal }));
        } });
      }
      for (const install of installHooks) await install();
      registrations.push(await ctx.session.hook("http.request", (evt) => {
        if (owned.has(evt.model.providerID)) return;
        if (!containsSentinel(evt.request.url, evt.request.headers.values(), TOMBSTONE_PREFIX)) return;
        const error = new CustodyOrphanError(handleError
          ? `handle file unavailable: ${handleError.message}; tombstone ownership cannot be proven; run enroll`
          : "credential is a claustrum tombstone but no handle serves this provider; run enroll");
        logError(error, evt.model.providerID);
        log.info({ provider: evt.model.providerID, state: "orphan" });
        throw error;
      }));
      return cleanup;
    } catch (error) {
      await cleanup();
      throw error;
    }
  };
}
