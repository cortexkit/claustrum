import { CustodyRedirectUnsafeError } from "../errors";
import type { CustodyLogger } from "../log";
import type { ServeAccount } from "../serve";
import type { SessionHttpRequest, SessionHttpResponse, SessionWebSocketHandshake } from "./host-types";
import { checkRedirectSafety, type RedirectProbeDependencies, type RedirectProbeResult } from "./redirect-self-test";

export type Ownership = "owned" | "other" | "absent" | "unknown";
export type ServedRequest = { instance: CustodyInstance; provider: string; account: ServeAccount; recordVersion: number };
export type CustodyInstance = {
  readonly id: string;
  ownership(provider: string): Ownership;
  request(provider: string, event: SessionHttpRequest): Promise<void>;
  handshake(provider: string, event: SessionWebSocketHandshake): Promise<void>;
  response(served: ServedRequest, event: SessionHttpResponse): Promise<void>;
};

const HOLDER_KEY = Symbol.for("cortexkit.claustrum.custody.inplace.v2/1");
const holders = globalThis as typeof globalThis & { [HOLDER_KEY]?: CustodyRegistry };

export class CustodyRegistry {
  readonly #instances: CustodyInstance[] = [];
  readonly #claimed = new WeakSet<object>();
  readonly #served = new WeakMap<Request, ServedRequest>();
  readonly #missingCredentialIds = new Set<string>();
  #probe: Promise<RedirectProbeResult> | undefined;
  #unsafeLogged = false;

  get current(): CustodyInstance | undefined { return this.#instances.at(-1); }

  register(instance: CustodyInstance): { dispose(): void } {
    this.#instances.push(instance);
    return { dispose: () => {
      const index = this.#instances.lastIndexOf(instance);
      if (index >= 0) this.#instances.splice(index, 1);
    } };
  }

  claim(event: object): boolean {
    if (this.#claimed.has(event)) return false;
    this.#claimed.add(event);
    return true;
  }

  track(request: Request, served: ServedRequest): void { this.#served.set(request, served); }

  take(request: Request): ServedRequest | undefined {
    const served = this.#served.get(request);
    this.#served.delete(request);
    return served;
  }

  warnMissingCredentialId(handle: string): boolean {
    if (this.#missingCredentialIds.has(handle)) return false;
    this.#missingCredentialIds.add(handle);
    return true;
  }

  async ensureRedirectSafe(dependencies: RedirectProbeDependencies, log: CustodyLogger): Promise<void> {
    this.#probe ??= checkRedirectSafety(dependencies);
    const result = await this.#probe;
    if (result.safe) return;
    const error = new CustodyRedirectUnsafeError(result.status);
    if (!this.#unsafeLogged) {
      this.#unsafeLogged = true;
      log.error({ errorClass: error.name, errorCode: typeof result.status === "number" ? "redirect_unsafe" : result.status,
        ...(typeof result.status === "number" ? { httpStatus: result.status } : {}), errorMessage: error.message });
    }
    throw error;
  }
}

export function getCustodyRegistry(): CustodyRegistry { return holders[HOLDER_KEY] ??= new CustodyRegistry(); }

export function resetCustodyRegistryForTests(): void { delete holders[HOLDER_KEY]; }
