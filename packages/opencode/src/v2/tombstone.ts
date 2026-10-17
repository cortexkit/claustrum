import { sentinel, TOMBSTONE_PREFIX } from "../tombstone";

// Far-future expiry avoids OC2's five-minute oauth refresh trigger for every provider
// OpenCode 2.0.32 packages/core/src/integration.ts:733-739.
export const V2_TOMBSTONE_EXPIRES = 253402300799000;

export function v2KeyTombstone(provider: string) {
  return { type: "key" as const, key: sentinel(provider) };
}

export function v2OauthTombstone(provider: string, methodID: string) {
  return { type: "oauth" as const, methodID, access: sentinel(provider), refresh: sentinel(provider), expires: V2_TOMBSTONE_EXPIRES };
}

export type V2CredentialClassification = "tombstone" | "v1-migrated" | "drift" | "real" | "invalid";

export function classifyV2Credential(value: unknown, provider: string): V2CredentialClassification {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "invalid";
  const credential = value as Record<string, unknown>;
  const keys = Object.keys(credential);
  const allowed = (base: string[]) => keys.every((key) => base.includes(key) || key === "metadata") &&
    (credential.metadata === undefined || (!!credential.metadata && typeof credential.metadata === "object" && !Array.isArray(credential.metadata)));
  const hasSentinel = Object.values(credential).some((entry) => typeof entry === "string" && entry.startsWith(TOMBSTONE_PREFIX));
  if (credential.type === "key") {
    // A V1 api tombstone migrates to { type: "key", key: sentinel } and classifies as tombstone.
    if (!allowed(["type", "key", "configuration"]) || typeof credential.key !== "string" || (credential.configuration !== undefined && (!credential.configuration || typeof credential.configuration !== "object" || Array.isArray(credential.configuration)))) return hasSentinel ? "drift" : "invalid";
    return credential.key === sentinel(provider) ? "tombstone" : hasSentinel ? "drift" : "real";
  }
  if (credential.type === "oauth") {
    if (credential.access === "" && credential.refresh === sentinel(provider) && credential.expires === 0 && typeof credential.methodID === "string" && allowed(["type", "methodID", "access", "refresh", "expires"])) return "v1-migrated";
    if (!allowed(["type", "methodID", "access", "refresh", "expires"]) || typeof credential.methodID !== "string" || typeof credential.access !== "string" || typeof credential.refresh !== "string" || typeof credential.expires !== "number") return hasSentinel ? "drift" : "invalid";
    const tombstone = credential.access === sentinel(provider) && credential.refresh === sentinel(provider) && credential.expires === V2_TOMBSTONE_EXPIRES;
    return tombstone ? "tombstone" : hasSentinel ? "drift" : "real";
  }
  return hasSentinel ? "drift" : "invalid";
}
