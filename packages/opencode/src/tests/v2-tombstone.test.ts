import { describe, expect, test } from "bun:test";
import { classifyV2Credential, V2_TOMBSTONE_EXPIRES, v2KeyTombstone, v2OauthTombstone } from "../v2/tombstone";
import { sentinel } from "../tombstone";

describe("V2 credential tombstones", () => {
  const provider = "xai";
  test("builders emit exact shapes", () => {
    expect(v2KeyTombstone(provider)).toEqual({ type: "key", key: sentinel(provider) });
    expect(v2OauthTombstone(provider, "oauth")).toEqual({ type: "oauth", methodID: "oauth", access: sentinel(provider), refresh: sentinel(provider), expires: V2_TOMBSTONE_EXPIRES });
  });
  test("classifies tombstones, migrated values, drift, real values and invalid inputs", () => {
    expect(classifyV2Credential(v2KeyTombstone(provider), provider)).toBe("tombstone");
    expect(classifyV2Credential(v2OauthTombstone(provider, "m"), provider)).toBe("tombstone");
    expect(classifyV2Credential({ type: "oauth", methodID: "m", access: "", refresh: sentinel(provider), expires: 0 }, provider)).toBe("v1-migrated");
    expect(classifyV2Credential({ type: "key", key: sentinel("other") }, provider)).toBe("drift");
    expect(classifyV2Credential({ ...v2KeyTombstone(provider), extra: true }, provider)).toBe("drift");
    expect(classifyV2Credential({ ...v2KeyTombstone(provider), metadata: {} }, provider)).toBe("tombstone");
    expect(classifyV2Credential({ type: "key", key: "real" }, provider)).toBe("real");
    expect(classifyV2Credential({ type: "oauth", methodID: "m", access: "a", refresh: "r", expires: 1 }, provider)).toBe("real");
    expect(classifyV2Credential({ type: "oauth", access: sentinel(provider) }, provider)).toBe("drift");
    expect(classifyV2Credential(null, provider)).toBe("invalid");
  });
  test("OAuth expiry remains beyond refresh threshold", () => {
    expect(V2_TOMBSTONE_EXPIRES).toBe(Date.UTC(9999, 11, 31, 23, 59, 59));
    expect(V2_TOMBSTONE_EXPIRES).toBeGreaterThan(Date.now() + 5 * 60_000);
    expect(v2OauthTombstone(provider, "m").expires).toBeGreaterThan(Date.now() + 5 * 60_000);
  });
  test("key configuration accepts objects only and does not loosen OAuth or unknown fields", () => {
    for (const configuration of [{}, { region: "eu", nested: { enabled: true }, names: ["a"] }]) expect(classifyV2Credential({ ...v2KeyTombstone(provider), configuration }, provider)).toBe("tombstone");
    for (const configuration of [null, [], "secret", 1, false]) expect(classifyV2Credential({ ...v2KeyTombstone(provider), configuration }, provider)).toBe("drift");
    expect(classifyV2Credential({ ...v2OauthTombstone(provider, "m"), configuration: {} }, provider)).toBe("drift");
    expect(classifyV2Credential({ ...v2KeyTombstone(provider), configuration: {}, extra: true }, provider)).toBe("drift");
  });
  test("review 7: a foreign V1 OAuth sentinel is drift, not migrated custody", () => {
    expect(classifyV2Credential({ type: "oauth", methodID: "m", access: "", refresh: sentinel("other"), expires: 0 }, "xai")).toBe("drift");
  });
});
