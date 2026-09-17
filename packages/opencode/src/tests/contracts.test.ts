import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { GoldenTombstone } from "../contracts";
import { carriesSentinel, isProviderTombstone, sentinel, TOMBSTONE_PREFIX, tombstoneFor } from "../tombstone";
import { parseHandleFile } from "../handles";
import goldenHandles from "../../golden/handles.json";
import goldenTombstoneJson from "../../golden/tombstone.json";

const goldenTombstone = goldenTombstoneJson as GoldenTombstone;
const validHandle = `ckh_${"a".repeat(43)}`;

function manifestWithCredential(provider: string, label: string, credentialId: string) {
  return {
    version: 1,
    providers: [{
      provider,
      shape: "api",
      serve: "opencode-claustrum",
      accounts: [{ label, handle: validHandle, credential_id: credentialId }],
    }],
  };
}

describe("custody wire contracts", () => {
  test("loads the canonical tombstone golden rather than a copied fixture", () => {
    expect(goldenTombstone).toEqual(JSON.parse(readFileSync(join(import.meta.dir, "../../golden/tombstone.json"), "utf8")));
  });
  test("api golden stays a valid OpenCode ApiAuth entry", () => {
    const fixture = goldenTombstone.fixtures.api;
    expect(fixture.entry.type).toBe("api");
    expect(isProviderTombstone(fixture.entry, fixture.provider)).toBe(true);
  });

  test("oauth golden stays a valid OpenCode OAuth entry", () => {
    const fixture = goldenTombstone.fixtures.oauth;
    expect(fixture.entry.type).toBe("oauth");
    expect(isProviderTombstone(fixture.entry, fixture.provider)).toBe(true);
  });

  // The sentinel-access variant has never been written by this repo or by any tenant, so it is not
  // a legacy form to tolerate -- it is an anomaly, and recognition stays exactly as wide as the
  // written shape. Refusal is deliberately wider: `carriesSentinel` still claims it, so an entry
  // like this reaches a refusal rather than being ignored. Widen recognition only when a real
  // artifact turns up on disk, with the artifact as the evidence.
  test("an unwritten sentinel-access variant is refused, not recognized", () => {
    const fixture = goldenTombstone.fixtures.oauth;
    const sentinelAccess = { ...fixture.entry, access: sentinel(fixture.provider) };
    expect(isProviderTombstone(sentinelAccess, fixture.provider)).toBe(false);
    expect(carriesSentinel(sentinelAccess)).toBe(true);
  });

  test("tombstone rendering is byte-stable for a provider", () => {
    const api = goldenTombstone.fixtures.api;
    const oauth = goldenTombstone.fixtures.oauth;
    expect(tombstoneFor("api", api.provider)).toEqual(api.entry);
    expect(tombstoneFor("oauth", oauth.provider)).toEqual(oauth.entry);
    expect(isProviderTombstone(tombstoneFor("api", "deepseek"), "anthropic")).toBe(false);
  });

  test("oauth tombstone key-count fence rejects extra fields", () => {
    const fixture = goldenTombstone.fixtures.oauth;
    expect(isProviderTombstone({ ...fixture.entry, source: "extra" }, fixture.provider)).toBe(false);
  });

  test("oauth tombstone remains scoped to its provider", () => {
    const fixture = goldenTombstone.fixtures.oauth;
    expect(isProviderTombstone({ ...fixture.entry, refresh: TOMBSTONE_PREFIX + "different-provider" }, fixture.provider)).toBe(false);
  });

  test("tombstone prefix remains pinned to the golden provider key", () => {
    const fixture = goldenTombstone.fixtures.api;
    if (fixture.entry.type !== "api") throw new Error("api golden changed shape");
    expect(TOMBSTONE_PREFIX + fixture.provider).toBe(fixture.entry.key);
  });

  test("handle schema preserves declared provider and account order", () => {
    const source = parseHandleFile(goldenHandles);
    const parsed = parseHandleFile(JSON.parse(JSON.stringify(source)));
    expect(parsed).toEqual(source);
    expect(parsed.providers.map((provider) => provider.provider)).toEqual(["deepseek", "anthropic"]);
    expect(parsed.providers[0]?.accounts.map((account) => account.label)).toEqual(["main", "backup"]);
    // The golden carries base64url-shaped handles (mixed case, `-`, `_`) on purpose: the vault
    // mints 256 CSPRNG bits as base64url, and a reader that derives its charset from an
    // all-lowercase fixture would reject real handles.
    expect(parsed.providers[0]?.accounts[0]?.handle).toBe("ckh_xOHjn5GYlYiTcwEqIt0DDVGaZR3eTdcwzpOEXuTdvsw");
    expect(parsed.providers[0]?.accounts[1]?.superseded).toEqual(["ckh_MNZO_t_aIvzhQ19mAskh44KtKxJE5NbOm4ul6A1kqpY"]);
    for (const provider of parsed.providers) {
      for (const account of provider.accounts) {
        for (const handle of [account.handle, ...(account.superseded ?? [])]) {
          expect(handle).toMatch(/^ckh_[A-Za-z0-9_-]{43}$/);
        }
      }
    }
    expect(goldenHandles.providers.flatMap((p) => p.accounts.map((a) => a.handle)).join("")).toMatch(/[A-Z]/);
    expect(goldenHandles.providers.flatMap((p) => p.accounts.map((a) => a.handle)).join("")).toMatch(/[-_]/);
    expect(() =>
      parseHandleFile({
        version: 1,
        providers: [{ provider: "deepseek", shape: "api", serve: "opencode-claustrum", accounts: [] }],
      }),
    ).toThrow("accounts");
    expect(() =>
      parseHandleFile({
        version: 1,
        providers: [{
          provider: "deepseek",
          shape: "api",
          serve: "opencode-claustrum",
          accounts: [{ label: "main", handle: `ckh_${"a".repeat(42)}!`, credential_id: "apikey:deepseek:main" }],
        }],
      }),
    ).toThrow("invalid handle");
  });

  // Discriminator: an oauth-only kind rule rejects this live OpenAI shape, so it cannot prove provider scoping.
  test("accepts chatgpt:openai for the openai provider", () => {
    expect(() => parseHandleFile(manifestWithCredential("openai", "main", "chatgpt:openai"))).not.toThrow();
  });

  // Discriminator: an oauth-only kind rule rejects this live Google shape, so it cannot prove provider scoping.
  test("accepts antigravity:google for the google provider", () => {
    expect(() => parseHandleFile(manifestWithCredential("google", "main", "antigravity:google"))).not.toThrow();
  });

  test("accepts a provider-scoped id whose label does not match the account label", () => {
    expect(() =>
      parseHandleFile(manifestWithCredential("anthropic", "work-alt", "oauth:anthropic:something-else")),
    ).not.toThrow();
  });

  test("rejects a credential id scoped to another provider", () => {
    expect(() => parseHandleFile(manifestWithCredential("anthropic", "main", "chatgpt:openai"))).toThrow("credential id");
  });

  test("accepts the existing apikey provider-scoped live shape", () => {
    expect(() => parseHandleFile(manifestWithCredential("deepseek", "main", "apikey:deepseek:main"))).not.toThrow();
  });

  test("accepts the existing unlabelled oauth provider-scoped live shape", () => {
    expect(() => parseHandleFile(manifestWithCredential("anthropic", "main", "oauth:anthropic"))).not.toThrow();
  });

  test("rejects a credential id without a provider segment", () => {
    expect(() => parseHandleFile(manifestWithCredential("anthropic", "main", "oauth"))).toThrow("credential id");
  });

  // Both of these satisfy "segment 2 is the provider" literally, so a position-1 check
  // alone accepts them -- and both name credentials that cannot exist, deferring a
  // guaranteed resolve-time failure past the door. They also fixed an asymmetry that
  // read as a bug: `oauth::anthropic` rejected (empty at position 1) while these passed
  // (empty at positions 0 and 2). Agreed with the anthropic-auth tenant and mirrored
  // there, so the rule is chosen on both sides rather than defaulted on either.
  test("rejects a credential id with an empty kind segment", () => {
    expect(() => parseHandleFile(manifestWithCredential("anthropic", "main", ":anthropic:x"))).toThrow("credential id");
  });

  test("rejects a credential id with an empty label segment", () => {
    expect(() => parseHandleFile(manifestWithCredential("anthropic", "main", "oauth:anthropic:"))).toThrow(
      "credential id",
    );
  });

  test("rejects a credential id with an empty provider segment", () => {
    expect(() => parseHandleFile(manifestWithCredential("anthropic", "main", "oauth::main"))).toThrow("credential id");
  });

  test("rejects a credential id whose provider segment differs only by case", () => {
    expect(() => parseHandleFile(manifestWithCredential("anthropic", "main", "oauth:Anthropic:main"))).toThrow("credential id");
  });
});
