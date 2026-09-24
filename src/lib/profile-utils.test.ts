import { describe, expect, it } from "vitest";
import { deriveFriendlyName, parsePayloadData } from "./profile-utils";

const wrap = (inner: string) => `{
  "com.example.app" = {
    "mcx_preference_settings" =     {
${inner}
      "Enabled" = 1;
    };
  };
}`;

const keysOf = (mdm: string) =>
  parsePayloadData(wrap(mdm))
    .entries.map((e) => e.key)
    .sort();

describe("parsePayloadData brace handling", () => {
  it("reads the whole block when no value contains a brace", () => {
    expect(keysOf(`      "Filter" = "plain";`)).toEqual(["Enabled", "Filter"]);
  });

  it("keeps every entry when a value holds a balanced brace pair", () => {
    // The control: a balanced pair leaves the depth where it started, so this
    // passes against the old counter too. Kept to pin the ordinary case.
    expect(keysOf(`      "URLTemplate" = "https://x.invalid/{0}/r";`)).toEqual([
      "Enabled",
      "URLTemplate",
    ]);
  });

  it("does not truncate on a lone closing brace inside a value", () => {
    // Previously this returned ['Filter'] and silently dropped 'Enabled'.
    expect(keysOf(`      "Filter" = "a}b";`)).toEqual(["Enabled", "Filter"]);
  });

  it("does not swallow the rest on a lone opening brace inside a value", () => {
    expect(keysOf(`      "Pattern" = "a{b";`)).toEqual(["Enabled", "Pattern"]);
  });

  it("treats an escaped quote as content, not as the end of the value", () => {
    // An escaped quote must not close the string, or the scanner would treat
    // the braces after it as structure again.
    expect(keysOf(`      "Note" = "say \\" then } brace";`)).toEqual(["Enabled", "Note"]);
  });
});

describe("parsePayloadData app target", () => {
  it("extracts the bundle identifier from the MCX block", () => {
    expect(parsePayloadData(wrap(`      "Filter" = "a";`)).appTarget).toBe("com.example.app");
  });

  it("still reads a payload with no MCX block", () => {
    const parsed = parsePayloadData(`{ "Standalone" = "1"; }`);
    expect(parsed.entries.map((e) => e.key)).toContain("Standalone");
  });
});

describe("deriveFriendlyName", () => {
  it("returns null for a profile that is not a ManagedClient preference", () => {
    expect(
      deriveFriendlyName({ profileIdentifier: "com.example.unrelated" } as never),
    ).toBeNull();
  });
});
