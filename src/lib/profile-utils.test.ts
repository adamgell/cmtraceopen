import { describe, expect, it } from "vitest";

import { parsePayloadData } from "./profile-utils";

/**
 * A brace inside a quoted value is data, not structure.
 *
 * These payloads are NeXTSTEP plist text, where a `}` in a filter expression,
 * a regex, or a template placeholder is routine. The block scanner must track
 * quoted regions so the dict around them still parses whole — a truncated
 * payload is worse than a parse error, because the profile simply looks
 * complete with some of its settings absent.
 */
describe("parsePayloadData with braces inside quoted values", () => {
  it("keeps the entries that follow a closing brace inside a quoted value", () => {
    const payload = `"mcx_preference_settings" = {
  "Filter" = "a}b";
  "Enabled" = 1;
};`;

    const { entries } = parsePayloadData(payload);

    expect(entries.map((e) => e.key)).toEqual(["Filter", "Enabled"]);
    expect(entries[0].value).toBe("a}b");
    expect(entries[1].value).toBe("1");
    expect(entries[1].type).toBe("boolean");
  });

  it("keeps the value and the siblings of a nested dict holding a quoted brace", () => {
    const payload = `"mcx_preference_settings" = {
  "Nested" = {
    "Filter" = "x}y";
    "Kept" = "z";
  };
  "After" = "w";
};`;

    const { entries } = parsePayloadData(payload);

    expect(entries.map((e) => e.key)).toEqual([
      "Nested → Filter",
      "Nested → Kept",
      "After",
    ]);
    expect(entries[0].value).toBe("x}y");
    expect(entries[2].value).toBe("w");
  });

  it("treats an escaped quote as part of the string rather than its end", () => {
    const payload = `"mcx_preference_settings" = {
  "Pattern" = "a\\"}b";
  "Enabled" = 1;
};`;

    const { entries } = parsePayloadData(payload);

    expect(entries.map((e) => e.key)).toEqual(["Pattern", "Enabled"]);
    expect(entries[1].type).toBe("boolean");
  });

  it("still parses a balanced brace pair, which never changes depth", () => {
    const payload = `"mcx_preference_settings" = {
  "Url" = "https://x/{0}/r";
  "Enabled" = 1;
};`;

    const { entries } = parsePayloadData(payload);

    expect(entries.map((e) => e.key)).toEqual(["Url", "Enabled"]);
    expect(entries[0].value).toBe("https://x/{0}/r");
  });
});
