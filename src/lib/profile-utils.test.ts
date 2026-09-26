import { describe, expect, it } from "vitest";
import { parsePayloadData } from "./profile-utils";

/** Wrap a dict body the way a ManagedClient.preferences payload carries it. */
function mcxPayload(body: string): string {
  return `"mcx_preference_settings" = {\n${body}\n};`;
}

function keys(body: string): string[] {
  return parsePayloadData(mcxPayload(body)).entries.map((e) => e.key);
}

function valueOf(body: string, key: string): string | undefined {
  return parsePayloadData(mcxPayload(body)).entries.find((e) => e.key === key)
    ?.value;
}

describe("parsePayloadData brace scanning", () => {
  // The case from #706: a lone closing brace inside a quoted value used to end
  // the block, and every setting after it was dropped without a word.
  it("keeps the settings that follow a brace inside a quoted value", () => {
    const body = [
      '  "Filter" = "a}b";',
      '  "Enabled" = 1;',
      '  "Level" = 2;',
    ].join("\n");

    expect(keys(body)).toEqual(["Filter", "Enabled", "Level"]);
  });

  it("keeps the settings that follow a brace inside a nested dict value", () => {
    const body = [
      '  "Nested" = {',
      '    "Filter" = "a}b";',
      '    "Inner" = 1;',
      "  };",
      '  "After" = 2;',
    ].join("\n");

    const parsed = keys(body);

    expect(parsed.some((k) => k.startsWith("Nested") && k.includes("Inner"))).toBe(
      true,
    );
    expect(parsed).toContain("After");
  });

  it("keeps a value holding an escaped quote and a brace", () => {
    const body = ['  "Note" = "say \\"hi\\" }";', '  "Enabled" = 1;'].join(
      "\n",
    );

    expect(keys(body)).toEqual(["Note", "Enabled"]);
    expect(valueOf(body, "Note")).toContain('\\"hi\\"');
  });

  it("keeps every dict of an array when an earlier value holds a brace", () => {
    const body = [
      '  "Rules" = (',
      "    {",
      '      "Comment" = "a}b";',
      '      "RuleType" = 1;',
      "    },",
      "    {",
      '      "Comment" = "second";',
      '      "RuleType" = 2;',
      "    }",
      "  );",
    ].join("\n");

    const parsed = keys(body);

    // The first dict's value must not swallow the second dict.
    expect(parsed.filter((k) => k.endsWith("RuleType")).length).toBe(2);
    expect(parsed.some((k) => k.includes("second"))).toBe(true);
  });

  it("parses a single-line array value that is the last line of the payload", () => {
    // The top-level path trims the outer braces, so this array's line is the
    // last one and its block closes without a trailing newline. A reader that
    // counts lines by the newline after the close consumed nothing and read the
    // same line again.
    const parsed = parsePayloadData('{ "Rules" = (1); }').entries;

    expect(parsed.map((e) => e.key)).toEqual(["Rules"]);
  });

  // Balanced braces inside a value were already harmless - the depth returns to
  // where it started - so this is the control that has to keep passing.
  it("reads a balanced brace placeholder as part of the value", () => {
    const body = [
      '  "Url" = "https://x/{0}/r";',
      '  "Enabled" = 1;',
    ].join("\n");

    expect(keys(body)).toEqual(["Url", "Enabled"]);
    expect(valueOf(body, "Url")).toContain("{0}");
  });

  it("still parses a nested dict that holds no brace in its values", () => {
    const body = [
      '  "Nested" = {',
      '    "Inner" = "plain";',
      "  };",
      '  "After" = 2;',
    ].join("\n");

    const parsed = keys(body);

    expect(parsed.some((k) => k.startsWith("Nested") && k.includes("Inner"))).toBe(
      true,
    );
    expect(parsed).toContain("After");
  });
});
