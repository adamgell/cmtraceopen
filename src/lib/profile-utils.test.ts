import { describe, expect, it } from "vitest";
import { deriveFriendlyName, parsePayloadData } from "./profile-utils";

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
  it.each([
    ['"Rules" = (', '  "a', '"', ");"],
    ['"Nested" = {', '  "Filter" = "a', '";', "};"],
  ])("keeps the setting after an escaped physical newline in %s", (open, value, quote, close) => {
    // Transform the existing Rules/Nested fixtures: put a backslash before a
    // physical newline and the closing quote at the beginning of the next line.
    const body = [open, value + "\\", quote, close, '"After" = 2;'].join("\n");

    expect(keys(body)).toContain("After");
    expect(valueOf(body, "After")).toBe("2");
  });

  // Transform the existing Rules array fixture to exercise the same scanner's
  // parenthesis mode, including an escaped quote before the delimiter.
  it.each(["a)b", "a(b", String.raw`a\" ) b`])(
    "keeps the array and following setting with quoted delimiter %s",
    (value) => {
      const body = [
        '  "Rules" = (',
        `    "${value}"`,
        "  );",
        '  "After" = 2;',
      ].join("\n");

      expect(keys(body)).toEqual(["Rules", "After"]);
      expect(valueOf(body, "Rules")).toBe(value);
    },
  );

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

// Retained from the superseded #707 (44f5b651) per the independent review.
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
