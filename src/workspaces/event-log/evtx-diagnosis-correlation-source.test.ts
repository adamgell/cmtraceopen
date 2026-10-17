/**
 * #838 ruling 1: no correlation count or row anywhere in the UI may come from the diagnosis
 * summary (`DiagnosisSummary.correlations`, `overview.correlationCount`). The Correlations card and
 * the Correlation view, built from the timeline's edges, are the correlation surfaces.
 *
 * The rule predates the Correlation view and was broken in a second place (the diagnosis details
 * disclosure) after the first was fixed, so it is enforced by reading the sources.
 *
 * WHAT IT CHECKS. In every non-test source file of src/ except the two wire files, with comments
 * removed, none of these appears:
 * - property access: `.correlations` and `?.correlations`;
 * - bracket access: `["correlations"]`, `['correlations']`, and the same in a template literal;
 * - destructuring: `correlations` in an object pattern, in a declaration
 *   (`const { correlations } = summary`, `const { correlations: edges } = ...`) or in a function
 *   parameter (`function f({ correlations })`, `({ correlations }) => ...`);
 * - the field `correlationCount` anywhere (a word, so `correlationCounts` is another name);
 * - `CorrelationRow` and `DiagnosisCorrelationEdge`, the diagnosis row component and its type.
 *
 * WHAT IT DOES NOT CHECK (text-scan limits, no more than that):
 * - a helper that reads the fields added INSIDE one of the two wire files, which are exempt whole;
 * - a read through a dynamic key (`summary[key]`) or through an alias of the summary's type;
 * - code after a `//` inside a string or a regular expression on the same line, which the comment
 *   stripper removes with the comment;
 * - the wrong count coming from somewhere else: this keeps the diagnosis summary out, and says
 *   nothing about the timeline's own edge totals (see the UnifiedTimelineView tests).
 * The wire type and its decoder are the two places that must name the fields (the backend still
 * sends them), and are listed.
 */
import { describe, expect, it } from "vitest";

const sources = import.meta.glob("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** The wire shape and its decoder: they describe what the backend sends, they do not show it. */
const WIRE = new Set(["/src/lib/commands.ts", "/src/workspaces/event-log/types.ts"]);

const isTestCode = (path: string) =>
  /\.test\.(ts|tsx)$/.test(path) ||
  /(^|\/)(__fixtures__|test-utils)\//.test(path) ||
  /test-fixtures\.ts$|test-setup\.ts$/.test(path);

/** Comments may name the rule. Code may not break it. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

/** `correlations` as a name bound by an object pattern: a declaration or a function parameter. */
const DESTRUCTURED_CORRELATIONS = [
  /\b(?:const|let|var)\s*\{[^{}]*\bcorrelations\b[^{}]*\}\s*(?::[^=]+)?(?:=|\bof\b|\bin\b)/,
  /\bfunction\s*\w*\s*\(\s*\{[^{}]*\bcorrelations\b[^{}]*\}/,
  /\(\s*\{[^{}]*\bcorrelations\b[^{}]*\}\s*(?::[^=)]+)?\)\s*(?::[^=]+)?=>/,
];

/** `correlations` read by a computed key whose key is the literal string. */
const BRACKET_CORRELATIONS = /\[\s*["'`]correlations["'`]\s*\]/;

const FORBIDDEN: [string, RegExp][] = [
  ["the summary's correlation rows (.correlations)", /\.correlations\b/],
  ["the summary's correlation rows by bracket (['correlations'])", BRACKET_CORRELATIONS],
  ["the summary's correlation rows by destructuring ({ correlations })", new RegExp(DESTRUCTURED_CORRELATIONS.map((r) => r.source).join("|"))],
  ["the overview's correlation total (correlationCount)", /\bcorrelationCount\b/],
  ["the diagnosis correlation row component (CorrelationRow)", /\bCorrelationRow\b/],
  ["the diagnosis correlation edge type (DiagnosisCorrelationEdge)", /\bDiagnosisCorrelationEdge\b/],
];

describe("no UI reads the diagnosis summary's correlations (#838 ruling 1)", () => {
  const ui = Object.entries(sources).filter(([path]) => !isTestCode(path) && !WIRE.has(path));

  it("scans the UI sources, so the scan is not vacuous", () => {
    expect(ui.length).toBeGreaterThan(100);
    expect(ui.map(([path]) => path)).toEqual(
      expect.arrayContaining([
        "/src/workspaces/event-log/EventDiagnosisPanel.tsx",
        "/src/workspaces/event-log/EvtxCorrelationView.tsx",
        "/src/workspaces/event-log/UnifiedTimelineView.tsx",
      ]),
    );
    expect(WIRE.size).toBe(2);
    for (const path of WIRE) expect(Object.keys(sources), path).toContain(path);
  });

  it.each(FORBIDDEN)("names %s nowhere in a UI file", (_what, pattern) => {
    const offenders = ui
      .filter(([, text]) => pattern.test(withoutComments(text)))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });

  it("still finds the fields where they belong, so a rename cannot hide a reader", () => {
    const wire = [...WIRE].map((path) => withoutComments(sources[path] ?? "")).join("\n");
    expect(wire).toMatch(/\bcorrelationCount\b/);
    expect(wire).toMatch(/\bDiagnosisCorrelationEdge\b/);
  });

  describe("the patterns themselves", () => {
    const hits = (code: string) => FORBIDDEN.filter(([, pattern]) => pattern.test(code)).map(([what]) => what);

    it.each([
      ["a declaration", "const { correlations } = summary;"],
      ["a declaration with other fields", "const { findings, correlations, overview } = summary;"],
      ["a renamed declaration", "const { correlations: edges } = summary;"],
      ["a declaration of a nested summary", "let { correlations } = state.diagnosis;"],
      ["a loop over summaries", "for (const { correlations } of summaries) use(correlations);"],
      ["a function parameter", "function show({ correlations }: Summary) { return correlations; }"],
      ["an arrow function parameter", "const rows = ({ correlations, overview }) => correlations;"],
      ["a typed arrow function parameter", "const rows = ({ correlations }: Pick<Summary, 'correlations'>): Row[] => [];"],
    ])("sees the field destructured in %s", (_why, code) => {
      expect(hits(code).some((what) => what.includes("destructuring"))).toBe(true);
    });

    it.each([
      ["single quotes", "const rows = summary['correlations'];"],
      ["double quotes", 'const rows = summary["correlations"];'],
      ["a template literal", "const rows = summary[`correlations`];"],
      ["with spaces", 'const rows = summary[ "correlations" ];'],
    ])("sees the field read by bracket with %s", (_why, code) => {
      expect(hits(code).some((what) => what.includes("bracket"))).toBe(true);
    });

    it.each([
      ["property access", "const rows = summary.correlations;"],
      ["optional chaining", "const rows = summary?.correlations ?? [];"],
    ])("still sees %s", (_why, code) => {
      expect(hits(code).some((what) => what.includes(".correlations"))).toBe(true);
    });

    it.each([
      ["another name that contains the word", "const correlationCounts = { exact: 1 };"],
      ["a local named correlations", "const correlations = chains.filter(isLinked);"],
      ["an object literal with the key", "report({ correlations: 3 });"],
      ["a literal object being returned", "return { correlations, total };"],
      ["a call with an object argument", "render({ correlations: rows });"],
      ["the chain model's own counts", "const { exact, candidate } = model.counts;"],
      ["a string that only says the word", 'const label = "correlations";'],
    ])("leaves %s alone", (_why, code) => {
      expect(hits(code)).toEqual([]);
    });
  });

  it("strips comments but not code", () => {
    expect(withoutComments("// summary.correlations\nconst a = 1;")).not.toMatch(/correlations/);
    expect(withoutComments("/* summary.correlations */ const a = 1;")).not.toMatch(/correlations/);
    expect(withoutComments("const n = summary.correlations.length;")).toMatch(/correlations/);
  });
});
