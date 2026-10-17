/**
 * #838 ruling 1: no correlation count or row anywhere in the UI may come from the diagnosis
 * summary (`DiagnosisSummary.correlations`, `overview.correlationCount`). The Correlations card and
 * the Correlation view, built from the timeline's edges, are the correlation surfaces.
 *
 * The rule predates the Correlation view and was broken in a second place (the diagnosis details
 * disclosure) after the first was fixed, so it is enforced by reading the sources: no UI file may
 * name those fields. The wire type and its decoder are the two places that must (the backend still
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

const FORBIDDEN: [string, RegExp][] = [
  ["the summary's correlation rows (.correlations)", /\.correlations\b/],
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

  it("strips comments but not code", () => {
    expect(withoutComments("// summary.correlations\nconst a = 1;")).not.toMatch(/correlations/);
    expect(withoutComments("/* summary.correlations */ const a = 1;")).not.toMatch(/correlations/);
    expect(withoutComments("const n = summary.correlations.length;")).toMatch(/correlations/);
  });
});
