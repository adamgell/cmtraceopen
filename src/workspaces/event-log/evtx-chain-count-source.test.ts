/**
 * One chain count (#841, ruling R1). Every surface that says "{n} chains" takes the number from
 * `correlationChainCount` (evtx-correlation-chains.ts): exact + candidate + ambiguous, with a coverage
 * blocked row counted apart. A second sum written inside a component could drift from it, so no source
 * of the workspace adds the strengths itself, and the surfaces that state a count call the one function.
 */
import { describe, expect, it } from "vitest";

/** Every source of the workspace that is not a test, a test helper or a fixture. */
const sources = Object.fromEntries(
  Object.entries(
    import.meta.glob("./**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>,
  )
    .filter(([path]) => !/\.test\.tsx?$|-test-helpers\.|-test-fixtures\.|\/__fixtures__\//.test(path))
    .map(([path, source]) => [path.replace(/^\.\//, ""), source]),
);

/** The sum of two strengths of a row-count record, written out: `x.exact + x.candidate`. */
const HAND_WRITTEN_SUM = /\bexact\s*\+\s*[\w.]*\bcandidate\b|\bcandidate\s*\+\s*[\w.]*\bambiguous\b/;

/** The surfaces that state a number of chains, and so must call the one function. */
const COUNTING_SURFACES = ["EventDiagnosisPanel.tsx"];

describe("the chain count has one definition", () => {
  it("sees the workspace and the module that owns the count", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    expect(sources["evtx-correlation-chains.ts"]).toMatch(/export function correlationChainCount\(/);
  });

  it("recognises a hand-written sum", () => {
    expect(HAND_WRITTEN_SUM.test("rows.exact + rows.candidate + rows.ambiguous")).toBe(true);
    expect(HAND_WRITTEN_SUM.test("counts.model.counts.candidate + counts.model.counts.ambiguous")).toBe(true);
    expect(HAND_WRITTEN_SUM.test("correlationChainCount(rows)")).toBe(false);
    expect(HAND_WRITTEN_SUM.test("const exactOnly = rows.exact;")).toBe(false);
  });

  it("is written by the owning module alone", () => {
    const writers = Object.entries(sources)
      .filter(([file, source]) => file !== "evtx-correlation-chains.ts" && HAND_WRITTEN_SUM.test(source))
      .map(([file]) => file);
    expect(writers).toEqual([]);
  });

  it.each(COUNTING_SURFACES)("is called by %s", (file) => {
    expect(sources[file], file).toMatch(/\bcorrelationChainCount\(/);
  });
});
