/**
 * One chain count (#841, ruling R1). Every surface that says "{n} chains" takes the number from
 * `correlationChainCount` (evtx-correlation-chains.ts): exact + candidate + ambiguous, with a coverage
 * blocked row counted apart. A second sum written inside a component could drift from it, so no source
 * of the workspace adds two of the strengths itself, and the surfaces that state a count call the one
 * function.
 *
 * What the scan sees: a strength word, a plus, an optional dotted or `?.` path, and another strength
 * word, in either order and with the path on either side (`x.exact + x.ambiguous`, `x?.candidate +
 * x?.exact`, or a destructured `exact + candidate`), each term optionally parenthesised and given a
 * nullish default (`(x?.exact ?? 0) + (x?.candidate ?? 0)`). What it does not see: a sum spelled through a
 * bracket index (`counts["exact"]`) or through an alias of the strength word, which is a deliberate
 * evasion and not a natural spelling.
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

const STRENGTH_WORDS = ["exact", "candidate", "ambiguous", "coverageBlocked"] as const;
const ANY_STRENGTH = STRENGTH_WORDS.join("|");

/**
 * One term of such a sum: a strength word with an optional dotted or `?.` path before it, an optional
 * nullish or logical default after it (`?? 0`, `|| 0`), and parentheses around either, which is how a
 * count that may be missing is naturally written: `(c?.exact ?? 0) + (c?.candidate ?? 0)`.
 */
const SUM_TERM = String.raw`\(?\s*(?:\w+(?:\??\.\w+)*\??\.)?\b(?:${ANY_STRENGTH})\b(?:\s*(?:\?\?|\|\|)\s*\w+)?\s*\)?`;

/** The sum of two strengths of a row-count record, written out, in any order. */
const HAND_WRITTEN_SUM = new RegExp(String.raw`${SUM_TERM}\s*\+\s*${SUM_TERM}`);

/** The one module that may write the sum: it is the definition. */
const THE_DEFINITION = "evtx-correlation-chains.ts";

/** The surfaces that state a number of chains, and so must call the one function. */
const COUNTING_SURFACES = ["EventDiagnosisPanel.tsx", "EvtxCorrelationView.tsx"];

describe("the chain count has one definition", () => {
  it("sees the workspace and the module that owns the count", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    expect(sources[THE_DEFINITION]).toMatch(/export function correlationChainCount\(/);
  });

  describe("recognises a hand-written sum", () => {
    const ordered = STRENGTH_WORDS.flatMap((first) =>
      STRENGTH_WORDS.filter((second) => second !== first).map((second) => [first, second] as const),
    );

    it.each(ordered)("%s then %s, dotted", (first, second) => {
      expect(HAND_WRITTEN_SUM.test(`rows.${first} + rows.${second}`)).toBe(true);
      expect(HAND_WRITTEN_SUM.test(`counts.model.counts.${first}+counts.model.counts.${second}`)).toBe(true);
    });

    it.each(ordered)("%s then %s, with optional chaining, bare, and across lines", (first, second) => {
      expect(HAND_WRITTEN_SUM.test(`rows?.${first} + rows?.${second}`)).toBe(true);
      expect(HAND_WRITTEN_SUM.test(`counts?.model?.counts?.${first} + counts?.model?.counts?.${second}`)).toBe(true);
      expect(HAND_WRITTEN_SUM.test(`${first} + ${second}`)).toBe(true);
      expect(HAND_WRITTEN_SUM.test(`rows.${first} +\n  rows.${second}`)).toBe(true);
    });

    it.each(ordered)("%s then %s, each term with a nullish or logical default and in parentheses (review L3)", (first, second) => {
      for (const text of [
        `(rows.${first} ?? 0) + (rows.${second} ?? 0)`,
        `(rows?.${first} ?? 0) + (rows?.${second} ?? 0)`,
        `(c?.model?.counts?.${first} ?? 0)+(c?.model?.counts?.${second} ?? 0)`,
        `(${first} ?? 0) + (${second} ?? 0)`,
        `(rows.${first} || 0) + (rows.${second} || 0)`,
        `rows?.${first} ?? 0 + rows?.${second}`,
        `(rows?.${first} ?? 0) + rows?.${second}`,
        `rows?.${first} + (rows?.${second} ?? 0)`,
        `(\n  rows?.${first} ?? 0\n) +\n(\n  rows?.${second} ?? 0\n)`,
        `(rows.${first}) + (rows.${second})`,
      ]) {
        expect(HAND_WRITTEN_SUM.test(text), text).toBe(true);
      }
    });

    it("sees the full sum in every one of its six orderings", () => {
      const three = ["exact", "candidate", "ambiguous"] as const;
      const orderings = three.flatMap((a) =>
        three.flatMap((b) => three.filter((c) => c !== a && c !== b && a !== b).map((c) => [a, b, c] as const)),
      );
      expect(orderings).toHaveLength(6);
      for (const [a, b, c] of orderings) {
        expect(HAND_WRITTEN_SUM.test(`rows.${a} + rows.${b} + rows.${c}`), `${a} ${b} ${c}`).toBe(true);
      }
    });

    it("does not see a call, a single strength, a difference, or a longer name", () => {
      for (const text of [
        "correlationChainCount(rows)",
        "rows.exact + 1",
        "1 + rows.candidate",
        "rows.exact - rows.candidate",
        "const exactOnly = rows.exact;",
        "exactCount + candidateCount",
        "rows.exacts + rows.candidates",
        "const total = a + b;",
        "(rows.exact ?? 0) + 1",
        "1 + (rows.candidate ?? 0)",
        "(rows.exact ?? 0) - (rows.candidate ?? 0)",
        "(rows.exact ?? 0) * (rows.candidate ?? 0)",
        "(exactCount ?? 0) + (candidateCount ?? 0)",
        "(a ?? 0) + (b ?? 0)",
      ]) {
        expect(HAND_WRITTEN_SUM.test(text), text).toBe(false);
      }
    });
  });

  it("is written by the owning module alone", () => {
    const writers = Object.entries(sources)
      .filter(([file, source]) => file !== THE_DEFINITION && HAND_WRITTEN_SUM.test(source))
      .map(([file]) => file);
    expect(writers).toEqual([]);
  });

  it("keeps the allow-list live: the definition still writes the sum", () => {
    expect(HAND_WRITTEN_SUM.test(sources[THE_DEFINITION]!)).toBe(true);
  });

  it.each(COUNTING_SURFACES)("is called by %s", (file) => {
    expect(sources[file], file).toMatch(/\bcorrelationChainCount\(/);
  });

  // The number is stated only where the engine's gaps leave it proven (review L1): one rule, so the
  // card, the announcement and the tab never disagree on whether to state one.
  it.each(COUNTING_SURFACES)("states it through chainCountForGaps, the rule the Chains tab asks: %s", (file) => {
    expect(sources[file], file).toMatch(/\bchainCountForGaps\(/);
  });

  it("has the Chains tab's number ask the same rule", () => {
    expect(sources[THE_DEFINITION]).toMatch(/export function chainsTabCount\([\s\S]*?\bchainCountForGaps\(/);
  });
});
