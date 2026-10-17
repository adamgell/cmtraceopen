/**
 * Drift guard: every coverage-gap source the engine can write is classified here (L1).
 *
 * `classifyCoverageGaps` files any source it does not know as a candidate ORIGIN ID. That is safe
 * for the links index (an unfound origin clears completeness) but not for the chain plot, which
 * has no origin lookup: a session-level source mistaken for an origin never withdraws "Not
 * linked". So a fixed source the engine adds must be classified as global or display before this
 * file passes, not discovered later.
 *
 * The engine's Rust sources are read as text (`?raw`, like evtx-correlation-store.test.ts does for
 * a TypeScript module) and scanned for the three ways a gap gets its `source`: a `*_SOURCE: &str`
 * constant, a string literal, or an expression naming an origin id. Two paths are scanned:
 * - every `TimelineCoverageGap { source ... }` construction in the three files;
 * - the first element of every `.insert((source, reason))` into the reducer's two gap sets,
 *   `fanout_gaps` and `gap_set` (unified_timeline/mod.rs), which the reducer turns into gaps at
 *   :1128-1131. That path carries fixed sources too (the truncation source), so it is not only
 *   per-origin.
 * Only the code above each file's `#[cfg(test)] mod` is read, so test fixtures never count.
 *
 * What the scan does not prove, as text-scan limits:
 * - the per-origin expressions below are pinned by name, not followed; their file:line pins say
 *   where the engine computes the origin id;
 * - a construction written reason-first (`{ reason, source }`) is not matched;
 * - production code placed after a file's first `#[cfg(test)] mod` is cut;
 * - a gap built in a file other than the three above is not scanned (a grep of src-tauri and
 *   crates finds none today);
 * - a `*_SOURCE` constant declared `&'static str` is not extracted. One used by a construction or
 *   a tuple fails the lookup; one used some other way is not seen;
 * - the gap sets are followed by name. What the last test checks is that every `insert` into them
 *   is one of the scanned `insert((` tuples (a tuple built first and inserted whole fails), that
 *   the only `extend` is the one pinned form, that no other method is called, and that exactly one
 *   shorthand `{ source, reason }` construction turns the pairs into gaps. It does not see an
 *   iterator chain built from `into_iter()` into a new set.
 */
import { describe, expect, it } from "vitest";
import analysisSessionSource from "../../../src-tauri/src/event_log/analysis_session.rs?raw";
import timelineSource from "../../../src-tauri/src/event_log/timeline.rs?raw";
import reducerSource from "../../../crates/cmtraceopen-parser/src/unified_timeline/mod.rs?raw";
import {
  DISPLAY_GAP_SOURCES,
  GLOBAL_CORRELATION_GAP_SOURCES,
  classifyCoverageGaps,
} from "./evtx-correlation-gaps";

const ENGINE_FILES = {
  "src-tauri/src/event_log/analysis_session.rs": analysisSessionSource,
  "src-tauri/src/event_log/timeline.rs": timelineSource,
  "crates/cmtraceopen-parser/src/unified_timeline/mod.rs": reducerSource,
} as const;

/**
 * `*_SOURCE` constants that name a DIAGNOSIS source, not a timeline one. They label findings
 * built by `finding_for_coverage` and travel in `DiagnosisSummary.coverage_gaps`, a different
 * list from `UnifiedTimeline.coverage_gaps` (analysis_session.rs:703, :713, :806, :1127, :1244).
 * Each is checked below never to be the source of a `TimelineCoverageGap`.
 */
const DIAGNOSIS_ONLY_CONSTANTS = [
  "DIAGNOSIS_INPUT_PROJECTION_SOURCE",
  "DIAGNOSIS_RESPONSE_PROJECTION_SOURCE",
  "TEXT_DIAGNOSIS_PROJECTION_SOURCE",
];

/**
 * `TimelineCoverageGap { source ... }` expressions that evaluate to an ORIGIN ID, so the gap is
 * about one origin. Each is the variable the engine builds the gap with:
 * - `stable_id.clone()`: unified_timeline/mod.rs:521 (identity alias conflicts), :597 and :605
 *   (process-start identity);
 * - `origin_id`: mod.rs:717 (duplicate origin coalesced);
 * - `left.clone()`: mod.rs:1020 and :1029 (candidate budget, ambiguous candidates), where `left`
 *   is the edge's left endpoint origin id;
 * - `source`: mod.rs:1131, the shorthand that turns every `(source, reason)` pair of `gap_set`
 *   into a gap. It is a MIXED stream, not an origin id: the pairs come from the tuple inserts
 *   below (per-origin ids and the fixed truncation source) and from the observations' own gaps
 *   (the constructions above). Its contents are checked at their inserts, not here.
 */
const PER_ORIGIN_EXPRESSIONS = ["stable_id.clone()", "origin_id", "left.clone()", "source"];

/**
 * First elements of the reducer's `.insert((source, reason))` calls that are ORIGIN IDS. Each is
 * pinned by name; the fixed ones are named constants and are classified instead.
 * - `id.clone()` and `id`: unified_timeline/mod.rs:797, :805, :814, :856, :872, :880, :918, where
 *   `id` iterates the member origin ids of an identity group that hit the member limit or the
 *   relation budget;
 * - `observation.origin_id.clone()`: mod.rs:1106 (machine identity unavailable) and :1114
 *   (secondary identity only).
 * The fixed source the tuples carry is CORRELATION_GAP_TRUNCATION_SOURCE, at :996 and :1072.
 */
const PER_ORIGIN_TUPLE_SOURCES = ["id.clone()", "id", "observation.origin_id.clone()"];

/** The one way an observation's own gaps enter `gap_set` (mod.rs:1094-1100); see the extend pin. */
const PINNED_EXTEND = /gap_set\s*\.extend\(\s*observation\s*\.coverage_gaps\s*\.iter\(\)\s*\.cloned\(\)\s*\.map\(\|gap\|\s*\(gap\.source,\s*gap\.reason\)\)\s*,?\s*\)/g;
/** What the reducer may do with its two gap sets: feed them, count them, and read them out. */
const GAP_SET_METHODS = ["insert", "extend", "len", "into_iter"];

/** The code above the first `#[cfg(test)] mod`: test fixtures are not engine behaviour. */
function productionCode(text: string): string {
  const testModule = text.search(/^#\[cfg\(test\)\]\s*\nmod\s/m);
  return testModule === -1 ? text : text.slice(0, testModule);
}

interface SourceConstant {
  file: string;
  name: string;
  value: string;
}

function sourceConstants(): SourceConstant[] {
  const found: SourceConstant[] = [];
  for (const [file, text] of Object.entries(ENGINE_FILES)) {
    const pattern = /\bconst\s+([A-Z][A-Z0-9_]*_SOURCE)\s*:\s*&str\s*=\s*"([^"]*)"\s*;/g;
    for (const match of productionCode(text).matchAll(pattern)) {
      found.push({ file, name: match[1] ?? "", value: match[2] ?? "" });
    }
  }
  return found;
}

interface GapConstruction {
  file: string;
  expression: string;
}

/** The `source:` expression of every `TimelineCoverageGap { ... }` the engine builds. */
function gapConstructions(): GapConstruction[] {
  const found: GapConstruction[] = [];
  for (const [file, text] of Object.entries(ENGINE_FILES)) {
    const pattern = /TimelineCoverageGap\s*\{\s*source\s*(?::\s*([^,}]+?))?\s*[,}]/g;
    for (const match of productionCode(text).matchAll(pattern)) {
      found.push({ file, expression: (match[1] ?? "source").trim() });
    }
  }
  return found;
}

interface TupleInsert {
  file: string;
  expression: string;
}

const REDUCER_FILE = "crates/cmtraceopen-parser/src/unified_timeline/mod.rs";
const GAP_SET_CALL = /\b(?:fanout_gaps|gap_set)\s*\.(\w+)\(/g;

/** The first element of every `.insert((source, reason))` into the reducer's two gap sets. */
function tupleInserts(): TupleInsert[] {
  const pattern = /\b(?:fanout_gaps|gap_set)\s*\.insert\(\s*\(\s*([^,]+?)\s*,/g;
  return [...productionCode(reducerSource).matchAll(pattern)].map((match) => ({
    file: REDUCER_FILE,
    expression: (match[1] ?? "").trim(),
  }));
}

const NAMED = /^([A-Z][A-Z0-9_]*)(?:\.to_string\(\)|\.into\(\))$/;
const LITERAL = /^"([^"]*)"(?:\.to_string\(\)|\.into\(\))$/;

function classify(source: string) {
  return classifyCoverageGaps([{ source, reason: "engine reason" }], 1);
}

describe("the engine's coverage-gap sources (drift guard)", () => {
  const constants = sourceConstants();
  const constructions = gapConstructions();
  const tuples = tupleInserts();
  /** Every place the engine gives a gap its source: a construction, or a tuple into a gap set. */
  const written = [
    ...constructions.map(({ file, expression }) => ({ file, expression, path: "construction" as const })),
    ...tuples.map(({ file, expression }) => ({ file, expression, path: "insert" as const })),
  ];
  const PINNED_ORIGIN_EXPRESSIONS = {
    construction: PER_ORIGIN_EXPRESSIONS,
    insert: PER_ORIGIN_TUPLE_SOURCES,
  };

  it("finds the engine's source constants and gap constructions, so the scan is not vacuous", () => {
    expect(constants.map((entry) => entry.name).sort()).toEqual([
      "CORRELATION_GAP_TRUNCATION_SOURCE",
      "DIAGNOSIS_INPUT_PROJECTION_SOURCE",
      "DIAGNOSIS_RESPONSE_PROJECTION_SOURCE",
      "TEXT_DIAGNOSIS_PROJECTION_SOURCE",
      "TIMELINE_CORRELATION_PROJECTION_SOURCE",
      "TIMELINE_ITEM_PROJECTION_SOURCE",
      "TIMELINE_MESSAGE_PROJECTION_SOURCE",
      "TIMELINE_TRANSPORT_PROJECTION_SOURCE",
    ]);
    expect(constructions.length).toBeGreaterThanOrEqual(13);
    expect(constructions.map((entry) => entry.file)).toEqual(
      expect.arrayContaining(Object.keys(ENGINE_FILES)),
    );
    // Seven group-member inserts, two truncation inserts, two per-observation inserts.
    expect(tuples.length).toBeGreaterThanOrEqual(11);
    expect(tuples.map((entry) => entry.expression)).toEqual(
      expect.arrayContaining(["id.clone()", "CORRELATION_GAP_TRUNCATION_SOURCE.to_string()", "observation.origin_id.clone()"]),
    );
  });

  it("classifies every fixed source a timeline gap can carry as global or display, never as an origin", () => {
    const fixedSources: string[] = [];
    for (const { file, expression, path } of written) {
      const named = NAMED.exec(expression);
      const literal = LITERAL.exec(expression);
      if (named !== null) {
        const constant = constants.find((entry) => entry.name === named[1]);
        expect(constant, `${file}: ${expression} names no *_SOURCE constant`).toBeDefined();
        fixedSources.push(constant?.value ?? "");
      } else if (literal !== null) {
        fixedSources.push(literal[1] ?? "");
      } else {
        expect(
          PINNED_ORIGIN_EXPRESSIONS[path],
          `${file}: a gap source of "${expression}" (${path}) is not classified. Pin it if it is an origin id, or give it a *_SOURCE constant and classify that.`,
        ).toContain(expression);
      }
    }
    for (const source of fixedSources) {
      const classified = classify(source);
      expect(
        classified.originIds.size,
        `"${source}" is a fixed engine source but is read as an origin id; classify it in evtx-correlation-gaps.ts`,
      ).toBe(0);
      expect(
        classified.global || DISPLAY_GAP_SOURCES.has(source),
        `"${source}" is neither global nor display`,
      ).toBe(true);
    }
    expect([...new Set(fixedSources)].sort()).toEqual([
      "correlation",
      "event-record-identity",
      "timeline-correlation-projection",
      "timeline-item-projection",
      "timeline-message-projection",
      "timeline-transport-projection",
    ]);
  });

  it("lists exactly the fixed sources the engine writes, with nothing stale", () => {
    const fixed = new Set<string>();
    for (const { expression } of written) {
      const named = NAMED.exec(expression);
      const literal = LITERAL.exec(expression);
      if (named !== null) fixed.add(constants.find((entry) => entry.name === named[1])?.value ?? "");
      if (literal !== null) fixed.add(literal[1] ?? "");
    }
    for (const source of [...GLOBAL_CORRELATION_GAP_SOURCES, ...DISPLAY_GAP_SOURCES]) {
      expect(fixed.has(source), `"${source}" is classified but no engine gap writes it`).toBe(true);
    }
  });

  it("keeps the diagnosis constants out of the timeline's gap list", () => {
    const diagnosis = constants.filter((entry) => DIAGNOSIS_ONLY_CONSTANTS.includes(entry.name));
    expect(diagnosis.map((entry) => entry.name).sort()).toEqual([...DIAGNOSIS_ONLY_CONSTANTS].sort());
    for (const { expression } of written) {
      const named = NAMED.exec(expression)?.[1];
      expect(
        DIAGNOSIS_ONLY_CONSTANTS,
        `${named ?? expression} is a diagnosis source but a timeline gap now uses it`,
      ).not.toContain(named);
    }
    // Every constant is either a timeline gap source (classified above) or listed as diagnosis-only.
    const timelineConstants = written
      .map((entry) => NAMED.exec(entry.expression)?.[1])
      .filter((name): name is string => name !== undefined);
    for (const { name } of constants) {
      expect(
        timelineConstants.includes(name) || DIAGNOSIS_ONLY_CONSTANTS.includes(name),
        `${name} is a *_SOURCE constant that is neither a timeline gap source nor listed as diagnosis-only`,
      ).toBe(true);
    }
  });

  it("classifies the first element of every tuple the reducer inserts into its gap sets (M1)", () => {
    // The tuple path is how the reducer adds both per-origin gaps and the fixed truncation source,
    // so a source added here is not a `TimelineCoverageGap {` construction and no constant need
    // change. Each first element must be a classified constant or a pinned origin variable.
    const fixed: string[] = [];
    for (const { expression } of tuples) {
      const named = NAMED.exec(expression);
      const literal = LITERAL.exec(expression);
      if (named !== null) {
        const constant = constants.find((entry) => entry.name === named[1]);
        expect(constant, `a tuple insert's source ${expression} names no *_SOURCE constant`).toBeDefined();
        fixed.push(constant?.value ?? "");
      } else if (literal !== null) {
        fixed.push(literal[1] ?? "");
      } else {
        expect(
          PER_ORIGIN_TUPLE_SOURCES,
          `a tuple insert's source "${expression}" is not classified. Pin it in PER_ORIGIN_TUPLE_SOURCES if it is an origin id, or give it a *_SOURCE constant and classify that.`,
        ).toContain(expression);
      }
    }
    for (const source of fixed) {
      const classified = classify(source);
      expect(
        classified.originIds.size,
        `"${source}" is a fixed source in a tuple insert but is read as an origin id; classify it in evtx-correlation-gaps.ts`,
      ).toBe(0);
      expect(classified.global || DISPLAY_GAP_SOURCES.has(source), `"${source}" is neither global nor display`).toBe(true);
    }
    expect([...new Set(fixed)]).toEqual(["correlation"]);
  });

  it("feeds the reducer's gap sets only by tuple insert and the one pinned extend", () => {
    // Without this, a third way in (another extend, a merge) would add sources the scans above
    // never see.
    const code = productionCode(reducerSource);
    const methods = [...code.matchAll(GAP_SET_CALL)].map((match) => match[1] ?? "");
    expect(methods.filter((method) => !GAP_SET_METHODS.includes(method))).toEqual([]);
    const extended = methods.filter((method) => method === "extend").length;
    expect([...code.matchAll(PINNED_EXTEND)].length, "the observations' gaps no longer enter gap_set by the pinned extend").toBe(1);
    expect(extended, "gap_set or fanout_gaps is extended some other way").toBe(1);
    // Every insert is a tuple whose first element was classified above: one built first and
    // inserted whole (`insert(pair)`) is a source nothing has classified.
    expect(
      methods.filter((method) => method === "insert").length,
      "an insert into a gap set is not a scanned `insert((source, reason))` tuple",
    ).toBe(tuples.length);
    // The shorthand `{ source, reason }` turns the set's pairs into gaps. A second one would turn
    // another stream of pairs into gaps with sources nothing here has seen.
    expect(
      constructions.filter((entry) => entry.expression === "source").length,
      "the pairs of gap_set are no longer turned into gaps by exactly one shorthand construction",
    ).toBe(1);
  });

  it("pins the global and display sets against the engine's constants and its one literal", () => {
    const byName = new Map(constants.map((entry) => [entry.name, entry.value]));
    expect([...GLOBAL_CORRELATION_GAP_SOURCES].sort()).toEqual(
      [
        byName.get("CORRELATION_GAP_TRUNCATION_SOURCE"),
        byName.get("TIMELINE_CORRELATION_PROJECTION_SOURCE"),
        byName.get("TIMELINE_TRANSPORT_PROJECTION_SOURCE"),
        // Not a constant: the literal at analysis_session.rs:448.
        "event-record-identity",
      ].sort(),
    );
    expect([...DISPLAY_GAP_SOURCES].sort()).toEqual(
      [
        byName.get("TIMELINE_ITEM_PROJECTION_SOURCE"),
        byName.get("TIMELINE_MESSAGE_PROJECTION_SOURCE"),
      ].sort(),
    );
  });
});
