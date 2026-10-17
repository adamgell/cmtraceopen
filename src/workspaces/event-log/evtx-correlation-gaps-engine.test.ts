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
 * a TypeScript module) and scanned for the three ways a `TimelineCoverageGap` gets its `source`:
 * a `*_SOURCE: &str` constant, a string literal, or an expression naming an origin id. Only the
 * code above each file's `#[cfg(test)] mod` is read, so test fixtures never count.
 *
 * What the scan does not prove: the per-origin expressions below are pinned by name, not
 * followed. Their file:line pins say where the engine computes the origin id.
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
 * Source expressions that evaluate to an ORIGIN ID, so the gap is about one origin. Each is the
 * variable the engine builds the gap with:
 * - `stable_id.clone()`: unified_timeline/mod.rs:521 (identity alias conflicts), :597 and :605
 *   (process-start identity);
 * - `origin_id`: mod.rs:717 (duplicate origin coalesced);
 * - `left.clone()`: mod.rs:1020 and :1029 (candidate budget, ambiguous candidates), where `left`
 *   is the edge's left endpoint origin id;
 * - `source`: mod.rs:1131, the first element of the (origin_id, reason) pairs collected at
 *   :1105-1119 (machine identity unavailable, secondary identity only).
 */
const PER_ORIGIN_EXPRESSIONS = ["stable_id.clone()", "origin_id", "left.clone()", "source"];

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

const NAMED = /^([A-Z][A-Z0-9_]*)(?:\.to_string\(\)|\.into\(\))$/;
const LITERAL = /^"([^"]*)"(?:\.to_string\(\)|\.into\(\))$/;

function classify(source: string) {
  return classifyCoverageGaps([{ source, reason: "engine reason" }], 1);
}

describe("the engine's coverage-gap sources (drift guard)", () => {
  const constants = sourceConstants();
  const constructions = gapConstructions();

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
  });

  it("classifies every fixed source a timeline gap can carry as global or display, never as an origin", () => {
    const fixedSources: string[] = [];
    for (const { file, expression } of constructions) {
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
          PER_ORIGIN_EXPRESSIONS,
          `${file}: a gap source of "${expression}" is not classified. Add it to PER_ORIGIN_EXPRESSIONS if it is an origin id, or give it a *_SOURCE constant and classify that.`,
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
    const written = new Set<string>();
    for (const { expression } of constructions) {
      const named = NAMED.exec(expression);
      const literal = LITERAL.exec(expression);
      if (named !== null) written.add(constants.find((entry) => entry.name === named[1])?.value ?? "");
      if (literal !== null) written.add(literal[1] ?? "");
    }
    for (const source of [...GLOBAL_CORRELATION_GAP_SOURCES, ...DISPLAY_GAP_SOURCES]) {
      expect(written.has(source), `"${source}" is classified but no engine gap writes it`).toBe(true);
    }
  });

  it("keeps the diagnosis constants out of the timeline's gap list", () => {
    const diagnosis = constants.filter((entry) => DIAGNOSIS_ONLY_CONSTANTS.includes(entry.name));
    expect(diagnosis.map((entry) => entry.name).sort()).toEqual([...DIAGNOSIS_ONLY_CONSTANTS].sort());
    for (const { expression } of constructions) {
      const named = NAMED.exec(expression)?.[1];
      expect(
        DIAGNOSIS_ONLY_CONSTANTS,
        `${named ?? expression} is a diagnosis source but a TimelineCoverageGap now uses it`,
      ).not.toContain(named);
    }
    // Every constant is either a timeline gap source (classified above) or listed as diagnosis-only.
    const timelineConstants = constructions
      .map((entry) => NAMED.exec(entry.expression)?.[1])
      .filter((name): name is string => name !== undefined);
    for (const { name } of constants) {
      expect(
        timelineConstants.includes(name) || DIAGNOSIS_ONLY_CONSTANTS.includes(name),
        `${name} is a *_SOURCE constant that is neither a timeline gap source nor listed as diagnosis-only`,
      ).toBe(true);
    }
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
