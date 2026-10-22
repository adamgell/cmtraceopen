/**
 * Classifying the engine's correlation coverage gaps by their `source`, never by their wording.
 * The shapes come from the parser crate's own reducer (`__fixtures__/correlation-edges.json`).
 */
import { describe, expect, it } from "vitest";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import {
  DISPLAY_GAP_SOURCES,
  GLOBAL_CORRELATION_GAP_SOURCES,
  UNKNOWN_CORRELATION_GAPS,
  classifyCoverageGaps,
  gapsClearCompleteness,
} from "./evtx-correlation-gaps";
import type { TimelineCoverageGap } from "./unified-timeline";

const ORIGIN = "source4:Live|machine10:DESKTOP-01|channel6:System|record7";

function fixtureGaps(name: string): TimelineCoverageGap[] {
  const scenarios = fixtureDocument.scenarios as unknown as Record<
    string,
    { coverageGaps: TimelineCoverageGap[] }
  >;
  const scenario = scenarios[name];
  if (scenario === undefined) throw new Error(`no fixture scenario ${name}`);
  return scenario.coverageGaps;
}

describe("classifyCoverageGaps", () => {
  it("names the origin a gap is about by its source: the engine's fan-out gap, from a real reducer run", () => {
    const gaps = fixtureGaps("fanOut");
    expect(gaps).toHaveLength(301);
    expect(gaps[0]?.reason).toMatch(/256-member correlation limit/);
    const classified = classifyCoverageGaps(gaps, gaps.length);
    expect(classified.originIds.size).toBe(301);
    expect([...classified.originIds].every((id) => id.startsWith("source4:Live|"))).toBe(true);
    expect(classified.global).toBe(false);
    expect(classified.previewCut).toBe(false);
    expect(gapsClearCompleteness(classified)).toBe(false);
  });

  it("sees a global limit by its source: the input limit, the reducer's truncation, and the session's own losses", () => {
    for (const source of [
      "timeline-correlation-projection",
      "correlation",
      "timeline-transport-projection",
      "event-record-identity",
    ]) {
      const classified = classifyCoverageGaps([{ source, reason: "anything" }], 1);
      expect(classified.global, source).toBe(true);
      expect(classified.originIds.size, source).toBe(0);
      expect(gapsClearCompleteness(classified), source).toBe(true);
    }
    expect([...GLOBAL_CORRELATION_GAP_SOURCES].sort()).toEqual([
      "correlation",
      "event-record-identity",
      "timeline-correlation-projection",
      "timeline-transport-projection",
    ]);
  });

  it("reads the session-level losses as global however the engine words them (L1)", () => {
    // The wording the engine writes today (analysis_session.rs:437-441).
    const transport = classifyCoverageGaps(
      [
        {
          source: "timeline-transport-projection",
          reason:
            "timeline transport projection affected 3 rows totaling 900 original serialized bytes and 300 retained bytes; omitted identity or derived fields may limit correlation while full records remain in the event grid or log view",
        },
      ],
      1,
    );
    expect(transport).toEqual({ originIds: new Set(), global: true, previewCut: false });
    // grouped_identity_gap_detail (analysis_session.rs:936-944; the text after "because" is the
    // engine's per-case detail and is illustrative here); the record keeps its timeline row
    // but sanitize_malformed_timeline_record (:828-845) strips every key that could link it.
    const identity = classifyCoverageGaps(
      [
        {
          source: "event-record-identity",
          reason:
            "1 event record was excluded from diagnosis because its EventRecordID is malformed; timeline rows were retained.",
        },
      ],
      1,
    );
    expect(identity).toEqual({ originIds: new Set(), global: true, previewCut: false });
  });

  it("decides by the source and never by the reason text", () => {
    // A limit-sounding reason on an origin's gap is still an origin gap...
    const originGap = classifyCoverageGaps(
      [{ source: ORIGIN, reason: "correlation input limit reached; 5 of 9 omitted" }],
      1,
    );
    expect(originGap.global).toBe(false);
    expect([...originGap.originIds]).toEqual([ORIGIN]);
    // ...and a global source with an origin-sounding reason is still global.
    const globalGap = classifyCoverageGaps(
      [{ source: "correlation", reason: "exact UserId identity group exceeds the 256-member correlation limit" }],
      1,
    );
    expect(globalGap.global).toBe(true);
    expect(globalGap.originIds.size).toBe(0);
  });

  it("ignores list-view compaction gaps: they say nothing about correlation", () => {
    const gaps = [
      { source: "timeline-item-projection", reason: "x" },
      { source: "timeline-message-projection", reason: "y" },
    ];
    const classified = classifyCoverageGaps(gaps, 2);
    expect(classified).toEqual({ originIds: new Set(), global: false, previewCut: false });
    expect(gapsClearCompleteness(classified)).toBe(false);
    expect([...DISPLAY_GAP_SOURCES].sort()).toEqual([
      "timeline-item-projection",
      "timeline-message-projection",
    ]);
  });

  it("is cut when the session counts more gaps than the preview holds", () => {
    const gaps = fixtureGaps("fanOut").slice(0, 100);
    const classified = classifyCoverageGaps(gaps, 301);
    expect(classified.previewCut).toBe(true);
    expect(classified.originIds.size).toBe(100);
    expect(gapsClearCompleteness(classified)).toBe(true);
  });

  it("is cut when the count is not known, and when it contradicts the preview", () => {
    const one = [{ source: ORIGIN, reason: "r" }];
    expect(classifyCoverageGaps(one, null).previewCut).toBe(true);
    expect(classifyCoverageGaps(one, 0).previewCut).toBe(true);
    expect(classifyCoverageGaps(one, 1).previewCut).toBe(false);
  });

  it("treats a session with no gaps and a count of 0 as clear", () => {
    const classified = classifyCoverageGaps([], 0);
    expect(classified).toEqual({ originIds: new Set(), global: false, previewCut: false });
    expect(gapsClearCompleteness(classified)).toBe(false);
  });

  it("keeps an unrecognised source as a candidate origin to be found, never as clear", () => {
    const classified = classifyCoverageGaps([{ source: "Live", reason: "channel Security was not collected" }], 1);
    expect([...classified.originIds]).toEqual(["Live"]);
  });

  it("is the safe value for 'no information': it claims a cut preview", () => {
    expect(gapsClearCompleteness(UNKNOWN_CORRELATION_GAPS)).toBe(true);
  });
});
