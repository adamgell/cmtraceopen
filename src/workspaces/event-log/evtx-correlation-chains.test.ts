import { describe, expect, it } from "vitest";
import {
  CORRELATION_CHAIN_RENDER_LIMIT,
  buildCorrelationChains,
  type CorrelationChain,
  type CorrelationChainInput,
  type CorrelationChainModel,
} from "./evtx-correlation-chains";
import type {
  TimelineCorrelationEdge,
  TimelineCorrelationStrength,
  TimelineCoverageGap,
  TimelineItem,
  TimelineSeverity,
} from "./unified-timeline";
import {
  assertUnifiedTimelineShape,
  timelineOriginId,
} from "./unified-timeline";

function eventItem(
  id: string,
  timestampMs: number,
  severity: TimelineSeverity = "info",
  message = `message of ${id}`,
  eventId = 100,
): TimelineItem {
  return {
    timestampMs,
    severity,
    message,
    origin: {
      kind: "event",
      stableId: id,
      source: "Live",
      machine: "HOST-A",
      bundle: null,
      channel: "Application",
      provider: "Provider",
      processId: null,
      eventId,
      recordId: 1,
    },
  };
}

function logItem(
  id: string,
  timestampMs: number,
  line: number,
  severity: TimelineSeverity = "info",
): TimelineItem {
  return {
    timestampMs,
    severity,
    message: `log line ${line}`,
    origin: {
      kind: "log",
      file: `${id}.log`,
      component: null,
      line,
      source: "ime",
      machine: "HOST-A",
      bundle: null,
      recordId: line,
    },
  };
}

function tEdge(
  id: string,
  fromId: string,
  toId: string | null,
  strength: TimelineCorrelationStrength,
  overrides: Partial<TimelineCorrelationEdge> = {},
): TimelineCorrelationEdge {
  return {
    id,
    fromId,
    toId,
    key: { kind: "activityId", value: `key-${id}` },
    strength,
    confidence: "high",
    candidateIds: [],
    evidence: [{ originId: fromId, field: "activityId", value: `key-${id}` }],
    coverage: { state: "covered" },
    ...overrides,
  };
}

function gapOf(reason: string, source = "Live"): TimelineCoverageGap {
  return { source, reason };
}

/** An exact pair that the backend marked as having a coverage gap. */
function gappedExact(
  id: string,
  fromId: string,
  toId: string,
  reason = "channel not collected",
): TimelineCorrelationEdge {
  return tEdge(id, fromId, toId, "exact", {
    coverage: { state: "gap", gap: gapOf(reason) },
  });
}

/**
 * Backend shape of an ambiguous group: N ids, one edge per unordered pair (N(N-1)/2 edges), each
 * carrying the group's multiple-candidates gap, `candidateIds` equal to the group minus `fromId`,
 * and `toId` always set.
 */
function ambiguousGroup(
  prefix: string,
  group: readonly string[],
): TimelineCorrelationEdge[] {
  const edges: TimelineCorrelationEdge[] = [];
  for (let i = 0; i < group.length; i += 1) {
    for (let j = i + 1; j < group.length; j += 1) {
      const fromId = group[i] as string;
      edges.push(
        tEdge(`${prefix}-${i}-${j}`, fromId, group[j] as string, "ambiguous", {
          candidateIds: group.filter((id) => id !== fromId),
          coverage: {
            state: "gap",
            gap: gapOf(
              `multiple exact identity candidates remain: ${group.join(", ")}`,
            ),
          },
        }),
      );
    }
  }
  return edges;
}

function build(input: Partial<CorrelationChainInput>): CorrelationChainModel {
  return buildCorrelationChains({
    items: [],
    timelineEdges: [],
    findings: [],
    ...input,
  });
}

function allMembers(chain: CorrelationChain): string[] {
  return [...chain.memberIds, ...chain.unresolvedMemberIds].sort();
}

describe("chain formation", () => {
  it("builds one chain per connected component over exact and candidate edges", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "b", "c", "exact"),
        tEdge("e3", "x", "y", "exact"),
      ],
    });
    expect(model.chains.map(allMembers)).toEqual([["a", "b", "c"], ["x", "y"]]);
    expect(model.counts.exact).toBe(2);
    expect(model.totalCount).toBe(2);
  });

  it("takes the weakest edge as the chain strength", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "b", "c", "candidate"),
      ],
    });
    expect(model.chains).toHaveLength(1);
    expect(model.chains[0]?.strength).toBe("candidate");
    expect(model.counts).toMatchObject({ exact: 0, candidate: 1 });
  });

  it("caps an exact edge on a secondary key at candidate", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact", {
          key: { kind: "secondary", value: "s" },
        }),
      ],
    });
    expect(model.chains[0]?.strength).toBe("candidate");
  });

  it("classifies a covered exact edge with a gap as coverage blocked and carries the gap", () => {
    const model = build({ timelineEdges: [gappedExact("e1", "a", "b", "why")] });
    expect(model.counts).toMatchObject({ exact: 0, coverageBlocked: 1 });
    expect(model.chains).toHaveLength(1);
    expect(model.chains[0]?.strength).toBe("coverageBlocked");
    expect(model.chains[0]?.coverageGaps).toEqual([gapOf("why")]);
  });

  it("counts exact or candidate edges that cannot link two entries as ignored", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", null, "exact"),
        tEdge("e2", "b", "b", "candidate"),
      ],
    });
    expect(model.totalCount).toBe(0);
    expect(model.ignoredRelationCount).toBe(2);
  });

  it("counts a degenerate non-linking relation as ignored too, once per reduced pair", () => {
    const degenerate = (id: string) =>
      tEdge(id, "a", "a", "ambiguous", {
        coverage: { state: "gap", gap: gapOf("g") },
      });
    const model = build({
      timelineEdges: [degenerate("d1"), degenerate("d2"), gappedExact("d3", "b", "b")],
    });
    expect(model.totalCount).toBe(0);
    expect(model.ignoredRelationCount).toBe(2);
  });

  it("makes one link one edge, however many observations back it", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "b", "a", "exact"),
        tEdge("e3", "a", "b", "exact"),
      ],
    });
    expect(model.counts.exact).toBe(1);
    expect(model.chains[0]?.edges).toHaveLength(1);
  });
});

describe("ambiguous groups in the backend shape", () => {
  it("shows a 4-id group as exactly one ambiguous row", () => {
    const group = ["a", "b", "c", "d"];
    const edges = ambiguousGroup("g", group);
    expect(edges).toHaveLength(6);
    const model = build({ timelineEdges: edges });
    expect(model.totalCount).toBe(1);
    expect(model.counts).toEqual({
      exact: 0,
      candidate: 0,
      ambiguous: 1,
      coverageBlocked: 0,
    });
    const row = model.chains[0];
    expect(row?.strength).toBe("ambiguous");
    expect(row?.memberCount).toBe(4);
    expect(row ? allMembers(row) : []).toEqual(group);
    expect(row?.coverageGaps).toHaveLength(1);
    expect(row?.coverageGaps[0]?.reason).toMatch(
      /^multiple exact identity candidates remain/,
    );
  });

  it("keeps two ambiguous groups that overlap in one member as two rows", () => {
    const model = build({
      timelineEdges: [
        ...ambiguousGroup("g1", ["a", "b", "c"]),
        ...ambiguousGroup("g2", ["c", "d", "e"]),
      ],
    });
    expect(model.counts.ambiguous).toBe(2);
    expect(model.totalCount).toBe(2);
    expect(model.chains.map(allMembers).sort()).toEqual([
      ["a", "b", "c"],
      ["c", "d", "e"],
    ]);
  });

  // Documents a consequence of the ruling: a pair shared by two groups is reduced to one relation
  // whose candidateIds are the union, so its member set equals neither group and it is its own row.
  it("gives a pair shared by two groups its own row with the combined member set", () => {
    const model = build({
      timelineEdges: [
        ...ambiguousGroup("g1", ["a", "b", "c"]),
        ...ambiguousGroup("g2", ["b", "c", "d"]),
      ],
    });
    expect(model.counts.ambiguous).toBe(3);
    expect(model.chains.map(allMembers).sort()).toEqual([
      ["a", "b", "c"],
      ["a", "b", "c", "d"],
      ["b", "c", "d"],
    ]);
  });

  it("does not merge ambiguous groups that only share members through a chain", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "c", "d", "exact"),
        ...ambiguousGroup("g", ["b", "c", "z"]),
      ],
    });
    expect(model.chains.filter((c) => c.strength === "exact").map(allMembers))
      .toEqual([["a", "b"], ["c", "d"]]);
    expect(model.counts).toMatchObject({ exact: 2, ambiguous: 1 });
  });
});

describe("contradicting observations on one pair", () => {
  it("lets an ambiguous observation veto an exact one", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        ...ambiguousGroup("g", ["a", "b"]),
      ],
    });
    expect(model.counts).toEqual({
      exact: 0,
      candidate: 0,
      ambiguous: 1,
      coverageBlocked: 0,
    });
    expect(model.chains).toHaveLength(1);
    expect(model.chains[0]?.strength).toBe("ambiguous");
  });

  it("takes candidate when exact and candidate disagree", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "a", "b", "candidate"),
      ],
    });
    expect(model.chains).toHaveLength(1);
    expect(model.chains[0]?.strength).toBe("candidate");
    expect(model.counts).toMatchObject({ exact: 0, candidate: 1 });
  });

  it("takes coverage blocked when exact meets exact with a gap", () => {
    const model = build({
      timelineEdges: [tEdge("e1", "a", "b", "exact"), gappedExact("e2", "a", "b")],
    });
    expect(model.chains).toHaveLength(1);
    expect(model.chains[0]?.strength).toBe("coverageBlocked");
  });

  it("takes coverage blocked when ambiguous meets exact with a gap", () => {
    const model = build({
      timelineEdges: [
        ...ambiguousGroup("g", ["a", "b"]),
        gappedExact("e2", "b", "a", "other gap"),
      ],
    });
    expect(model.chains).toHaveLength(1);
    expect(model.chains[0]?.strength).toBe("coverageBlocked");
    expect(model.chains[0]?.coverageGaps.map((gap) => gap.reason)).toEqual([
      "multiple exact identity candidates remain: a, b",
      "other gap",
    ]);
  });

  it("does not let a vetoed pair connect its endpoints through the chain edges", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        ...ambiguousGroup("g", ["a", "b"]),
        tEdge("e2", "b", "c", "exact"),
      ],
    });
    const chain = model.chains.find((row) => row.strength === "exact");
    expect(chain && allMembers(chain)).toEqual(["b", "c"]);
  });
});

describe("partial members", () => {
  it("separates resolved from unresolved members", () => {
    const model = build({
      items: [eventItem("a", 1000, "error", "boom", 7), eventItem("b", 2000)],
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "b", "z", "exact"),
      ],
    });
    const chain = model.chains[0];
    expect(chain?.memberIds).toEqual(["a", "b"]);
    expect(chain?.unresolvedMemberIds).toEqual(["z"]);
    expect(chain?.memberCount).toBe(3);
    expect(chain?.startMs).toBe(1000);
    expect(chain?.endMs).toBe(2000);
    expect(chain?.title).toBe("7 · boom");
  });

  it("gives null span and title when every member is unresolved", () => {
    const model = build({
      timelineEdges: [tEdge("e1", "a", "b", "exact")],
    });
    const chain = model.chains[0];
    expect(chain?.memberIds).toEqual([]);
    expect(chain?.unresolvedMemberIds).toEqual(["a", "b"]);
    expect(chain?.memberCount).toBe(2);
    expect(chain?.startMs).toBeNull();
    expect(chain?.endMs).toBeNull();
    expect(chain?.title).toBeNull();
  });

  it("orders members by timestamp, ties by id, and unresolved by id", () => {
    const model = build({
      items: [eventItem("m", 1000), eventItem("b", 1000), eventItem("a", 2000)],
      timelineEdges: [
        tEdge("e1", "m", "b", "exact"),
        tEdge("e2", "a", "z", "exact"),
        tEdge("e3", "a", "y", "exact"),
        tEdge("e4", "b", "a", "exact"),
      ],
    });
    const chain = model.chains[0];
    expect(chain?.memberIds).toEqual(["b", "m", "a"]);
    expect(chain?.unresolvedMemberIds).toEqual(["y", "z"]);
  });

  it("applies the same split to an ambiguous row", () => {
    const model = build({
      items: [eventItem("a", 1000), eventItem("b", 2000)],
      timelineEdges: ambiguousGroup("g", ["a", "b", "z"]),
    });
    const row = model.chains[0];
    expect(row?.memberIds).toEqual(["a", "b"]);
    expect(row?.unresolvedMemberIds).toEqual(["z"]);
    expect(row?.memberCount).toBe(3);
  });

  it("orders rows by total member count, not resolved count", () => {
    const model = build({
      items: [eventItem("p", 1000), eventItem("q", 1100)],
      timelineEdges: [
        tEdge("e1", "p", "q", "exact"),
        tEdge("e2", "u1", "u2", "exact"),
        tEdge("e3", "u2", "u3", "exact"),
      ],
    });
    expect(model.chains.map((c) => c.memberCount)).toEqual([3, 2]);
  });
});

describe("duplicate origins", () => {
  it("keeps the earliest timestamp regardless of input order", () => {
    const early = eventItem("a", 1000, "info", "same");
    const late = eventItem("a", 5000, "info", "same");
    const edges = [tEdge("e1", "a", "b", "exact")];
    const one = build({ items: [early, late], timelineEdges: edges });
    const two = build({ items: [late, early], timelineEdges: edges });
    expect(one).toEqual(two);
    expect(one.chains[0]?.startMs).toBe(1000);
  });

  it("breaks an equal-timestamp tie without depending on input order", () => {
    const x = eventItem("a", 1000, "info", "alpha", 1);
    const y = eventItem("a", 1000, "error", "beta", 2);
    const edges = [tEdge("e1", "a", "b", "exact")];
    expect(build({ items: [x, y], timelineEdges: edges })).toEqual(
      build({ items: [y, x], timelineEdges: edges }),
    );
  });
});

describe("ordering", () => {
  it("orders exact, candidate, ambiguous, then coverage blocked", () => {
    const model = build({
      timelineEdges: [
        gappedExact("p", "p", "q"),
        ...ambiguousGroup("g", ["m", "n"]),
        tEdge("c", "j", "k", "candidate"),
        tEdge("e", "a", "b", "exact"),
      ],
    });
    expect(model.chains.map((c) => c.strength)).toEqual([
      "exact",
      "candidate",
      "ambiguous",
      "coverageBlocked",
    ]);
  });

  it("orders by member count descending, then earliest timestamp, then id", () => {
    const model = build({
      items: [
        eventItem("a1", 3000),
        eventItem("a2", 3100),
        eventItem("b1", 1000),
        eventItem("b2", 1100),
        eventItem("c1", 2000),
        eventItem("c2", 2100),
        eventItem("c3", 2200),
        eventItem("d1", 1000),
        eventItem("d2", 1100),
      ],
      timelineEdges: [
        tEdge("ea", "a1", "a2", "exact"),
        tEdge("eb", "b1", "b2", "exact"),
        tEdge("ec1", "c1", "c2", "exact"),
        tEdge("ec2", "c2", "c3", "exact"),
        tEdge("ed", "d1", "d2", "exact"),
      ],
    });
    expect(model.chains.map((c) => c.memberIds[0])).toEqual([
      "c1",
      "b1",
      "d1",
      "a1",
    ]);
  });
});

describe("render cap", () => {
  it("caps rows at 100 and reports the omitted count", () => {
    const edges = Array.from({ length: 130 }, (_, i) =>
      tEdge(`e${i}`, `l${i}`, `r${i}`, "exact"),
    );
    const model = build({ timelineEdges: edges });
    expect(CORRELATION_CHAIN_RENDER_LIMIT).toBe(100);
    expect(model.chains).toHaveLength(100);
    expect(model.totalCount).toBe(130);
    expect(model.omittedCount).toBe(30);
    expect(model.counts.exact).toBe(130);
  });

  it("omits nothing at or under the cap", () => {
    const edges = Array.from({ length: 100 }, (_, i) =>
      tEdge(`e${i}`, `l${i}`, `r${i}`, "exact"),
    );
    const model = build({ timelineEdges: edges });
    expect(model.chains).toHaveLength(100);
    expect(model.omittedCount).toBe(0);
  });

  it("keeps the strongest rows when capping", () => {
    const edges = [
      ...Array.from({ length: 100 }, (_, i) =>
        tEdge(`c${i}`, `cl${i}`, `cr${i}`, "candidate"),
      ),
      tEdge("ex", "xl", "xr", "exact"),
    ];
    const model = build({ timelineEdges: edges });
    expect(model.chains[0]?.strength).toBe("exact");
    expect(model.omittedCount).toBe(1);
  });
});

describe("D19 titles", () => {
  it("uses eventId and message head of the highest-severity member", () => {
    const model = build({
      items: [
        eventItem("a", 1000, "info", "starting", 1),
        eventItem("b", 2000, "error", "token broker failed\nsecond line", 1014),
        eventItem("c", 3000, "warning", "retrying", 3),
      ],
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "b", "c", "exact"),
      ],
    });
    expect(model.chains[0]?.title).toBe("1014 · token broker failed");
  });

  it("breaks severity ties by earliest timestamp", () => {
    const model = build({
      items: [
        eventItem("late", 5000, "error", "later failure", 2),
        eventItem("early", 1000, "error", "earlier failure", 1),
      ],
      timelineEdges: [tEdge("e1", "late", "early", "exact")],
    });
    expect(model.chains[0]?.title).toBe("1 · earlier failure");
  });

  it("uses source and line for a log-line member", () => {
    const item = logItem("ime", 1000, 42, "critical");
    const model = build({
      items: [item, eventItem("evt", 2000, "info")],
      timelineEdges: [tEdge("e1", timelineOriginId(item.origin), "evt", "exact")],
    });
    expect(model.chains[0]?.title).toBe("ime · line 42 · log line 42");
  });

  it("uses a finding title only when its evidence covers the whole chain", () => {
    const items = [eventItem("a", 1000, "error", "boom", 7), eventItem("b", 2000)];
    const timelineEdges = [tEdge("e1", "a", "b", "exact")];
    const covering = build({
      items,
      timelineEdges,
      findings: [
        { findingId: "f1", title: "Enrollment failed", originIds: ["a", "b", "z"] },
      ],
    });
    expect(covering.chains[0]?.title).toBe("Enrollment failed");

    const partial = build({
      items,
      timelineEdges,
      findings: [{ findingId: "f1", title: "Enrollment failed", originIds: ["a"] }],
    });
    expect(partial.chains[0]?.title).toBe("7 · boom");
  });

  it("requires a finding to cover unresolved members too", () => {
    const model = build({
      items: [eventItem("a", 1000, "error", "boom", 7)],
      timelineEdges: [tEdge("e1", "a", "z", "exact")],
      findings: [{ findingId: "f1", title: "Finding", originIds: ["a"] }],
    });
    expect(model.chains[0]?.title).toBe("7 · boom");
  });

  it("picks the covering finding with the lowest findingId", () => {
    const model = build({
      items: [eventItem("a", 1000)],
      timelineEdges: [tEdge("e1", "a", "b", "exact")],
      findings: [
        { findingId: "f2", title: "Second", originIds: ["a", "b"] },
        { findingId: "f1", title: "First", originIds: ["a", "b"] },
      ],
    });
    expect(model.chains[0]?.title).toBe("First");
  });

  it("prefers a confirmed failure over other classes, then the lowest findingId", () => {
    const model = build({
      items: [eventItem("a", 1000)],
      timelineEdges: [tEdge("e1", "a", "b", "exact")],
      findings: [
        { findingId: "f1", title: "Symptom", originIds: ["a", "b"], findingClass: "symptom" },
        { findingId: "f9", title: "Confirmed late", originIds: ["a", "b"], findingClass: "confirmedFailure" },
        { findingId: "f5", title: "Confirmed early", originIds: ["a", "b"], findingClass: "confirmedFailure" },
        { findingId: "f0", title: "Unclassed", originIds: ["a", "b"] },
      ],
    });
    expect(model.chains[0]?.title).toBe("Confirmed early");
  });

  it("does not apply a finding title to ambiguous or coverage blocked items", () => {
    const model = build({
      items: [eventItem("a", 1000, "error", "boom", 7)],
      timelineEdges: ambiguousGroup("g", ["a", "b"]),
      findings: [{ findingId: "f1", title: "Finding", originIds: ["a", "b"] }],
    });
    expect(model.chains[0]?.title).toBe("7 · boom");
  });

  it("truncates a long message head", () => {
    const model = build({
      items: [eventItem("a", 1000, "error", "x".repeat(200), 5)],
      timelineEdges: [tEdge("e1", "a", "b", "exact")],
    });
    const title = model.chains[0]?.title ?? "";
    expect(title.startsWith("5 · xxx")).toBe(true);
    expect(title.length).toBeLessThan(90);
  });
});

describe("evidence", () => {
  it("keeps the evidence rows and keys behind each chain edge", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact", {
          key: { kind: "sessionId", value: "S-1" },
          evidence: [
            { originId: "b", field: "sessionId", value: "S-1" },
            { originId: "a", field: "sessionId", value: "S-1" },
          ],
        }),
      ],
    });
    const chain = model.chains[0];
    expect(chain?.keys).toEqual([{ kind: "sessionId", value: "S-1" }]);
    expect(chain?.evidence.map((e) => e.originId)).toEqual(["a", "b"]);
  });
});

describe("input contract", () => {
  it("no longer accepts diagnosisEdges", () => {
    const input: CorrelationChainInput = {
      items: [],
      timelineEdges: [],
      findings: [],
      // @ts-expect-error diagnosis edges are a redacted projection and are not an input
      diagnosisEdges: [],
    };
    expect(buildCorrelationChains(input).totalCount).toBe(0);
    expect("nearby" in buildCorrelationChains(input)).toBe(false);
  });

  it("supplying the same edges twice yields a deep-equal model", () => {
    const edges = [
      tEdge("e1", "a", "b", "exact"),
      tEdge("e2", "b", "c", "candidate"),
      gappedExact("e3", "x", "y"),
      ...ambiguousGroup("g", ["m", "n", "o"]),
    ];
    const items = [eventItem("a", 1000), eventItem("m", 2000)];
    expect(build({ items, timelineEdges: [...edges, ...edges] })).toEqual(
      build({ items, timelineEdges: edges }),
    );
  });
});

describe("D7 at the decoder", () => {
  function timelineWith(strength: string): unknown {
    return {
      items: [],
      unplaced: [],
      coverageGaps: [],
      edges: [
        {
          id: "e1",
          fromId: "a",
          toId: "b",
          key: { kind: "activityId", value: "k" },
          strength,
          confidence: "high",
          candidateIds: [],
          evidence: [],
          coverage: { state: "covered" },
        },
      ],
    };
  }

  it("accepts the strengths the backend produces", () => {
    for (const strength of ["exact", "candidate", "ambiguous"]) {
      expect(() => assertUnifiedTimelineShape(timelineWith(strength))).not.toThrow();
    }
  });

  it("rejects timestampOnly and notCausal edges", () => {
    expect(() => assertUnifiedTimelineShape(timelineWith("timestampOnly"))).toThrow();
    expect(() => assertUnifiedTimelineShape(timelineWith("notCausal"))).toThrow();
  });
});

// ---- property tests -------------------------------------------------------

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface RandomGraph {
  timelineEdges: TimelineCorrelationEdge[];
  items: TimelineItem[];
}

function pick<T>(random: () => number, values: readonly T[]): T {
  return values[Math.floor(random() * values.length)] as T;
}

function randomGraph(seed: number): RandomGraph {
  const random = mulberry32(seed);
  const nodeCount = 2 + Math.floor(random() * 14);
  const node = () => `n${Math.floor(random() * nodeCount)}`;
  const items: TimelineItem[] = [];
  for (let i = 0; i < nodeCount; i += 1) {
    // About one node in four is deliberately left unloaded.
    if (random() < 0.25) continue;
    const copies = random() < 0.2 ? 2 : 1;
    for (let c = 0; c < copies; c += 1) {
      items.push(
        eventItem(
          `n${i}`,
          Math.floor(random() * 5) * 1000,
          pick(random, ["verbose", "info", "warning", "error", "critical"] as const),
          `m${Math.floor(random() * 3)}`,
          Math.floor(random() * 4),
        ),
      );
    }
  }
  const timelineEdges: TimelineCorrelationEdge[] = [];
  const edgeCount = Math.floor(random() * 12);
  for (let i = 0; i < edgeCount; i += 1) {
    const roll = random();
    if (roll < 0.3) {
      const size = 2 + Math.floor(random() * 3);
      const group = [...new Set(Array.from({ length: size }, node))];
      if (group.length >= 2) {
        timelineEdges.push(...ambiguousGroup(`g${i}`, group));
      }
    } else if (roll < 0.45) {
      timelineEdges.push(gappedExact(`x${i}`, node(), node(), `gap${i % 2}`));
    } else {
      timelineEdges.push(
        tEdge(
          `t${i}`,
          node(),
          node(),
          pick(random, ["exact", "candidate"] as const),
          random() < 0.2 ? { key: { kind: "secondary", value: `s${i}` } } : {},
        ),
      );
    }
  }
  // Duplicate some observations so contradictions and repeats both occur.
  const duplicates = timelineEdges.filter(() => random() < 0.25);
  return { items, timelineEdges: [...timelineEdges, ...duplicates] };
}

function shuffled<T>(random: () => number, values: readonly T[]): T[] {
  const copy = [...values];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j] as T, copy[i] as T];
  }
  return copy;
}

/** Swaps the endpoints, keeping the backend invariant candidateIds = group minus fromId. */
function swapped(edge: TimelineCorrelationEdge): TimelineCorrelationEdge {
  if (edge.toId === null) return edge;
  const group = new Set([edge.fromId, ...edge.candidateIds]);
  const candidateIds =
    edge.candidateIds.length === 0
      ? []
      : [...group].filter((id) => id !== edge.toId);
  return { ...edge, fromId: edge.toId, toId: edge.fromId, candidateIds };
}

function isLinkingObservation(edge: TimelineCorrelationEdge): boolean {
  return (
    edge.coverage.state === "covered" &&
    (edge.strength === "exact" || edge.strength === "candidate")
  );
}

function pairKey(a: string, b: string): string {
  return a < b ? `${a}\n${b}` : `${b}\n${a}`;
}

const GRAPH_COUNT = 600;

describe("properties over seeded random backend-shaped graphs", () => {
  it("is identical across permutations of the input, duplicates and contradictions included", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const graph = randomGraph(seed);
      const random = mulberry32(seed * 7919);
      const baseline = build({ ...graph });
      const permuted = build({
        items: shuffled(random, graph.items),
        timelineEdges: shuffled(random, graph.timelineEdges).map((e) =>
          random() < 0.5 ? swapped(e) : e,
        ),
      });
      expect(permuted).toEqual(baseline);
    }
  });

  it("never puts a pair with a non-linking observation inside an exact or candidate row", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const graph = randomGraph(seed);
      const model = build({ ...graph });
      expect(model.omittedCount).toBe(0);

      const vetoed = new Set<string>();
      const linkable = new Set<string>();
      for (const edge of graph.timelineEdges) {
        if (edge.toId === null || edge.toId === edge.fromId) continue;
        const key = pairKey(edge.fromId, edge.toId);
        if (isLinkingObservation(edge)) linkable.add(key);
        else vetoed.add(key);
      }
      const expectedLinks = [...linkable].filter((key) => !vetoed.has(key));

      // Reference components over the non-vetoed linking pairs only.
      const parent = new Map<string, string>();
      const find = (x: string): string => {
        let root = x;
        while ((parent.get(root) ?? root) !== root) root = parent.get(root) as string;
        return root;
      };
      for (const key of expectedLinks) {
        const [a, b] = key.split("\n") as [string, string];
        parent.set(find(a), find(b));
      }
      const components = new Map<string, Set<string>>();
      for (const key of expectedLinks) {
        for (const id of key.split("\n")) {
          const root = find(id);
          const set = components.get(root) ?? new Set<string>();
          set.add(id);
          components.set(root, set);
        }
      }
      const expectedSets = [...components.values()]
        .map((set) => [...set].sort())
        .sort((a, b) => a.join().localeCompare(b.join()));

      const chainRows = model.chains.filter(
        (row) => row.strength === "exact" || row.strength === "candidate",
      );
      for (const row of chainRows) {
        for (const edge of row.edges) {
          expect(edge.right).not.toBeNull();
          const key = pairKey(edge.left, edge.right as string);
          expect(vetoed.has(key)).toBe(false);
          expect(linkable.has(key)).toBe(true);
        }
      }
      const actualSets = chainRows
        .map(allMembers)
        .sort((a, b) => a.join().localeCompare(b.join()));
      expect(actualSets).toEqual(expectedSets);
    }
  });

  it("splits members consistently and cites only ids present in the input edges", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const graph = randomGraph(seed);
      const model = build({ ...graph });
      const loaded = new Set(graph.items.map((i) => timelineOriginId(i.origin)));
      const cited = new Set<string>();
      for (const edge of graph.timelineEdges) {
        cited.add(edge.fromId);
        if (edge.toId !== null) cited.add(edge.toId);
        for (const id of edge.candidateIds) cited.add(id);
        for (const row of edge.evidence) cited.add(row.originId);
      }
      for (const row of model.chains) {
        expect(row.memberCount).toBe(
          row.memberIds.length + row.unresolvedMemberIds.length,
        );
        expect(row.memberIds.every((id) => loaded.has(id))).toBe(true);
        expect(row.unresolvedMemberIds.every((id) => !loaded.has(id))).toBe(true);
        expect([...row.unresolvedMemberIds].sort()).toEqual(row.unresolvedMemberIds);
        for (const id of [...row.memberIds, ...row.unresolvedMemberIds]) {
          expect(cited.has(id)).toBe(true);
        }
        for (const edge of row.edges) {
          expect(cited.has(edge.left)).toBe(true);
          if (edge.right !== null) expect(cited.has(edge.right)).toBe(true);
        }
        for (const ev of row.evidence) expect(cited.has(ev.originId)).toBe(true);
        if (row.memberIds.length === 0) {
          expect(row.startMs).toBeNull();
          expect(row.endMs).toBeNull();
          expect(row.title).toBeNull();
        } else {
          expect(row.startMs).not.toBeNull();
          expect(row.title).not.toBeNull();
        }
      }
    }
  });

  it("keeps counts consistent with the rows and the cap", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const model = build({ ...randomGraph(seed) });
      const sum =
        model.counts.exact +
        model.counts.candidate +
        model.counts.ambiguous +
        model.counts.coverageBlocked;
      expect(model.totalCount).toBe(sum);
      expect(model.chains.length + model.omittedCount).toBe(sum);
      expect(model.chains.length).toBeLessThanOrEqual(CORRELATION_CHAIN_RENDER_LIMIT);
    }
  });

  it("applies the cap of 100 with omittedCount on large random graphs", () => {
    for (let seed = 1; seed <= 20; seed += 1) {
      const random = mulberry32(seed);
      const pairs = 101 + Math.floor(random() * 60);
      const edges = Array.from({ length: pairs }, (_, i) =>
        tEdge(`e${i}`, `l${i}`, `r${i}`, pick(random, ["exact", "candidate"] as const)),
      );
      const model = build({ timelineEdges: shuffled(random, edges) });
      expect(model.chains).toHaveLength(CORRELATION_CHAIN_RENDER_LIMIT);
      expect(model.totalCount).toBe(pairs);
      expect(model.omittedCount).toBe(pairs - CORRELATION_CHAIN_RENDER_LIMIT);
    }
  });

  it("yields a deep-equal model when every edge is supplied twice", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const graph = randomGraph(seed);
      expect(
        build({
          items: graph.items,
          timelineEdges: [...graph.timelineEdges, ...graph.timelineEdges],
        }),
      ).toEqual(build({ ...graph }));
    }
  });
});
