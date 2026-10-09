import { describe, expect, it } from "vitest";
import {
  CORRELATION_CHAIN_RENDER_LIMIT,
  buildCorrelationChains,
  type CorrelationChainInput,
  type CorrelationChainModel,
} from "./evtx-correlation-chains";
import type {
  DiagnosisCorrelationBasis,
  DiagnosisCorrelationEdge,
  DiagnosisCorrelationStatus,
} from "./types";
import type {
  TimelineCorrelationEdge,
  TimelineCorrelationStrength,
  TimelineItem,
  TimelineSeverity,
} from "./unified-timeline";
import { timelineOriginId } from "./unified-timeline";

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

function dEdge(
  left: string,
  right: string | null,
  basis: DiagnosisCorrelationBasis,
  status: DiagnosisCorrelationStatus,
  candidateIds: string[] = [],
): DiagnosisCorrelationEdge {
  return { left, right, basis, status, candidateIds, evidence: [] };
}

function build(input: Partial<CorrelationChainInput>): CorrelationChainModel {
  return buildCorrelationChains({
    items: [],
    timelineEdges: [],
    diagnosisEdges: [],
    findings: [],
    ...input,
  });
}

function chainMemberSets(model: CorrelationChainModel): string[][] {
  return model.chains.map((chain) => [...chain.memberIds].sort());
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
    expect(chainMemberSets(model)).toEqual([["a", "b", "c"], ["x", "y"]]);
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

  it("downgrades an exact edge that rests on a candidate identifier basis", () => {
    const model = build({
      diagnosisEdges: [dEdge("a", "b", "candidateIdentifier", "exact")],
    });
    expect(model.chains[0]?.strength).toBe("candidate");
  });

  it("merges components across the timeline and diagnosis inputs", () => {
    const model = build({
      timelineEdges: [tEdge("e1", "a", "b", "exact")],
      diagnosisEdges: [dEdge("b", "c", "exactIdentifier", "exact")],
    });
    expect(chainMemberSets(model)).toEqual([["a", "b", "c"]]);
  });

  it("does not double count a relation present in both inputs", () => {
    const model = build({
      timelineEdges: [tEdge("e1", "a", "b", "exact")],
      diagnosisEdges: [dEdge("a", "b", "exactIdentifier", "exact")],
    });
    expect(model.counts.exact).toBe(1);
    expect(model.chains[0]?.edges).toHaveLength(1);
  });

  it("treats a timeline edge with a coverage gap as coverage blocked, not a link", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact", {
          coverage: { state: "gap", gap: { source: "s", reason: "r" } },
        }),
      ],
    });
    expect(model.counts).toMatchObject({ exact: 0, coverageBlocked: 1 });
    expect(model.chains[0]?.strength).toBe("coverageBlocked");
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
});

describe("Q-4: ambiguous edges never merge components", () => {
  it("keeps two exact chains separate when an ambiguous edge bridges them", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "c", "d", "exact"),
        tEdge("amb", "b", "c", "ambiguous"),
      ],
    });
    const chains = model.chains.filter((c) => c.strength === "exact");
    expect(chains.map((c) => [...c.memberIds].sort())).toEqual([
      ["a", "b"],
      ["c", "d"],
    ]);
    expect(model.counts).toMatchObject({ exact: 2, ambiguous: 1 });
  });

  it("lists an ambiguous relation as one item with its candidates as members", () => {
    const model = build({
      timelineEdges: [
        tEdge("amb", "a", null, "ambiguous", { candidateIds: ["b", "c"] }),
      ],
    });
    expect(model.chains).toHaveLength(1);
    const item = model.chains[0];
    expect(item?.strength).toBe("ambiguous");
    expect([...(item?.memberIds ?? [])].sort()).toEqual(["a", "b", "c"]);
  });

  it("does not create a chain from ambiguous edges alone", () => {
    const model = build({
      timelineEdges: [
        tEdge("amb1", "a", "b", "ambiguous"),
        tEdge("amb2", "b", "c", "ambiguous"),
      ],
    });
    expect(model.counts).toMatchObject({ exact: 0, candidate: 0, ambiguous: 2 });
    expect(model.chains.every((c) => c.strength === "ambiguous")).toBe(true);
  });

  it("applies the same rule to diagnosis ambiguous and coverageBlocked relations", () => {
    const model = build({
      diagnosisEdges: [
        dEdge("a", "b", "exactIdentifier", "exact"),
        dEdge("c", "d", "exactIdentifier", "exact"),
        dEdge("b", "c", "exactIdentifier", "ambiguous"),
        dEdge("d", "e", "exactIdentifier", "coverageBlocked"),
      ],
    });
    expect(model.counts).toEqual({
      exact: 2,
      candidate: 0,
      ambiguous: 1,
      coverageBlocked: 1,
    });
  });
});

describe("D7: nearby, not linked", () => {
  it("routes timestampOnly basis and notCausal status to nearby only", () => {
    const model = build({
      diagnosisEdges: [
        dEdge("a", "b", "timestampOnly", "ambiguous"),
        dEdge("c", "d", "timestampOnly", "exact"),
        dEdge("e", "f", "exactIdentifier", "notCausal"),
        dEdge("g", "h", "timestampOnly", "coverageBlocked"),
      ],
    });
    expect(model.totalCount).toBe(0);
    expect(model.chains).toEqual([]);
    expect(model.counts).toEqual({
      exact: 0,
      candidate: 0,
      ambiguous: 0,
      coverageBlocked: 0,
    });
    expect(model.nearby).toHaveLength(4);
  });

  it("never lets a nearby relation connect two chains", () => {
    const model = build({
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "c", "d", "exact"),
      ],
      diagnosisEdges: [dEdge("b", "c", "timestampOnly", "exact")],
    });
    expect(chainMemberSets(model)).toEqual([["a", "b"], ["c", "d"]]);
    expect(model.nearby).toHaveLength(1);
  });
});

describe("ordering", () => {
  it("orders exact, candidate, ambiguous, then coverage blocked", () => {
    const model = build({
      diagnosisEdges: [
        dEdge("p", "q", "exactIdentifier", "coverageBlocked"),
        dEdge("m", "n", "exactIdentifier", "ambiguous"),
        dEdge("j", "k", "exactIdentifier", "candidate"),
        dEdge("a", "b", "exactIdentifier", "exact"),
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
      "c1", // 3 members
      "b1", // 2 members, 1000, id b1 before d1
      "d1", // 2 members, 1000
      "a1", // 2 members, 3000
    ]);
  });

  it("sorts members and spans by timestamp, with unknown timestamps last", () => {
    const model = build({
      items: [eventItem("b", 2000), eventItem("a", 1000)],
      timelineEdges: [
        tEdge("e1", "a", "b", "exact"),
        tEdge("e2", "b", "z", "exact"),
      ],
    });
    const chain = model.chains[0];
    expect(chain?.memberIds).toEqual(["a", "b", "z"]);
    expect(chain?.startMs).toBe(1000);
    expect(chain?.endMs).toBe(2000);
  });

  it("leaves the span null when no member has a timeline item", () => {
    const model = build({ timelineEdges: [tEdge("e1", "a", "b", "exact")] });
    expect(model.chains[0]?.startMs).toBeNull();
    expect(model.chains[0]?.endMs).toBeNull();
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
    expect(model.chains[0]?.title).toBe("ime \u00b7 line 42 \u00b7 log line 42");
  });

  it("uses a finding title only when its evidence covers the whole chain", () => {
    const items = [eventItem("a", 1000, "error", "boom", 7), eventItem("b", 2000)];
    const timelineEdges = [tEdge("e1", "a", "b", "exact")];
    const covering = build({
      items,
      timelineEdges,
      findings: [{ findingId: "f1", title: "Enrollment failed", originIds: ["a", "b", "z"] }],
    });
    expect(covering.chains[0]?.title).toBe("Enrollment failed");

    const partial = build({
      items,
      timelineEdges,
      findings: [{ findingId: "f1", title: "Enrollment failed", originIds: ["a"] }],
    });
    expect(partial.chains[0]?.title).toBe("7 · boom");
  });

  it("picks the covering finding with the lowest findingId", () => {
    const model = build({
      timelineEdges: [tEdge("e1", "a", "b", "exact")],
      findings: [
        { findingId: "f2", title: "Second", originIds: ["a", "b"] },
        { findingId: "f1", title: "First", originIds: ["a", "b"] },
      ],
    });
    expect(model.chains[0]?.title).toBe("First");
  });

  it("does not apply a finding title to ambiguous or coverage blocked items", () => {
    const model = build({
      items: [eventItem("a", 1000, "error", "boom", 7)],
      timelineEdges: [tEdge("amb", "a", "b", "ambiguous")],
      findings: [{ findingId: "f1", title: "Finding", originIds: ["a", "b"] }],
    });
    expect(model.chains[0]?.title).toBe("7 · boom");
  });

  it("returns a null title when no member has a timeline item", () => {
    const model = build({ timelineEdges: [tEdge("e1", "a", "b", "exact")] });
    expect(model.chains[0]?.title).toBeNull();
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
  diagnosisEdges: DiagnosisCorrelationEdge[];
  items: TimelineItem[];
}

const BASES: DiagnosisCorrelationBasis[] = [
  "exactIdentifier",
  "candidateIdentifier",
  "timestampOnly",
];
const STATUSES: DiagnosisCorrelationStatus[] = [
  "exact",
  "candidate",
  "ambiguous",
  "coverageBlocked",
  "notCausal",
];
const STRENGTHS: TimelineCorrelationStrength[] = [
  "exact",
  "candidate",
  "ambiguous",
];

function pick<T>(random: () => number, values: readonly T[]): T {
  return values[Math.floor(random() * values.length)] as T;
}

function randomGraph(seed: number): RandomGraph {
  const random = mulberry32(seed);
  const nodeCount = 2 + Math.floor(random() * 14);
  const node = () => `n${Math.floor(random() * nodeCount)}`;
  const items = Array.from({ length: nodeCount }, (_, i) =>
    eventItem(
      `n${i}`,
      Math.floor(random() * 5) * 1000,
      pick(random, ["verbose", "info", "warning", "error", "critical"] as const),
      `m${Math.floor(random() * 3)}`,
      Math.floor(random() * 4),
    ),
  );
  const timelineEdges = Array.from(
    { length: Math.floor(random() * 12) },
    (_, i) =>
      tEdge(
        `t${i}`,
        node(),
        random() < 0.1 ? null : node(),
        pick(random, STRENGTHS),
        {
          candidateIds: random() < 0.3 ? [node(), node()] : [],
          coverage:
            random() < 0.15
              ? { state: "gap", gap: { source: "s", reason: "r" } }
              : { state: "covered" },
        },
      ),
  );
  const diagnosisEdges = Array.from(
    { length: Math.floor(random() * 12) },
    () =>
      dEdge(
        node(),
        random() < 0.1 ? null : node(),
        pick(random, BASES),
        pick(random, STATUSES),
        random() < 0.3 ? [node()] : [],
      ),
  );
  return { items, timelineEdges, diagnosisEdges };
}

function shuffled<T>(random: () => number, values: readonly T[]): T[] {
  const copy = [...values];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j] as T, copy[i] as T];
  }
  return copy;
}

function swapped(edge: DiagnosisCorrelationEdge): DiagnosisCorrelationEdge {
  return edge.right === null
    ? edge
    : { ...edge, left: edge.right, right: edge.left };
}

const GRAPH_COUNT = 600;

describe("properties over seeded random graphs", () => {
  it("never lets a timestampOnly or notCausal relation contribute to a chain or count", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const graph = randomGraph(seed);
      const withNearby = build({ ...graph });
      const nearbyOnly = graph.diagnosisEdges.filter(
        (e) => e.basis === "timestampOnly" || e.status === "notCausal",
      );
      const withoutNearby = build({
        ...graph,
        diagnosisEdges: graph.diagnosisEdges.filter(
          (e) => !nearbyOnly.includes(e),
        ),
      });
      // Removing the nearby relations must not change anything but the nearby list.
      expect(withNearby.chains).toEqual(withoutNearby.chains);
      expect(withNearby.counts).toEqual(withoutNearby.counts);
      expect(withNearby.totalCount).toBe(withoutNearby.totalCount);
      expect(withNearby.nearby.length).toBeGreaterThanOrEqual(
        new Set(nearbyOnly.map((e) => `${e.left}|${e.right}`)).size > 0 ? 1 : 0,
      );
      // A graph made only of nearby relations yields no chain rows at all.
      const onlyNearby = build({
        items: graph.items,
        diagnosisEdges: nearbyOnly,
      });
      expect(onlyNearby.totalCount).toBe(0);
      expect(onlyNearby.chains).toEqual([]);
      expect(onlyNearby.counts).toEqual({
        exact: 0,
        candidate: 0,
        ambiguous: 0,
        coverageBlocked: 0,
      });
    }
  });

  it("is identical across permutations of the input", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const graph = randomGraph(seed);
      const random = mulberry32(seed * 7919);
      const baseline = build({ ...graph });
      const permuted = build({
        items: shuffled(random, graph.items),
        timelineEdges: shuffled(random, graph.timelineEdges),
        diagnosisEdges: shuffled(random, graph.diagnosisEdges).map((e) =>
          random() < 0.5 ? swapped(e) : e,
        ),
      });
      expect(permuted).toEqual(baseline);
    }
  });

  it("never connects chains through an ambiguous, coverage blocked or nearby relation", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const graph = randomGraph(seed);
      const model = build({ ...graph });
      // Rebuild expected components with a reference union-find that only sees
      // exact and candidate relations.
      const parent = new Map<string, string>();
      const find = (x: string): string => {
        let root = parent.get(x) ?? x;
        while ((parent.get(root) ?? root) !== root) root = parent.get(root) as string;
        parent.set(x, root);
        return root;
      };
      const union = (a: string, b: string) => parent.set(find(a), find(b));
      const linkable: Array<[string, string]> = [];
      for (const e of graph.timelineEdges) {
        if (
          e.coverage.state === "covered" &&
          (e.strength === "exact" || e.strength === "candidate") &&
          e.toId !== null &&
          e.toId !== e.fromId
        ) {
          linkable.push([e.fromId, e.toId]);
        }
      }
      for (const e of graph.diagnosisEdges) {
        if (
          e.basis !== "timestampOnly" &&
          (e.status === "exact" || e.status === "candidate") &&
          e.right !== null &&
          e.right !== e.left
        ) {
          linkable.push([e.left, e.right]);
        }
      }
      for (const [a, b] of linkable) union(a, b);
      const expected = new Map<string, string[]>();
      for (const [a, b] of linkable) {
        for (const id of [a, b]) {
          const root = find(id);
          expected.set(root, [...(expected.get(root) ?? []), id]);
        }
      }
      const expectedSets = [...expected.values()]
        .map((ids) => [...new Set(ids)].sort())
        .sort((a, b) => a.join().localeCompare(b.join()));
      const actualSets = model.chains
        .filter((c) => c.strength === "exact" || c.strength === "candidate")
        .map((c) => [...c.memberIds].sort())
        .sort((a, b) => a.join().localeCompare(b.join()));
      // The cap is not reached by these small graphs.
      expect(model.omittedCount).toBe(0);
      expect(actualSets).toEqual(expectedSets);
    }
  });

  it("keeps counts consistent with the rows", () => {
    for (let seed = 1; seed <= GRAPH_COUNT; seed += 1) {
      const model = build({ ...randomGraph(seed) });
      const sum =
        model.counts.exact +
        model.counts.candidate +
        model.counts.ambiguous +
        model.counts.coverageBlocked;
      expect(model.totalCount).toBe(sum);
      expect(model.chains.length + model.omittedCount).toBe(sum);
    }
  });
});
