/** The part of a chain row a window can draw: members with an item, in time order, and the rest counted. */
import { describe, expect, it } from "vitest";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import { chainInWindow } from "./evtx-correlation-chain-in-window";
import { eventItem, recordFor, rid, synthetic } from "./evtx-correlation-test-fixtures";
import { timelineOriginId, type TimelineItem } from "./unified-timeline";

describe("chainInWindow (the adapter between a row and the plot)", () => {
  const t = recordFor(1).timestampEpoch;
  const mapOf = (...items: TimelineItem[]) => new Map(items.map((item) => [timelineOriginId(item.origin), item]));
  const row = (memberIds: string[], unresolvedMemberIds: string[] = []) => {
    const edges = [synthetic("e1", rid(1), rid(2)), synthetic("e2", rid(2), rid(3))];
    const model = buildCorrelationChains({ items: [], timelineEdges: edges, totalTimelineEdges: 2, findings: [] });
    const full = model.chains[0]!;
    return { ...full, memberIds, unresolvedMemberIds };
  };

  it("places the members that have an item, in time order, and lists the rest as having none", () => {
    const part = chainInWindow(row([], [rid(3), rid(1), rid(2)]), rid(1), mapOf(eventItem(1, t + 5_000), eventItem(3, t)));
    expect(part.memberIds).toEqual([rid(3), rid(1)]);
    expect(part.unresolvedMemberIds).toEqual([rid(2)]);
  });

  it("gives the same part for a counts-only row (every member unresolved) and a full row (members resolved)", () => {
    const items = mapOf(eventItem(1, t), eventItem(2, t + 1_000), eventItem(3, t + 2_000));
    const countsOnly = chainInWindow(row([], [rid(1), rid(2), rid(3)]), rid(1), items);
    const full = chainInWindow(row([rid(1), rid(2), rid(3)], []), rid(1), items);
    expect(full).toEqual(countsOnly);
    expect(full.memberIds).toEqual([rid(1), rid(2), rid(3)]);
    expect(full.unresolvedMemberIds).toEqual([]);
  });

  it("takes the span from the placed members only, never from members that have no item", () => {
    const part = chainInWindow(row([], [rid(3), rid(1), rid(2)]), rid(1), mapOf(eventItem(1, t + 4_000), eventItem(2, t + 9_000)));
    expect(part.startMs).toBe(t + 4_000);
    expect(part.endMs).toBe(t + 9_000);
    expect(part.unresolvedMemberIds).toEqual([rid(3)]);
  });

  it("breaks a tie on time by id, so the order does not depend on the row's own order", () => {
    const items = mapOf(eventItem(2, t), eventItem(1, t), eventItem(3, t));
    const forward = chainInWindow(row([], [rid(1), rid(2), rid(3)]), rid(1), items);
    const reversed = chainInWindow(row([], [rid(3), rid(2), rid(1)]), rid(1), items);
    expect(forward.memberIds).toEqual([rid(1), rid(2), rid(3)]);
    expect(reversed).toEqual(forward);
  });

  it("hands the row's edges and evidence over untouched, and does not change the row", () => {
    const given = row([], [rid(1), rid(2), rid(3)]);
    const before = JSON.stringify(given);
    const part = chainInWindow(given, rid(1), mapOf(eventItem(1, t)));
    expect(part.edges).toBe(given.edges);
    expect(part.evidence).toBe(given.evidence);
    expect(JSON.stringify(given)).toBe(before);
  });

  it("is the origin alone, with no edge, no evidence and nothing unresolved, when the event is in no row", () => {
    expect(chainInWindow(null, rid(1), mapOf(eventItem(1, t + 3_000), eventItem(2, t)))).toEqual({
      memberIds: [rid(1)],
      unresolvedMemberIds: [],
      edges: [],
      evidence: [],
      startMs: t + 3_000,
      endMs: t + 3_000,
    });
  });

  it("is empty, with no span, when there is no row and no origin, or the origin has no item", () => {
    const empty = { memberIds: [], unresolvedMemberIds: [], edges: [], evidence: [], startMs: null, endMs: null };
    expect(chainInWindow(null, null, mapOf(eventItem(1, t)))).toEqual(empty);
    expect(chainInWindow(null, rid(9), mapOf(eventItem(1, t)))).toEqual(empty);
  });

  it("lists every member as having no item, with no span, when none has one", () => {
    const part = chainInWindow(row([], [rid(1), rid(2)]), rid(1), new Map());
    expect(part.memberIds).toEqual([]);
    expect(part.unresolvedMemberIds).toEqual([rid(1), rid(2)]);
    expect(part.startMs).toBeNull();
    expect(part.endMs).toBeNull();
  });
});
