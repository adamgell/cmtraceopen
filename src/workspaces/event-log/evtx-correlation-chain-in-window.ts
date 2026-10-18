/**
 * The adapter between a row of the chain model and the lane plot, for a surface that holds only the
 * entries of a window (the dock): what part of the row it can draw. Pure.
 */
import { compareStrings, type CorrelationChain } from "./evtx-correlation-chains";
import type { PlotChain } from "./evtx-correlation-view-model";
import type { TimelineItem } from "./unified-timeline";

/**
 * The adapter between a row of the model and the lane plot: the part of the row whose entries have
 * an item in `itemsById` (the items the dock can draw), in time order, with the rest listed as
 * members that have no item. The plot places `memberIds` and counts `unresolvedMemberIds` as
 * entries with no item to draw; it never gives those a position.
 *
 * `row` is a row of the counts-only model, whose every member is unresolved, or of a full one; both
 * give the same part. With no row (the event is in none), the one member is the origin itself, with
 * no edge and no evidence, and nothing is unresolved: there is no chain to be partial. With neither
 * a row nor an origin the part is empty. The span is that of the placed members only.
 */
export function chainInWindow(
  row: Pick<CorrelationChain, "memberIds" | "unresolvedMemberIds" | "edges" | "evidence"> | null,
  originId: string | null,
  itemsById: ReadonlyMap<string, TimelineItem>,
): PlotChain {
  const wanted =
    row === null
      ? originId === null
        ? []
        : [originId]
      : [...new Set([...row.memberIds, ...row.unresolvedMemberIds])];
  const timeOf = (id: string) => (itemsById.get(id) as TimelineItem).timestampMs;
  const placed = wanted
    .filter((id) => itemsById.has(id))
    .sort((a, b) => timeOf(a) - timeOf(b) || compareStrings(a, b));
  const placedSet = new Set(placed);
  return {
    memberIds: placed,
    unresolvedMemberIds:
      row === null ? [] : wanted.filter((id) => !placedSet.has(id)).sort(compareStrings),
    edges: row === null ? [] : row.edges,
    evidence: row === null ? [] : row.evidence,
    startMs: placed.length === 0 ? null : timeOf(placed[0] as string),
    endMs: placed.length === 0 ? null : timeOf(placed[placed.length - 1] as string),
  };
}
