/**
 * The order the record grid renders, shared by the grid and by Details Previous and Next so the
 * two cannot drift: sorted by the grid's sort, grouped by Group by, and with the records of
 * collapsed groups left out (they are not rows).
 */
import { buildGroupedRows, type EvtxGroupField } from "./evtx-filter";
import type { EvtxSortDirection, EvtxSortField } from "./evtx-store";
import type { EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

const LEVEL_ORDER: Record<EvtxLevel, number> = {
  Critical: 0,
  Error: 1,
  Warning: 2,
  Information: 3,
  Verbose: 4,
};

export function compareRecords(
  a: EvtxRecord,
  b: EvtxRecord,
  field: EvtxSortField,
  direction: EvtxSortDirection,
): number {
  let cmp = 0;
  switch (field) {
    case "time":
      cmp = a.timestampEpoch - b.timestampEpoch;
      break;
    case "eventId":
      cmp = a.eventId - b.eventId;
      break;
    case "level":
      cmp = LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level];
      break;
    case "provider":
      cmp = a.provider.localeCompare(b.provider);
      break;
    case "channel":
      cmp = a.channel.localeCompare(b.channel);
      break;
  }
  return direction === "asc" ? cmp : -cmp;
}

export function sortForGrid(
  records: readonly EvtxRecord[],
  field: EvtxSortField,
  direction: EvtxSortDirection,
): EvtxRecord[] {
  return [...records].sort((a, b) => compareRecords(a, b, field, direction));
}

/** The records that have a row, in row order. */
export function renderedRecords(
  sorted: EvtxRecord[],
  groupBy: EvtxGroupField[],
  collapsedGroups: ReadonlySet<string>,
  timeZoneMode: EvtxTimeZoneMode,
): EvtxRecord[] {
  const records: EvtxRecord[] = [];
  for (const row of buildGroupedRows(sorted, groupBy, collapsedGroups, timeZoneMode)) {
    if (row.kind === "record") records.push(row.record);
  }
  return records;
}
