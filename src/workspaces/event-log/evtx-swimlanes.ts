/**
 * The Event Logs swimlanes' data (spec section 8.9), with no React, no canvas and no clock.
 *
 * What it promises, because the view paints from it and the hit test reads it:
 *
 * - The x axis IS the histogram's: the scene is built by `buildHistogram`, over the same records
 *   through the same zone, and keeps its edges. A lane dot sits at `fractionAt(axis, time)`, the
 *   bucket-wise position the brush overlay (`rangeOnPlot`) uses, so a dot and the wash over it can
 *   never disagree, including across a DST change on a chart of whole days.
 * - A record with no usable timestamp cannot be placed. It is in `untimed` and in no lane, so the
 *   lane counts plus `untimed` are the records given (`placed + untimed`, as in the histogram).
 *   Lanes are ranked by what is placed, so a lane never ranks on events it cannot show.
 * - Lanes are the top 12 keys by count and then one "Other" lane folding the rest, except that
 *   when only one key would fold it keeps its own lane: "Other (1 lane)" would hide one name for
 *   nothing.
 * - Every lane keeps its dots in time order, which is also x order. That order is the index the
 *   hit test searches. The store hands the records over sorted by time, so the order is checked
 *   and a lane is sorted only if it is not.
 * - A lane holds the record OBJECTS. `EvtxRecord.id` is an index the store rewrites in place on
 *   every merge, so an id read now may name another event after the next batch; whoever selects a
 *   record reads `.id` at the moment of the click.
 */
import { hasUsableTimestamp } from "./evtx-filter";
import {
  HISTOGRAM_STACK_ORDER,
  buildHistogram,
  describeBucket,
  fractionAt,
  zoneClockFor,
  type EvtxHistogram,
  type HistogramBucket,
  type LevelCounts,
  type ZoneClock,
} from "./evtx-histogram";
import { formatCount } from "./evtx-insights-data";
import {
  formatEventTime,
  formatTimeRange,
  timeZoneLabel,
  type EvtxTimeZoneMode,
} from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

/** What a lane is made of. The order is the Lanes dropdown's (spec 8.9). */
export const SWIMLANE_FIELDS = ["provider", "channel", "eventId"] as const;
export type SwimlaneField = (typeof SWIMLANE_FIELDS)[number];

export const SWIMLANE_FIELD_LABELS: Readonly<Record<SwimlaneField, string>> = {
  provider: "Provider",
  channel: "Channel",
  eventId: "Event ID",
};

/** The noun inside the title "Swimlanes by {provider|channel|event ID}" (spec 8.9). */
export const SWIMLANE_FIELD_NOUNS: Readonly<Record<SwimlaneField, string>> = {
  provider: "provider",
  channel: "channel",
  eventId: "event ID",
};

/** Lanes shown by name before the rest fold into "Other" (spec 8.9). */
export const MAX_NAMED_LANES = 12;

/**
 * A click selects the nearest dot within this many CSS pixels of the pointer, measured from the
 * dot's edge (spec 8.9, acceptance). It lives here because the tooltip words it too.
 */
export const HIT_SLOP_PX = 4;

/** How many folded keys the Other lane names in its description; the count is always complete. */
export const OTHER_DISCLOSURE_LIMIT = 20;

export const OTHER_LANE_ID = "\u0000other";

/**
 * The key a record has in a lane field. The empty-name fallbacks and the event ID as plain digits
 * are `groupValue`'s (`evtx-filter.ts`), so a lane and a group of the same field are named alike
 * (a test holds the two together). Event ID is the ID alone, as Group by and Top event IDs key it;
 * the Charts view's pairs (provider, ID) are a different, finer question.
 */
export function laneKeyOf(record: EvtxRecord, field: SwimlaneField): string {
  switch (field) {
    case "provider":
      return record.provider || "(no provider)";
    case "channel":
      return record.channel || "(no channel)";
    case "eventId":
      return String(record.eventId);
  }
}

/** The slot of a level in `HISTOGRAM_STACK_ORDER`: Verbose 0 up to Critical 4, the severity rank. */
export const LEVEL_SLOT: Readonly<Record<EvtxLevel, number>> = Object.fromEntries(
  HISTOGRAM_STACK_ORDER.map((level, slot) => [level, slot]),
) as Record<EvtxLevel, number>;

export interface SwimlaneLane {
  /** The key of a named lane; `OTHER_LANE_ID` for the folded lane. */
  id: string;
  /** What the label block reads: the key, or `Other (n lanes)`. */
  label: string;
  isOther: boolean;
  /** Keys folded into this lane: zero for a named lane. */
  foldedLaneCount: number;
  /** The folded keys with the most events, at most `OTHER_DISCLOSURE_LIMIT`. */
  foldedKeys: readonly string[];
  /** Placed events in the lane. */
  count: number;
  levelCounts: LevelCounts;
  /** Parallel arrays in time order, one entry per dot. */
  epochs: Float64Array;
  /** 0 to 1 across the plot (`fractionAt` on the scene's axis). */
  fractions: Float64Array;
  /** `LEVEL_SLOT` of each dot. */
  levels: Uint8Array;
  records: readonly EvtxRecord[];
}

export interface SwimlaneScene {
  field: SwimlaneField;
  /** The histogram of the same records: the domain, edges, ladder labels and year rule. */
  axis: EvtxHistogram;
  lanes: readonly SwimlaneLane[];
  /** Records in a lane. `placed + untimed` is the number of records given. */
  placed: number;
  /** Records with no usable timestamp: in no lane. */
  untimed: number;
  /** Distinct keys before folding. */
  keyCount: number;
}

const EMPTY_SCENE_COUNTS: LevelCounts = {
  Critical: 0,
  Error: 0,
  Warning: 0,
  Information: 0,
  Verbose: 0,
};

function compareKeys(a: string, b: string, field: SwimlaneField): number {
  if (field === "eventId") return Number(a) - Number(b);
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Builds the lanes of `records` by `field` on the histogram axis of the same records. Two passes
 * over the records after the axis, one key lookup per record, and no per-lane sort when the
 * records arrive in time order.
 */
export function buildSwimlanes(
  records: readonly EvtxRecord[],
  field: SwimlaneField,
  mode: EvtxTimeZoneMode,
  clock: ZoneClock = zoneClockFor(mode),
  nowMs: number = Date.now(),
): SwimlaneScene {
  const axis = buildHistogram(records, mode, clock, nowMs);
  if (axis.domain === null) {
    return { field, axis, lanes: [], placed: 0, untimed: axis.untimed, keyCount: 0 };
  }

  const idOfKey = new Map<string, number>();
  const keys: string[] = [];
  const keyCounts: number[] = [];
  const keyOfRecord = new Int32Array(records.length).fill(-1);
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (!hasUsableTimestamp(record)) continue;
    const key = laneKeyOf(record, field);
    let id = idOfKey.get(key);
    if (id === undefined) {
      id = keys.length;
      idOfKey.set(key, id);
      keys.push(key);
      keyCounts.push(0);
    }
    keyCounts[id] += 1;
    keyOfRecord[index] = id;
  }

  const ranked = keys
    .map((_, id) => id)
    .sort((a, b) => keyCounts[b] - keyCounts[a] || compareKeys(keys[a], keys[b], field));
  // Thirteen keys are thirteen lanes: an Other that folds one lane names nothing it hides.
  const namedCount = keys.length <= MAX_NAMED_LANES + 1 ? keys.length : MAX_NAMED_LANES;
  const foldedCount = keys.length - namedCount;
  const laneCount = namedCount + (foldedCount > 0 ? 1 : 0);
  const laneOfKey = new Int32Array(keys.length);
  ranked.forEach((id, rank) => {
    laneOfKey[id] = rank < namedCount ? rank : namedCount;
  });

  const laneSize = new Array<number>(laneCount).fill(0);
  for (let id = 0; id < keys.length; id += 1) laneSize[laneOfKey[id]] += keyCounts[id];
  const epochs = laneSize.map((size) => new Float64Array(size));
  const levels = laneSize.map((size) => new Uint8Array(size));
  const laneRecords = laneSize.map(() => [] as EvtxRecord[]);
  const unsorted = new Array<boolean>(laneCount).fill(false);
  for (let index = 0; index < records.length; index += 1) {
    const id = keyOfRecord[index];
    if (id < 0) continue;
    const record = records[index];
    const lane = laneOfKey[id];
    const position = laneRecords[lane].length;
    if (position > 0 && record.timestampEpoch < epochs[lane][position - 1]) unsorted[lane] = true;
    epochs[lane][position] = record.timestampEpoch;
    levels[lane][position] = LEVEL_SLOT[record.level] ?? 0;
    laneRecords[lane].push(record);
  }

  const lanes: SwimlaneLane[] = [];
  for (let lane = 0; lane < laneCount; lane += 1) {
    if (unsorted[lane]) sortLane(epochs[lane], levels[lane], laneRecords[lane]);
    const fractions = new Float64Array(laneSize[lane]);
    const levelCounts = { ...EMPTY_SCENE_COUNTS } as Record<EvtxLevel, number>;
    for (let dot = 0; dot < fractions.length; dot += 1) {
      fractions[dot] = fractionAt(axis, epochs[lane][dot]);
      levelCounts[HISTOGRAM_STACK_ORDER[levels[lane][dot]]] += 1;
    }
    const isOther = foldedCount > 0 && lane === namedCount;
    const named = isOther ? null : keys[ranked[lane]];
    lanes.push({
      id: isOther ? OTHER_LANE_ID : (named as string),
      label: isOther ? `Other (${formatCount(foldedCount)} lanes)` : (named as string),
      isOther,
      foldedLaneCount: isOther ? foldedCount : 0,
      foldedKeys: isOther
        ? ranked.slice(namedCount, namedCount + OTHER_DISCLOSURE_LIMIT).map((id) => keys[id])
        : [],
      count: laneSize[lane],
      levelCounts,
      epochs: epochs[lane],
      fractions,
      levels: levels[lane],
      records: laneRecords[lane],
    });
  }
  return {
    field,
    axis,
    lanes,
    placed: lanes.reduce((sum, lane) => sum + lane.count, 0),
    untimed: axis.untimed,
    keyCount: keys.length,
  };
}

/** Puts a lane in time order, keeping the arrival order of equal times. */
function sortLane(epochs: Float64Array, levels: Uint8Array, records: EvtxRecord[]): void {
  const order = Array.from({ length: records.length }, (_, index) => index).sort(
    (a, b) => epochs[a] - epochs[b] || a - b,
  );
  const sortedEpochs = Float64Array.from(order, (index) => epochs[index]);
  const sortedLevels = Uint8Array.from(order, (index) => levels[index]);
  const sortedRecords = order.map((index) => records[index]);
  epochs.set(sortedEpochs);
  levels.set(sortedLevels);
  for (let index = 0; index < sortedRecords.length; index += 1) records[index] = sortedRecords[index];
}

/** The first dot in time order at or after `epochMs`. */
export function lowerBoundEpoch(epochs: Float64Array, epochMs: number): number {
  let low = 0;
  let high = epochs.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (epochs[middle] < epochMs) low = middle + 1;
    else high = middle;
  }
  return low;
}

/** A lane's dots in `[startMs, endMs)`, as an index range. */
export function laneCellRange(
  lane: SwimlaneLane,
  startMs: number,
  endMs: number,
): { from: number; to: number } {
  return { from: lowerBoundEpoch(lane.epochs, startMs), to: lowerBoundEpoch(lane.epochs, endMs) };
}

/** The per-level counts of a lane in one time cell. */
export function laneCellCounts(lane: SwimlaneLane, startMs: number, endMs: number): HistogramBucket {
  const { from, to } = laneCellRange(lane, startMs, endMs);
  const counts = { ...EMPTY_SCENE_COUNTS } as Record<EvtxLevel, number>;
  for (let dot = from; dot < to; dot += 1) counts[HISTOGRAM_STACK_ORDER[lane.levels[dot]]] += 1;
  return { startMs, endMs, counts, total: to - from };
}

/**
 * The event a keyboard selection in a cell picks: the most severe, and the earliest of those. Null
 * for an empty cell.
 */
export function topEventInCell(
  lane: SwimlaneLane,
  startMs: number,
  endMs: number,
): EvtxRecord | null {
  const { from, to } = laneCellRange(lane, startMs, endMs);
  let best = -1;
  for (let dot = from; dot < to; dot += 1) {
    if (best < 0 || lane.levels[dot] > lane.levels[best]) best = dot;
  }
  return best < 0 ? null : lane.records[best];
}

/**
 * Where the record with this id is drawn, or null if it is not charted (filtered out, untimed, or
 * not loaded). Ids are read now, not when the scene was built: the store rewrites them in place.
 */
export function findRecordInScene(
  scene: SwimlaneScene,
  recordId: number | null,
): { lane: number; dot: number } | null {
  if (recordId === null) return null;
  for (let lane = 0; lane < scene.lanes.length; lane += 1) {
    const dot = scene.lanes[lane].records.findIndex((record) => record.id === recordId);
    if (dot >= 0) return { lane, dot };
  }
  return null;
}

/** The lane at `index` of `lanes`, or null (a cursor held across a rebuild may be past the end). */
export function laneAt(scene: SwimlaneScene, index: number): SwimlaneLane | null {
  return scene.lanes[index] ?? null;
}

/** "{n} events", the label block's second line (spec 8.9). */
export function describeLaneCount(count: number): string {
  return count === 1 ? "1 event" : `${formatCount(count)} events`;
}

/**
 * What the Other lane holds, for its label's title and accessible name: how many keys folded and
 * which, bounded. The count is complete even when the list is not.
 */
export function describeFoldedLanes(lane: SwimlaneLane, field: SwimlaneField): string {
  if (!lane.isOther) return "";
  const noun = SWIMLANE_FIELD_NOUNS[field];
  const shown = lane.foldedKeys.join(", ");
  const rest = lane.foldedLaneCount - lane.foldedKeys.length;
  return (
    `${formatCount(lane.foldedLaneCount)} ${noun} lanes folded into Other: ${shown}` +
    (rest > 0 ? `, and ${formatCount(rest)} more` : "")
  );
}

/**
 * The figure's accessible name: the field, the span actually charted with its zone, like the
 * histogram's. The span is the loaded events', not the time window's.
 */
export function describeSwimlaneFigure(scene: SwimlaneScene, mode: EvtxTimeZoneMode): string {
  const noun = SWIMLANE_FIELD_NOUNS[scene.field];
  const { domain } = scene.axis;
  if (domain === null) return `Events by ${noun}, one lane per ${noun}`;
  return (
    `Events by ${noun} over ` +
    `${formatTimeRange(domain.startMs, domain.endMs, mode, scene.axis.showYear)} ` +
    `(${timeZoneLabel(mode, domain.startMs)}), one lane per ${noun}`
  );
}

/**
 * A lane in one bucket as the slider's value text and the caption read it: the lane, then the
 * bucket's range and counts exactly as the histogram words a bucket.
 */
export function describeLaneCell(
  lane: SwimlaneLane,
  startMs: number,
  endMs: number,
  mode: EvtxTimeZoneMode,
  withYear: boolean,
): string {
  return `${lane.label}, ${describeBucket(laneCellCounts(lane, startMs, endMs), mode, withYear)}`;
}

/**
 * One dot as the tooltip reads it. The record's own provider, ID and channel are always named, so a
 * dot in Other still says what it is. `more` is the number of other events within the hit slop.
 */
export function describeDot(record: EvtxRecord, mode: EvtxTimeZoneMode, more: number): string {
  return (
    `${formatEventTime(record.timestampEpoch, mode)} · ${record.level} · ` +
    `${record.provider || "(no provider)"} ${record.eventId} · ${record.channel || "(no channel)"} ` +
    `(${timeZoneLabel(mode, record.timestampEpoch)})` +
    (more > 0 ? ` · +${formatCount(more)} more within ${HIT_SLOP_PX} px` : "")
  );
}

/** The label block's text sizes: the lane name at f - 1, the count at f - 3 (spec 7.1 and 8.9). */
export function laneLabelFonts(fontSize: number): { namePx: number; countPx: number } {
  return { namePx: Math.max(11, fontSize - 1), countPx: Math.max(10, fontSize - 3) };
}

/** Vertical padding inside a lane's label block. */
const LANE_LABEL_PAD_PX = 6;
const LANE_LINE_HEIGHT = 1.25;
export const MIN_LANE_HEIGHT_PX = 36;

/**
 * A lane is 36 px tall (spec 8.9) at the default size, and taller when its two-line label block
 * needs it: the text sizes follow the list font size, so a fixed 36 clips them at the large end.
 */
export function laneHeightFor(fontSize: number): number {
  const { namePx, countPx } = laneLabelFonts(fontSize);
  const labels = Math.ceil(namePx * LANE_LINE_HEIGHT) + Math.ceil(countPx * LANE_LINE_HEIGHT);
  return Math.max(MIN_LANE_HEIGHT_PX, labels + LANE_LABEL_PAD_PX);
}

/** The label lines' pixel heights, so the DOM and `laneHeightFor` use one number. */
export function laneLabelLineHeights(fontSize: number): { nameLine: number; countLine: number } {
  const { namePx, countPx } = laneLabelFonts(fontSize);
  return {
    nameLine: Math.ceil(namePx * LANE_LINE_HEIGHT),
    countLine: Math.ceil(countPx * LANE_LINE_HEIGHT),
  };
}
