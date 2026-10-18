/**
 * Pure derivations for the Event Logs Charts view (spec 8.10). No React, no
 * colors, no stores: the view hands in plain data and gets plain data back.
 *
 * Evidence-first rules this module keeps:
 * - A KPI sublabel exists only when it can be derived from the input (D15).
 *   Comparative sublabels ("vs prior 24 h") exist only when the input carries
 *   a comparison, and the caller hands one in only when it is complete and
 *   current. Without one the sublabel is omitted, never estimated. A ratio
 *   is never formed from a prior count of 0 (no "infinity"), and one that would
 *   round to 1 or to 0 is stated as the two counts instead.
 * - An event without a usable timestamp is counted as unplaced. It is never
 *   put in hour 0. "Usable" mirrors the engine (`parsed_timestamp_epoch` in
 *   `src-tauri/src/event_log/timeline.rs`): a non-zero epoch, or text that
 *   parses as RFC 3339 (the date and time may be separated by "T", "t" or a
 *   space, and the offset may use the U+2212 minus sign, as chrono accepts) or
 *   as `%Y-%m-%dT%H:%M:%S%.f` read as UTC. Hours are 00 to 23 in both, as in
 *   chrono (`T24:00:00` stays unplaced). One deliberate narrowing: second 60 (a
 *   leap second, which chrono accepts) stays unplaced, because JavaScript
 *   cannot represent it. Display text such as
 *   "2026-11-01 01:30:00.000" is never guessed at.
 * - Archived text-log lines (`originKind: "log"`) are not Windows events. They
 *   count toward the visible total and the level counts and hours, which
 *   follow the visible rows, but not toward anything keyed by event ID or
 *   channel: distinct IDs, top IDs, the Warnings and Critical sublabels, and
 *   the channel figures.
 * - Hide rules that are not understood or that do not filter (an invalid
 *   Event ID list) are not reported as exclusions.
 */
import type { ComparableWindow } from "./evtx-comparison";
import type { CorrelationChainModel } from "./evtx-correlation-chains";
import {
  isEventRecord,
  parseEventIdSelectors,
  type EvtxQuickFilter,
} from "./evtx-filter";
import type { EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxLevel, EvtxRecord, EvtxTimeWindow } from "./types";

/** Top event IDs shown in figure 2 (spec 8.10). */
export const TOP_EVENT_ID_LIMIT = 9;
/** Channel rows shown in figures 1 and 3. The rest are counted, not drawn. */
export const CHANNEL_ROW_LIMIT = 12;
export const HOURS_PER_DAY = 24;
/** Matches `heatSteps.length` in the visual tokens (six fixed steps, D11). */
const HEAT_STEP_COUNT = 6;
const QUALIFIER_QUERY_LIMIT = 32;
/** Off-order channels spread over this many color indexes after the ordered ones. */
const OFF_ORDER_SPAN = 6;

/** FNV-1a over UTF-16 code units: a small, stable, dependency-free hash. */
function stableNameHash(name: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < name.length; i += 1) {
    hash ^= name.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash;
}

/** The record fields the Charts view reads. `EvtxRecord` satisfies it. */
export type EvtxChartRecord = Pick<
  EvtxRecord,
  "channel" | "provider" | "eventId" | "level" | "timestamp" | "originKind" | "sourceLabel"
> & {
  /** Absent or non-finite means the event has no usable time. */
  timestampEpoch?: number | null;
};

/** What the chains KPI needs from the merged chain model (D7: Exact + Candidate only). */
export type EvtxChartChainSummary = Pick<
  CorrelationChainModel,
  "counts" | "edgeInputComplete"
>;

/**
 * What the delta sublabels need of a comparison (spec 8.16). Supplied only for a comparison that
 * finished complete and still describes the period the tiles show; a partial, refused, running or
 * out-of-date comparison supplies none, so no delta is shown for it.
 */
export interface EvtxChartComparison {
  /** The window both periods have, named as the Events tile names it. */
  window: ComparableWindow;
  /** Counted over the comparison's own current period, not over the rows the tiles count. */
  current: { errors: number; distinctIds: ReadonlySet<string> };
  prior: { errors: number; distinctIds: ReadonlySet<string> };
}

export interface EvtxChartInput {
  records: readonly EvtxChartRecord[];
  /** Null when no chain model exists yet; the chains KPI then has no value. */
  chains: EvtxChartChainSummary | null;
  /** Active quick filters. Only `action: "hide"` rules are read. */
  hideRules: readonly EvtxQuickFilter[];
  /** Channel display order (spec 8.6); an index here is the channel's color index. */
  channelOrder: readonly string[];
  timeZoneMode: EvtxTimeZoneMode;
  /**
   * Loaded channels, from `loadedChannelCountFor`: live mode counts the channels whose load
   * completed; files mode counts the distinct channel names of the loaded event records.
   */
  loadedChannelCount: number;
  /** Distinct text-log sources, from `countTextLogSources` (sources, not lines). */
  textLogCount: number;
  /** A complete, current comparison with the previous period; absent when there is none. */
  comparison?: EvtxChartComparison | null;
}

export type EvtxChartKpiId =
  | "events"
  | "errors"
  | "warnings"
  | "critical"
  | "distinctIds"
  | "chains";

/** The glyph a trend sublabel starts with, followed by one space. */
export const TREND_GLYPH = { up: "\u25b2", down: "\u25bc" } as const;

export interface EvtxChartKpi {
  id: EvtxChartKpiId;
  label: string;
  /** Null when the value is not available (no chain model). */
  value: number | null;
  /** Present only when derivable from the input. */
  sublabel: string | null;
  /**
   * The direction of a ratio sublabel, which then starts with `TREND_GLYPH[trend]` and a space so a
   * reader that cannot say a glyph can say the direction instead. Null for every other sublabel,
   * counts included: an arrow only ever sits beside a ratio that says which way it moved.
   */
  trend: "up" | "down" | null;
  /** True exactly when the sublabel is a comparison delta, so the view can colour it for contrast. */
  comparative: boolean;
}

export interface EvtxChartChannelBar {
  channel: string;
  /** Position in channel display order, for `channelColor(i)`. */
  colorIndex: number;
  count: number;
  errors: number;
  warnings: number;
}

export interface EvtxChartTopId {
  eventId: number;
  provider: string;
  count: number;
}

export interface EvtxChartHeatRow {
  channel: string;
  colorIndex: number;
  /** Events per hour of day, 24 entries. Unplaced events are in no entry. */
  counts: number[];
  /** Fixed step per hour: -1 for an empty cell, else 0 to `HEAT_STEP_COUNT - 1`. */
  steps: number[];
}

export interface EvtxChartHourly {
  hour: number;
  errors: number;
  warnings: number;
}

export interface EvtxChartPeak {
  hour: number;
  /** Errors plus warnings in that hour. */
  count: number;
  /** "HH:00" in the requested clock. */
  label: string;
}

export interface EvtxChartData {
  kpis: EvtxChartKpi[];
  totalEvents: number;
  /** Largest channels first; capped at `CHANNEL_ROW_LIMIT`. */
  channels: EvtxChartChannelBar[];
  /** Channels and events beyond the cap. */
  omittedChannels: { channels: number; events: number };
  topIds: EvtxChartTopId[];
  /** "excluding 7036 / 16384" from the active hide rules, or null when none apply. */
  topIdsQualifier: string | null;
  heatMap: { rows: EvtxChartHeatRow[]; maxCount: number };
  hourly: EvtxChartHourly[];
  /** Null when no placed event is an error or a warning. */
  peak: EvtxChartPeak | null;
  /** Visible rows (events and text-log lines) with no usable timestamp: never placed in an hour. */
  unplacedCount: number;
  /** The same, events only: the rows figure 3 would draw. */
  unplacedEventCount: number;
  /** Unplaced rows at level Error or Warning (events and text-log lines): the rows figure 4 would draw. */
  unplacedErrorWarningCount: number;
  /** Text-log lines among the visible rows. They have no channel, so figures 1 and 3 omit them. */
  textLogLineCount: number;
}

/** The window as the Events tile names it: "24 h", "7 d", or "all loaded" when none applies. */
export function chartWindowLabel(window: EvtxTimeWindow): string {
  switch (window) {
    case "1h":
      return "1 h";
    case "24h":
      return "24 h";
    case "7d":
      return "7 d";
    case "30d":
      return "30 d";
    case "all":
      return "all loaded";
  }
}

/**
 * Distinct text-log sources: the file paths of the attached log entries plus the
 * source labels of archived text-log records, de-duplicated across both. This
 * counts sources, not lines (`EventLogAnalysisSessionStatus.logItems` counts
 * placed lines).
 */
export function countTextLogSources(
  entries: readonly { filePath: string }[],
  records: readonly Pick<EvtxChartRecord, "originKind" | "sourceLabel">[],
): number {
  const sources = new Set<string>();
  for (const entry of entries) sources.add(entry.filePath);
  for (const record of records) {
    if (!isEventRecord(record)) sources.add(record.sourceLabel);
  }
  return sources.size;
}

/**
 * Loaded channels. Live mode counts the channels whose load completed
 * (`loadedChannels`, not every enumerated channel). Files mode counts the
 * distinct channel names of the loaded EVENT records: an archived text log is not
 * a channel (its record's channel is its source label), a channel present in
 * several files (a rotated `Archive-System-*.evtx` beside `System.evtx`) counts
 * once, and a file with no records adds nothing.
 */
export function loadedChannelCountFor(input: {
  sourceMode: "files" | "live" | null;
  loadedChannels: ReadonlySet<string>;
  records: readonly Pick<EvtxChartRecord, "channel" | "originKind">[];
}): number {
  if (input.sourceMode === "live") return input.loadedChannels.size;
  const names = new Set<string>();
  for (const record of input.records) {
    if (isEventRecord(record)) names.add(record.channel);
  }
  return names.size;
}

const pad2 = (value: number) => String(value).padStart(2, "0");

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

const RFC3339 =
  /^\d{4}-\d{2}-\d{2}[Tt ](?:[01]\d|2[0-3]):\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;
const NAIVE_ISO = /^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):\d{2}:\d{2}(?:\.\d+)?$/;

/** False when the date part names a day its month does not have (leap years included). */
function dayExists(text: string): boolean {
  const year = Number(text.slice(0, 4));
  const month = Number(text.slice(5, 7));
  const day = Number(text.slice(8, 10));
  if (month < 1 || month > 12 || day < 1) return false;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const length = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  return day <= length;
}

/**
 * The event time in epoch milliseconds, or null when the engine would call it
 * missing. Mirrors `parsed_timestamp_epoch`: a non-zero epoch is taken as is;
 * a zero epoch falls back to the text, which must be RFC 3339 (separator "T",
 * "t" or a space; a U+2212 minus sign in the offset is read as "-"; hours 00 to
 * 23) or a zone-less `T` ISO form read as UTC. Second 60 stays unplaced (see the
 * module header). A day beyond its month's length is rejected before parsing,
 * as chrono does. Never `Date.parse` on a display string.
 */
function placedEpochMs(
  record: Pick<EvtxChartRecord, "timestamp" | "timestampEpoch">,
): number | null {
  const epoch = record.timestampEpoch;
  if (typeof epoch !== "number" || !Number.isFinite(epoch)) return null;
  if (epoch !== 0) return epoch;
  // U+2212 is read as "-" only as the offset sign, never between date parts.
  const text = (record.timestamp?.trim() ?? "").replace(/\u2212(?=\d{2}:\d{2}$)/, "-");
  if (RFC3339.test(text) && dayExists(text)) {
    const parsed = Date.parse(text.replace(/^(\d{4}-\d{2}-\d{2})[Tt ]/, "$1T").toUpperCase());
    return Number.isNaN(parsed) ? null : parsed;
  }
  if (NAIVE_ISO.test(text) && dayExists(text)) {
    const parsed = Date.parse(`${text}Z`);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

/** The hour of day (0 to 23) of an event, or null when it has no usable time. */
export function hourOfDay(
  record: Pick<EvtxChartRecord, "timestamp" | "timestampEpoch">,
  mode: EvtxTimeZoneMode,
): number | null {
  const epoch = placedEpochMs(record);
  if (epoch === null) return null;
  const date = new Date(epoch);
  const hour = mode === "utc" ? date.getUTCHours() : date.getHours();
  return Number.isNaN(hour) ? null : hour;
}

/**
 * The heat step for a cell: -1 for an empty cell, otherwise 0 (faintest) to
 * `stepCount - 1`, scaling the cell against the largest cell. Any non-empty
 * cell gets at least the faintest step.
 */
export function heatStepIndex(
  count: number,
  maxCount: number,
  stepCount = HEAT_STEP_COUNT,
): number {
  if (count <= 0 || maxCount <= 0) return -1;
  const step = Math.ceil((count / maxCount) * stepCount) - 1;
  return Math.min(stepCount - 1, Math.max(0, step));
}

/**
 * The caption qualifier for the top-IDs figure, built from the active hide
 * rules. Event ID rules list their IDs and ranges; other hide rules list their
 * query. A rule that does not filter (empty, or an invalid ID list) is left out.
 */
export function buildHideRuleQualifier(
  hideRules: readonly EvtxQuickFilter[],
): string | null {
  const parts: string[] = [];
  const seen = new Set<string>();
  const add = (part: string) => {
    if (!seen.has(part)) {
      seen.add(part);
      parts.push(part);
    }
  };
  for (const rule of hideRules) {
    if (rule.action !== "hide") continue;
    const query = rule.query.trim();
    if (!query) continue;
    if (rule.mode === "eventIds") {
      const parsed = parseEventIdSelectors(query);
      if (parsed.invalid) continue;
      for (const selector of parsed.selectors) {
        add(
          selector.kind === "single"
            ? String(selector.id)
            : `${selector.low}-${selector.high}`,
        );
      }
    } else {
      const shown =
        query.length > QUALIFIER_QUERY_LIMIT
          ? `${query.slice(0, QUALIFIER_QUERY_LIMIT)}...`
          : query;
      add(`matching "${shown}"`);
    }
  }
  return parts.length === 0 ? null : `excluding ${parts.join(" / ")}`;
}

interface IdTally {
  eventId: number;
  provider: string;
  count: number;
}

/** Count descending, then event ID ascending, then provider ascending: a total order. */
function compareIdTally(a: IdTally, b: IdTally): number {
  return (
    b.count - a.count ||
    a.eventId - b.eventId ||
    (a.provider < b.provider ? -1 : a.provider > b.provider ? 1 : 0)
  );
}

function rankIds(tally: Map<string, IdTally>): IdTally[] {
  return [...tally.values()].sort(compareIdTally);
}

function bump(tally: Map<string, IdTally>, record: EvtxChartRecord): void {
  const key = `${record.provider.length}:${record.provider}|${record.eventId}`;
  const existing = tally.get(key);
  if (existing) existing.count += 1;
  else
    tally.set(key, {
      eventId: record.eventId,
      provider: record.provider,
      count: 1,
    });
}

/** A count as the tiles print it. */
const count = (value: number) => value.toLocaleString();

/**
 * The Errors delta: a ratio of the current count to the previous one, or the two counts when no
 * ratio can be said truthfully.
 *
 * The ratio is current over previous for an increase and a decrease alike (a drop to two fifths
 * reads 0.4, never 2.5 lower), to one decimal below 10 and to a whole number from 10, with ".0"
 * dropped. It is formed only from two non-zero counts that differ, and only when its rounded form
 * is neither 1 nor 0, so an arrow is never printed beside a number that says nothing moved or that
 * everything went. A previous count of 0 has no ratio at all and reads as a count against 0.
 */
function errorsDelta(
  current: number,
  prior: number,
  window: string,
): { sublabel: string; trend: "up" | "down" | null } {
  const counts = (text: string) => ({ sublabel: text, trend: null });
  if (prior === 0 && current > 0) {
    return counts(`${count(current)} new vs 0 in prior ${window}`);
  }
  if (current === 0 || prior === 0 || current === prior) {
    return counts(`${count(current)} vs ${count(prior)} in prior ${window}`);
  }
  // Integer arithmetic, so a ratio near a rounding boundary is decided the same way everywhere.
  const tenths = Math.round((current * 10) / prior);
  if (tenths === 10 || tenths === 0) {
    return counts(`${count(current)} vs ${count(prior)} in prior ${window}`);
  }
  const ratio = tenths >= 100 ? count(Math.round(current / prior)) : String(tenths / 10);
  const trend = current > prior ? "up" : "down";
  return { sublabel: `${TREND_GLYPH[trend]} ${ratio}\u00d7 vs prior ${window}`, trend };
}

/** The IDs of the current period that the previous one did not have. */
function newIdCount(
  current: ReadonlySet<string>,
  prior: ReadonlySet<string>,
): number {
  let fresh = 0;
  for (const id of current) if (!prior.has(id)) fresh += 1;
  return fresh;
}

export function buildEvtxChartData(input: EvtxChartInput): EvtxChartData {
  const {
    records,
    chains,
    hideRules,
    channelOrder,
    timeZoneMode,
    loadedChannelCount,
    textLogCount,
    comparison,
  } = input;

  const byLevel: Record<EvtxLevel, number> = {
    Critical: 0,
    Error: 0,
    Warning: 0,
    Information: 0,
    Verbose: 0,
  };
  const allIds = new Map<string, IdTally>();
  const warningIds = new Map<string, IdTally>();
  const criticalIds = new Map<string, IdTally>();
  const perChannel = new Map<
    string,
    { count: number; errors: number; warnings: number; hours: number[] }
  >();
  const hourly: EvtxChartHourly[] = Array.from(
    { length: HOURS_PER_DAY },
    (_, hour) => ({ hour, errors: 0, warnings: 0 }),
  );
  let unplacedCount = 0;
  let unplacedEventCount = 0;
  let unplacedErrorWarningCount = 0;
  let textLogLineCount = 0;

  for (const record of records) {
    byLevel[record.level] += 1;
    const isEvent = isEventRecord(record);
    if (isEvent) {
      bump(allIds, record);
      if (record.level === "Warning") bump(warningIds, record);
      if (record.level === "Critical") bump(criticalIds, record);
    }

    const hour = hourOfDay(record, timeZoneMode);
    if (hour === null) unplacedCount += 1;
    if (hour === null && isEvent) unplacedEventCount += 1;
    if (hour === null && (record.level === "Error" || record.level === "Warning")) {
      unplacedErrorWarningCount += 1;
    }
    if (!isEvent) textLogLineCount += 1;
    if (hour !== null) {
      if (record.level === "Error") hourly[hour].errors += 1;
      else if (record.level === "Warning") hourly[hour].warnings += 1;
    }

    if (!isEvent) continue;
    let channel = perChannel.get(record.channel);
    if (!channel) {
      channel = {
        count: 0,
        errors: 0,
        warnings: 0,
        hours: new Array<number>(HOURS_PER_DAY).fill(0),
      };
      perChannel.set(record.channel, channel);
    }
    channel.count += 1;
    if (record.level === "Error") channel.errors += 1;
    else if (record.level === "Warning") channel.warnings += 1;
    if (hour !== null) channel.hours[hour] += 1;
  }

  // Colors follow display order, so a channel keeps its color when a filter
  // empties others. A channel outside the display order gets an index derived
  // from its own name only (never from which other channels are visible), so
  // its color is stable across filters. `channelColor` cycles every six, so an
  // off-order channel can share a color with a pane channel; the label next to
  // each bar, not the color, identifies it.
  const orderIndex = new Map<string, number>();
  channelOrder.forEach((name, index) => {
    if (!orderIndex.has(name)) orderIndex.set(name, index);
  });
  for (const name of perChannel.keys()) {
    if (!orderIndex.has(name)) {
      orderIndex.set(name, channelOrder.length + stableNameHash(name) % OFF_ORDER_SPAN);
    }
  }

  const ranked: EvtxChartChannelBar[] = [...perChannel.entries()]
    .map(([channel, tally]) => ({
      channel,
      colorIndex: orderIndex.get(channel) ?? 0,
      count: tally.count,
      errors: tally.errors,
      warnings: tally.warnings,
    }))
    .sort(
      (a, b) =>
        b.count - a.count ||
        (a.channel < b.channel ? -1 : a.channel > b.channel ? 1 : 0),
    );
  const channels = ranked.slice(0, CHANNEL_ROW_LIMIT);
  const omitted = ranked.slice(CHANNEL_ROW_LIMIT);

  const heatRows = channels.map((bar) => ({
    channel: bar.channel,
    colorIndex: bar.colorIndex,
    counts: perChannel.get(bar.channel)!.hours,
  }));
  const maxCount = heatRows.reduce(
    (max, row) => Math.max(max, ...row.counts),
    0,
  );

  let peak: EvtxChartPeak | null = null;
  for (const bucket of hourly) {
    const count = bucket.errors + bucket.warnings;
    // Strict comparison keeps the earliest hour on a tie.
    if (count > 0 && (peak === null || count > peak.count)) {
      peak = { hour: bucket.hour, count, label: `${pad2(bucket.hour)}:00` };
    }
  }

  // The share is of every warning on the tile. A text-log warning line has no
  // event ID, so it counts toward the denominator and is never a top ID.
  const rankedWarnings = rankIds(warningIds);
  const warningSublabel =
    rankedWarnings.length >= 2
      ? `Top 2 IDs = ${Math.round(
          ((rankedWarnings[0].count + rankedWarnings[1].count) /
            byLevel.Warning) *
            100,
        )}%`
      : null;
  const topCritical = rankIds(criticalIds)[0];

  const exact = chains?.counts.exact ?? 0;
  const chainCount = chains ? exact + chains.counts.candidate : null;
  // A zero from a bounded edge preview is not a definite zero: whenever the
  // edges are a loaded subset the qualifier shows, whatever the count.
  const chainsSublabel = !chains
    ? null
    : !chains.edgeInputComplete
      ? `${exact} exact, loaded edges only`
      : chainCount! > 0
        ? `${exact} exact`
        : null;

  const windowLabel = comparison ? chartWindowLabel(comparison.window) : "";
  const errorsSublabel = comparison
    ? errorsDelta(comparison.current.errors, comparison.prior.errors, windowLabel)
    : null;
  const kpis: EvtxChartKpi[] = [
    {
      id: "events",
      label: "Events",
      value: records.length,
      sublabel:
        records.length === 0
          ? null
          : `${plural(loadedChannelCount, "channel", "channels")} \u00b7 ${plural(
              textLogCount,
              "text log",
              "text logs",
            )}`,
      trend: null,
      comparative: false,
    },
    {
      id: "errors",
      label: "Errors",
      value: byLevel.Error,
      sublabel: errorsSublabel?.sublabel ?? null,
      trend: errorsSublabel?.trend ?? null,
      comparative: errorsSublabel !== null,
    },
    {
      id: "warnings",
      label: "Warnings",
      value: byLevel.Warning,
      sublabel: warningSublabel,
      trend: null,
      comparative: false,
    },
    {
      id: "critical",
      label: "Critical",
      value: byLevel.Critical,
      sublabel: topCritical ? `${topCritical.provider} ${topCritical.eventId}` : null,
      trend: null,
      comparative: false,
    },
    {
      id: "distinctIds",
      label: "Distinct event IDs",
      value: allIds.size,
      sublabel: comparison
        ? `${count(newIdCount(comparison.current.distinctIds, comparison.prior.distinctIds))} new vs prior ${windowLabel}`
        : null,
      trend: null,
      comparative: comparison !== null && comparison !== undefined,
    },
    {
      id: "chains",
      label: "Correlation chains",
      value: chainCount,
      sublabel: chainsSublabel,
      trend: null,
      comparative: false,
    },
  ];

  return {
    kpis,
    totalEvents: records.length,
    channels,
    omittedChannels: {
      channels: omitted.length,
      events: omitted.reduce((sum, bar) => sum + bar.count, 0),
    },
    topIds: rankIds(allIds).slice(0, TOP_EVENT_ID_LIMIT),
    topIdsQualifier: buildHideRuleQualifier(hideRules),
    heatMap: {
      rows: heatRows.map((row) => ({
        ...row,
        steps: row.counts.map((count) => heatStepIndex(count, maxCount)),
      })),
      maxCount,
    },
    hourly,
    peak,
    unplacedCount,
    unplacedEventCount,
    unplacedErrorWarningCount,
    textLogLineCount,
  };
}
