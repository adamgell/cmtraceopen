/**
 * Pure derivations for the Event Logs Charts view (spec 8.10). No React, no
 * colors, no stores: the view hands in plain data and gets plain data back.
 *
 * Evidence-first rules this module keeps:
 * - A KPI sublabel exists only when it can be derived from the input (D15).
 *   Comparative sublabels ("vs prior 24 h") need Phase 17b's comparison and
 *   are not produced here.
 * - An event without a usable timestamp is counted as unplaced. It is never
 *   put in hour 0.
 * - Hide rules that are not understood or that do not filter (an invalid
 *   Event ID list) are not reported as exclusions.
 */
import type { CorrelationChainModel } from "./evtx-correlation-chains";
import { parseEventIdSelectors, type EvtxQuickFilter } from "./evtx-filter";
import type { EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

/** Top event IDs shown in figure 2 (spec 8.10). */
export const TOP_EVENT_ID_LIMIT = 9;
/** Channel rows shown in figures 1 and 3. The rest are counted, not drawn. */
export const CHANNEL_ROW_LIMIT = 12;
export const HOURS_PER_DAY = 24;
/** Matches `heatSteps.length` in the visual tokens (six fixed steps, D11). */
export const HEAT_STEP_COUNT = 6;
const QUALIFIER_QUERY_LIMIT = 32;

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

export interface EvtxChartInput {
  records: readonly EvtxChartRecord[];
  /** Null when no chain model exists yet; the chains KPI then has no value. */
  chains: EvtxChartChainSummary | null;
  /** Active quick filters. Only `action: "hide"` rules are read. */
  hideRules: readonly EvtxQuickFilter[];
  /** Channel display order (spec 8.6); an index here is the channel's color index. */
  channelOrder: readonly string[];
  timeZoneMode: EvtxTimeZoneMode;
}

export type EvtxChartKpiId =
  | "events"
  | "errors"
  | "warnings"
  | "critical"
  | "distinctIds"
  | "chains";

export interface EvtxChartKpi {
  id: EvtxChartKpiId;
  label: string;
  /** Null when the value is not available (no chain model). */
  value: number | null;
  /** Present only when derivable from the input. */
  sublabel: string | null;
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
  /** Events with no usable timestamp: counted, never placed in an hour. */
  unplacedCount: number;
}

const pad2 = (value: number) => String(value).padStart(2, "0");

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** The hour of day (0 to 23) of an event, or null when it has no usable time. */
export function hourOfDay(
  record: Pick<EvtxChartRecord, "timestamp" | "timestampEpoch">,
  mode: EvtxTimeZoneMode,
): number | null {
  const epoch = record.timestampEpoch;
  if (typeof epoch !== "number" || !Number.isFinite(epoch)) return null;
  // A zero epoch with no timestamp text is a default value, not 1970.
  if (epoch === 0 && !record.timestamp?.trim()) return null;
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

export function buildEvtxChartData(input: EvtxChartInput): EvtxChartData {
  const { records, chains, hideRules, channelOrder, timeZoneMode } = input;

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
  const channelNames = new Set<string>();
  const textLogs = new Set<string>();
  const perChannel = new Map<
    string,
    { count: number; errors: number; warnings: number; hours: number[] }
  >();
  const hourly: EvtxChartHourly[] = Array.from(
    { length: HOURS_PER_DAY },
    (_, hour) => ({ hour, errors: 0, warnings: 0 }),
  );
  let unplacedCount = 0;

  for (const record of records) {
    byLevel[record.level] += 1;
    bump(allIds, record);
    if (record.level === "Warning") bump(warningIds, record);
    if (record.level === "Critical") bump(criticalIds, record);

    if (record.originKind === "log") textLogs.add(record.sourceLabel);
    else channelNames.add(record.channel);

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

    const hour = hourOfDay(record, timeZoneMode);
    if (hour === null) {
      unplacedCount += 1;
      continue;
    }
    channel.hours[hour] += 1;
    if (record.level === "Error") hourly[hour].errors += 1;
    else if (record.level === "Warning") hourly[hour].warnings += 1;
  }

  // Colors follow display order, so a channel keeps its color when a filter
  // empties others. Channels outside the display order follow it, by name.
  const orderIndex = new Map<string, number>();
  channelOrder.forEach((name, index) => {
    if (!orderIndex.has(name)) orderIndex.set(name, index);
  });
  const extras = [...perChannel.keys()]
    .filter((name) => !orderIndex.has(name))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  extras.forEach((name, i) => orderIndex.set(name, channelOrder.length + i));

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
  const chainsSublabel =
    chains && chainCount! > 0
      ? `${exact} exact${chains.edgeInputComplete ? "" : ", loaded edges only"}`
      : null;

  const kpis: EvtxChartKpi[] = [
    {
      id: "events",
      label: "Events",
      value: records.length,
      sublabel:
        records.length === 0
          ? null
          : `${plural(channelNames.size, "channel", "channels")} · ${plural(
              textLogs.size,
              "text log",
              "text logs",
            )}`,
    },
    { id: "errors", label: "Errors", value: byLevel.Error, sublabel: null },
    {
      id: "warnings",
      label: "Warnings",
      value: byLevel.Warning,
      sublabel: warningSublabel,
    },
    {
      id: "critical",
      label: "Critical",
      value: byLevel.Critical,
      sublabel: topCritical ? `${topCritical.provider} ${topCritical.eventId}` : null,
    },
    {
      id: "distinctIds",
      label: "Distinct event IDs",
      value: allIds.size,
      sublabel: null,
    },
    {
      id: "chains",
      label: "Correlation chains",
      value: chainCount,
      sublabel: chainsSublabel,
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
  };
}
