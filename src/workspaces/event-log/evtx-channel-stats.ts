/**
 * The pure model behind the Event Logs channel pane (spec section 8.6).
 *
 * Everything the pane has to decide lives here so a test can reach it without a DOM or the store
 * (which loads the Tauri bridge at module scope): the per-channel numbers and 24-bin activity, and
 * the read state of each row. The tree and the display order are in `evtx-channel-order`. Nothing here reads a clock; the
 * caller passes `nowMs`.
 *
 * Evidence rules the model keeps (soul.md): a channel that could not be read is a coverage gap and
 * never a channel with zero events; a number is shown only for a channel that was actually read;
 * a partial read is never reported as complete.
 */
import {
  buildChannelTree,
  orderChannelNames,
  textLogChannelNames,
  type ChannelTree,
  type ChannelTreeNode,
} from "./evtx-channel-order";
import {
  EVTX_TIME_WINDOW_MS,
  type EvtxChannelInfo,
  type EvtxCoverageGap,
  type EvtxCoverageGapKind,
  type EvtxRecord,
  type EvtxTimeWindow,
  type EventLogSourceCoverage,
} from "./types";

// ── Activity statistics ─────────────────────────────────────────────────────

export const CHANNEL_ACTIVITY_BINS = 24;

export interface ChannelActivitySpan {
  startMs: number;
  endMs: number;
}

export interface ChannelStats {
  /** Events loaded for the channel. */
  total: number;
  /** Error and Critical events. Critical is the worse of the two, so it is never left out. */
  errors: number;
  warnings: number;
  /** `CHANNEL_ACTIVITY_BINS` counts of placed events inside the span. */
  bins: readonly number[];
  /** In `total`, not in `bins`: the event has no usable timestamp. */
  unplaced: number;
  /** In `total`, not in `bins`: the timestamp falls before or after the span. */
  outsideSpan: number;
}

const EMPTY_BINS: readonly number[] = Object.freeze(new Array<number>(CHANNEL_ACTIVITY_BINS).fill(0));

/** The stats of a channel that has no loaded events. */
export const NO_CHANNEL_STATS: ChannelStats = Object.freeze({
  total: 0,
  errors: 0,
  warnings: 0,
  bins: EMPTY_BINS,
  unplaced: 0,
  outsideSpan: 0,
});

/**
 * The event's time in Unix milliseconds, or null when it has none.
 *
 * The backend writes 0 for an event whose timestamp it could not read (`parsed_timestamp_epoch` in
 * timeline.rs treats 0 as missing), and a negative value predates any event log, so neither is a
 * time. The `timestamp` text is deliberately not parsed as a fallback: a naive local timestamp read
 * by `Date.parse` would invent a UTC offset.
 */
export function recordTimestampMs(record: Pick<EvtxRecord, "timestampEpoch">): number | null {
  const epoch = record.timestampEpoch;
  return Number.isFinite(epoch) && epoch > 0 ? epoch : null;
}

export interface ChannelStatsOptions {
  nowMs: number;
  timeWindow: EvtxTimeWindow;
}

export interface ChannelStatsResult {
  /** The time range all bins share, or null when "All time" holds no placed event. */
  span: ChannelActivitySpan | null;
  byChannel: ReadonlyMap<string, ChannelStats>;
}

/**
 * The range the bins cover. A finite window ends at `nowMs`. "All time" runs from the earliest to
 * the latest placed event; events that share one instant get a one millisecond span so they land
 * in the first bin.
 */
function activitySpan(
  records: readonly EvtxRecord[],
  { nowMs, timeWindow }: ChannelStatsOptions
): ChannelActivitySpan | null {
  if (timeWindow !== "all") {
    return { startMs: nowMs - EVTX_TIME_WINDOW_MS[timeWindow], endMs: nowMs };
  }
  let earliest = Infinity;
  let latest = -Infinity;
  for (const record of records) {
    const at = recordTimestampMs(record);
    if (at === null) continue;
    if (at < earliest) earliest = at;
    if (at > latest) latest = at;
  }
  if (earliest === Infinity) return null;
  return { startMs: earliest, endMs: latest > earliest ? latest : earliest + 1 };
}

interface MutableStats {
  total: number;
  errors: number;
  warnings: number;
  bins: number[];
  unplaced: number;
  outsideSpan: number;
}

/**
 * Per-channel totals, error and warning counts and a 24-bin activity series, from the loaded
 * records. Every channel shares one span so their sparklines line up.
 *
 * An event without a timestamp is counted in the totals but placed in no bin, and is never
 * counted as bin 0. An event outside the span is likewise counted but not clamped into an edge
 * bin. `unplaced` and `outsideSpan` say how many events the series leaves out.
 */
export function computeChannelStats(
  records: readonly EvtxRecord[],
  options: ChannelStatsOptions
): ChannelStatsResult {
  const span = activitySpan(records, options);
  const width = span === null ? 0 : (span.endMs - span.startMs) / CHANNEL_ACTIVITY_BINS;
  const byChannel = new Map<string, MutableStats>();

  for (const record of records) {
    let stats = byChannel.get(record.channel);
    if (stats === undefined) {
      stats = {
        total: 0,
        errors: 0,
        warnings: 0,
        bins: new Array<number>(CHANNEL_ACTIVITY_BINS).fill(0),
        unplaced: 0,
        outsideSpan: 0,
      };
      byChannel.set(record.channel, stats);
    }
    stats.total += 1;
    if (record.level === "Error" || record.level === "Critical") stats.errors += 1;
    else if (record.level === "Warning") stats.warnings += 1;

    const at = recordTimestampMs(record);
    if (at === null) {
      stats.unplaced += 1;
    } else if (span === null || at < span.startMs || at > span.endMs) {
      stats.outsideSpan += 1;
    } else {
      // The end of the span belongs to the last bin; every other edge belongs to the later bin.
      const bin = Math.min(CHANNEL_ACTIVITY_BINS - 1, Math.floor((at - span.startMs) / width));
      stats.bins[bin] += 1;
    }
  }
  return { span, byChannel };
}

/**
 * Bar heights in pixels for a sparkline: 0 for an empty bin, otherwise scaled to the busiest bin
 * and never below 2 px so a lone event stays visible next to an empty bin's 1 px baseline.
 */
export function scaleActivityBars(bins: readonly number[], maxHeight: number): number[] {
  const peak = Math.max(0, ...bins);
  return bins.map((count) =>
    count <= 0 ? 0 : Math.min(maxHeight, Math.max(2, Math.round((count / peak) * maxHeight)))
  );
}

// ── Coverage and read state ─────────────────────────────────────────────────

export type ChannelReadState =
  /** Acquired with no gap. A zero here is a real zero. */
  | "read"
  /** Acquired, but a gap says some of it is missing. The numbers are a lower bound. */
  | "partial"
  /** A live channel nobody has loaded yet. No numbers. */
  | "notLoaded"
  /** The service refused it and this app is not elevated. No numbers. */
  | "needsElevation"
  /** Refused on a remote machine, where elevating this app would not help. No numbers. */
  | "accessDenied"
  /** Could not be read and nothing was kept. No numbers. */
  | "notRead"
  /** The service reports the channel as switched off: nothing to read, not a hole in the view. */
  | "disabled";

/** One gap, whichever of the three channels it reached the store through. */
interface ChannelGap {
  source: string;
  /** Null for a legacy string, which carries no kind. */
  kind: EvtxCoverageGapKind | null;
  reason: string;
}

/**
 * Kinds that mean the whole source could not be read. The rest leave part of a source readable.
 */
const BLOCKING_KINDS: ReadonlySet<EvtxCoverageGapKind> = new Set([
  "accessDenied",
  "missing",
  "unsupported",
  "file",
  "invalidPattern",
]);

/**
 * The backend files a live refusal as kind "record" (`absorb_scan` in commands.rs), not as
 * accessDenied, so for a live channel the reason is the only place the refusal is named. These are
 * the exact phrases `describe_query_status` in live.rs writes for Windows error 5 ("Access is
 * denied") and 1314 ("A required privilege is not held by the client"). A follow-up should let
 * the backend send accessDenied for both.
 */
const DENIED_REASON = /\baccess (?:is )?denied\b|\bprivilege is not held\b/i;

function isDenied(gap: ChannelGap): boolean {
  return gap.kind === "accessDenied" || DENIED_REASON.test(gap.reason);
}

/**
 * Kinds that leave every event in place, so they do not make a read partial. `provider` is a
 * message that could not be formatted (the record is kept and its raw data is shown), which is
 * common on a real machine with missing publisher metadata; `empty` says the source holds nothing,
 * and a channel read as empty is a real zero. Every other kind, and a legacy string that has no
 * structured twin, says events may be missing.
 */
const COMPLETE_DESPITE_KINDS: ReadonlySet<EvtxCoverageGapKind> = new Set(["provider", "empty"]);

function isIncomplete(gap: ChannelGap): boolean {
  return gap.kind === null || !COMPLETE_DESPITE_KINDS.has(gap.kind);
}

function isBlocking(gap: ChannelGap): boolean {
  if (gap.kind === null) return /\bnot read\b/i.test(gap.reason) || isDenied(gap);
  return BLOCKING_KINDS.has(gap.kind) || isDenied(gap);
}

/**
 * What a structured gap and the legacy string written for it have in common: the same source and
 * the same reason. The string's source is already free of its location (see `legacyGap`).
 */
function twinKey(gap: ChannelGap): string {
  return `${gap.source.trim()}\u0000${gap.reason.trim()}`;
}

// `formatCoverageGap` appends " chunk N" or " record N" to the source of a legacy string. Only a
// legacy string carries it: a structured gap's source is the bare path, and a folder in that path
// may well be called "record 42".
const LEGACY_LOCATION_SUFFIX = /\s+(?:chunk|record)\s+\d+$/i;

function legacyGap(text: string): ChannelGap {
  const message = text.trim();
  const separator = message.indexOf(": ");
  return separator > 0
    ? {
        source: message.slice(0, separator).replace(LEGACY_LOCATION_SUFFIX, "").trim(),
        kind: null,
        reason: message.slice(separator + 2),
      }
    : { source: "", kind: null, reason: message };
}

const EVTX_EXTENSION = /\.evtx$/i;

/**
 * The name a gap's file would carry as a channel, or null when the source is not a single .evtx
 * file. Used only to name a row for a file that never opened; which channel a gap belongs to is
 * decided by the source path, never by this name.
 */
function evtxStem(source: string): string | null {
  // The member of an archive follows "::", so "bundle.zip::System.evtx" is named System.
  const member = source.lastIndexOf("::");
  const cut = Math.max(
    source.lastIndexOf("/"),
    source.lastIndexOf("\\"),
    member === -1 ? -1 : member + 1,
  );
  const basename = source.slice(cut + 1).trim();
  if (!EVTX_EXTENSION.test(basename)) return null;
  // Event Viewer writes a "/" in a channel name as "%4" in the file name.
  return basename.replace(EVTX_EXTENSION, "").replace(/%4/g, "/");
}

/** Gaps by the exact source they name. A channel finds its gaps by its name or its file path. */
type GapIndex = Map<string, ChannelGap[]>;

function indexGaps(gaps: readonly ChannelGap[], remoteMachine: string | null): GapIndex {
  const index: GapIndex = new Map();
  const push = (key: string, gap: ChannelGap) => {
    const list = index.get(key);
    if (list === undefined) index.set(key, [gap]);
    else list.push(gap);
  };
  const remotePrefix = remoteMachine ? `${remoteMachine}/` : null;
  for (const gap of gaps) {
    push(gap.source, gap);
    // A remote query names its gaps "Machine/Channel"; the channel list names them "Channel".
    if (remotePrefix !== null && gap.source.startsWith(remotePrefix)) {
      push(gap.source.slice(remotePrefix.length), gap);
    }
  }
  return index;
}

/** The distinct gaps filed under any of `keys`. */
function gapsFor(index: GapIndex, keys: readonly string[]): ChannelGap[] {
  const found = new Set<ChannelGap>();
  for (const key of keys) {
    for (const gap of index.get(key) ?? []) found.add(gap);
  }
  return [...found];
}

// ── The pane model ──────────────────────────────────────────────────────────

export interface ChannelPaneInput {
  channels: readonly EvtxChannelInfo[];
  records: readonly EvtxRecord[];
  loadedChannels: ReadonlySet<string>;
  sourceMode: "files" | "live" | null;
  remoteMachine: string | null;
  nowMs: number;
  timeWindow: EvtxTimeWindow;
  /** Structured parser and live gaps (`coverageDetails`). */
  coverageDetails: readonly EvtxCoverageGap[];
  /** Source-level gaps from the manifest of a file or folder open. */
  manifestCoverage: readonly EventLogSourceCoverage[];
  /** The legacy gap strings (`coverageGaps`); a thrown query leaves nothing else. */
  legacyCoverage: readonly string[];
  /** The live tail's gap strings (`tailCoverageGaps`); only those that mean lost events count. */
  tailCoverage: readonly string[];
  /** True when the service reports the channel as switched off. */
  isSwitchedOff: (channel: EvtxChannelInfo) => boolean;
}

export interface ChannelRowModel {
  name: string;
  /** The channel's color index: the `i` for `channelColor(i)`. See `ChannelPaneModel.order`. */
  index: number;
  state: ChannelReadState;
  /** Numbers for a read or partial row. For every other state they must not be shown. */
  stats: ChannelStats;
  /** False for a row that stands for a source that could not be opened. */
  selectable: boolean;
  /** Up to three distinct reasons the channel is not complete, for a tooltip and a description. */
  reasons: string[];
}

/** A text log the archive reader listed as a channel: not an event channel, so no event semantics. */
export interface TextLogRowModel {
  /** The channel name the records carry, which is what the selection toggles. */
  name: string;
  /** The member's file name. */
  label: string;
  entries: number;
}

export interface ChannelPaneModel {
  /** The event channels plus a row for each source that could not be opened. Names are unique. */
  channels: EvtxChannelInfo[];
  tree: ChannelTree<EvtxChannelInfo>;
  /**
   * Color index of every row. The channels the workbench lists take their position from
   * `orderChannelNames`, exactly as the Table and the charts compute it from the same names. A
   * source that never opened has no events anywhere else, so it is indexed after them and cannot
   * shift a real channel's color. Text logs are not channels and have no index.
   */
  order: ReadonlyMap<string, number>;
  rows: ReadonlyMap<string, ChannelRowModel>;
  /** Text logs from archives, listed apart from the channels and counted in neither total. */
  textLogs: TextLogRowModel[];
  span: ChannelActivitySpan | null;
  /** Rows whose events were acquired, wholly or in part. */
  readCount: number;
  totalCount: number;
}

const MAX_REASONS = 3;

function classify(
  gaps: readonly ChannelGap[],
  { acquired, switchedOff, stats, remote }: {
    acquired: boolean;
    switchedOff: boolean;
    stats: ChannelStats;
    remote: boolean;
  }
): ChannelReadState {
  if (switchedOff && !acquired) return "disabled";
  const kept = stats.total > 0;
  if (!kept && gaps.some(isDenied)) return remote ? "accessDenied" : "needsElevation";
  if (!kept && gaps.some(isBlocking)) return "notRead";
  // A gap with nothing kept is a channel that could not be read, however it was acquired: zero
  // here is not a count of events but the absence of any.
  if (gaps.length > 0) return kept ? "partial" : "notRead";
  return acquired || kept ? "read" : "notLoaded";
}

function distinctReasons(gaps: readonly ChannelGap[]): string[] {
  return [...new Set(gaps.map((gap) => gap.reason.trim()).filter(Boolean))].slice(0, MAX_REASONS);
}

/**
 * Live tail gaps that do not mean an event was lost. A tail that could not start, a stop that
 * failed, a subscription that fell back to polling, and a provider message that could not be
 * formatted all leave every event delivered so far intact. Everything else a tail reports (a batch
 * that was not received or delivered, a callback error, a poll that could not read events) says
 * events may be missing, and an unrecognized gap is treated that way too.
 */
const NEUTRAL_TAIL_GAP =
  /\blive tail unavailable\b|\blive tail stop failed\b|polling fallback is active|raw event data is shown instead|provider database lookup failed/i;

function filePathOf(channel: EvtxChannelInfo): string | null {
  const source = channel.sourceType;
  return typeof source === "object" && "file" in source ? source.file.path : null;
}

interface ListedChannel {
  channel: EvtxChannelInfo;
  /** Every source a gap can name this channel by: its name and the path of each file it came from. */
  keys: string[];
}

/**
 * Builds the rows, order and counts the pane renders.
 *
 * A gap belongs to a channel when its source is exactly the channel's name (a live channel) or the
 * path of a file the channel was read from (files mode). The file's name is never used to guess the
 * channel: a renamed export, a file listed under its own path because nothing in it was readable,
 * and a member of an archive all carry the path they were read from.
 *
 * A source that could not be opened has no channel entry (an access-denied Security.evtx is only a
 * gap), yet the pane has to show it: omitting it would hide the very channel that is missing. So a
 * gap that blocks a single .evtx file no channel listed becomes a row of its own, counted in the
 * total and never in the read count.
 */
export function buildChannelPaneModel(input: ChannelPaneInput): ChannelPaneModel {
  const { loadedChannels, remoteMachine, sourceMode } = input;

  // Text logs from archives share the channel list but are not event channels.
  const textLogNames = textLogChannelNames(input.records);
  const eventRecords =
    textLogNames.size === 0
      ? input.records
      : input.records.filter((record) => !textLogNames.has(record.channel));
  const { span, byChannel } = computeChannelStats(eventRecords, input);
  const entryCounts = new Map<string, number>();
  if (textLogNames.size > 0) {
    for (const record of input.records) {
      if (textLogNames.has(record.channel)) {
        entryCounts.set(record.channel, (entryCounts.get(record.channel) ?? 0) + 1);
      }
    }
  }

  // One row per channel name: two exports of the same log are one channel read from two files.
  const listed = new Map<string, ListedChannel>();
  const textLogs: TextLogRowModel[] = [];
  for (const channel of input.channels) {
    if (textLogNames.has(channel.name)) {
      if (!textLogs.some((row) => row.name === channel.name)) {
        textLogs.push({
          name: channel.name,
          label: memberLabel(channel.name),
          entries: entryCounts.get(channel.name) ?? 0,
        });
      }
      continue;
    }
    const path = filePathOf(channel);
    const existing = listed.get(channel.name);
    if (existing === undefined) {
      listed.set(channel.name, { channel, keys: path === null ? [channel.name] : [channel.name, path] });
    } else if (path !== null && !existing.keys.includes(path)) {
      existing.keys.push(path);
    }
  }
  textLogs.sort((a, b) => a.label.localeCompare(b.label) || a.name.localeCompare(b.name));

  const structured: ChannelGap[] = [
    ...input.coverageDetails.map(({ source, kind, reason }) => ({ source, kind, reason })),
    ...input.manifestCoverage.map(({ path, kind, reason }) => ({ source: path, kind, reason })),
  ];
  // A legacy string repeats a structured gap; it counts only when nothing structured says the same,
  // as for a thrown query, which leaves no structured gap at all.
  const structuredKeys = new Set(structured.map(twinKey));
  const gaps = [
    ...structured,
    ...input.legacyCoverage.map(legacyGap).filter((gap) => !structuredKeys.has(twinKey(gap))),
    ...input.tailCoverage.map(legacyGap).filter((gap) => !NEUTRAL_TAIL_GAP.test(gap.reason)),
  ].filter(isIncomplete);
  const index = indexGaps(gaps, remoteMachine);

  // A blocking gap on an .evtx file that no listed channel came from is a source that never opened.
  const knownSources = new Set([...listed.values()].flatMap((entry) => entry.keys));
  const remotePrefix = remoteMachine ? `${remoteMachine}/` : "";
  const takenNames = new Set([...listed.keys()].map((name) => name.toLowerCase()));
  const unopened: EvtxChannelInfo[] = [];
  for (const [source, sourceGaps] of index) {
    const stem = evtxStem(source);
    if (stem === null || knownSources.has(source)) continue;
    if (remotePrefix !== "" && knownSources.has(source.slice(remotePrefix.length))) continue;
    if (!sourceGaps.some(isBlocking)) continue;
    // The file's own name when that is free; otherwise its path, which is unique, so two files
    // called Security.evtx (or one called System.evtx beside the System channel) stay two rows.
    const name = takenNames.has(stem.toLowerCase()) ? source : stem;
    takenNames.add(name.toLowerCase());
    unopened.push({ name, eventCount: 0, sourceType: { file: { path: source } } });
  }

  const listedChannels = [...listed.values()].map((entry) => entry.channel);
  const allChannels = [...listedChannels, ...unopened];
  const unopenedNames = new Set(unopened.map((channel) => channel.name));

  const tree = buildChannelTree(allChannels);
  const order = new Map(
    [
      ...orderChannelNames(listedChannels.map((channel) => channel.name)),
      ...orderChannelNames(unopened.map((channel) => channel.name)),
    ].map((name, position) => [name, position] as const),
  );
  const rows = new Map<string, ChannelRowModel>();
  let readCount = 0;
  for (const channel of allChannels) {
    const isUnopened = unopenedNames.has(channel.name);
    const keys = isUnopened
      ? [(channel.sourceType as { file: { path: string } }).file.path]
      : (listed.get(channel.name)?.keys ?? [channel.name]);
    const channelGaps = gapsFor(index, keys);
    const stats = byChannel.get(channel.name) ?? NO_CHANNEL_STATS;
    // A parsed file set was read as it was opened. A live channel was read when it was loaded. With
    // no source mode nothing was read: the channel list alone proves nothing about its events.
    const acquired =
      !isUnopened &&
      (sourceMode === "files" || (sourceMode === "live" && loadedChannels.has(channel.name)));
    const state = classify(channelGaps, {
      acquired,
      switchedOff: !isUnopened && input.isSwitchedOff(channel),
      stats,
      remote: remoteMachine !== null && remoteMachine !== "",
    });
    if (state === "read" || state === "partial") readCount += 1;
    rows.set(channel.name, {
      name: channel.name,
      index: order.get(channel.name) ?? 0,
      state,
      stats,
      selectable: !isUnopened,
      reasons: state === "read" || state === "notLoaded" ? [] : distinctReasons(channelGaps),
    });
  }

  return {
    channels: allChannels,
    tree,
    order,
    rows,
    textLogs,
    span,
    readCount,
    totalCount: allChannels.length,
  };
}

/** The member a text-log channel label names: "bundle.zip::logs/app.log" is app.log. */
function memberLabel(name: string): string {
  const member = name.lastIndexOf("::");
  const cut = Math.max(name.lastIndexOf("/"), name.lastIndexOf("\\"), member === -1 ? -1 : member + 1);
  return name.slice(cut + 1).trim() || name;
}

// ── Text logs correlated alongside the channels ─────────────────────────────

export interface LogSourceSummary {
  path: string;
  label: string;
  entries: number;
}

function basename(path: string): string {
  return path.slice(Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\")) + 1);
}

/**
 * The text logs handed to the analysis session, one row per file with its parsed entry count.
 *
 * The grouping key is the entry's `filePath`, the log file itself. It is not the entry's
 * `sourceFile`, which the session records as the origin `source` and which, for a CCM log, is the
 * code file the line names (`file=` in the line), so it would split one log into many labels.
 * The count is parsed entries: one entry can span several physical lines.
 */
export function summarizeLogSources(
  entries: readonly { filePath: string }[]
): LogSourceSummary[] {
  const counts = new Map<string, number>();
  for (const entry of entries) counts.set(entry.filePath, (counts.get(entry.filePath) ?? 0) + 1);
  return [...counts]
    .map(([path, count]) => ({
      path,
      label: basename(path) || path || "Unnamed source",
      entries: count,
    }))
    .sort((a, b) => a.label.localeCompare(b.label) || a.path.localeCompare(b.path));
}

// ── Which groups start open ─────────────────────────────────────────────────

/** Group keys of the two top-level headers; nested folders use `fullPath || name`. */
export const WINDOWS_LOGS_GROUP = "Windows Logs";
export const APP_SERVICES_GROUP = "AppServices";
export const TEXT_LOGS_GROUP = "TextLogs";

/**
 * The groups that start open: Windows Logs, and every group on the path to a channel that was
 * acquired and holds events. A group that only holds channels nobody loaded, channels that came
 * back empty, or channels that could not be read stays closed, so opening the pane does not unfold
 * the hundreds of service channels a live machine lists. A group the operator opened or closed
 * keeps that choice; this is only the starting point.
 */
export function defaultExpandedGroups(
  model: Pick<ChannelPaneModel, "tree" | "rows" | "textLogs">
): Set<string> {
  const open = new Set([WINDOWS_LOGS_GROUP]);
  // The text logs in an archive are why the operator opened it, and they are few.
  if (model.textLogs.length > 0) open.add(TEXT_LOGS_GROUP);
  const holdsEvents = (name: string) => {
    const row = model.rows.get(name);
    return (
      row !== undefined && (row.state === "read" || row.state === "partial") && row.stats.total > 0
    );
  };
  const visit = (node: ChannelTreeNode<EvtxChannelInfo>): boolean => {
    let found = node.channel !== null && holdsEvents(node.channel.name);
    for (const child of node.children.values()) {
      if (visit(child)) found = true;
    }
    if (found && node !== model.tree.serviceTree) open.add(node.fullPath || node.name);
    return found;
  };
  if (visit(model.tree.serviceTree)) open.add(APP_SERVICES_GROUP);
  return open;
}
