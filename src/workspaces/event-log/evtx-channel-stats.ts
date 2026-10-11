/**
 * The pure model behind the Event Logs channel pane (spec section 8.6).
 *
 * Everything the pane has to decide lives here so a test can reach it without a DOM or the store
 * (which loads the Tauri bridge at module scope): the tree and display order, the per-channel
 * numbers and 24-bin activity, and the read state of each row. Nothing here reads a clock; the
 * caller passes `nowMs`.
 *
 * Evidence rules the model keeps (soul.md): a channel that could not be read is a coverage gap and
 * never a channel with zero events; a number is shown only for a channel that was actually read;
 * a partial read is never reported as complete.
 */
import {
  EVTX_TIME_WINDOW_MS,
  type EvtxChannelInfo,
  type EvtxCoverageGap,
  type EvtxCoverageGapKind,
  type EvtxRecord,
  type EvtxTimeWindow,
  type EventLogSourceCoverage,
} from "./types";

// ── Tree and display order ──────────────────────────────────────────────────

export interface ChannelTreeNode {
  name: string;
  fullPath: string;
  channel: EvtxChannelInfo | null; // leaf node if present
  children: Map<string, ChannelTreeNode>;
}

export interface ChannelTree {
  windowsLogs: EvtxChannelInfo[];
  serviceTree: ChannelTreeNode;
}

const WINDOWS_LOGS = new Set(["Application", "Security", "Setup", "System", "ForwardedEvents"]);
const WINDOWS_LOGS_ORDER = ["Application", "Security", "System", "Setup", "ForwardedEvents"];

export function buildChannelTree(channels: readonly EvtxChannelInfo[]): ChannelTree {
  const windowsLogs: EvtxChannelInfo[] = [];
  const root: ChannelTreeNode = { name: "", fullPath: "", channel: null, children: new Map() };

  for (const ch of channels) {
    if (WINDOWS_LOGS.has(ch.name)) {
      windowsLogs.push(ch);
      continue;
    }

    // Split channel path: "Microsoft-Windows-AAD/Operational"
    // → split on "/" first, then split the provider part on "-"
    const slashParts = ch.name.split("/");
    const providerParts = slashParts[0].split("-");
    const allParts = [...providerParts, ...slashParts.slice(1)];

    let node = root;
    for (const part of allParts) {
      if (!node.children.has(part)) {
        node.children.set(part, {
          name: part,
          fullPath: "",
          channel: null,
          children: new Map(),
        });
      }
      node = node.children.get(part)!;
    }
    node.channel = ch;
    node.fullPath = ch.name;
  }

  // Collapse single-child chains: if a node has exactly one child and no channel,
  // merge it with its child (e.g., "Microsoft" → "Windows" becomes "Microsoft-Windows" if Windows only has children)
  collapseChains(root);

  windowsLogs.sort(
    (a, b) => WINDOWS_LOGS_ORDER.indexOf(a.name) - WINDOWS_LOGS_ORDER.indexOf(b.name)
  );

  return { windowsLogs, serviceTree: root };
}

function collapseChains(node: ChannelTreeNode) {
  // Process children first (bottom-up)
  for (const child of node.children.values()) {
    collapseChains(child);
  }

  // If this node has exactly one child, no channel, and child also has no channel,
  // merge child's name into this node
  if (node.children.size === 1 && !node.channel) {
    const [childName, child] = [...node.children.entries()][0];
    if (!child.channel || child.children.size > 0) {
      // Merge: combine names with "-"
      const mergedName = node.name ? `${node.name}-${childName}` : childName;
      node.name = mergedName;
      node.channel = child.channel;
      node.fullPath = child.fullPath;
      node.children = child.children;
    }
  }
}

export function countChannelLeaves(node: ChannelTreeNode): number {
  if (node.children.size === 0) return node.channel ? 1 : 0;
  let count = node.channel ? 1 : 0;
  for (const child of node.children.values()) {
    count += countChannelLeaves(child);
  }
  return count;
}

export function sortedChannelChildren(node: ChannelTreeNode): ChannelTreeNode[] {
  return [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Each channel's position in channel display order (spec 6.3): Windows Logs in Event Viewer order,
 * then the service tree depth first with a node's own channel ahead of the channels beneath it.
 * This is the `i` every placement passes to `channelColor(i)`.
 *
 * It is a function of the channel set alone. It does not change with the filter text, with which
 * groups are collapsed, or with the order the channels arrived in, so a channel keeps its color.
 */
export function channelDisplayOrder(tree: ChannelTree): Map<string, number> {
  const order = new Map<string, number>();
  const add = (name: string) => {
    if (!order.has(name)) order.set(name, order.size);
  };
  for (const channel of tree.windowsLogs) add(channel.name);
  const walk = (node: ChannelTreeNode) => {
    for (const child of sortedChannelChildren(node)) {
      if (child.channel) add(child.channel.name);
      walk(child);
    }
  };
  walk(tree.serviceTree);
  return order;
}

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
 * Kinds that mean the whole source could not be read. The rest (record, chunk, xml, provider,
 * limit, limitReached, cancelled) leave part of a source readable. `empty` says the source holds
 * nothing and blocks nothing.
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

function isBlocking(gap: ChannelGap): boolean {
  if (gap.kind === null) return /\bnot read\b/i.test(gap.reason) || isDenied(gap);
  return BLOCKING_KINDS.has(gap.kind) || isDenied(gap);
}

function legacyGap(text: string): ChannelGap {
  const message = text.trim();
  const separator = message.indexOf(": ");
  return separator > 0
    ? { source: message.slice(0, separator), kind: null, reason: message.slice(separator + 2) }
    : { source: "", kind: null, reason: message };
}

const EVTX_EXTENSION = /\.evtx$/i;
// formatCoverageGap appends " chunk N" / " record N" to the source of a legacy string.
const LOCATION_SUFFIX = /\s+(?:chunk|record)\s+\S+$/i;

/** The file stem a gap's source names, or null when the source is not a single .evtx file. */
function evtxStem(source: string): string | null {
  const trimmed = source.replace(LOCATION_SUFFIX, "").trim();
  const basename = trimmed.slice(Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\")) + 1);
  if (!EVTX_EXTENSION.test(basename)) return null;
  // Event Viewer writes a "/" in a channel name as "%4" in the file name.
  return basename.replace(EVTX_EXTENSION, "").replace(/%4/g, "/");
}

interface GapIndex {
  /** Gaps keyed by the live channel context ("Channel" or "Machine/Channel" with the machine removed). */
  byContext: Map<string, ChannelGap[]>;
  /** Gaps keyed by the lower-cased channel name their .evtx file stands for. */
  byFile: Map<string, ChannelGap[]>;
  /** The first source seen for each file stem, for naming and locating a row the file produced. */
  files: Map<string, { name: string; path: string }>;
}

function indexGaps(gaps: readonly ChannelGap[], remoteMachine: string | null): GapIndex {
  const index: GapIndex = { byContext: new Map(), byFile: new Map(), files: new Map() };
  const push = (map: Map<string, ChannelGap[]>, key: string, gap: ChannelGap) => {
    const list = map.get(key);
    if (list === undefined) map.set(key, [gap]);
    else list.push(gap);
  };
  const remotePrefix = remoteMachine ? `${remoteMachine}/` : null;
  for (const gap of gaps) {
    const stem = evtxStem(gap.source);
    if (stem !== null) {
      push(index.byFile, stem.toLowerCase(), gap);
      if (!index.files.has(stem.toLowerCase())) {
        index.files.set(stem.toLowerCase(), {
          name: stem,
          path: gap.source.replace(LOCATION_SUFFIX, "").trim(),
        });
      }
      continue;
    }
    if (remotePrefix === null) push(index.byContext, gap.source, gap);
    else if (gap.source.startsWith(remotePrefix)) {
      push(index.byContext, gap.source.slice(remotePrefix.length), gap);
    }
  }
  return index;
}

function gapsFor(index: GapIndex, channelName: string): ChannelGap[] {
  // File stems were decoded (%4 back to a slash) when indexed, so the channel name is the key.
  return [
    ...(index.byContext.get(channelName) ?? []),
    ...(index.byFile.get(channelName.toLowerCase()) ?? []),
  ];
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
  /** True when the service reports the channel as switched off. */
  isSwitchedOff: (channel: EvtxChannelInfo) => boolean;
}

export interface ChannelRowModel {
  name: string;
  /** Position in channel display order: the `i` for `channelColor(i)`. */
  index: number;
  state: ChannelReadState;
  /** Numbers for a read or partial row. For every other state they must not be shown. */
  stats: ChannelStats;
  /** False for a row that stands for a source that could not be opened. */
  selectable: boolean;
  /** Up to three distinct reasons the channel is not complete, for a tooltip. */
  reasons: string[];
}

export interface ChannelPaneModel {
  /** The channels plus a row for each source that could not be opened. */
  channels: EvtxChannelInfo[];
  order: ReadonlyMap<string, number>;
  rows: ReadonlyMap<string, ChannelRowModel>;
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
  if (gaps.length > 0) return acquired || kept ? "partial" : "notRead";
  return acquired || kept ? "read" : "notLoaded";
}

function distinctReasons(gaps: readonly ChannelGap[]): string[] {
  return [...new Set(gaps.map((gap) => gap.reason.trim()).filter(Boolean))].slice(0, MAX_REASONS);
}

/**
 * Builds the rows, order and counts the pane renders.
 *
 * A source that could not be opened has no channel entry (an access-denied Security.evtx is only a
 * gap), yet the pane has to show it: omitting it would hide the very channel that is missing. So a
 * gap that blocks a single .evtx file no channel matches becomes a row of its own, counted in the
 * total and never in the read count.
 */
export function buildChannelPaneModel(input: ChannelPaneInput): ChannelPaneModel {
  const { channels, loadedChannels, remoteMachine, sourceMode } = input;
  const { span, byChannel } = computeChannelStats(input.records, input);

  const gaps: ChannelGap[] = [
    ...input.coverageDetails.map(({ source, kind, reason }) => ({ source, kind, reason })),
    ...input.manifestCoverage.map(({ path, kind, reason }) => ({ source: path, kind, reason })),
    ...input.legacyCoverage.map(legacyGap),
  ];
  const index = indexGaps(gaps, remoteMachine);

  const known = new Set(channels.map((channel) => channel.name.toLowerCase()));
  const unopened: EvtxChannelInfo[] = [];
  for (const [key, fileGaps] of index.byFile) {
    const file = index.files.get(key);
    if (file === undefined || known.has(key) || !fileGaps.some(isBlocking)) continue;
    unopened.push({ name: file.name, eventCount: 0, sourceType: { file: { path: file.path } } });
  }
  const unopenedNames = new Set(unopened.map((channel) => channel.name));
  const allChannels = [...channels, ...unopened];

  const order = channelDisplayOrder(buildChannelTree(allChannels));
  const rows = new Map<string, ChannelRowModel>();
  let readCount = 0;
  for (const channel of allChannels) {
    const channelGaps = gapsFor(index, channel.name);
    const isUnopened = unopenedNames.has(channel.name);
    const stats = byChannel.get(channel.name) ?? NO_CHANNEL_STATS;
    const state = classify(channelGaps, {
      acquired: !isUnopened && (sourceMode !== "live" || loadedChannels.has(channel.name)),
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

  return { channels: allChannels, order, rows, span, readCount, totalCount: allChannels.length };
}
