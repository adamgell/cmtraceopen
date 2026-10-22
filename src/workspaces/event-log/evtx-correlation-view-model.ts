/**
 * What the Correlation view and the lane plot draw, computed from the chain model (spec 8.11).
 *
 * Pure: no React, no stores, no IO. The components stay thin because the decisions live here and
 * are tested here:
 *
 * - A connector is drawn only for an exact or candidate edge whose two endpoints are both drawn
 *   AND that has at least one evidence row (`evidenceForEdge`). An ambiguous or coverage blocked
 *   relation never gets a connector. Each connector carries the strength of ITS edge.
 * - A lane is one source: an event lane is a (source, channel), a log lane is the log FILE
 *   (`origin.file`; for a CCM line `origin.source` is the code file that wrote it and would merge
 *   unrelated logs).
 * - A member outside the lane window is pinned to the edge, never dropped, and says how far
 *   outside it is.
 * - Every cap says how much it left out: nothing is hidden silently, and an unknown count is
 *   never shown as 0.
 * - `nearby` is the seam for "Not linked" context markers (decision A on #838): production passes
 *   `[]`, there is no producer, and those markers never join a chain or a connector.
 */
import { getBaseName, getDirectoryName } from "../../lib/file-paths";
import {
  compareStrings,
  type CorrelationChain,
  type CorrelationChainEdge,
  type CorrelationChainModel,
  type CorrelationChainStrength,
  type CorrelationEvidenceRow,
} from "./evtx-correlation-chains";
import { gapsClearCompleteness, type CorrelationGaps } from "./evtx-correlation-gaps";
import { chipForOriginKind, type KindChip } from "./evtx-kind-chip-value";
import {
  eventDateKey,
  formatClock,
  formatDayClock,
  TIME_RANGE_SEPARATOR,
  timeRangeNeedsYear,
  type EvtxTimeZoneMode,
} from "./evtx-time";
import type { EvtxLevel } from "./types";
import {
  originContext,
  TIMELINE_SEVERITY_RANK,
  timelineOriginId,
  type TimelineCorrelationKey,
  type TimelineItem,
  type TimelineOrigin,
  type TimelineSeverity,
} from "./unified-timeline";

/** Spec 8.11: the lane window is the chain span padded 25% on each side, at least 10 s wide. */
export const CORRELATION_WINDOW_PAD_RATIO = 0.25;
export const CORRELATION_MIN_WINDOW_MS = 10_000;
/** Markers and connectors drawn at once. Past these the view says how many it left out. */
export const CORRELATION_MARKER_CAP = 150;
export const CORRELATION_CONNECTOR_CAP = 300;
/** Sequence rows shown before "Show all". */
export const CORRELATION_SEQUENCE_INITIAL = 200;
/** Spec 8.11 overview and 8.12 axis: five ticks. */
export const CORRELATION_AXIS_TICKS = 5;
/** Spec 8.11: the key value is truncated in the middle to 12 characters. */
export const KEY_VALUE_DISPLAY_CHARS = 12;

export function levelOfSeverity(severity: TimelineSeverity): EvtxLevel {
  switch (severity) {
    case "critical":
      return "Critical";
    case "error":
      return "Error";
    case "warning":
      return "Warning";
    case "info":
      return "Information";
    case "verbose":
      return "Verbose";
  }
}

// ---- window and placement ---------------------------------------------------------------------

export interface TimeWindow {
  startMs: number;
  endMs: number;
}

/**
 * The default lane window: the chain span padded by 25% of the span on each side, and never
 * narrower than 10 s, centred on the span. Null when the chain has no placed member.
 */
export function defaultLaneWindow(
  startMs: number | null,
  endMs: number | null,
): TimeWindow | null {
  if (startMs === null || endMs === null) return null;
  const span = Math.max(0, endMs - startMs);
  const width = Math.max(span * (1 + 2 * CORRELATION_WINDOW_PAD_RATIO), CORRELATION_MIN_WINDOW_MS);
  const centre = (startMs + endMs) / 2;
  return { startMs: centre - width / 2, endMs: centre + width / 2 };
}

export type PinSide = "before" | "after";

export interface Placement {
  /** 0 to 1 across the window. A pinned member sits at 0 or 1. */
  x: number;
  pinned: PinSide | null;
  /** How far outside the window the member is; 0 inside it. */
  outsideMs: number;
}

/** Where a timestamp sits in the window. The window's two edges are inside it. */
export function placeInWindow(timestampMs: number, window: TimeWindow): Placement {
  if (timestampMs < window.startMs) {
    return { x: 0, pinned: "before", outsideMs: window.startMs - timestampMs };
  }
  if (timestampMs > window.endMs) {
    return { x: 1, pinned: "after", outsideMs: timestampMs - window.endMs };
  }
  const width = window.endMs - window.startMs;
  return { x: width <= 0 ? 0.5 : (timestampMs - window.startMs) / width, pinned: null, outsideMs: 0 };
}

/** `count` evenly spaced times from the window's start to its end. */
export function axisTicks(window: TimeWindow, count = CORRELATION_AXIS_TICKS): number[] {
  if (count < 2) return [window.startMs];
  return Array.from(
    { length: count },
    (_, i) => window.startMs + ((window.endMs - window.startMs) * i) / (count - 1),
  );
}

interface TickLabelOptions {
  /**
   * Seconds on every label. By default they are shown when the ticks are less than a minute apart,
   * so two neighbours never read as the same minute.
   */
  withSeconds?: boolean;
  /** "Now" for the year rule, which compares with the current year. The real clock unless a test gives one. */
  nowMs?: number;
}

/**
 * The labels of an axis, one per tick: the clock alone (`10:20:05`) on a span inside one calendar
 * day of the current year, and the day with it (`Oct 6 23:59:57`) once the ticks cross midnight, so
 * a bare clock never names two different days alike. A span outside the current year, or across a
 * year, names the year too (`Oct 6 2026 10:20:05`). This is the histogram's rule (`buildAxisTicks`
 * in evtx-histogram.ts) with the same pieces: `eventDateKey`, `timeRangeNeedsYear` and
 * `formatDayClock`, in the zone the view shows times in. The lane plot and the overview strip share
 * it, so one window cannot be labelled two ways.
 */
export function tickLabels(
  ticks: readonly number[],
  mode: EvtxTimeZoneMode,
  options: TickLabelOptions = {},
): string[] {
  const first = ticks[0];
  const last = ticks[ticks.length - 1];
  if (first === undefined || last === undefined) return [];
  const step = ticks.length > 1 ? (last - first) / (ticks.length - 1) : Number.POSITIVE_INFINITY;
  const withSeconds = options.withSeconds ?? step < 60_000;
  const withYear = timeRangeNeedsYear(first, last, mode, options.nowMs ?? Date.now());
  const withDay = eventDateKey(first, mode) !== eventDateKey(last, mode) || withYear;
  return ticks.map((tick) =>
    withDay ? formatDayClock(tick, mode, withSeconds, withYear) : formatClock(tick, mode, withSeconds),
  );
}

function trimmedFixed(value: number): string {
  return value.toFixed(1).replace(/\.0$/, "");
}

/**
 * A duration for a label, never negative: "850 ms", "3.3 s", "2 min 5 s", "1 h 4 min", "2 d 3 h".
 * The caller adds the sign or the words around it.
 */
export function formatDelta(ms: number): string {
  const total = Math.abs(ms);
  if (total < 1_000) return `${Math.round(total)} ms`;
  if (total < 60_000) return `${trimmedFixed(total / 1_000)} s`;
  const seconds = Math.round(total / 1_000);
  if (seconds < 3_600) {
    const minutes = Math.floor(seconds / 60);
    const rest = seconds % 60;
    return rest === 0 ? `${minutes} min` : `${minutes} min ${rest} s`;
  }
  if (seconds < 86_400) {
    const hours = Math.floor(seconds / 3_600);
    const minutes = Math.floor((seconds % 3_600) / 60);
    return minutes === 0 ? `${hours} h` : `${hours} h ${minutes} min`;
  }
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  return hours === 0 ? `${days} d` : `${days} d ${hours} h`;
}

/** The span label "HH:mm:ss" to "HH:mm:ss" (the spec's separator), or null with no placed member. */
export function spanText(
  startMs: number | null,
  endMs: number | null,
  mode: EvtxTimeZoneMode,
): string | null {
  if (startMs === null || endMs === null) return null;
  return `${formatClock(startMs, mode, true)}${TIME_RANGE_SEPARATOR}${formatClock(endMs, mode, true)}`;
}

// ---- lanes --------------------------------------------------------------------------------------

export interface LaneInfo {
  key: string;
  kind: "event" | "log";
  /** Short and unique among the lanes shown. */
  label: string;
  /** The full name for a tooltip. A tooltip is supplementary: the Entry text carries the same. */
  detail: string;
}

/** The lane an origin belongs to. Logs are keyed by FILE, never by `source`. */
export function laneKeyOf(origin: TimelineOrigin): string {
  return origin.kind === "event"
    ? `event\u0000${origin.source}\u0000${origin.channel}`
    : `log\u0000${origin.file}`;
}

function sourceName(source: string): string {
  return getBaseName(source) || source;
}

/**
 * Labels for the lanes of `origins`. An event lane is named by its channel, with its source added
 * only when two lanes share a channel. A log lane is named by the basename of its file, with the
 * parent folder added only when two files share a basename, and the whole path when that is not
 * enough. Lanes order: event lanes by channel then source, then log lanes by file path.
 */
export function describeLanes(origins: Iterable<TimelineOrigin>): LaneInfo[] {
  const first = new Map<string, TimelineOrigin>();
  for (const origin of origins) {
    const key = laneKeyOf(origin);
    if (!first.has(key)) first.set(key, origin);
  }
  const events = [...first.values()].filter(
    (origin): origin is Extract<TimelineOrigin, { kind: "event" }> => origin.kind === "event",
  );
  const logs = [...first.values()].filter(
    (origin): origin is Extract<TimelineOrigin, { kind: "log" }> => origin.kind === "log",
  );

  const channelCount = new Map<string, number>();
  for (const origin of events) {
    channelCount.set(origin.channel, (channelCount.get(origin.channel) ?? 0) + 1);
  }
  const eventShort = (origin: Extract<TimelineOrigin, { kind: "event" }>) =>
    channelCount.get(origin.channel) === 1
      ? origin.channel
      : `${origin.channel} (${sourceName(origin.source)})`;
  const eventShortCount = new Map<string, number>();
  for (const origin of events) {
    eventShortCount.set(eventShort(origin), (eventShortCount.get(eventShort(origin)) ?? 0) + 1);
  }
  const eventLanes: LaneInfo[] = events
    .sort(
      (a, b) =>
        compareStrings(a.channel.toLowerCase(), b.channel.toLowerCase()) ||
        compareStrings(a.channel, b.channel) ||
        compareStrings(a.source, b.source),
    )
    .map((origin) => ({
      key: laneKeyOf(origin),
      kind: "event" as const,
      label:
        eventShortCount.get(eventShort(origin)) === 1
          ? eventShort(origin)
          : `${origin.channel} (${origin.source})`,
      detail: `${origin.channel} · ${originContext(origin)}`,
    }));

  const baseCount = new Map<string, number>();
  for (const origin of logs) {
    const base = sourceName(origin.file);
    baseCount.set(base, (baseCount.get(base) ?? 0) + 1);
  }
  const withFolder = (origin: Extract<TimelineOrigin, { kind: "log" }>) => {
    const folder = getBaseName(getDirectoryName(origin.file));
    return folder === "" ? sourceName(origin.file) : `${folder}/${sourceName(origin.file)}`;
  };
  const folderCount = new Map<string, number>();
  for (const origin of logs) {
    if (baseCount.get(sourceName(origin.file)) !== 1) {
      folderCount.set(withFolder(origin), (folderCount.get(withFolder(origin)) ?? 0) + 1);
    }
  }
  const logLanes: LaneInfo[] = logs
    .sort((a, b) => compareStrings(a.file, b.file))
    .map((origin) => {
      const base = sourceName(origin.file);
      let label = base;
      if (baseCount.get(base) !== 1) {
        label = folderCount.get(withFolder(origin)) === 1 ? withFolder(origin) : origin.file;
      }
      return { key: laneKeyOf(origin), kind: "log" as const, label, detail: origin.file };
    });

  return [...eventLanes, ...logLanes];
}

/** The Entry text: "{eventId} · {channel}" for an event, "{file} · line {n}" for a log line. */
export function entryLabel(item: TimelineItem, lane: LaneInfo | undefined): string {
  const origin = item.origin;
  return origin.kind === "event"
    ? `${origin.eventId} · ${origin.channel}`
    : `${lane?.label ?? sourceName(origin.file)} · line ${origin.line}`;
}

/** The short name a pinned label uses: the event ID, or the log file and line. */
export function shortEntryId(item: TimelineItem, lane: LaneInfo | undefined): string {
  return item.origin.kind === "event" ? String(item.origin.eventId) : entryLabel(item, lane);
}

// ---- evidence -----------------------------------------------------------------------------------

/** Activity and related-activity ids are one key kind to the engine (`correlation_kind`). */
function keyGroup(kind: string): string {
  return kind === "activityId" || kind === "relatedActivityId" ? "activityId" : kind;
}

/**
 * The evidence rows that back one edge: rows of one of its two endpoints, for a key the edge
 * carries (same value, and the same key kind). The row's `field` can name the related-activity
 * alias while the edge names the activity id, so the kinds are compared as the engine compares them.
 * The model keeps evidence per chain, not per edge, so this is how a connector is traced.
 */
export function evidenceForEdge(
  chain: Pick<CorrelationChain, "evidence">,
  edge: Pick<CorrelationChainEdge, "left" | "right" | "keys">,
): CorrelationEvidenceRow[] {
  if (edge.right === null) return [];
  return chain.evidence.filter(
    (row) =>
      (row.originId === edge.left || row.originId === edge.right) &&
      edge.keys.some(
        (key) => key.value === row.value && keyGroup(key.kind) === keyGroup(row.field),
      ),
  );
}

// ---- the plot -----------------------------------------------------------------------------------

/**
 * What a context marker and the legend say when the session can speak for the entry: every edge is
 * loaded, nothing is narrowed, no correlation limit or truncation gap exists, and no gap names the
 * entry's own origin.
 */
export const NOT_LINKED_LABEL = "Not linked";
/**
 * What they say otherwise. An edge that was never loaded, an event the view left out, or an origin
 * the engine never correlated may link the entry; the absence of a loaded link is a coverage
 * state, not evidence of no link.
 */
export const NO_LOADED_LINK_LABEL = "No loaded link";
/**
 * What a context marker says of an entry that HAS a loaded exact or candidate partner, so it is in
 * another chain. It is a fact the edges gave, true whatever else is incomplete, and it is not
 * "Not linked": the entry is linked, to something this chain does not hold.
 */
export const IN_ANOTHER_CHAIN_LABEL = "In another chain";
/**
 * The one legend word for the dotted marker when any marker it stands for is in another chain: what
 * every such marker has in common is that it is not part of this chain, and nothing more.
 */
export const NOT_IN_THIS_CHAIN_LABEL = "Not in this chain";
/**
 * What a context marker says of an entry that has a loaded partner when the plot's own selection is
 * NOT IDENTIFIED (`selectionIdentified` false): the entry is linked to something, and whether that
 * something is the selected event cannot be told, so it is neither "in another chain" nor "not
 * linked". It is also the legend's word then: with no chain of the selected event drawn, "this
 * chain" names nothing.
 */
export const LINK_TO_EVENT_UNKNOWN_LABEL = "Link to this event not known";

export interface PlotMarker {
  id: string;
  laneKey: string;
  kind: "event" | "log";
  /** `member`: a placed entry of the chain. `nearby`: a dotted context marker, drawn for an entry that is not in the chain. */
  role: "member" | "nearby";
  timestampMs: number;
  severity: TimelineSeverity;
  level: EvtxLevel;
  entry: string;
  message: string;
  placement: Placement;
  /** "{id} · {delta} earlier" or "later" (the delta is the distance outside the window); the view draws the arrow icon. */
  pinLabel: string | null;
  /** Position among the chain's placed members in time order; null for a nearby marker. */
  sequenceIndex: number | null;
  /**
   * For a nearby marker, "In another chain", "Not linked" or "No loaded link" (see
   * `ChainPlotInput`); null for a member, which is linked or is a row that is not.
   */
  linkLabel: string | null;
}

export interface PlotLane extends LaneInfo {
  markers: PlotMarker[];
}

export interface PlotConnector {
  left: string;
  right: string;
  /** The strength of THIS edge after the weakest-label reduction, not of the chain. */
  strength: "exact" | "candidate";
  evidence: CorrelationEvidenceRow[];
}

export type UndrawnReason = "endpointWithoutItem" | "noEvidence" | "beyondMarkerCap";

export interface UndrawnEdge {
  left: string;
  right: string;
  strength: "exact" | "candidate";
  reason: UndrawnReason;
}

export interface ChainPlot {
  window: TimeWindow | null;
  ticks: number[];
  lanes: PlotLane[];
  /** Drawn members, in time order. */
  members: PlotMarker[];
  /** Drawn "Not linked" markers. Always empty in production. */
  nearby: PlotMarker[];
  connectors: PlotConnector[];
  /** Exact or candidate edges that were not drawn, with the reason. Never silent. */
  undrawnEdges: UndrawnEdge[];
  /** Placed members not drawn because of the marker cap. */
  omittedMarkers: number;
  omittedNearby: number;
  /** Drawable edges not drawn because of the connector cap. */
  omittedConnectors: number;
  /** Members with no item to draw: listed, never given a position. Why they have none is not said here. */
  membersWithoutItem: number;
  /** The legend shows the dotted entry only when such a marker is drawn. */
  showsNotLinkedLegend: boolean;
  /** The words for that legend entry and for every nearby marker. */
  notLinkedLabel: string;
}

/**
 * What the plot reads of a row. A row from the model is one; so is the dock's view of a row that
 * holds only the members inside its window, or of an entry that is in no row at all.
 */
export type PlotChain = Pick<
  CorrelationChain,
  "memberIds" | "unresolvedMemberIds" | "edges" | "evidence" | "startMs" | "endMs"
>;

/**
 * What decides the word for an entry that is not in the row it is compared with: whether the
 * session can speak for an absence of a link, the engine's coverage gaps, and the entries that have
 * a loaded partner.
 */
export interface NearbyLabelRule {
  /**
   * `sessionSpeaksForAbsence` over the members of the row the entry is compared with. A list that
   * is compared with no row (the rail's, which is session-level) asks it with no members.
   */
  chainClear: boolean;
  /** A gap that names the entry's own origin withdraws "Not linked" for it alone. */
  gaps: Pick<CorrelationGaps, "originIds">;
  /** Distinct exact and candidate partners per origin id (`linkPartnerCounts`). */
  linkPartners?: ReadonlyMap<string, number>;
  /** See `ChainPlotInput.selectionIdentified`. Defaults to true. */
  selectionIdentified?: boolean;
}

/**
 * The word for ONE entry that is not a member of the row: "In another chain" (or, when the plot's
 * selected entry is not identified, `LINK_TO_EVENT_UNKNOWN_LABEL`) for an entry with a loaded
 * partner, a fact whatever else is incomplete; "Not linked" only when the session can speak for an
 * absence and no gap names the entry; otherwise "No loaded link".
 */
export function nearbyLinkLabel(originId: string, rule: NearbyLabelRule): string {
  if ((rule.linkPartners?.get(originId) ?? 0) > 0) {
    return rule.selectionIdentified === false ? LINK_TO_EVENT_UNKNOWN_LABEL : IN_ANOTHER_CHAIN_LABEL;
  }
  return rule.chainClear && !rule.gaps.originIds.has(originId) ? NOT_LINKED_LABEL : NO_LOADED_LINK_LABEL;
}

/**
 * The ONE legend word for the dotted entry: it says "Not linked" only if every entry it stands for
 * may be called that and the session speaks. It drops to "Not in this chain" when any of them is
 * linked elsewhere, which is all they then have in common, and says the link to the event is not
 * known when any of them is. With no entry it is what the session can say about an absence.
 */
export function notLinkedLegendLabel(labels: readonly (string | null)[], chainClear: boolean): string {
  if (labels.some((label) => label === LINK_TO_EVENT_UNKNOWN_LABEL)) return LINK_TO_EVENT_UNKNOWN_LABEL;
  if (labels.some((label) => label === IN_ANOTHER_CHAIN_LABEL)) return NOT_IN_THIS_CHAIN_LABEL;
  return chainClear && labels.every((label) => label === NOT_LINKED_LABEL) ? NOT_LINKED_LABEL : NO_LOADED_LINK_LABEL;
}

export interface ChainPlotInput {
  chain: PlotChain;
  itemsById: ReadonlyMap<string, TimelineItem>;
  /**
   * Every timeline edge of the session was loaded (`CorrelationChainModel.edgeInputComplete`).
   * Required, with no default: a caller that does not know must say so (false).
   */
  edgeInputComplete: boolean;
  /**
   * The view is narrowed (visible events fewer than loaded events, or a scope that is not known), so
   * an event outside it may link an entry shown here. Required for the same reason.
   */
  scopeNarrowed: boolean;
  /**
   * Some source's records were not (all) loaded (`useUnreadSources`), so an event that never reached
   * the session may link an entry shown here. Required for the same reason.
   */
  unreadSources: boolean;
  /**
   * The model on show is an earlier session's and a newer one is being built, so a negative claim
   * from it is unproven. Required for the same reason.
   */
  updating: boolean;
  /**
   * The engine's correlation coverage gaps (`classifyCoverageGaps`). Required: a limit or
   * truncation gap, a preview that does not show every gap, a gap naming an entry's own origin,
   * or a gap naming a member of the chain each stop "Not linked" from being said (an uncorrelated
   * entry has no edge because none was computed).
   */
  gaps: CorrelationGaps;
  /** Overrides the default window (the zoom band, a later phase). */
  window?: TimeWindow | null;
  /**
   * Context entries to draw as dotted markers: entries that are not in the chain. The Correlation
   * view passes none; the dock passes the other items of its window (a time-proximity read, never a
   * relation: they get no connector, no chain and no count).
   */
  nearby?: readonly TimelineItem[];
  /**
   * Distinct exact and candidate partners per origin id (`linkPartnerCounts`), so a context entry
   * that is linked elsewhere is called "In another chain" and never "Not linked". Optional: without
   * it no entry is known to be linked and the labels are the other two.
   */
  linkPartners?: ReadonlyMap<string, number>;
  /**
   * The plot's selected entry was identified. False when it could not be (several entries could be
   * it, or the read stopped before it): an entry with a loaded partner may then be linked TO IT, so
   * it is called `LINK_TO_EVENT_UNKNOWN_LABEL`, never "In another chain". "Not linked" and "No
   * loaded link" are facts about the entry itself and are unchanged. Defaults to true.
   */
  selectionIdentified?: boolean;
  markerCap?: number;
  connectorCap?: number;
}

function isLinkingStrength(strength: CorrelationChainStrength): strength is "exact" | "candidate" {
  return strength === "exact" || strength === "candidate";
}

interface AbsenceInput {
  /** Every timeline edge of the session was loaded. */
  edgeInputComplete: boolean;
  /** See `ChainPlotInput.scopeNarrowed`. */
  scopeNarrowed: boolean;
  /** See `ChainPlotInput.unreadSources`. */
  unreadSources: boolean;
  /** See `ChainPlotInput.updating`. */
  updating: boolean;
  gaps: CorrelationGaps;
  /** Every member of the row the entry is compared with, placed or not. */
  memberIds: Iterable<string>;
}

/**
 * Whether the session can speak for the ABSENCE of a link: "Not linked" is a claim about the whole
 * session, so it needs every edge, every event and every origin correlated. Three caveats say events
 * may be missing or superseded: the scope is narrowed, a source was not fully read, or a rebuild is
 * under way. They are separate inputs, never one folded flag, and any one of them withdraws the
 * claim. A gap that names an entry's own origin withdraws it for that entry alone (a per-entry
 * check the caller makes with `gaps.originIds`). A gap that names a MEMBER of the row withdraws it
 * for every entry and the legend: some gaps are specific to one observation (an identity alias
 * conflict, an invalid process start), and for such a member the key it would share with a context
 * entry was never computed. Every member counts, not only the drawn ones, because the key was lost
 * whether or not the member is drawn.
 *
 * The plot's labels read it, and so does the Details context list, which decides with it whether a
 * missing link icon needs a caveat: one rule for "no link was found, and that means something".
 */
export function sessionSpeaksForAbsence(input: AbsenceInput): boolean {
  if (!input.edgeInputComplete || gapsClearCompleteness(input.gaps)) return false;
  if (input.scopeNarrowed || input.unreadSources || input.updating) return false;
  for (const id of input.memberIds) {
    if (input.gaps.originIds.has(id)) return false;
  }
  return true;
}

export function buildChainPlot(input: ChainPlotInput): ChainPlot {
  const { chain, itemsById } = input;
  // A gap that names an entry's own origin withdraws "Not linked" for that entry alone
  // (`nearbyLinkLabel`); the rest of the rule is `sessionSpeaksForAbsence`.
  const chainClear = sessionSpeaksForAbsence({
    edgeInputComplete: input.edgeInputComplete,
    scopeNarrowed: input.scopeNarrowed,
    unreadSources: input.unreadSources,
    updating: input.updating,
    gaps: input.gaps,
    memberIds: [...chain.memberIds, ...chain.unresolvedMemberIds],
  });
  const labelRule: NearbyLabelRule = {
    chainClear,
    gaps: input.gaps,
    linkPartners: input.linkPartners,
    selectionIdentified: input.selectionIdentified,
  };
  const markerCap = input.markerCap ?? CORRELATION_MARKER_CAP;
  const connectorCap = input.connectorCap ?? CORRELATION_CONNECTOR_CAP;
  const placed = chain.memberIds.flatMap((id) => {
    const item = itemsById.get(id);
    return item === undefined ? [] : [{ id, item }];
  });
  const membersWithoutItem =
    chain.unresolvedMemberIds.length + (chain.memberIds.length - placed.length);
  const window =
    input.window !== undefined
      ? input.window
      : defaultLaneWindow(chain.startMs, chain.endMs);
  const memberIds = new Set(placed.map((entry) => entry.id));

  const empty: ChainPlot = {
    window,
    ticks: window === null ? [] : axisTicks(window),
    lanes: [],
    members: [],
    nearby: [],
    connectors: [],
    undrawnEdges: [],
    omittedMarkers: placed.length,
    omittedNearby: 0,
    omittedConnectors: 0,
    membersWithoutItem,
    showsNotLinkedLegend: false,
    notLinkedLabel: notLinkedLegendLabel([], chainClear),
  };
  if (window === null) return empty;

  // A context entry that belongs to the chain is a member, never a "Not linked" marker.
  const context = [...(input.nearby ?? [])]
    .filter((item) => !memberIds.has(timelineOriginId(item.origin)))
    .sort((a, b) => a.timestampMs - b.timestampMs || compareStrings(timelineOriginId(a.origin), timelineOriginId(b.origin)));
  const drawnMembers = placed.slice(0, markerCap);
  const drawnContext = context.slice(0, markerCap);

  const laneInfos = describeLanes([
    ...drawnMembers.map((entry) => entry.item.origin),
    ...drawnContext.map((item) => item.origin),
  ]);
  const laneByKey = new Map(laneInfos.map((lane) => [lane.key, lane]));

  const marker = (
    id: string,
    item: TimelineItem,
    role: "member" | "nearby",
    sequenceIndex: number | null,
  ): PlotMarker => {
    const laneKey = laneKeyOf(item.origin);
    const lane = laneByKey.get(laneKey);
    const entry = entryLabel(item, lane);
    const placement = placeInWindow(item.timestampMs, window);
    return {
      id,
      laneKey,
      kind: item.origin.kind,
      role,
      timestampMs: item.timestampMs,
      severity: item.severity,
      level: levelOfSeverity(item.severity),
      entry,
      message: item.message,
      placement,
      pinLabel:
        placement.pinned === null
          ? null
          : `${shortEntryId(item, lane)} · ${formatDelta(placement.outsideMs)} ${placement.pinned === "before" ? "earlier" : "later"}`,
      sequenceIndex,
      linkLabel: role === "nearby" ? nearbyLinkLabel(id, labelRule) : null,
    };
  };

  const members = drawnMembers.map((entry, index) => marker(entry.id, entry.item, "member", index));
  const nearby = drawnContext.map((item) =>
    marker(timelineOriginId(item.origin), item, "nearby", null),
  );
  const drawnIds = new Set(members.map((m) => m.id));

  const connectors: PlotConnector[] = [];
  const undrawnEdges: UndrawnEdge[] = [];
  let omittedConnectors = 0;
  for (const edge of chain.edges) {
    // Only an exact or candidate edge is ever a link; the others are never drawn, whatever the row.
    if (edge.right === null || !isLinkingStrength(edge.strength)) continue;
    const base = { left: edge.left, right: edge.right, strength: edge.strength };
    if (!memberIds.has(edge.left) || !memberIds.has(edge.right)) {
      undrawnEdges.push({ ...base, reason: "endpointWithoutItem" });
      continue;
    }
    if (!drawnIds.has(edge.left) || !drawnIds.has(edge.right)) {
      undrawnEdges.push({ ...base, reason: "beyondMarkerCap" });
      continue;
    }
    const evidence = evidenceForEdge(chain, edge);
    if (evidence.length === 0) {
      undrawnEdges.push({ ...base, reason: "noEvidence" });
      continue;
    }
    if (connectors.length >= connectorCap) {
      omittedConnectors += 1;
      continue;
    }
    connectors.push({ ...base, evidence });
  }

  const lanes: PlotLane[] = laneInfos.map((lane) => ({
    ...lane,
    markers: [...members, ...nearby].filter((m) => m.laneKey === lane.key),
  }));

  return {
    window,
    ticks: axisTicks(window),
    lanes,
    members,
    nearby,
    connectors,
    undrawnEdges,
    omittedMarkers: placed.length - members.length,
    omittedNearby: context.length - nearby.length,
    omittedConnectors,
    membersWithoutItem,
    showsNotLinkedLegend: nearby.length > 0,
    // One legend entry for the dotted marker, in the one word every marker it stands for may carry.
    notLinkedLabel: notLinkedLegendLabel(
      nearby.map((marker) => marker.linkLabel),
      chainClear,
    ),
  };
}

// ---- what is known about members with no item ----------------------------------------------------

/** What is known about entries that have no item: the scan and the unplaced list. */
export interface UnplacedEvidence {
  /** Every timeline page was read (`LoadedLinkedItems.complete`). */
  scanComplete: boolean;
  /** The unplaced preview holds every unplaced item (preview length equals the session's count). */
  unplacedListComplete: boolean;
  unplacedIds: ReadonlySet<string>;
}

/**
 * Whether an entry is PROVEN to carry no timestamp: the scan finished, the unplaced list is
 * complete, and the id is on it. This is the one proof behind every string that says an entry is
 * "not placed" or "without a timeline position". Without it the most that can be said is that no
 * position was loaded, which is true whatever the reason.
 */
export function isProvenUnplaced(id: string, evidence: UnplacedEvidence): boolean {
  return evidence.scanComplete && evidence.unplacedListComplete && evidence.unplacedIds.has(id);
}

/** `ids` split by `isProvenUnplaced`, each part in the order given. */
export function partitionUnplaced(
  ids: readonly string[],
  evidence: UnplacedEvidence,
): { proven: string[]; unknown: string[] } {
  const proven: string[] = [];
  const unknown: string[] = [];
  for (const id of ids) (isProvenUnplaced(id, evidence) ? proven : unknown).push(id);
  return { proven, unknown };
}

// ---- tables and lists ---------------------------------------------------------------------------

export interface WhyRow {
  originId: string;
  /** "{eventId} · {channel}" or "{file} · line {n}"; a fixed phrase when the entry has no position. */
  entry: string;
  /** False when the entry has no timeline item: its text is not an entry label. */
  placed: boolean;
  field: string;
  value: string;
}

/** The Entry text for an entry with no item, once it is proven to carry no timestamp. */
export const UNPLACED_ENTRY = "Entry without a timeline position";
/** The Entry text for any other entry with no item: true whatever the reason. */
export const UNLOADED_ENTRY = "Entry with no loaded timeline position";

/**
 * The "Why these are linked" rows: one per evidence row of the chain, grouped by entry in the
 * chain's time order (entries with no item last), then by field and value. An entry with no item
 * is called "without a timeline position" only when `unplaced` proves it; with no evidence given,
 * or none that proves it, the text says only that no position was loaded.
 */
export function whyRows(
  chain: CorrelationChain,
  itemsById: ReadonlyMap<string, TimelineItem>,
  unplaced?: UnplacedEvidence,
): WhyRow[] {
  const lanes = new Map(
    describeLanes(
      chain.memberIds.flatMap((id) => {
        const item = itemsById.get(id);
        return item === undefined ? [] : [item.origin];
      }),
    ).map((lane) => [lane.key, lane]),
  );
  const position = new Map(chain.memberIds.map((id, index) => [id, index]));
  return [...chain.evidence]
    .sort(
      (a, b) =>
        (position.get(a.originId) ?? Number.MAX_SAFE_INTEGER) -
          (position.get(b.originId) ?? Number.MAX_SAFE_INTEGER) ||
        compareStrings(a.originId, b.originId) ||
        compareStrings(a.field, b.field) ||
        compareStrings(a.value, b.value),
    )
    .map((row) => {
      const item = itemsById.get(row.originId);
      return {
        originId: row.originId,
        entry:
          item === undefined
            ? unplaced !== undefined && isProvenUnplaced(row.originId, unplaced)
              ? UNPLACED_ENTRY
              : UNLOADED_ENTRY
            : entryLabel(item, lanes.get(laneKeyOf(item.origin))),
        placed: item !== undefined,
        field: row.field,
        value: row.value,
      };
    });
}

export interface SequenceEntry {
  id: string;
  index: number;
  entry: string;
  laneLabel: string;
  timestampMs: number;
  /** From the first placed member; 0 for the first. */
  offsetMs: number;
  level: EvtxLevel;
  message: string;
  /** The same timestamp as the member before it: their order is not established by time. */
  sameTimeAsPrevious: boolean;
  /** The member the title is drawn from (D19): highest severity, then earliest, then id. */
  highestSeverity: boolean;
  /** `EVT` for a Windows event, `LOG` for a text-log line: the chip's one rule, `chipForOriginKind`. */
  chip: KindChip;
}

export interface ChainSequence {
  entries: SequenceEntry[];
  /** Members with no item, by id. Never given a place in the order. Whether they are unplaced is `isProvenUnplaced`'s to say. */
  itemlessIds: string[];
}

/** The chain's members in time order, with offsets from the first. */
export function chainSequence(
  chain: CorrelationChain,
  itemsById: ReadonlyMap<string, TimelineItem>,
): ChainSequence {
  const placed = chain.memberIds.flatMap((id) => {
    const item = itemsById.get(id);
    return item === undefined ? [] : [{ id, item }];
  });
  const lanes = new Map(
    describeLanes(placed.map((entry) => entry.item.origin)).map((lane) => [lane.key, lane]),
  );
  let best = -1;
  placed.forEach((entry, index) => {
    if (best < 0) {
      best = index;
      return;
    }
    const current = placed[best]!;
    const rank =
      TIMELINE_SEVERITY_RANK[entry.item.severity] - TIMELINE_SEVERITY_RANK[current.item.severity];
    if (
      rank > 0 ||
      (rank === 0 &&
        (entry.item.timestampMs < current.item.timestampMs ||
          (entry.item.timestampMs === current.item.timestampMs && entry.id < current.id)))
    ) {
      best = index;
    }
  });
  const entries = placed.map(({ id, item }, index) => {
    const lane = lanes.get(laneKeyOf(item.origin));
    return {
      id,
      index,
      entry: entryLabel(item, lane),
      laneLabel: lane?.label ?? "",
      timestampMs: item.timestampMs,
      offsetMs: item.timestampMs - (placed[0]?.item.timestampMs ?? item.timestampMs),
      level: levelOfSeverity(item.severity),
      message: item.message,
      sameTimeAsPrevious:
        index > 0 && placed[index - 1]!.item.timestampMs === item.timestampMs,
      highestSeverity: index === best,
      chip: chipForOriginKind(item.origin.kind),
    };
  });
  return {
    entries,
    itemlessIds: [
      ...chain.unresolvedMemberIds,
      ...chain.memberIds.filter((id) => !itemsById.has(id)),
    ].sort(compareStrings),
  };
}

// ---- header text --------------------------------------------------------------------------------

/** `value` cut in the middle to `max` characters, with one ellipsis. Counts code points. */
export function middleTruncate(value: string, max = KEY_VALUE_DISPLAY_CHARS): string {
  const points = Array.from(value);
  if (points.length <= max) return value;
  const keep = Math.max(2, max - 1);
  const head = Math.ceil(keep / 2);
  const tail = keep - head;
  return `${points.slice(0, head).join("")}…${points.slice(points.length - tail).join("")}`;
}

export interface KeyHeader {
  kind: string;
  value: string;
  shortValue: string;
  /** Further keys the row carries. */
  more: number;
}

/** The header's "key {kind} {value}": the first key, how many more there are. Null with no key. */
export function keyHeader(keys: readonly TimelineCorrelationKey[]): KeyHeader | null {
  const first = keys[0];
  if (first === undefined) return null;
  return {
    kind: first.kind,
    value: first.value,
    shortValue: middleTruncate(first.value),
    more: keys.length - 1,
  };
}

/** Who is told the link is partial: any member with no timeline position. */
export function isPartialChain(chain: Pick<CorrelationChain, "unresolvedMemberIds">): boolean {
  return chain.unresolvedMemberIds.length > 0;
}

/** "{n} entries": the count of ALL members, placed or not. */
export function entriesText(memberCount: number): string {
  return `${memberCount.toLocaleString()} ${memberCount === 1 ? "entry" : "entries"}`;
}

/**
 * The title of a row with none. It claims nothing: a chain has no title until an item is read for
 * one of its members, which says nothing about whether any member has a position.
 */
export const UNTITLED_CHAIN = "Untitled chain";

/** The row title: the derived title, or a neutral fallback. */
export function chainTitle(chain: Pick<CorrelationChain, "title">): string {
  return chain.title ?? UNTITLED_CHAIN;
}

/**
 * The accessible name of a row. A titled row is named by its title; an untitled one keeps its id,
 * so two untitled rows are still told apart by a screen reader.
 */
export function chainAccessibleName(chain: Pick<CorrelationChain, "title" | "id">): string {
  return chain.title ?? `${UNTITLED_CHAIN} ${chain.id}`;
}

// ---- selection ----------------------------------------------------------------------------------

export interface ReconciledSelection {
  selectedId: string | null;
  /** The chain the operator had selected is gone, so another was chosen (or none). */
  lost: boolean;
}

/**
 * The selection to show: the selected chain when it still exists, else the first, else none.
 * `lost` is true when a selection existed and could not be kept, so the view can announce it
 * instead of silently showing another chain's evidence.
 */
export function reconcileSelection(
  chains: readonly { id: string }[],
  selectedId: string | null,
): ReconciledSelection {
  if (selectedId !== null && chains.some((chain) => chain.id === selectedId)) {
    return { selectedId, lost: false };
  }
  return { selectedId: chains[0]?.id ?? null, lost: selectedId !== null };
}

export interface ListedRows {
  /** The capped rows, then the selected row when the cap dropped it. */
  rows: readonly CorrelationChain[];
  /** The id of the selected row when it is listed past the cap, else null. */
  pastCapId: string | null;
}

/**
 * The rows the list shows: the model's capped `chains`, plus the selected row when the render cap
 * dropped it. The dock and the rail open a row by id from a record's own chain (found through
 * `rowsByMember`, which the cap does not trim), and that row can be one of thousands. Without this
 * the selection would read as lost and another row would be shown in its place.
 *
 * The extra row is listed AFTER the capped ones, so the order of the capped rows never moves and
 * the cap notice stays true. An id that no row has is not listed, and `reconcileSelection` then
 * reports the loss.
 */
export function listedRows(
  model: Pick<CorrelationChainModel, "chains" | "rowsByMember">,
  selectedId: string | null,
): ListedRows {
  if (selectedId === null || model.chains.some((row) => row.id === selectedId)) {
    return { rows: model.chains, pastCapId: null };
  }
  for (const rows of model.rowsByMember.values()) {
    const row = rows.find((candidate) => candidate.id === selectedId);
    if (row !== undefined) return { rows: [...model.chains, row], pastCapId: row.id };
  }
  return { rows: model.chains, pastCapId: null };
}

/** Distinct partners of each placed member by link strength, for a marker's accessible name. */
export function memberLinkSummary(
  chain: Pick<CorrelationChain, "edges">,
): Map<string, { exact: number; candidate: number }> {
  const partners = new Map<string, { exact: Set<string>; candidate: Set<string> }>();
  const add = (id: string, other: string, strength: "exact" | "candidate") => {
    const entry = partners.get(id) ?? { exact: new Set<string>(), candidate: new Set<string>() };
    entry[strength].add(other);
    partners.set(id, entry);
  };
  for (const edge of chain.edges) {
    if (edge.right === null || !isLinkingStrength(edge.strength)) continue;
    add(edge.left, edge.right, edge.strength);
    add(edge.right, edge.left, edge.strength);
  }
  return new Map(
    [...partners].map(([id, entry]) => [id, { exact: entry.exact.size, candidate: entry.candidate.size }]),
  );
}
