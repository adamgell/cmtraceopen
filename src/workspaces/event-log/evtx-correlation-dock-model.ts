/**
 * What the correlation dock shows for one selected event and one window read (spec 8.12, #842).
 *
 * Pure: no React, no stores, no IO. The component stays thin because every decision is made here and
 * tested here. The inputs are three facts the caller holds: the selected record, the window that was
 * read around it (`loadCorrelationWindow`), and the counts-only chain model of the session the window
 * came from. Nothing here scans the timeline: the dock reads the items inside its window and the rows
 * and edges the counts hold, and says plainly what that leaves out.
 *
 * Rules, all enforced here:
 * - A window answers ONE center. A record whose timestamp is another center is not paired with it.
 * - The counts are paired with the window only when they are the SAME session and are current
 *   (`builtFor` equals the window's session key, and they are not marked updating). Otherwise no
 *   entry is called linked or not linked, and no connector is drawn.
 * - The selected record's origin is found in the other direction than the engine gives it: the window
 *   items are tested against the record with the origin join's own matchers. An id is never rebuilt.
 *   An origin that is no item of the window is not found, and the dock says so.
 * - The record's row is the strongest row of `rowsByMember` (uncapped, so a chain past the view's 100
 *   rows is found). Members of it that have no item in the window are counted and never placed.
 * - Every other entry of the window is CONTEXT: there by its time and for nothing else. It gets no
 *   connector, no chain and no count. Its words are `nearbyReason`'s: "not linked" only under the
 *   plot's full rule, "in another chain" when the edges show a partner, and otherwise "no loaded link".
 * - Every cap says how much it left out: nothing is hidden silently, and an unknown count is never
 *   shown as 0.
 */
import { buildEvidenceIndex } from "./evtx-insights-data";
import {
  derivedTitle,
  messageHead,
  type CorrelationChain,
} from "./evtx-correlation-chains";
import {
  AMBIGUOUS_EVENT_NOTE,
  DOCK_SCOPE_NOTE,
  LINKS_LOADING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  STRENGTH_LABELS,
  UNREAD_SOURCES_NOTE,
  coverageGapNotice,
  dockOmissionNotice,
  edgeInputNotice,
  emptyWindowText,
  keyKindLabel,
  nearbyReason,
  outsideWindowNote,
  partialChainTitle,
  scopeDisclosure,
  sourcesText,
  windowNotice,
  type NearbyReason,
  type OpenDisabled,
} from "./evtx-correlation-copy";
import { UNKNOWN_CORRELATION_GAPS } from "./evtx-correlation-gaps";
import { itemsByOriginId, resolveOriginRecords } from "./evtx-correlation-origin-index";
import {
  IN_ANOTHER_CHAIN_LABEL,
  NOT_LINKED_LABEL,
  buildChainPlot,
  describeLanes,
  keyHeader,
  laneKeyOf,
  shortEntryId,
  type ChainPlot,
  type KeyHeader,
  type PlotChain,
  type PlotMarker,
} from "./evtx-correlation-view-model";
import type { LoadedCorrelationWindow } from "./evtx-correlation-window";
import { hasUsableTimestamp } from "./evtx-filter";
import { formatClock, type EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxRecord } from "./types";
import type { CorrelationCounts } from "./useEvtxCorrelation";
import { timelineOriginId, type TimelineItem } from "./unified-timeline";

/** Spec 8.12: up to five lanes. */
export const DOCK_MAX_LANES = 5;
/** Context markers drawn at most, nearest the selected event first. */
export const DOCK_NEARBY_MARKER_CAP = 60;
/** Spec 8.12: the chain's members as steps, up to four. */
export const DOCK_STEP_CAP = 4;
/** Entries named on the "Also nearby" line. */
export const DOCK_NEARBY_LINE_CAP = 4;

/** The part of the counts-only model the dock reads: one session's rows, partners, gaps and scope. */
export type DockCounts = Pick<
  CorrelationCounts,
  "model" | "builtFor" | "linkPartners" | "gaps" | "scope" | "updating"
>;

export interface DockModelInput {
  /** The selected record, or null for none. */
  record: EvtxRecord | null;
  /** What was read around the record, or null before any read. */
  window: LoadedCorrelationWindow | null;
  /** The newest session's counts-only model, or null before it is in. */
  counts: DockCounts | null;
  /** A source was not fully read (a channel needs elevation, a file failed): entries may be missing. */
  unreadSources: boolean;
}

export interface DockStep {
  id: string;
  timestampMs: number;
  /** The event ID, or the log file and line. */
  entry: string;
  message: string;
}

export interface DockNearbyEntry {
  id: string;
  /** "{eventId} · {channel}" or "{file} · line {n}". */
  entry: string;
  /** Milliseconds from the selected event, negative before it. */
  deltaMs: number;
  reason: NearbyReason;
}

export interface DockRow {
  id: string;
  strength: CorrelationChain["strength"];
  title: string;
  key: KeyHeader | null;
  memberCount: number;
  /** Members that have an item in the window. */
  inWindow: number;
  /** Members that have none: counted, never placed. */
  outsideWindow: number;
  /** Other rows the selected event is also in. */
  otherRows: number;
}

export type DockSelected =
  | { status: "found"; originId: string }
  | { status: "notInTimeline" }
  | { status: "ambiguous" };

/** What activating a marker can do: select its record, or nothing, and why. */
export type MarkerSelectability = "event" | "log" | "selected" | "ambiguous" | "notLoaded";

/** What the dock knows about one drawn marker, for its accessible name. */
export interface MarkerFacts {
  role: "selected" | "member" | "nearby";
  /** The words after "time only", for a nearby marker. */
  reason: NearbyReason | null;
  /** The row's strength, for a member. */
  strength: CorrelationChain["strength"] | null;
  key: KeyHeader | null;
  selectability: MarkerSelectability;
}

export interface DockReady {
  kind: "ready";
  eventId: number;
  centerMs: number;
  halfWidthMs: number;
  /** The session and revision the window was read from. */
  sessionKey: string;
  /** "{n} sources", or "at least {n} sources" when the window was not read whole. */
  sources: string;
  sourceCount: number;
  /** The counts belong to the window's session and are current: links and strengths are known. */
  paired: boolean;
  selected: DockSelected;
  row: DockRow | null;
  steps: DockStep[];
  moreSteps: number;
  nearby: DockNearbyEntry[];
  /** Nearby entries in the window that the line does not name. */
  moreNearby: number;
  plot: ChainPlot;
  facts: ReadonlyMap<string, MarkerFacts>;
  /** One line each, in the order they are shown. */
  notices: string[];
  /** Set when no other source has an entry in a window that was read whole. */
  empty: { text: string; absolute: boolean } | null;
  open: { rowId: string } | { disabled: OpenDisabled };
}

export type DockModel =
  | { kind: "noSelection" }
  | { kind: "untimed" }
  /** There is no read for this selection (yet): the window is null or answers another center. */
  | { kind: "unread" }
  /** The first reply never came, so even the count of entries is not known. */
  | { kind: "failed"; error: string | null }
  | DockReady;

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function isLinking(strength: CorrelationChain["strength"]): boolean {
  return strength === "exact" || strength === "candidate";
}

/** The words for a context marker's label, which `buildChainPlot` decided. */
function reasonOfLabel(label: string | null): NearbyReason {
  if (label === NOT_LINKED_LABEL) return "notLinked";
  if (label === IN_ANOTHER_CHAIN_LABEL) return "inAnotherChain";
  return "noLoadedLink";
}

/**
 * The origin ids of the window's event items that name `record`, found with the origin join's own
 * matchers against an index of that one record. Never a rebuilt stable id.
 */
function originsNaming(record: EvtxRecord, items: readonly TimelineItem[]): Set<string> {
  const index = buildEvidenceIndex([record]);
  const found = new Set<string>();
  for (const item of items) {
    if (item.origin.kind !== "event") continue;
    const resolution = resolveOriginRecords(item.origin, index);
    if (resolution.kind === "matches" && resolution.records.includes(record)) {
      found.add(timelineOriginId(item.origin));
    }
  }
  return found;
}

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

export function buildDockModel(input: DockModelInput): DockModel {
  const { record, window, counts } = input;
  if (record === null) return { kind: "noSelection" };
  if (!hasUsableTimestamp(record) || !Number.isSafeInteger(record.timestampEpoch)) {
    return { kind: "untimed" };
  }
  // A window answers one center. Another selection's window is never shown under this record.
  if (window === null || window.centerMs !== record.timestampEpoch) return { kind: "unread" };
  if (window.windowItems === null) return { kind: "failed", error: window.error };

  const paired =
    counts !== null && !counts.updating && counts.builtFor === window.sessionKey;
  const pairedCounts = paired ? counts : null;
  const byId = itemsByOriginId(window.items);
  const items = [...byId.values()];

  // ---- the selected event, in the window ----
  const naming = originsNaming(record, items);
  const selected: DockSelected =
    naming.size === 1
      ? { status: "found", originId: [...naming][0] as string }
      : naming.size === 0
        ? { status: "notInTimeline" }
        : { status: "ambiguous" };
  const originId = selected.status === "found" ? selected.originId : null;

  // ---- its rows, from the uncapped index of the SAME session ----
  const rows =
    pairedCounts !== null && originId !== null
      ? (pairedCounts.model.rowsByMember.get(originId) ?? [])
      : [];
  const row = rows[0] ?? null;
  const rowMembers =
    row === null
      ? []
      : [...new Set([...row.memberIds, ...row.unresolvedMemberIds])].sort(compareStrings);
  const inWindowMembers = new Set<string>(
    row === null ? (originId === null ? [] : [originId]) : rowMembers.filter((id) => byId.has(id)),
  );

  // ---- lanes: at most five, the selected event's first, then the chain's, then the busiest ----
  const laneInfos = describeLanes(items.map((item) => item.origin));
  const laneOrder = new Map(laneInfos.map((lane, index) => [lane.key, index]));
  const entriesInLane = new Map<string, number>();
  for (const item of items) {
    const key = laneKeyOf(item.origin);
    entriesInLane.set(key, (entriesInLane.get(key) ?? 0) + 1);
  }
  const selectedLane = originId === null ? null : laneKeyOf((byId.get(originId) as TimelineItem).origin);
  const memberLanes = new Set(
    [...inWindowMembers].map((id) => laneKeyOf((byId.get(id) as TimelineItem).origin)),
  );
  const priority = (key: string) => (key === selectedLane ? 0 : memberLanes.has(key) ? 1 : 2);
  const chosenLanes = new Set(
    laneInfos
      .map((lane) => lane.key)
      .sort(
        (a, b) =>
          priority(a) - priority(b) ||
          (entriesInLane.get(b) ?? 0) - (entriesInLane.get(a) ?? 0) ||
          (laneOrder.get(a) ?? 0) - (laneOrder.get(b) ?? 0),
      )
      .slice(0, DOCK_MAX_LANES),
  );
  const drawable = items.filter((item) => chosenLanes.has(laneKeyOf(item.origin)));
  const drawableById = itemsByOriginId(drawable);
  const omittedSources = laneInfos.length - chosenLanes.size;
  const omittedSourceEntries = items.length - drawable.length;

  // ---- the part of the row the plot is given ----
  const byTime = (a: string, b: string) =>
    ((byId.get(a) as TimelineItem).timestampMs - (byId.get(b) as TimelineItem).timestampMs) ||
    compareStrings(a, b);
  const part = chainInWindow(row, originId, drawableById);

  // ---- context: everything else in the window, nearest the selected event first ----
  const byDistance = (a: TimelineItem, b: TimelineItem) =>
    Math.abs(a.timestampMs - record.timestampEpoch) - Math.abs(b.timestampMs - record.timestampEpoch) ||
    compareStrings(timelineOriginId(a.origin), timelineOriginId(b.origin));
  const context = drawable
    .filter((item) => !inWindowMembers.has(timelineOriginId(item.origin)))
    .sort(byDistance);
  const drawnContext = context.slice(0, DOCK_NEARBY_MARKER_CAP);
  const allContextCount = items.filter((item) => !inWindowMembers.has(timelineOriginId(item.origin))).length;

  const narrowed = pairedCounts === null ? true : scopeDisclosure(pairedCounts.scope) !== null;
  const plot = buildChainPlot({
    chain: part,
    itemsById: drawableById,
    edgeInputComplete: pairedCounts === null ? false : pairedCounts.model.edgeInputComplete,
    narrowed,
    gaps: pairedCounts === null ? UNKNOWN_CORRELATION_GAPS : pairedCounts.gaps,
    window: { startMs: window.startMs, endMs: window.endMs },
    nearby: drawnContext,
    linkPartners: pairedCounts === null ? undefined : pairedCounts.linkPartners,
  });

  // ---- entries the selected event shares a non-linking row with are named for it ----
  const annotations = new Map<string, NearbyReason>();
  for (const candidate of rows) {
    if (isLinking(candidate.strength)) continue;
    const reason: NearbyReason =
      candidate.strength === "ambiguous" ? "ambiguousWithEvent" : "coverageBlockedWithEvent";
    for (const id of [...candidate.memberIds, ...candidate.unresolvedMemberIds]) {
      if (id !== originId && !annotations.has(id)) annotations.set(id, reason);
    }
  }
  const reasonFor = (marker: PlotMarker): NearbyReason =>
    annotations.get(marker.id) ?? reasonOfLabel(marker.linkLabel);

  const nearby: DockNearbyEntry[] = [...plot.nearby]
    .sort(
      (a, b) =>
        Math.abs(a.timestampMs - record.timestampEpoch) - Math.abs(b.timestampMs - record.timestampEpoch) ||
        compareStrings(a.id, b.id),
    )
    .slice(0, DOCK_NEARBY_LINE_CAP)
    .map((marker) => ({
      id: marker.id,
      entry: marker.entry,
      deltaMs: marker.timestampMs - record.timestampEpoch,
      reason: reasonFor(marker),
    }));

  // ---- the summary of the row ----
  const keys = row === null ? null : keyHeader(row.keys);
  const lanesByKey = new Map(laneInfos.map((lane) => [lane.key, lane]));
  const memberItems = [...inWindowMembers].sort(byTime);
  const steps: DockStep[] = memberItems.slice(0, DOCK_STEP_CAP).map((id) => {
    const item = byId.get(id) as TimelineItem;
    return {
      id,
      timestampMs: item.timestampMs,
      entry: shortEntryId(item, lanesByKey.get(laneKeyOf(item.origin))),
      message: messageHead(item.message),
    };
  });
  const outside = row === null ? 0 : rowMembers.filter((id) => !byId.has(id)).length;
  const dockRow: DockRow | null =
    row === null
      ? null
      : {
          id: row.id,
          strength: row.strength,
          // The title is the model's own (D19) only when every entry of the row is in the window.
          title:
            outside === 0
              ? (derivedTitle(rowMembers, byId) ?? partialChainTitle(row.memberCount, inWindowMembers.size))
              : partialChainTitle(row.memberCount, inWindowMembers.size),
          key: keys,
          memberCount: row.memberCount,
          inWindow: inWindowMembers.size,
          outsideWindow: outside,
          otherRows: rows.length - 1,
        };

  // ---- what each drawn marker is, for its name ----
  const facts = new Map<string, MarkerFacts>();
  for (const marker of [...plot.members, ...plot.nearby]) {
    const isSelected = marker.id === originId;
    const resolution: MarkerSelectability = isSelected
      ? "selected"
      : marker.kind === "log"
        ? "log"
        : "event";
    facts.set(marker.id, {
      role: isSelected ? "selected" : marker.role === "member" ? "member" : "nearby",
      reason: marker.role === "nearby" ? reasonFor(marker) : null,
      strength: marker.role === "member" && row !== null ? row.strength : null,
      key: marker.role === "member" ? keys : null,
      selectability: resolution,
    });
  }

  // ---- notices, in the order they are shown ----
  const notices: string[] = [];
  const push = (text: string | null) => {
    if (text !== null) notices.push(text);
  };
  push(windowNotice(window));
  if (pairedCounts === null) {
    push(LINKS_LOADING_TEXT);
  } else {
    push(
      edgeInputNotice({
        edgeInputComplete: pairedCounts.model.edgeInputComplete,
        unloadedEdgeCount: pairedCounts.model.unloadedEdgeCount,
      }),
    );
    push(coverageGapNotice(pairedCounts.gaps));
    const scope = scopeDisclosure(pairedCounts.scope);
    if (scope !== null) {
      push(scope.strengthNote);
      push(scope.textLogNote);
      push(DOCK_SCOPE_NOTE);
    }
  }
  if (input.unreadSources) push(UNREAD_SOURCES_NOTE);
  if (selected.status === "notInTimeline") push(NOT_IN_TIMELINE_NOTE);
  if (selected.status === "ambiguous") push(AMBIGUOUS_EVENT_NOTE);
  if (dockRow !== null) push(outsideWindowNote(dockRow.outsideWindow, dockRow.memberCount));
  push(
    dockOmissionNotice({
      omittedMarkers: plot.omittedMarkers,
      omittedNearby: context.length - drawnContext.length + plot.omittedNearby,
      omittedConnectors: plot.omittedConnectors,
      omittedSources,
      omittedSourceEntries,
    }),
  );

  // ---- "no other sources", an absence claim, only for a window read whole ----
  const hasOtherSource = items.some((item) =>
    selectedLane === null ? true : laneKeyOf(item.origin) !== selectedLane,
  );
  const empty =
    window.complete && !hasOtherSource
      ? emptyWindowText({
          halfWidthMs: window.halfWidthMs,
          narrowed,
          unreadSources: input.unreadSources,
        })
      : null;

  const open: DockReady["open"] =
    dockRow !== null
      ? { rowId: dockRow.id }
      : {
          disabled: !paired
            ? "loading"
            : selected.status === "notInTimeline"
              ? "notInTimeline"
              : selected.status === "ambiguous"
                ? "ambiguous"
                : "notInChain",
        };

  return {
    kind: "ready",
    eventId: record.eventId,
    centerMs: window.centerMs,
    halfWidthMs: window.halfWidthMs,
    sessionKey: window.sessionKey,
    sources: sourcesText(laneInfos.length, window.complete),
    sourceCount: laneInfos.length,
    paired,
    selected,
    row: dockRow,
    steps,
    moreSteps: Math.max(0, inWindowMembers.size - steps.length),
    nearby,
    moreNearby: Math.max(0, allContextCount - nearby.length),
    plot,
    facts,
    notices,
    empty,
    open,
  };
}

/** "an ambiguous", "a coverage blocked". */
function withArticle(noun: string): string {
  return `${/^[aeiou]/.test(noun) ? "an" : "a"} ${noun}`;
}

/** What activating a marker did or can do, in the words that end its accessible name. */
function selectabilityPhrase(selectability: MarkerSelectability): string {
  switch (selectability) {
    case "event":
      return "activate to select this event";
    case "log":
      return "a text-log line, not an event record, so activating it selects nothing";
    case "selected":
      return "the selected event";
    case "ambiguous":
      return "more than one loaded record matches, so activating it selects nothing";
    case "notLoaded":
      return "no loaded record matches, so activating it selects nothing";
  }
}

/**
 * A marker's accessible name: source, entry, level, time, the head of its message, what is known of
 * its link, and what activating it does. A nearby entry is named by `nearbyReason`, so it is never
 * called linked; a member is named by the row's strength and key. `selectability` is the one fact
 * only a click can settle (does exactly one loaded record match?): pass what the click found.
 */
export function dockMarkerName(
  model: Pick<DockReady, "facts" | "plot">,
  marker: PlotMarker,
  timeZoneMode: EvtxTimeZoneMode,
  selectability?: MarkerSelectability,
): string {
  const facts = model.facts.get(marker.id);
  const lane = model.plot.lanes.find((candidate) => candidate.key === marker.laneKey);
  const relation =
    facts === undefined
      ? null
      : facts.role === "nearby"
        ? facts.reason === null
          ? null
          : nearbyReason(facts.reason)
        : facts.strength === null
          ? facts.role === "selected"
            ? "no loaded chain"
            : null
          : isLinking(facts.strength)
            ? `${STRENGTH_LABELS[facts.strength].toLowerCase()} link${facts.key === null ? "" : ` by ${keyKindLabel(facts.key.kind)}`}`
            : `in ${withArticle(STRENGTH_LABELS[facts.strength].toLowerCase())} row, which establishes no link`;
  const head = messageHead(marker.message);
  return [
    lane?.label,
    marker.entry,
    marker.level,
    formatClock(marker.timestampMs, timeZoneMode, true),
    head === "" ? null : head,
    relation,
    selectabilityPhrase(selectability ?? facts?.selectability ?? "event"),
  ]
    .filter((part): part is string => part !== undefined && part !== null)
    .join(", ");
}
