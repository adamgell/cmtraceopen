/**
 * What the correlation dock shows for one selected event and one window read (spec 8.12, #842).
 *
 * Pure: no React, no stores, no IO. The component stays thin because every decision is made here and
 * tested here. The inputs are three facts the caller holds: the selected record, the window that was
 * read around it (`loadCorrelationWindow`), and the counts-only chain model of the session the window
 * came from. Nothing here scans the timeline: the dock reads the items inside its window and the rows
 * and edges the counts hold, and says plainly what that leaves out.
 *
 * The first half of that, which entry of the window is the selected event and what may be shown, is
 * `readWindowFacts`, which the Details context list reads too (#843): one ladder, two surfaces.
 *
 * Rules, all enforced here:
 * - A window answers ONE center. A record whose timestamp is another center is not paired with it.
 * - The counts are paired with the window only when they are the SAME session (`builtFor` equals the
 *   window's session key). Otherwise no entry is called linked or not linked, and no connector is
 *   drawn. A pair that belongs to an EARLIER session than the newest (`counts.updating`) is still a
 *   consistent pair, and is shown as it was with `updating` set, as the hook keeps its previous
 *   model while a newer session loads: nothing from the newer session is mixed into it.
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
import { buildEvidenceIndex, timelineTextMatches } from "./evtx-insights-data";
import {
  compareStrings,
  derivedTitle,
  messageHead,
  type CorrelationChain,
} from "./evtx-correlation-chains";
import {
  DOCK_SCOPE_NOTE,
  LINKS_LOADING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  NOT_READ_NOTE,
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
  ambiguousEventNote,
  moreText,
  notReadNote,
  unmatchableNote,
  type NearbyReason,
  type OpenDisabled,
} from "./evtx-correlation-copy";
import { UNKNOWN_CORRELATION_GAPS } from "./evtx-correlation-gaps";
import {
  isUnmatchableEvent,
  itemsByOriginId,
  logOriginNamesRecord,
  resolveOriginRecords,
} from "./evtx-correlation-origin-index";
import {
  IN_ANOTHER_CHAIN_LABEL,
  LINK_TO_EVENT_UNKNOWN_LABEL,
  NOT_LINKED_LABEL,
  buildChainPlot,
  describeLanes,
  keyHeader,
  laneKeyOf,
  shortEntryId,
  type ChainPlot,
  type KeyHeader,
  type PlotMarker,
} from "./evtx-correlation-view-model";
import type { LoadedCorrelationWindow } from "./evtx-correlation-window";
import { chainInWindow } from "./evtx-correlation-chain-in-window";
import { hasUsableTimestamp } from "./evtx-filter";
import { formatClock, type EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxRecord } from "./types";
import type { CorrelationCounts } from "./useEvtxCorrelation";
import { timelineOriginId, type TimelineItem, type TimelineOrigin } from "./unified-timeline";

/** Spec 8.12: up to five lanes. */
const DOCK_MAX_LANES = 5;
/** Context markers drawn at most, nearest the selected event first. */
const DOCK_NEARBY_MARKER_CAP = 60;
/** Spec 8.12: the chain's members as steps, up to four. */
const DOCK_STEP_CAP = 4;
/** Entries named on the "Also nearby" line. */
const DOCK_NEARBY_LINE_CAP = 4;

/** The part of the counts-only model the dock reads: one session's rows, partners, gaps and scope. */
export type DockCounts = Pick<
  CorrelationCounts,
  "model" | "builtFor" | "linkPartners" | "gaps" | "scope" | "unplacedList" | "updating"
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

interface DockStep {
  id: string;
  timestampMs: number;
  /** The event ID, or the log file and line. */
  entry: string;
  message: string;
}

interface DockNearbyEntry {
  id: string;
  /** "{eventId} · {channel}" or "{file} · line {n}". */
  entry: string;
  /** Milliseconds from the selected event, negative before it. */
  deltaMs: number;
  reason: NearbyReason;
}

interface DockRow {
  id: string;
  strength: CorrelationChain["strength"];
  title: string;
  key: KeyHeader | null;
  memberCount: number;
  /** Members that have an item among the entries READ. */
  read: number;
  /** Members that have none: an exact count, never placed. Where they are is `outsideWindow`'s. */
  notShown: number;
  /**
   * How many of those are outside the window, known only when the window was read whole. In a window
   * that was not, a member without an item may be inside it and unread: null, never `notShown`.
   */
  outsideWindow: number | null;
  /** Other rows the selected event is also in. */
  otherRows: number;
}

/**
 * Which entry of the window is the selected event, decided in this order (an untimed record never
 * reaches here: it is `DockModel`'s "untimed"):
 * - `unmatchable`: an event record with no usable record identity, which the join can never name.
 *   Decided from the record alone, before any entry is looked at. No entry is drawn as context,
 *   since any of them could be the event itself (an origin input ordinal, #957, is the way out);
 * - `found`: exactly one entry names the record;
 * - `ambiguous`: several do. They are left out of the context and counted;
 * - `notInTimeline`: none does, in a window that was read WHOLE, for a record the join could match;
 * - `notRead`: none does in what was read, and the read stopped early: the event may be in the part
 *   that was not read, so nothing is said about whether it is in the timeline.
 */
export type DockSelected =
  | { status: "found"; originId: string }
  | { status: "ambiguous"; candidates: number }
  | { status: "unmatchable" }
  | { status: "notInTimeline" }
  | { status: "notRead" };

/** What activating a marker can do: select its record, or nothing, and why. */
export type MarkerSelectability =
  /** Before a click: an event entry, selected if exactly one loaded record matches. */
  | "event"
  /** Before a click: a log entry, selected if exactly one loaded archive text row matches. */
  | "logLine"
  /** After a click: a line of a log file that has no record in the grid (a Log Viewer file). */
  | "log"
  | "selected"
  | "ambiguous"
  | "notLoaded"
  | "noIdentity";

/** What the dock knows about one drawn marker, for its accessible name. */
interface MarkerFacts {
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
  /** The counts belong to the window's session: links and strengths are known for it. */
  paired: boolean;
  /**
   * The window and its counts are an earlier session's pair, shown while a newer session is read.
   * They agree with each other and with nothing newer; the dock says it is updating.
   */
  updating: boolean;
  /**
   * Every entry of the window was read. When false, every list below is taken from the entries READ:
   * "nearest" means the nearest of those (nearer ones may be unread), and the counts of what a list
   * leaves out are lower bounds (`moreStepsText` and `moreNearbyText` say "at least").
   */
  complete: boolean;
  selected: DockSelected;
  row: DockRow | null;
  steps: DockStep[];
  /** Members read that the steps do not name; a lower bound when the window was not read whole. */
  moreSteps: number;
  moreStepsText: string | null;
  nearby: DockNearbyEntry[];
  /** Nearby entries read that the line does not name; a lower bound when not read whole. */
  moreNearby: number;
  moreNearbyText: string | null;
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

function isLinking(strength: CorrelationChain["strength"]): boolean {
  return strength === "exact" || strength === "candidate";
}

/** The words for a context marker's label, which `buildChainPlot` decided. */
function reasonOfLabel(label: string | null): NearbyReason {
  if (label === NOT_LINKED_LABEL) return "notLinked";
  if (label === IN_ANOTHER_CHAIN_LABEL) return "inAnotherChain";
  if (label === LINK_TO_EVENT_UNKNOWN_LABEL) return "linkUnknownToEvent";
  return "noLoadedLink";
}

/**
 * The origin ids of the window's items that name `record`, found with the origin join's own
 * matchers: an event record against an index of that one record, an archive text row (`originKind`
 * "log") with the strict log matcher. Never a rebuilt stable id.
 */
function originsNaming(record: EvtxRecord, items: readonly TimelineItem[]): Set<string> {
  const found = new Set<string>();
  if (record.originKind === "log") {
    for (const item of items) {
      if (logOriginNamesRecord(item.origin, record)) found.add(timelineOriginId(item.origin));
    }
    return found;
  }
  const index = buildEvidenceIndex([record]);
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
 * Why "Open in Correlation view" has no row to open. What is known of the selected event comes
 * first: it is true whether or not the links are in. Only an identified event waits for them.
 */
function openDisabledReason(selected: DockSelected, paired: boolean): OpenDisabled {
  switch (selected.status) {
    case "unmatchable":
    case "notRead":
    case "ambiguous":
    case "notInTimeline":
      return selected.status;
    case "found":
      return paired ? "notInChain" : "loading";
  }
}

/**
 * The instant a window is read around for `record`: its epoch, when it is a usable whole number of
 * milliseconds, else null (no selection, or an event that cannot be placed). The ONE definition: the
 * reader of the window (the dock's and the Details context's) and `readWindowFacts` decide it with
 * the same predicate, the one the time-range criterion uses.
 */
export function dockCenterMs(record: EvtxRecord | null): number | null {
  if (record === null || !hasUsableTimestamp(record) || !Number.isSafeInteger(record.timestampEpoch)) {
    return null;
  }
  return record.timestampEpoch;
}

/**
 * Nearest `centerMs` first, ties broken by `idOf` so the order never depends on the input order.
 * The one nearest-first order of the dock's context and of the Details context.
 */
export function compareByDistance<T extends { timestampMs: number }>(
  centerMs: number,
  idOf: (entry: T) => string,
): (a: T, b: T) => number {
  return (a, b) =>
    Math.abs(a.timestampMs - centerMs) - Math.abs(b.timestampMs - centerMs) ||
    compareStrings(idOf(a), idOf(b));
}

/**
 * What a window read says about the selected event, shared by every surface that lists the entries
 * around it. `kind` is `read` only for a record with a window that answers its instant and whose
 * first reply gave a count; the other kinds are the states before there is anything to list.
 */
export interface WindowRead {
  kind: "read";
  record: EvtxRecord;
  window: LoadedCorrelationWindow;
  /** Every entry inside the window, read or not: the first reply's count, which a read always has. */
  windowItems: number;
  /** The counts belong to the window's session (the keys are equal). */
  paired: boolean;
  /** The counts when `paired`, else null: nothing is ever read from counts of another session. */
  pairedCounts: DockCounts | null;
  /** The pair is an earlier session's, shown while a newer one is read. */
  updating: boolean;
  /** The window's entries by origin id, the first of equal ids winning. */
  byId: Map<string, TimelineItem>;
  /** The distinct entries read (the values of `byId`), in the order they were read. */
  items: TimelineItem[];
  /** The origin ids of the entries that name the record. */
  naming: ReadonlySet<string>;
  selected: DockSelected;
  /** The selected event's origin id, when found. */
  originId: string | null;
  /** Whether an entry's link to the event can be said: the event is found, or is known to be absent. */
  identified: boolean;
  /**
   * What may be shown: nothing when the event cannot be told from the entries (unmatchable), and not
   * the entries that could each be the event when several name it (ambiguous). `items` itself
   * otherwise (the same array).
   */
  usable: TimelineItem[];
  /** The scope is narrower than what is loaded, or is not known. Unpaired counts cannot speak for it. */
  scopeNarrowed: boolean;
  /**
   * "Not linked" is a claim that no event missing from the session could carry the link. The scope
   * says events were left out of it; an unread source is records that never reached it; and a pair
   * that an earlier session left behind is being replaced because events were added or reloaded.
   */
  narrowed: boolean;
  /** The session's own count of entries it could not place in time, from the paired counts only. */
  unplacedTotal: number | null;
}

export type WindowFacts =
  | { kind: "noSelection" }
  | { kind: "untimed" }
  /** There is no read for this selection (yet): the window is null or answers another center. */
  | { kind: "unread" }
  /** The first reply never came, so even the count of entries is not known. */
  | { kind: "failed"; error: string | null }
  | WindowRead;

/** Reads the window around the selected record: the ruled ladder, in one place. */
export function readWindowFacts(input: DockModelInput): WindowFacts {
  const { record, window, counts } = input;
  if (record === null) return { kind: "noSelection" };
  const center = dockCenterMs(record);
  if (center === null) return { kind: "untimed" };
  // A window answers one center. Another selection's window is never shown under this record.
  if (window === null || window.centerMs !== center) return { kind: "unread" };
  if (window.windowItems === null) return { kind: "failed", error: window.error };

  const paired = counts !== null && counts.builtFor === window.sessionKey;
  const pairedCounts = paired ? counts : null;
  const updating = pairedCounts !== null && pairedCounts.updating;
  const byId = itemsByOriginId(window.items);
  const items = [...byId.values()];

  // ---- the selected event, in the window ----
  const unmatchable = isUnmatchableEvent(record);
  const naming = unmatchable ? new Set<string>() : originsNaming(record, items);
  const selected: DockSelected = unmatchable
    ? { status: "unmatchable" }
    : naming.size === 1
      ? { status: "found", originId: [...naming][0] as string }
      : naming.size > 1
        ? { status: "ambiguous", candidates: naming.size }
        : window.complete
          ? { status: "notInTimeline" }
          : { status: "notRead" };
  const usable =
    selected.status === "unmatchable"
      ? []
      : selected.status === "ambiguous"
        ? items.filter((item) => !naming.has(timelineOriginId(item.origin)))
        : items;
  const scopeNarrowed = pairedCounts === null ? true : scopeDisclosure(pairedCounts.scope) !== null;
  return {
    kind: "read",
    record,
    window,
    windowItems: window.windowItems,
    paired,
    pairedCounts,
    updating,
    byId,
    items,
    naming,
    selected,
    originId: selected.status === "found" ? selected.originId : null,
    // An entry's link to the selected event can be said only when the event is identified.
    identified: selected.status === "found" || selected.status === "notInTimeline",
    usable,
    scopeNarrowed,
    narrowed: scopeNarrowed || input.unreadSources || updating,
    unplacedTotal: pairedCounts === null ? null : pairedCounts.unplacedList.total,
  };
}

export function buildDockModel(input: DockModelInput): DockModel {
  const windowRead = readWindowFacts(input);
  if (windowRead.kind !== "read") return windowRead;
  const {
    record,
    window,
    windowItems,
    pairedCounts,
    paired,
    updating,
    byId,
    items,
    selected,
    originId,
    identified,
    usable: drawItems,
    scopeNarrowed,
    narrowed,
    unplacedTotal,
  } = windowRead;

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
  const readMembers = new Set<string>(
    row === null ? (originId === null ? [] : [originId]) : rowMembers.filter((id) => byId.has(id)),
  );

  // ---- lanes: at most five, the selected event's first, then the chain's, then the busiest ----
  const allLaneInfos = describeLanes(items.map((item) => item.origin));
  const laneInfos =
    drawItems === items ? allLaneInfos : describeLanes(drawItems.map((item) => item.origin));
  const laneOrder = new Map(laneInfos.map((lane, index) => [lane.key, index]));
  const entriesInLane = new Map<string, number>();
  for (const item of drawItems) {
    const key = laneKeyOf(item.origin);
    entriesInLane.set(key, (entriesInLane.get(key) ?? 0) + 1);
  }
  const selectedLane = originId === null ? null : laneKeyOf((byId.get(originId) as TimelineItem).origin);
  const memberLanes = new Set(
    [...readMembers].map((id) => laneKeyOf((byId.get(id) as TimelineItem).origin)),
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
  const drawable = drawItems.filter((item) => chosenLanes.has(laneKeyOf(item.origin)));
  const drawableById = itemsByOriginId(drawable);
  const omittedSources = laneInfos.length - chosenLanes.size;
  const omittedSourceEntries = drawItems.length - drawable.length;

  // ---- the part of the row the plot is given ----
  const byTime = (a: string, b: string) =>
    ((byId.get(a) as TimelineItem).timestampMs - (byId.get(b) as TimelineItem).timestampMs) ||
    compareStrings(a, b);
  const part = chainInWindow(row, originId, drawableById);

  // ---- context: everything else in the window, nearest the selected event first ----
  const context = drawable
    .filter((item) => !readMembers.has(timelineOriginId(item.origin)))
    .sort(compareByDistance<TimelineItem>(record.timestampEpoch, (item) => timelineOriginId(item.origin)));
  const drawnContext = context.slice(0, DOCK_NEARBY_MARKER_CAP);
  const allContextCount = drawItems.filter((item) => !readMembers.has(timelineOriginId(item.origin))).length;

  const plot = buildChainPlot({
    chain: part,
    itemsById: drawableById,
    edgeInputComplete: pairedCounts === null ? false : pairedCounts.model.edgeInputComplete,
    narrowed,
    gaps: pairedCounts === null ? UNKNOWN_CORRELATION_GAPS : pairedCounts.gaps,
    window: { startMs: window.startMs, endMs: window.endMs },
    nearby: drawnContext,
    linkPartners: pairedCounts === null ? undefined : pairedCounts.linkPartners,
    selectionIdentified: identified,
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
    .sort(compareByDistance<PlotMarker>(record.timestampEpoch, (marker) => marker.id))
    .slice(0, DOCK_NEARBY_LINE_CAP)
    .map((marker) => ({
      id: marker.id,
      entry: marker.entry,
      deltaMs: marker.timestampMs - record.timestampEpoch,
      reason: reasonFor(marker),
    }));

  // ---- the summary of the row ----
  const keys = row === null ? null : keyHeader(row.keys);
  const lanesByKey = new Map(allLaneInfos.map((lane) => [lane.key, lane]));
  const memberItems = [...readMembers].sort(byTime);
  const steps: DockStep[] = memberItems.slice(0, DOCK_STEP_CAP).map((id) => {
    const item = byId.get(id) as TimelineItem;
    return {
      id,
      timestampMs: item.timestampMs,
      entry: shortEntryId(item, lanesByKey.get(laneKeyOf(item.origin))),
      message: messageHead(item.message),
    };
  });
  const notShown = row === null ? 0 : rowMembers.filter((id) => !byId.has(id)).length;
  const dockRow: DockRow | null =
    row === null
      ? null
      : {
          id: row.id,
          strength: row.strength,
          // The title is the model's own (D19) only when every entry of the row was read.
          title:
            notShown === 0
              ? (derivedTitle(rowMembers, byId) ??
                partialChainTitle(row.memberCount, readMembers.size, window.complete))
              : partialChainTitle(row.memberCount, readMembers.size, window.complete),
          key: keys,
          memberCount: row.memberCount,
          read: readMembers.size,
          notShown,
          outsideWindow: window.complete ? notShown : null,
          otherRows: rows.length - 1,
        };

  // ---- what each drawn marker is, for its name ----
  const facts = new Map<string, MarkerFacts>();
  for (const marker of [...plot.members, ...plot.nearby]) {
    const isSelected = marker.id === originId;
    const resolution: MarkerSelectability = isSelected
      ? "selected"
      : marker.kind === "log"
        ? "logLine"
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
  if (selected.status === "notRead") push(NOT_READ_NOTE);
  if (selected.status === "ambiguous") push(ambiguousEventNote(selected.candidates));
  if (selected.status === "unmatchable") push(unmatchableNote(windowItems, window.halfWidthMs));
  if (dockRow !== null) {
    push(
      window.complete
        ? outsideWindowNote(dockRow.notShown, dockRow.memberCount)
        : notReadNote(dockRow.notShown, dockRow.memberCount),
    );
  }
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
          narrowed: scopeNarrowed,
          unreadSources: input.unreadSources,
          updating,
          // The same run's own count, from the paired counts only; unpaired is not known.
          unplacedTotal,
        })
      : null;

  const moreSteps = Math.max(0, readMembers.size - steps.length);
  const moreNearby = Math.max(0, allContextCount - nearby.length);

  const open: DockReady["open"] =
    dockRow !== null
      ? { rowId: dockRow.id }
      : { disabled: openDisabledReason(selected, paired) };

  return {
    kind: "ready",
    eventId: record.eventId,
    centerMs: window.centerMs,
    halfWidthMs: window.halfWidthMs,
    sessionKey: window.sessionKey,
    updating,
    sources: sourcesText(allLaneInfos.length, window.complete),
    sourceCount: allLaneInfos.length,
    paired,
    complete: window.complete,
    selected,
    row: dockRow,
    steps,
    moreSteps,
    moreStepsText: moreText(moreSteps, window.complete),
    nearby,
    moreNearby,
    moreNearbyText: moreText(moreNearby, window.complete),
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
    case "logLine":
      return "activate to select this log line's record when exactly one is loaded";
    case "log":
      return "it is a line of a log file with no record in the grid, so activating it selects nothing";
    case "selected":
      return "the selected event";
    case "ambiguous":
      return "more than one loaded record matches, so activating it selects nothing";
    case "notLoaded":
      return "no loaded record matches, so activating it selects nothing";
    case "noIdentity":
      return "it has no usable record identity, so activating it selects nothing";
  }
}

/** What activating a marker found: the one record to select, or why there is none. */
type MarkerClick =
  | { kind: "select"; recordId: number }
  | { kind: "nothing"; selectability: Exclude<MarkerSelectability, "event" | "logLine" | "selected"> };

/**
 * What a click on a marker does, decided from the loaded records (`records`, scanned when the click
 * needs it): it selects the record only when EXACTLY ONE loaded record matches the entry's origin.
 * An entry with no usable identity names none, and no or several matches would be a guess; each of
 * those selects nothing and says why, and the reason goes into the marker's accessible name
 * (`dockMarkerName`'s `selectability`).
 *
 * An event entry is matched by the origin join (`resolveOriginRecords`). A log entry is matched by the
 * strict log matcher (`logOriginNamesRecord`) against the loaded archive text rows, the same matcher
 * that identifies the SELECTED record when it is such a row, so one definition decides both. A log
 * entry that no row matches is `notLoaded` when some loaded row is of its file (the file is in the
 * grid, this line is not), and `log` when none is: a line of a Log Viewer file, which the grid has no
 * record of.
 */
export function resolveMarkerClick(origin: TimelineOrigin, records: readonly EvtxRecord[]): MarkerClick {
  if (origin.kind === "log") {
    const rows = records.filter((record) => record.originKind === "log");
    const named = rows.filter((row) => logOriginNamesRecord(origin, row));
    if (named.length === 1) return { kind: "select", recordId: (named[0] as EvtxRecord).id };
    if (named.length > 1) return { kind: "nothing", selectability: "ambiguous" };
    return {
      kind: "nothing",
      selectability: rows.some((row) => timelineTextMatches(origin.file, row.sourceLabel)) ? "notLoaded" : "log",
    };
  }
  const resolution = resolveOriginRecords(origin, buildEvidenceIndex(records));
  if (resolution.kind === "noUsableIdentity") return { kind: "nothing", selectability: "noIdentity" };
  if (resolution.kind === "matches" && resolution.records.length === 1) {
    return { kind: "select", recordId: (resolution.records[0] as EvtxRecord).id };
  }
  return {
    kind: "nothing",
    selectability: resolution.kind === "matches" && resolution.records.length > 1 ? "ambiguous" : "notLoaded",
  };
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
