/**
 * What the Details "Context ±5 min" list shows for one selected event and one window read (spec 8.13
 * Details tab item 7, #843): the 12 nearest timeline items, events and text-log lines interleaved by
 * time, each with its kind chip, its offset from the event and its source, and a link icon on the
 * entries that share an Exact or Candidate edge with the event.
 *
 * Pure: no React, no stores, no IO. The component stays thin because every decision is made here and
 * tested here. The inputs are the same three facts the dock's model holds (the selected record, the
 * window read around it with `loadCorrelationWindow`, and the counts-only chain model of the session
 * the window came from) and the model asks the same questions of them through the same functions:
 * `readWindowFacts` (which entry is the event, whether the counts belong to the window, what may be
 * shown), `compareByDistance` (nearest first), `sessionSpeaksForAbsence` and `emptyWindowText` (the
 * absence claims). Nothing here is a second copy of a ruled rule.
 *
 * Rules, all enforced here:
 * - A row carries NO relationship words. The list is context only: its entries are there by their
 *   time. The one mark a row can carry is the link icon, and only for a DIRECT Exact or Candidate
 *   edge between the entry and the selected event, in the event's own rows, from counts that belong
 *   to the window's session, for an event that was found. An entry that is linked elsewhere, in the
 *   same chain without an edge to the event, in an Ambiguous or Coverage blocked row, or in no
 *   loaded row, has no mark and no words. The absence of the icon is not a claim, and the list says
 *   so in one section sentence (`LINKS_MAY_BE_MISSING_TEXT`) whenever the session could not speak
 *   for the absence of a link.
 * - "Nearest" is said only when it is proven. A window read to its end holds every entry. A read that
 *   stopped holds the EARLIEST entries, so the rows are the nearest of what was read; they are
 *   provably the nearest overall only when the read went past the event and every row is strictly
 *   nearer than anything unread can be.
 * - The selected event is one of the 12 when it was found. When it cannot be told from the entries
 *   (unmatchable, ambiguous) nothing that could be it is listed.
 * - An unknown count is never shown as 0, and an absence is claimed only under the five conditions
 *   of `emptyWindowText`.
 */
import type { CorrelationChain } from "./evtx-correlation-chains";
import {
  ANALYSIS_BUILDING_TEXT,
  DOCK_SCOPE_NOTE,
  LINKS_LOADING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  NOT_READ_NOTE,
  NO_SESSION_TEXT,
  READING_WINDOW_TEXT,
  STRENGTH_LABELS,
  UNREAD_SOURCES_NOTE,
  UNTIMED_TEXT,
  UPDATING_CORRELATION_TEXT,
  ambiguousEventNote,
  coverageGapNotice,
  edgeInputNotice,
  emptyWindowText,
  keyKindLabel,
  scopeDisclosure,
  sharedOriginNote,
  unmatchableNote,
  windowFailureText,
  windowNotice,
  windowWidthLabel,
} from "./evtx-correlation-copy";
import {
  compareByDistance,
  readWindowFacts,
  type DockModelInput,
  type DockSelected,
  type WindowRead,
} from "./evtx-correlation-dock-model";
import type { EvtxAnalysisSessionState } from "./evtx-analysis-session";
import { repeatedItems } from "./evtx-correlation-origin-index";
import { chipForOriginKind, type KindChip } from "./evtx-kind-chip-value";
import {
  describeLanes,
  entryLabel,
  formatDelta,
  laneKeyOf,
  sessionSpeaksForAbsence,
} from "./evtx-correlation-view-model";
import { timelineOriginId, type TimelineItem } from "./unified-timeline";

/** Spec 8.13 item 7: ±5 min around the selected record. */
export const DETAIL_CONTEXT_HALF_WIDTH_MS = 300_000;
/** Spec 8.13 item 7: the 12 nearest items. */
const DETAIL_CONTEXT_ROW_CAP = 12;
/** The eyebrow: "Context ±5 min". */
export const DETAIL_CONTEXT_TITLE = `Context ${windowWidthLabel(DETAIL_CONTEXT_HALF_WIDTH_MS)}`;
/** The eyebrow's right side. */
export const DETAIL_CONTEXT_KINDS_LABEL = "events + text logs";

/** Said when at least one row carries the link icon. */
const LINK_LEGEND_TEXT = "Link icon: Exact or Candidate link to this event.";

/**
 * Said when the absence of a link icon could be misread as an absence of a link: the session could
 * not speak for it (an edge, an event or an origin may be missing). The specific reasons are the
 * notes beside it.
 */
const LINKS_MAY_BE_MISSING_TEXT =
  "Links may be missing, so an entry without a link icon may still be linked to this event.";

export interface DetailContextInput extends DockModelInput {
  /**
   * The state of the analysis session (`analysisSessionState`). Under `none` nothing is listed,
   * whatever window it is given: there is no session and none is coming. A window kept while a
   * session is being rebuilt (`building`) is still listed, as an earlier session's pair.
   */
  session: EvtxAnalysisSessionState;
}

/** A direct Exact or Candidate edge between an entry and the selected event. */
interface DirectLink {
  strength: "exact" | "candidate";
  /** The one key kind the edge carries, as the views word it, or null when it carries none or several. */
  keyLabel: string | null;
}

export interface DetailContextRow {
  /** The entry's origin id. */
  id: string;
  kind: "event" | "log";
  chip: KindChip;
  timestampMs: number;
  /** Milliseconds from the selected event, negative before it. */
  offsetMs: number;
  /** "+3.3 s", "-3.3 s", "same time", or "this event" on the selected row. */
  offsetText: string;
  /** "{eventId} · {channel}" or "{file} · line {n}". */
  entry: string;
  message: string;
  isSelected: boolean;
  /** Set only for a direct Exact or Candidate edge to the selected event; `name` is its accessible name. */
  link: { strength: "exact" | "candidate"; name: string } | null;
}

interface DetailContextReady {
  kind: "ready";
  eventId: number;
  centerMs: number;
  /** The session and revision the window was read from. */
  sessionKey: string;
  selected: DockSelected;
  /** The counts belong to the window's session. */
  paired: boolean;
  /** The pair is an earlier session's, shown while a newer one is read. */
  updating: boolean;
  /** Every entry of the window was read. */
  complete: boolean;
  /** The rows are the nearest entries overall, not only of the entries read. */
  nearestProven: boolean;
  /** In time order. */
  rows: DetailContextRow[];
  /** How the rows were chosen, or null when there is nothing to say (no other entry). */
  caption: string | null;
  /** Set only when a row carries the link icon. */
  legend: string | null;
  /** One line each, in the order they are shown. */
  notices: string[];
  /** Set when no entry other than the selected event is in a window that was read whole. */
  empty: { text: string; absolute: boolean } | null;
}

type DetailContextModel =
  | { kind: "none" }
  | { kind: "untimed"; text: string }
  | { kind: "noSession"; text: string }
  | { kind: "building"; text: string }
  /** There is no read for this selection (yet): the session is there and the window has not come. */
  | { kind: "reading"; text: string }
  /** The first reply never came, so even the count of entries is not known. */
  | { kind: "failed"; text: string; error: string | null }
  | DetailContextReady;

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function isLinkingStrength(strength: string): strength is "exact" | "candidate" {
  return strength === "exact" || strength === "candidate";
}

/**
 * The entries that share an Exact or Candidate edge with `originId`, in the rows that hold it. Only
 * a pair's own reduced edge counts: a member of the same chain with no edge to the origin is not a
 * partner, and an Ambiguous or Coverage blocked edge links nothing.
 *
 * A partner is set once, with no merge of two readings of one pair, because the chain model reduces
 * every observation of a pair to ONE relation before a row is built (evtx-correlation-chains.ts: the
 * header, and reduceByPair). A pair therefore has one edge in every row that holds it, and the label
 * a row gives it is already the weakest one seen.
 */
function directLinks(
  rows: readonly { edges: readonly CorrelationChain["edges"][number][] }[],
  originId: string,
): Map<string, DirectLink> {
  const partners = new Map<string, DirectLink>();
  for (const row of rows) {
    for (const edge of row.edges) {
      if (edge.right === null || !isLinkingStrength(edge.strength)) continue;
      const other = edge.left === originId ? edge.right : edge.right === originId ? edge.left : null;
      if (other === null || other === originId) continue;
      const labels = new Set(edge.keys.map((key) => keyKindLabel(key.kind)));
      const keyLabel = labels.size === 1 ? ([...labels][0] as string) : null;
      partners.set(other, { strength: edge.strength, keyLabel });
    }
  }
  return partners;
}

/** The accessible name and tooltip of the link icon. */
function linkName(link: DirectLink): string {
  return `${STRENGTH_LABELS[link.strength]} link to this event${link.keyLabel === null ? "" : ` by ${link.keyLabel}`}`;
}

function offsetText(offsetMs: number, isSelected: boolean): string {
  if (isSelected) return "this event";
  if (offsetMs === 0) return "same time";
  return `${offsetMs > 0 ? "+" : "-"}${formatDelta(offsetMs)}`;
}

function count(value: number): string {
  return value.toLocaleString();
}

function entriesText(value: number): string {
  return `${count(value)} ${value === 1 ? "entry" : "entries"}`;
}

/**
 * How the rows were chosen. Words "nearest" only for rows that are: of a window read whole (every
 * entry was a candidate), or of a read that stopped but is proven. Otherwise the rows are the
 * nearest of the entries READ, and the caption says so.
 *
 * The counts are the ones the card above it and the engine give: `windowItems`, the entries of the
 * window, and `read`, the entries read (`window.items.length`, which `windowNotice` names too). They
 * are never the count of the list left after entries were set aside, so a reader can put the two
 * lines side by side; the entries the list leaves out are explained by the notes of their own (the
 * ambiguous event's, and `sharedOriginNote`).
 *
 * "N nearest" is literally true. The counts are of entries read, and exactly two kinds of entry that
 * is counted has no row and is not simply ranked after the rows: the entries that may be an
 * ambiguous event (set aside), and a later reading of an origin already read (`repeatedItems`, which
 * `itemsByOriginId` leaves out). When one of either is nearer to the event's instant than the
 * farthest row the caption says so: the rows are the nearest APART from the first (`apart`, how many
 * may be the event), and COUNTING REPEATS ONCE for the second (`repeats`).
 */
function captionFor(input: {
  shown: number;
  windowItems: number;
  read: number;
  complete: boolean;
  proven: boolean;
  halfWidthMs: number;
  apart: number | null;
  repeats: boolean;
}): string {
  const width = windowWidthLabel(input.halfWidthMs);
  const plain = `${count(input.shown)} nearest`;
  // One sentence for what was set aside or counted once: "apart from the 2 that may be this event
  // and counting repeats once".
  const clauses = [
    input.apart === null ? null : `apart from the ${count(input.apart)} that may be this event`,
    input.repeats ? "counting repeats once" : null,
  ].filter((clause): clause is string => clause !== null);
  const qualified = clauses.length === 0 ? "" : `, ${clauses.join(" and ")},`;
  const lead = input.apart === null ? plain : input.shown === 1 ? "The nearest" : `The ${plain}`;
  if (input.complete) {
    return input.windowItems > input.shown
      ? `${lead}${qualified} of ${entriesText(input.windowItems)} within ${width}`
      : `${entriesText(input.windowItems)} within ${width}`;
  }
  if (input.proven) return `${lead} entries${qualified} within ${width}`;
  return input.read > input.shown
    ? `${lead}${qualified} of the ${entriesText(input.read)} read`
    : `${entriesText(input.read)} read`;
}

function unreadState(session: EvtxAnalysisSessionState): DetailContextModel {
  if (session === "none") return { kind: "noSession", text: NO_SESSION_TEXT };
  if (session === "building") return { kind: "building", text: ANALYSIS_BUILDING_TEXT };
  return { kind: "reading", text: READING_WINDOW_TEXT };
}

function buildReady(read: WindowRead, unreadSources: boolean): DetailContextReady {
  const { window, pairedCounts, paired, updating, usable, selected, originId } = read;
  const center = window.centerMs;
  const idOf = (item: TimelineItem) => timelineOriginId(item.origin);
  // The entries read again under an origin already read: counted in the window, with no row of their own.
  const repeats = repeatedItems(window.items);

  // ---- the rows: the selected event, then the nearest of the rest, shown in time order ----
  const selectedItem = originId === null ? null : (read.byId.get(originId) ?? null);
  const others = usable.filter((item) => idOf(item) !== originId).sort(compareByDistance<TimelineItem>(center, idOf));
  const chosenOthers = others.slice(0, DETAIL_CONTEXT_ROW_CAP - (selectedItem === null ? 0 : 1));
  const chosen = selectedItem === null ? chosenOthers : [selectedItem, ...chosenOthers];

  // ---- which of them share a direct Exact or Candidate edge with the event ----
  const rowsOfEvent =
    pairedCounts !== null && originId !== null ? (pairedCounts.model.rowsByMember.get(originId) ?? []) : [];
  const partners = originId === null ? new Map<string, DirectLink>() : directLinks(rowsOfEvent, originId);

  const lanes = new Map(describeLanes(read.items.map((item) => item.origin)).map((lane) => [lane.key, lane]));
  const rows: DetailContextRow[] = chosen
    .sort((a, b) => a.timestampMs - b.timestampMs || compareStrings(idOf(a), idOf(b)))
    .map((item) => {
      const id = idOf(item);
      const isSelected = id === originId;
      const offsetMs = item.timestampMs - center;
      const partner = partners.get(id);
      const lane = lanes.get(laneKeyOf(item.origin));
      return {
        id,
        kind: item.origin.kind,
        chip: chipForOriginKind(item.origin.kind),
        timestampMs: item.timestampMs,
        offsetMs,
        offsetText: offsetText(offsetMs, isSelected),
        entry: entryLabel(item, lane),
        message: item.message,
        isSelected,
        link: partner === undefined ? null : { strength: partner.strength, name: linkName(partner) },
      };
    });

  // ---- is "nearest" proven? ----
  // A read that stopped holds the earliest entries of the window, in time order. Everything unread is
  // at or after the last entry read, so once the read has passed the event every unread entry is at
  // least (last - center) away; the rows are the nearest overall when there are 12 and the farthest
  // is strictly nearer than that (an unread entry tied with the last one read is exactly that far).
  // `farthest < last - center` already says the read went past the event: a distance is never
  // negative, so a last entry at or before the event can prove nothing.
  const last = window.items.length === 0 ? null : (window.items[window.items.length - 1] as TimelineItem).timestampMs;
  const farthest = chosen.reduce((max, item) => Math.max(max, Math.abs(item.timestampMs - center)), 0);
  // A row is "the nearest" only if nothing set aside is nearer: the entries that may be an ambiguous
  // event are left out of the rows, and one of them may be closer to the event than the farthest row.
  const nearerSetAside =
    selected.status === "ambiguous" &&
    [...read.naming].some((id) => {
      const setAside = read.byId.get(id);
      return setAside !== undefined && Math.abs(setAside.timestampMs - center) < farthest;
    })
      ? selected.candidates
      : null;
  const repeatsNearer = repeats.some((item) => Math.abs(item.timestampMs - center) < farthest);
  const nearestProven =
    window.complete ||
    (chosen.length === DETAIL_CONTEXT_ROW_CAP && last !== null && farthest < last - center);

  // ---- notices, in the order they are shown ----
  const notices: string[] = [];
  const push = (text: string | null) => {
    if (text !== null) notices.push(text);
  };
  push(windowNotice(window));
  push(sharedOriginNote(repeats.length));
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
  if (unreadSources) push(UNREAD_SOURCES_NOTE);
  if (updating) push(UPDATING_CORRELATION_TEXT);
  if (selected.status === "notInTimeline") push(NOT_IN_TIMELINE_NOTE);
  if (selected.status === "notRead") push(NOT_READ_NOTE);
  if (selected.status === "ambiguous") push(ambiguousEventNote(selected.candidates, "list"));
  if (selected.status === "unmatchable") push(unmatchableNote(read.windowItems, window.halfWidthMs, "list"));

  // The absence of an icon is not a claim, unless the session could not have shown a link that
  // exists. That is the plot's rule for "Not linked", plus any gap that names a listed entry.
  const listedOthers = rows.filter((row) => !row.isSelected);
  if (selected.status === "found" && listedOthers.length > 0) {
    const speaks =
      pairedCounts !== null &&
      sessionSpeaksForAbsence({
        edgeInputComplete: pairedCounts.model.edgeInputComplete,
        scopeNarrowed: read.scopeNarrowed,
        unreadSources,
        updating: read.updating,
        gaps: pairedCounts.gaps,
        memberIds: [originId as string, ...rowsOfEvent.flatMap((row) => [...row.memberIds, ...row.unresolvedMemberIds])],
      }) &&
      !listedOthers.some((row) => pairedCounts.gaps.originIds.has(row.id));
    if (!speaks) push(LINKS_MAY_BE_MISSING_TEXT);
  }

  // ---- "no other entries", an absence claim, only for a window read whole ----
  const othersInWindow = read.items.filter((item) => idOf(item) !== originId);
  const empty =
    window.complete && othersInWindow.length === 0
      ? emptyWindowText({
          halfWidthMs: window.halfWidthMs,
          scopeNarrowed: read.scopeNarrowed,
          unreadSources,
          updating,
          unplacedTotal: read.unplacedTotal,
          subject: "entries",
        })
      : null;

  return {
    kind: "ready",
    eventId: read.record.eventId,
    centerMs: center,
    sessionKey: window.sessionKey,
    selected,
    paired,
    updating,
    complete: window.complete,
    nearestProven,
    rows,
    caption:
      chosenOthers.length === 0
        ? null
        : captionFor({
            shown: rows.length,
            windowItems: read.windowItems,
            read: window.items.length,
            complete: window.complete,
            proven: nearestProven,
            halfWidthMs: window.halfWidthMs,
            apart: nearerSetAside,
            repeats: repeatsNearer,
          }),
    legend: rows.some((row) => row.link !== null) ? LINK_LEGEND_TEXT : null,
    notices,
    empty,
  };
}

/**
 * What the Details context list shows. A window of another width than ±5 min is no read of this
 * list's request, so it is treated as none (the caption and the title say ±5 min).
 */
export function buildDetailContext(input: DetailContextInput): DetailContextModel {
  if (input.record === null) return { kind: "none" };
  // Under no session nothing is listed; a window of another width is no read of this list's request.
  const window =
    input.session !== "none" &&
    input.window !== null &&
    input.window.halfWidthMs === DETAIL_CONTEXT_HALF_WIDTH_MS
      ? input.window
      : null;
  const facts = readWindowFacts({
    record: input.record,
    window,
    counts: input.counts,
    unreadSources: input.unreadSources,
  });
  switch (facts.kind) {
    case "noSelection":
      return { kind: "none" };
    case "untimed":
      return { kind: "untimed", text: UNTIMED_TEXT };
    case "unread":
      return unreadState(input.session);
    case "failed":
      return { kind: "failed", text: windowFailureText(facts.error), error: facts.error };
    case "read":
      return buildReady(facts, input.unreadSources);
  }
}
