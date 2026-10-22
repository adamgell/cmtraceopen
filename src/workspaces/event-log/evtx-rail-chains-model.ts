/**
 * What the rail's Chains tab shows (spec 8.13, #841), decided as data and drawn by EvtxRailChains.
 *
 * Pure: no React, no stores, no IO. Everything is read from ONE snapshot of the shared correlation
 * data, because the model, its items, origins, gaps, unplaced evidence and scan were stored together
 * by the run that built the model. Nothing here writes a rule of its own:
 * - the rows are `model.chains` as the model ordered and capped them (plus the selected event's row
 *   when the cap dropped it, `listedRows`), never re-sorted and never grouped by strength;
 * - an exact or candidate row is a card with steps, any other row is a compact row with none, and
 *   the explanations are the copy module's (`whyStatement`, `unresolvedStepsNotice`);
 * - an absence is claimed only when `sessionSpeaksForAbsenceOverall` holds: nothing is narrowed,
 *   no source went unread, no rebuild is under way and no gap names an origin. "Not linked" is the
 *   plot's per-entry rule (`nearbyLinkLabel`) at session level, and the nearby group has no
 *   strength, no connector and no count;
 * - a count that is not known is never 0, and an entry with no loaded position is never given one.
 *
 * The "Nearby, not linked" group is fed by a typed `nearby` input that nothing produces in this
 * version (decision A on #838): the workspace passes none, so it is empty in production.
 */
import {
  strongestRowOf,
  type CorrelationChain,
  type CorrelationChainStrength,
} from "./evtx-correlation-chains";
import {
  CHAIN_ENTRIES_BEING_READ_TEXT,
  CHAIN_STEPS_NOT_READ_TEXT,
  CONTAINS_SELECTED_EVENT_SUFFIX,
  NO_ANALYSIS_TEXT,
  NO_ENTRY_POSITION_TEXT,
  NO_POSITION_TEXT,
  READING_EDGES_TEXT,
  SEQUENCE_ORDER_NOTE,
  UNREAD_SOURCES_CHAINS_NOTE,
  UPDATING_CORRELATION_TEXT,
  chainActionAvailability,
  chainRowName,
  correlationFailureText,
  correlationNotices,
  keyKindLabel,
  moreText,
  nearbyHeading,
  nearbyReason,
  nearbyReasonOfLabel,
  noLinkedChainsText,
  noLinkingChainsLine,
  scopeDisclosure,
  timelineReadingText,
  unresolvedStepsNotice,
  whyStatement,
} from "./evtx-correlation-copy";
import { originsNaming } from "./evtx-correlation-origin-index";
import {
  chainSequence,
  chainTitle,
  describeLanes,
  entriesText,
  entryLabel,
  isPartialChain,
  keyHeader,
  laneKeyOf,
  listedRows,
  nearbyLinkLabel,
  notLinkedLegendLabel,
  sessionSpeaksForAbsenceOverall,
  spanText,
} from "./evtx-correlation-view-model";
import { formatClock, type EvtxTimeZoneMode } from "./evtx-time";
import type { KindChip } from "./evtx-kind-chip-value";
import type { EvtxLevel, EvtxRecord } from "./types";
import { describeUnplaced, notPlacedLabel, unplacedHeader } from "./evtx-unplaced";
import type { EvtxCorrelationData } from "./useEvtxCorrelation";
import { timelineOriginId, type TimelineItem } from "./unified-timeline";

/** Spec 8.13: a card lists at most six steps; further entries collapse into "+{n} more". */
export const RAIL_CHAIN_STEP_LIMIT = 6;

/** Spec 8.13 legend: D9 vocabulary in place of the mockup's Explicit / Secondary / Time-adjacent. */
const LEGEND_EXACT_WORD = "Exact match";
const LEGEND_CANDIDATE_WORD = "Candidate identity";

/** The parts of the shared data the tab reads, all from the snapshot of the model on show. */
export type RailChainsData = Pick<
  EvtxCorrelationData,
  | "stage"
  | "model"
  | "hasItems"
  | "itemsById"
  | "edges"
  | "gaps"
  | "scope"
  | "scan"
  | "nextScan"
  | "unplaced"
  | "unplacedList"
  | "linkPartners"
  | "updating"
  | "error"
>;

export interface RailStep {
  id: string;
  /** The clock with seconds, in the chosen zone. */
  timeText: string;
  level: EvtxLevel;
  chip: KindChip;
  message: string;
  /** The same timestamp as the step above: time does not order the two. */
  sameTimeAsPrevious: boolean;
}

interface RailRowBase {
  chain: CorrelationChain;
  /** The accessible name: strength, title, entry count, partial, and whether it holds the selected event. */
  name: string;
  title: string;
  strength: CorrelationChainStrength;
  /** "HH:mm:ss" to "HH:mm:ss", or the neutral words when no member has a loaded position. */
  span: string;
  /** "{n} entries": the count of ALL members, placed or not. */
  entries: string;
  partial: boolean;
  /** The row of the selected event's chain (the strongest the event is in). */
  selected: boolean;
}

export interface RailCardRow extends RailRowBase {
  kind: "card";
  key: { label: string; shortValue: string; fullValue: string; more: number } | null;
  steps: RailStep[];
  /** "+{n} more" for the steps the six-step limit left out. */
  more: string | null;
  /** In place of steps: the entries are being read, were not read, or none has a loaded position. */
  stepsText: string | null;
  /** Why some members are not listed as steps, when some are not. */
  partialNote: string | null;
}

export interface RailCompactRow extends RailRowBase {
  kind: "compact";
  /** Why the row is not a link, in the words the Correlation view's "why" card uses. */
  description: string;
}

export type RailRow = RailCardRow | RailCompactRow;

export interface RailLegend {
  exact: string;
  candidate: string;
  /** The dotted entry's word, only when a nearby entry is listed. */
  notLinked: string | null;
}

export interface RailNearbyRow {
  id: string;
  timeText: string;
  entry: string;
  message: string;
  /** "time only, not linked", "time only, no loaded link" or "time only; in another chain". */
  reason: string;
}

export interface RailChainsReady {
  kind: "ready";
  updating: boolean;
  /** "Updating correlation..." while a newer session is built; the rows are the earlier session's. */
  statusText: string | null;
  /** How far the timeline read has got, while one is running. Not a live region's text. */
  readingText: string | null;
  /** A failure to update the model on show. */
  error: string | null;
  /** The edges or the timeline read stopped early: Retry runs the steps again. */
  retry: boolean;
  notices: string[];
  legend: RailLegend | null;
  /** Said once above the cards, when any card lists steps. */
  orderNote: string | null;
  rows: RailRow[];
  /** Above rows that are not links, when there is no exact or candidate chain. */
  rowsLine: string | null;
  /** The model holds no row at all. */
  emptyText: string | null;
  nearby: { heading: string; rows: RailNearbyRow[] } | null;
  notPlaced: { heading: string; body: string } | null;
  actions: { canAct: boolean; reason: string | undefined };
}

export type RailChainsModel =
  | { kind: "waiting"; text: string }
  | { kind: "failed"; text: string }
  | RailChainsReady;

export interface RailChainsInput {
  data: RailChainsData;
  timeZoneMode: EvtxTimeZoneMode;
  /** Some source's records were not (all) loaded (`useUnreadSources`). */
  unreadSources: boolean;
  /** The id of the selected event's row (`selectedRecordRowId`), or null. */
  selectedRowId: string | null;
  /** Context entries listed as "Nearby, not linked". There is no producer, so production passes none. */
  nearby: readonly TimelineItem[];
}

/**
 * The row of the selected event's chain: the strongest row of the ONE entry that names the record.
 * Several entries naming it (an identical entry read twice) pick none among them, and neither does a
 * record no row holds, no record, or entries that were not read. The join is the origin join's own
 * (`originsNaming`), never a rebuilt id.
 */
export function selectedRecordRowId(
  record: EvtxRecord | null,
  data: Pick<EvtxCorrelationData, "model" | "hasItems" | "itemsById">,
): string | null {
  if (record === null || data.model === null || !data.hasItems) return null;
  const naming = originsNaming(record, [...data.itemsById.values()]);
  if (naming.size !== 1) return null;
  return strongestRowOf(data.model.rowsByMember, [...naming][0] as string)?.id ?? null;
}

function isLinking(strength: CorrelationChainStrength): boolean {
  return strength === "exact" || strength === "candidate";
}

export function buildRailChains(input: RailChainsInput): RailChainsModel {
  const { data, timeZoneMode } = input;
  const model = data.model;
  if (model === null) {
    if (data.error !== null) return { kind: "failed", text: correlationFailureText(data.error, "built") };
    return { kind: "waiting", text: data.stage === "unavailable" ? NO_ANALYSIS_TEXT : READING_EDGES_TEXT };
  }

  const scope = scopeDisclosure(data.scope);
  // An absence of links is claimed for the session only when nothing is narrowed, unread or being
  // rebuilt, every edge was loaded, no gap clears completeness and no gap names an origin: a negative
  // claim from a superseded session is unproven, and an origin the engine did not correlate may hold
  // the link. The rule is the plot's and the dock's, with the same three inputs, asked of the whole
  // session (every origin gap is a member).
  const speaks = sessionSpeaksForAbsenceOverall({
    edgeInputComplete: model.edgeInputComplete,
    scopeNarrowed: scope !== null,
    unreadSources: input.unreadSources,
    updating: data.updating,
    gaps: data.gaps,
  });
  const reading = data.nextScan?.state === "running" || data.stage === "scanning";
  const progress = data.nextScan?.progress ?? data.scan.progress;
  const listed = listedRows(model, input.selectedRowId);

  const buildRow = (chain: CorrelationChain): RailRow => {
    const selected = chain.id === input.selectedRowId;
    const base: RailRowBase = {
      chain,
      name: `${chainRowName(chain)}${selected ? CONTAINS_SELECTED_EVENT_SUFFIX : ""}`,
      title: chainTitle(chain),
      strength: chain.strength,
      span: spanText(chain.startMs, chain.endMs, timeZoneMode) ?? NO_POSITION_TEXT,
      entries: entriesText(chain.memberCount),
      partial: isPartialChain(chain),
      selected,
    };
    if (!isLinking(chain.strength)) return { ...base, kind: "compact", description: whyStatement(chain) };

    const header = keyHeader(chain.keys);
    const sequence = data.hasItems ? chainSequence(chain, data.itemsById) : null;
    const entries = sequence?.entries ?? [];
    const steps = entries.slice(0, RAIL_CHAIN_STEP_LIMIT).map(
      (entry): RailStep => ({
        id: entry.id,
        timeText: formatClock(entry.timestampMs, timeZoneMode, true),
        level: entry.level,
        chip: entry.chip,
        message: entry.message,
        sameTimeAsPrevious: entry.sameTimeAsPrevious,
      }),
    );
    return {
      ...base,
      kind: "card",
      key:
        header === null
          ? null
          : {
              label: `key: ${keyKindLabel(header.kind)}`,
              shortValue: header.shortValue,
              fullValue: header.value,
              more: header.more,
            },
      steps,
      more: moreText(entries.length - steps.length, true),
      stepsText: !data.hasItems
        ? reading
          ? CHAIN_ENTRIES_BEING_READ_TEXT
          : CHAIN_STEPS_NOT_READ_TEXT
        : entries.length === 0
          ? NO_ENTRY_POSITION_TEXT
          : null,
      partialNote: data.hasItems ? unresolvedStepsNotice(chain, data.unplaced) : null,
    };
  };
  const rows = listed.rows.map(buildRow);

  // The nearby group: context entries that no row holds, ordered by time. Each carries the one word
  // the plot's rule gives an entry that is not in the row, asked of the session.
  const context = input.nearby
    .filter((item) => !model.rowsByMember.has(timelineOriginId(item.origin)))
    .sort(
      (a, b) =>
        a.timestampMs - b.timestampMs ||
        (timelineOriginId(a.origin) < timelineOriginId(b.origin) ? -1 : 1),
    );
  const rule = { chainClear: speaks, gaps: data.gaps, linkPartners: data.linkPartners };
  const labels = context.map((item) => nearbyLinkLabel(timelineOriginId(item.origin), rule));
  const lanes = new Map(describeLanes(context.map((item) => item.origin)).map((lane) => [lane.key, lane]));
  const nearbyWord = notLinkedLegendLabel(labels, speaks);

  const unplacedView = describeUnplaced(data.unplacedList);
  const hasCards = rows.some((row) => row.kind === "card");
  const notices = correlationNotices({
    edgeInput: { edgeInputComplete: model.edgeInputComplete, unloadedEdgeCount: model.unloadedEdgeCount },
    edgeError: data.edges.error,
    gaps: data.gaps,
    scan: data.scan,
    selectionLoss: null,
    scope,
    cap: { shown: model.chains.length, totalCount: model.totalCount, omittedCount: model.omittedCount },
    pastCapShown: listed.pastCapId === null ? null : model.chains.length,
  });
  if (input.unreadSources) notices.push(UNREAD_SOURCES_CHAINS_NOTE);

  return {
    kind: "ready",
    updating: data.updating,
    statusText: data.updating ? UPDATING_CORRELATION_TEXT : null,
    readingText: reading ? timelineReadingText(progress) : null,
    error: data.error === null ? null : correlationFailureText(data.error, "updated"),
    retry: data.edges.error !== null || data.scan.state === "incomplete",
    notices,
    legend:
      rows.length === 0 && context.length === 0
        ? null
        : {
            exact: LEGEND_EXACT_WORD,
            candidate: LEGEND_CANDIDATE_WORD,
            notLinked: context.length === 0 ? null : nearbyWord,
          },
    orderNote: rows.some((row) => row.kind === "card" && row.steps.length > 0) ? SEQUENCE_ORDER_NOTE : null,
    rows,
    rowsLine: rows.length > 0 && !hasCards ? noLinkingChainsLine(speaks) : null,
    emptyText:
      model.totalCount === 0 ? noLinkedChainsText({ speaks, edgeInputComplete: model.edgeInputComplete }) : null,
    nearby:
      context.length === 0
        ? null
        : {
            heading: nearbyHeading(nearbyWord, context.length),
            rows: context.map((item, index) => ({
              id: timelineOriginId(item.origin),
              timeText: formatClock(item.timestampMs, timeZoneMode, true),
              entry: entryLabel(item, lanes.get(laneKeyOf(item.origin))),
              message: item.message,
              reason: nearbyReason(nearbyReasonOfLabel(labels[index] ?? null)),
            })),
          },
    notPlaced: unplacedView.present
      ? { heading: notPlacedLabel(unplacedView), body: unplacedHeader(unplacedView) }
      : null,
    actions: chainActionAvailability({ hasItems: data.hasItems, updating: data.updating, hasChain: true }),
  };
}
