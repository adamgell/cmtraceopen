/**
 * The words the Correlation view says about what it can and cannot show, and the "Copy as text"
 * block (spec 8.11). Pure: strings from the chain model and its view model, nothing else.
 *
 * Evidence first (soul.md): every sentence here is either a count the model holds or a statement
 * of what was NOT loaded, scoped or read. None says one entry caused, followed or explains another:
 * a sequence is ordered by recorded time and says so.
 *
 * No string says an entry is "not placed", "without a timeline position" or carries no timestamp
 * unless `isProvenUnplaced` proves it (the scan finished and the id is on a complete unplaced
 * list). Anything else says "no loaded position", which is true whatever the reason.
 */
import type {
  CorrelationChain,
  CorrelationChainStrength,
} from "./evtx-correlation-chains";
import { gapsClearCompleteness, type CorrelationGaps } from "./evtx-correlation-gaps";
import {
  IN_ANOTHER_CHAIN_LABEL,
  LINK_TO_EVENT_UNKNOWN_LABEL,
  NOT_LINKED_LABEL,
  chainAccessibleName,
  chainSequence,
  chainTitle,
  entriesText,
  formatDelta,
  isPartialChain,
  isProvenUnplaced,
  partitionUnplaced,
  whyRows,
  type UnplacedEvidence,
} from "./evtx-correlation-view-model";
import { formatEventTime, timeZoneLabel, type EvtxTimeZoneMode } from "./evtx-time";
import { WAIT_FOR_UPDATE_REASON } from "./evtx-unplaced";
import type { TimelineItem } from "./unified-timeline";
import type { LoadedCorrelationWindow } from "./evtx-correlation-window";

export type { UnplacedEvidence };

/** The strength words. They equal `strengths.<s>.label` in evtx-visual-tokens.ts; a test pins that. */
export const STRENGTH_LABELS: Record<CorrelationChainStrength, string> = {
  exact: "Exact",
  candidate: "Candidate",
  ambiguous: "Ambiguous",
  coverageBlocked: "Coverage blocked",
};

const KEY_KIND_LABELS: Record<string, string> = {
  activityId: "ActivityId",
  relatedActivityId: "RelatedActivityId",
  providerChannelEventRecord: "provider, channel and record",
  processStart: "process start",
  sessionId: "SessionId",
  deviceId: "DeviceId",
  userId: "UserId",
  secondary: "secondary identifier",
};

export function keyKindLabel(kind: string): string {
  return KEY_KIND_LABELS[kind] ?? kind;
}

function count(value: number): string {
  return value.toLocaleString();
}

function events(value: number): string {
  return `${count(value)} ${value === 1 ? "event" : "events"}`;
}

// ---- scope and completeness ---------------------------------------------------------------------

export interface ScopeDisclosureInput {
  /** Events the analysis session was built from (the visible events). */
  visibleCount: number;
  /** Events loaded. */
  loadedCount: number;
  /** Text-log entries in the session. */
  textLogCount: number;
}

export interface ScopeDisclosure {
  /** Always present when the view is narrowed. */
  strengthNote: string;
  /** Present when text logs were given to the session unscoped. */
  textLogNote: string | null;
}

/**
 * Said when the scope the model was built from is not known. Not knowing it is not the same as
 * nothing being narrowed, so the disclosure is shown, not left out.
 */
export const SCOPE_NOT_KNOWN_NOTICE =
  "The events this model was built from are not known here, so events outside them may make an Exact link ambiguous.";

/**
 * The disclosure for a narrowed view (decision 10): links and strengths are computed over the
 * visible events only, so an event outside the view can make an Exact link ambiguous. It uses the
 * rail's condition, visible < loaded, and the rail's text-log sentence. Null when nothing is
 * narrowed, because then there is nothing the events were left out of. When the scope is not
 * known (`input` null) the disclosure says so: an unknown scope is never read as no narrowing.
 */
export function scopeDisclosure(input: ScopeDisclosureInput | null): ScopeDisclosure | null {
  if (input === null) return { strengthNote: SCOPE_NOT_KNOWN_NOTICE, textLogNote: null };
  if (!(input.visibleCount < input.loadedCount)) return null;
  return {
    strengthNote: `Links and strengths are computed over the ${events(input.visibleCount)} visible. Events outside the view can make an Exact link ambiguous.`,
    textLogNote: input.textLogCount > 0 ? "Text logs are not scoped." : null,
  };
}

export interface EdgeInputState {
  edgeInputComplete: boolean;
  unloadedEdgeCount: number;
}

/**
 * The paged-and-bounded notice (spec 8.11). Null only when every edge is loaded. With a known
 * shortfall it says how many edges were left out; with an unknown total it says the total is not
 * known, and never "0 omitted".
 */
export function edgeInputNotice(state: EdgeInputState): string | null {
  if (state.edgeInputComplete) return null;
  return state.unloadedEdgeCount > 0
    ? `Correlation details are paged and bounded: ${count(state.unloadedEdgeCount)} correlation edges were not loaded, so chains may be incomplete.`
    : "Correlation details are paged and bounded: the number of correlation edges in this session is not known, so chains may be incomplete.";
}

/**
 * The notice for the engine's correlation coverage gaps (`gapsClearCompleteness`), or null when
 * nothing about them stops the view from being whole. A missing link is a coverage state, not
 * proof of no link, so the notice says only that some entries may not have been correlated.
 */
export function coverageGapNotice(gaps: CorrelationGaps): string | null {
  if (!gapsClearCompleteness(gaps)) return null;
  const tail = "so some entries may not have been correlated and chains may be incomplete.";
  if (gaps.global && gaps.previewCut) {
    return `The engine limited correlation and may report more coverage gaps than are listed, ${tail}`;
  }
  if (gaps.global) return `The engine limited correlation, ${tail}`;
  return `More coverage gaps may exist than are listed, ${tail}`;
}

/**
 * The notice for the origins the engine left uncorrelated (`gaps.originIds`), or null when it left
 * none. A gap that names an origin means that origin's records were never fully correlated, so a
 * link involving them can be missing, and so an absence of links anywhere in the session is
 * unproven. `coverageGapNotice` says nothing for such a gap (it is not global and cuts nothing), so
 * without this note a surface that withdrew its absence claim would point at no note at all. The
 * number is the distinct origins the preview names; when the preview is cut, the gaps that are not
 * shown may name more, so it is a lower bound and the sentence says so.
 */
export function uncorrelatedOriginsNotice(gaps: CorrelationGaps): string | null {
  const n = gaps.originIds.size;
  if (n === 0) return null;
  const sentence = `${events(n)} could not be fully correlated, so links involving ${n === 1 ? "it" : "them"} may be missing.`;
  return gaps.previewCut ? `At least ${sentence}` : sentence;
}

export interface ScanNoticeInput {
  state: "idle" | "running" | "complete" | "incomplete";
  stoppedBy: "budget" | "error" | null;
  error: string | null;
}

/**
 * Why some entries have no loaded position when reading the timeline stopped early, or null when it
 * did not. It says what stopped the read and never claims the entries have no timestamp.
 */
export function scanNotice(scan: ScanNoticeInput): string | null {
  if (scan.state !== "incomplete") return null;
  const tail = "so some entries have no loaded timeline position.";
  if (scan.stoppedBy === "budget") return `Reading the timeline stopped at its memory limit, ${tail}`;
  if (scan.stoppedBy === "error") {
    return `Reading the timeline stopped on an error${scan.error === null ? "" : ` (${scan.error})`}, ${tail}`;
  }
  return `Reading the timeline did not finish, ${tail}`;
}

/** The failure of an edge page, or null. Its consequence (fewer edges) is `edgeInputNotice`'s. */
export function edgeErrorNotice(error: string | null): string | null {
  return error === null ? null : `Loading correlation edges stopped on an error (${error}).`;
}

/** The 100-row cap line (spec 8.11), or null when no row was dropped by the cap. */
export function renderCapNotice(input: {
  shown: number;
  totalCount: number;
  omittedCount: number;
}): string | null {
  return input.omittedCount > 0
    ? `Showing the first ${count(input.shown)} of ${count(input.totalCount)}; ${count(input.omittedCount)} omitted.`
    : null;
}

/**
 * The line when the selected row is past the render cap and is listed after the rows the cap kept
 * (`listedRows`). `shown` is the number of rows the cap kept. Without it a row opened from the dock
 * or the rail would appear below the cap with nothing saying why it is there.
 */
export function pastCapNotice(shown: number): string {
  return `The selected chain is past the first ${count(shown)} rows, so it is listed after them.`;
}

// ---- the words the Correlation view and the Chains tab say alike ---------------------------------

/** Said when no analysis session exists and none is on the way. */
export const NO_ANALYSIS_TEXT = "No event analysis is available. Load events to see correlation.";

/** Said while a session is built or its edges are read and there is no model yet: never "no chains". */
export const READING_EDGES_TEXT = "Reading correlation edges...";

/** A row whose members have no loaded position says so, and nothing about why. */
export const NO_POSITION_TEXT = "No loaded timeline position";

/** Why an action on a chain's entries waits: the entries have not been read yet. */
export const WAIT_FOR_ENTRIES_REASON = "Wait for the entries of this chain to be read.";

/**
 * Whether an action on the model on show (filter the table, copy, open) may act. It waits for a
 * rebuild first, then for the entries to be read: the model on show can be an earlier session's,
 * and a chain whose entries were not read has no records to name.
 */
export function chainActionAvailability(input: {
  hasItems: boolean;
  updating: boolean;
  hasChain: boolean;
}): { canAct: boolean; reason: string | undefined } {
  const canAct = input.hasItems && !input.updating && input.hasChain;
  return {
    canAct,
    reason: canAct ? undefined : input.updating ? WAIT_FOR_UPDATE_REASON : WAIT_FOR_ENTRIES_REASON,
  };
}

/** Said once above a list of entries in time order: a sequence is not a cause. */
export const SEQUENCE_ORDER_NOTE = "Ordered by recorded time. Order is not evidence of cause.";

/**
 * The heading of the copied text's sequence: the order note's two sentences as one parenthesised clause
 * (the first word of each lower-cased, a semicolon between), so the copied text and the list say it in
 * the one set of words.
 */
export const SEQUENCE_HEADING = `Sequence (${SEQUENCE_ORDER_NOTE.replace(/\.$/, "")
  .split(". ")
  .map((part) => part.charAt(0).toLowerCase() + part.slice(1))
  .join("; ")})`;

/** The sentence said of an entry whose timestamp equals the entry above it: time does not order the two. */
const SAME_TIME_SENTENCE = "same timestamp as the entry above; their order is not established";

/** `SAME_TIME_SENTENCE` as the note beside an entry in a list. */
export const SAME_TIME_NOTE = `(${SAME_TIME_SENTENCE})`;

/** A failure that is not a load result: the model could not be built, or could not be updated. */
export function correlationFailureText(error: string, phase: "built" | "updated"): string {
  return `Correlation could not be ${phase}: ${error}`;
}

/**
 * How far reading the timeline has got, in words that are not a live region's. With no progress it
 * prints no number at all: a count that is not known is not 0.
 */
export function timelineReadingText(
  progress: { scannedItems: number; totalItems: number } | null,
): string {
  return progress === null
    ? "Reading the timeline..."
    : `Reading ${count(progress.scannedItems)} of ${count(progress.totalItems)} timeline items...`;
}

/**
 * The line for a model that holds no chain. The absolute sentence is said only when every edge was
 * loaded; with edges missing it says only what was looked at.
 */
export function noChainsFoundText(edgeInputComplete: boolean): string {
  return edgeInputComplete
    ? "No correlation chains were found in this session."
    : "No chains were found among the edges that were loaded.";
}

/** Said in place of a chain's entries while they are read. */
export const CHAIN_ENTRIES_BEING_READ_TEXT = "The entries of this chain are being read.";

/** Said in place of a chain's steps when the read of its entries did not reach them. */
export const CHAIN_STEPS_NOT_READ_TEXT = "The entries of this chain were not read, so there are no steps to show.";

/** Said of a chain none of whose entries has a loaded position (the entries were read). */
export const NO_ENTRY_POSITION_TEXT = "No entry has a loaded timeline position.";

/** Added to the name of the chain row that holds the selected event. */
export const CONTAINS_SELECTED_EVENT_SUFFIX = ", contains the selected event";

/** The spec's empty state (8.13). An absence of links is claimed here, so it needs `noLinkedChainsText`. */
export const NO_LINKED_EVENTS_TEXT =
  "No linked events. Correlation requires a shared identifier; time proximity alone is not a link.";

/** Said when no chain was found and the session cannot speak for an absence: the notes say why. */
export const NO_CHAINS_QUALIFIED_TEXT =
  "No chains were found, but the notes above say what was not covered, so this does not show that none exist.";

/**
 * The line for a model that holds no row at all. The spec's sentence says there are no linked events,
 * which is a claim about the whole session: it is said only when `speaks` (every edge loaded, nothing
 * narrowed, no gap that clears completeness, no unread source, no rebuild under way). Without that it
 * says only what was looked at.
 */
export function noLinkedChainsText(input: { speaks: boolean; edgeInputComplete: boolean }): string {
  if (input.speaks) return NO_LINKED_EVENTS_TEXT;
  return input.edgeInputComplete ? NO_CHAINS_QUALIFIED_TEXT : noChainsFoundText(false);
}

/** The line above rows that establish no link (ambiguous, coverage blocked) when there is no chain. */
export function noLinkingChainsLine(speaks: boolean): string {
  return speaks
    ? "No exact or candidate chains were found."
    : "No exact or candidate chains were found among what was loaded.";
}

/** Said when sources were not fully read: what the chains hold can be missing entries and links. */
export const UNREAD_SOURCES_CHAINS_NOTE =
  "Some sources were not fully read, so entries and links may be missing from these chains.";

/** The heading of the nearby group: the one word its entries may carry, and how many they are. */
export function nearbyHeading(word: string, entries: number): string {
  return `Nearby, ${word.toLowerCase()} (${count(entries)})`;
}

/**
 * The name a screen reader gives a chain row: its strength, its title (or "Untitled chain" and its
 * id, so two untitled rows are told apart), its entry count from ALL members, and "partial" when
 * members have no loaded position.
 */
export function chainRowName(
  chain: Pick<CorrelationChain, "strength" | "title" | "id" | "memberCount" | "unresolvedMemberIds">,
): string {
  return `${STRENGTH_LABELS[chain.strength]}, ${chainAccessibleName(chain)}, ${entriesText(chain.memberCount)}${isPartialChain(chain) ? ", partial" : ""}`;
}

export interface CorrelationNoticesInput {
  edgeInput: EdgeInputState;
  edgeError: string | null;
  gaps: CorrelationGaps;
  scan: ScanNoticeInput;
  /**
   * The Correlation view's own notice that the chain it had selected is gone, placed after the scan
   * notice. A surface that holds no selection (the Chains tab) passes null.
   */
  selectionLoss: string | null;
  scope: ScopeDisclosure | null;
  /** The 100-row cap: rows listed, rows before the cap, rows it dropped. */
  cap: { shown: number; totalCount: number; omittedCount: number };
  /** The number of rows the cap kept when the selected row is listed past them; null otherwise. */
  pastCapShown: number | null;
}

/**
 * Everything the model says about what it did not cover, in one order, for every surface that lists
 * its chains: the edges that were not all loaded, a failed edge page, the engine's coverage gaps and
 * the origins it left uncorrelated, an unfinished timeline read, a narrowed view, and the render
 * cap. A notice with nothing to say is left out.
 */
export function correlationNotices(input: CorrelationNoticesInput): string[] {
  return [
    edgeInputNotice(input.edgeInput),
    edgeErrorNotice(input.edgeError),
    coverageGapNotice(input.gaps),
    uncorrelatedOriginsNotice(input.gaps),
    scanNotice(input.scan),
    input.selectionLoss,
    ...(input.scope === null ? [] : [input.scope.strengthNote, input.scope.textLogNote]),
    renderCapNotice(input.cap),
    input.pastCapShown === null ? null : pastCapNotice(input.pastCapShown),
  ].filter((text): text is string => text !== null);
}

/**
 * Why a chain has members that are not on the plot, or null when all are. "No timestamp" is said
 * only when it is PROVEN for every one of them (`isProvenUnplaced`). Otherwise the sentence says
 * only that no position was loaded, and that they are not drawn.
 */
export function unresolvedNotice(
  chain: Pick<CorrelationChain, "unresolvedMemberIds" | "memberCount">,
  evidence: UnplacedEvidence,
): string | null {
  const missing = chain.unresolvedMemberIds.length;
  if (missing === 0) return null;
  const proven = chain.unresolvedMemberIds.every((id) => isProvenUnplaced(id, evidence));
  return proven
    ? `${count(missing)} of ${count(chain.memberCount)} entries carry no timestamp, so they are not placed on the plot.`
    : `${count(missing)} of ${count(chain.memberCount)} entries have no loaded timeline position, so they are not drawn on the plot.`;
}

/**
 * Why a chain has members that are not listed as steps, or null when all are. Like `unresolvedNotice`,
 * "no timestamp" is said only when it is PROVEN for every one of them (`isProvenUnplaced`); otherwise
 * it says only that no position was loaded. It speaks of steps, not of a plot.
 */
export function unresolvedStepsNotice(
  chain: Pick<CorrelationChain, "unresolvedMemberIds" | "memberCount">,
  evidence: UnplacedEvidence,
): string | null {
  const missing = chain.unresolvedMemberIds.length;
  if (missing === 0) return null;
  const proven = chain.unresolvedMemberIds.every((id) => isProvenUnplaced(id, evidence));
  return proven
    ? `${count(missing)} of ${count(chain.memberCount)} entries carry no timestamp, so they are not listed as steps.`
    : `${count(missing)} of ${count(chain.memberCount)} entries have no loaded timeline position, so they are not listed as steps.`;
}

/** The line after the plot when a cap left entries or connectors undrawn. Null when none was. */
export function plotOmissionNotice(input: {
  omittedMarkers: number;
  omittedConnectors: number;
}): string | null {
  const parts: string[] = [];
  if (input.omittedMarkers > 0) {
    parts.push(
      `${count(input.omittedMarkers)} ${input.omittedMarkers === 1 ? "entry is" : "entries are"} listed in Sequence but not drawn`,
    );
  }
  if (input.omittedConnectors > 0) {
    parts.push(
      `${count(input.omittedConnectors)} ${input.omittedConnectors === 1 ? "connector is" : "connectors are"} not drawn`,
    );
  }
  return parts.length === 0 ? null : `${parts.join("; ")}.`;
}

// ---- why ----------------------------------------------------------------------------------------

/** An ambiguous or coverage blocked row is not a link, so it is never headed as one. */
export function whyHeading(strength: CorrelationChainStrength): string {
  return strength === "exact" || strength === "candidate"
    ? "Why these are linked"
    : "Why this is not a link";
}

const GAP_REASONS_SHOWN = 3;

/** One plain sentence generated from the row's keys, strength and gaps. */
export function whyStatement(
  chain: Pick<CorrelationChain, "strength" | "keys" | "memberCount" | "coverageGaps">,
): string {
  const entries = entriesText(chain.memberCount);
  const only = chain.keys.length === 1 ? chain.keys[0] : undefined;
  switch (chain.strength) {
    case "exact":
      return only !== undefined
        ? `One ${keyKindLabel(only.kind)} value matches across ${entries} on one machine.`
        : `${count(chain.keys.length)} identifier values link these ${entries}; each connector is backed by the rows below.`;
    case "candidate":
      return `A secondary identifier matches across ${entries}. This is a candidate link, not a confirmed one.`;
    case "ambiguous":
      return only !== undefined
        ? `${capitalize(entries)} share ${keyKindLabel(only.kind)} ${only.value}, so no single link between two of them is established.`
        : `${capitalize(entries)} share more than one identifier value, so no single link between two of them is established.`;
    case "coverageBlocked": {
      const reasons = chain.coverageGaps.map((gap) => gap.reason);
      const shown = reasons.slice(0, GAP_REASONS_SHOWN).join("; ");
      const rest = reasons.length - GAP_REASONS_SHOWN;
      return `A coverage gap stops a link between these ${entries}${shown === "" ? "." : `: ${shown}${rest > 0 ? `; and ${count(rest)} more` : ""}.`}`;
    }
  }
}

function capitalize(text: string): string {
  return text === "" ? text : text[0]!.toUpperCase() + text.slice(1);
}

// ---- copy as text -------------------------------------------------------------------------------

export interface ChainCopyInput {
  chain: CorrelationChain;
  itemsById: ReadonlyMap<string, TimelineItem>;
  timeZoneMode: EvtxTimeZoneMode;
  scope: ScopeDisclosure | null;
  edgeInput: EdgeInputState;
  unplaced: UnplacedEvidence;
}

const UNPLACED_IDS_LISTED = 20;

function indented(message: string): string {
  return message.replace(/\r?\n/g, "\n      ");
}

/**
 * The selected row as plain text: its title and strength, keys, span, what was left out, the
 * sequence with offsets from the first entry, and the evidence rows. The same data and the same
 * notices as the screen, so a pasted copy cannot read as more certain than the view.
 */
export function chainCopyText(input: ChainCopyInput): string {
  const { chain, itemsById, timeZoneMode } = input;
  const lines: string[] = [];
  lines.push(`${STRENGTH_LABELS[chain.strength]}: ${chainTitle(chain)}`);
  if (chain.keys.length > 0) {
    lines.push(`Key: ${chain.keys.map((key) => `${key.kind} ${key.value}`).join("; ")}`);
  }
  lines.push(`Time zone: ${timeZoneLabel(timeZoneMode, chain.startMs ?? Date.now())}`);
  lines.push(
    chain.startMs === null || chain.endMs === null
      ? "Span: not known, no entry of this chain has a loaded timeline position"
      : `Span: ${formatEventTime(chain.startMs, timeZoneMode)} to ${formatEventTime(chain.endMs, timeZoneMode)}`,
  );
  const sequence = chainSequence(chain, itemsById);
  const parts = partitionUnplaced(sequence.itemlessIds, input.unplaced);
  lines.push(
    `Entries: ${count(chain.memberCount)} (${[
      `${count(sequence.entries.length)} placed`,
      ...(parts.proven.length > 0 ? [`${count(parts.proven.length)} not placed`] : []),
      ...(parts.unknown.length > 0
        ? [`${count(parts.unknown.length)} with no loaded position`]
        : []),
    ].join(", ")})`,
  );
  for (const note of [
    input.scope?.strengthNote ?? null,
    input.scope?.textLogNote ?? null,
    edgeInputNotice(input.edgeInput),
    unresolvedNotice(chain, input.unplaced),
  ]) {
    if (note !== null) lines.push(note);
  }

  lines.push("", SEQUENCE_HEADING);
  if (sequence.entries.length === 0) lines.push(`  ${NO_ENTRY_POSITION_TEXT}`);
  for (const entry of sequence.entries) {
    const when =
      entry.index === 0
        ? formatEventTime(entry.timestampMs, timeZoneMode)
        : `+${formatDelta(entry.offsetMs)}`;
    lines.push(
      `  ${entry.index + 1}. ${when}  ${entry.level}  ${entry.entry}  [${entry.laneLabel}]  ${indented(entry.message)}`,
    );
    if (entry.sameTimeAsPrevious) {
      lines.push(`      ${SAME_TIME_SENTENCE}`);
    }
  }
  for (const [heading, ids] of [
    ["Entries without a timeline position:", parts.proven],
    ["Entries with no loaded timeline position:", parts.unknown],
  ] as const) {
    if (ids.length === 0) continue;
    lines.push(`  ${heading}`);
    for (const id of ids.slice(0, UNPLACED_IDS_LISTED)) lines.push(`    ${id}`);
    if (ids.length > UNPLACED_IDS_LISTED) {
      lines.push(`    and ${count(ids.length - UNPLACED_IDS_LISTED)} more`);
    }
  }

  lines.push("", whyHeading(chain.strength), whyStatement(chain));
  const rows = whyRows(chain, itemsById, input.unplaced);
  if (rows.length === 0) lines.push("  No evidence row was loaded for this row.");
  for (const row of rows) lines.push(`  ${row.entry}: ${row.field} = ${row.value}`);
  return lines.join("\n");
}

// ---- the correlation dock (spec 8.12, #842) ------------------------------------------------------
//
// The dock shows what was recorded around one event. Every entry it draws that is not in the event's
// chain is there because of its TIME and for no other reason, and its words say so: they never say
// one entry caused, followed or explains another, and "not linked" is said only when the session can
// speak for the entry (`buildChainPlot`'s rule). Everything the dock could not look at is a coverage
// state in its words, never an absence.

/** The half width as the dropdown names it: "±30 s", "±75 s", "±2 min", "±5 min". */
export function windowWidthLabel(halfWidthMs: number): string {
  if (halfWidthMs >= 60_000 && halfWidthMs % 60_000 === 0) return `\u00b1${halfWidthMs / 60_000} min`;
  if (halfWidthMs >= 1_000 && halfWidthMs % 1_000 === 0) return `\u00b1${halfWidthMs / 1_000} s`;
  return `\u00b1${count(halfWidthMs)} ms`;
}

/**
 * "{n} sources", or "at least {n} sources" when the window was not read whole: an unread entry can
 * belong to a source that is not counted.
 */
export function sourcesText(sourceCount: number, complete: boolean): string {
  const noun = sourceCount === 1 ? "source" : "sources";
  return `${complete ? "" : "at least "}${count(sourceCount)} ${noun}`;
}

interface DockSubtitleInput {
  eventId: number;
  /** The event's time, formatted by the caller in the operator's time zone. */
  timeText: string;
  halfWidthMs: number;
  /** Null when the window was not read (the dock is collapsed, or the read has not finished). */
  sources: string | null;
}

/** The header line (spec 8.12): "around Event {id} · {time} · window ±{w} · {n} sources". */
export function dockSubtitle(input: DockSubtitleInput): string {
  return [
    `around Event ${input.eventId}`,
    input.timeText,
    `window ${windowWidthLabel(input.halfWidthMs)}`,
    input.sources,
  ]
    .filter((part): part is string => part !== null)
    .join(" \u00b7 ");
}

/** The dock body when no event is selected. */
export const NO_SELECTION_TEXT = "Select an event to see what happened around it.";

/**
 * The dock body when the selected event has no usable timestamp (spec 8.12). It states a fact read
 * from the event's OWN timestamp field (a record is untimed when it has none), not a claim about an
 * entry of the unplaced list, so the unplaced audit does not apply to it.
 */
export const UNTIMED_TEXT = "This event has no timestamp; it cannot be placed.";

/**
 * The body of a surface that reads the analysis session, while there is no session and none is on
 * the way: nothing was loaded, or the analysis could not be built.
 */
export const NO_SESSION_TEXT = "No event analysis is available. Load events to see what is around an event.";

/**
 * The same surfaces' body while the session IS on the way: the events are loaded and the analysis is
 * being built (or rebuilt), so there is no session yet. "Pending" is not "none": this says to wait,
 * where `NO_SESSION_TEXT` says there is nothing to wait for. Shared by the correlation dock and the
 * Details context (#843).
 */
export const ANALYSIS_BUILDING_TEXT =
  "The event analysis is being built, so the entries around this event are not available yet.";

/**
 * What a surface that shows the correlation says while the correlation it shows belongs to an
 * earlier session and a newer one is being built. One constant for the Correlation view, the dock and
 * the Details context list, so the three say it alike.
 */
export const UPDATING_CORRELATION_TEXT = "Updating correlation...";

/** The dock body while the first read of a window is under way. */
export const READING_WINDOW_TEXT = "Reading the entries around this event...";

/**
 * Said while the session's correlation links are not in: the entries are shown by time alone, and
 * no entry is called linked or not linked.
 */
export const LINKS_LOADING_TEXT =
  "Correlation links for this session are still loading, so entries are shown by time only.";

/** The failure of the first read, whose count of entries is therefore not known. */
export function windowFailureText(error: string | null): string {
  return `The entries around this event could not be read${error === null ? "" : ` (${error})`}.`;
}

/**
 * The line for a window that was not read whole, or null when it was. The numbers are exact: the
 * first reply counted the window. It names what stopped the read and never says the unread entries
 * do not exist. A read that failed before any count is `windowFailureText`'s.
 */
export function windowNotice(
  window: Pick<
    LoadedCorrelationWindow,
    "complete" | "windowItems" | "omittedItems" | "items" | "halfWidthMs" | "stoppedBy" | "error"
  >,
): string | null {
  if (window.complete) return null;
  if (window.windowItems === null) return windowFailureText(window.error);
  const why =
    window.stoppedBy === "callLimit"
      ? "its call limit"
      : window.stoppedBy === "budget"
        ? "its memory limit"
        : `an error${window.error === null ? "" : ` (${window.error})`}`;
  return `Showing ${count(window.items.length)} of ${count(window.windowItems)} entries within ${windowWidthLabel(window.halfWidthMs)}; reading stopped at ${why}, so entries and sources may be missing.`;
}

interface EmptyWindowInput {
  halfWidthMs: number;
  /** The session was built from fewer events than are loaded, or from a scope that is not known. */
  scopeNarrowed: boolean;
  /** A source was not fully read (a channel needs elevation, a file failed): entries may be missing. */
  unreadSources: boolean;
  /**
   * The window and its counts are an earlier session's, shown while a newer one is read: the newer
   * one exists because events were added or the load changed, so the claim may already be false.
   */
  updating: boolean;
  /**
   * How many entries the session could not place in time (`CorrelationCounts.unplacedList.total`,
   * the engine's own count from the same run), or null when it is not known. An entry the engine
   * could not place is in NO window, so a window cannot speak for it: the claim needs a KNOWN zero.
   */
  unplacedTotal: number | null;
  /**
   * What the sentence says there are none of: "sources" (the dock's, the default) or "entries" (the
   * Details context list's). The conditions are the same; only the noun is.
   */
  subject?: "sources" | "entries";
}

/**
 * The dock's "no other sources" sentence, or the Details list's "no other entries". The spec's own
 * words are an absence claim, so they are said only when all of these hold: the window was read
 * whole (the caller asks only then), nothing is narrowed, no source went unread, the pair is not an
 * earlier session's, and the session's count of entries it could not place in time is a known zero.
 * Otherwise the sentence says what it was looked for IN, and what was not looked at. (A correlation
 * coverage gap does not bear on it: no gap removes an entry from the window; gaps withdraw "not
 * linked", and the dock does that.)
 */
export function emptyWindowText(input: EmptyWindowInput): { text: string; absolute: boolean } {
  const width = windowWidthLabel(input.halfWidthMs);
  const entries = input.subject === "entries";
  if (!input.scopeNarrowed && !input.unreadSources && !input.updating && input.unplacedTotal === 0) {
    return {
      text: entries ? `No other entries within ${width}.` : `No other sources have entries within ${width}.`,
      absolute: true,
    };
  }
  const parts = [
    entries
      ? `No other visible entries within ${width}.`
      : `No other visible sources have entries within ${width}.`,
  ];
  if (input.scopeNarrowed) parts.push("Events hidden by the current filters or time range are not searched.");
  if (input.unreadSources) parts.push("Some sources were not fully read, so entries may be missing.");
  if (input.updating) parts.push("The timeline is being rebuilt, so this may change.");
  if (input.unplacedTotal === null) {
    parts.push("How many entries have no usable time is not known, and such entries are in no window.");
  } else if (input.unplacedTotal > 0) {
    parts.push(
      `${count(input.unplacedTotal)} ${input.unplacedTotal === 1 ? "entry has" : "entries have"} no usable time and ${input.unplacedTotal === 1 ? "appears" : "appear"} in no window.`,
    );
  }
  return { text: parts.join(" "), absolute: false };
}

/** Added after the scope disclosure when the view is narrowed: the window is narrowed too. */
export const DOCK_SCOPE_NOTE =
  "Entries from events hidden by the current filters or time range are not shown in this window.";

/** A source was not fully read: the window may be missing entries from it. */
export const UNREAD_SOURCES_NOTE = "Some sources were not fully read, so entries may be missing from this window.";

/**
 * The selected event is not among the entries the timeline was built from. An absence claim: it is
 * given ONLY for a window that was read whole (an unread entry could be the event), and only for a
 * record the join could have matched.
 */
export const NOT_IN_TIMELINE_NOTE =
  "This event is not among the entries this timeline was built from (the current filters can hide it), so its links cannot be shown.";

/**
 * The read of the window stopped before this event was found. It may be among the entries that
 * were not read, so nothing is said about whether it is in the timeline or what it is linked to.
 */
export const NOT_READ_NOTE =
  "The read of this window stopped before this event was found, so whether it is among the entries, and what it is linked to, are not known.";

/**
 * Entries read that repeat the origin of another entry read are one entry to the join, so a count of
 * the origins is smaller than the count of the entries read. This says by how many, and claims
 * nothing more: not that the origin is on any list (it may be outside it, or the list may be empty),
 * and not that another entry exists besides the one it repeats. Null when none does.
 */
export function sharedOriginNote(duplicates: number): string | null {
  if (duplicates <= 0) return null;
  return `${count(duplicates)} ${duplicates === 1 ? "entry read repeats" : "entries read repeat"} another entry's origin and ${duplicates === 1 ? "is" : "are"} counted once.`;
}

/** Where the entries of a window are shown: the dock draws them, the Details list lists them. */
type NoteSurface = "dock" | "list";

/**
 * Several entries of the window each match the selected event, so which one it is cannot be told.
 * They are named by count and left out of the context, since each of them could be the event.
 */
export function ambiguousEventNote(candidates: number, surface: NoteSurface = "dock"): string {
  return `${count(candidates)} entries of this window match this event, so which one it is cannot be told. They are not ${surface === "list" ? "listed" : "drawn as context"}, and no link is shown.`;
}

/**
 * The selected event has no record identity the timeline's join can match (an event the provider
 * never numbered), so which entry of the window is it cannot be told, and none is drawn: any of
 * them could be the event itself. A way out is an input ordinal on the timeline origins (#957).
 */
export function unmatchableNote(entries: number, halfWidthMs: number, surface: NoteSurface = "dock"): string {
  const width = windowWidthLabel(halfWidthMs);
  return entries === 0
    ? `This event has no record identity the timeline can match, so it cannot be found among the entries within ${width}. No link is shown.`
    : `This event has no record identity the timeline can match, so which of the ${count(entries)} ${entries === 1 ? "entry" : "entries"} within ${width} it is cannot be told. They are not ${surface === "list" ? "listed" : "drawn"}, and no link is shown.`;
}

/**
 * How many of the row's entries are outside the window. They are counted, never placed. For a window
 * that was read WHOLE only: in a window that was not, an entry without an item may be inside it and
 * simply unread, and `notReadNote` is the sentence for that.
 */
export function outsideWindowNote(outside: number, memberCount: number): string | null {
  if (outside <= 0) return null;
  return `${count(outside)} of ${count(memberCount)} ${memberCount === 1 ? "entry" : "entries"} of this chain ${outside === 1 ? "is" : "are"} outside this window, so ${outside === 1 ? "it is" : "they are"} not shown here.`;
}

/**
 * How many of the row's entries are not among the entries that were read, for a window that was NOT
 * read whole. The number is exact; where those entries are (outside the window, or inside it and
 * unread) is not known, so it is never said to be "outside".
 */
export function notReadNote(notShown: number, memberCount: number): string | null {
  if (notShown <= 0) return null;
  return `${count(notShown)} of ${count(memberCount)} ${memberCount === 1 ? "entry" : "entries"} of this chain ${notShown === 1 ? "is" : "are"} not among the entries read, so ${notShown === 1 ? "it is" : "they are"} not shown here.`;
}

/**
 * The row title when the entries read are only some of the row's: no title is claimed for the whole.
 * `read` counts the entries read. For a window read whole they are the ones in the window; for one
 * that was not, the others may be inside it, so the count says "read" and nothing about the window.
 */
export function partialChainTitle(memberCount: number, read: number, windowComplete: boolean): string {
  return `Chain of ${entriesText(memberCount)} (${count(read)} ${windowComplete ? "in this window" : "read"})`;
}

/**
 * "+3 more" when the count is exact, "at least 3 more" when it is a lower bound: a list taken from
 * the entries READ of a window that was not read whole has more entries than it can count.
 */
export function moreText(more: number, exact: boolean): string | null {
  if (more <= 0) return null;
  return exact ? `+${count(more)} more` : `at least ${count(more)} more`;
}

/** What a context entry's words may be, from the facts the dock holds about it. */
export type NearbyReason =
  | "notLinked"
  | "noLoadedLink"
  | "inAnotherChain"
  | "linkUnknownToEvent"
  | "ambiguousWithEvent"
  | "coverageBlockedWithEvent";

/**
 * The reason beside an entry of "Also nearby" and in its marker's name.
 *
 * The three RULED reasons (#842 ruling 2) say the entry is there by TIME ("time only"), then the one
 * thing known about its links; "not linked" appears only for the entry the session can speak for.
 *
 * The other three are RECORDED ADDITIONS to ruling 2 (rulings_a1 item 2 for the first two,
 * rulings_a1_fix A for the third), and do not begin "time only", because each says more than time:
 * - "ambiguous with this event" and "coverage blocked with this event": the engine reported a shared
 *   identity key with the selected event in a row that establishes no link (ambiguous: several
 *   entries could be the same transaction; coverage blocked: a gap stopped the link);
 * - "linked, but its link to this event is not known": the entry has a loaded partner and the
 *   selected event could not be identified, so its partner may be the event.
 */
export function nearbyReason(reason: NearbyReason): string {
  switch (reason) {
    case "notLinked":
      return "time only, not linked";
    case "noLoadedLink":
      return "time only, no loaded link";
    case "inAnotherChain":
      return "time only; in another chain";
    case "linkUnknownToEvent":
      return "linked, but its link to this event is not known";
    case "ambiguousWithEvent":
      return "ambiguous with this event";
    case "coverageBlockedWithEvent":
      return "coverage blocked with this event";
  }
}

/**
 * The reason that goes with the label `nearbyLinkLabel` gave a context entry. A label that is not
 * one of the three this reads, or none, is the weakest claim: no loaded link.
 */
export function nearbyReasonOfLabel(label: string | null): NearbyReason {
  if (label === NOT_LINKED_LABEL) return "notLinked";
  if (label === IN_ANOTHER_CHAIN_LABEL) return "inAnotherChain";
  if (label === LINK_TO_EVENT_UNKNOWN_LABEL) return "linkUnknownToEvent";
  return "noLoadedLink";
}

/** The line after the dock's plot when a cap left entries, sources or connectors undrawn. */
export function dockOmissionNotice(input: {
  omittedMarkers: number;
  omittedNearby: number;
  omittedConnectors: number;
  omittedSources: number;
  omittedSourceEntries: number;
}): string | null {
  const parts: string[] = [];
  if (input.omittedSources > 0) {
    parts.push(
      `${count(input.omittedSources)} more ${input.omittedSources === 1 ? "source" : "sources"} not drawn (${count(input.omittedSourceEntries)} ${input.omittedSourceEntries === 1 ? "entry" : "entries"})`,
    );
  }
  if (input.omittedMarkers > 0) {
    parts.push(`${count(input.omittedMarkers)} ${input.omittedMarkers === 1 ? "entry" : "entries"} of this chain not drawn`);
  }
  if (input.omittedNearby > 0) {
    parts.push(`${count(input.omittedNearby)} more nearby ${input.omittedNearby === 1 ? "entry" : "entries"} not drawn`);
  }
  if (input.omittedConnectors > 0) {
    parts.push(`${count(input.omittedConnectors)} ${input.omittedConnectors === 1 ? "connector is" : "connectors are"} not drawn`);
  }
  return parts.length === 0 ? null : `${parts.join("; ")}.`;
}

/** Why "Open in Correlation view" cannot act, as visible text beside the disabled button. */
export type OpenDisabled =
  | "loading"
  | "notInTimeline"
  | "notRead"
  | "unmatchable"
  | "notInChain"
  | "ambiguous";

export function openDisabledText(reason: OpenDisabled): string {
  switch (reason) {
    case "loading":
      return "Correlation links are still loading.";
    case "notInTimeline":
      return "Not in the timeline built for these filters.";
    case "notRead":
      return "The read of this window did not reach this event.";
    case "unmatchable":
      return "This event cannot be matched to an entry.";
    case "notInChain":
      return "Not in a loaded chain.";
    case "ambiguous":
      return "More than one entry matches this event.";
  }
}
