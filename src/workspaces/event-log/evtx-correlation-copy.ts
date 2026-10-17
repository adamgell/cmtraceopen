/**
 * The words the Correlation view says about what it can and cannot show, and the "Copy as text"
 * block (spec 8.11). Pure: strings from the chain model and its view model, nothing else.
 *
 * Evidence first (soul.md): every sentence here is either a count the model holds or a statement
 * of what was NOT loaded, scoped or placed. None says one entry caused, followed or explains
 * another: a sequence is ordered by recorded time and says so.
 */
import type {
  CorrelationChain,
  CorrelationChainStrength,
} from "./evtx-correlation-chains";
import {
  chainSequence,
  chainTitle,
  entriesText,
  formatDelta,
  whyRows,
} from "./evtx-correlation-view-model";
import { formatEventTime, timeZoneLabel, type EvtxTimeZoneMode } from "./evtx-time";
import type { TimelineItem } from "./unified-timeline";

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
 * The disclosure for a narrowed view (decision 10): links and strengths are computed over the
 * visible events only, so an event outside the view can make an Exact link ambiguous. It uses the
 * rail's condition, visible < loaded, and the rail's text-log sentence. Null when nothing is
 * narrowed, because then there is nothing the events were left out of.
 */
export function scopeDisclosure(input: ScopeDisclosureInput): ScopeDisclosure | null {
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

/** What is known about entries that have no item: the scan and the unplaced list. */
export interface UnplacedEvidence {
  /** Every timeline page was read (`LoadedLinkedItems.complete`). */
  scanComplete: boolean;
  /** The unplaced preview holds every unplaced item (preview length equals the session's count). */
  unplacedListComplete: boolean;
  unplacedIds: ReadonlySet<string>;
}

/**
 * Why a chain has members that are not on the plot, or null when all are. "No timestamp" is said
 * only when it is PROVEN: the scan finished, the unplaced list is complete, and every such member
 * is on it. Otherwise the sentence says only that no position was loaded.
 */
export function unresolvedNotice(
  chain: Pick<CorrelationChain, "unresolvedMemberIds" | "memberCount">,
  evidence: UnplacedEvidence,
): string | null {
  const missing = chain.unresolvedMemberIds.length;
  if (missing === 0) return null;
  const proven =
    evidence.scanComplete &&
    evidence.unplacedListComplete &&
    chain.unresolvedMemberIds.every((id) => evidence.unplacedIds.has(id));
  return proven
    ? `${count(missing)} of ${count(chain.memberCount)} entries carry no timestamp, so they are not placed on the plot.`
    : `${count(missing)} of ${count(chain.memberCount)} entries have no loaded timeline position, so they are not placed on the plot.`;
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
      ? "Span: not known, no entry of this chain has a timeline position"
      : `Span: ${formatEventTime(chain.startMs, timeZoneMode)} to ${formatEventTime(chain.endMs, timeZoneMode)}`,
  );
  const sequence = chainSequence(chain, itemsById);
  lines.push(
    `Entries: ${count(chain.memberCount)} (${count(sequence.entries.length)} placed, ${count(chain.memberCount - sequence.entries.length)} not placed)`,
  );
  for (const note of [
    input.scope?.strengthNote ?? null,
    input.scope?.textLogNote ?? null,
    edgeInputNotice(input.edgeInput),
    unresolvedNotice(chain, input.unplaced),
  ]) {
    if (note !== null) lines.push(note);
  }

  lines.push("", "Sequence (ordered by recorded time; order is not evidence of cause)");
  if (sequence.entries.length === 0) lines.push("  No entry has a timeline position.");
  for (const entry of sequence.entries) {
    const when =
      entry.index === 0
        ? formatEventTime(entry.timestampMs, timeZoneMode)
        : `+${formatDelta(entry.offsetMs)}`;
    lines.push(
      `  ${entry.index + 1}. ${when}  ${entry.level}  ${entry.entry}  [${entry.laneLabel}]  ${indented(entry.message)}`,
    );
    if (entry.sameTimeAsPrevious) {
      lines.push("      same timestamp as the entry above; their order is not established");
    }
  }
  if (sequence.unplacedIds.length > 0) {
    lines.push("  Entries without a timeline position:");
    for (const id of sequence.unplacedIds.slice(0, UNPLACED_IDS_LISTED)) lines.push(`    ${id}`);
    const more = sequence.unplacedIds.length - UNPLACED_IDS_LISTED;
    if (more > 0) lines.push(`    and ${count(more)} more`);
  }

  lines.push("", whyHeading(chain.strength), whyStatement(chain));
  const rows = whyRows(chain, itemsById);
  if (rows.length === 0) lines.push("  No evidence row was loaded for this row.");
  for (const row of rows) lines.push(`  ${row.entry}: ${row.field} = ${row.value}`);
  return lines.join("\n");
}
