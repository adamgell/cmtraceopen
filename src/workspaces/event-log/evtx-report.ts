/**
 * The Markdown analysis report (#851): the request the backend renders, and the save flow.
 *
 * The request carries ids, enum words and numbers only. The backend (analysis_report.rs) refuses
 * unknown fields, confirms every chain link against the session's own edges, and redacts
 * everything it prints, so nothing here formats or redacts text.
 */
import type {
  EventLogAnalysisReportChainRow,
  EventLogAnalysisReportChains,
  EventLogAnalysisReportFilters,
  EventLogAnalysisReportRequest,
  EventLogAnalysisReportScope,
} from "../../lib/commands";
import type { CorrelationChain, CorrelationChainModel } from "./evtx-correlation-chains";
import type { CorrelationGaps } from "./evtx-correlation-gaps";
import { parseEventIdSelectors, type EvtxRecordScopeKind, type EvtxTimeRange } from "./evtx-filter";
import type { EvtxCoverageGap, EvtxLevel, EvtxRecord, EvtxTimeWindow } from "./types";

/** The backend's request bounds (analysis_report.rs). */
export const REPORT_CHAIN_ROW_CAP = 100;
export const REPORT_CHAIN_MEMBER_CAP = 50;
export const REPORT_CHAIN_PAIR_CAP = 64;
const REPORT_PAIR_KEY_CAP = 16;
const REPORT_TOP_EVENT_IDS = 10;
const REPORT_CHANNELS_CAP = 64;

const LEVELS_MOST_SEVERE_FIRST: readonly EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

/**
 * One chain as the backend takes it. Members are listed in breadth-first order from the first
 * resolved member, so every listed member is joined to the ones before it; the pairs are first the
 * spanning tree that joins them, then further pairs between listed members, up to the cap. The
 * backend refuses a row whose pairs do not connect, a listed member no pair ends at, and a row
 * without a pair, so this is the only shape that renders.
 */
export function reportChainRow(chain: CorrelationChain): EventLogAnalysisReportChainRow | null {
  if (chain.strength !== "exact" && chain.strength !== "candidate") return null;
  const linking = chain.edges.filter(
    (edge): edge is typeof edge & { right: string } =>
      edge.right !== null && (edge.strength === "exact" || edge.strength === "candidate"),
  );
  const neighbours = new Map<string, typeof linking>();
  for (const edge of linking) {
    for (const end of [edge.left, edge.right]) {
      const list = neighbours.get(end);
      if (list) list.push(edge);
      else neighbours.set(end, [edge]);
    }
  }
  const start = [...chain.memberIds, ...chain.unresolvedMemberIds].find((id) => neighbours.has(id));
  if (start === undefined) return null;

  const listed: string[] = [start];
  const listedSet = new Set(listed);
  const tree: typeof linking = [];
  for (let index = 0; index < listed.length && listed.length < REPORT_CHAIN_MEMBER_CAP; index += 1) {
    for (const edge of neighbours.get(listed[index]) ?? []) {
      const other = edge.left === listed[index] ? edge.right : edge.left;
      if (listedSet.has(other)) continue;
      listedSet.add(other);
      listed.push(other);
      tree.push(edge);
      if (listed.length >= REPORT_CHAIN_MEMBER_CAP) break;
    }
  }
  if (tree.length === 0) return null;
  const used = new Set(tree);
  const extra = linking.filter(
    (edge) => !used.has(edge) && listedSet.has(edge.left) && listedSet.has(edge.right),
  );
  const pairs = [...tree, ...extra].slice(0, REPORT_CHAIN_PAIR_CAP).map((edge) => ({
    left: edge.left,
    right: edge.right,
    keys: edge.keys.slice(0, REPORT_PAIR_KEY_CAP).map(({ kind, value }) => ({ kind, value })),
  }));
  return {
    strength: chain.strength,
    memberCount: Math.max(chain.memberCount, listed.length),
    memberIds: listed,
    pairs,
  };
}

/**
 * The chains of the session the report is for, or null when the model on hand was built for
 * another session or revision. Unknown is null, never an empty list.
 */
export function buildReportChains(input: {
  sessionKey: string;
  builtFor: string | null;
  model: CorrelationChainModel | null;
  loadedEdgeCount: number;
  gaps: CorrelationGaps;
}): EventLogAnalysisReportChains | null {
  if (input.model === null || input.builtFor !== input.sessionKey) return null;
  const rows: EventLogAnalysisReportChainRow[] = [];
  for (const chain of input.model.chains) {
    if (rows.length >= REPORT_CHAIN_ROW_CAP) break;
    const row = reportChainRow(chain);
    if (row !== null) rows.push(row);
  }
  const counts = input.model.counts;
  return {
    loadedEdgeCount: input.loadedEdgeCount,
    correlationGaps: { global: input.gaps.global, previewCut: input.gaps.previewCut },
    counts: {
      exact: counts.exact,
      candidate: counts.candidate,
      ambiguous: counts.ambiguous,
      coverageBlocked: counts.coverageBlocked,
    },
    rows,
  };
}

/** Counts over the event records the session was built from (never archive text rows). */
export function buildReportScope(input: {
  sourceMode: "files" | "live";
  loadedRecordCount: number;
  sessionRecords: readonly EvtxRecord[];
  textLogEntryCount: number;
  filters: EventLogAnalysisReportFilters;
}): EventLogAnalysisReportScope {
  // An archived text-log line is shaped like a record but is not an event (origin "log").
  const events = input.sessionRecords.filter((record) => record.originKind !== "log");
  const levelCounts = new Map<EvtxLevel, number>();
  const idCounts = new Map<number, number>();
  for (const record of events) {
    levelCounts.set(record.level, (levelCounts.get(record.level) ?? 0) + 1);
    idCounts.set(record.eventId, (idCounts.get(record.eventId) ?? 0) + 1);
  }
  return {
    sourceMode: input.sourceMode,
    loadedRecordCount: input.loadedRecordCount,
    eventRecordCount: events.length,
    archiveTextRecordCount: input.sessionRecords.length - events.length,
    textLogEntryCount: input.textLogEntryCount,
    levelMix: LEVELS_MOST_SEVERE_FIRST.filter((level) => levelCounts.has(level)).map((level) => ({
      level,
      count: levelCounts.get(level) ?? 0,
    })),
    topEventIds: [...idCounts]
      .sort(([idA, a], [idB, b]) => b - a || idA - idB)
      .slice(0, REPORT_TOP_EVENT_IDS)
      .map(([eventId, count]) => ({ eventId, count })),
    distinctEventIdCount: idCounts.size,
    filters: input.filters,
  };
}

/** The filters in force, as typed fields: typed text is reported as "active", never as text. */
export function buildReportFilters(state: {
  filterLevels: ReadonlySet<EvtxLevel>;
  selectedChannels: ReadonlySet<string>;
  channelsHeld: number;
  filterEventIds: string;
  timeWindow: EvtxTimeWindow;
  timeRange: EvtxTimeRange | null;
  filterSearch: string;
  quickFilterActive: boolean;
  recordScopeKind: EvtxRecordScopeKind | null;
}): EventLogAnalysisReportFilters {
  const parsed = parseEventIdSelectors(state.filterEventIds);
  return {
    levels: LEVELS_MOST_SEVERE_FIRST.filter((level) => state.filterLevels.has(level)),
    channelsSelected: [...state.selectedChannels].sort().slice(0, REPORT_CHANNELS_CAP),
    channelsHeld: state.channelsHeld,
    eventIdSelectors: parsed.invalid
      ? []
      : parsed.selectors.flatMap((selector): EventLogAnalysisReportFilters["eventIdSelectors"] =>
          selector.kind === "single" && selector.id !== undefined
            ? [{ kind: "single" as const, id: selector.id }]
            : selector.kind === "range" && selector.low !== undefined && selector.high !== undefined
              ? [{ kind: "range" as const, low: selector.low, high: selector.high }]
              : [],
        ),
    timeWindow: state.timeWindow,
    timeRange: state.timeRange === null ? null : { ...state.timeRange },
    searchActive: state.filterSearch.trim().length > 0,
    quickFilterActive: state.quickFilterActive,
    recordScope: state.recordScopeKind,
  };
}

export function buildReportRequest(input: {
  sessionId: string;
  revision: number;
  generatedAtMs: number;
  coverageGaps: EvtxCoverageGap[];
  remoteMachine: string | null;
  scope: EventLogAnalysisReportScope;
  chains: EventLogAnalysisReportChains | null;
}): EventLogAnalysisReportRequest {
  const remote = input.remoteMachine?.trim() ?? "";
  return {
    sessionId: input.sessionId,
    expectedRevision: input.revision,
    generatedAtMs: input.generatedAtMs,
    coverageGaps: input.coverageGaps,
    remoteMachine: remote === "" ? null : remote,
    scope: input.scope,
    chains: input.chains,
  };
}

export type SaveReportOutcome =
  | { status: "saved"; path: string; characters: number }
  | { status: "cancelled" };

/**
 * Renders, asks where to save, then writes. A cancelled dialog writes nothing; a render or write
 * failure is thrown to the caller, never swallowed.
 */
export async function saveMarkdownReport(deps: {
  request: EventLogAnalysisReportRequest;
  render: (request: EventLogAnalysisReportRequest) => Promise<string>;
  chooseDestination: () => Promise<string | null>;
  write: (path: string, contents: string) => Promise<void>;
}): Promise<SaveReportOutcome> {
  const markdown = await deps.render(deps.request);
  const path = await deps.chooseDestination();
  if (!path) return { status: "cancelled" };
  await deps.write(path, markdown);
  return { status: "saved", path, characters: markdown.length };
}
