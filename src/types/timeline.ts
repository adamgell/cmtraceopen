import type { LogEntry, ParserKind } from "./log";
import type { IntuneEvent } from "../workspaces/intune/types";

export type SignalKind = "errorSeverity" | "knownErrorCode" | "imeFailed";

/**
 * Mirrors Rust `TimelineSourceKind` in `src-tauri/src/timeline/models.rs`.
 *
 * The enum uses the default (externally-tagged) serde representation; the
 * variant names are renamed to camelCase and `LogFile` carries an inner
 * `#[serde(rename_all = "camelCase")]` so its field also camelCases.
 */
export type TimelineSourceKind =
  | { logFile: { parserKind: ParserKind } }
  | "intuneEvents";

export interface TimelineSourceMeta {
  idx: number;
  kind: TimelineSourceKind;
  path: string;
  displayName: string;
  color: string;
  entryCount: number;
}

export interface Incident {
  id: number;
  tsStartMs: number;
  tsEndMs: number;
  signalCount: number;
  sourceCount: number;
  confidence: number;
  anchorEventRef?: [number, number];
  anchorGuid?: string;
  summary: string;
}

export interface TimelineTunables {
  overlapWindowMs: number;
  minSourceCount: number;
  maxIncidentSpanMs: number;
  enabledSignalKinds: SignalKind[];
}

export interface SourceError {
  path: string;
  message: string;
}

export interface TimelineBundle {
  id: string;
  sources: TimelineSourceMeta[];
  timeRangeMs: [number, number];
  totalEntries: number;
  incidents: Incident[];
  deniedGuids: string[];
  errors: SourceError[];
  tunables: TimelineTunables;
}

export interface LaneBucket {
  sourceIdx: number;
  tsStartMs: number;
  tsEndMs: number;
  totalCount: number;
  errorCount: number;
  warnCount: number;
}

export type TimelineEntry =
  | { kind: "log"; sourceIdx: number; entry: LogEntry }
  | { kind: "imeEvent"; sourceIdx: number; event: IntuneEvent };

export interface IncidentSignalDetail {
  sourceIdx: number;
  sourceName: string;
  tsMs: number;
  kind: SignalKind;
  correlationId?: string;
  lineNumber: number;
  preview: string;
}

export interface IncidentDetail {
  incident: Incident;
  signals: IncidentSignalDetail[];
  perSourceSignalCounts: Record<string, number>;
}

/**
 * Mirrors Rust `TimelineError` (tagged union via `#[serde(tag = "kind", rename_all = "camelCase")]`).
 */
export type TimelineError =
  | { kind: "notFound"; id: string }
  | { kind: "tooLarge"; estimated: number; limit: number }
  | { kind: "noSources" }
  | { kind: "sourceRead"; path: string; message: string }
  | { kind: "internal"; message: string };
