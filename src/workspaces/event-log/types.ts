export interface EvtxRecord {
  id: number;
  eventRecordId: number;
  timestamp: string;
  timestampEpoch: number;
  provider: string;
  channel: string;
  eventId: number;
  level: EvtxLevel;
  computer: string;
  message: string;
  eventData: EvtxField[];
  rawXml: string;
  sourceLabel: string;
  /** Provider-defined task grouping, absent when the event declares none. */
  task?: number | null;
  /** Operation within the task. */
  opcode?: number | null;
  /** Emitting process. */
  processId?: number | null;
  /** Emitting thread. */
  threadId?: number | null;
  /** Raw security identifier; not resolved to an account name. */
  userSid?: string | null;
  /** Keyword bitmask as written by the provider. */
  keywords?: string | null;
  /** Columns produced by an EvtxECmd map; empty when no map covers this event type. */
  mapped?: EvtxMappedColumn[];
}

export interface EvtxMappedColumn {
  property: string;
  text: string;
  /** False when the map referenced a field this event did not carry. */
  complete: boolean;
}

export interface EvtxField {
  name: string;
  value: string;
}

export type EvtxLevel = "Critical" | "Error" | "Warning" | "Information" | "Verbose";

export interface EvtxChannelInfo {
  name: string;
  eventCount: number;
  sourceType: "live" | { file: { path: string } };
}

export interface EvtxParseResult {
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  totalRecords: number;
  parseErrors: number;
  errorMessages: string[];
}

/**
 * How far back a live query reaches.
 *
 * Applied by the Event Log service as an XPath predicate, so events outside the window are never
 * fetched or rendered. This is the difference between a bounded query and a walk of every channel:
 * FullEventLogView filters time client-side, which is why its seven-day default is slow.
 */
export type EvtxTimeWindow = "1h" | "24h" | "7d" | "30d" | "all";

export const EVTX_TIME_WINDOW_MS: Record<Exclude<EvtxTimeWindow, "all">, number> = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

export const EVTX_TIME_WINDOW_LABELS: Record<EvtxTimeWindow, string> = {
  "1h": "Last hour",
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
  all: "All time",
};

/**
 * The subset of the backend's query filter this workspace currently sends.
 *
 * Deliberately not the whole contract. `cmtraceopen_parser::event_query::EventQueryFilter` also
 * carries `eventIds`, `eventIdMode`, `providerMode` and `keywords`, and its `TimeWindow` has a
 * `between` variant as well as `last`. The Rust struct is `#[serde(default)]`, so omitting them
 * deserializes to defaults and this works; what is absent is UI for them, not backend support.
 *
 * Named as a subset so nobody reads a missing field here as a capability the backend lacks.
 */
export interface EventQueryFilterSubset {
  time?: { kind: "last"; milliseconds: number };
  levels?: number[];
  providers?: string[];
}
