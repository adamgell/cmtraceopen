export interface EvtxRecord {
  id: number;
  eventRecordId: number;
  /** Lossless decimal EventRecordID emitted alongside the legacy numeric field. */
  eventRecordIdText?: string | null;
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
  /** Distinguishes archived text records from Windows event records. */
  originKind?: "event" | "log";
  /** Provider-defined task grouping, absent when the event declares none. */
  task?: number | null;
  /** Operation within the task. */
  opcode?: number | null;
  /** Emitting process. */
  processId?: number | null;
  /** Provider-declared correlation ActivityID. */
  activityId?: string | null;
  /** Provider-declared related ActivityID. */
  relatedActivityId?: string | null;
  /** Explicit session/device/user identity values from event XML/data. */
  sessionId?: string | null;
  deviceId?: string | null;
  userId?: string | null;
  /** Explicit process start evidence, paired with processId. */
  processStartTime?: string | null;
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
  sourceType: "live" | { remote: { machine: string } } | { file: { path: string } };
}

export type EvtxCoverageGapKind =
  | "unsupported"
  | "accessDenied"
  | "missing"
  | "invalidPattern"
  | "limitReached"
  | "empty"
  | "file"
  | "chunk"
  | "record"
  | "xml"
  | "provider"
  | "limit";

export interface EvtxCoverageGap {
  source: string;
  kind: EvtxCoverageGapKind;
  reason: string;
  chunkId?: number;
  eventRecordId?: number;
  /** Exact decimal u64 identity when the JSON number is outside JavaScript's safe range. */
  eventRecordIdText?: string;
}

export type EvtxArchiveMemberKind = "evtx" | "text" | "registry" | "binary";
export type EvtxArchiveMemberOutcome =
  | "parsed"
  | "unsupported"
  | "malformed"
  | "duplicate"
  | "limit";
export interface EvtxArchiveMember {
  path: string;
  kind: EvtxArchiveMemberKind;
  sha256?: string;
  outcome: EvtxArchiveMemberOutcome;
}
export interface EvtxParseResult {
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  totalRecords: number;
  parseErrors: number;
  errorMessages: string[];
  coverageGaps?: EvtxCoverageGap[];
  coverage?: EventLogSourceCoverage[];
  archiveMembers?: EvtxArchiveMember[];
}

export type EventLogSourceKind = "file" | "folder" | "wildcard" | "archive" | "vss";

export interface EventLogSourceSelection {
  path: string;
  kind: EventLogSourceKind;
}
export interface EventLogSourceManifestEntry {
  sourceId: string;
  path: string;
  kind: EventLogSourceKind;
}

export type EventLogSourceCoverage =
  | { kind: "unsupported"; path: string; reason: string }
  | { kind: "accessDenied"; path: string; reason: string }
  | { kind: "missing"; path: string; reason: string }
  | { kind: "empty"; path: string; reason: string }
  | { kind: "invalidPattern"; path: string; reason: string }
  | { kind: "limitReached"; path: string; reason: string };

export interface EventLogSourceManifest {
  entries: EventLogSourceManifestEntry[];
  coverage: EventLogSourceCoverage[];
}
export type EvtxLiveMode = "subscription" | "polling" | "mixed" | "unsupported";

export interface EvtxTailStatus {
  requestId: string;
  channel: string;
  mode: EvtxLiveMode;
  active: boolean;
  nextSequence: number;
  coverageGaps: string[];
}

export interface EvtxTailBatch {
  requestId: string;
  channel: string;
  sequence: number;
  mode: EvtxLiveMode;
  records: EvtxRecord[];
  coverageGaps: string[];
}

export type EvtxClearResult =
  | { status: "cleared" | "cancelled" | "empty"; channel: string }
  | { status: "denied" | "unavailable" | "unsupported"; channel: string; detail: string };


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
export type DiagnosisCoverageState =
  | "covered"
  | "unknown"
  | "absent"
  | "accessDenied"
  | "capped"
  | "skipped"
  | "unsupported"
  | "malformed"
  | "parseFailed";

export type DiagnosisFindingClass =
  | "confirmedFailure"
  | "likelyContributor"
  | "symptom"
  | "recovered"
  | "contradictoryEvidence"
  | "coverageGap"
  | "unknown";

export type DiagnosisFindingSeverity = "info" | "warning" | "error" | "critical";
export type DiagnosisFindingConfidence = "unknown" | "low" | "medium" | "high";

export interface DiagnosisIntuneEvidence {
  evidenceId: string;
  sourceArtifactId: string;
}

export interface DiagnosisSccmEvidence {
  artifactId: string;
  entryId: string;
  lineStart?: number | null;
  lineEnd?: number | null;
}

export interface DiagnosisTextLogEvidence {
  source: string;
  filePath: string;
  lineNumber: number;
  entryId: number;
}

export interface DiagnosisEventEvidence {
  source: string;
  provider: string;
  eventId: number;
  recordId: number;
  recordIdText?: string | null;
  fallbackIdentity?: string | null;
  machine?: string | null;
  channel?: string | null;
  activityId?: string | null;
}

export type DiagnosisEvidence =
  | { kind: "intune"; value: DiagnosisIntuneEvidence }
  | { kind: "esp"; value: DiagnosisIntuneEvidence }
  | { kind: "sccm"; value: DiagnosisSccmEvidence }
  | { kind: "dsregcmdRaw"; value: string }
  | { kind: "textLog"; value: DiagnosisTextLogEvidence }
  | { kind: "event"; value: DiagnosisEventEvidence };

export interface DiagnosisCoverageGap {
  id: string;
  source: string;
  state: DiagnosisCoverageState;
  detail: string;
  evidence: DiagnosisEvidence[];
}

export interface DiagnosisFinding {
  findingId: string;
  class: DiagnosisFindingClass;
  severity: DiagnosisFindingSeverity;
  confidence: DiagnosisFindingConfidence;
  title: string;
  summary: string;
  evidence: DiagnosisEvidence[];
  coverageGaps: DiagnosisCoverageGap[];
  recommendedChecks: string[];
}

export interface DiagnosisErrorToken {
  raw: string;
  decimal?: number | null;
  hex?: string | null;
  malformed: boolean;
  found: boolean;
  description?: string | null;
  category?: string | null;
}

export interface EventDiagnosis {
  evidence: DiagnosisEvidence[];
  family: "autopilot" | "esp" | "mdmEnrollment" | "configMgrClient" | "other";
  findings: DiagnosisFinding[];
  errorTokens: DiagnosisErrorToken[];
}

export type DiagnosisCorrelationBasis =
  | "exactIdentifier"
  | "candidateIdentifier"
  | "timestampOnly";
export type DiagnosisCorrelationStatus =
  | "exact"
  | "candidate"
  | "ambiguous"
  | "coverageBlocked"
  | "notCausal";

export interface DiagnosisCorrelationEvidence {
  originId: string;
  field: string;
  value: string;
}

export interface DiagnosisCorrelationEdge {
  left: string;
  right: string | null;
  basis: DiagnosisCorrelationBasis;
  status: DiagnosisCorrelationStatus;
  candidateIds: string[];
  evidence: DiagnosisCorrelationEvidence[];
}

export interface DiagnosisOverview {
  outcome:
    | "confirmedFailure"
    | "contradictoryEvidence"
    | "symptomsOnly"
    | "insufficientEvidence"
    | "noFindings";
  headline: string;
  findingCount: number;
  coverageGapCount: number;
  evidenceCount: number;
  correlationCount: number;
}

export interface DiagnosisSummary {
  findings: DiagnosisFinding[];
  evidence: DiagnosisEvidence[];
  coverageGaps: DiagnosisCoverageGap[];
  correlations: DiagnosisCorrelationEdge[];
  events: EventDiagnosis[];
  overview: DiagnosisOverview;
}
