export type Severity = "Info" | "Warning" | "Error";
export type LogFormat = "Ccm" | "Simple" | "Plain" | "Timestamped";
export type ParserKind =
  | "ccm"
  | "simple"
  | "timestamped"
  | "plain"
  | "panther"
  | "cbs"
  | "dism"
  | "reportingEvents";
export type ParserImplementation =
  | "ccm"
  | "simple"
  | "genericTimestamped"
  | "reportingEvents"
  | "plainText";
export type ParserProvenance = "dedicated" | "heuristic" | "fallback";
export type ParseQuality = "structured" | "semiStructured" | "textFallback";
export type RecordFraming = "physicalLine" | "logicalRecord";
export type DateFieldOrder = "monthFirst" | "dayFirst";

export type LogSourceKind = "file" | "folder" | "known";
export type KnownSourcePathKind = "file" | "folder";
export type PlatformKind = "all" | "windows" | "macos" | "linux";
export type KnownSourceDefaultFileSelectionBehavior =
  | "none"
  | "preferFileName"
  | "preferFileNameThenPattern"
  | "preferPattern";

export type LogSource =
  | {
    kind: "file";
    path: string;
  }
  | {
    kind: "folder";
    path: string;
  }
  | {
    kind: "known";
    sourceId: string;
    defaultPath: string;
    pathKind: KnownSourcePathKind;
  };

export interface FolderEntry {
  name: string;
  path: string;
  isDir: boolean;
  sizeBytes: number | null;
  modifiedUnixMs: number | null;
}

export interface FolderListingResult {
  sourceKind: LogSourceKind;
  source: LogSource;
  entries: FolderEntry[];
}

export interface KnownSourceGroupingMetadata {
  familyId: string;
  familyLabel: string;
  groupId: string;
  groupLabel: string;
  groupOrder: number;
  sourceOrder: number;
}

export interface KnownSourceDefaultFileIntent {
  selectionBehavior: KnownSourceDefaultFileSelectionBehavior;
  preferredFileNames: string[];
}

export interface KnownSourceMetadata {
  id: string;
  label: string;
  description: string;
  platform: PlatformKind;
  sourceKind: LogSourceKind;
  source: LogSource;
  filePatterns: string[];
  grouping?: KnownSourceGroupingMetadata;
  defaultFileIntent?: KnownSourceDefaultFileIntent;
}

export interface LogEntry {
  id: number;
  lineNumber: number;
  message: string;
  component: string | null;
  timestamp: number | null;
  timestampDisplay: string | null;
  severity: Severity;
  thread: number | null;
  threadDisplay: string | null;
  sourceFile: string | null;
  format: LogFormat;
  filePath: string;
  timezoneOffset: number | null;
}

export interface ParserSelectionInfo {
  parser: ParserKind;
  implementation: ParserImplementation;
  provenance: ParserProvenance;
  parseQuality: ParseQuality;
  recordFraming: RecordFraming;
  dateOrder: DateFieldOrder | null;
}

export interface ParseResult {
  entries: LogEntry[];
  formatDetected: LogFormat;
  parserSelection: ParserSelectionInfo;
  totalLines: number;
  parseErrors: number;
  filePath: string;
  fileSize: number;
  byteOffset: number;
}

/** Payload emitted by the Rust tail watcher */
export interface TailPayload {
  entries: LogEntry[];
  filePath: string;
  parserSelection?: ParserSelectionInfo;
}