import type { ParserSelectionInfo } from "./log";

export interface EvidenceBundleArtifactCounts {
  collected: number;
  missing: number;
  failed: number;
  skipped: number;
}

export interface EvidenceBundleMetadata {
  manifestPath: string;
  notesPath: string | null;
  evidenceRoot: string | null;
  primaryEntryPoints: string[];
  availablePrimaryEntryPoints: string[];
  bundleId: string | null;
  bundleLabel: string | null;
  createdUtc: string | null;
  caseReference: string | null;
  summary: string | null;
  collectorProfile: string | null;
  collectorVersion: string | null;
  collectedUtc: string | null;
  deviceName: string | null;
  primaryUser: string | null;
  platform: string | null;
  osVersion: string | null;
  tenant: string | null;
  artifactCounts: EvidenceBundleArtifactCounts | null;
}

export type EvidenceArtifactStatus =
  | "collected"
  | "missing"
  | "failed"
  | "skipped"
  | "unknown";

export interface EvidenceArtifactTimeCoverage {
  startUtc: string | null;
  endUtc: string | null;
}

export type EvidenceArtifactIntakeKind =
  | "log"
  | "registrySnapshot"
  | "eventLogExport"
  | "commandOutput"
  | "screenshot"
  | "export"
  | "unknown";

export type EvidenceArtifactIntakeStatus =
  | "recognized"
  | "generic"
  | "unsupported"
  | "missing";

export interface EvidenceArtifactIntake {
  kind: EvidenceArtifactIntakeKind;
  status: EvidenceArtifactIntakeStatus;
  recognizedAs: string | null;
  summary: string;
  parserSelection: ParserSelectionInfo | null;
  parseDiagnostics: EvidenceArtifactParseDiagnostics | null;
}

export interface EvidenceArtifactParseDiagnostics {
  totalLines: number;
  entryCount: number;
  parseErrors: number;
  cleanParse: boolean;
}

export interface RegistrySnapshotValuePreview {
  name: string;
  valueType: string;
  value: string;
}

export interface RegistrySnapshotKeyPreview {
  path: string;
  valueCount: number;
  values: RegistrySnapshotValuePreview[];
}

export interface RegistrySnapshotSummary {
  keyCount: number;
  valueCount: number;
  keys: RegistrySnapshotKeyPreview[];
}

export interface EvidenceEventLogExportPreview {
  channel: string | null;
  fileSizeBytes: number | null;
  modifiedUnixMs: number | null;
  exportFormat: string;
}

export interface EvidenceArtifactPreview {
  path: string;
  intakeKind: EvidenceArtifactIntakeKind;
  summary: string;
  registrySnapshot: RegistrySnapshotSummary | null;
  eventLogExport: EvidenceEventLogExportPreview | null;
}

export interface EvidenceArtifactRecord {
  artifactId: string | null;
  category: string;
  family: string | null;
  relativePath: string;
  absolutePath: string | null;
  originPath: string | null;
  collectedUtc: string | null;
  status: EvidenceArtifactStatus;
  parseHints: string[];
  notes: string | null;
  timeCoverage: EvidenceArtifactTimeCoverage | null;
  sha256: string | null;
  existsOnDisk: boolean;
  intake: EvidenceArtifactIntake;
}

export interface ExpectedEvidenceRecord {
  category: string;
  relativePath: string;
  required: boolean;
  reason: string | null;
  available: boolean;
}

export interface EvidenceBundleDetails {
  bundleRootPath: string;
  metadata: EvidenceBundleMetadata;
  manifestContent: string;
  notesContent: string | null;
  artifacts: EvidenceArtifactRecord[];
  expectedEvidence: ExpectedEvidenceRecord[];
  observedGaps: string[];
  priorityQuestions: string[];
  handoffSummary: string | null;
}