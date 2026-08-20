import { invoke } from "@tauri-apps/api/core";
import type {
  AggregateParseResult,
  FolderListingResult,
  KnownSourceMetadata,
  LogEntry,
  LogFormat,
  LogSource,
  ParseResult,
  WorkspaceId,
} from "../types/log";
import type {
  DiagnosisCorrelationEdge,
  DiagnosisCoverageGap,
  DiagnosisErrorToken,
  DiagnosisEvidence,
  DiagnosisFinding,
  DiagnosisSummary,
  EventDiagnosis,
  EventLogSourceCoverage,
  EventLogSourceKind,
  EventLogSourceManifest,
  EventLogSourceManifestEntry,
  EventLogSourceSelection,
  DiagnosisOverview,
  EvtxCoverageGap,
  EvtxParseResult,
  EvtxRecord,
} from "../workspaces/event-log/types";
import type { UnifiedTimeline } from "../workspaces/event-log/unified-timeline";
import type {
  EvidenceArtifactPreview,
  EvidenceBundleDetails,
  EvidenceArtifactIntakeKind,
} from "../types/evidence";
import type { RegistryParseResult } from "../types/registry";
import {
  isSourceOperation,
  recordAccessDenied,
  type AccessDeniedClassification,
} from "./source-error";
import type {
  AppElevationState,
  ElevationRequest,
  RelaunchResult,
  RestoreTicket,
} from "../types/elevation";
import type { IntuneAnalysisResult } from "../workspaces/intune/types";
import type { SysmonAnalysisResult } from "../workspaces/sysmon/types";
import type {
  DsregcmdAnalysisResult,
  DsregcmdCaptureResult,
  DsregcmdResolvedSource,
} from "../workspaces/dsregcmd/types";
import type {
  EspAppFlipBackup,
  EspAppFlipResult,
  EspDiagnosticsSnapshot,
  EspElevationState,
  EspGraphOverlay,
  EspGraphRequest,
  EspRelaunchResult,
  EspSessionEnvelope,
} from "../workspaces/esp-diagnostics/types";
import type { EspSessionCaptureMeta } from "../workspaces/esp-diagnostics/esp-session-capture";
import type {
  SccmCaptureResult,
  SccmAdvancedCaptureAuthorizationRequest,
  SccmAdvancedCaptureCapability,
  SccmEnvironmentDiscovery,
} from "../workspaces/sccm/types";
import type { Marker, MarkerCategory, MarkerFile } from "../types/markers";

export interface FileAssociationPromptStatus {
  supported: boolean;
  shouldPrompt: boolean;
  isAssociated: boolean;
}

export interface SystemDateTimePreferences {
  datePattern: string;
  timePattern: string;
  amDesignator: string | null;
  pmDesignator: string | null;
}

export interface AnalyzeIntuneLogsOptions {
  includeLiveEventLogs?: boolean;
}

export interface UpdatePolicy {
  updateChecksDisabledByPolicy: boolean;
}

const normalizedCommandErrorMessages = new WeakMap<Error, string>();

/**
 * True only for plain data objects — those whose prototype is `Object.prototype`
 * or `null`. Serialized Rust command errors (e.g. `{ kind, path, message }`)
 * arrive this way, whereas class instances (`Error`, custom classes) do not and
 * must keep falling back. The prototype probe is wrapped so a hostile Proxy that
 * traps `getPrototypeOf` and throws is contained rather than allowed to escape.
 */
function isPlainDataObject(error: object): boolean {
  let prototype: unknown;
  try {
    prototype = Object.getPrototypeOf(error);
  } catch {
    return false;
  }
  return prototype === Object.prototype || prototype === null;
}

/**
 * Reads an own string DATA property without ever invoking a getter.
 *
 * Accessor descriptors (a `get`/`set`) are ignored outright, so a hostile
 * `message` getter is never called. A forged data descriptor — e.g. a Proxy
 * `getOwnPropertyDescriptor` trap that fabricates a value — is rejected unless a
 * direct read of the same own property agrees; a genuine plain data object
 * always agrees, and the direct read cannot trigger a getter because accessor
 * descriptors were already discarded.
 */
function readOwnStringData(error: object, key: string): string | null {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(error, key);
  } catch {
    return null;
  }
  if (
    !descriptor ||
    typeof descriptor.get === "function" ||
    typeof descriptor.set === "function"
  ) {
    return null;
  }
  const value = descriptor.value;
  if (typeof value !== "string") {
    return null;
  }
  let directValue: unknown;
  try {
    directValue = (error as Record<string, unknown>)[key];
  } catch {
    return null;
  }
  if (directValue !== value) {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/** Turns a Rust error `kind` identifier (e.g. `sourceNotFound`) into a readable phrase. */
function humanizeErrorKind(kind: string): string {
  const spaced = kind
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (spaced.length === 0) {
    return kind;
  }
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

interface CommandRejectionInfo {
  message: string;
  accessDenied: AccessDeniedClassification | null;
}

/**
 * Extracts the backend reason and any Access Denied verdict in a single pass.
 *
 * Message and classification are read together, and the prototype is probed
 * exactly once, because every probe is another chance for a hostile Proxy trap
 * to run. Splitting this into two functions doubled the trap count.
 *
 * Returns a null message for anything that is not a plain data object so the
 * caller keeps the safe fallback.
 */
function inspectPlainDataError(error: object): {
  message: string | null;
  accessDenied: AccessDeniedClassification | null;
} {
  if (!isPlainDataObject(error)) {
    return { message: null, accessDenied: null };
  }

  const kind = readOwnStringData(error, "kind");
  const message = readOwnStringData(error, "message");

  // Every field must be present and valid. A partially-formed payload yields no
  // verdict rather than a half-trusted one, because the only thing a verdict is
  // used for is deciding whether to offer a UAC prompt.
  let accessDenied: AccessDeniedClassification | null = null;
  if (kind === "accessDenied" && message !== null) {
    const operation = readOwnStringData(error, "operation");
    if (isSourceOperation(operation)) {
      accessDenied = {
        kind: "accessDenied",
        operation,
        path: readOwnStringData(error, "path"),
        message,
      };
    }
  }

  if (message !== null) {
    return { message, accessDenied };
  }
  if (kind !== null) {
    return { message: humanizeErrorKind(kind), accessDenied };
  }
  return { message: null, accessDenied };
}

/**
 * Resolves a rejection to displayable text plus any structured verdict.
 *
 * Shared by `getSafeErrorMessage` and the command normalizer so both agree on
 * what a rejection means and neither inspects the value twice.
 */
function inspectCommandRejection(
  error: unknown,
  fallback: string,
): CommandRejectionInfo {
  if (typeof error === "string") {
    return { message: error.trim() || fallback, accessDenied: null };
  }

  if (
    (typeof error === "object" && error !== null) ||
    typeof error === "function"
  ) {
    // Trusted, self-normalized command errors are recorded by exact identity;
    // this WeakMap channel cannot invoke Proxy traps.
    const trusted = normalizedCommandErrorMessages.get(error as Error);
    if (trusted !== undefined) {
      return { message: trusted, accessDenied: null };
    }

    // Serialized Rust command errors arrive as plain data objects. Surface their
    // precise reason while keeping the hostile-Proxy protection intact: only
    // plain-prototype objects are inspected, no getter is ever invoked, and a
    // forged descriptor value is rejected. Class instances, functions, Proxies,
    // and accessor-only objects fall through to the safe fallback.
    if (typeof error === "object") {
      const info = inspectPlainDataError(error);
      if (info.message !== null) {
        return { message: info.message, accessDenied: info.accessDenied };
      }
      return { message: fallback, accessDenied: info.accessDenied };
    }

    return { message: fallback, accessDenied: null };
  }

  return { message: fallback, accessDenied: null };
}

export function getSafeErrorMessage(
  error: unknown,
  fallback = "The operation failed.",
): string {
  return inspectCommandRejection(error, fallback).message;
}

function normalizeCommandInvokeError(
  commandName: string,
  error: unknown,
): Error {
  const { message, accessDenied } = inspectCommandRejection(
    error,
    `Command '${commandName}' failed.`,
  );
  const missingCommandPattern = new RegExp(
    `command\\s+${commandName}\\s+not found`,
    "i",
  );

  let normalizedMessage = message;
  if (missingCommandPattern.test(message)) {
    normalizedMessage = `The running desktop backend does not expose '${commandName}'. Restart CMTrace Open so the frontend and Tauri backend are on the same build.`;
  }

  const normalizedError = new Error(normalizedMessage);
  normalizedCommandErrorMessages.set(normalizedError, normalizedMessage);

  // Carry a confirmed permission refusal across the normalization boundary.
  // Every consumer still sees a plain Error with the same message it always had;
  // only callers that explicitly ask get the structured verdict.
  if (accessDenied) {
    recordAccessDenied(normalizedError, accessDenied);
  }

  return normalizedError;
}

async function invokeCommand<T>(
  commandName: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invoke<T>(commandName, args);
  } catch (error) {
    throw normalizeCommandInvokeError(commandName, error);
  }
}
function isMarkerObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isMarkerString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isMarkerTimestamp(value: unknown): value is string {
  if (!isMarkerString(value)) return false;
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.exec(
      value,
    );
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] =
    match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(hour, minute, second, 0);
  return (
    calendar.getUTCFullYear() === year &&
    calendar.getUTCMonth() === month - 1 &&
    calendar.getUTCDate() === day &&
    calendar.getUTCHours() === hour &&
    calendar.getUTCMinutes() === minute &&
    calendar.getUTCSeconds() === second &&
    Number.isFinite(Date.parse(value))
  );
}

function decodeMarker(value: unknown): Marker {
  if (
    !isMarkerObject(value) ||
    typeof value.lineId !== "number" ||
    !Number.isSafeInteger(value.lineId) ||
    value.lineId < 0 ||
    (value.identity !== undefined && !isMarkerString(value.identity)) ||
    !isMarkerString(value.category) ||
    !isMarkerString(value.color) ||
    !isMarkerTimestamp(value.added)
  ) {
    throw new Error("load_markers returned an invalid marker");
  }
  return {
    lineId: value.lineId,
    ...(value.identity === undefined ? {} : { identity: value.identity }),
    category: value.category,
    color: value.color,
    added: value.added,
  };
}

function decodeMarkerCategory(value: unknown): MarkerCategory {
  if (
    !isMarkerObject(value) ||
    !isMarkerString(value.id) ||
    !isMarkerString(value.label) ||
    !isMarkerString(value.color)
  ) {
    throw new Error("load_markers returned an invalid marker category");
  }
  return {
    id: value.id,
    label: value.label,
    color: value.color,
  };
}

function decodeMarkerFile(value: unknown): MarkerFile | null {
  if (value === null) return null;
  if (
    !isMarkerObject(value) ||
    typeof value.version !== "number" ||
    !Number.isFinite(value.version) ||
    !Number.isInteger(value.version) ||
    !isMarkerString(value.sourcePath) ||
    typeof value.sourceSize !== "number" ||
    !Number.isSafeInteger(value.sourceSize) ||
    value.sourceSize < 0 ||
    !isMarkerTimestamp(value.created) ||
    !isMarkerTimestamp(value.modified) ||
    !Array.isArray(value.markers) ||
    !Array.isArray(value.categories)
  ) {
    throw new Error("load_markers returned an invalid marker file");
  }
  const markers = value.markers.map(decodeMarker);
  const categories = value.categories.map(decodeMarkerCategory);
  return {
    version: value.version,
    sourcePath: value.sourcePath,
    sourceSize: value.sourceSize,
    created: value.created,
    modified: value.modified,
    markers,
    categories,
  };
}

export async function loadMarkerFile(
  filePath: string,
): Promise<MarkerFile | null> {
  return decodeMarkerFile(
    await invokeCommand<unknown>("load_markers", { filePath }),
  );
}

export async function openLogFile(path: string): Promise<ParseResult> {
  return invokeCommand<ParseResult>("open_log_file", { path });
}

/** Parse multiple files in parallel on the Rust side (Rayon thread pool).
 *  Returns all results in a single IPC response — eliminates N-1 round-trips. */
export async function parseFilesBatch(paths: string[]): Promise<ParseResult[]> {
  return invokeCommand<ParseResult[]>("parse_files_batch", { paths });
}

export async function listLogFolder(
  path: string,
): Promise<FolderListingResult> {
  return invokeCommand<FolderListingResult>("list_log_folder", { path });
}

const EVENT_LOG_SOURCE_KINDS: readonly EventLogSourceKind[] = [
  "file",
  "folder",
  "wildcard",
  "archive",
  "vss",
];
const EVENT_LOG_SOURCE_COVERAGE_KINDS: readonly EventLogSourceCoverage["kind"][] =
  [
    "unsupported",
    "accessDenied",
    "missing",
    "empty",
    "invalidPattern",
    "limitReached",
  ];

function isManifestEntry(value: unknown): value is EventLogSourceManifestEntry {
  if (typeof value !== "object" || value === null) return false;
  const entry = value as Partial<EventLogSourceManifestEntry>;
  return (
    typeof entry.sourceId === "string" &&
    typeof entry.path === "string" &&
    typeof entry.kind === "string" &&
    EVENT_LOG_SOURCE_KINDS.includes(entry.kind as EventLogSourceKind)
  );
}

function isSourceCoverage(value: unknown): value is EventLogSourceCoverage {
  if (typeof value !== "object" || value === null) return false;
  const coverage = value as Partial<EventLogSourceCoverage>;
  return (
    typeof coverage.path === "string" &&
    typeof coverage.reason === "string" &&
    typeof coverage.kind === "string" &&
    EVENT_LOG_SOURCE_COVERAGE_KINDS.includes(
      coverage.kind as EventLogSourceCoverage["kind"],
    )
  );
}

function assertEventLogSourceManifest(
  value: unknown,
): asserts value is EventLogSourceManifest {
  if (typeof value !== "object" || value === null) {
    throw new Error("the event log reader returned an invalid source manifest");
  }
  const manifest = value as Partial<EventLogSourceManifest>;

  if (!Array.isArray(manifest.entries)) {
    throw new Error(
      "the event log reader returned an invalid source manifest entries list",
    );
  }
  const invalidEntryIndex = manifest.entries.findIndex(
    (entry) => !isManifestEntry(entry),
  );
  if (invalidEntryIndex >= 0) {
    throw new Error(
      `the event log reader returned an invalid source manifest entry at index ${invalidEntryIndex}`,
    );
  }

  if (!Array.isArray(manifest.coverage)) {
    throw new Error(
      "the event log reader returned an invalid source manifest coverage list",
    );
  }
  const invalidCoverageIndex = manifest.coverage.findIndex(
    (coverage) => !isSourceCoverage(coverage),
  );
  if (invalidCoverageIndex >= 0) {
    throw new Error(
      `the event log reader returned an invalid source manifest coverage at index ${invalidCoverageIndex}`,
    );
  }
}

export async function expandEventLogSources(
  sources: EventLogSourceSelection[],
): Promise<EventLogSourceManifest> {
  const manifest = await invokeCommand<unknown>("evtx_expand_sources", {
    sources,
  });
  assertEventLogSourceManifest(manifest);
  return manifest;
}

export async function parseEventLogManifest(
  manifest: EventLogSourceManifest,
): Promise<EvtxParseResult> {
  return invokeCommand<EvtxParseResult>("evtx_parse_manifest", { manifest });
}
const DIAGNOSIS_COVERAGE_STATES = new Set([
  "covered",
  "unknown",
  "absent",
  "accessDenied",
  "capped",
  "skipped",
  "unsupported",
  "malformed",
  "parseFailed",
]);
const DIAGNOSIS_FINDING_CLASSES = new Set([
  "confirmedFailure",
  "likelyContributor",
  "symptom",
  "recovered",
  "contradictoryEvidence",
  "coverageGap",
  "unknown",
]);
const DIAGNOSIS_FINDING_SEVERITIES = new Set([
  "info",
  "warning",
  "error",
  "critical",
]);
const DIAGNOSIS_FINDING_CONFIDENCES = new Set([
  "unknown",
  "low",
  "medium",
  "high",
]);
const DIAGNOSIS_EVENT_FAMILIES = new Set([
  "autopilot",
  "esp",
  "mdmEnrollment",
  "configMgrClient",
  "other",
]);
const DIAGNOSIS_OVERVIEW_OUTCOMES = new Set([
  "confirmedFailure",
  "contradictoryEvidence",
  "symptomsOnly",
  "insufficientEvidence",
  "noFindings",
]);
const DIAGNOSIS_CORRELATION_BASES = new Set([
  "exactIdentifier",
  "candidateIdentifier",
  "timestampOnly",
]);
const DIAGNOSIS_CORRELATION_STATUSES = new Set([
  "exact",
  "candidate",
  "ambiguous",
  "coverageBlocked",
  "notCausal",
]);

const MAX_DIAGNOSIS_U64 = 18_446_744_073_709_551_615n;

function isDiagnosisRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isDiagnosisIdentityString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isDiagnosisU64Number(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    value >= 0
  );
}

function isDiagnosisInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value >= 0;
}
function isDiagnosisEvidence(value: unknown): value is DiagnosisEvidence {
  if (!isDiagnosisRecord(value) || typeof value.kind !== "string") return false;
  if (value.kind === "dsregcmdRaw") {
    return isDiagnosisIdentityString(value.value);
  }
  if (!isDiagnosisRecord(value.value)) return false;
  const evidence = value.value;
  switch (value.kind) {
    case "intune":
    case "esp":
      return (
        isDiagnosisIdentityString(evidence.evidenceId) &&
        isDiagnosisIdentityString(evidence.sourceArtifactId)
      );
    case "sccm":
      return (
        isDiagnosisIdentityString(evidence.artifactId) &&
        isDiagnosisIdentityString(evidence.entryId)
      );
    case "textLog":
      return (
        isDiagnosisIdentityString(evidence.source) &&
        isDiagnosisIdentityString(evidence.filePath) &&
        isDiagnosisInteger(evidence.lineNumber) &&
        evidence.lineNumber > 0 &&
        isDiagnosisInteger(evidence.entryId)
      );
    case "event": {
      if (
        !isDiagnosisIdentityString(evidence.source) ||
        !isDiagnosisIdentityString(evidence.provider) ||
        !isDiagnosisInteger(evidence.eventId) ||
        !isDiagnosisU64Number(evidence.recordId)
      ) {
        return false;
      }
      const recordIdText = evidence.recordIdText;
      let normalizedRecordIdText: string | null = null;
      if (recordIdText !== undefined && recordIdText !== null) {
        if (
          !isDiagnosisIdentityString(recordIdText) ||
          !/^\d+$/.test(recordIdText.trim())
        ) {
          return false;
        }
        normalizedRecordIdText = recordIdText.trim();
        const numericRecordIdIsSafe = Number.isSafeInteger(evidence.recordId);
        const parsedRecordIdText = BigInt(normalizedRecordIdText);
        if (parsedRecordIdText > MAX_DIAGNOSIS_U64) {
          return false;
        }
        if (
          numericRecordIdIsSafe &&
          parsedRecordIdText !== BigInt(evidence.recordId)
        ) {
          return false;
        }
        if (
          !numericRecordIdIsSafe &&
          evidence.recordId !== Number(parsedRecordIdText)
        ) {
          return false;
        }
      } else if (!Number.isSafeInteger(evidence.recordId)) {
        return false;
      }
      return (
        (normalizedRecordIdText !== null
          ? !/^0+$/.test(normalizedRecordIdText)
          : evidence.recordId > 0) ||
        isDiagnosisIdentityString(evidence.fallbackIdentity)
      );
    }
    default:
      return false;
  }
}

function isDiagnosisEvidenceArray(
  value: unknown,
): value is DiagnosisEvidence[] {
  return Array.isArray(value) && value.every(isDiagnosisEvidence);
}

function isOptionalNullableString(value: unknown): boolean {
  return value === undefined || value === null || typeof value === "string";
}

function isOptionalNullableNumber(value: unknown): boolean {
  return (
    value === undefined ||
    value === null ||
    (typeof value === "number" && Number.isSafeInteger(value))
  );
}

function isDiagnosisCoverageGap(value: unknown): value is DiagnosisCoverageGap {
  if (!isDiagnosisRecord(value)) return false;
  return (
    isDiagnosisIdentityString(value.id) &&
    isDiagnosisIdentityString(value.source) &&
    typeof value.state === "string" &&
    DIAGNOSIS_COVERAGE_STATES.has(value.state) &&
    isDiagnosisIdentityString(value.detail) &&
    isDiagnosisEvidenceArray(value.evidence)
  );
}

function isDiagnosisFinding(value: unknown): value is DiagnosisFinding {
  if (
    !isDiagnosisRecord(value) ||
    !isDiagnosisEvidenceArray(value.evidence) ||
    !Array.isArray(value.coverageGaps)
  ) {
    return false;
  }
  const evidence = Array.isArray(value.evidence) ? value.evidence : [];
  const coverageGaps = Array.isArray(value.coverageGaps)
    ? value.coverageGaps
    : [];
  const hasSupportingData =
    value.class === "coverageGap"
      ? coverageGaps.length > 0
      : evidence.length > 0;
  return (
    isDiagnosisIdentityString(value.findingId) &&
    typeof value.class === "string" &&
    DIAGNOSIS_FINDING_CLASSES.has(value.class) &&
    typeof value.severity === "string" &&
    DIAGNOSIS_FINDING_SEVERITIES.has(value.severity) &&
    typeof value.confidence === "string" &&
    DIAGNOSIS_FINDING_CONFIDENCES.has(value.confidence) &&
    isDiagnosisIdentityString(value.title) &&
    typeof value.summary === "string" &&
    hasSupportingData &&
    value.coverageGaps.every(isDiagnosisCoverageGap) &&
    isStringArray(value.recommendedChecks)
  );
}

function isDiagnosisErrorToken(value: unknown): value is DiagnosisErrorToken {
  if (!isDiagnosisRecord(value)) return false;
  return (
    isDiagnosisIdentityString(value.raw) &&
    isOptionalNullableNumber(value.decimal) &&
    isOptionalNullableString(value.hex) &&
    typeof value.malformed === "boolean" &&
    typeof value.found === "boolean" &&
    isOptionalNullableString(value.description) &&
    isOptionalNullableString(value.category)
  );
}

function isDiagnosisEvent(value: unknown): value is EventDiagnosis {
  if (!isDiagnosisRecord(value)) return false;
  const evidence = value.evidence;
  const findings = value.findings;
  const errorTokens = value.errorTokens;
  return (
    isDiagnosisEvidenceArray(evidence) &&
    Array.isArray(evidence) &&
    evidence.length > 0 &&
    typeof value.family === "string" &&
    DIAGNOSIS_EVENT_FAMILIES.has(value.family) &&
    Array.isArray(findings) &&
    findings.every(isDiagnosisFinding) &&
    Array.isArray(errorTokens) &&
    errorTokens.every(isDiagnosisErrorToken)
  );
}

function isDiagnosisCorrelation(
  value: unknown,
): value is DiagnosisCorrelationEdge {
  if (!isDiagnosisRecord(value)) return false;
  return (
    isDiagnosisIdentityString(value.left) &&
    (value.right === null || isDiagnosisIdentityString(value.right)) &&
    typeof value.basis === "string" &&
    DIAGNOSIS_CORRELATION_BASES.has(value.basis) &&
    typeof value.status === "string" &&
    DIAGNOSIS_CORRELATION_STATUSES.has(value.status) &&
    isStringArray(value.candidateIds) &&
    value.candidateIds.every(isDiagnosisIdentityString) &&
    Array.isArray(value.evidence) &&
    value.evidence.every(
      (item) =>
        isDiagnosisRecord(item) &&
        isDiagnosisIdentityString(item.originId) &&
        isDiagnosisIdentityString(item.field) &&
        isDiagnosisIdentityString(item.value),
    )
  );
}

function isDiagnosisOverview(value: unknown): value is DiagnosisOverview {
  if (!isDiagnosisRecord(value)) return false;
  const count = (candidate: unknown): candidate is number =>
    typeof candidate === "number" &&
    Number.isSafeInteger(candidate) &&
    candidate >= 0;
  return (
    typeof value.outcome === "string" &&
    DIAGNOSIS_OVERVIEW_OUTCOMES.has(value.outcome) &&
    isDiagnosisIdentityString(value.headline) &&
    count(value.findingCount) &&
    count(value.coverageGapCount) &&
    count(value.evidenceCount) &&
    count(value.correlationCount)
  );
}

function isDiagnosisSummary(value: unknown): value is DiagnosisSummary {
  if (!isDiagnosisRecord(value)) return false;
  const { findings, evidence, coverageGaps, correlations, events, overview } =
    value;
  if (
    !Array.isArray(findings) ||
    !findings.every(isDiagnosisFinding) ||
    !isDiagnosisEvidenceArray(evidence) ||
    !Array.isArray(coverageGaps) ||
    !coverageGaps.every(isDiagnosisCoverageGap) ||
    !Array.isArray(correlations) ||
    !correlations.every(isDiagnosisCorrelation) ||
    !Array.isArray(events) ||
    !events.every(isDiagnosisEvent) ||
    !isDiagnosisOverview(overview)
  ) {
    return false;
  }
  return (
    overview.findingCount === findings.length &&
    overview.coverageGapCount === coverageGaps.length &&
    overview.evidenceCount === evidence.length &&
    overview.correlationCount === correlations.length
  );
}

function decodeDiagnosisSummary(
  value: unknown,
  commandName: string,
): DiagnosisSummary {
  if (!isDiagnosisSummary(value)) {
    throw new Error(`Command '${commandName}' returned an invalid response.`);
  }
  return value;
}

type DiagnosisTransportRecord = Omit<EvtxRecord, "eventRecordId"> & {
  eventRecordId: number;
};

// Keep an unsafe numeric ID in the u64 transport range while the optional text field carries its
// exact identity (or its malformed decimal text) for Rust diagnosis validation.
const DIAGNOSIS_UNSAFE_EVENT_RECORD_ID_FALLBACK = Number.MAX_SAFE_INTEGER + 1;

function diagnosisRecordForTransport(
  record: EvtxRecord,
): DiagnosisTransportRecord {
  const numericId = record.eventRecordId;
  if (
    typeof numericId !== "number" ||
    !Number.isFinite(numericId) ||
    !Number.isInteger(numericId) ||
    numericId < 0
  ) {
    throw new Error("EventRecordID must be a non-negative integer.");
  }
  const textId = record.eventRecordIdText?.trim() ?? "";
  const textIsDecimal = textId.length > 0 && /^\d+$/.test(textId);
  const decimalText = textIsDecimal ? BigInt(textId) : null;
  if (
    decimalText !== null &&
    !Number.isSafeInteger(numericId) &&
    decimalText <= BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error(
      "EventRecordID text must preserve an unsafe numeric identity.",
    );
  }
  const eventRecordId = Number.isSafeInteger(numericId)
    ? numericId
    : DIAGNOSIS_UNSAFE_EVENT_RECORD_ID_FALLBACK;
  return { ...record, eventRecordId };
}

function transportDiagnosisRecords(
  records: EvtxRecord[],
): DiagnosisTransportRecord[] {
  return records.map(diagnosisRecordForTransport);
}

export async function diagnoseEventRecords(
  records: EvtxRecord[],
  coverageGaps: EvtxCoverageGap[] = [],
  timeline?: UnifiedTimeline,
  textEntries: LogEntry[] = [],
): Promise<DiagnosisSummary> {
  const commandName = "evtx_diagnose_records";
  return decodeDiagnosisSummary(
    await invokeCommand<unknown>(commandName, {
      records: transportDiagnosisRecords(records),
      coverageGaps,
      timeline: timeline ?? null,
      textEntries,
    }),
    commandName,
  );
}

export async function inspectEvidenceBundle(
  path: string,
): Promise<EvidenceBundleDetails> {
  return invokeCommand<EvidenceBundleDetails>("inspect_evidence_bundle", {
    path,
  });
}

export async function inspectEvidenceArtifact(
  path: string,
  intakeKind: EvidenceArtifactIntakeKind,
  originPath?: string | null,
): Promise<EvidenceArtifactPreview> {
  return invokeCommand<EvidenceArtifactPreview>("inspect_evidence_artifact", {
    path,
    intakeKind,
    originPath: originPath ?? null,
  });
}

export async function parseRegistryFile(
  path: string,
): Promise<RegistryParseResult> {
  return invokeCommand<RegistryParseResult>("parse_registry_file", { path });
}

export async function getKnownLogSources(): Promise<KnownSourceMetadata[]> {
  return invokeCommand<KnownSourceMetadata[]>("get_known_log_sources");
}

export async function openLogSourceFile(
  source: LogSource,
): Promise<ParseResult> {
  if (source.kind === "file") {
    return openLogFile(source.path);
  }

  if (source.kind === "known" && source.pathKind === "file") {
    return openLogFile(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a single file path.`,
  );
}

export async function listLogSourceFolder(
  source: LogSource,
): Promise<FolderListingResult> {
  if (source.kind === "folder") {
    return listLogFolder(source.path);
  }

  if (source.kind === "known" && source.pathKind === "folder") {
    return listLogFolder(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a folder path.`,
  );
}

export async function openLogFolderAggregate(
  path: string,
): Promise<AggregateParseResult> {
  return invokeCommand<AggregateParseResult>("open_log_folder_aggregate", {
    path,
  });
}

export async function openLogSourceFolderAggregate(
  source: LogSource,
): Promise<AggregateParseResult> {
  if (source.kind === "folder") {
    return openLogFolderAggregate(source.path);
  }

  if (source.kind === "known" && source.pathKind === "folder") {
    return openLogFolderAggregate(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a folder path.`,
  );
}

export async function startTail(
  path: string,
  format: LogFormat,
  byteOffset: number,
  nextId: number,
  nextLine: number,
): Promise<void> {
  return invokeCommand<void>("start_tail", {
    path,
    format,
    byteOffset,
    nextId,
    nextLine,
  });
}

export async function stopTail(path: string): Promise<void> {
  return invokeCommand<void>("stop_tail", { path });
}

export async function pauseTail(path: string): Promise<void> {
  return invokeCommand<void>("pause_tail", { path });
}

export async function resumeTail(path: string): Promise<void> {
  return invokeCommand<void>("resume_tail", { path });
}

export async function analyzeIntuneLogs(
  path: string,
  requestId: string,
  options?: AnalyzeIntuneLogsOptions & { graphApiEnabled?: boolean },
): Promise<IntuneAnalysisResult> {
  return invokeCommand<IntuneAnalysisResult>("analyze_intune_logs", {
    path,
    requestId,
    includeLiveEventLogs: options?.includeLiveEventLogs ?? false,
    graphApiEnabled: options?.graphApiEnabled ?? false,
  });
}

export async function analyzeSysmonLogs(
  path: string,
  requestId: string,
  options?: { includeLiveEventLogs?: boolean },
): Promise<SysmonAnalysisResult> {
  return invokeCommand<SysmonAnalysisResult>("analyze_sysmon_logs", {
    path,
    requestId,
    includeLiveEventLogs: options?.includeLiveEventLogs ?? false,
  });
}

export async function analyzeDsregcmd(
  input: string,
  bundlePath?: string | null,
): Promise<DsregcmdAnalysisResult> {
  return invokeCommand<DsregcmdAnalysisResult>("analyze_dsregcmd", {
    input,
    bundlePath: bundlePath ?? null,
  });
}

export async function captureDsregcmd(): Promise<DsregcmdCaptureResult> {
  return invokeCommand<DsregcmdCaptureResult>("capture_dsregcmd");
}

export async function inspectPathKind(
  path: string,
): Promise<"file" | "folder" | "unknown"> {
  return invokeCommand<"file" | "folder" | "unknown">("inspect_path_kind", {
    path,
  });
}

export async function writeTextOutputFile(
  path: string,
  contents: string,
): Promise<void> {
  return invokeCommand<void>("write_text_output_file", { path, contents });
}

export async function loadDsregcmdSource(
  kind: "file" | "folder",
  path: string,
): Promise<DsregcmdResolvedSource> {
  return invokeCommand<DsregcmdResolvedSource>("load_dsregcmd_source", {
    kind,
    path,
  });
}

export async function getInitialFilePaths(): Promise<string[]> {
  return invokeCommand<string[]>("get_initial_file_paths");
}

export async function getInitialWorkspace(): Promise<WorkspaceId | null> {
  return invokeCommand<WorkspaceId | null>("get_initial_workspace");
}

// --- Application-wide elevation ---

export async function getAppElevationState(): Promise<AppElevationState> {
  return invokeCommand<AppElevationState>("get_app_elevation_state");
}

export async function restartAsAdministrator(
  request: ElevationRequest,
): Promise<RelaunchResult> {
  return invokeCommand<RelaunchResult>("restart_as_administrator", {
    request,
  });
}

/**
 * Claim the single-use restore ticket this process was started with.
 *
 * Returns null for every unusable case — no ticket, expired, malformed, or
 * already consumed — because a failed restore must never stop the app starting.
 */
export async function getInitialElevationRestore(): Promise<RestoreTicket | null> {
  return invokeCommand<RestoreTicket | null>("get_initial_elevation_restore");
}

export async function getAvailableWorkspaces(): Promise<WorkspaceId[]> {
  return invokeCommand<WorkspaceId[]>("get_available_workspaces");
}

export async function discoverSccmEnvironment(): Promise<SccmEnvironmentDiscovery> {
  return invokeCommand<SccmEnvironmentDiscovery>("discover_sccm_environment");
}

export async function captureSccmDiagnostics(): Promise<SccmCaptureResult> {
  return invokeCommand<SccmCaptureResult>("capture_sccm_diagnostics");
}

export async function authorizeSccmAdvancedCapture(
  request: SccmAdvancedCaptureAuthorizationRequest,
): Promise<SccmAdvancedCaptureCapability> {
  return invokeCommand<SccmAdvancedCaptureCapability>(
    "authorize_sccm_advanced_capture",
    { request },
  );
}

export async function captureSccmAdvancedDiagnostics(
  capabilityHandle: string,
): Promise<SccmCaptureResult> {
  return invokeCommand<SccmCaptureResult>("capture_sccm_advanced_diagnostics", {
    capabilityHandle,
  });
}

export async function cancelSccmAdvancedCapture(
  capabilityHandle: string,
): Promise<void> {
  return invokeCommand<void>("cancel_sccm_advanced_capture", {
    capabilityHandle,
  });
}

export async function revealInFileManager(path: string): Promise<void> {
  return invokeCommand<void>("reveal_in_file_manager", { path });
}

export async function getUpdatePolicy(): Promise<UpdatePolicy> {
  return invokeCommand<UpdatePolicy>("get_update_policy");
}

export interface DnsLoggingStatus {
  dnsServerInstalled: boolean;
  debugLoggingEnabled: boolean;
  logFilePath: string | null;
  dhcpServerInstalled: boolean;
}

export async function checkDnsLoggingStatus(): Promise<DnsLoggingStatus> {
  return invokeCommand<DnsLoggingStatus>("check_dns_logging_status");
}

export async function enableDnsDebugLogging(): Promise<string> {
  return invokeCommand<string>("enable_dns_debug_logging");
}

export interface DnsDhcpCollectionProgress {
  requestId: string;
  message: string;
  currentServer: string | null;
  completedServers: number;
  totalServers: number;
}

export interface DnsDhcpServerResult {
  server: string;
  status: string;
  filesCollected: number;
  bytesCopied: number;
  errors: string[];
}

export interface DnsDhcpCollectionResult {
  bundlePath: string;
  servers: DnsDhcpServerResult[];
  totalFiles: number;
  totalBytes: number;
  durationMs: number;
}

export async function collectDnsDhcpFromDomain(
  requestId: string,
  outputRoot?: string,
  servers?: string[],
): Promise<DnsDhcpCollectionResult> {
  return invokeCommand<DnsDhcpCollectionResult>(
    "collect_dns_dhcp_from_domain",
    {
      requestId,
      outputRoot: outputRoot ?? null,
      servers: servers ?? null,
    },
  );
}

export async function getFileAssociationPromptStatus(): Promise<FileAssociationPromptStatus> {
  return invokeCommand<FileAssociationPromptStatus>(
    "get_file_association_prompt_status",
  );
}

export async function associateLogFilesWithApp(): Promise<void> {
  return invokeCommand<void>("associate_log_files_with_app");
}

export async function setFileAssociationPromptSuppressed(
  suppressed: boolean,
): Promise<void> {
  return invokeCommand<void>("set_file_association_prompt_suppressed", {
    suppressed,
  });
}

export async function getSystemDateTimePreferences(): Promise<SystemDateTimePreferences> {
  return invokeCommand<SystemDateTimePreferences>(
    "get_system_date_time_preferences",
  );
}

// --- Diagnostics Collection ---

export interface CollectionResult {
  bundlePath: string;
  bundleId: string;
  artifactCounts: {
    collected: number;
    missing: number;
    failed: number;
    total: number;
  };
  durationMs: number;
  gaps: Array<{
    artifactId: string;
    category: string;
    reason: string;
  }>;
}

export async function collectDiagnostics(
  requestId: string,
  outputRoot?: string | null,
  enabledFamilies?: string[] | null,
): Promise<CollectionResult> {
  return invokeCommand<CollectionResult>("collect_diagnostics", {
    requestId,
    outputRoot: outputRoot ?? null,
    enabledFamilies: enabledFamilies ?? null,
  });
}

// --- ESP Diagnostics ---

export async function getEspElevationState(): Promise<EspElevationState> {
  return invokeCommand<EspElevationState>("get_esp_elevation_state");
}

export async function analyzeEspEvidence(
  path: string,
  requestId: string,
): Promise<EspDiagnosticsSnapshot> {
  return invokeCommand<EspDiagnosticsSnapshot>("analyze_esp_evidence", {
    path,
    requestId,
  });
}

/**
 * Write an ESP session to a user-chosen file.
 *
 * The backend builds the capture: the redaction projection is applied inside
 * the parser crate, which is the only place that can produce an exportable
 * session. The frontend never serializes a snapshot to a file itself
 * (issue #549).
 */
export async function exportEspSession(
  destination: string,
  snapshot: EspDiagnosticsSnapshot,
  meta: EspSessionCaptureMeta,
): Promise<void> {
  return invokeCommand<void>("export_esp_session", {
    destination,
    snapshot,
    meta,
  });
}

export async function startEspDiagnosticsSession(
  requestId: string,
): Promise<EspSessionEnvelope> {
  return invokeCommand<EspSessionEnvelope>("start_esp_diagnostics_session", {
    requestId,
  });
}

export async function getEspDiagnosticsSession(
  sessionId: string,
): Promise<EspSessionEnvelope> {
  return invokeCommand<EspSessionEnvelope>("get_esp_diagnostics_session", {
    sessionId,
  });
}

export async function stopEspDiagnosticsSession(
  sessionId: string,
): Promise<void> {
  return invokeCommand<void>("stop_esp_diagnostics_session", { sessionId });
}

export async function restartEspAsAdministrator(): Promise<EspRelaunchResult> {
  return invokeCommand<EspRelaunchResult>("restart_esp_as_administrator");
}

export async function graphFetchEspDiagnostics(
  request: EspGraphRequest,
): Promise<EspGraphOverlay> {
  return invokeCommand<EspGraphOverlay>("graph_fetch_esp_diagnostics", {
    request,
  });
}

export async function espFlipAppInstalled(
  appId: string,
): Promise<EspAppFlipResult> {
  return invokeCommand<EspAppFlipResult>("esp_flip_app_installed", { appId });
}

export async function espRestoreAppState(
  backup: EspAppFlipBackup,
): Promise<void> {
  return invokeCommand<void>("esp_restore_app_state", { backup });
}

export async function graphCancelEspDiagnostics(
  requestId: string,
): Promise<void> {
  return invokeCommand<void>("graph_cancel_esp_diagnostics", { requestId });
}

// --- Graph API (Windows only, opt-in) ---

export interface GraphAuthCapabilities {
  managedDevices: boolean;
  serviceConfig: boolean;
  apps: boolean;
  configuration: boolean;
  scripts: boolean;
}

export interface GraphAuthStatus {
  isAuthenticated: boolean;
  userPrincipalName: string | null;
  objectId: string | null;
  tenantId: string | null;
  grantedScopes: string[];
  missingScopes: string[];
  expiresAt: number | null;
  capabilities: GraphAuthCapabilities;
}

export type GraphHostCapabilityKind =
  | "available"
  | "personalAccountOnly"
  | "noOrganizationalAccount"
  | "providerUnavailable"
  | "unknown";

export interface GraphHostCapability {
  kind: GraphHostCapabilityKind;
}

export type GraphAuthAttemptOutcome =
  "connected" | "cancelled" | "timedOut" | "unavailable" | "failed" | "stale";

export interface GraphAuthAttemptResult {
  outcome: GraphAuthAttemptOutcome;
  status: GraphAuthStatus;
  capability: GraphHostCapability;
  message: string | null;
}

export type GraphPermissionUpgradeOutcome =
  | "upgraded"
  | "unchanged"
  | "cancelled"
  | "timedOut"
  | "denied"
  | "failed"
  | "stale";

export interface GraphPermissionUpgradeResult {
  outcome: GraphPermissionUpgradeOutcome;
  status: GraphAuthStatus;
  message: string | null;
}

export type GraphInteractiveOperationKind =
  "authentication" | "permissionConsent";

export interface GraphInteractiveOperationTicket {
  attemptId: string;
}

function isGraphRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function isGraphAuthStatus(value: unknown): value is GraphAuthStatus {
  if (!isGraphRecord(value) || !isGraphRecord(value.capabilities)) return false;
  const capabilities = value.capabilities;
  return (
    typeof value.isAuthenticated === "boolean" &&
    isNullableString(value.userPrincipalName) &&
    isNullableString(value.objectId) &&
    isNullableString(value.tenantId) &&
    isStringArray(value.grantedScopes) &&
    isStringArray(value.missingScopes) &&
    (value.expiresAt === null ||
      (typeof value.expiresAt === "number" &&
        Number.isFinite(value.expiresAt))) &&
    typeof capabilities.managedDevices === "boolean" &&
    typeof capabilities.serviceConfig === "boolean" &&
    typeof capabilities.apps === "boolean" &&
    typeof capabilities.configuration === "boolean" &&
    typeof capabilities.scripts === "boolean"
  );
}

const GRAPH_HOST_CAPABILITY_KINDS = new Set<GraphHostCapabilityKind>([
  "available",
  "personalAccountOnly",
  "noOrganizationalAccount",
  "providerUnavailable",
  "unknown",
]);

const GRAPH_AUTH_ATTEMPT_OUTCOMES = new Set<GraphAuthAttemptOutcome>([
  "connected",
  "cancelled",
  "timedOut",
  "unavailable",
  "failed",
  "stale",
]);

const GRAPH_PERMISSION_UPGRADE_OUTCOMES =
  new Set<GraphPermissionUpgradeOutcome>([
    "upgraded",
    "unchanged",
    "cancelled",
    "timedOut",
    "denied",
    "failed",
    "stale",
  ]);

function invalidGraphResponse(commandName: string): never {
  throw new Error(`Command '${commandName}' returned an invalid response.`);
}

function decodeGraphHostCapability(
  value: unknown,
  commandName: string,
): GraphHostCapability {
  if (
    !isGraphRecord(value) ||
    typeof value.kind !== "string" ||
    !GRAPH_HOST_CAPABILITY_KINDS.has(value.kind as GraphHostCapabilityKind)
  ) {
    return invalidGraphResponse(commandName);
  }
  return value as unknown as GraphHostCapability;
}

function decodeGraphAuthStatus(
  value: unknown,
  commandName: string,
): GraphAuthStatus {
  if (!isGraphAuthStatus(value)) return invalidGraphResponse(commandName);
  return value;
}

function decodeGraphAuthAttemptResult(
  value: unknown,
  commandName: string,
): GraphAuthAttemptResult {
  if (
    !isGraphRecord(value) ||
    typeof value.outcome !== "string" ||
    !GRAPH_AUTH_ATTEMPT_OUTCOMES.has(
      value.outcome as GraphAuthAttemptOutcome,
    ) ||
    !isGraphAuthStatus(value.status) ||
    !isNullableString(value.message)
  ) {
    return invalidGraphResponse(commandName);
  }
  decodeGraphHostCapability(value.capability, commandName);
  return value as unknown as GraphAuthAttemptResult;
}

function decodeGraphPermissionUpgradeResult(
  value: unknown,
  commandName: string,
): GraphPermissionUpgradeResult {
  if (
    !isGraphRecord(value) ||
    typeof value.outcome !== "string" ||
    !GRAPH_PERMISSION_UPGRADE_OUTCOMES.has(
      value.outcome as GraphPermissionUpgradeOutcome,
    ) ||
    !isGraphAuthStatus(value.status) ||
    !isNullableString(value.message)
  ) {
    return invalidGraphResponse(commandName);
  }
  return value as unknown as GraphPermissionUpgradeResult;
}

function decodeGraphInteractiveOperationTicket(
  value: unknown,
  commandName: string,
): GraphInteractiveOperationTicket {
  if (
    !isGraphRecord(value) ||
    typeof value.attemptId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value.attemptId,
    )
  ) {
    return invalidGraphResponse(commandName);
  }
  return value as unknown as GraphInteractiveOperationTicket;
}

export interface GraphAppInfo {
  id: string;
  displayName: string;
  publisher: string | null;
  odataType: string | null;
}

export interface GraphResolutionResult {
  resolved: Record<string, GraphAppInfo>;
  notFound: string[];
  errors: string[];
}

export async function graphReserveInteractiveOperation(
  kind: GraphInteractiveOperationKind,
): Promise<GraphInteractiveOperationTicket> {
  const commandName = "graph_reserve_interactive_operation";
  return decodeGraphInteractiveOperationTicket(
    await invokeCommand<unknown>(commandName, { kind }),
    commandName,
  );
}

export async function graphAuthenticate(
  attemptId: string,
): Promise<GraphAuthAttemptResult> {
  const commandName = "graph_authenticate";
  return decodeGraphAuthAttemptResult(
    await invokeCommand<unknown>(commandName, { attemptId }),
    commandName,
  );
}

export async function graphCancelAuthentication(
  attemptId: string,
): Promise<boolean> {
  const commandName = "graph_cancel_authentication";
  const result = await invokeCommand<unknown>(commandName, { attemptId });
  return typeof result === "boolean"
    ? result
    : invalidGraphResponse(commandName);
}

export async function graphRequestMissingPermissions(
  attemptId: string,
): Promise<GraphPermissionUpgradeResult> {
  const commandName = "graph_request_missing_permissions";
  return decodeGraphPermissionUpgradeResult(
    await invokeCommand<unknown>(commandName, { attemptId }),
    commandName,
  );
}

export async function graphGetAuthStatus(): Promise<GraphAuthStatus> {
  const commandName = "graph_get_auth_status";
  return decodeGraphAuthStatus(
    await invokeCommand<unknown>(commandName),
    commandName,
  );
}

export async function graphSignOut(): Promise<void> {
  return invokeCommand<void>("graph_sign_out");
}

export async function graphResolveGuids(
  guids: string[],
): Promise<GraphResolutionResult> {
  return invokeCommand<GraphResolutionResult>("graph_resolve_guids", { guids });
}

export async function graphFetchAllApps(): Promise<GraphAppInfo[]> {
  return invokeCommand<GraphAppInfo[]>("graph_fetch_all_apps");
}

// --- macOS Diagnostics ---

import type {
  MacosDiagEnvironment,
  MacosIntuneLogScanResult,
  MacosProfilesResult,
  MacosDefenderResult,
  MacosPackagesResult,
  MacosPackageInfo,
  MacosPackageFiles,
  MacosUnifiedLogResult,
} from "../workspaces/macos-diag/types";

export async function macosScanEnvironment(): Promise<MacosDiagEnvironment> {
  return invokeCommand<MacosDiagEnvironment>("macos_scan_environment");
}

export async function macosScanIntuneLogs(): Promise<MacosIntuneLogScanResult> {
  return invokeCommand<MacosIntuneLogScanResult>("macos_scan_intune_logs");
}

export async function macosListProfiles(): Promise<MacosProfilesResult> {
  return invokeCommand<MacosProfilesResult>("macos_list_profiles");
}

export async function macosInspectDefender(): Promise<MacosDefenderResult> {
  return invokeCommand<MacosDefenderResult>("macos_inspect_defender");
}

export async function macosListPackages(): Promise<MacosPackagesResult> {
  return invokeCommand<MacosPackagesResult>("macos_list_packages");
}

export async function macosGetPackageInfo(
  packageId: string,
): Promise<MacosPackageInfo> {
  return invokeCommand<MacosPackageInfo>("macos_get_package_info", {
    packageId,
  });
}

export async function macosGetPackageFiles(
  packageId: string,
): Promise<MacosPackageFiles> {
  return invokeCommand<MacosPackageFiles>("macos_get_package_files", {
    packageId,
  });
}

export async function macosQueryUnifiedLog(
  presetId: string,
  timeRangeMinutes: number,
  resultCap: number,
): Promise<MacosUnifiedLogResult> {
  const now = new Date();
  const start = new Date(now.getTime() - timeRangeMinutes * 60 * 1000);
  const fmt = (d: Date) =>
    `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  const timeRange = { start: fmt(start), end: fmt(now) };
  return invokeCommand<MacosUnifiedLogResult>("macos_query_unified_log", {
    presetId,
    timeRange,
    resultCap,
  });
}

// --- Secure Boot ---

import type { SecureBootAnalysisResult } from "../workspaces/secureboot/types";

export async function analyzeSecureBoot(
  path?: string | null,
): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("analyze_secureboot", {
    path: path ?? null,
  });
}

export async function rescanSecureBoot(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("rescan_secureboot", {});
}

export async function runSecureBootDetection(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>(
    "run_secureboot_detection",
    {},
  );
}

export async function runSecureBootRemediation(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>(
    "run_secureboot_remediation",
    {},
  );
}
