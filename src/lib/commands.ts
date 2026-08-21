import { invoke } from "@tauri-apps/api/core";
import type {
  AggregateParseResult,
  FolderListingResult,
  KnownSourceMetadata,
  LogEntry,
  LogFormat,
  LogSource,
  ParseResult,
  ParserKind,
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
  EvtxChannelInfo,
  EvtxParseResult,
  EvtxRecord,
} from "../workspaces/event-log/types";
import { assertParseResultShape } from "../workspaces/event-log/evtx-coverage";
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
import type { SignalKind, TimelineBundle } from "../types/timeline";

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

type CommandDecoder<T> = (value: unknown, commandName: string) => T;

async function invokeCommand<Name extends CommandName>(
  commandName: Name,
  args?: Record<string, unknown>,
): Promise<CommandResponse<Name>>;
async function invokeCommand(
  commandName: CommandName,
  args?: Record<string, unknown>,
): Promise<CommandResponse<CommandName>> {
  let response: unknown;
  try {
    response = await invoke<unknown>(commandName, args);
  } catch (error) {
    throw normalizeCommandInvokeError(commandName, error);
  }

  const decoder = COMMAND_DECODERS[commandName];
  if (!decoder) {
    throw new Error(`No response decoder registered for '${commandName}'.`);
  }
  return decoder(response, commandName);
}

function isCommandRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonNegativeCommandCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isEvtxFieldResponse(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    typeof value.name === "string" &&
    typeof value.value === "string"
  );
}

function isEvtxRecordResponse(value: unknown): value is EvtxRecord {
  if (
    !isCommandRecord(value) ||
    !isFiniteCommandNumber(value.id) ||
    !isFiniteCommandNumber(value.eventRecordId) ||
    !(
      value.eventRecordIdText === undefined ||
      isNullableCommandString(value.eventRecordIdText)
    ) ||
    typeof value.timestamp !== "string" ||
    !isFiniteCommandNumber(value.timestampEpoch) ||
    typeof value.provider !== "string" ||
    typeof value.channel !== "string" ||
    !isFiniteCommandNumber(value.eventId) ||
    !(
      value.level === "Critical" ||
      value.level === "Error" ||
      value.level === "Warning" ||
      value.level === "Information" ||
      value.level === "Verbose"
    ) ||
    typeof value.computer !== "string" ||
    typeof value.message !== "string" ||
    !Array.isArray(value.eventData) ||
    !value.eventData.every(isEvtxFieldResponse) ||
    typeof value.rawXml !== "string" ||
    typeof value.sourceLabel !== "string"
  ) {
    return false;
  }
  return (
    value.originKind === undefined ||
    value.originKind === "event" ||
    value.originKind === "log"
  ) && (
    value.task === undefined ||
    value.task === null ||
    isFiniteCommandNumber(value.task)
  ) && (
    value.opcode === undefined ||
    value.opcode === null ||
    isFiniteCommandNumber(value.opcode)
  ) && (
    value.processId === undefined ||
    value.processId === null ||
    isFiniteCommandNumber(value.processId)
  ) && (
    value.activityId === undefined ||
    value.activityId === null ||
    typeof value.activityId === "string"
  ) && (
    value.relatedActivityId === undefined ||
    value.relatedActivityId === null ||
    typeof value.relatedActivityId === "string"
  ) && (
    value.sessionId === undefined ||
    value.sessionId === null ||
    typeof value.sessionId === "string"
  ) && (
    value.deviceId === undefined ||
    value.deviceId === null ||
    typeof value.deviceId === "string"
  ) && (
    value.userId === undefined ||
    value.userId === null ||
    typeof value.userId === "string"
  ) && (
    value.processStartTime === undefined ||
    value.processStartTime === null ||
    typeof value.processStartTime === "string"
  ) && (
    value.threadId === undefined ||
    value.threadId === null ||
    isFiniteCommandNumber(value.threadId)
  ) && (
    value.userSid === undefined ||
    value.userSid === null ||
    typeof value.userSid === "string"
  ) && (
    value.keywords === undefined ||
    value.keywords === null ||
    typeof value.keywords === "string"
  ) && (
    value.mapped === undefined ||
    (Array.isArray(value.mapped) &&
      value.mapped.every(
        (mapped) =>
          isCommandRecord(mapped) &&
          typeof mapped.property === "string" &&
          typeof mapped.text === "string" &&
          typeof mapped.complete === "boolean",
      ))
  );
}

function isEvtxChannelSourceType(value: unknown): boolean {
  if (value === "live") return true;
  if (!isCommandRecord(value)) return false;
  if (isCommandRecord(value.remote)) {
    return typeof value.remote.machine === "string";
  }
  if (isCommandRecord(value.file)) {
    return typeof value.file.path === "string";
  }
  return false;
}

function isEvtxChannelInfoResponse(value: unknown): value is EvtxChannelInfo {
  return (
    isCommandRecord(value) &&
    typeof value.name === "string" &&
    isNonNegativeCommandCount(value.eventCount) &&
    isEvtxChannelSourceType(value.sourceType)
  );
}
function assertEvtxRecordArray(
  records: unknown[],
  commandName: string,
): asserts records is EvtxRecord[] {
  if (!records.every(isEvtxRecordResponse)) {
    invalidCommandResponse(commandName);
  }
}

function assertEvtxChannelArray(
  channels: unknown[],
  commandName: string,
): asserts channels is EvtxChannelInfo[] {
  if (!channels.every(isEvtxChannelInfoResponse)) {
    invalidCommandResponse(commandName);
  }
}

function isFiniteCommandNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isNullableCommandNumber(value: unknown): value is number | null {
  return value === null || isFiniteCommandNumber(value);
}

function isNullableCommandString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isParserSelectionResponse(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    typeof value.parser === "string" &&
    typeof value.implementation === "string" &&
    typeof value.provenance === "string" &&
    typeof value.parseQuality === "string" &&
    typeof value.recordFraming === "string" &&
    isNullableCommandString(value.dateOrder) &&
    (value.specialization === undefined ||
      isNullableCommandString(value.specialization))
  );
}

function isLogEntryResponse(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    isFiniteCommandNumber(value.id) &&
    isFiniteCommandNumber(value.lineNumber) &&
    typeof value.message === "string" &&
    isNullableCommandString(value.component) &&
    isNullableCommandNumber(value.timestamp) &&
    isNullableCommandString(value.timestampDisplay) &&
    typeof value.severity === "string" &&
    isNullableCommandNumber(value.thread) &&
    isNullableCommandString(value.threadDisplay) &&
    isNullableCommandString(value.sourceFile) &&
    typeof value.format === "string" &&
    typeof value.filePath === "string" &&
    isNullableCommandNumber(value.timezoneOffset)
  );
}

function isParseResultResponse(value: unknown): value is ParseResult {
  return (
    isCommandRecord(value) &&
    Array.isArray(value.entries) &&
    value.entries.every(isLogEntryResponse) &&
    typeof value.formatDetected === "string" &&
    isParserSelectionResponse(value.parserSelection) &&
    isFiniteCommandNumber(value.totalLines) &&
    isFiniteCommandNumber(value.parseErrors) &&
    typeof value.filePath === "string" &&
    isFiniteCommandNumber(value.fileSize) &&
    isFiniteCommandNumber(value.byteOffset)
  );
}

function isLogSourceKind(value: unknown): boolean {
  return value === "file" || value === "folder" || value === "known";
}

function isLogSourceResponse(value: unknown): boolean {
  if (!isCommandRecord(value) || !isLogSourceKind(value.kind)) {
    return false;
  }
  if (value.kind === "file" || value.kind === "folder") {
    return typeof value.path === "string";
  }
  return (
    typeof value.sourceId === "string" &&
    typeof value.defaultPath === "string" &&
    (value.pathKind === "file" || value.pathKind === "folder")
  );
}

function isFolderEntryResponse(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    typeof value.name === "string" &&
    typeof value.path === "string" &&
    typeof value.isDir === "boolean" &&
    isNullableCommandNumber(value.sizeBytes) &&
    isNullableCommandNumber(value.modifiedUnixMs)
  );
}

function isFolderListingResponse(value: unknown): value is FolderListingResult {
  return (
    isCommandRecord(value) &&
    isLogSourceKind(value.sourceKind) &&
    isLogSourceResponse(value.source) &&
    Array.isArray(value.entries) &&
    value.entries.every(isFolderEntryResponse) &&
    (value.bundleMetadata === undefined ||
      value.bundleMetadata === null ||
      isCommandRecord(value.bundleMetadata))
  );
}
const TIMELINE_PARSER_KIND_MEMBERS = {
  ccm: true,
  simple: true,
  timestamped: true,
  plain: true,
  iisW3c: true,
  panther: true,
  cbs: true,
  dism: true,
  reportingEvents: true,
  msi: true,
  psadtLegacy: true,
  intuneMacOs: true,
  intuneDeviceInventory: true,
  dhcp: true,
  burn: true,
  patchMyPcDetection: true,
  registry: true,
  secureBootLog: true,
  dnsDebug: true,
  dnsAudit: true,
  cmtLog: true,
  companyPortal: true,
} satisfies Record<ParserKind, true>;

const TIMELINE_PARSER_KINDS = new Set(Object.keys(TIMELINE_PARSER_KIND_MEMBERS));

const TIMELINE_SIGNAL_KIND_MEMBERS = {
  errorSeverity: true,
  knownErrorCode: true,
  imeFailed: true,
} satisfies Record<SignalKind, true>;

const TIMELINE_SIGNAL_KINDS = new Set(Object.keys(TIMELINE_SIGNAL_KIND_MEMBERS));

function isTimelineSourceKind(value: unknown): boolean {
  if (value === "intuneEvents") return true;
  if (!isCommandRecord(value) || !isCommandRecord(value.logFile)) {
    return false;
  }
  return (
    typeof value.logFile.parserKind === "string" &&
    TIMELINE_PARSER_KINDS.has(value.logFile.parserKind)
  );
}

function isTimelineSourceMeta(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    isFiniteCommandNumber(value.idx) &&
    isTimelineSourceKind(value.kind) &&
    typeof value.path === "string" &&
    typeof value.displayName === "string" &&
    typeof value.color === "string" &&
    isFiniteCommandNumber(value.entryCount)
  );
}

function isTimelineIncident(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    isFiniteCommandNumber(value.id) &&
    isFiniteCommandNumber(value.tsStartMs) &&
    isFiniteCommandNumber(value.tsEndMs) &&
    isFiniteCommandNumber(value.signalCount) &&
    isFiniteCommandNumber(value.sourceCount) &&
    isFiniteCommandNumber(value.confidence) &&
    (value.anchorEventRef === undefined ||
      value.anchorEventRef === null ||
      (Array.isArray(value.anchorEventRef) &&
        value.anchorEventRef.length === 2 &&
        value.anchorEventRef.every(isFiniteCommandNumber))) &&
    (value.anchorGuid === undefined ||
      value.anchorGuid === null ||
      typeof value.anchorGuid === "string") &&
    typeof value.summary === "string"
  );
}

function isTimelineError(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    typeof value.path === "string" &&
    typeof value.message === "string"
  );
}

function isTimelineTunables(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    isFiniteCommandNumber(value.overlapWindowMs) &&
    isFiniteCommandNumber(value.minSourceCount) &&
    isFiniteCommandNumber(value.maxIncidentSpanMs) &&
    Array.isArray(value.enabledSignalKinds) &&
    value.enabledSignalKinds.every(
      (kind) => typeof kind === "string" && TIMELINE_SIGNAL_KINDS.has(kind),
    )
  );
}

function isTimelineBundleResponse(value: unknown): value is TimelineBundle {
  return (
    isCommandRecord(value) &&
    typeof value.id === "string" &&
    Array.isArray(value.sources) &&
    value.sources.every(isTimelineSourceMeta) &&
    Array.isArray(value.timeRangeMs) &&
    value.timeRangeMs.length === 2 &&
    value.timeRangeMs.every(isFiniteCommandNumber) &&
    isFiniteCommandNumber(value.totalEntries) &&
    Array.isArray(value.incidents) &&
    value.incidents.every(isTimelineIncident) &&
    isStringArray(value.deniedGuids) &&
    Array.isArray(value.errors) &&
    value.errors.every(isTimelineError) &&
    isTimelineTunables(value.tunables)
  );
}

function decodeTimelineBundle(
  value: unknown,
  commandName: string,
): TimelineBundle {
  if (!isTimelineBundleResponse(value)) {
    return invalidCommandResponse(commandName);
  }
  return value;
}

function invalidCommandResponse(commandName: string): never {
  throw new Error(`Command '${commandName}' returned an invalid response.`);
}

type CommandFieldValidator = (value: unknown) => boolean;

function hasCommandFields(
  value: Record<string, unknown>,
  fields: Record<string, CommandFieldValidator>,
): boolean {
  return Object.entries(fields).every(([key, validator]) =>
    validator(value[key]),
  );
}

function decodeRecordResponse<T>(
  value: unknown,
  commandName: string,
  fields: Record<string, CommandFieldValidator> = {},
): T {
  if (!isCommandRecord(value) || !hasCommandFields(value, fields)) {
    return invalidCommandResponse(commandName);
  }
  return value as T;
}

function decodeRecordArrayResponse<T>(
  value: unknown,
  commandName: string,
  fields: Record<string, CommandFieldValidator> = {},
): T {
  if (
    !Array.isArray(value) ||
    !value.every(
      (item) => isCommandRecord(item) && hasCommandFields(item, fields),
    )
  ) {
    return invalidCommandResponse(commandName);
  }
  return value as T;
}

function decodeStringArrayResponse(
  value: unknown,
  commandName: string,
): string[] {
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string")
  ) {
    return invalidCommandResponse(commandName);
  }
  return value;
}

function decodeStringResponse(value: unknown, commandName: string): string {
  if (typeof value !== "string") return invalidCommandResponse(commandName);
  return value;
}

function decodeBooleanResponse(value: unknown, commandName: string): boolean {
  if (typeof value !== "boolean") return invalidCommandResponse(commandName);
  return value;
}

function decodeNullableRecordResponse<T>(
  value: unknown,
  commandName: string,
  fields: Record<string, CommandFieldValidator> = {},
): T | null {
  if (value === null) return null;
  return decodeRecordResponse<T>(value, commandName, fields);
}

function decodeUnitResponse(value: unknown, commandName: string): void {
  if (value !== null && value !== undefined) {
    return invalidCommandResponse(commandName);
  }
}

function decodeWorkspaceIdResponse(
  value: unknown,
  commandName: string,
): WorkspaceId {
  if (!isWorkspaceIdValue(value)) {
    return invalidCommandResponse(commandName);
  }
  return value;
}

function decodeNullableWorkspaceIdResponse(
  value: unknown,
  commandName: string,
): WorkspaceId | null {
  return value === null ? null : decodeWorkspaceIdResponse(value, commandName);
}

function decodePathKindResponse(
  value: unknown,
  commandName: string,
): "file" | "folder" | "unknown" {
  if (value !== "file" && value !== "folder" && value !== "unknown") {
    return invalidCommandResponse(commandName);
  }
  return value;
}

const WORKSPACE_IDS: Record<WorkspaceId, true> = {
  log: true,
  intune: true,
  "new-intune": true,
  dsregcmd: true,
  "macos-diag": true,
  "macos-jamf": true,
  deployment: true,
  "event-log": true,
  "esp-diagnostics": true,
  sccm: true,
  secureboot: true,
  sysmon: true,
  timeline: true,
  "dns-dhcp": true,
};

function isWorkspaceIdValue(value: unknown): value is WorkspaceId {
  return (
    typeof value === "string" &&
    Object.prototype.hasOwnProperty.call(WORKSPACE_IDS, value)
  );
}

function decodeWorkspaceIdArrayResponse(
  value: unknown,
  commandName: string,
): WorkspaceId[] {
  if (!Array.isArray(value) || !value.every(isWorkspaceIdValue)) {
    return invalidCommandResponse(commandName);
  }
  return value;
}

function isCommandRecordArray(value: unknown): boolean {
  return Array.isArray(value) && value.every(isCommandRecord);
}

function isNullableCommandRecord(value: unknown): boolean {
  return value === null || isCommandRecord(value);
}
const EVIDENCE_ARTIFACT_INTAKE_KIND_MEMBERS = {
  log: true,
  registrySnapshot: true,
  eventLogExport: true,
  commandOutput: true,
  screenshot: true,
  export: true,
  unknown: true,
} satisfies Record<EvidenceArtifactIntakeKind, true>;

function isEvidenceArtifactIntakeKind(value: unknown): boolean {
  return (
    typeof value === "string" &&
    Object.prototype.hasOwnProperty.call(
      EVIDENCE_ARTIFACT_INTAKE_KIND_MEMBERS,
      value,
    )
  );
}

function isRegistrySnapshotValuePreview(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    typeof value.name === "string" &&
    typeof value.valueType === "string" &&
    typeof value.value === "string"
  );
}

function isRegistrySnapshotKeyPreview(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    typeof value.path === "string" &&
    isFiniteCommandNumber(value.valueCount) &&
    Array.isArray(value.values) &&
    value.values.every(isRegistrySnapshotValuePreview)
  );
}

function isRegistrySnapshotSummary(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    isFiniteCommandNumber(value.keyCount) &&
    isFiniteCommandNumber(value.valueCount) &&
    Array.isArray(value.keys) &&
    value.keys.every(isRegistrySnapshotKeyPreview)
  );
}

function isEvidenceEventLogExportPreview(value: unknown): boolean {
  return (
    isCommandRecord(value) &&
    isNullableCommandString(value.channel) &&
    isNullableCommandNumber(value.fileSizeBytes) &&
    isNullableCommandNumber(value.modifiedUnixMs) &&
    typeof value.exportFormat === "string"
  );
}

function isNullableRegistrySnapshotSummary(value: unknown): boolean {
  return value === null || isRegistrySnapshotSummary(value);
}

function isNullableEvidenceEventLogExportPreview(value: unknown): boolean {
  return value === null || isEvidenceEventLogExportPreview(value);
}


function decodeParseResults(
  value: unknown,
  commandName: string,
): ParseResult[] {
  if (!Array.isArray(value) || !value.every(isParseResultResponse)) {
    return invalidCommandResponse(commandName);
  }
  return value;
}

function decodeParseResult(value: unknown, commandName: string): ParseResult {
  if (!isParseResultResponse(value)) {
    return invalidCommandResponse(commandName);
  }
  return value;
}

function decodeAggregateParseResult(
  value: unknown,
  commandName: string,
): AggregateParseResult {
  return decodeRecordResponse<AggregateParseResult>(value, commandName, {
    entries: (entries) =>
      Array.isArray(entries) && entries.every(isLogEntryResponse),
    totalLines: isFiniteCommandNumber,
    parseErrors: isFiniteCommandNumber,
    folderPath: (path) => typeof path === "string",
    files: (files) =>
      Array.isArray(files) &&
      files.every(
        (file) =>
          isCommandRecord(file) &&
          typeof file.filePath === "string" &&
          isFiniteCommandNumber(file.totalLines) &&
          isFiniteCommandNumber(file.parseErrors) &&
          isFiniteCommandNumber(file.fileSize) &&
          isFiniteCommandNumber(file.byteOffset),
      ),
  });
}

function decodeFolderListingResult(
  value: unknown,
  commandName: string,
): FolderListingResult {
  if (!isFolderListingResponse(value)) {
    return invalidCommandResponse(commandName);
  }
  return value;
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
  return invokeCommand("load_markers", { filePath });
}

export async function openLogFile(path: string): Promise<ParseResult> {
  return invokeCommand("open_log_file", { path });
}

/** Parse multiple files in parallel on the Rust side (Rayon thread pool).
 *  Returns all results in a single IPC response.  The request ID tags progress
 *  events to the owning source load and the offset makes progress monotonic
 *  across sequential batches. */
export async function parseFilesBatch(
  paths: string[],
  requestId: number,
  completedOffset: number,
): Promise<ParseResult[]> {
  return invokeCommand("parse_files_batch", {
    paths,
    requestId,
    completedOffset,
  });
}

export async function listLogFolder(
  path: string,
): Promise<FolderListingResult> {
  return invokeCommand("list_log_folder", { path });
}

export async function buildTimeline(
  sources: { path: string; displayName?: string }[],
): Promise<TimelineBundle> {
  return invokeCommand("build_timeline_cmd", { sources });
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

function decodeEventLogSourceManifest(
  value: unknown,
  _commandName: string,
): EventLogSourceManifest {
  assertEventLogSourceManifest(value);
  return value;
}

function decodeEventLogParseResult(
  value: unknown,
  commandName: string,
): EvtxParseResult {
  const shape = assertParseResultShape(value);
  const reply = value as Record<string, unknown>;
  const totalRecords = shape.totalRecords;
  const parseErrors = reply.parseErrors;
  if (
    totalRecords === null ||
    !isNonNegativeCommandCount(totalRecords) ||
    !isNonNegativeCommandCount(parseErrors)
  ) {
    return invalidCommandResponse(commandName);
  }
  assertEvtxRecordArray(shape.records, commandName);
  assertEvtxChannelArray(shape.channels, commandName);
  const result: EvtxParseResult = {
    records: shape.records,
    channels: shape.channels,
    totalRecords,
    parseErrors,
    errorMessages: shape.errorMessages,
  };
  if (reply.coverageGaps !== undefined) result.coverageGaps = shape.coverageGaps;
  if (reply.coverage !== undefined) result.coverage = shape.coverage;
  if (reply.archiveMembers !== undefined) result.archiveMembers = shape.archiveMembers;
  return result;

}
export async function expandEventLogSources(
  sources: EventLogSourceSelection[],
): Promise<EventLogSourceManifest> {
  return invokeCommand("evtx_expand_sources", {
    sources,
  });
}


export async function parseEventLogManifest(
  manifest: EventLogSourceManifest,
): Promise<EvtxParseResult> {
  return invokeCommand("evtx_parse_manifest", { manifest });
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
    await invokeCommand(commandName, {
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
  return invokeCommand("inspect_evidence_bundle", {
    path,
  });
}

export async function inspectEvidenceArtifact(
  path: string,
  intakeKind: EvidenceArtifactIntakeKind,
  originPath?: string | null,
): Promise<EvidenceArtifactPreview> {
  return invokeCommand("inspect_evidence_artifact", {
    path,
    intakeKind,
    originPath: originPath ?? null,
  });
}

export async function parseRegistryFile(
  path: string,
): Promise<RegistryParseResult> {
  return invokeCommand("parse_registry_file", { path });
}

export async function getKnownLogSources(): Promise<KnownSourceMetadata[]> {
  return invokeCommand("get_known_log_sources");
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
  return invokeCommand("open_log_folder_aggregate", {
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
  return invokeCommand("start_tail", {
    path,
    format,
    byteOffset,
    nextId,
    nextLine,
  });
}

export async function stopTail(path: string): Promise<void> {
  return invokeCommand("stop_tail", { path });
}

export async function pauseTail(path: string): Promise<void> {
  return invokeCommand("pause_tail", { path });
}

export async function resumeTail(path: string): Promise<void> {
  return invokeCommand("resume_tail", { path });
}

export async function analyzeIntuneLogs(
  path: string,
  requestId: string,
  options?: AnalyzeIntuneLogsOptions & { graphApiEnabled?: boolean },
): Promise<IntuneAnalysisResult> {
  return invokeCommand("analyze_intune_logs", {
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
  return invokeCommand("analyze_sysmon_logs", {
    path,
    requestId,
    includeLiveEventLogs: options?.includeLiveEventLogs ?? false,
  });
}

export async function analyzeDsregcmd(
  input: string,
  bundlePath?: string | null,
): Promise<DsregcmdAnalysisResult> {
  return invokeCommand("analyze_dsregcmd", {
    input,
    bundlePath: bundlePath ?? null,
  });
}

export async function captureDsregcmd(): Promise<DsregcmdCaptureResult> {
  return invokeCommand("capture_dsregcmd");
}

export async function inspectPathKind(
  path: string,
): Promise<"file" | "folder" | "unknown"> {
  return invokeCommand("inspect_path_kind", {
    path,
  });
}

export async function writeTextOutputFile(
  path: string,
  contents: string,
): Promise<void> {
  return invokeCommand("write_text_output_file", { path, contents });
}

export async function loadDsregcmdSource(
  kind: "file" | "folder",
  path: string,
): Promise<DsregcmdResolvedSource> {
  return invokeCommand("load_dsregcmd_source", {
    kind,
    path,
  });
}

export async function getInitialFilePaths(): Promise<string[]> {
  return invokeCommand("get_initial_file_paths");
}

export async function getInitialWorkspace(): Promise<WorkspaceId | null> {
  return invokeCommand("get_initial_workspace");
}

// --- Application-wide elevation ---

export async function getAppElevationState(): Promise<AppElevationState> {
  return invokeCommand("get_app_elevation_state");
}

export async function restartAsAdministrator(
  request: ElevationRequest,
): Promise<RelaunchResult> {
  return invokeCommand("restart_as_administrator", {
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
  return invokeCommand("get_initial_elevation_restore");
}

export async function getAvailableWorkspaces(): Promise<WorkspaceId[]> {
  return invokeCommand("get_available_workspaces");
}

export async function discoverSccmEnvironment(): Promise<SccmEnvironmentDiscovery> {
  return invokeCommand("discover_sccm_environment");
}

export async function captureSccmDiagnostics(): Promise<SccmCaptureResult> {
  return invokeCommand("capture_sccm_diagnostics");
}

export async function authorizeSccmAdvancedCapture(
  request: SccmAdvancedCaptureAuthorizationRequest,
): Promise<SccmAdvancedCaptureCapability> {
  return invokeCommand("authorize_sccm_advanced_capture", { request });
}

export async function captureSccmAdvancedDiagnostics(
  capabilityHandle: string,
): Promise<SccmCaptureResult> {
  return invokeCommand("capture_sccm_advanced_diagnostics", {
    capabilityHandle,
  });
}

export async function cancelSccmAdvancedCapture(
  capabilityHandle: string,
): Promise<void> {
  return invokeCommand("cancel_sccm_advanced_capture", {
    capabilityHandle,
  });
}

export async function revealInFileManager(path: string): Promise<void> {
  return invokeCommand("reveal_in_file_manager", { path });
}

export async function getUpdatePolicy(): Promise<UpdatePolicy> {
  return invokeCommand("get_update_policy");
}

export interface DnsLoggingStatus {
  dnsServerInstalled: boolean;
  debugLoggingEnabled: boolean;
  logFilePath: string | null;
  dhcpServerInstalled: boolean;
}

export async function checkDnsLoggingStatus(): Promise<DnsLoggingStatus> {
  return invokeCommand("check_dns_logging_status");
}

export async function enableDnsDebugLogging(): Promise<string> {
  return invokeCommand("enable_dns_debug_logging");
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
  return invokeCommand("collect_dns_dhcp_from_domain", {
    requestId,
    outputRoot: outputRoot ?? null,
    servers: servers ?? null,
  });
}

export async function getFileAssociationPromptStatus(): Promise<FileAssociationPromptStatus> {
  return invokeCommand("get_file_association_prompt_status");
}

export async function associateLogFilesWithApp(): Promise<void> {
  return invokeCommand("associate_log_files_with_app");
}

export async function setFileAssociationPromptSuppressed(
  suppressed: boolean,
): Promise<void> {
  return invokeCommand("set_file_association_prompt_suppressed", {
    suppressed,
  });
}

export async function getSystemDateTimePreferences(): Promise<SystemDateTimePreferences> {
  return invokeCommand("get_system_date_time_preferences");
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
  return invokeCommand("collect_diagnostics", {
    requestId,
    outputRoot: outputRoot ?? null,
    enabledFamilies: enabledFamilies ?? null,
  });
}

// --- ESP Diagnostics ---

export async function getEspElevationState(): Promise<EspElevationState> {
  return invokeCommand("get_esp_elevation_state");
}

export async function analyzeEspEvidence(
  path: string,
  requestId: string,
): Promise<EspDiagnosticsSnapshot> {
  return invokeCommand("analyze_esp_evidence", {
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
  return invokeCommand("export_esp_session", {
    destination,
    snapshot,
    meta,
  });
}

export async function startEspDiagnosticsSession(
  requestId: string,
): Promise<EspSessionEnvelope> {
  return invokeCommand("start_esp_diagnostics_session", {
    requestId,
  });
}

export async function getEspDiagnosticsSession(
  sessionId: string,
): Promise<EspSessionEnvelope> {
  return invokeCommand("get_esp_diagnostics_session", {
    sessionId,
  });
}

export async function stopEspDiagnosticsSession(
  sessionId: string,
): Promise<void> {
  return invokeCommand("stop_esp_diagnostics_session", { sessionId });
}

export async function restartEspAsAdministrator(): Promise<EspRelaunchResult> {
  return invokeCommand("restart_esp_as_administrator");
}

export async function graphFetchEspDiagnostics(
  request: EspGraphRequest,
): Promise<EspGraphOverlay> {
  return invokeCommand("graph_fetch_esp_diagnostics", {
    request,
  });
}

export async function espFlipAppInstalled(
  appId: string,
): Promise<EspAppFlipResult> {
  return invokeCommand("esp_flip_app_installed", { appId });
}

export async function espRestoreAppState(
  backup: EspAppFlipBackup,
): Promise<void> {
  return invokeCommand("esp_restore_app_state", { backup });
}

export async function graphCancelEspDiagnostics(
  requestId: string,
): Promise<void> {
  return invokeCommand("graph_cancel_esp_diagnostics", { requestId });
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


function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function isGraphAuthStatus(value: unknown): value is GraphAuthStatus {
  if (!isCommandRecord(value) || !isCommandRecord(value.capabilities)) return false;
  const capabilities = value.capabilities;
  return (
    typeof value.isAuthenticated === "boolean" &&
    isNullableCommandString(value.userPrincipalName) &&
    isNullableCommandString(value.objectId) &&
    isNullableCommandString(value.tenantId) &&
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


function decodeGraphHostCapability(
  value: unknown,
  commandName: string,
): GraphHostCapability {
  if (
    !isCommandRecord(value) ||
    typeof value.kind !== "string" ||
    !GRAPH_HOST_CAPABILITY_KINDS.has(value.kind as GraphHostCapabilityKind)
  ) {
    return invalidCommandResponse(commandName);
  }
  return value as unknown as GraphHostCapability;
}

function decodeGraphAuthStatus(
  value: unknown,
  commandName: string,
): GraphAuthStatus {
  if (!isGraphAuthStatus(value)) return invalidCommandResponse(commandName);
  return value;
}

function decodeGraphAuthAttemptResult(
  value: unknown,
  commandName: string,
): GraphAuthAttemptResult {
  if (
    !isCommandRecord(value) ||
    typeof value.outcome !== "string" ||
    !GRAPH_AUTH_ATTEMPT_OUTCOMES.has(
      value.outcome as GraphAuthAttemptOutcome,
    ) ||
    !isGraphAuthStatus(value.status) ||
    !isNullableCommandString(value.message)
  ) {
    return invalidCommandResponse(commandName);
  }
  decodeGraphHostCapability(value.capability, commandName);
  return value as unknown as GraphAuthAttemptResult;
}

function decodeGraphPermissionUpgradeResult(
  value: unknown,
  commandName: string,
): GraphPermissionUpgradeResult {
  if (
    !isCommandRecord(value) ||
    typeof value.outcome !== "string" ||
    !GRAPH_PERMISSION_UPGRADE_OUTCOMES.has(
      value.outcome as GraphPermissionUpgradeOutcome,
    ) ||
    !isGraphAuthStatus(value.status) ||
    !isNullableCommandString(value.message)
  ) {
    return invalidCommandResponse(commandName);
  }
  return value as unknown as GraphPermissionUpgradeResult;
}

function decodeGraphInteractiveOperationTicket(
  value: unknown,
  commandName: string,
): GraphInteractiveOperationTicket {
  if (
    !isCommandRecord(value) ||
    typeof value.attemptId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value.attemptId,
    )
  ) {
    return invalidCommandResponse(commandName);
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
  return invokeCommand(commandName, { kind });
}

export async function graphAuthenticate(
  attemptId: string,
): Promise<GraphAuthAttemptResult> {
  const commandName = "graph_authenticate";
  return invokeCommand(commandName, { attemptId });
}

export async function graphCancelAuthentication(
  attemptId: string,
): Promise<boolean> {
  const commandName = "graph_cancel_authentication";
  return invokeCommand(commandName, { attemptId });
}

export async function graphRequestMissingPermissions(
  attemptId: string,
): Promise<GraphPermissionUpgradeResult> {
  const commandName = "graph_request_missing_permissions";
  return invokeCommand(commandName, { attemptId });
}

export async function graphGetAuthStatus(): Promise<GraphAuthStatus> {
  const commandName = "graph_get_auth_status";
  return invokeCommand(commandName);
}

export async function graphSignOut(): Promise<void> {
  return invokeCommand("graph_sign_out");
}

export async function graphResolveGuids(
  guids: string[],
): Promise<GraphResolutionResult> {
  return invokeCommand("graph_resolve_guids", { guids });
}

export async function graphFetchAllApps(): Promise<GraphAppInfo[]> {
  return invokeCommand("graph_fetch_all_apps");
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
  return invokeCommand("macos_scan_environment");
}

export async function macosScanIntuneLogs(): Promise<MacosIntuneLogScanResult> {
  return invokeCommand("macos_scan_intune_logs");
}

export async function macosListProfiles(): Promise<MacosProfilesResult> {
  return invokeCommand("macos_list_profiles");
}

export async function macosInspectDefender(): Promise<MacosDefenderResult> {
  return invokeCommand("macos_inspect_defender");
}

export async function macosListPackages(): Promise<MacosPackagesResult> {
  return invokeCommand("macos_list_packages");
}

export async function macosGetPackageInfo(
  packageId: string,
): Promise<MacosPackageInfo> {
  return invokeCommand("macos_get_package_info", {
    packageId,
  });
}

export async function macosGetPackageFiles(
  packageId: string,
): Promise<MacosPackageFiles> {
  return invokeCommand("macos_get_package_files", {
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
  return invokeCommand("macos_query_unified_log", {
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
  return invokeCommand("analyze_secureboot", {
    path: path ?? null,
  });
}

export async function rescanSecureBoot(): Promise<SecureBootAnalysisResult> {
  return invokeCommand("rescan_secureboot", {});
}

export async function runSecureBootDetection(): Promise<SecureBootAnalysisResult> {
  return invokeCommand("run_secureboot_detection", {});
}

export async function runSecureBootRemediation(): Promise<SecureBootAnalysisResult> {
  return invokeCommand("run_secureboot_remediation", {});
}

function decodeSecureBootAnalysisResult(
  value: unknown,
  commandName: string,
): SecureBootAnalysisResult {
  return decodeRecordResponse<SecureBootAnalysisResult>(value, commandName, {
    stage: (field) => typeof field === "string",
    dataSource: (field) => typeof field === "string",
    scanState: isCommandRecord,
    sessions: isCommandRecordArray,
    timeline: isCommandRecordArray,
    diagnostics: isCommandRecordArray,
    scriptResult: isNullableCommandRecord,
  });
}

const decodeSccmCaptureResult: CommandDecoder<SccmCaptureResult> = (
  value,
  commandName,
) =>
  decodeRecordResponse<SccmCaptureResult>(value, commandName, {
    bundleRoot: (field) => typeof field === "string",
    capturedAtUtc: (field) => typeof field === "string",
    roles: isStringArray,
    sources: isCommandRecordArray,
    artifactCount: isFiniteCommandNumber,
    retainedBytes: isFiniteCommandNumber,
  });

const decodeEspSessionEnvelope: CommandDecoder<EspSessionEnvelope> = (
  value,
  commandName,
) =>
  decodeRecordResponse<EspSessionEnvelope>(value, commandName, {
    sessionId: (field) => typeof field === "string",
    requestId: (field) => typeof field === "string",
    sequence: isFiniteCommandNumber,
    state: (field) => typeof field === "string",
    snapshot: isCommandRecord,
  });
const COMMAND_DECODERS = {
  open_log_file: decodeParseResult,
  parse_files_batch: decodeParseResults,
  list_log_folder: decodeFolderListingResult,
  load_markers: decodeMarkerFile,
  evtx_expand_sources: decodeEventLogSourceManifest,
  evtx_parse_manifest: decodeEventLogParseResult,
  evtx_diagnose_records: decodeDiagnosisSummary,
  build_timeline_cmd: decodeTimelineBundle,
  inspect_evidence_bundle: (value, commandName) =>
    decodeRecordResponse<EvidenceBundleDetails>(value, commandName, {
      bundleRootPath: (field) => typeof field === "string",
      metadata: isCommandRecord,
      manifestContent: (field) => typeof field === "string",
      artifacts: isCommandRecordArray,
      expectedEvidence: isCommandRecordArray,
      observedGaps: isStringArray,
      priorityQuestions: isStringArray,
    }),
  inspect_evidence_artifact: (value, commandName) =>
    decodeRecordResponse<EvidenceArtifactPreview>(value, commandName, {
      path: (field) => typeof field === "string",
      intakeKind: isEvidenceArtifactIntakeKind,
      summary: (field) => typeof field === "string",
      registrySnapshot: isNullableRegistrySnapshotSummary,
      eventLogExport: isNullableEvidenceEventLogExportPreview,
    }),
  parse_registry_file: (value, commandName) =>
    decodeRecordResponse<RegistryParseResult>(value, commandName, {
      keys: isCommandRecordArray,
      filePath: (field) => typeof field === "string",
      fileSize: isFiniteCommandNumber,
      totalKeys: isFiniteCommandNumber,
      totalValues: isFiniteCommandNumber,
      parseErrors: isFiniteCommandNumber,
    }),
  get_known_log_sources: (value, commandName) =>
    decodeRecordArrayResponse<KnownSourceMetadata[]>(value, commandName, {
      id: (field) => typeof field === "string",
      label: (field) => typeof field === "string",
      description: (field) => typeof field === "string",
      platform: (field) => typeof field === "string",
      sourceKind: isLogSourceKind,
      source: isLogSourceResponse,
      filePatterns: isStringArray,
    }),
  open_log_folder_aggregate: decodeAggregateParseResult,
  start_tail: decodeUnitResponse,
  stop_tail: decodeUnitResponse,
  pause_tail: decodeUnitResponse,
  resume_tail: decodeUnitResponse,
  analyze_intune_logs: (value, commandName) =>
    decodeRecordResponse<IntuneAnalysisResult>(value, commandName, {
      events: isCommandRecordArray,
      downloads: isCommandRecordArray,
      summary: isCommandRecord,
      diagnostics: isCommandRecordArray,
      sourceFile: (field) => typeof field === "string",
      sourceFiles: isStringArray,
      diagnosticsCoverage: isCommandRecord,
      diagnosticsConfidence: isCommandRecord,
      repeatedFailures: isCommandRecordArray,
      guidRegistry: isCommandRecord,
    }),
  analyze_sysmon_logs: (value, commandName) =>
    decodeRecordResponse<SysmonAnalysisResult>(value, commandName, {
      events: isCommandRecordArray,
      summary: isCommandRecord,
      config: isCommandRecord,
      dashboard: isCommandRecord,
      sourcePath: (field) => typeof field === "string",
    }),
  analyze_dsregcmd: (value, commandName) =>
    decodeRecordResponse<DsregcmdAnalysisResult>(value, commandName, {
      facts: isCommandRecord,
      derived: isCommandRecord,
      diagnostics: isCommandRecordArray,
      policyEvidence: isCommandRecord,
      osVersion: isNullableCommandRecord,
      proxyEvidence: isNullableCommandRecord,
      enrollmentEvidence: isNullableCommandRecord,
      activeEvidence: isNullableCommandRecord,
      scheduledTaskEvidence: isNullableCommandRecord,
      eventLogAnalysis: isNullableCommandRecord,
    }),
  capture_dsregcmd: (value, commandName) =>
    decodeRecordResponse<DsregcmdCaptureResult>(value, commandName, {
      input: (field) => typeof field === "string",
      bundlePath: isNullableCommandString,
      evidenceFilePath: isNullableCommandString,
    }),
  inspect_path_kind: decodePathKindResponse,
  write_text_output_file: decodeUnitResponse,
  load_dsregcmd_source: (value, commandName) =>
    decodeRecordResponse<DsregcmdResolvedSource>(value, commandName, {
      input: (field) => typeof field === "string",
      bundlePath: isNullableCommandString,
      resolvedPath: isNullableCommandString,
      evidenceFilePath: isNullableCommandString,
    }),
  get_initial_file_paths: decodeStringArrayResponse,
  get_initial_workspace: decodeNullableWorkspaceIdResponse,
  get_app_elevation_state: (value, commandName) =>
    decodeRecordResponse<AppElevationState>(value, commandName, {
      platformSupported: (field) => typeof field === "boolean",
      isElevated: (field) => typeof field === "boolean",
    }),
  restart_as_administrator: (value, commandName) =>
    decodeRecordResponse<RelaunchResult>(value, commandName, {
      launched: (field) => typeof field === "boolean",
      reason: (field) => typeof field === "string",
    }),
  get_initial_elevation_restore: (value, commandName) =>
    decodeNullableRecordResponse<RestoreTicket>(value, commandName, {
      schemaVersion: isFiniteCommandNumber,
      ticketId: (field) => typeof field === "string",
      createdAtMs: isFiniteCommandNumber,
      originPid: isFiniteCommandNumber,
      workspace: isWorkspaceIdValue,
      target: isCommandRecord,
      reason: (field) => typeof field === "string",
      retryAttempted: (field) => typeof field === "boolean",
    }),
  get_available_workspaces: decodeWorkspaceIdArrayResponse,
  discover_sccm_environment: (value, commandName) =>
    decodeRecordResponse<SccmEnvironmentDiscovery>(value, commandName, {
      supported: (field) => typeof field === "boolean",
      configmgrVersion: isNullableCommandString,
      roles: isCommandRecordArray,
      sources: isCommandRecordArray,
      issues: isCommandRecordArray,
      advancedSources: isCommandRecordArray,
    }),
  capture_sccm_diagnostics: decodeSccmCaptureResult,
  authorize_sccm_advanced_capture: (value, commandName) =>
    decodeRecordResponse<SccmAdvancedCaptureCapability>(value, commandName, {
      capabilityHandle: (field) => typeof field === "string",
      cardId: (field) => typeof field === "string",
      cardVersion: (field) => typeof field === "string",
      sourceId: (field) => typeof field === "string",
      roleScope: (field) => typeof field === "string",
      pathClass: (field) => typeof field === "string",
      sourceVersion: isNullableCommandString,
    }),
  capture_sccm_advanced_diagnostics: decodeSccmCaptureResult,
  cancel_sccm_advanced_capture: decodeUnitResponse,
  reveal_in_file_manager: decodeUnitResponse,
  get_update_policy: (value, commandName) =>
    decodeRecordResponse<UpdatePolicy>(value, commandName, {
      updateChecksDisabledByPolicy: (field) => typeof field === "boolean",
    }),
  check_dns_logging_status: (value, commandName) =>
    decodeRecordResponse<DnsLoggingStatus>(value, commandName, {
      dnsServerInstalled: (field) => typeof field === "boolean",
      debugLoggingEnabled: (field) => typeof field === "boolean",
      logFilePath: isNullableCommandString,
      dhcpServerInstalled: (field) => typeof field === "boolean",
    }),
  enable_dns_debug_logging: decodeStringResponse,
  collect_dns_dhcp_from_domain: (value, commandName) =>
    decodeRecordResponse<DnsDhcpCollectionResult>(value, commandName, {
      bundlePath: (field) => typeof field === "string",
      servers: isCommandRecordArray,
      totalFiles: isFiniteCommandNumber,
      totalBytes: isFiniteCommandNumber,
      durationMs: isFiniteCommandNumber,
    }),
  get_file_association_prompt_status: (value, commandName) =>
    decodeRecordResponse<FileAssociationPromptStatus>(value, commandName, {
      supported: (field) => typeof field === "boolean",
      shouldPrompt: (field) => typeof field === "boolean",
      isAssociated: (field) => typeof field === "boolean",
    }),
  associate_log_files_with_app: decodeUnitResponse,
  set_file_association_prompt_suppressed: decodeUnitResponse,
  get_system_date_time_preferences: (value, commandName) =>
    decodeRecordResponse<SystemDateTimePreferences>(value, commandName, {
      datePattern: (field) => typeof field === "string",
      timePattern: (field) => typeof field === "string",
      amDesignator: isNullableCommandString,
      pmDesignator: isNullableCommandString,
    }),
  collect_diagnostics: (value, commandName) =>
    decodeRecordResponse<CollectionResult>(value, commandName, {
      bundlePath: (field) => typeof field === "string",
      bundleId: (field) => typeof field === "string",
      artifactCounts: isCommandRecord,
      durationMs: isFiniteCommandNumber,
      gaps: isCommandRecordArray,
    }),
  get_esp_elevation_state: (value, commandName) =>
    decodeRecordResponse<EspElevationState>(value, commandName, {
      isElevated: (field) => typeof field === "boolean",
      restartSupported: (field) => typeof field === "boolean",
      restrictedSources: isStringArray,
    }),
  analyze_esp_evidence: (value, commandName) =>
    decodeRecordResponse<EspDiagnosticsSnapshot>(value, commandName, {
      schemaVersion: isFiniteCommandNumber,
      scenario: (field) => typeof field === "string",
      phase: (field) => typeof field === "string",
      generatedAtUtc: (field) => typeof field === "string",
      elevation: isCommandRecord,
      identity: isCommandRecord,
      profile: isNullableCommandRecord,
      enrollments: isCommandRecordArray,
      sessions: isCommandRecordArray,
      workloads: isCommandRecordArray,
      installerCorrelations: isCommandRecordArray,
      nodeCache: isCommandRecordArray,
      registrationEvents: isCommandRecordArray,
      deliveryOptimization: isNullableCommandRecord,
      hardware: isNullableCommandRecord,
      activity: isCommandRecordArray,
      findings: isCommandRecordArray,
      coverage: isCommandRecordArray,
      rawEvidence: isCommandRecordArray,
      graph: isNullableCommandRecord,
    }),
  export_esp_session: decodeUnitResponse,
  start_esp_diagnostics_session: decodeEspSessionEnvelope,
  get_esp_diagnostics_session: decodeEspSessionEnvelope,
  stop_esp_diagnostics_session: decodeUnitResponse,
  restart_esp_as_administrator: (value, commandName) =>
    decodeRecordResponse<EspRelaunchResult>(value, commandName, {
      launched: (field) => typeof field === "boolean",
      reason: (field) => typeof field === "string",
    }),
  graph_fetch_esp_diagnostics: (value, commandName) =>
    decodeRecordResponse<EspGraphOverlay>(value, commandName, {
      requestId: (field) => typeof field === "string",
      requestedAtUtc: (field) => typeof field === "string",
      deviceMatch: isCommandRecord,
      autopilotIdentity: isCommandRecord,
      deploymentProfile: isCommandRecord,
      intendedDeploymentProfile: isCommandRecord,
      profileAssignments: isCommandRecord,
      autopilotEvents: isCommandRecord,
      enrollmentConfiguration: isCommandRecord,
      apps: isCommandRecord,
      policies: isCommandRecord,
      scripts: isCommandRecord,
    }),
  esp_flip_app_installed: (value, commandName) =>
    decodeRecordResponse<EspAppFlipResult>(value, commandName, {
      appId: (field) => typeof field === "string",
      installationState: isFiniteCommandNumber,
      backup: isCommandRecord,
    }),
  esp_restore_app_state: decodeUnitResponse,
  graph_cancel_esp_diagnostics: decodeUnitResponse,
  graph_reserve_interactive_operation: decodeGraphInteractiveOperationTicket,
  graph_authenticate: decodeGraphAuthAttemptResult,
  graph_cancel_authentication: decodeBooleanResponse,
  graph_request_missing_permissions: decodeGraphPermissionUpgradeResult,
  graph_get_auth_status: decodeGraphAuthStatus,
  graph_sign_out: decodeUnitResponse,
  graph_resolve_guids: (value, commandName) =>
    decodeRecordResponse<GraphResolutionResult>(value, commandName, {
      resolved: isCommandRecord,
      notFound: isStringArray,
      errors: isStringArray,
    }),
  graph_fetch_all_apps: (value, commandName) =>
    decodeRecordArrayResponse<GraphAppInfo[]>(value, commandName, {
      id: (field) => typeof field === "string",
      displayName: (field) => typeof field === "string",
      publisher: isNullableCommandString,
      odataType: isNullableCommandString,
    }),
  macos_scan_environment: (value, commandName) =>
    decodeRecordResponse<MacosDiagEnvironment>(value, commandName, {
      macosVersion: (field) => typeof field === "string",
      macosBuild: (field) => typeof field === "string",
      fullDiskAccess: (field) => typeof field === "string",
      tools: isCommandRecord,
      directories: isCommandRecord,
      summary: (field) => typeof field === "string",
    }),
  macos_scan_intune_logs: (value, commandName) =>
    decodeRecordResponse<MacosIntuneLogScanResult>(value, commandName, {
      files: isCommandRecordArray,
      scannedDirectories: isStringArray,
      totalSizeBytes: isFiniteCommandNumber,
    }),
  macos_list_profiles: (value, commandName) =>
    decodeRecordResponse<MacosProfilesResult>(value, commandName, {
      profiles: isCommandRecordArray,
      enrollmentStatus: isCommandRecord,
      rawOutput: (field) => typeof field === "string",
    }),
  macos_inspect_defender: (value, commandName) =>
    decodeRecordResponse<MacosDefenderResult>(value, commandName, {
      health: isNullableCommandRecord,
      logFiles: isCommandRecordArray,
      diagFiles: isCommandRecordArray,
    }),
  macos_list_packages: (value, commandName) =>
    decodeRecordResponse<MacosPackagesResult>(value, commandName, {
      packages: isCommandRecordArray,
      totalCount: isFiniteCommandNumber,
      microsoftCount: isFiniteCommandNumber,
    }),
  macos_get_package_info: (value, commandName) =>
    decodeRecordResponse<MacosPackageInfo>(value, commandName, {
      packageId: (field) => typeof field === "string",
      version: (field) => typeof field === "string",
      volume: isNullableCommandString,
      location: isNullableCommandString,
      installTime: isNullableCommandString,
    }),
  macos_get_package_files: (value, commandName) =>
    decodeRecordResponse<MacosPackageFiles>(value, commandName, {
      packageId: (field) => typeof field === "string",
      files: isStringArray,
      fileCount: isFiniteCommandNumber,
    }),
  macos_query_unified_log: (value, commandName) =>
    decodeRecordResponse<MacosUnifiedLogResult>(value, commandName, {
      entries: isCommandRecordArray,
      totalMatched: isFiniteCommandNumber,
      capped: (field) => typeof field === "boolean",
      resultCap: isFiniteCommandNumber,
      predicateUsed: (field) => typeof field === "string",
      timeRange: isNullableCommandRecord,
    }),
  analyze_secureboot: decodeSecureBootAnalysisResult,
  rescan_secureboot: decodeSecureBootAnalysisResult,
  run_secureboot_detection: decodeSecureBootAnalysisResult,
  run_secureboot_remediation: decodeSecureBootAnalysisResult,
} satisfies Record<string, CommandDecoder<unknown>>;

type CommandName = keyof typeof COMMAND_DECODERS;
type CommandResponse<Name extends CommandName> = ReturnType<
  (typeof COMMAND_DECODERS)[Name]
>;
