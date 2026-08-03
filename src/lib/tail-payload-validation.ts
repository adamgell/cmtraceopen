import type {
  ErrorCodeSpan,
  LogEntry,
  LogFormat,
  ParserImplementation,
  ParserKind,
  ParserSelectionInfo,
  Severity,
  TailEntryAmendment,
  TailPayload,
} from "../types/log";

const SEVERITIES = new Set<Severity>(["Success", "Info", "Warning", "Error"]);
const LOG_FORMATS = new Set<LogFormat>([
  "Ccm",
  "Simple",
  "Plain",
  "Timestamped",
  "DnsDebug",
  "DnsAudit",
  "CmtLog",
]);
const PARSER_KINDS = new Set<ParserKind>([
  "ccm",
  "simple",
  "timestamped",
  "plain",
  "iisW3c",
  "panther",
  "cbs",
  "dism",
  "reportingEvents",
  "msi",
  "psadtLegacy",
  "intuneMacOs",
  "intuneDeviceInventory",
  "dhcp",
  "burn",
  "patchMyPcDetection",
  "registry",
  "secureBootLog",
  "dnsDebug",
  "dnsAudit",
  "cmtLog",
  "companyPortal",
]);
const PARSER_IMPLEMENTATIONS = new Set<ParserImplementation>([
  "ccm",
  "simple",
  "genericTimestamped",
  "iisW3c",
  "reportingEvents",
  "plainText",
  "msi",
  "psadtLegacy",
  "intuneMacOs",
  "intuneDeviceInventory",
  "dhcp",
  "burn",
  "patchMyPcDetection",
  "registry",
  "secureBootLog",
  "dnsDebug",
  "dnsAudit",
  "cmtLog",
  "companyPortal",
]);
const PARSER_PROVENANCES = new Set(["dedicated", "heuristic", "fallback"]);
const PARSE_QUALITIES = new Set([
  "structured",
  "semiStructured",
  "textFallback",
]);
const RECORD_FRAMINGS = new Set(["physicalLine", "logicalRecord"]);
const DATE_ORDERS = new Set(["monthFirst", "dayFirst"]);
const PARSER_SPECIALIZATIONS = new Set([
  "ime",
  "intuneDeviceInventoryHarvester",
  "intuneDeviceInventoryAdaptor",
  "intuneDeviceInventoryRotationFailure",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeInteger(value: unknown, minimum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isErrorCodeSpan(value: unknown): value is ErrorCodeSpan {
  return (
    isRecord(value) &&
    isSafeInteger(value.start, 0) &&
    isSafeInteger(value.end, 1) &&
    value.end > value.start &&
    typeof value.codeHex === "string" &&
    typeof value.codeDecimal === "string" &&
    typeof value.description === "string" &&
    typeof value.category === "string"
  );
}

function isLogEntry(value: unknown): value is LogEntry {
  return (
    isRecord(value) &&
    isSafeInteger(value.id, 0) &&
    isSafeInteger(value.lineNumber, 1) &&
    typeof value.message === "string" &&
    isNullableString(value.component) &&
    (value.timestamp === null ||
      (typeof value.timestamp === "number" && Number.isFinite(value.timestamp))) &&
    isNullableString(value.timestampDisplay) &&
    typeof value.severity === "string" &&
    SEVERITIES.has(value.severity as Severity) &&
    (value.thread === null || isSafeInteger(value.thread, 0)) &&
    isNullableString(value.threadDisplay) &&
    isNullableString(value.sourceFile) &&
    typeof value.format === "string" &&
    LOG_FORMATS.has(value.format as LogFormat) &&
    typeof value.filePath === "string" &&
    value.filePath.length > 0 &&
    (value.timezoneOffset === null || Number.isSafeInteger(value.timezoneOffset)) &&
    (value.errorCodeSpans === undefined ||
      (Array.isArray(value.errorCodeSpans) &&
        value.errorCodeSpans.every(isErrorCodeSpan)))
  );
}

function isTailEntryAmendment(value: unknown): value is TailEntryAmendment {
  if (
    !isRecord(value) ||
    !isSafeInteger(value.entryId, 0) ||
    !isSafeInteger(value.entryLineNumber, 1) ||
    !isSafeInteger(value.continuationStartLine, 1) ||
    !isSafeInteger(value.continuationEndLine, value.continuationStartLine) ||
    !isSafeInteger(value.messageUtf16Start, 0) ||
    typeof value.messageSuffix !== "string" ||
    !value.messageSuffix.startsWith("\n") ||
    !Array.isArray(value.errorCodeSpans) ||
    !value.errorCodeSpans.every(isErrorCodeSpan)
  ) {
    return false;
  }

  const physicalLineCount =
    value.continuationEndLine - value.continuationStartLine + 1;
  return value.messageSuffix.split("\n").length - 1 === physicalLineCount;
}

function isParserSelection(value: unknown): value is ParserSelectionInfo {
  return (
    isRecord(value) &&
    typeof value.parser === "string" &&
    PARSER_KINDS.has(value.parser as ParserKind) &&
    typeof value.implementation === "string" &&
    PARSER_IMPLEMENTATIONS.has(value.implementation as ParserImplementation) &&
    typeof value.provenance === "string" &&
    PARSER_PROVENANCES.has(value.provenance) &&
    typeof value.parseQuality === "string" &&
    PARSE_QUALITIES.has(value.parseQuality) &&
    typeof value.recordFraming === "string" &&
    RECORD_FRAMINGS.has(value.recordFraming) &&
    (value.dateOrder === null ||
      (typeof value.dateOrder === "string" && DATE_ORDERS.has(value.dateOrder))) &&
    (value.specialization === undefined ||
      value.specialization === null ||
      (typeof value.specialization === "string" &&
        PARSER_SPECIALIZATIONS.has(value.specialization)))
  );
}

/** Validate the Tauri event boundary before any payload reaches application state. */
export function parseTailPayload(value: unknown): TailPayload | null {
  if (
    !isRecord(value) ||
    !Array.isArray(value.entries) ||
    !value.entries.every(isLogEntry) ||
    !Array.isArray(value.amendments) ||
    !value.amendments.every(isTailEntryAmendment) ||
    typeof value.filePath !== "string" ||
    value.filePath.length === 0 ||
    !isSafeInteger(value.parseErrors, 0) ||
    (value.observedThroughLine !== null &&
      !isSafeInteger(value.observedThroughLine, 1)) ||
    (value.parserSelection !== undefined &&
      !isParserSelection(value.parserSelection)) ||
    typeof value.reset !== "boolean"
  ) {
    return null;
  }

  return value as unknown as TailPayload;
}
