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
const ENTRY_KINDS = new Set(["Log", "Section", "Iteration", "Header"]);
const OPTIONAL_NULLABLE_STRING_FIELDS = [
  "ipAddress",
  "hostName",
  "macAddress",
  "resultCode",
  "gleCode",
  "setupPhase",
  "operationName",
  "httpMethod",
  "uriStem",
  "uriQuery",
  "clientIp",
  "serverIp",
  "userAgent",
  "username",
  "queryName",
  "queryType",
  "responseCode",
  "dnsDirection",
  "dnsProtocol",
  "sourceIp",
  "dnsFlags",
  "zoneName",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeInteger(
  value: unknown,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= minimum &&
    (value as number) <= maximum
  );
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isOptionalNullableString(value: unknown): boolean {
  return value === undefined || isNullableString(value);
}

function isOptionalString(value: unknown): boolean {
  return value === undefined || typeof value === "string";
}

function isOptionalInteger(value: unknown, maximum: number): boolean {
  return (
    value === undefined ||
    value === null ||
    isSafeInteger(value, 0, maximum)
  );
}

function isErrorCodeSpan(
  value: unknown,
  minimumStart = 0,
  maximumEnd = Number.MAX_SAFE_INTEGER,
): value is ErrorCodeSpan {
  return (
    isRecord(value) &&
    isSafeInteger(value.start, minimumStart, maximumEnd) &&
    isSafeInteger(value.end, minimumStart + 1, maximumEnd) &&
    value.end > value.start &&
    typeof value.codeHex === "string" &&
    typeof value.codeDecimal === "string" &&
    typeof value.description === "string" &&
    typeof value.category === "string"
  );
}

function physicalEndLine(entry: LogEntry): number | null {
  const endLine = entry.lineNumber + entry.message.split("\n").length - 1;
  return isSafeInteger(endLine, entry.lineNumber, 4_294_967_295)
    ? endLine
    : null;
}

function isLogEntry(value: unknown): value is LogEntry {
  if (!isRecord(value) || typeof value.message !== "string") {
    return false;
  }
  const message = value.message;

  if (
    isSafeInteger(value.id, 0) &&
    isSafeInteger(value.lineNumber, 1, 4_294_967_295) &&
    isNullableString(value.component) &&
    (value.timestamp === null ||
      (typeof value.timestamp === "number" && Number.isFinite(value.timestamp))) &&
    isNullableString(value.timestampDisplay) &&
    typeof value.severity === "string" &&
    SEVERITIES.has(value.severity as Severity) &&
    (value.thread === null || isSafeInteger(value.thread, 0, 4_294_967_295)) &&
    isNullableString(value.threadDisplay) &&
    isNullableString(value.sourceFile) &&
    typeof value.format === "string" &&
    LOG_FORMATS.has(value.format as LogFormat) &&
    typeof value.filePath === "string" &&
    value.filePath.length > 0 &&
    (value.timezoneOffset === null ||
      isSafeInteger(value.timezoneOffset, -2_147_483_648, 2_147_483_647)) &&
    (value.errorCodeSpans === undefined ||
      (Array.isArray(value.errorCodeSpans) &&
        value.errorCodeSpans.every((span) =>
          isErrorCodeSpan(span, 0, message.length),
        ))) &&
    OPTIONAL_NULLABLE_STRING_FIELDS.every((field) =>
      isOptionalNullableString(value[field]),
    ) &&
    isOptionalInteger(value.statusCode, 65_535) &&
    isOptionalInteger(value.subStatus, 65_535) &&
    isOptionalInteger(value.timeTakenMs, Number.MAX_SAFE_INTEGER) &&
    isOptionalInteger(value.serverPort, 65_535) &&
    isOptionalInteger(value.win32Status, 4_294_967_295) &&
    isOptionalInteger(value.dnsEventId, 4_294_967_295) &&
    (value.entryKind === undefined ||
      (typeof value.entryKind === "string" &&
        ENTRY_KINDS.has(value.entryKind))) &&
    (value.whatif === undefined || typeof value.whatif === "boolean") &&
    isOptionalString(value.sectionName) &&
    isOptionalString(value.sectionColor) &&
    isOptionalString(value.iteration) &&
    (value.tags === undefined ||
      (Array.isArray(value.tags) &&
        value.tags.every((tag) => typeof tag === "string")))
  ) {
    return physicalEndLine(value as unknown as LogEntry) !== null;
  }

  return false;
}

function isTailEntryAmendment(value: unknown): value is TailEntryAmendment {
  if (
    !isRecord(value) ||
    !isSafeInteger(value.entryId, 0) ||
    !isSafeInteger(value.entryLineNumber, 1, 4_294_967_295) ||
    !isSafeInteger(value.continuationStartLine, 1, 4_294_967_295) ||
    value.continuationStartLine <= value.entryLineNumber ||
    !isSafeInteger(
      value.continuationEndLine,
      value.continuationStartLine,
      4_294_967_295,
    ) ||
    !isSafeInteger(value.messageUtf16Start, 0) ||
    typeof value.messageSuffix !== "string" ||
    !value.messageSuffix.startsWith("\n") ||
    !Array.isArray(value.errorCodeSpans)
  ) {
    return false;
  }

  const physicalLineCount =
    value.continuationEndLine - value.continuationStartLine + 1;
  const messageUtf16Start = value.messageUtf16Start;
  const messageUtf16End = messageUtf16Start + value.messageSuffix.length;
  return (
    Number.isSafeInteger(messageUtf16End) &&
    value.messageSuffix.split("\n").length - 1 === physicalLineCount &&
    value.errorCodeSpans.every((span) =>
      isErrorCodeSpan(span, messageUtf16Start, messageUtf16End),
    )
  );
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

  const payload = value as unknown as TailPayload;
  const entryEndLines = payload.entries.map(physicalEndLine);
  if (entryEndLines.some((line) => line === null)) {
    return null;
  }

  const observedRanges = [
    ...(entryEndLines as number[]),
    ...payload.amendments.map((amendment) => amendment.continuationEndLine),
  ];
  if (
    observedRanges.length > 0 &&
    (payload.observedThroughLine === null ||
      payload.observedThroughLine < Math.max(...observedRanges))
  ) {
    return null;
  }

  return payload;
}
