import type { LogEntry } from "../../types/log";
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import {
  appendEventLogAnalysisChunk,
  closeEventLogAnalysisSession,
  createEventLogAnalysisSession,
  diagnoseEventLogAnalysisSession,
  eventLogAnalysisRecordForTransport,
  finalizeEventLogAnalysisSession,
  queryEventLogAnalysisTimeline,
  type EventLogAnalysisLogEntryInput,
  type EventLogAnalysisRecordInput,
  type EventLogAnalysisSessionStatus,
  type EventLogAnalysisTimelinePage,
} from "../../lib/commands";
import type { DiagnosisSummary, EvtxCoverageGap, EvtxRecord } from "./types";

export const EVENT_LOG_ANALYSIS_CHUNK_RECORD_LIMIT = 1_000;
export const EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT = 8 * 1024 * 1024;
export const EVENT_LOG_ANALYSIS_PAGE_SIZE = 1_000;
export const EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT = 256;
export const EVENT_LOG_ANALYSIS_MESSAGE_BYTE_LIMIT = 8 * 1024;

const utf8Encoder = new TextEncoder();
const LARGE_TEXT_STREAMING_PREFLIGHT_CODE_UNITS = 256 * 1024;
const COMPLETE_RECORD_WRAPPER_BYTES =
  utf8Encoder.encode('{"record":').byteLength +
  utf8Encoder.encode(',"originalSerializedBytes":null}').byteLength;
const COMPLETE_ENTRY_WRAPPER_BYTES =
  utf8Encoder.encode('{"entry":').byteLength +
  utf8Encoder.encode(',"originalSerializedBytes":null}').byteLength;

export class EventLogAnalysisCancelled extends Error {
  constructor() {
    super("Event-log analysis was superseded by newer input.");
    this.name = "EventLogAnalysisCancelled";
  }
}

export interface EventLogAnalysisResult {
  status: EventLogAnalysisSessionStatus;
  initialPage: EventLogAnalysisTimelinePage;
  diagnosis: DiagnosisSummary;
}

export interface BuildEventLogAnalysisOptions {
  records: EvtxRecord[];
  entries: LogEntry[];
  coverageGaps: EvtxCoverageGap[];
  cancelled?: () => boolean;
}

function serializedBytes(value: unknown): number {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new Error("Event-log analysis input could not be serialized.");
  }
  return utf8Encoder.encode(serialized).byteLength;
}

function checkedJsonByteTotal(total: number, additional: number): number {
  const next = total + additional;
  if (!Number.isSafeInteger(next)) {
    throw new Error(
      "Event-log analysis input byte length is not a safe integer.",
    );
  }
  return next;
}

/** Exact byte length of a string after JSON quoting, without materializing the quoted string. */
function jsonStringUtf8ByteLength(value: string): number {
  let bytes = 2;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (
      unit === 0x22 ||
      unit === 0x5c ||
      unit === 0x08 ||
      unit === 0x09 ||
      unit === 0x0a ||
      unit === 0x0c ||
      unit === 0x0d
    ) {
      bytes = checkedJsonByteTotal(bytes, 2);
    } else if (unit <= 0x1f) {
      bytes = checkedJsonByteTotal(bytes, 6);
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes = checkedJsonByteTotal(bytes, 4);
        index += 1;
      } else {
        // Well-formed JSON.stringify escapes lone UTF-16 surrogates as `\udxxx`.
        bytes = checkedJsonByteTotal(bytes, 6);
      }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      bytes = checkedJsonByteTotal(bytes, 6);
    } else if (unit <= 0x7f) {
      bytes = checkedJsonByteTotal(bytes, 1);
    } else if (unit <= 0x7ff) {
      bytes = checkedJsonByteTotal(bytes, 2);
    } else {
      bytes = checkedJsonByteTotal(bytes, 3);
    }
  }
  return bytes;
}

function jsonValueUtf8ByteLength(value: unknown): number | undefined {
  if (value === null) return 4;
  switch (typeof value) {
    case "string":
      return jsonStringUtf8ByteLength(value);
    case "number":
      return Number.isFinite(value) ? String(value).length : 4;
    case "boolean":
      return value ? 4 : 5;
    case "undefined":
    case "function":
    case "symbol":
      return undefined;
    case "bigint":
      throw new TypeError("Event-log analysis input cannot contain a BigInt.");
    case "object":
      break;
  }

  if (Array.isArray(value)) {
    let bytes = 2;
    for (let index = 0; index < value.length; index += 1) {
      const itemBytes = jsonValueUtf8ByteLength(value[index]) ?? 4;
      bytes = checkedJsonByteTotal(bytes, (index === 0 ? 0 : 1) + itemBytes);
    }
    return bytes;
  }

  let bytes = 2;
  let propertyCount = 0;
  const record = value as Record<string, unknown>;
  for (const key in record) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
    const propertyBytes = jsonValueUtf8ByteLength(record[key]);
    if (propertyBytes === undefined) continue;
    bytes = checkedJsonByteTotal(
      bytes,
      (propertyCount === 0 ? 0 : 1) +
        jsonStringUtf8ByteLength(key) +
        1 +
        propertyBytes,
    );
    propertyCount += 1;
  }
  return bytes;
}

function streamingSerializedBytes(value: unknown): number {
  const bytes = jsonValueUtf8ByteLength(value);
  if (bytes === undefined) {
    throw new Error("Event-log analysis input could not be serialized.");
  }
  return bytes;
}

function recordHasLargeText(record: EvtxRecord): boolean {
  let codeUnits =
    record.timestamp.length +
    record.provider.length +
    record.channel.length +
    record.computer.length +
    record.message.length +
    record.rawXml.length +
    record.sourceLabel.length +
    (record.eventRecordIdText?.length ?? 0) +
    (record.activityId?.length ?? 0) +
    (record.relatedActivityId?.length ?? 0) +
    (record.sessionId?.length ?? 0) +
    (record.deviceId?.length ?? 0) +
    (record.userId?.length ?? 0) +
    (record.processStartTime?.length ?? 0) +
    (record.userSid?.length ?? 0) +
    (record.keywords?.length ?? 0);
  if (codeUnits >= LARGE_TEXT_STREAMING_PREFLIGHT_CODE_UNITS) return true;
  for (const field of record.eventData) {
    codeUnits += field.name.length + field.value.length;
    if (codeUnits >= LARGE_TEXT_STREAMING_PREFLIGHT_CODE_UNITS) return true;
  }
  for (const column of record.mapped ?? []) {
    codeUnits += column.property.length + column.text.length;
    if (codeUnits >= LARGE_TEXT_STREAMING_PREFLIGHT_CODE_UNITS) return true;
  }
  return false;
}

function entryHasLargeText(entry: LogEntry): boolean {
  let codeUnits =
    entry.message.length +
    (entry.component?.length ?? 0) +
    (entry.timestampDisplay?.length ?? 0) +
    (entry.threadDisplay?.length ?? 0) +
    (entry.sourceFile?.length ?? 0) +
    entry.filePath.length +
    (entry.ipAddress?.length ?? 0) +
    (entry.hostName?.length ?? 0) +
    (entry.macAddress?.length ?? 0) +
    (entry.resultCode?.length ?? 0) +
    (entry.gleCode?.length ?? 0) +
    (entry.setupPhase?.length ?? 0) +
    (entry.operationName?.length ?? 0) +
    (entry.httpMethod?.length ?? 0) +
    (entry.uriStem?.length ?? 0) +
    (entry.uriQuery?.length ?? 0) +
    (entry.clientIp?.length ?? 0) +
    (entry.serverIp?.length ?? 0) +
    (entry.userAgent?.length ?? 0) +
    (entry.username?.length ?? 0) +
    (entry.queryName?.length ?? 0) +
    (entry.queryType?.length ?? 0) +
    (entry.responseCode?.length ?? 0) +
    (entry.dnsDirection?.length ?? 0) +
    (entry.dnsProtocol?.length ?? 0) +
    (entry.sourceIp?.length ?? 0) +
    (entry.dnsFlags?.length ?? 0) +
    (entry.zoneName?.length ?? 0) +
    (entry.sectionName?.length ?? 0) +
    (entry.sectionColor?.length ?? 0) +
    (entry.iteration?.length ?? 0);
  if (codeUnits >= LARGE_TEXT_STREAMING_PREFLIGHT_CODE_UNITS) return true;
  for (const span of entry.errorCodeSpans ?? []) {
    codeUnits +=
      span.codeHex.length +
      span.codeDecimal.length +
      span.description.length +
      span.category.length;
    if (codeUnits >= LARGE_TEXT_STREAMING_PREFLIGHT_CODE_UNITS) return true;
  }
  for (const tag of entry.tags ?? []) {
    codeUnits += tag.length;
    if (codeUnits >= LARGE_TEXT_STREAMING_PREFLIGHT_CODE_UNITS) return true;
  }
  return false;
}

function recordSerializedBytes(record: EvtxRecord): number {
  return recordHasLargeText(record)
    ? streamingSerializedBytes(record)
    : serializedBytes(record);
}

function entrySerializedBytes(entry: LogEntry): number {
  return entryHasLargeText(entry)
    ? streamingSerializedBytes(entry)
    : serializedBytes(entry);
}

function boundedOptionalAnalysisText(
  value: string | null | undefined,
): string | null | undefined {
  return value === null || value === undefined
    ? value
    : boundUtf8WithDigest(value, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
}

function boundedNullableAnalysisText(value: string | null): string | null {
  return value === null
    ? null
    : boundUtf8WithDigest(value, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
}

function projectRecordForAnalysis(record: EvtxRecord): EvtxRecord {
  return {
    id: record.id,
    eventRecordId: record.eventRecordId,
    eventRecordIdText: boundedOptionalAnalysisText(record.eventRecordIdText),
    timestamp: boundUtf8WithDigest(
      record.timestamp,
      EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
    ),
    timestampEpoch: record.timestampEpoch,
    provider: boundUtf8WithDigest(
      record.provider,
      EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
    ),
    channel: boundUtf8WithDigest(
      record.channel,
      EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
    ),
    eventId: record.eventId,
    level: record.level,
    computer: boundUtf8WithDigest(
      record.computer,
      EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
    ),
    message: boundUtf8WithDigest(
      record.message,
      EVENT_LOG_ANALYSIS_MESSAGE_BYTE_LIMIT,
    ),
    eventData: [],
    rawXml: "",
    sourceLabel: boundUtf8WithDigest(
      record.sourceLabel,
      EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
    ),
    originKind: record.originKind,
    task: record.task,
    opcode: record.opcode,
    processId: record.processId,
    activityId: boundedOptionalAnalysisText(record.activityId),
    relatedActivityId: boundedOptionalAnalysisText(record.relatedActivityId),
    sessionId: boundedOptionalAnalysisText(record.sessionId),
    deviceId: boundedOptionalAnalysisText(record.deviceId),
    userId: boundedOptionalAnalysisText(record.userId),
    processStartTime: boundedOptionalAnalysisText(record.processStartTime),
    threadId: record.threadId,
    userSid: boundedOptionalAnalysisText(record.userSid),
    keywords: boundedOptionalAnalysisText(record.keywords),
  };
}

function projectEntryForAnalysis(entry: LogEntry): LogEntry {
  return {
    id: entry.id,
    lineNumber: entry.lineNumber,
    message: boundUtf8WithDigest(
      entry.message,
      EVENT_LOG_ANALYSIS_MESSAGE_BYTE_LIMIT,
    ),
    component: boundedNullableAnalysisText(entry.component),
    timestamp: entry.timestamp,
    timestampDisplay: boundedNullableAnalysisText(entry.timestampDisplay),
    severity: entry.severity,
    thread: entry.thread,
    threadDisplay: boundedNullableAnalysisText(entry.threadDisplay),
    sourceFile: boundedNullableAnalysisText(entry.sourceFile),
    format: entry.format,
    filePath: boundUtf8WithDigest(
      entry.filePath,
      EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
    ),
    timezoneOffset: entry.timezoneOffset,
  };
}

function analysisRecordInput(record: EvtxRecord): {
  input: EventLogAnalysisRecordInput;
  serializedBytes: number;
} {
  const originalSerializedBytes = recordSerializedBytes(record);
  const transportRecord = eventLogAnalysisRecordForTransport(record);
  const transportRecordBytes =
    transportRecord === record
      ? originalSerializedBytes
      : originalSerializedBytes -
        serializedBytes(record.eventRecordId) +
        serializedBytes(transportRecord.eventRecordId);
  let input: EventLogAnalysisRecordInput = {
    record: transportRecord,
    originalSerializedBytes: null,
  };
  let inputBytes = transportRecordBytes + COMPLETE_RECORD_WRAPPER_BYTES;
  if (inputBytes + 2 <= EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT) {
    return { input, serializedBytes: inputBytes };
  }

  input = {
    record: eventLogAnalysisRecordForTransport(
      projectRecordForAnalysis(record),
    ),
    originalSerializedBytes,
  };
  inputBytes = serializedBytes(input);
  if (inputBytes + 2 > EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT) {
    throw new Error(
      "Projected event record exceeds the 8 MiB analysis transport limit.",
    );
  }
  return { input, serializedBytes: inputBytes };
}

function analysisEntryInput(entry: LogEntry): {
  input: EventLogAnalysisLogEntryInput;
  serializedBytes: number;
} {
  const originalSerializedBytes = entrySerializedBytes(entry);
  let input: EventLogAnalysisLogEntryInput = {
    entry,
    originalSerializedBytes: null,
  };
  let inputBytes = originalSerializedBytes + COMPLETE_ENTRY_WRAPPER_BYTES;
  if (inputBytes + 2 <= EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT) {
    return { input, serializedBytes: inputBytes };
  }

  input = {
    entry: projectEntryForAnalysis(entry),
    originalSerializedBytes,
  };
  inputBytes = serializedBytes(input);
  if (inputBytes + 2 > EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT) {
    throw new Error(
      "Projected text-log entry exceeds the 8 MiB analysis transport limit.",
    );
  }
  return { input, serializedBytes: inputBytes };
}

async function appendRecordChunks(
  sessionId: string,
  records: EvtxRecord[],
  cancelled: () => boolean,
): Promise<void> {
  let chunk: EventLogAnalysisRecordInput[] = [];
  let chunkBytes = 2;

  const flush = async () => {
    if (chunk.length === 0) return;
    if (cancelled()) throw new EventLogAnalysisCancelled();
    const pending = chunk;
    chunk = [];
    chunkBytes = 2;
    await appendEventLogAnalysisChunk(sessionId, pending);
  };

  for (const record of records) {
    const { input, serializedBytes: recordBytes } = analysisRecordInput(record);
    const separatorBytes = chunk.length === 0 ? 0 : 1;
    if (
      chunk.length >= EVENT_LOG_ANALYSIS_CHUNK_RECORD_LIMIT ||
      chunkBytes + separatorBytes + recordBytes >
        EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT
    ) {
      await flush();
    }
    chunk.push(input);
    chunkBytes += (chunk.length === 1 ? 0 : 1) + recordBytes;
  }
  await flush();
}

async function appendEntryChunks(
  sessionId: string,
  entries: LogEntry[],
  cancelled: () => boolean,
): Promise<void> {
  let chunk: EventLogAnalysisLogEntryInput[] = [];
  let chunkBytes = 2;

  const flush = async () => {
    if (chunk.length === 0) return;
    if (cancelled()) throw new EventLogAnalysisCancelled();
    const pending = chunk;
    chunk = [];
    chunkBytes = 2;
    await appendEventLogAnalysisChunk(sessionId, [], pending);
  };

  for (const entry of entries) {
    const { input, serializedBytes: entryBytes } = analysisEntryInput(entry);
    const separatorBytes = chunk.length === 0 ? 0 : 1;
    if (
      chunk.length >= EVENT_LOG_ANALYSIS_CHUNK_RECORD_LIMIT ||
      chunkBytes + separatorBytes + entryBytes >
        EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT
    ) {
      await flush();
    }
    chunk.push(input);
    chunkBytes += (chunk.length === 1 ? 0 : 1) + entryBytes;
  }
  await flush();
}

/**
 * Builds one backend-owned analysis session without ever placing the complete record set in a
 * Tauri command payload. The returned first page is enough to paint the timeline immediately;
 * later pages are fetched on demand by the virtualized view.
 */
export async function buildEventLogAnalysisSession({
  records,
  entries,
  coverageGaps,
  cancelled = () => false,
}: BuildEventLogAnalysisOptions): Promise<EventLogAnalysisResult> {
  const created = await createEventLogAnalysisSession();
  const sessionId = created.sessionId;
  try {
    if (cancelled()) throw new EventLogAnalysisCancelled();
    await appendRecordChunks(sessionId, records, cancelled);
    await appendEntryChunks(sessionId, entries, cancelled);
    if (cancelled()) throw new EventLogAnalysisCancelled();
    const status = await finalizeEventLogAnalysisSession(sessionId);
    if (cancelled()) throw new EventLogAnalysisCancelled();
    const [initialPage, diagnosis] = await Promise.all([
      queryEventLogAnalysisTimeline(sessionId, 0, EVENT_LOG_ANALYSIS_PAGE_SIZE),
      diagnoseEventLogAnalysisSession(sessionId, coverageGaps),
    ]);
    if (cancelled()) throw new EventLogAnalysisCancelled();
    return { status, initialPage, diagnosis };
  } catch (error) {
    await closeEventLogAnalysisSession(sessionId).catch(() => undefined);
    throw error;
  }
}
