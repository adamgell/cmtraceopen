import type { EvtxRecord } from "./types";

export const EVTX_EXPORT_FORMATS = [
  { value: "csv", label: "CSV", extension: "csv" },
  { value: "tsv", label: "TSV", extension: "tsv" },
  { value: "json", label: "JSON", extension: "json" },
  { value: "xml", label: "Event XML", extension: "xml" },
  { value: "html", label: "HTML", extension: "html" },
  { value: "rawXml", label: "Raw Event XML", extension: "xml" },
] as const;

export type EvtxExportFormat = (typeof EVTX_EXPORT_FORMATS)[number];
export type EvtxExportFormatValue = EvtxExportFormat["value"];

/**
 * Decoded bytes per IPC call. Base64 expands this to at most 5.34 MiB, leaving ample room below
 * Tauri's 64 MiB JSON message ceiling even after the command envelope is encoded.
 */
export const MAX_EXPORT_CHUNK_BYTES = 4 * 1024 * 1024;
export const MAX_EXPORT_CHUNK_RECORDS = 1_000;

export interface EvtxExportChunk {
  payloadBase64: string;
  decodedBytes: number;
  completedRecords: number;
}

type EvtxReducedRecord = Omit<EvtxRecord, "rawXml" | "eventData">;
const REDUCED_EXPORT_FORMATS = new Set<EvtxExportFormatValue>([
  "csv",
  "tsv",
  "html",
]);

function projectRecord(
  format: EvtxExportFormatValue,
  record: EvtxRecord,
): EvtxRecord | EvtxReducedRecord {
  if (!REDUCED_EXPORT_FORMATS.has(format)) return record;
  const { rawXml: _rawXml, eventData: _eventData, ...projected } = record;
  return projected;
}

function utf8CodePointWidth(value: string, index: number): {
  codeUnits: number;
  bytes: number;
} {
  const first = value.charCodeAt(index);
  if (first <= 0x7f) return { codeUnits: 1, bytes: 1 };
  if (first <= 0x7ff) return { codeUnits: 1, bytes: 2 };
  if (first >= 0xd800 && first <= 0xdbff) {
    const second = value.charCodeAt(index + 1);
    if (second >= 0xdc00 && second <= 0xdfff) {
      return { codeUnits: 2, bytes: 4 };
    }
  }
  // TextEncoder replaces lone surrogates with U+FFFD, which is three UTF-8 bytes.
  return { codeUnits: 1, bytes: 3 };
}

function takeUtf8Prefix(
  value: string,
  start: number,
  byteBudget: number,
): { end: number; bytes: number } {
  let end = start;
  let bytes = 0;
  while (end < value.length) {
    const next = utf8CodePointWidth(value, end);
    if (bytes + next.bytes > byteBudget) break;
    bytes += next.bytes;
    end += next.codeUnits;
  }
  return { end, bytes };
}

function bytesToBase64(bytes: Uint8Array): string {
  const parts: string[] = [];
  const blockSize = 32 * 1024;
  for (let offset = 0; offset < bytes.length; offset += blockSize) {
    parts.push(String.fromCharCode(...bytes.subarray(offset, offset + blockSize)));
  }
  return btoa(parts.join(""));
}

function encodeChunk(
  parts: string[],
  expectedBytes: number,
  completedRecords: number,
): EvtxExportChunk {
  const bytes = new TextEncoder().encode(parts.join(""));
  if (bytes.byteLength !== expectedBytes) {
    throw new Error("event export UTF-8 accounting invariant failed");
  }
  return {
    payloadBase64: bytesToBase64(bytes),
    decodedBytes: bytes.byteLength,
    completedRecords,
  };
}

/**
 * Lazily projects records into canonical NDJSON and emits bounded base64 envelopes. A record may
 * span calls, so the transport has no event-count or single-event-size ceiling. The backend owns
 * the reassembled spool and treats only fully parsed NDJSON records as authoritative.
 */
export function* exportPayloadChunks(
  format: EvtxExportFormatValue,
  records: Iterable<EvtxRecord>,
): Generator<EvtxExportChunk> {
  let parts: string[] = [];
  let decodedBytes = 0;
  let completedRecords = 0;

  const flush = (): EvtxExportChunk => {
    const chunk = encodeChunk(parts, decodedBytes, completedRecords);
    parts = [];
    decodedBytes = 0;
    completedRecords = 0;
    return chunk;
  };

  for (const record of records) {
    const line = `${JSON.stringify(projectRecord(format, record))}\n`;
    let offset = 0;
    while (offset < line.length) {
      if (
        decodedBytes === MAX_EXPORT_CHUNK_BYTES ||
        completedRecords === MAX_EXPORT_CHUNK_RECORDS
      ) {
        yield flush();
      }

      const budget = MAX_EXPORT_CHUNK_BYTES - decodedBytes;
      const prefix = takeUtf8Prefix(line, offset, budget);
      if (prefix.end === offset) {
        // The remaining budget can be smaller than the next multibyte code point. Flush what is
        // already staged; an empty 4 MiB envelope can always hold one code point.
        if (decodedBytes === 0) {
          throw new Error("event export UTF-8 chunking invariant failed");
        }
        yield flush();
        continue;
      }
      parts.push(line.slice(offset, prefix.end));
      decodedBytes += prefix.bytes;
      offset = prefix.end;
      if (offset === line.length) completedRecords += 1;

      if (
        decodedBytes === MAX_EXPORT_CHUNK_BYTES ||
        completedRecords === MAX_EXPORT_CHUNK_RECORDS
      ) {
        yield flush();
      }
    }
  }

  if (decodedBytes > 0) yield flush();
}
