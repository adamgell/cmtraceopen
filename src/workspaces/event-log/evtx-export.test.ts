import { describe, expect, it } from "vitest";
import {
  EVTX_EXPORT_FORMATS,
  MAX_EXPORT_CHUNK_BYTES,
  MAX_EXPORT_CHUNK_RECORDS,
  exportPayloadChunks,
} from "./evtx-export";
import type { EvtxRecord } from "./types";

const record = (partial: Partial<EvtxRecord> = {}): EvtxRecord => ({
  id: 1,
  eventRecordId: 2,
  timestamp: "2026-08-09T12:00:00Z",
  timestampEpoch: 0,
  provider: "Provider",
  channel: "Application",
  eventId: 326,
  level: "Error",
  computer: "HOST",
  message: "event",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "events.evtx",
  ...partial,
});

function decodeChunks(chunks: Array<{ payloadBase64: string }>): string {
  const binary = chunks.map((chunk) => atob(chunk.payloadBase64)).join("");
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

describe("event export invocation", () => {
  it("offers every backend format, including HTML and raw XML", () => {
    expect(EVTX_EXPORT_FORMATS.map((format) => format.value)).toEqual([
      "csv",
      "tsv",
      "json",
      "xml",
      "html",
      "rawXml",
    ]);
  });

  it("splits thousands of records into bounded row envelopes without changing order", () => {
    const records = Array.from({ length: MAX_EXPORT_CHUNK_RECORDS * 2 + 17 }, (_, index) =>
      record({ id: index + 1, eventRecordId: index + 1, message: `event-${index + 1}` })
    );

    const chunks = [...exportPayloadChunks("json", records)];

    expect(chunks.map((chunk) => chunk.completedRecords)).toEqual([
      MAX_EXPORT_CHUNK_RECORDS,
      MAX_EXPORT_CHUNK_RECORDS,
      17,
    ]);
    const decoded = decodeChunks(chunks)
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as EvtxRecord);
    expect(decoded.map((candidate) => candidate.id)).toEqual(
      records.map((candidate) => candidate.id)
    );
    for (const chunk of chunks) {
      expect(chunk.completedRecords).toBeLessThanOrEqual(MAX_EXPORT_CHUNK_RECORDS);
      expect(atob(chunk.payloadBase64).length).toBe(chunk.decodedBytes);
      expect(chunk.decodedBytes).toBeLessThanOrEqual(MAX_EXPORT_CHUNK_BYTES);
    }
  });

  it("measures multibyte UTF-8 payloads instead of JavaScript character counts", () => {
    const message = "\u754c".repeat(600_000);
    const records = Array.from({ length: 6 }, (_, index) =>
      record({ id: index + 1, eventRecordId: index + 1, message })
    );

    const chunks = [...exportPayloadChunks("json", records)];

    expect(chunks.length).toBeGreaterThan(1);
    for (const chunk of chunks) {
      expect(atob(chunk.payloadBase64).length).toBe(chunk.decodedBytes);
      expect(chunk.decodedBytes).toBeLessThanOrEqual(MAX_EXPORT_CHUNK_BYTES);
    }
  });

  it("fragments one oversized event without truncating or exceeding an IPC envelope", () => {
    const oversized = record({
      message: `before-${"x".repeat(MAX_EXPORT_CHUNK_BYTES + 1_024)}-after`,
    });

    const chunks = [...exportPayloadChunks("json", [oversized])];

    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks.slice(0, -1).every((chunk) => chunk.completedRecords === 0)).toBe(true);
    expect(chunks[chunks.length - 1]?.completedRecords).toBe(1);
    expect(chunks.every((chunk) => chunk.decodedBytes <= MAX_EXPORT_CHUNK_BYTES)).toBe(true);
    const decoded = JSON.parse(decodeChunks(chunks).trimEnd());
    expect(decoded.message).toBe(oversized.message);
  });

  it(
    "streams more than the legacy 64 MiB IPC limit through bounded ordered envelopes",
    () => {
      const message = "x".repeat(1024 * 1024);
      const records = Array.from({ length: 65 }, (_, index) =>
        record({ id: index + 1, eventRecordId: index + 1, message }),
      );
      let totalBytes = 0;
      let pendingLine = "";
      const decodedIds: number[] = [];

      for (const chunk of exportPayloadChunks("json", records)) {
        const binary = atob(chunk.payloadBase64);
        expect(binary.length).toBe(chunk.decodedBytes);
        expect(chunk.decodedBytes).toBeLessThanOrEqual(MAX_EXPORT_CHUNK_BYTES);
        totalBytes += chunk.decodedBytes;
        pendingLine += binary;
        const lines = pendingLine.split("\n");
        pendingLine = lines.pop() ?? "";
        for (const line of lines) {
          decodedIds.push((JSON.parse(line) as EvtxRecord).id);
        }
      }

      expect(totalBytes).toBeGreaterThan(64 * 1024 * 1024);
      expect(pendingLine).toBe("");
      expect(decodedIds).toEqual(records.map((candidate) => candidate.id));
    },
    30_000,
  );

  it("omits payload-heavy fields only for formats whose writers never read them", () => {
    const projectedCsv = JSON.parse(
      decodeChunks([...exportPayloadChunks("csv", [record()])]).trimEnd()
    );
    const projectedHtml = JSON.parse(
      decodeChunks([...exportPayloadChunks("html", [record()])]).trimEnd()
    );
    const projectedRawXml = JSON.parse(
      decodeChunks([...exportPayloadChunks("rawXml", [record()])]).trimEnd()
    );

    expect(projectedCsv).not.toHaveProperty("rawXml");
    expect(projectedCsv).not.toHaveProperty("eventData");
    expect(projectedHtml).not.toHaveProperty("rawXml");
    expect(projectedHtml).not.toHaveProperty("eventData");
    expect(projectedRawXml).toHaveProperty("rawXml");
  });
});
