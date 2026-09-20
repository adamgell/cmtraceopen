import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  append: vi.fn(),
  close: vi.fn(),
  create: vi.fn(),
  diagnose: vi.fn(),
  finalize: vi.fn(),
  query: vi.fn(),
}));

vi.mock("../../lib/commands", () => ({
  appendEventLogAnalysisChunk: mocks.append,
  closeEventLogAnalysisSession: mocks.close,
  createEventLogAnalysisSession: mocks.create,
  diagnoseEventLogAnalysisSession: mocks.diagnose,
  eventLogAnalysisRecordForTransport: (record: EvtxRecord) =>
    Number.isSafeInteger(record.eventRecordId)
      ? record
      : { ...record, eventRecordId: Number.MAX_SAFE_INTEGER + 1 },
  finalizeEventLogAnalysisSession: mocks.finalize,
  queryEventLogAnalysisTimeline: mocks.query,
}));

import {
  buildEventLogAnalysisSession,
  EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT,
  EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
  EVENT_LOG_ANALYSIS_MESSAGE_BYTE_LIMIT,
} from "./event-analysis-session";
import type { LogEntry } from "../../types/log";
import type { EvtxRecord } from "./types";

const encoder = new TextEncoder();

const CREATED_STATUS = {
  sessionId: "analysis-session",
  revision: 0,
  totalItems: 0,
  eventItems: 0,
  logItems: 0,
  totalUnplaced: 0,
  totalEdges: 0,
  totalCoverageGaps: 0,
  finalized: false,
};

const FINAL_STATUS = {
  ...CREATED_STATUS,
  revision: 2,
  totalItems: 1,
  eventItems: 1,
  finalized: true,
};

function logEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    id: 7,
    lineNumber: 19,
    message: "Ordinary anchored test log message",
    component: "Example component",
    timestamp: 1_755_523_200_000,
    timestampDisplay: "08-18-2026 12:00:00.000",
    severity: "Info",
    thread: 42,
    threadDisplay: "42 (0x002A)",
    sourceFile: "example.log",
    format: "Ccm",
    filePath: "C:\\Logs\\example.log",
    timezoneOffset: 0,
    ...overrides,
  };
}

describe("buildEventLogAnalysisSession", () => {
  beforeEach(() => {
    mocks.append.mockReset().mockResolvedValue(CREATED_STATUS);
    mocks.close.mockReset().mockResolvedValue(undefined);
    mocks.create.mockReset().mockResolvedValue(CREATED_STATUS);
    mocks.finalize.mockReset().mockResolvedValue(FINAL_STATUS);
    mocks.query.mockReset().mockResolvedValue({
      ...FINAL_STATUS,
      offset: 0,
      nextOffset: null,
      serializedBytes: 1_024,
      items: [],
      unplacedPreview: [],
      edgesPreview: [],
      coverageGapsPreview: [],
    });
    mocks.diagnose.mockReset().mockResolvedValue({
      findings: [],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [],
      overview: {
        outcome: "noFindings",
        headline: "No issues detected.",
        findingCount: 0,
        actionableFindingCount: 0,
        coverageGapCount: 0,
        evidenceCount: 0,
        correlationCount: 0,
        errorTokenEventCount: 0,
      },
    });
  });

  it("projects one oversized ordinary event without mutating the source record", async () => {
    const oversizedMessage = `Example event message ${"🙂".repeat(
      Math.ceil(EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT / 4) + 1_024,
    )}`;
    const eventData = [{ name: "Payload", value: "ordinary event data" }];
    const mapped = [
      { property: "Mapped detail", text: "ordinary detail", complete: true },
    ];
    const record: EvtxRecord = {
      id: 1,
      eventRecordId: 101,
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Example Provider",
      channel: "Application",
      eventId: 42,
      level: "Information",
      computer: "TEST-PC",
      message: oversizedMessage,
      eventData,
      rawXml: "<Event><System><EventID>42</EventID></System></Event>",
      sourceLabel: "sample.evtx",
      originKind: "event",
      mapped,
    };
    const originalSerializedBytes = encoder.encode(
      JSON.stringify(record),
    ).byteLength;

    await expect(
      buildEventLogAnalysisSession({
        records: [record],
        entries: [],
        coverageGaps: [],
      }),
    ).resolves.toMatchObject({ status: FINAL_STATUS });

    expect(mocks.append).toHaveBeenCalledTimes(1);
    const outboundRecords = mocks.append.mock.calls[0][1] as Array<{
      record: EvtxRecord;
      originalSerializedBytes: number | null;
    }>;
    expect(
      encoder.encode(JSON.stringify(outboundRecords)).byteLength,
    ).toBeLessThanOrEqual(EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT);
    expect(outboundRecords).toHaveLength(1);
    expect(outboundRecords[0].originalSerializedBytes).toBe(
      originalSerializedBytes,
    );
    expect(originalSerializedBytes).toBeGreaterThan(
      EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT,
    );

    const projected = outboundRecords[0].record;
    expect(projected).not.toBe(record);
    expect(projected.provider).toBe(record.provider);
    expect(projected.channel).toBe(record.channel);
    expect(projected.eventId).toBe(record.eventId);
    expect(projected.timestampEpoch).toBe(record.timestampEpoch);
    expect(projected.level).toBe(record.level);
    expect(projected.eventRecordId).toBe(record.eventRecordId);
    expect(projected.rawXml).toBe("");
    expect(projected.eventData).toEqual([]);
    expect(Object.prototype.hasOwnProperty.call(projected, "mapped")).toBe(
      false,
    );
    expect(encoder.encode(projected.message).byteLength).toBeLessThanOrEqual(
      EVENT_LOG_ANALYSIS_MESSAGE_BYTE_LIMIT,
    );
    expect(projected.message).toMatch(/…\[truncated:[0-9a-f]{16}\]$/);

    expect(record.message).toBe(oversizedMessage);
    expect(record.rawXml).toBe(
      "<Event><System><EventID>42</EventID></System></Event>",
    );
    expect(record.eventData).toBe(eventData);
    expect(record.mapped).toBe(mapped);
  });

  it("counts a 64 MiB event exactly without stringifying or encoding the full source", async () => {
    const asciiLength = 64 * 1024 * 1024 + 1;
    const rawXmlTail = '"\\\n\ud800🙂';
    const rawXml = `${"x".repeat(asciiLength)}${rawXmlTail}`;
    const record: EvtxRecord = {
      id: 1,
      eventRecordId: 101,
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Example Provider",
      channel: "Application",
      eventId: 42,
      level: "Information",
      computer: "TEST-PC",
      message: "An ordinary event with an oversized raw XML envelope",
      eventData: [],
      rawXml,
      sourceLabel: "sample.evtx",
      originKind: "event",
    };
    const emptyRawXmlBytes = encoder.encode(
      JSON.stringify({ ...record, rawXml: "" }),
    ).byteLength;
    const tailJsonBytes = 2 + 2 + 2 + 6 + 4;
    const expectedOriginalBytes =
      emptyRawXmlBytes + asciiLength + tailJsonBytes;
    const stringify = vi.spyOn(JSON, "stringify");
    const encode = vi.spyOn(TextEncoder.prototype, "encode");

    try {
      await buildEventLogAnalysisSession({
        records: [record],
        entries: [],
        coverageGaps: [],
      });

      const outboundRecords = mocks.append.mock.calls[0][1] as Array<{
        record: EvtxRecord;
        originalSerializedBytes: number | null;
      }>;
      expect(outboundRecords[0].originalSerializedBytes).toBe(
        expectedOriginalBytes,
      );
      expect(stringify.mock.calls.some(([value]) => value === record)).toBe(
        false,
      );
      expect(encode.mock.calls.some(([value]) => value === rawXml)).toBe(false);
      expect(record.rawXml).toBe(rawXml);
      expect(record.rawXml.length).toBe(asciiLength + rawXmlTail.length);
    } finally {
      stringify.mockRestore();
      encode.mockRestore();
    }
  }, 30_000);

  it("projects one oversized text-log entry without mutating the source", async () => {
    const message = `Anchored sample message ${"🙂".repeat(
      Math.ceil(EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT / 4) + 1_024,
    )}`;
    const errorCodeSpans = [
      {
        start: 0,
        end: 10,
        codeHex: "0x80070005",
        codeDecimal: "2147942405",
        description: "Access is denied",
        category: "Win32",
      },
    ];
    const tags = ["deployment", "anchored-test"];
    const entry = logEntry({
      message,
      component: "component-".repeat(100),
      filePath: `C:\\Logs\\${"nested-".repeat(100)}example.log`,
      errorCodeSpans,
      operationName: "Apply drivers",
      tags,
    });
    const emptyMessageBytes = encoder.encode(
      JSON.stringify({ ...entry, message: "" }),
    ).byteLength;
    const expectedOriginalBytes =
      emptyMessageBytes + encoder.encode(message).byteLength;
    const stringify = vi.spyOn(JSON, "stringify");
    const encode = vi.spyOn(TextEncoder.prototype, "encode");

    try {
      await expect(
        buildEventLogAnalysisSession({
          records: [],
          entries: [entry],
          coverageGaps: [],
        }),
      ).resolves.toMatchObject({ status: FINAL_STATUS });

      expect(mocks.append).toHaveBeenCalledTimes(1);
      const outboundEntries = mocks.append.mock.calls[0][2] as Array<{
        entry: LogEntry;
        originalSerializedBytes: number | null;
      }>;
      expect(
        encoder.encode(JSON.stringify(outboundEntries)).byteLength,
      ).toBeLessThanOrEqual(EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT);
      expect(outboundEntries).toHaveLength(1);
      expect(outboundEntries[0].originalSerializedBytes).toBe(
        expectedOriginalBytes,
      );
      const projected = outboundEntries[0].entry;
      expect(projected).not.toBe(entry);
      expect(projected.id).toBe(entry.id);
      expect(projected.lineNumber).toBe(entry.lineNumber);
      expect(projected.timestamp).toBe(entry.timestamp);
      expect(projected.severity).toBe(entry.severity);
      expect(projected.sourceFile).toBe(entry.sourceFile);
      expect(encoder.encode(projected.message).byteLength).toBeLessThanOrEqual(
        EVENT_LOG_ANALYSIS_MESSAGE_BYTE_LIMIT,
      );
      expect(projected.message).toMatch(/…\[truncated:[0-9a-f]{16}\]$/);
      expect(
        encoder.encode(projected.component ?? "").byteLength,
      ).toBeLessThanOrEqual(EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
      expect(encoder.encode(projected.filePath).byteLength).toBeLessThanOrEqual(
        EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT,
      );
      expect(
        Object.prototype.hasOwnProperty.call(projected, "errorCodeSpans"),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(projected, "operationName"),
      ).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(projected, "tags")).toBe(
        false,
      );
      expect(stringify.mock.calls.some(([value]) => value === entry)).toBe(
        false,
      );
      expect(encode.mock.calls.some(([value]) => value === message)).toBe(
        false,
      );
      expect(entry.message).toBe(message);
      expect(entry.errorCodeSpans).toBe(errorCodeSpans);
      expect(entry.operationName).toBe("Apply drivers");
      expect(entry.tags).toBe(tags);
    } finally {
      stringify.mockRestore();
      encode.mockRestore();
    }
  }, 30_000);

  it("includes the exact record-wrapper overhead when splitting normal chunks", async () => {
    const baseRecord: EvtxRecord = {
      id: 1,
      eventRecordId: 101,
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Example Provider",
      channel: "Application",
      eventId: 42,
      level: "Information",
      computer: "TEST-PC",
      message: "",
      eventData: [],
      rawXml: "",
      sourceLabel: "sample.evtx",
      originKind: "event",
    };
    const emptyWrapperBytes = encoder.encode(
      JSON.stringify({ record: baseRecord, originalSerializedBytes: null }),
    ).byteLength;
    const targetWrapperBytes =
      Math.floor((EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT - 3) / 2) + 1;
    const message = "x".repeat(targetWrapperBytes - emptyWrapperBytes);
    const first = { ...baseRecord, message };
    const second = {
      ...baseRecord,
      id: 2,
      eventRecordId: 102,
      message,
    };
    const wrappers = [first, second].map((record) => ({
      record,
      originalSerializedBytes: null,
    }));

    expect(encoder.encode(JSON.stringify(wrappers[0])).byteLength).toBe(
      targetWrapperBytes,
    );
    expect(encoder.encode(JSON.stringify(wrappers)).byteLength).toBe(
      EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT + 1,
    );

    await buildEventLogAnalysisSession({
      records: [first, second],
      entries: [],
      coverageGaps: [],
    });

    expect(mocks.append).toHaveBeenCalledTimes(2);
    for (const [, outboundRecords] of mocks.append.mock.calls) {
      expect(
        encoder.encode(JSON.stringify(outboundRecords)).byteLength,
      ).toBeLessThanOrEqual(EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT);
    }
    expect(mocks.append.mock.calls[0][1]).toEqual([wrappers[0]]);
    expect(mocks.append.mock.calls[1][1]).toEqual([wrappers[1]]);
  });

  it("includes the exact entry-wrapper overhead when splitting normal chunks", async () => {
    const baseEntry = logEntry({ message: "" });
    const emptyWrapperBytes = encoder.encode(
      JSON.stringify({ entry: baseEntry, originalSerializedBytes: null }),
    ).byteLength;
    const targetWrapperBytes =
      Math.floor((EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT - 3) / 2) + 1;
    const message = "x".repeat(targetWrapperBytes - emptyWrapperBytes);
    const first = { ...baseEntry, message };
    const second = { ...baseEntry, id: 8, lineNumber: 20, message };
    const wrappers = [first, second].map((entry) => ({
      entry,
      originalSerializedBytes: null,
    }));

    expect(encoder.encode(JSON.stringify(wrappers[0])).byteLength).toBe(
      targetWrapperBytes,
    );
    expect(encoder.encode(JSON.stringify(wrappers)).byteLength).toBe(
      EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT + 1,
    );

    await buildEventLogAnalysisSession({
      records: [],
      entries: [first, second],
      coverageGaps: [],
    });

    expect(mocks.append).toHaveBeenCalledTimes(2);
    for (const [, outboundRecords, outboundEntries] of mocks.append.mock
      .calls) {
      expect(outboundRecords).toEqual([]);
      expect(
        encoder.encode(JSON.stringify(outboundEntries)).byteLength,
      ).toBeLessThanOrEqual(EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT);
    }
    expect(mocks.append.mock.calls[0][2]).toEqual([wrappers[0]]);
    expect(mocks.append.mock.calls[1][2]).toEqual([wrappers[1]]);
  });

  it("accounts for unsafe EventRecordID transport normalization before chunking", async () => {
    const unsafeEventRecordId = 1e100;
    const baseRecord: EvtxRecord = {
      id: 1,
      eventRecordId: unsafeEventRecordId,
      eventRecordIdText: `1${"0".repeat(100)}`,
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Example Provider",
      channel: "Application",
      eventId: 42,
      level: "Information",
      computer: "TEST-PC",
      message: "",
      eventData: [],
      rawXml: "",
      sourceLabel: "sample.evtx",
      originKind: "event",
    };
    const transportBase = {
      ...baseRecord,
      eventRecordId: Number.MAX_SAFE_INTEGER + 1,
    };
    const emptyTransportWrapperBytes = encoder.encode(
      JSON.stringify({
        record: transportBase,
        originalSerializedBytes: null,
      }),
    ).byteLength;
    const targetWrapperBytes =
      Math.floor((EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT - 3) / 2) + 1;
    const message = "x".repeat(targetWrapperBytes - emptyTransportWrapperBytes);
    const first = { ...baseRecord, message };
    const second = { ...baseRecord, id: 2, message };

    await buildEventLogAnalysisSession({
      records: [first, second],
      entries: [],
      coverageGaps: [],
    });

    expect(mocks.append).toHaveBeenCalledTimes(2);
    for (const [, outboundRecords] of mocks.append.mock.calls) {
      expect(
        encoder.encode(JSON.stringify(outboundRecords)).byteLength,
      ).toBeLessThanOrEqual(EVENT_LOG_ANALYSIS_CHUNK_BYTE_LIMIT);
      expect(outboundRecords[0].record.eventRecordId).toBe(
        Number.MAX_SAFE_INTEGER + 1,
      );
    }
  });
});
