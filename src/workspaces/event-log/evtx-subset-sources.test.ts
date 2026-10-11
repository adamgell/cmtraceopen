import { describe, expect, it } from "vitest";
import {
  describeSkippedRecords,
  eventRecordIdText,
  planEvtxSubsetSources,
  summarizeEvtxSubsetResult,
} from "./evtx-subset-sources";
import type { EvtxSubsetFileResult } from "../../lib/commands";
import type { EvtxRecord } from "./types";

const record = (partial: Partial<EvtxRecord> = {}): EvtxRecord => ({
  id: 1,
  eventRecordId: 1,
  timestamp: "2026-08-09T12:00:00Z",
  timestampEpoch: 0,
  provider: "Provider",
  channel: "System",
  eventId: 1,
  level: "Error",
  computer: "HOST",
  message: "event",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "Live",
  ...partial,
});

describe("eventRecordIdText", () => {
  it("prefers the lossless text over the number", () => {
    expect(
      eventRecordIdText(record({ eventRecordId: 9007199254740992, eventRecordIdText: "9007199254740993" })),
    ).toBe("9007199254740993");
  });

  it("falls back to a safe positive number and treats zero as no identity", () => {
    expect(eventRecordIdText(record({ eventRecordId: 42 }))).toBe("42");
    expect(eventRecordIdText(record({ eventRecordId: 0 }))).toBeNull();
    expect(eventRecordIdText(record({ eventRecordId: Number.NaN }))).toBeNull();
    expect(eventRecordIdText(record({ eventRecordId: 2 ** 60 }))).toBeNull();
  });

  it("ignores text that is not a plain decimal", () => {
    expect(eventRecordIdText(record({ eventRecordId: 7, eventRecordIdText: "0x10" }))).toBe("7");
    expect(eventRecordIdText(record({ eventRecordId: 7, eventRecordIdText: "-3" }))).toBe("7");
  });
});

describe("planEvtxSubsetSources", () => {
  it("groups live records by the channel they were read from, not by the Live label", () => {
    const plan = planEvtxSubsetSources([
      record({ channel: "System", eventRecordId: 5 }),
      record({ channel: "Application", eventRecordId: 2 }),
      record({ channel: "System", eventRecordId: 6 }),
    ]);
    expect(plan.sources).toEqual([
      { kind: "channel", path: "Application", recordIds: ["2"], recordCount: 1 },
      { kind: "channel", path: "System", recordIds: ["5", "6"], recordCount: 2 },
    ]);
    expect(plan.exportableRecords).toBe(3);
    expect(plan.skipped).toEqual([]);
  });

  it("groups file records by their .evtx path and sends the XML record id", () => {
    const path = "C:\\logs\\Setup.evtx";
    const plan = planEvtxSubsetSources([
      record({ sourceLabel: path, eventRecordId: 10, eventRecordIdText: "10" }),
      record({ sourceLabel: path, eventRecordId: 11, eventRecordIdText: "9007199254740993" }),
    ]);
    expect(plan.sources).toEqual([
      { kind: "file", path, recordIds: ["10", "9007199254740993"], recordCount: 2 },
    ]);
  });

  it("sends each id once and treats sources that differ only by case as one", () => {
    const plan = planEvtxSubsetSources([
      record({ channel: "System", eventRecordId: 5 }),
      record({ channel: "system", eventRecordId: 5 }),
      record({ channel: "SYSTEM", eventRecordId: 6 }),
    ]);
    expect(plan.sources).toHaveLength(1);
    expect(plan.sources[0].path).toBe("System");
    expect(plan.sources[0].recordIds).toEqual(["5", "6"]);
  });

  it("counts, by reason, what cannot be exported instead of dropping it", () => {
    const plan = planEvtxSubsetSources([
      record({ channel: "System", eventRecordId: 1 }),
      record({ originKind: "log", sourceLabel: "C:\\logs\\setup.log" }),
      record({ originKind: "log", sourceLabel: "C:\\logs\\other.log" }),
      record({ sourceLabel: "Remote: SRV01", eventRecordId: 3 }),
      record({ sourceLabel: "C:\\logs\\bundle.zip::logs\\System.evtx", eventRecordId: 4 }),
      record({ sourceLabel: "C:\\logs\\Notes.txt", eventRecordId: 5 }),
      record({ channel: "System", eventRecordId: 0 }),
    ]);
    expect(plan.exportableRecords).toBe(1);
    expect(plan.skippedRecords).toBe(6);
    expect(plan.skipped).toEqual([
      { reason: "remote", records: 1 },
      { reason: "archive", records: 1 },
      { reason: "textLog", records: 2 },
      { reason: "notEvtx", records: 1 },
      { reason: "noRecordId", records: 1 },
    ]);
    expect(plan.skipped.map(describeSkippedRecords)).toEqual([
      "1 event from a remote machine (remote export is not supported)",
      "1 event read from inside an archive (an archive member has no .evtx file of its own)",
      "2 text log lines (not Windows events)",
      "1 event not read from an .evtx file",
      "1 event without an EventRecordID (they cannot be selected by ID)",
    ]);
  });

  it("returns an empty plan for no records", () => {
    expect(planEvtxSubsetSources([])).toEqual({
      sources: [],
      skipped: [],
      exportableRecords: 0,
      skippedRecords: 0,
    });
  });

  it("accepts an upper-case .EVTX extension", () => {
    const plan = planEvtxSubsetSources([
      record({ sourceLabel: "C:\\logs\\System.EVTX", eventRecordId: 1 }),
    ]);
    expect(plan.sources.map((source) => source.kind)).toEqual(["file"]);
  });
});

const file = (partial: Partial<EvtxSubsetFileResult> = {}): EvtxSubsetFileResult => ({
  kind: "channel",
  sourcePath: "System",
  fileName: "System-subset.evtx",
  outputPath: "C:\\out\\System-subset.evtx",
  requestedRecords: 3,
  status: "exported",
  exportedRecords: 3,
  messagesArchived: true,
  error: null,
  warnings: [],
  ...partial,
});

describe("summarizeEvtxSubsetResult", () => {
  it("counts verified events when every file exported", () => {
    expect(
      summarizeEvtxSubsetResult({
        folder: "C:\\out",
        files: [file(), file({ fileName: "b", outputPath: "b", requestedRecords: 1, exportedRecords: 1 })],
      }),
    ).toBe("Exported 2 EVTX subset files (4 events).");
  });

  it("says when a count could not be verified rather than presenting the request as fact", () => {
    expect(
      summarizeEvtxSubsetResult({
        folder: "C:\\out",
        files: [file({ exportedRecords: null, requestedRecords: 5 })],
      }),
    ).toBe("Exported 1 EVTX subset file (5 events, counts not verified).");
  });

  it("names failures, and the all-failed case exports nothing", () => {
    const failed = file({ status: "failed", exportedRecords: null, error: "denied" });
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [file(), failed] })).toBe(
      "Exported 1 of 2 EVTX subset files (3 events); 1 failed.",
    );
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [failed] })).toBe(
      "Nothing was exported: 1 EVTX subset file failed.",
    );
  });
});
