import { describe, expect, it } from "vitest";
import {
  describeSkippedRecords,
  eventRecordIdText,
  fileDiffersFromRequest,
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

  it("follows the store's rule: all-zero text is no identity, leading zeros are stripped", () => {
    expect(eventRecordIdText(record({ eventRecordId: 7, eventRecordIdText: "0" }))).toBeNull();
    expect(eventRecordIdText(record({ eventRecordId: 7, eventRecordIdText: "000" }))).toBeNull();
    expect(eventRecordIdText(record({ eventRecordId: 7, eventRecordIdText: "0042" }))).toBe("42");
    expect(eventRecordIdText(record({ eventRecordId: 0, eventRecordIdText: " 17 " }))).toBe("17");
  });

  it("does not guess at text that is not a plain decimal", () => {
    // The store treats it as no identity rather than falling back to the number.
    expect(eventRecordIdText(record({ eventRecordId: 7, eventRecordIdText: "0x10" }))).toBeNull();
    expect(eventRecordIdText(record({ eventRecordId: 7, eventRecordIdText: "-3" }))).toBeNull();
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
      {
        kind: "channel",
        path: "Application",
        recordGroups: [{ computer: "HOST", recordIds: ["2"] }],
        recordCount: 1,
      },
      {
        kind: "channel",
        path: "System",
        recordGroups: [{ computer: "HOST", recordIds: ["5", "6"] }],
        recordCount: 2,
      },
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
      {
        kind: "file",
        path,
        recordGroups: [{ computer: "HOST", recordIds: ["10", "9007199254740993"] }],
        recordCount: 2,
      },
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
    expect(plan.sources[0].recordGroups).toEqual([{ computer: "HOST", recordIds: ["5", "6"] }]);
  });

  it("keeps events of different machines apart, so one machine's id never stands for another's", () => {
    // A log that collects events can hold the same EventRecordID from two machines.
    const plan = planEvtxSubsetSources([
      record({ channel: "ForwardedEvents", computer: "HOST-A", eventRecordId: 100 }),
      record({ channel: "ForwardedEvents", computer: "HOST-B", eventRecordId: 100 }),
      record({ channel: "ForwardedEvents", computer: "HOST-A", eventRecordId: 100 }),
    ]);
    expect(plan.sources).toHaveLength(1);
    expect(plan.sources[0].recordGroups).toEqual([
      { computer: "HOST-A", recordIds: ["100"] },
      { computer: "HOST-B", recordIds: ["100"] },
    ]);
    // Two distinct events, not one: the dialog must not offer "1 event" for them.
    expect(plan.sources[0].recordCount).toBe(2);
    expect(plan.exportableRecords).toBe(2);
  });

  it("sends no computer for events that name none", () => {
    const plan = planEvtxSubsetSources([
      record({ computer: "Unknown", eventRecordId: 1 }),
      record({ computer: "  ", eventRecordId: 2 }),
    ]);
    expect(plan.sources[0].recordGroups).toEqual([{ computer: null, recordIds: ["1", "2"] }]);
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
  missing: { count: 0, sample: [] },
  unrequested: { count: 0, sample: [] },
  messagesArchived: true,
  error: null,
  warnings: [],
  ...partial,
});

const unverified = {
  exportedRecords: null,
  missing: null,
  unrequested: null,
} satisfies Partial<EvtxSubsetFileResult>;

describe("fileDiffersFromRequest", () => {
  it("is true only for an exported file verified to be short or to hold extra events", () => {
    expect(fileDiffersFromRequest(file())).toBe(false);
    expect(fileDiffersFromRequest(file({ missing: { count: 1, sample: ["2"] } }))).toBe(true);
    expect(fileDiffersFromRequest(file({ unrequested: { count: 2, sample: ["8", "9"] } }))).toBe(true);
    // Unverified is a state of its own, stated as such, not a difference.
    expect(fileDiffersFromRequest(file(unverified))).toBe(false);
    // A failed file holds nothing to compare.
    expect(fileDiffersFromRequest(file({ status: "failed", ...unverified }))).toBe(false);
  });
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
        files: [file({ ...unverified, requestedRecords: 5 })],
      }),
    ).toBe("Exported 1 EVTX subset file (5 events, counts not verified).");
  });

  it("names failures, and the all-failed case exports nothing", () => {
    const failed = file({ status: "failed", ...unverified, error: "denied" });
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [file(), failed] })).toBe(
      "Exported 1 of 2 EVTX subset files (3 events); 1 failed.",
    );
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [failed] })).toBe(
      "Nothing was exported: 1 EVTX subset file failed.",
    );
  });

  it("says how many events were left out, so it never reads as a complete export of the view", () => {
    const result = { folder: "f", files: [file({ requestedRecords: 600, exportedRecords: 600 })] };
    expect(summarizeEvtxSubsetResult(result, 400)).toBe(
      "Exported 1 EVTX subset file (600 events); 400 not included.",
    );
    expect(summarizeEvtxSubsetResult(result, 0)).toBe("Exported 1 EVTX subset file (600 events).");
    expect(summarizeEvtxSubsetResult(result)).toBe("Exported 1 EVTX subset file (600 events).");
    expect(summarizeEvtxSubsetResult(result, 1234)).toContain("; 1,234 not included.");
  });

  it("says how many files were found to differ from the request", () => {
    const short = file({ exportedRecords: 2, missing: { count: 1, sample: ["2"] } });
    const extra = file({
      fileName: "b",
      outputPath: "b",
      exportedRecords: 4,
      unrequested: { count: 1, sample: ["9"] },
    });
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [short] })).toBe(
      "Exported 1 EVTX subset file (2 events); 1 file differs from the request.",
    );
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [short, extra, file()] })).toBe(
      "Exported 3 EVTX subset files (9 events); 2 files differ from the request.",
    );
  });

  it("puts failures, left-out events and differences together, in that order", () => {
    const failed = file({ status: "failed", ...unverified });
    const short = file({ exportedRecords: 2, missing: { count: 1, sample: ["2"] } });
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [short, failed] }, 4)).toBe(
      "Exported 1 of 2 EVTX subset files (2 events); 1 failed; 4 not included; 1 file differs from the request.",
    );
    expect(summarizeEvtxSubsetResult({ folder: "f", files: [failed] }, 4)).toBe(
      "Nothing was exported: 1 EVTX subset file failed; 4 not included.",
    );
  });
});
