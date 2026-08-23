import { describe, expect, it } from "vitest";
import {
  assertParseResultShape,
  formatCoverageGap,
  mergeCoverageGaps,
  mergeDiagnosisCoverageGaps,
  summarizeCoverageGaps,
} from "./evtx-coverage";

describe("mergeCoverageGaps", () => {
  it("accumulates gaps across channels", () => {
    // Each channel loads separately and reports its own gaps. Replacing rather than accumulating
    // would leave only the last channel's gaps visible and silently drop the rest.
    const merged = mergeCoverageGaps(["Application: 3 records unreadable"], [
      "System: stopped at 100000 events",
    ]);
    expect(merged).toEqual([
      "Application: 3 records unreadable",
      "System: stopped at 100000 events",
    ]);
  });

  it("does not repeat a gap when a channel is re-queried", () => {
    // A banner that grows on every refresh trains an operator to stop reading it.
    const first = mergeCoverageGaps([], ["Application: 3 records unreadable"]);
    const second = mergeCoverageGaps(first, ["Application: 3 records unreadable"]);
    expect(second).toHaveLength(1);
  });

  it("keeps the order gaps were first reported in", () => {
    // A gap that moves around the list as later channels finish is hard to read past.
    const merged = mergeCoverageGaps(["first", "second"], ["third", "first"]);
    expect(merged).toEqual(["first", "second", "third"]);
  });

  it("reports nothing when nothing is missing", () => {
    expect(mergeCoverageGaps([], [])).toEqual([]);
  });
});

describe("summarizeCoverageGaps", () => {
  it("uses the singular for one gap", () => {
    expect(summarizeCoverageGaps(["only"])).toBe("1 gap in this view");
  });

  it("uses the plural otherwise", () => {
    expect(summarizeCoverageGaps(["a", "b"])).toBe("2 gaps in this view");
  });
});

describe("gaps across load paths", () => {
  it("a refresh replaces gaps rather than carrying stale ones forward", () => {
    // The refresh clears records, so the gaps describing them have to go too. Keeping them would
    // report a gap from a set no longer on screen while the new result's own gap went unsaid.
    const beforeRefresh = ["Application: 3 records unreadable"];
    const afterClear = mergeCoverageGaps([], ["System: stopped at 100000 events"]);
    expect(afterClear).not.toContain(beforeRefresh[0]);
    expect(afterClear).toEqual(["System: stopped at 100000 events"]);
  });

  it("an incremental channel load adds to what is already reported", () => {
    // Channels load one at a time, so replacing here would leave only the last channel's gaps.
    const first = mergeCoverageGaps([], ["Application: 3 records unreadable"]);
    const second = mergeCoverageGaps(first, ["Security: 1 record unreadable"]);
    expect(second).toHaveLength(2);
  });
});

describe("assertParseResultShape", () => {
  it("accepts a well formed reply", () => {
    const shape = assertParseResultShape({
      records: [],
      channels: [],
      errorMessages: ["Application: 3 records unreadable"],
    });
    expect(shape.errorMessages).toEqual(["Application: 3 records unreadable"]);
  });
  it("preserves an omitted or valid totalRecords count", () => {
    expect(
      assertParseResultShape({ records: [], channels: [], totalRecords: 0 }).totalRecords
    ).toBe(0);
    expect(assertParseResultShape({ records: [], channels: [] }).totalRecords).toBeNull();
  });

  it("rejects a malformed totalRecords count", () => {
    for (const totalRecords of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Infinity]) {
      expect(() =>
        assertParseResultShape({ records: [], channels: [], totalRecords })
      ).toThrow(/totalRecords/);
    }
  });
  it("preserves valid archive member provenance", () => {
    const sha256 = "a".repeat(64);
    const shape = assertParseResultShape({
      records: [],
      channels: [],
      archiveMembers: [
        {
          path: "bundle.zip::Application.evtx",
          kind: "evtx",
          sha256,
          outcome: "parsed",
        },
        { path: "bundle.zip::readme.txt", kind: "text", outcome: "unsupported" },
      ],
    });

    expect(shape.archiveMembers).toEqual([
      {
        path: "bundle.zip::Application.evtx",
        kind: "evtx",
        sha256,
        outcome: "parsed",
      },
      { path: "bundle.zip::readme.txt", kind: "text", outcome: "unsupported" },
    ]);
  });

  it("rejects malformed archive member provenance instead of dropping it", () => {
    expect(() =>
      assertParseResultShape({
        records: [],
        channels: [],
        archiveMembers: [
          {
            path: "bundle.zip::Application.evtx",
            kind: "evtx",
            sha256: "abc123",
            outcome: "parsed",
          },
        ],
      })
    ).toThrow(/invalid archive member at index 0/);
  });

  it("treats omitted optional collections as empty", () => {
    const shape = assertParseResultShape({ records: [], channels: [] });
    expect(shape.errorMessages).toEqual([]);
    expect(shape.coverageGaps).toEqual([]);
    expect(shape.coverage).toEqual([]);
  });

  it("rejects a non-array errorMessages field", () => {
    expect(() =>
      assertParseResultShape({ records: [], channels: [], errorMessages: "not a list" })
    ).toThrow(/errorMessages/);
  });

  it("rejects malformed errorMessages entries with their field and index", () => {
    expect(() =>
      assertParseResultShape({
        records: [],
        channels: [],
        errorMessages: ["real", 42, null],
      })
    ).toThrow(/errorMessages at index 1/);
  });

  it("rejects a non-array coverageGaps field", () => {
    expect(() =>
      assertParseResultShape({ records: [], channels: [], coverageGaps: "not a list" })
    ).toThrow(/coverageGaps/);
  });

  it("rejects malformed coverageGaps entries with their field and index", () => {
    expect(() =>
      assertParseResultShape({
        records: [],
        channels: [],
        coverageGaps: [
          { source: "real.evtx", kind: "file", reason: "unreadable" },
          { source: "missing-kind", reason: "not a gap" },
          "legacy text",
        ],
      })
    ).toThrow(/coverageGaps at index 1/);
  });

  it("rejects coverageGaps locations outside the safe integer range", () => {
    expect(() =>
      assertParseResultShape({
        records: [],
        channels: [],
        coverageGaps: [
          {
            source: "oversized.evtx",
            kind: "chunk",
            reason: "incomplete chunk",
            chunkId: Number.MAX_SAFE_INTEGER + 1,
          },
        ],
      })
    ).toThrow(/coverageGaps at index 0/);
  });

  it("rejects a non-array coverage field", () => {
    expect(() =>
      assertParseResultShape({ records: [], channels: [], coverage: "not a list" })
    ).toThrow(/coverage/);
  });

  it("rejects malformed coverage entries with their field and index", () => {
    expect(() =>
      assertParseResultShape({
        records: [],
        channels: [],
        coverage: [
          { kind: "missing", path: "missing.evtx", reason: "not found" },
          { kind: "unknown", path: "unknown.evtx", reason: "invalid kind" },
        ],
      })
    ).toThrow(/coverage at index 1/);
  });

  it("rejects coverageGaps eventRecordId outside the safe integer range", () => {
    expect(() =>
      assertParseResultShape({
        records: [],
        channels: [],
        coverageGaps: [
          {
            source: "oversized.evtx",
            kind: "record",
            reason: "unreadable record",
            eventRecordId: Number.MAX_SAFE_INTEGER + 1,
          },
        ],
      })
    ).toThrow(/coverageGaps at index 0/);
  });

  it("preserves an unsafe coverage-gap record ID through its exact u64 text", () => {
    const eventRecordIdText = "18446744073709551615";
    const shape = assertParseResultShape({
      records: [],
      channels: [],
      coverageGaps: [
        {
          source: "oversized.evtx",
          kind: "record",
          reason: "unreadable record",
          eventRecordId: Number(eventRecordIdText),
          eventRecordIdText,
        },
      ],
    });

    expect(shape.coverageGaps).toEqual([
      expect.objectContaining({ eventRecordIdText }),
    ]);
    expect(formatCoverageGap(shape.coverageGaps[0])).toBe(
      `oversized.evtx record ${eventRecordIdText}: unreadable record`
    );
  });

  it.each([
    ["outside u64", "18446744073709551616", Number("18446744073709551616")],
    ["non-decimal", "record-42", 42],
    ["mismatched", "42", Number.MAX_SAFE_INTEGER + 1],
  ])("rejects %s coverage-gap record ID text", (_label, eventRecordIdText, eventRecordId) => {
    expect(() =>
      assertParseResultShape({
        records: [],
        channels: [],
        coverageGaps: [
          {
            source: "invalid.evtx",
            kind: "record",
            reason: "unreadable record",
            eventRecordId,
            eventRecordIdText,
          },
        ],
      })
    ).toThrow(/coverageGaps at index 0/);
  });

  it("preserves valid coverage entries", () => {
    const shape = assertParseResultShape({
      records: [],
      channels: [],
      coverage: [{ kind: "missing", path: "missing.evtx", reason: "not found" }],
    });
    expect(shape.coverage).toEqual([
      { kind: "missing", path: "missing.evtx", reason: "not found" },
    ]);
  });

  it("rejects a reply whose records are not a list", () => {
    // Spreading this would throw somewhere unrelated and surface as a confusing load error.
    expect(() => assertParseResultShape({ records: null, channels: [] })).toThrow(
      /cannot read/
    );
    expect(() => assertParseResultShape({ channels: [] })).toThrow(/cannot read/);
    expect(() => assertParseResultShape(undefined)).toThrow(/cannot read/);
  });
});

describe("structured recovery gaps", () => {
  it("keeps chunk and record provenance in the boundary shape", () => {
    const shape = assertParseResultShape({
      records: [],
      channels: [],
      coverageGaps: [
        {
          source: "dirty.evtx",
          kind: "chunk",
          reason: "incomplete chunk",
          chunkId: 9,
        },
        {
          source: "dirty.evtx",
          kind: "xml",
          reason: "malformed XML",
          eventRecordId: 42,
        },
      ],
    });

    expect(shape.coverageGaps).toEqual([
      {
        source: "dirty.evtx",
        kind: "chunk",
        reason: "incomplete chunk",
        chunkId: 9,
      },
      {
        source: "dirty.evtx",
        kind: "xml",
        reason: "malformed XML",
        eventRecordId: 42,
      },
    ]);
  });

});
describe("diagnosis coverage gaps", () => {
  it("merges typed, manifest, legacy, and tail gaps deterministically", () => {
    expect(
      mergeDiagnosisCoverageGaps(
        [{ source: "parser.evtx", kind: "chunk", reason: "incomplete chunk", chunkId: 4 }],
        [{ kind: "missing", path: "manifest.evtx", reason: "source path does not exist" }],
        [
          "Application: live batch 1 was not delivered",
          "Remote: remote source unavailable",
          "Parser: malformed XML",
          "Application: live batch 1 was not delivered",
        ],
        ["Tail: 2 records shortfall"]
      )
    ).toEqual([
      { source: "parser.evtx", kind: "chunk", reason: "incomplete chunk", chunkId: 4 },
      { source: "manifest.evtx", kind: "missing", reason: "source path does not exist" },
      { source: "Application", kind: "limitReached", reason: "live batch 1 was not delivered" },
      { source: "Remote", kind: "unsupported", reason: "remote source unavailable" },
      { source: "Parser", kind: "invalidPattern", reason: "malformed XML" },
      { source: "Tail", kind: "limitReached", reason: "2 records shortfall" },
    ]);
  });
  it("keeps one canonical typed gap when its formatted copy is also legacy coverage", () => {
    const typedGap = {
      source: "parser.evtx",
      kind: "limit" as const,
      reason: "reader stopped at 100 events; the source may contain more",
      eventRecordId: 99,
    };

    expect(
      mergeDiagnosisCoverageGaps(
        [typedGap],
        [],
        [
          "parser.evtx record 99: reader stopped at 100 events; the source may contain more",
          "Application: live batch 1 was not delivered",
        ],
        ["Tail: unrelated live gap"]
      )
    ).toEqual([
      typedGap,
      { source: "Application", kind: "limitReached", reason: "live batch 1 was not delivered" },
      { source: "Tail", kind: "record", reason: "unrelated live gap" },
    ]);
  });

  it.each([
    "Application: reader stopped at 100 events; the source may contain more",
    "Application: stopped after 100 events, the channel could not be read further (EvtNext failed)",
  ])("classifies backend reader truncation as limitReached: %s", (message) => {
    expect(mergeDiagnosisCoverageGaps([], [], [message], [])).toEqual([
      {
        source: "Application",
        kind: "limitReached",
        reason: message.slice("Application: ".length),
      },
    ]);
  });


  it("makes the frontend bound explicit instead of silently dropping gaps", () => {
    const gaps = mergeDiagnosisCoverageGaps(
      [],
      [],
      Array.from({ length: 257 }, (_, index) => `source-${index}: unreadable record`),
      []
    );
    expect(gaps).toHaveLength(256);
    expect(gaps[gaps.length - 1]).toEqual({
      source: "frontend-diagnosis",
      kind: "limitReached",
      reason:
        "frontend coverage bound omitted 2 additional gaps; " +
        "backend diagnosis also enforces an input cap",
    });
  });
});
