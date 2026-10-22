import { describe, expect, it, vi } from "vitest";
import type { EventLogAnalysisReportRequest } from "../../lib/commands";
import type { CorrelationChain, CorrelationChainModel } from "./evtx-correlation-chains";
import type { CorrelationGaps } from "./evtx-correlation-gaps";
import {
  REPORT_CHAIN_MEMBER_CAP,
  buildReportChains,
  buildReportFilters,
  buildReportRequest,
  buildReportScope,
  reportChainRow,
  saveMarkdownReport,
} from "./evtx-report";
import type { EvtxRecord } from "./types";

const key = (value: string) => [{ kind: "activityId" as const, value }];

function chain(
  strength: CorrelationChain["strength"],
  memberIds: string[],
  edges: [string, string][],
  memberCount = memberIds.length,
): CorrelationChain {
  return {
    id: memberIds.join("+"),
    strength,
    memberIds,
    unresolvedMemberIds: [],
    memberCount,
    edges: edges.map(([left, right], index) => ({
      left,
      right,
      strength: strength === "candidate" ? "candidate" : "exact",
      keys: key(`k${index}`),
    })),
    keys: [],
    evidence: [],
    coverageGaps: [],
    startMs: null,
    endMs: null,
    title: null,
  };
}

/** Every pair end is reachable from the first through the pairs: one connected chain. */
function connected(pairs: { left: string; right: string }[]): boolean {
  const ends = new Set(pairs.flatMap((pair) => [pair.left, pair.right]));
  const reached = new Set<string>();
  const frontier = [pairs[0].left];
  while (frontier.length > 0) {
    const id = frontier.pop() as string;
    if (reached.has(id)) continue;
    reached.add(id);
    for (const pair of pairs) {
      if (pair.left === id) frontier.push(pair.right);
      if (pair.right === id) frontier.push(pair.left);
    }
  }
  return reached.size === ends.size;
}

const NO_GAPS: CorrelationGaps = { originIds: new Set(), global: false, previewCut: false };

describe("a chain row as the backend takes it", () => {
  it("lists members joined to each other and pairs that form one chain", () => {
    const row = reportChainRow(chain("exact", ["a", "b", "c"], [["a", "b"], ["b", "c"]]));
    expect(row?.memberIds).toEqual(["a", "b", "c"]);
    expect(row?.pairs.map((pair) => [pair.left, pair.right])).toEqual([
      ["a", "b"],
      ["b", "c"],
    ]);
    expect(connected(row?.pairs ?? [])).toBe(true);
  });

  it("caps a long chain at 50 connected members and attributes the full count", () => {
    const ids = Array.from({ length: 60 }, (_, index) => `m${String(index).padStart(2, "0")}`);
    const edges = ids.slice(1).map((id, index): [string, string] => [ids[index], id]);
    const row = reportChainRow(chain("exact", ids, edges));
    expect(row?.memberIds).toHaveLength(REPORT_CHAIN_MEMBER_CAP);
    expect(row?.pairs).toHaveLength(REPORT_CHAIN_MEMBER_CAP - 1);
    expect(row?.memberCount).toBe(60);
    expect(connected(row?.pairs ?? [])).toBe(true);
    const listed = new Set(row?.memberIds);
    for (const pair of row?.pairs ?? []) {
      expect(listed.has(pair.left) && listed.has(pair.right)).toBe(true);
    }
  });

  it("sends no ambiguous or coverage-blocked chain", () => {
    expect(reportChainRow(chain("ambiguous", ["a", "b"], [["a", "b"]]))).toBeNull();
    expect(reportChainRow(chain("coverageBlocked", ["a", "b"], [["a", "b"]]))).toBeNull();
  });

  it("sends no row without a linking pair", () => {
    expect(reportChainRow(chain("exact", ["a"], []))).toBeNull();
  });
});

describe("the chains of a report", () => {
  const model = {
    chains: [chain("exact", ["a", "b"], [["a", "b"]])],
    counts: { exact: 1, candidate: 0, ambiguous: 2, coverageBlocked: 0 },
  } as unknown as CorrelationChainModel;

  it("are null when the model was built for another session or revision", () => {
    expect(
      buildReportChains({
        sessionKey: "s:2",
        builtFor: "s:1",
        model,
        loadedEdgeCount: 1,
        gaps: NO_GAPS,
      }),
    ).toBeNull();
    expect(
      buildReportChains({ sessionKey: "s:2", builtFor: "s:2", model: null, loadedEdgeCount: 0, gaps: NO_GAPS }),
    ).toBeNull();
  });

  it("carry the counts, the gaps and the loaded edges for the session they were built for", () => {
    const chains = buildReportChains({
      sessionKey: "s:2",
      builtFor: "s:2",
      model,
      loadedEdgeCount: 3,
      gaps: { originIds: new Set(["o"]), global: true, previewCut: false },
    });
    expect(chains).toEqual({
      loadedEdgeCount: 3,
      correlationGaps: { global: true, previewCut: false },
      counts: { exact: 1, candidate: 0, ambiguous: 2, coverageBlocked: 0 },
      rows: [
        {
          strength: "exact",
          memberCount: 2,
          memberIds: ["a", "b"],
          pairs: [{ left: "a", right: "b", keys: key("k0") }],
        },
      ],
    });
  });
});

describe("the scope of a report", () => {
  const record = (level: EvtxRecord["level"], eventId: number, originKind?: "event" | "log") =>
    ({ level, eventId, originKind }) as EvtxRecord;
  const filters = buildReportFilters({
    filterLevels: new Set(),
    selectedChannels: new Set(["System"]),
    channelsHeld: 1,
    filterEventIds: "",
    timeWindow: "all",
    timeRange: null,
    filterSearch: "",
    quickFilterActive: false,
    recordScopeKind: null,
  });

  it("counts events only, never archive text lines", () => {
    const scope = buildReportScope({
      sourceMode: "files",
      loadedRecordCount: 4,
      sessionRecords: [record("Error", 7), record("Error", 7), record("Warning", 9), record("Error", 0, "log")],
      textLogEntryCount: 0,
      filters,
    });
    expect(scope.eventRecordCount).toBe(3);
    expect(scope.archiveTextRecordCount).toBe(1);
    expect(scope.levelMix).toEqual([
      { level: "Error", count: 2 },
      { level: "Warning", count: 1 },
    ]);
    expect(scope.topEventIds).toEqual([
      { eventId: 7, count: 2 },
      { eventId: 9, count: 1 },
    ]);
    expect(scope.distinctEventIdCount).toBe(2);
  });
});

describe("the filters of a report", () => {
  it("say a search or quick filter is active and never carry its text", () => {
    const filters = buildReportFilters({
      filterLevels: new Set(["Warning", "Critical"]),
      selectedChannels: new Set(["System", "Application"]),
      channelsHeld: 2,
      filterEventIds: "7, 10-12",
      timeWindow: "24h",
      timeRange: null,
      filterSearch: "examiner password",
      quickFilterActive: true,
      recordScopeKind: "chain",
    });
    expect(filters).toEqual({
      levels: ["Critical", "Warning"],
      channelsSelected: ["Application", "System"],
      channelsHeld: 2,
      eventIdSelectors: [
        { kind: "single", id: 7 },
        { kind: "range", low: 10, high: 12 },
      ],
      timeWindow: "24h",
      timeRange: null,
      searchActive: true,
      quickFilterActive: true,
      recordScope: "chain",
    });
    expect(JSON.stringify(filters)).not.toContain("examiner");
  });
});

describe("the request of a report", () => {
  it("sends a remote machine trimmed, and null for a local source", () => {
    const base = {
      sessionId: "s",
      revision: 2,
      generatedAtMs: 1,
      coverageGaps: [],
      scope: {} as EventLogAnalysisReportRequest["scope"],
      chains: null,
    };
    expect(buildReportRequest({ ...base, remoteMachine: " HOST-0002 " }).remoteMachine).toBe("HOST-0002");
    expect(buildReportRequest({ ...base, remoteMachine: null }).remoteMachine).toBeNull();
    expect(buildReportRequest({ ...base, remoteMachine: "  " }).remoteMachine).toBeNull();
  });
});

describe("saving a report", () => {
  const request = {} as EventLogAnalysisReportRequest;

  it("writes nothing when the save dialog is cancelled", async () => {
    const write = vi.fn();
    const outcome = await saveMarkdownReport({
      request,
      render: async () => "# report",
      chooseDestination: async () => null,
      write,
    });
    expect(outcome).toEqual({ status: "cancelled" });
    expect(write).not.toHaveBeenCalled();
  });

  it("writes the rendered Markdown to the chosen file", async () => {
    const write = vi.fn(async () => undefined);
    const outcome = await saveMarkdownReport({
      request,
      render: async () => "# report",
      chooseDestination: async () => "/cases/examiner/report.md",
      write,
    });
    expect(write).toHaveBeenCalledWith("/cases/examiner/report.md", "# report");
    expect(outcome).toEqual({ status: "saved", path: "/cases/examiner/report.md", characters: 8 });
  });

  it("throws a write failure instead of reporting success", async () => {
    await expect(
      saveMarkdownReport({
        request,
        render: async () => "# report",
        chooseDestination: async () => "/cases/report.md",
        write: async () => {
          throw new Error("disk full");
        },
      }),
    ).rejects.toThrow("disk full");
  });

  it("throws a render failure before asking where to save", async () => {
    const chooseDestination = vi.fn();
    await expect(
      saveMarkdownReport({
        request,
        render: async () => {
          throw new Error("The report request does not match this analysis session's links");
        },
        chooseDestination,
        write: vi.fn(),
      }),
    ).rejects.toThrow(/does not match/);
    expect(chooseDestination).not.toHaveBeenCalled();
  });
});
