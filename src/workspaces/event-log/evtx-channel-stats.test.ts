import { describe, expect, it } from "vitest";
import {
  CHANNEL_ACTIVITY_BINS,
  buildChannelPaneModel,
  computeChannelStats,
  defaultExpandedGroups,
  recordTimestampMs,
  scaleActivityBars,
  summarizeLogSources,
  type ChannelPaneInput,
} from "./evtx-channel-stats";
import type {
  EvtxChannelInfo,
  EvtxCoverageGap,
  EvtxLevel,
  EvtxRecord,
} from "./types";

const HOUR = 60 * 60 * 1000;
const NOW = Date.UTC(2026, 9, 10, 12, 0, 0);
const DAY_START = NOW - 24 * HOUR;
const BIN_MS = HOUR; // 24 h over 24 bins

function record(
  channel: string,
  timestampEpoch: number,
  level: EvtxLevel = "Information",
): EvtxRecord {
  return {
    id: 0,
    eventRecordId: 1,
    timestamp: "",
    timestampEpoch,
    provider: "Provider",
    channel,
    eventId: 1,
    level,
    computer: "HOST",
    message: "",
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
  };
}

function live(name: string, extra: Partial<EvtxChannelInfo> = {}): EvtxChannelInfo {
  return { name, eventCount: 0, sourceType: "live", enabledState: "enabled", ...extra };
}

/**
 * A channel read from a file, as `append_parsed_file` lists it: named by the events' own channel,
 * with the path of the file it came from. A file normally carries its channel's name, with a slash
 * written as %4.
 */
function file(name: string, path = `C:\\logs\\${name.replace(/\//g, "%4")}.evtx`): EvtxChannelInfo {
  return { name, eventCount: 0, sourceType: { file: { path } } };
}

describe("recordTimestampMs", () => {
  it("returns a positive finite epoch and nothing else", () => {
    expect(recordTimestampMs(record("A", NOW))).toBe(NOW);
    // 0 is the backend's "no timestamp" sentinel (parsed_timestamp_epoch in timeline.rs).
    expect(recordTimestampMs(record("A", 0))).toBeNull();
    expect(recordTimestampMs(record("A", Number.NaN))).toBeNull();
    expect(recordTimestampMs(record("A", Number.POSITIVE_INFINITY))).toBeNull();
    // A FILETIME zero converted to Unix milliseconds predates any event log.
    expect(recordTimestampMs(record("A", -11_644_473_600_000))).toBeNull();
  });
});

describe("computeChannelStats", () => {
  const options = { nowMs: NOW, timeWindow: "24h" as const };

  it("counts totals, errors and warnings per channel, with Critical counted as an error", () => {
    const { byChannel } = computeChannelStats(
      [
        record("System", NOW - 5 * HOUR, "Error"),
        record("System", NOW - 4 * HOUR, "Critical"),
        record("System", NOW - 3 * HOUR, "Warning"),
        record("System", NOW - 2 * HOUR, "Information"),
        record("System", NOW - HOUR, "Verbose"),
        record("Application", NOW - HOUR, "Warning"),
      ],
      options,
    );
    expect(byChannel.get("System")).toMatchObject({ total: 5, errors: 2, warnings: 1 });
    expect(byChannel.get("Application")).toMatchObject({ total: 1, errors: 0, warnings: 1 });
    expect(byChannel.has("Security")).toBe(false);
  });

  it("anchors a finite window at now and splits it into 24 equal bins", () => {
    const result = computeChannelStats([record("System", NOW - 30 * 60 * 1000)], options);
    expect(result.span).toEqual({ startMs: DAY_START, endMs: NOW });
    const bins = result.byChannel.get("System")!.bins;
    expect(bins).toHaveLength(CHANNEL_ACTIVITY_BINS);
    expect(CHANNEL_ACTIVITY_BINS).toBe(24);
    expect(bins.filter((count) => count > 0)).toHaveLength(1);
    expect(bins[23]).toBe(1);
  });

  it("places the exact start in bin 0, the exact end in the last bin, and each bin edge in the later bin", () => {
    const { byChannel } = computeChannelStats(
      [
        record("A", DAY_START),
        record("A", NOW),
        record("A", DAY_START + 5 * BIN_MS),
        record("A", DAY_START + 5 * BIN_MS - 1),
      ],
      options,
    );
    const bins = byChannel.get("A")!.bins;
    expect(bins[0]).toBe(1);
    expect(bins[4]).toBe(1);
    expect(bins[5]).toBe(1);
    expect(bins[23]).toBe(1);
    expect(bins.reduce((sum, count) => sum + count, 0)).toBe(4);
  });

  it("does not place an event without a timestamp in any bin, least of all bin 0", () => {
    const { byChannel } = computeChannelStats(
      [
        record("A", 0, "Error"),
        record("A", Number.NaN, "Warning"),
        record("A", -1),
        record("A", NOW - 2 * HOUR),
      ],
      options,
    );
    const stats = byChannel.get("A")!;
    // They are events the channel holds, so they still count in the totals ...
    expect(stats.total).toBe(4);
    expect(stats.errors).toBe(1);
    expect(stats.warnings).toBe(1);
    // ... but they are not plotted anywhere, and the pane can say how many.
    expect(stats.unplaced).toBe(3);
    expect(stats.bins[0]).toBe(0);
    expect(stats.bins.reduce((sum, count) => sum + count, 0)).toBe(1);
  });

  it("does not clamp events outside the window into the edge bins", () => {
    const { byChannel } = computeChannelStats(
      [record("A", DAY_START - 1), record("A", NOW + 1), record("A", NOW - HOUR)],
      options,
    );
    const stats = byChannel.get("A")!;
    expect(stats.total).toBe(3);
    expect(stats.outsideSpan).toBe(2);
    expect(stats.unplaced).toBe(0);
    expect(stats.bins[0]).toBe(0);
    expect(stats.bins.reduce((sum, count) => sum + count, 0)).toBe(1);
  });

  it("spans earliest to latest placed record for All time, shared by every channel", () => {
    const first = NOW - 10 * HOUR;
    const last = NOW - HOUR;
    const result = computeChannelStats(
      [record("A", first), record("B", last), record("B", 0), record("A", (first + last) / 2)],
      { nowMs: NOW, timeWindow: "all" },
    );
    expect(result.span).toEqual({ startMs: first, endMs: last });
    expect(result.byChannel.get("A")!.bins[0]).toBe(1);
    expect(result.byChannel.get("B")!.bins[23]).toBe(1);
    expect(result.byChannel.get("B")!.unplaced).toBe(1);
  });

  it("has no span, and flat bins, when All time holds no placed record", () => {
    const result = computeChannelStats([record("A", 0), record("A", Number.NaN)], {
      nowMs: NOW,
      timeWindow: "all",
    });
    expect(result.span).toBeNull();
    const stats = result.byChannel.get("A")!;
    expect(stats.total).toBe(2);
    expect(stats.unplaced).toBe(2);
    expect(stats.bins.every((count) => count === 0)).toBe(true);
  });

  it("puts events that share one instant in bin 0 of a one-millisecond span", () => {
    const result = computeChannelStats([record("A", NOW), record("A", NOW)], {
      nowMs: NOW,
      timeWindow: "all",
    });
    expect(result.span).toEqual({ startMs: NOW, endMs: NOW + 1 });
    expect(result.byChannel.get("A")!.bins[0]).toBe(2);
  });

  it("returns an empty result for no records", () => {
    const result = computeChannelStats([], options);
    expect(result.byChannel.size).toBe(0);
    expect(result.span).toEqual({ startMs: DAY_START, endMs: NOW });
  });
});

describe("scaleActivityBars", () => {
  it("maps empty bins to 0 and scales the rest to the busiest, never below 2 px", () => {
    expect(scaleActivityBars([0, 1, 10, 0, 5], 18)).toEqual([0, 2, 18, 0, 9]);
  });

  it("is flat when nothing happened", () => {
    expect(scaleActivityBars([0, 0, 0], 18)).toEqual([0, 0, 0]);
  });

  it("never exceeds the height it was given", () => {
    expect(Math.max(...scaleActivityBars([3, 3, 3], 18))).toBe(18);
  });
});

function paneInput(overrides: Partial<ChannelPaneInput>): ChannelPaneInput {
  return {
    channels: [],
    records: [],
    loadedChannels: new Set<string>(),
    sourceMode: "live",
    remoteMachine: null,
    nowMs: NOW,
    timeWindow: "24h",
    coverageDetails: [],
    manifestCoverage: [],
    legacyCoverage: [],
    tailCoverage: [],
    archiveMembers: [],
    isSwitchedOff: () => false,
    ...overrides,
  };
}

function gap(
  source: string,
  kind: EvtxCoverageGap["kind"],
  reason = "reason",
): EvtxCoverageGap {
  return { source, kind, reason };
}

describe("buildChannelPaneModel", () => {
  const SECURITY_REFUSAL =
    "the Event Log service refused the channel query (Windows error 5: Access is denied)";

  it("reads a loaded live channel with no gap, and a real zero stays a zero", () => {
    const model = buildChannelPaneModel(
      paneInput({
        channels: [live("System"), live("Application")],
        loadedChannels: new Set(["System", "Application"]),
        records: [record("System", NOW - HOUR, "Error")],
      }),
    );
    expect(model.rows.get("System")).toMatchObject({ state: "read", stats: { total: 1, errors: 1 } });
    expect(model.rows.get("Application")).toMatchObject({ state: "read", stats: { total: 0 } });
    expect(model.readCount).toBe(2);
    expect(model.totalCount).toBe(2);
  });

  it("shows a live channel that was never loaded as not loaded, without a number", () => {
    const model = buildChannelPaneModel(paneInput({ channels: [live("System")] }));
    expect(model.rows.get("System")?.state).toBe("notLoaded");
    expect(model.readCount).toBe(0);
    expect(model.totalCount).toBe(1);
  });

  it("treats every channel in a parsed file set as read", () => {
    const model = buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file("System")],
        records: [record("System", NOW - HOUR)],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("read");
  });

  it("reports a structured accessDenied gap as needs elevation", () => {
    const model = buildChannelPaneModel(
      paneInput({
        channels: [live("Security")],
        coverageDetails: [gap("Security", "accessDenied", "denied")],
      }),
    );
    expect(model.rows.get("Security")?.state).toBe("needsElevation");
  });

  it("reports the live refusal text as needs elevation although the backend files it as a record gap", () => {
    // `absorb_scan` turns every live scan gap into kind "record", the Windows error 5 and 1314
    // refusals included, so the kind alone never says "denied" for a live channel.
    for (const reason of [
      SECURITY_REFUSAL,
      "the Event Log service refused the channel query (Windows error 1314: A required privilege is not held by the client)",
    ]) {
      const model = buildChannelPaneModel(
        paneInput({
          channels: [live("Security")],
          coverageDetails: [gap("Security", "record", reason)],
          legacyCoverage: [`Security: ${reason}`],
        }),
      );
      expect(model.rows.get("Security")?.state).toBe("needsElevation");
    }
  });

  it("does not suggest elevating this app for a refusal from a remote machine", () => {
    const model = buildChannelPaneModel(
      paneInput({
        remoteMachine: "SRV01",
        channels: [live("Security")],
        legacyCoverage: [`SRV01/Security: ${SECURITY_REFUSAL}`],
      }),
    );
    expect(model.rows.get("Security")?.state).toBe("accessDenied");
  });

  it("attributes a gap that only the legacy string carries (a thrown query)", () => {
    const model = buildChannelPaneModel(
      paneInput({
        channels: [live("System")],
        legacyCoverage: ["System: not read (the RPC server is unavailable)"],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("notRead");
  });

  it("does not attribute one channel's gap to another whose name starts the same way", () => {
    const model = buildChannelPaneModel(
      paneInput({
        channels: [live("App"), live("Application")],
        loadedChannels: new Set(["App", "Application"]),
        legacyCoverage: ["Application: not read (denied)"],
      }),
    );
    expect(model.rows.get("App")?.state).toBe("read");
    expect(model.rows.get("Application")?.state).toBe("notRead");
  });

  it("marks a channel that has records and a record-level gap as partial, never complete", () => {
    const model = buildChannelPaneModel(
      paneInput({
        channels: [live("System")],
        loadedChannels: new Set(["System"]),
        records: [record("System", NOW - HOUR)],
        coverageDetails: [gap("System", "record", "record 7 could not be decoded")],
      }),
    );
    expect(model.rows.get("System")).toMatchObject({ state: "partial", stats: { total: 1 } });
    expect(model.readCount).toBe(1);
  });

  describe("which gaps make a read partial", () => {
    const loaded = (coverageDetails: EvtxCoverageGap[], legacyCoverage: string[] = []) =>
      buildChannelPaneModel(
        paneInput({
          channels: [live("Application")],
          loadedChannels: new Set(["Application"]),
          records: [record("Application", NOW - HOUR)],
          coverageDetails,
          legacyCoverage,
        }),
      ).rows.get("Application")?.state;

    it.each(["chunk", "record", "xml", "limit", "limitReached", "cancelled"] as const)(
      "treats a %s gap as events that may be missing",
      (kind) => {
        expect(loaded([gap("Application", kind, "some events may be missing")])).toBe("partial");
      },
    );

    it("does not call a read partial because a provider message could not be formatted", () => {
      // The record is kept and its raw data is shown, so every event is there. This gap is common
      // on a real machine (missing publisher metadata) and must not label most channels partial.
      const providerGap = gap(
        "Application",
        "provider",
        "provider message for Contoso could not be rendered at EvtOpenPublisherMetadata (Windows error 2); raw event data is shown instead",
      );
      expect(loaded([providerGap])).toBe("read");
      // The legacy string the backend writes for the same gap is not a second opinion.
      expect(loaded([providerGap], [`Application: ${providerGap.reason}`])).toBe("read");
    });

    it("recognizes the legacy twin of a file gap whose structured form carries a record location", () => {
      const fileGap: EvtxCoverageGap = {
        source: "C:\\logs\\Application.evtx",
        kind: "provider",
        reason: "provider message for Contoso could not be rendered",
        eventRecordId: 7,
      };
      const model = buildChannelPaneModel(
        paneInput({
          sourceMode: "files",
          timeWindow: "all",
          channels: [file("Application")],
          records: [record("Application", NOW - HOUR)],
          coverageDetails: [fileGap],
          // The Rust formatter writes "source: reason", the TypeScript one adds " record 7".
          legacyCoverage: [
            "C:\\logs\\Application.evtx: provider message for Contoso could not be rendered",
            "C:\\logs\\Application.evtx record 7: provider message for Contoso could not be rendered",
          ],
        }),
      );
      expect(model.rows.get("Application")?.state).toBe("read");
    });

    it("keeps a legacy-only shortfall, which no structured gap explains, as partial", () => {
      expect(loaded([], ["Application: live stream batch 3 was not received"])).toBe("partial");
    });

    it("reads a channel the parser reports as empty as a real zero", () => {
      const model = buildChannelPaneModel(
        paneInput({
          sourceMode: "files",
          timeWindow: "all",
          channels: [file("Application")],
          coverageDetails: [gap("C:\\logs\\Application.evtx", "empty", "the file holds no events")],
        }),
      );
      expect(model.rows.get("Application")).toMatchObject({ state: "read", stats: { total: 0 } });
      expect(model.rows.get("Application")?.reasons).toEqual([]);
    });
  });

  it("marks a stopped load that kept some records as partial and one that kept none as not read", () => {
    const stopped = gap("System", "cancelled", "operator stopped the load");
    const withRecords = buildChannelPaneModel(
      paneInput({
        channels: [live("System")],
        records: [record("System", NOW - HOUR)],
        coverageDetails: [stopped],
      }),
    );
    expect(withRecords.rows.get("System")?.state).toBe("partial");
    const withoutRecords = buildChannelPaneModel(
      paneInput({ channels: [live("System")], coverageDetails: [stopped] }),
    );
    expect(withoutRecords.rows.get("System")?.state).toBe("notRead");
  });

  it("keeps the existing switched-off marker for a channel the service reports as disabled", () => {
    const model = buildChannelPaneModel(
      paneInput({
        channels: [live("AirSpaceChannel", { enabledState: "disabled" })],
        isSwitchedOff: (channel) => channel.enabledState === "disabled",
      }),
    );
    expect(model.rows.get("AirSpaceChannel")?.state).toBe("disabled");
  });

  it("matches a file source to its channel by exact basename, including the %4 form of a slash", () => {
    const model = buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file("Application"), file("Microsoft-Windows-AAD/Operational")],
        records: [
          record("Application", NOW - HOUR),
          record("Microsoft-Windows-AAD/Operational", NOW - HOUR),
        ],
        coverageDetails: [
          gap("C:\\logs\\Application.evtx", "chunk", "chunk 3 is corrupt"),
          gap("C:\\logs\\Microsoft-Windows-AAD%4Operational.evtx", "record", "record 9"),
        ],
      }),
    );
    expect(model.rows.get("Application")?.state).toBe("partial");
    expect(model.rows.get("Microsoft-Windows-AAD/Operational")?.state).toBe("partial");
  });

  it("does not match a basename that only contains the channel name", () => {
    const model = buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file("App")],
        records: [record("App", NOW - HOUR)],
        coverageDetails: [gap("C:\\logs\\Application.evtx", "chunk", "chunk 3")],
      }),
    );
    expect(model.rows.get("App")?.state).toBe("read");
  });

  describe("a file that could not be opened has no channel entry", () => {
    const manifestDenied = {
      kind: "accessDenied" as const,
      path: "C:\\logs\\Security.evtx",
      reason: "source metadata access was denied",
    };
    const input = paneInput({
      sourceMode: "files",
      timeWindow: "all",
      channels: [file("System"), file("Microsoft-Windows-AAD/Operational")],
      records: [
        record("System", NOW - HOUR),
        record("Microsoft-Windows-AAD/Operational", NOW - HOUR),
      ],
      coverageDetails: [gap("C:\\logs\\Security.evtx", "accessDenied", "source metadata access was denied")],
      manifestCoverage: [manifestDenied],
      legacyCoverage: ["C:\\logs\\Security.evtx: source metadata access was denied"],
    });

    it("adds a row for it, once, in the place Windows Logs puts that channel", () => {
      const model = buildChannelPaneModel(input);
      expect(model.rows.get("Security")).toMatchObject({
        state: "needsElevation",
        selectable: false,
      });
      expect(model.channels.filter((channel) => channel.name === "Security")).toHaveLength(1);
      // Listed in the place Windows Logs puts Security, though it takes its color index last.
      const listed = (name: string) =>
        model.tree.windowsLogs.some((channel) => channel.name === name);
      expect(listed("Security")).toBe(true);
      expect(model.tree.windowsLogs.map((channel) => channel.name)).toEqual(["Security", "System"]);
    });

    it("counts it in the total but not in the read count", () => {
      const model = buildChannelPaneModel(input);
      expect(model.readCount).toBe(2);
      expect(model.totalCount).toBe(3);
    });

    it("never gives it numbers", () => {
      const row = buildChannelPaneModel(input).rows.get("Security")!;
      expect(row.state).not.toBe("read");
      expect(row.stats.bins.every((count) => count === 0)).toBe(true);
    });

    it("indexes the channels the workbench lists as orderChannelNames does, and the unopened source after them", () => {
      const withRow = buildChannelPaneModel(input);
      const withoutRow = buildChannelPaneModel({
        ...input,
        coverageDetails: [],
        manifestCoverage: [],
        legacyCoverage: [],
      });
      // The Table and the charts compute these two from the same names, so an unopened source
      // that sorts ahead of System in the pane must not move System's color.
      for (const name of ["System", "Microsoft-Windows-AAD/Operational"]) {
        expect(withRow.rows.get(name)?.index).toBe(withoutRow.rows.get(name)?.index);
      }
      expect(withRow.rows.get("System")?.index).toBe(0);
      expect(withRow.rows.get("Microsoft-Windows-AAD/Operational")?.index).toBe(1);
      expect(withRow.rows.get("Security")?.index).toBe(2);
    });
  });

  it("does not invent a row for a gap whose source is not a single .evtx file", () => {
    const model = buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file("System")],
        records: [record("System", NOW - HOUR)],
        manifestCoverage: [
          { kind: "accessDenied", path: "C:\\logs\\protected-folder", reason: "denied" },
          { kind: "invalidPattern", path: "C:\\logs\\*.evtx[", reason: "bad pattern" },
        ],
      }),
    );
    expect(model.totalCount).toBe(1);
  });
});

describe("summarizeLogSources", () => {
  it("counts parsed entries per log file and labels each by its file name", () => {
    const summary = summarizeLogSources([
      { filePath: "C:\\logs\\ccmexec.log" },
      { filePath: "C:\\logs\\AppEnforce.log" },
      { filePath: "C:\\logs\\ccmexec.log" },
      { filePath: "/var/log/IntuneManagementExtension.log" },
    ]);
    expect(summary).toEqual([
      { path: "C:\\logs\\AppEnforce.log", label: "AppEnforce.log", entries: 1 },
      { path: "C:\\logs\\ccmexec.log", label: "ccmexec.log", entries: 2 },
      { path: "/var/log/IntuneManagementExtension.log", label: "IntuneManagementExtension.log", entries: 1 },
    ]);
  });

  it("keeps two files with the same name apart", () => {
    const summary = summarizeLogSources([{ filePath: "a/x.log" }, { filePath: "b/x.log" }]);
    expect(summary.map((item) => item.path)).toEqual(["a/x.log", "b/x.log"]);
  });

  it("returns nothing for no entries and a placeholder for a path with no name", () => {
    expect(summarizeLogSources([])).toEqual([]);
    expect(summarizeLogSources([{ filePath: "" }])[0].label).toBe("Unnamed source");
  });
});

describe("defaultExpandedGroups", () => {
  const model = (over: Partial<ChannelPaneInput>) =>
    buildChannelPaneModel(
      paneInput({
        channels: [
          live("System"),
          live("Contoso-AAD/Operational"),
          live("Contoso-AAD/Admin"),
          live("Fabrikam-Other/Operational"),
        ],
        ...over,
      }),
    );

  it("always opens Windows Logs and nothing else when no channel holds events", () => {
    expect([...defaultExpandedGroups(model({}))]).toEqual(["Windows Logs"]);
  });

  it("opens each group on the path to a loaded channel that has records, and only those", () => {
    const open = defaultExpandedGroups(
      model({
        loadedChannels: new Set(["Contoso-AAD/Operational", "Fabrikam-Other/Operational"]),
        records: [record("Contoso-AAD/Operational", NOW - HOUR)],
      }),
    );
    expect(open.has("Windows Logs")).toBe(true);
    expect(open.has("AppServices")).toBe(true);
    // The folder that holds the channel with records is open ...
    expect(open.has("Contoso-AAD")).toBe(true);
    // ... a sibling folder whose channel was loaded but holds nothing is not.
    expect(open.has("Fabrikam-Other")).toBe(false);
  });

  it("does not open a group for a channel that is loaded and empty, or not read", () => {
    const open = defaultExpandedGroups(
      model({
        loadedChannels: new Set(["Contoso-AAD/Operational"]),
        legacyCoverage: ["Fabrikam-Other/Operational: not read (denied)"],
      }),
    );
    expect(open.has("AppServices")).toBe(false);
    expect(open.has("Contoso-AAD")).toBe(false);
  });

  it("does not open a group for a row that shows no numbers, whatever records the store holds", () => {
    // A channel the service reports as switched off and nobody loaded shows a dash, so there is
    // nothing in its group to come for.
    const open = defaultExpandedGroups(
      model({
        channels: [live("Contoso-AAD/Operational", { enabledState: "disabled" })],
        isSwitchedOff: (channel) => channel.enabledState === "disabled",
        records: [record("Contoso-AAD/Operational", NOW - HOUR)],
      }),
    );
    expect(open.has("AppServices")).toBe(false);
  });

  it("counts a partial channel that kept records", () => {
    const open = defaultExpandedGroups(
      model({
        loadedChannels: new Set(["Contoso-AAD/Admin"]),
        records: [record("Contoso-AAD/Admin", NOW - HOUR)],
        coverageDetails: [gap("Contoso-AAD/Admin", "record", "record 7 could not be decoded")],
      }),
    );
    expect(open.has("Contoso-AAD")).toBe(true);
  });
});

describe("files mode: a gap belongs to the file a channel was read from", () => {
  const filesInput = (over: Partial<ChannelPaneInput>) =>
    paneInput({ sourceMode: "files", timeWindow: "all", ...over });

  it("reports a file listed under its own path, with nothing read from it, as not read", () => {
    // The shape `append_parsed_file` gives a file whose chunks all failed: no records, a channel
    // named by the path, and its gaps keyed by that same path.
    const path = "C:\\logs\\System.evtx";
    const model = buildChannelPaneModel(
      filesInput({
        channels: [file(path, path)],
        coverageDetails: [{ source: path, kind: "chunk", reason: "chunk 3 is corrupt", chunkId: 3 }],
        legacyCoverage: [`${path} chunk 3: chunk 3 is corrupt`],
      }),
    );
    expect(model.rows.get(path)).toMatchObject({ state: "notRead", stats: { total: 0 } });
    expect(model.rows.get(path)?.reasons).toEqual(["chunk 3 is corrupt"]);
    expect(model.readCount).toBe(0);
    expect(model.totalCount).toBe(1);
  });

  it("calls a file with only incomplete gaps and no records not read, whatever acquired it", () => {
    const model = buildChannelPaneModel(
      filesInput({
        channels: [file("System")],
        coverageDetails: [gap("C:\\logs\\System.evtx", "limit", "the read stopped at the cap")],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("notRead");
  });

  it("attributes a gap to a file that is not named after its channel", () => {
    const exported = "C:\\exports\\PC01-System-2026.evtx";
    const model = buildChannelPaneModel(
      filesInput({
        channels: [file("System", exported), file("Application")],
        records: [record("System", NOW - HOUR), record("Application", NOW - HOUR)],
        coverageDetails: [gap(exported, "chunk", "chunk 2 was zero-filled")],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("partial");
    expect(model.rows.get("Application")?.state).toBe("read");
    // The renamed export is not an unopened source: a channel came from it.
    expect(model.totalCount).toBe(2);
  });

  it("does not guess a channel from a file name that matches it", () => {
    const model = buildChannelPaneModel(
      filesInput({
        channels: [file("Application", "C:\\logs\\one.evtx")],
        records: [record("Application", NOW - HOUR)],
        coverageDetails: [gap("C:\\elsewhere\\Application.evtx", "chunk", "chunk 2 was zero-filled")],
      }),
    );
    expect(model.rows.get("Application")?.state).toBe("read");
  });

  it("attributes gaps by the full path of an archive member at the archive root", () => {
    const member = "C:\\cases\\bundle.zip::System.evtx";
    const model = buildChannelPaneModel(
      filesInput({
        channels: [file("System", member)],
        records: [record("System", NOW - HOUR)],
        coverageDetails: [
          gap(member, "record", "record 9 could not be decoded"),
          gap("C:\\cases\\bundle.zip::Security.evtx", "accessDenied", "member was denied"),
        ],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("partial");
    // The unopened member is named after the member, not after the archive.
    expect(model.rows.get("Security")).toMatchObject({ state: "needsElevation", selectable: false });
    expect(model.rows.has("bundle.zip::Security")).toBe(false);
  });

  it("names an unopened file by its path when its name is already a channel, so rows stay unique", () => {
    const model = buildChannelPaneModel(
      filesInput({
        channels: [file("System")],
        records: [record("System", NOW - HOUR)],
        coverageDetails: [
          gap("D:\\other\\System.evtx", "accessDenied", "denied"),
          gap("D:\\a\\Security.evtx", "accessDenied", "denied"),
          gap("D:\\b\\Security.evtx", "accessDenied", "denied"),
        ],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("read");
    expect(model.rows.get("D:\\other\\System.evtx")?.state).toBe("needsElevation");
    expect(model.rows.get("Security")?.state).toBe("needsElevation");
    expect(model.rows.get("D:\\b\\Security.evtx")?.state).toBe("needsElevation");
    expect(model.totalCount).toBe(4);
    expect(new Set(model.channels.map((channel) => channel.name)).size).toBe(4);
  });

  it("keeps a folder called 'record 42' in a structured source", () => {
    const path = "C:\\Exports\\Incident record 42\\System.evtx";
    const model = buildChannelPaneModel(
      filesInput({
        channels: [file("System", path)],
        records: [record("System", NOW - HOUR)],
        coverageDetails: [gap(path, "chunk", "chunk 2 was zero-filled")],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("partial");
  });

  it("strips a location only from a legacy string, and only when it is a number", () => {
    const path = "C:\\logs\\System.evtx";
    const read = (legacy: string) =>
      buildChannelPaneModel(
        filesInput({
          channels: [file("System")],
          records: [record("System", NOW - HOUR)],
          legacyCoverage: [legacy],
        }),
      ).rows.get("System")?.state;
    expect(read(`${path} chunk 3: chunk 3 is corrupt`)).toBe("partial");
    expect(read(`${path} record 77: record 77 could not be decoded`)).toBe("partial");
    // "record 7a" is not a location, so this names a different source and reaches nothing.
    expect(read(`${path} record 7a: something`)).toBe("read");
  });
});

describe("what counts as acquired", () => {
  it("does not treat a channel list with no source mode as read", () => {
    // A remote load whose queries all failed clears the mode but keeps the enumerated channels.
    const model = buildChannelPaneModel(
      paneInput({ sourceMode: null, channels: [live("System"), live("Application")] }),
    );
    expect(model.rows.get("System")?.state).toBe("notLoaded");
    expect(model.rows.get("Application")?.state).toBe("notLoaded");
    expect(model.readCount).toBe(0);
    expect(model.totalCount).toBe(2);
  });

  it("shows records that are on screen as read even with no source mode", () => {
    const model = buildChannelPaneModel(
      paneInput({
        sourceMode: null,
        channels: [live("System")],
        records: [record("System", NOW - HOUR)],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("read");
  });
});

describe("live tail gaps", () => {
  const withTail = (tailCoverage: string[]) =>
    buildChannelPaneModel(
      paneInput({
        channels: [live("System")],
        loadedChannels: new Set(["System"]),
        records: [record("System", NOW - HOUR)],
        tailCoverage,
      }),
    ).rows.get("System")?.state;

  it.each([
    ["a batch that was not received", "System: live tail batch 12 was not received"],
    ["a batch the backend could not deliver", "System: live tail batch 4 was not delivered (channel closed)"],
    ["a subscription callback error", "System: subscription callback reported an error"],
    [
      "a stop that failed, after which the tail's check for missing batches never ran",
      "System: live tail stop failed (channel not found)",
    ],
    [
      "a gap carried by a tail batch's payload",
      "System: 3 events could not be read and are missing from this view",
    ],
  ])("makes the row partial for %s", (_name, gapText) => {
    expect(withTail([gapText])).toBe("partial");
  });

  it.each([
    ["a tail that could not start", "System: live tail unavailable (not supported)"],
    [
      "a subscription that fell back to polling",
      "System: EvtSubscribe unavailable; polling fallback is active (Windows error 87)",
    ],
    [
      "a provider message that could not be formatted",
      "System: provider message for Contoso could not be rendered at EvtFormatMessage (Windows error 15027); raw event data is shown instead",
    ],
  ])("leaves the row read for %s", (_name, gapText) => {
    expect(withTail([gapText])).toBe("read");
  });

  it("does not attribute a tail gap to another channel", () => {
    const model = buildChannelPaneModel(
      paneInput({
        channels: [live("System"), live("Application")],
        loadedChannels: new Set(["System", "Application"]),
        records: [record("System", NOW - HOUR), record("Application", NOW - HOUR)],
        tailCoverage: ["System: live tail batch 12 was not received"],
      }),
    );
    expect(model.rows.get("Application")?.state).toBe("read");
    expect(model.rows.get("System")?.state).toBe("partial");
  });
});

describe("one row per channel name", () => {
  it("lists two exports of the same log once, with one count", () => {
    const model = buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file("System", "C:\\a\\System.evtx"), file("System", "C:\\b\\System.evtx")],
        records: [record("System", NOW - HOUR), record("System", NOW - 2 * HOUR)],
      }),
    );
    expect(model.channels.filter((channel) => channel.name === "System")).toHaveLength(1);
    expect(model.totalCount).toBe(1);
    expect(model.readCount).toBe(1);
    expect(model.rows.get("System")?.stats.total).toBe(2);
  });

  it("reads a gap from either file against the one row", () => {
    const model = buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file("System", "C:\\a\\System.evtx"), file("System", "C:\\b\\System.evtx")],
        records: [record("System", NOW - HOUR)],
        coverageDetails: [gap("C:\\b\\System.evtx", "chunk", "chunk 2 was zero-filled")],
      }),
    );
    expect(model.rows.get("System")?.state).toBe("partial");
  });
});

describe("text logs from archives", () => {
  const log = (channel: string, at: number) => ({
    ...record(channel, at),
    originKind: "log" as const,
  });
  const MEMBER = "C:\\cases\\bundle.zip::logs/IntuneManagementExtension.log";

  const model = () =>
    buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        // append_parsed_file lists a text member under its own label, which is also its path.
        channels: [file("System"), file(MEMBER, MEMBER)],
        records: [record("System", NOW - HOUR), log(MEMBER, NOW - 2 * HOUR), log(MEMBER, NOW - 3 * HOUR)],
      }),
    );

  it("lists a text-log member apart from the channels, with its entry count", () => {
    const built = model();
    expect(built.textLogs).toEqual([
      {
        name: MEMBER,
        label: "IntuneManagementExtension.log",
        entries: 2,
        state: "read",
        reasons: [],
      },
    ]);
    expect(built.rows.has(MEMBER)).toBe(false);
    expect(built.channels.map((channel) => channel.name)).toEqual(["System"]);
  });

  it("counts it in neither the total nor the read count, and gives it no color index", () => {
    const built = model();
    expect(built.totalCount).toBe(1);
    expect(built.readCount).toBe(1);
    expect([...built.order.keys()]).toEqual(["System"]);
  });

  it("keeps its timestamps out of the shared activity span", () => {
    const built = model();
    // All time runs over the event channels only: the one System event.
    expect(built.span).toEqual({ startMs: NOW - HOUR, endMs: NOW - HOUR + 1 });
  });

  it("does not change an event channel's color index", () => {
    // The member label begins "C:\\", so it sorts ahead of every Microsoft-* service channel: were
    // it ordered with the channels it would push this one from index 1 to 2.
    const AAD = "Microsoft-Windows-AAD/Operational";
    const input = (channels: EvtxChannelInfo[], records: EvtxRecord[]) =>
      paneInput({ sourceMode: "files", timeWindow: "all", channels, records });
    const withLog = buildChannelPaneModel(
      input(
        [file("System"), file(AAD), file(MEMBER, MEMBER)],
        [record("System", NOW - HOUR), record(AAD, NOW - HOUR), log(MEMBER, NOW - 2 * HOUR)],
      ),
    );
    const without = buildChannelPaneModel(
      input([file("System"), file(AAD)], [record("System", NOW - HOUR), record(AAD, NOW - HOUR)]),
    );
    expect(without.rows.get(AAD)?.index).toBe(1);
    expect(withLog.rows.get(AAD)?.index).toBe(without.rows.get(AAD)?.index);
    expect(withLog.rows.get("System")?.index).toBe(without.rows.get("System")?.index);
  });

  it("treats a channel with any event record as a channel, not a text log", () => {
    const mixed = buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file("Mixed")],
        records: [record("Mixed", NOW - HOUR), log("Mixed", NOW - 2 * HOUR)],
      }),
    );
    expect(mixed.textLogs).toEqual([]);
    expect(mixed.rows.get("Mixed")?.stats.total).toBe(2);
  });

  it("starts its group open", () => {
    expect(defaultExpandedGroups(model()).has("TextLogs")).toBe(true);
  });
});

describe("text-log members carry their coverage", () => {
  const MEMBER = "C:\\cases\\bundle.zip::logs/IntuneManagementExtension.log";
  const log = (at: number) => ({ ...record(MEMBER, at), originKind: "log" as const });
  const logs = (count: number) => Array.from({ length: count }, (_, i) => log(NOW - (i + 1) * HOUR));
  const build = (over: Partial<ChannelPaneInput>) =>
    buildChannelPaneModel(
      paneInput({
        sourceMode: "files",
        timeWindow: "all",
        channels: [file(MEMBER, MEMBER)],
        ...over,
      }),
    );

  it("shows a member cut off at the archive's line limit as partial, with the reason", () => {
    // A 60,000-line member is parsed up to MAX_ARCHIVE_TEXT_RECORDS (25,000) lines.
    const reason = "text member parsing stopped after 25000 lines; later records were not parsed";
    const built = build({ records: logs(3), coverageDetails: [gap(MEMBER, "limit", reason)] });
    expect(built.textLogs).toEqual([
      expect.objectContaining({ name: MEMBER, entries: 3, state: "partial", reasons: [reason] }),
    ]);
  });

  it("shows a member with lines that would not parse as partial", () => {
    const reason = "12 text records could not be parsed";
    const built = build({
      records: logs(2),
      coverageDetails: [gap(MEMBER, "record", reason)],
      legacyCoverage: [`${MEMBER}: ${reason}`],
    });
    expect(built.textLogs[0]).toMatchObject({ state: "partial", entries: 2, reasons: [reason] });
  });

  it("shows a member with no records and a gap that says why as not read, not as zero entries", () => {
    const reason = "12 text records could not be parsed";
    const built = build({
      records: [],
      archiveMembers: [{ path: MEMBER, kind: "text" }],
      coverageDetails: [gap(MEMBER, "record", reason)],
    });
    expect(built.textLogs).toEqual([
      expect.objectContaining({ entries: 0, state: "notRead", reasons: [reason] }),
    ]);
  });

  it("shows a member cut to zero lines by the archive budget as not read", () => {
    const built = build({
      records: [],
      archiveMembers: [{ path: MEMBER, kind: "text" }],
      coverageDetails: [
        gap(MEMBER, "limit", "text member parsing stopped after 0 lines; later records were not parsed"),
      ],
    });
    expect(built.textLogs[0]).toMatchObject({ entries: 0, state: "notRead" });
  });

  it("shows an empty member as read, with a real zero", () => {
    const built = build({
      records: [],
      archiveMembers: [{ path: MEMBER, kind: "text" }],
      coverageDetails: [gap(MEMBER, "empty", "text member is empty")],
    });
    expect(built.textLogs).toEqual([
      expect.objectContaining({ entries: 0, state: "read", reasons: [] }),
    ]);
  });

  it("never lists an empty or unparseable text member as an event channel", () => {
    // None of these kept a record, so only the archive's member list or the label names them.
    for (const over of [
      { archiveMembers: [{ path: MEMBER, kind: "text" as const }] },
      { archiveMembers: [] },
    ]) {
      const built = build({ records: [], coverageDetails: [gap(MEMBER, "empty", "text member is empty")], ...over });
      expect(built.channels).toEqual([]);
      expect(built.totalCount).toBe(0);
      expect(built.readCount).toBe(0);
      expect(built.textLogs).toHaveLength(1);
    }
  });

  it("keeps an EVTX member that kept nothing as a channel, rotated names included", () => {
    for (const member of [
      "C:\\cases\\bundle.zip::logs/System.evtx",
      "C:\\cases\\bundle.zip::logs/System.evtx.1",
    ]) {
      const built = build({
        channels: [file(member, member)],
        records: [],
        coverageDetails: [gap(member, "chunk", "chunk 3 is corrupt")],
      });
      expect(built.textLogs).toEqual([]);
      expect(built.rows.get(member)?.state).toBe("notRead");
    }
  });
});

describe("sources no listed channel came from", () => {
  const filesInput = (over: Partial<ChannelPaneInput>) =>
    paneInput({
      sourceMode: "files",
      timeWindow: "all",
      channels: [file("System")],
      records: [record("System", NOW - HOUR)],
      ...over,
    });

  it("lists a member the archive's record budget skipped, though the gap is a limit", () => {
    const member = "C:\\cases\\bundle.zip::logs/Security.evtx";
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap(member, "limit", "archive record budget of 1000000 records was exhausted"),
        ],
      }),
    );
    expect(built.rows.get("Security")).toMatchObject({ state: "notRead", selectable: false });
    expect(built.totalCount).toBe(2);
    expect(built.readCount).toBe(1);
  });

  it("lists the next unparsed source when the manifest's byte budget ran out", () => {
    const built = buildChannelPaneModel(
      filesInput({
        manifestCoverage: [
          { kind: "limitReached", path: "C:\\logs\\Next.evtx", reason: "the manifest byte budget was reached" },
        ],
      }),
    );
    expect(built.rows.get("Next")?.state).toBe("notRead");
  });

  it("lists a rotated log, which the archive accepts as an EVTX name", () => {
    for (const source of ["C:\\logs\\System.evtx.1", "C:\\cases\\bundle.zip::logs/System.evtx.12"]) {
      const built = buildChannelPaneModel(
        filesInput({ coverageDetails: [gap(source, "file", "could not be parsed")] }),
      );
      const name = source.slice(Math.max(source.lastIndexOf("\\"), source.lastIndexOf("/")) + 1);
      expect(built.rows.get(name)).toMatchObject({ state: "notRead", selectable: false });
      expect(built.rows.get("System")?.state).toBe("read");
    }
  });

  it("does not drop a coalesced summary, and says the gaps could not be attributed", () => {
    // Past the per-run limit the backend folds gaps into one summary under a made-up source.
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap("<coverage>", "limit", "4096 further coverage gaps were coalesced"),
          gap("<archive coverage>", "limit", "812 archive coverage gaps were coalesced"),
        ],
        legacyCoverage: ["<live tail coverage>: 40 tail coverage gaps were coalesced"],
      }),
    );
    expect(built.unattributed.count).toBe(3);
    expect(built.unattributed.reasons).toEqual([
      "<coverage>: 4096 further coverage gaps were coalesced",
      "<archive coverage>: 812 archive coverage gaps were coalesced",
      "<live tail coverage>: 40 tail coverage gaps were coalesced",
    ]);
    expect(built.totalCount).toBe(1);
    expect(built.readCount).toBe(1);
  });

  it("does not invent a row named after a wildcard that matched nothing", () => {
    const built = buildChannelPaneModel(
      filesInput({
        manifestCoverage: [
          { kind: "missing", path: "C:\\logs\\Sys*.evtx", reason: "no files matched the pattern" },
          { kind: "missing", path: "C:\\logs\\Sec?rity.evtx", reason: "no files matched the pattern" },
        ],
      }),
    );
    expect(built.totalCount).toBe(1);
    expect(built.channels.map((channel) => channel.name)).toEqual(["System"]);
    expect(built.unattributed.count).toBe(2);
    expect(built.unattributed.reasons[0]).toBe("C:\\logs\\Sys*.evtx: no files matched the pattern");
  });

  it("discloses a gap on a folder, a gap with no source and a gap from a source nobody listed", () => {
    const built = buildChannelPaneModel(
      filesInput({
        manifestCoverage: [
          { kind: "accessDenied", path: "C:\\logs\\protected-folder", reason: "folder access was denied" },
        ],
        legacyCoverage: ["something went wrong reading the sources", "Elsewhere: not read (gone)"],
      }),
    );
    expect(built.unattributed.count).toBe(3);
    expect(built.unattributed.reasons).toContain("something went wrong reading the sources");
    expect(built.unattributed.reasons).toContain("Elsewhere: not read (gone)");
    expect(built.totalCount).toBe(1);
  });

  it("reports nothing unattributed when every gap belongs to a row", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap("C:\\logs\\System.evtx", "chunk", "chunk 2 was zero-filled"),
          gap("C:\\logs\\Security.evtx", "accessDenied", "denied"),
          gap("C:\\logs\\System.evtx", "provider", "provider message could not be formatted"),
        ],
        legacyCoverage: ["C:\\logs\\Security.evtx: denied"],
      }),
    );
    expect(built.unattributed).toEqual({ count: 0, reasons: [] });
  });

  it("matches a remote gap to its channel by its Machine/Channel source", () => {
    const built = buildChannelPaneModel(
      paneInput({
        remoteMachine: "SRV01",
        channels: [live("System")],
        loadedChannels: new Set(["System"]),
        records: [record("System", NOW - HOUR)],
        legacyCoverage: ["SRV01/System: live stream batch 3 was not received"],
      }),
    );
    expect(built.rows.get("System")?.state).toBe("partial");
    expect(built.unattributed.count).toBe(0);
  });
});

describe("sources the backend accepts, mirrored", () => {
  const VSS = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\winevt\\Logs\\Security.evtx";
  const filesInput = (over: Partial<ChannelPaneInput>) =>
    paneInput({
      sourceMode: "files",
      timeWindow: "all",
      channels: [file("System")],
      records: [record("System", NOW - HOUR)],
      ...over,
    });

  it("lists a shadow copy a non-elevated process was refused as needs elevation", () => {
    // The "?" of the \\?\ prefix is not a wildcard: a VSS path is a file.
    const built = buildChannelPaneModel(
      filesInput({
        manifestCoverage: [
          { kind: "accessDenied", path: VSS, reason: "VSS event-log sources require an elevated process" },
        ],
      }),
    );
    expect(built.rows.get("Security")).toMatchObject({ state: "needsElevation", selectable: false });
    expect(built.unattributed.count).toBe(0);
    expect(built.totalCount).toBe(2);
  });

  it("lists a shadow copy an elevated process could not parse as not read", () => {
    const built = buildChannelPaneModel(
      filesInput({ coverageDetails: [gap(VSS, "file", "the file could not be parsed")] }),
    );
    expect(built.rows.get("Security")).toMatchObject({ state: "notRead", selectable: false });
    expect(built.unattributed.count).toBe(0);
  });

  it("reads a shadow copy path with forward slashes and any case the same way", () => {
    const path = VSS.replace(/\\/g, "/").toUpperCase();
    const built = buildChannelPaneModel(
      filesInput({ coverageDetails: [gap(path, "file", "the file could not be parsed")] }),
    );
    expect(built.unattributed.count).toBe(0);
    expect(built.totalCount).toBe(2);
  });

  it("does not take a path that merely starts like a shadow copy for one", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap(
            "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\Logs\\Sys*.evtx",
            "missing",
            "no files matched the pattern",
          ),
        ],
      }),
    );
    expect(built.totalCount).toBe(1);
    expect(built.unattributed.count).toBe(1);
  });

  it("strips the long-path prefix before looking for a wildcard", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap("\\\\?\\C:\\logs\\Security.evtx", "accessDenied", "denied"),
          gap("\\\\?\\C:\\logs\\Sys*.evtx", "missing", "no files matched the pattern"),
        ],
      }),
    );
    expect(built.rows.get("Security")?.state).toBe("needsElevation");
    expect(built.unattributed.reasons).toEqual([
      "\\\\?\\C:\\logs\\Sys*.evtx: no files matched the pattern",
    ]);
  });

  it("counts a bracket as a wildcard, as the backend does", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [gap("C:\\logs\\Sys[t]em.evtx", "missing", "no files matched the pattern")],
      }),
    );
    expect(built.totalCount).toBe(1);
    expect(built.channels.map((channel) => channel.name)).toEqual(["System"]);
    expect(built.unattributed.count).toBe(1);
  });

  it("lists the other names the backend opens as event logs: .evtx~ and .evtx.bak", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap("C:\\logs\\Application.evtx~", "file", "the file could not be parsed"),
          gap("C:\\logs\\Setup.evtx.bak", "file", "the file could not be parsed"),
        ],
      }),
    );
    expect(built.rows.get("Application.evtx~")).toMatchObject({ state: "notRead", selectable: false });
    expect(built.rows.get("Setup.evtx.bak")).toMatchObject({ state: "notRead", selectable: false });
    expect(built.unattributed.count).toBe(0);
  });

  it("does not take a name that only resembles an event log for one", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap("C:\\logs\\System.evtxx", "file", "the file could not be parsed"),
          gap("C:\\logs\\evtx", "file", "the file could not be parsed"),
        ],
      }),
    );
    expect(built.totalCount).toBe(1);
    expect(built.unattributed.count).toBe(2);
  });

  it("rejects an archive member whose stem is empty, as is_evtx_name does", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [gap("C:\\cases\\bundle.zip::logs/.evtx.1", "file", "could not be parsed")],
      }),
    );
    expect(built.totalCount).toBe(1);
    expect(built.unattributed.count).toBe(1);
  });
});

describe("what the header counts as unattributed", () => {
  const filesInput = (over: Partial<ChannelPaneInput>) =>
    paneInput({
      sourceMode: "files",
      timeWindow: "all",
      channels: [file("System")],
      records: [record("System", NOW - HOUR)],
      ...over,
    });

  it("is not triggered by an archive member that is only inventory", () => {
    // A registry hive and a trace file can never be channels. Their gaps stay in the banner.
    const reg = "C:\\cases\\bundle.zip::logs/Profile.reg";
    const etl = "C:\\cases\\bundle.zip::logs/Boot.etl";
    const built = buildChannelPaneModel(
      filesInput({
        archiveMembers: [
          { path: reg, kind: "registry" },
          { path: etl, kind: "binary" },
        ],
        coverageDetails: [
          gap(reg, "unsupported", "registry hives are listed but not parsed"),
          gap(etl, "unsupported", "binary members are listed but not parsed"),
        ],
      }),
    );
    expect(built.unattributed).toEqual({ count: 0, reasons: [] });
    expect(built.totalCount).toBe(1);
  });

  it("still counts a gap about a member the open did not list at all", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [
          gap("C:\\cases\\bundle.zip::logs/Boot.etl", "unsupported", "binary members are listed but not parsed"),
        ],
      }),
    );
    expect(built.unattributed.count).toBe(1);
  });

  it("counts each distinct gap once, whichever lists carry it", () => {
    const built = buildChannelPaneModel(
      filesInput({
        coverageDetails: [gap("<coverage>", "limit", "4096 further coverage gaps were coalesced")],
        legacyCoverage: [
          "<coverage>: 4096 further coverage gaps were coalesced",
          "<live tail coverage>: 40 tail coverage gaps were coalesced",
        ],
        tailCoverage: ["<live tail coverage>: 40 tail coverage gaps were coalesced"],
      }),
    );
    expect(built.unattributed.count).toBe(2);
    expect(built.unattributed.reasons).toEqual([
      "<coverage>: 4096 further coverage gaps were coalesced",
      "<live tail coverage>: 40 tail coverage gaps were coalesced",
    ]);
  });

  it("keeps every distinct reason for the pane to cap", () => {
    const built = buildChannelPaneModel(
      filesInput({
        legacyCoverage: Array.from({ length: 7 }, (_, i) => `Elsewhere${i}: not read (gone)`),
      }),
    );
    expect(built.unattributed.count).toBe(7);
    expect(built.unattributed.reasons).toHaveLength(7);
  });
});
