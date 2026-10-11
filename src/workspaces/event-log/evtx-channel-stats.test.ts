import { describe, expect, it } from "vitest";
import {
  CHANNEL_ACTIVITY_BINS,
  buildChannelPaneModel,
  buildChannelTree,
  channelDisplayOrder,
  computeChannelStats,
  recordTimestampMs,
  scaleActivityBars,
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

function file(name: string): EvtxChannelInfo {
  return { name, eventCount: 0, sourceType: { file: { path: `C:\\logs\\${name}.evtx` } } };
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

describe("channel tree and display order", () => {
  const channels = [
    live("Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"),
    live("System"),
    live("Microsoft-Windows-AAD/Operational"),
    live("Application"),
    live("Security"),
    live("Setup"),
  ];

  it("puts Windows Logs first in Event Viewer order, then the sorted service tree", () => {
    const order = channelDisplayOrder(buildChannelTree(channels));
    expect([...order.keys()]).toEqual([
      "Application",
      "Security",
      "System",
      "Setup",
      "Microsoft-Windows-AAD/Operational",
      "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    ]);
    expect([...order.values()]).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it("does not depend on the order the channels arrived in", () => {
    const forward = channelDisplayOrder(buildChannelTree(channels));
    const backward = channelDisplayOrder(buildChannelTree([...channels].reverse()));
    expect([...backward.entries()].sort()).toEqual([...forward.entries()].sort());
  });

  it("visits a node's own channel before the channels beneath it", () => {
    const order = channelDisplayOrder(
      buildChannelTree([live("Contoso/Operational"), live("Contoso"), live("Fabrikam/Operational")]),
    );
    expect([...order.keys()]).toEqual(["Contoso", "Contoso/Operational", "Fabrikam/Operational"]);
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
      expect([...model.order.keys()]).toEqual([
        "Security",
        "System",
        "Microsoft-Windows-AAD/Operational",
      ]);
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

    it("gives every channel the same color index no matter which rows are shown", () => {
      const withRow = buildChannelPaneModel(input);
      expect(withRow.rows.get("Security")?.index).toBe(0);
      expect(withRow.rows.get("System")?.index).toBe(1);
      expect(withRow.rows.get("Microsoft-Windows-AAD/Operational")?.index).toBe(2);
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
