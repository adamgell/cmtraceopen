/**
 * The pure words and rules of the "Not placed" pane (spec 8.11a), over `UnplacedItem` objects shaped
 * exactly as the engine serializes them (origin and reason, nothing else).
 */
import { describe, expect, it } from "vitest";
import analysisSessionSource from "../../../src-tauri/src/event_log/analysis_session.rs?raw";
import {
  UNPLACED_LIST_LIMIT,
  describeUnplaced,
  logViewerLines,
  notPlacedCaption,
  notPlacedLabel,
  openAtLineAvailability,
  unplacedCardLine,
  unplacedCopyText,
  unplacedHeader,
  unplacedOmittedNotice,
  type UnplacedListInput,
} from "./evtx-unplaced";
import unplacedSource from "./evtx-unplaced.ts?raw";
import type { UnplacedItem } from "./unified-timeline";

function logItem(n: number, file = `C:\\Logs\\ccm${n % 3}.log`): UnplacedItem {
  return {
    reason: "missingTimestamp",
    origin: {
      kind: "log",
      file,
      component: n % 2 === 0 ? "Policy" : null,
      line: n,
      source: "writer.cpp",
      machine: null,
      bundle: null,
      recordId: n,
    },
  };
}

function eventItem(n: number, recordIdText: string | null = String(88_000 + n)): UnplacedItem {
  return {
    reason: "missingTimestamp",
    origin: {
      kind: "event",
      stableId: `source4:Live|machine10:DESKTOP-01|channel6:System|record${n}`,
      source: "Live",
      machine: "DESKTOP-01",
      bundle: null,
      channel: "Microsoft-Windows-AAD/Operational",
      provider: "Microsoft-Windows-AAD",
      processId: null,
      eventId: 1_104,
      recordIdText,
      recordId: 88_000 + n,
    },
  };
}

const many = (count: number, make = logItem) => Array.from({ length: count }, (_, i) => make(i + 1));
const list = (items: UnplacedItem[], total: number | null = items.length): UnplacedListInput => ({
  items,
  total,
});

describe("the cap and what it left out", () => {
  it("lists at most 100 rows and counts the rest from the engine's count, not the preview's length", () => {
    const view = describeUnplaced(list(many(100), 5_000));
    expect(view.rows).toHaveLength(100);
    expect(view.total).toBe(5_000);
    expect(view.omitted).toBe(4_900);
    expect(unplacedOmittedNotice(view)).toBe(
      "Showing the first 100 of 5,000; 4,900 omitted. The engine returns a bounded preview, so the others cannot be listed here.",
    );
  });

  it("caps a list longer than the limit defensively and counts what the cap dropped", () => {
    const view = describeUnplaced(list(many(150)));
    expect(view.rows).toHaveLength(100);
    expect(view.omitted).toBe(50);
    expect(view.complete).toBe(false);
  });

  it("omits nothing, and says nothing, when the list holds every item", () => {
    const view = describeUnplaced(list(many(7)));
    expect(view.omitted).toBe(0);
    expect(view.complete).toBe(true);
    expect(unplacedOmittedNotice(view)).toBeNull();
  });

  it("keeps the limit together with the engine's own preview cap", () => {
    const engine = /const MAX_ANALYSIS_TIMELINE_PREVIEW_ITEMS: usize = (\d+);/.exec(analysisSessionSource);
    expect(engine).not.toBeNull();
    expect(UNPLACED_LIST_LIMIT).toBe(Number(engine?.[1]));
  });

  it("preserves the engine's order and does not sort", () => {
    const items = [logItem(9), eventItem(2), logItem(3)];
    expect(describeUnplaced(list(items)).rows.map((row) => row.originId)).toEqual(
      items.map((item) => describeUnplaced(list([item])).rows[0].originId),
    );
  });
});

describe("a count that is not known is never 0", () => {
  it("treats a null count with items as unknown: no omitted count, no zero", () => {
    const view = describeUnplaced(list(many(3), null));
    expect(view.total).toBeNull();
    expect(view.omitted).toBeNull();
    expect(view.complete).toBe(false);
    expect(view.present).toBe(true);
    expect(notPlacedLabel(view)).toBe("Not placed (count unknown)");
    expect(unplacedHeader(view)).toBe(
      "The number of items that carry no timestamp is not known. Placing them would invent an order the evidence does not support.",
    );
    expect(unplacedOmittedNotice(view)).toBe(
      "Showing the first 3 unplaced entries; the number in this session is not known.",
    );
    for (const text of [notPlacedLabel(view), unplacedHeader(view), unplacedOmittedNotice(view) ?? ""]) {
      expect(text).not.toMatch(/\b0\b/);
    }
  });

  it("treats a count below the items listed as contradictory, so unknown", () => {
    const view = describeUnplaced(list(many(5), 3));
    expect(view.total).toBeNull();
    expect(view.omitted).toBeNull();
    expect(view.complete).toBe(false);
  });

  it("has nothing to show for a known 0 with no item, and for an unknown count with no item", () => {
    expect(describeUnplaced(list([], 0)).present).toBe(false);
    expect(describeUnplaced(list([], null)).present).toBe(false);
    expect(unplacedCardLine(list([], 0))).toBeNull();
    expect(unplacedCardLine(list([], null))).toBeNull();
  });

  it("shows a known count even when the preview is empty", () => {
    const view = describeUnplaced(list([], 12));
    expect(view.present).toBe(true);
    expect(notPlacedLabel(view)).toBe("Not placed (12)");
    expect(view.omitted).toBe(12);
  });
});

describe("the header and the row label", () => {
  it("states the spec sentence with the count, in the singular for one", () => {
    expect(unplacedHeader(describeUnplaced(list(many(3), 3)))).toBe(
      "3 items carry no timestamp. Placing them would invent an order the evidence does not support.",
    );
    expect(unplacedHeader(describeUnplaced(list(many(1), 1)))).toBe(
      "1 item carries no timestamp. Placing it would invent an order the evidence does not support.",
    );
    expect(unplacedHeader(describeUnplaced(list(many(100), 12_345)))).toMatch(/^12,345 items carry/);
  });

  it("labels the row from the count, not the preview", () => {
    expect(notPlacedLabel(describeUnplaced(list(many(100), 5_000)))).toBe("Not placed (5,000)");
  });
});

describe("the row caption (R3)", () => {
  it("uses the spec's sentence only for a complete list of log lines", () => {
    expect(notPlacedCaption(describeUnplaced(list(many(4))))).toBe(
      "Text-log lines without timestamps are listed, never guessed onto the timeline.",
    );
  });

  it.each([
    ["an event among the log lines", describeUnplaced(list([logItem(1), eventItem(2)]))],
    ["an incomplete list", describeUnplaced(list(many(3), 9))],
    ["an unknown count", describeUnplaced(list(many(3), null))],
    ["nothing listed", describeUnplaced(list([], 4))],
    ["only events", describeUnplaced(list(many(2, eventItem)))],
  ])("uses the neutral sentence for %s", (_why, view) => {
    expect(notPlacedCaption(view)).toBe(
      "Entries without timestamps are listed, never guessed onto the timeline.",
    );
  });
});

describe("the rows", () => {
  it("names a log line by its file, its context and its line, with the LOG chip", () => {
    const [row] = describeUnplaced(list([logItem(7, "C:\\Logs\\IntuneManagementExtension.log")])).rows;
    expect(row).toMatchObject({
      kind: "log",
      chip: "LOG",
      label: "IntuneManagementExtension.log",
      context: "machine unknown · writer.cpp",
      position: "line 7",
      file: "C:\\Logs\\IntuneManagementExtension.log",
      line: 7,
    });
    expect(row.detail).toContain("C:\\Logs\\IntuneManagementExtension.log:7");
  });

  it("names an event by its channel leaf, event id and record, with the EVT chip and no file", () => {
    const [row] = describeUnplaced(list([eventItem(4)])).rows;
    expect(row).toMatchObject({
      kind: "event",
      chip: "EVT",
      label: "Operational (1104)",
      position: "record 88004",
      file: null,
      line: null,
    });
  });

  it("reads an event's record in the engine's identity order, and never prints a missing one as 0", () => {
    expect(describeUnplaced(list([eventItem(1, " 77 ")])).rows[0].position).toBe("record 77");
    const none = { ...eventItem(1, "000") } as UnplacedItem;
    if (none.origin.kind === "event") none.origin = { ...none.origin, recordId: 0 };
    expect(describeUnplaced(list([none])).rows[0].position).toBe("no record ID");
  });

  it("gives every row its own key, even for the same origin listed twice", () => {
    const rows = describeUnplaced(list([logItem(1), logItem(1)])).rows;
    expect(new Set(rows.map((row) => row.key)).size).toBe(2);
  });
});

describe("copy as text", () => {
  const view = describeUnplaced(list([logItem(7), eventItem(2)], 5));

  it("carries the header, the caption, every row and the omitted line", () => {
    const text = unplacedCopyText(view);
    expect(text).toContain("5 items carry no timestamp.");
    expect(text).toContain("Entries without timestamps are listed, never guessed onto the timeline.");
    expect(text).toContain("1. LOG  ccm1.log");
    expect(text).toContain("2. EVT  Operational (1104)");
    expect(text).toContain("Showing the first 2 of 5; 3 omitted.");
  });

  it("has no omitted line for a complete list, and no time anywhere", () => {
    const text = unplacedCopyText(describeUnplaced(list(many(3))));
    expect(text).not.toContain("omitted");
    expect(text).not.toMatch(/\d{1,2}:\d{2}/);
    expect(text).not.toMatch(/[\u2013\u2014]/);
  });
});

describe("the Insights card's line (8.13 item 6)", () => {
  it("uses the existing summary wording, with the kind split, for a complete list", () => {
    expect(unplacedCardLine(list([logItem(1), logItem(2), eventItem(3)]))).toBe(
      "2 log lines and 1 event could not be placed: no timestamp",
    );
  });

  it("says the count, not the preview's length, for a partial list", () => {
    expect(unplacedCardLine(list(many(100), 5_000))).toBe(
      "5,000 timeline items could not be placed: no timestamp",
    );
    expect(unplacedCardLine(list(many(1), 1_001))).not.toContain(" 1 ");
    expect(unplacedCardLine(list([], 1))).toBe("1 timeline item could not be placed: no timestamp");
  });

  it("says at least, and that the total is not known, when only the preview is known", () => {
    expect(unplacedCardLine(list(many(4), null))).toBe(
      "At least 4 timeline items could not be placed: no timestamp. The total is not known.",
    );
  });
});

describe("Open in Log Viewer (R4)", () => {
  const file = "C:\\Logs\\ccm1.log";
  const other = "C:\\Logs\\other.log";
  const entries = [
    { filePath: file, lineNumber: 7 },
    { filePath: file, lineNumber: 8 },
  ];
  const mixed = [...entries, { filePath: other, lineNumber: 7 }];
  const viewer = (openFilePath: string | null, loaded = entries) => logViewerLines(openFilePath, loaded);

  it("is enabled only for the open file when it holds that exact line", () => {
    const result = openAtLineAvailability(viewer(file), file, 7);
    expect(result).toEqual({
      enabled: true,
      reason: null,
      name: "Open ccm1.log in the Log Viewer near line 7",
    });
  });

  it("is disabled, with its reason, when no single file is open", () => {
    const result = openAtLineAvailability(viewer(null), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe("The Log Viewer has no single file open, so this line cannot be opened there.");
  });

  it("is disabled when a different file is open, naming the file to open first", () => {
    const result = openAtLineAvailability(viewer(other, mixed), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe("The Log Viewer has a different file open. Open ccm1.log there first.");
  });

  it("is disabled when the open file does not hold that line, even if another file does", () => {
    const result = openAtLineAvailability(viewer(file), file, 99);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe("Line 99 is not among the lines the Log Viewer has loaded.");
    expect(logViewerLines(other, mixed).lines.has(7)).toBe(true);
    expect(logViewerLines(other, mixed).lines.has(8)).toBe(false);
  });

  it("is disabled when lines of several files are loaded, as after a merged tab, even for the open file's own line", () => {
    // createMergedTab leaves openFilePath as it was while the entries span several files, and the
    // consumer of the scroll target ignores the file: line 7 could select the other file's line 7.
    const result = openAtLineAvailability(viewer(file, mixed), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe(
      "The Log Viewer has lines of several files loaded, so it cannot open this one at its place.",
    );
    expect(viewer(file, mixed).otherFilesLoaded).toBe(true);
    expect(viewer(file).otherFilesLoaded).toBe(false);
  });

  it("is disabled when the open file's lines were not loaded", () => {
    expect(openAtLineAvailability(viewer(file, []), file, 7).enabled).toBe(false);
  });

  it("compares the path exactly, with no case or slash folding", () => {
    expect(openAtLineAvailability(viewer("c:\\logs\\ccm1.log"), file, 7).enabled).toBe(false);
  });

  it("always names the button 'near line n', enabled or not", () => {
    expect(openAtLineAvailability(viewer(null), file, 7).name).toContain("near line 7");
    expect(openAtLineAvailability(viewer(file), file, 7).name).toContain("near line 7");
  });
});

describe("an unplaced item is never positioned (acceptance)", () => {
  it("imports nothing that can place an entry, and has no time, window or placement in its code", () => {
    const code = unplacedSource
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    const imports = [...code.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
    expect(imports.sort()).toEqual(
      [
        "../../lib/file-paths",
        "./evtx-insights-data",
        "./unified-timeline",
      ].sort(),
    );
    for (const word of [
      "timestampMs",
      "placeInWindow",
      "Placement",
      "defaultLaneWindow",
      "axisTicks",
      "buildChainPlot",
      "TimeWindow",
      "formatClock",
      "formatEventTime",
    ]) {
      expect(code, word).not.toContain(word);
    }
  });

  it("produces rows and texts with no clock time in them", () => {
    const view = describeUnplaced(list([logItem(7), eventItem(2)], 40));
    const everything = JSON.stringify(view) + unplacedCopyText(view) + unplacedHeader(view) + notPlacedCaption(view);
    expect(everything).not.toMatch(/\b\d{1,2}:\d{2}(:\d{2})?\b/);
  });
});
