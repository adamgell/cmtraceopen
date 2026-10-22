/**
 * The pure words and rules of the "Not placed" pane (spec 8.11a), over `UnplacedItem` objects shaped
 * exactly as the engine serializes them (origin and reason, nothing else).
 */
import { describe, expect, it } from "vitest";
import {
  OPEN_IN_LOG_VIEWER_LABEL,
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
import { EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT } from "./evtx-timeline-paging";
import unplacedSource from "./evtx-unplaced.ts?raw";
import type { SourceOpenMode } from "../../lib/tab-snapshot-cache";
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

  it("caps at the engine's preview limit, the one constant, and keeps no number of its own", () => {
    expect(describeUnplaced(list(many(EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT + 1))).rows).toHaveLength(
      EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT,
    );
    const code = unplacedSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    expect(code).toMatch(/limit: number = EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT,/);
    expect(code).not.toMatch(/\b100\b|\b(UNPLACED_LIST_LIMIT|UNPLACED_PREVIEW_LIMIT)\b/);
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

  it("has nothing to show for a counted 0 with no item, and for no run at all", () => {
    expect(describeUnplaced(list([], 0)).present).toBe(false);
    expect(describeUnplaced(null).present).toBe(false);
    expect(unplacedCardLine(list([], 0))).toBeNull();
    expect(unplacedCardLine(null)).toBeNull();
  });

  it("shows a run whose count is unknown and whose preview is empty, as unknown and never as a counted 0", () => {
    // `{ items: [], total: null }` is a run that may have unplaced items nobody counted. It must not
    // read as `{ items: [], total: 0 }`, and it is told apart from no run by type, not by identity.
    const unknown = describeUnplaced(list([], null));
    expect(unknown.present).toBe(true);
    expect(unknown.total).toBeNull();
    expect(unknown.omitted).toBeNull();
    expect(notPlacedLabel(unknown)).toBe("Not placed (count unknown)");
    expect(unplacedHeader(unknown)).toBe(
      "The number of items that carry no timestamp is not known. Placing them would invent an order the evidence does not support.",
    );
    expect(unplacedCardLine(list([], null))).toBe(
      "The number of timeline items that could not be placed is not known",
    );
    // The same shape as a counted zero in every field but the count, and the reverse in what it shows.
    expect(describeUnplaced(list([], 0)).present).not.toBe(unknown.present);
    expect(unplacedCardLine(list([], 0))).not.toBe(unplacedCardLine(list([], null)));
  });

  it("gives no run an empty view that shows nothing, so a missing run is never a row", () => {
    expect(describeUnplaced(null)).toEqual({
      rows: [],
      total: null,
      complete: false,
      omitted: null,
      allLogLines: false,
      present: false,
    });
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
  /** A Log Viewer entry. The lines an unplaced row names are untimed (timestamp null). */
  const entry = (filePath: string, lineNumber: number, timestamp: number | null = null) => ({
    filePath,
    lineNumber,
    timestamp,
  });
  const entries = [entry(file, 7), entry(file, 8)];
  const bothFiles = [...entries, entry(other, 7)];
  /** The Log Viewer as the log store holds it: its open file, its mode and its entries. */
  const viewer = (
    openFilePath: string | null,
    mode: SourceOpenMode = "single-file",
    loaded = entries,
    wanted: ReadonlySet<number> | null = null,
  ) => logViewerLines(openFilePath, mode, loaded, wanted);
  /** Availability while the correlation data is current, unless a test says it is updating. */
  const check = (v: ReturnType<typeof viewer>, f: string, line: number, updating = false) =>
    openAtLineAvailability(v, f, line, updating);

  it("is enabled only for a single file, open, holding that exact untimed line", () => {
    expect(check(viewer(file), file, 7)).toEqual({
      enabled: true,
      reason: null,
      name: "Open in Log Viewer: ccm1.log, near line 7",
    });
  });

  // One test per state of the log store's sourceOpenMode that is not "single-file". In each the open
  // file is the line's file and holds the exact line, which is what the file and line rules alone
  // would accept; the mode is what refuses.
  it("is disabled in a merged view with every file shown", () => {
    const result = check(viewer(file, "merged", bothFiles), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe(
      "The Log Viewer is showing a merged view of several files, which does not keep each file's lines in order.",
    );
  });

  it("is disabled in a merged view with the other files hidden, though the line is loaded", () => {
    // setFileVisibility leaves the entries holding only the open file, in timestamp order with the
    // untimed lines last. Line 7 is loaded, and a click would select the first TIMED line numbered
    // 7 or more, which is not line 7.
    const hidden = viewer(file, "merged", entries);
    expect(hidden.lines.has(7)).toBe(true);
    const result = check(hidden, file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toContain("merged view");
  });

  it("is disabled in diff mode, where the diff is mounted instead of the list that consumes the target", () => {
    const result = check(viewer(file, "diff"), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe(
      "The Log Viewer is showing a comparison, not the file, so it cannot open this line there.",
    );
  });

  it("is disabled in an aggregate folder, with or without an open file", () => {
    for (const open of [null, file]) {
      const result = check(viewer(open, "aggregate-folder", bothFiles), file, 7);
      expect(result.enabled, String(open)).toBe(false);
      expect(result.reason).toBe(
        "The Log Viewer is showing a folder of files, so it cannot open one line of one file there.",
      );
    }
  });

  it("is disabled with no mode, as after a diff is closed, whatever the open file and entries say", () => {
    const result = check(viewer(file, null), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe("The Log Viewer has no single file open, so this line cannot be opened there.");
  });

  // The aggregate firewall tail (#967) writes a file's rows into its "single-file" snapshot in the
  // aggregate's timestamp order, untimed rows last, and the sidebar restores it as the open file.
  const firewallOrder = [
    entry(file, 1, 100),
    entry(file, 2, 200),
    entry(file, 4, 300),
    entry(file, 5, 400),
    entry(file, 3),
  ];

  it("is disabled in single-file mode when the entries are out of line order, the untimed row last, though the line is loaded", () => {
    const restored = viewer(file, "single-file", firewallOrder);
    expect(restored.lines.has(3)).toBe(true);
    expect(restored.inLineOrder).toBe(false);
    const result = check(restored, file, 3);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe(
      "The Log Viewer is not showing this file in its own line order, so it cannot open this line at its place.",
    );
  });

  it("is enabled in single-file mode when several entries share a line number, as a parser may emit", () => {
    // "Never decreases", not "strictly increases": equal numbers in a row do not move the find.
    const repeated = [
      entry(file, 1, 10),
      entry(file, 2, 20),
      entry(file, 2, 21),
      entry(file, 3, 30),
      entry(file, 7),
      entry(file, 7),
    ];
    expect(viewer(file, "single-file", repeated).inLineOrder).toBe(true);
    expect(check(viewer(file, "single-file", repeated), file, 7).enabled).toBe(true);
  });

  it("refuses the hidden-merged state on the order alone, whatever the mode says", () => {
    expect(check(viewer(file, "single-file", firewallOrder), file, 3).enabled).toBe(false);
  });

  it("counts an empty list and one entry as in order", () => {
    expect(viewer(file, "single-file", []).inLineOrder).toBe(true);
    expect(viewer(file, "single-file", [entry(file, 9)]).inLineOrder).toBe(true);
  });

  // The list on show can be older than the entries (fv2): after a rotation or a reload of the same
  // path, line n is a different record. An unplaced row names an UNTIMED entry, so a timed one at
  // that number proves the row stale.
  it("is disabled when the loaded line n is timed now, as after a rotation, though everything else matches", () => {
    const rotated = [entry(file, 6, 60), entry(file, 7, 70), entry(file, 8, 80)];
    const v = viewer(file, "single-file", rotated);
    expect(v.inLineOrder).toBe(true);
    expect(v.lines.has(7)).toBe(true);
    const result = check(v, file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe(
      "Line 7 of this file now has a timestamp in the Log Viewer, so the list of lines without one is out of date.",
    );
  });

  it("is disabled when line n has a timed entry beside an untimed one", () => {
    const both = [entry(file, 7, 70), entry(file, 7)];
    expect(check(viewer(file, "single-file", both), file, 7).enabled).toBe(false);
  });

  it("is enabled for an untimed line among timed ones", () => {
    const mixed = [entry(file, 5, 50), entry(file, 6, 60), entry(file, 7), entry(file, 8, 80)];
    expect(check(viewer(file, "single-file", mixed), file, 7).enabled).toBe(true);
  });

  it("is disabled while the correlation data is updating, however the Log Viewer looks", () => {
    const result = check(viewer(file), file, 7, true);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe(
      "The correlation is being updated, so this list may belong to an earlier session. Try again when it has finished.",
    );
  });

  it("narrows its line sets to the lines the list names, and still judges order from every entry", () => {
    const many = Array.from({ length: 500 }, (_, i) => entry(file, i + 1, i % 50 === 0 ? null : 1000 + i));
    const narrow = viewer(file, "single-file", many, new Set([1, 51, 500]));
    expect([...narrow.lines].sort((a, b) => a - b)).toEqual([1, 51, 500]);
    expect([...narrow.untimed].sort((a, b) => a - b)).toEqual([1, 51]);
    expect([...narrow.timed]).toEqual([500]);
    expect(narrow.inLineOrder).toBe(true);
    const decreasing = viewer(file, "single-file", [entry(file, 9), entry(file, 2)], new Set([9]));
    expect(decreasing.inLineOrder).toBe(false);
  });

  it("is disabled, with its reason, when a single file is meant but none is open", () => {
    const result = check(viewer(null), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe("The Log Viewer has no single file open, so this line cannot be opened there.");
  });

  it("is disabled when a different file is open, naming the file to open first", () => {
    const result = check(viewer(other, "single-file", bothFiles), file, 7);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe("The Log Viewer has a different file open. Open ccm1.log there first.");
  });

  it("is disabled when the open file does not hold that line, even if another file does", () => {
    const result = check(viewer(file), file, 99);
    expect(result.enabled).toBe(false);
    expect(result.reason).toBe("Line 99 is not among the lines the Log Viewer has loaded.");
    expect(logViewerLines(other, "single-file", bothFiles).lines.has(7)).toBe(true);
    expect(logViewerLines(other, "single-file", bothFiles).lines.has(8)).toBe(false);
  });

  it("is disabled when the open file's lines were not loaded", () => {
    expect(check(viewer(file, "single-file", []), file, 7).enabled).toBe(false);
  });

  it("compares the path exactly, with no case or slash folding", () => {
    expect(check(viewer("c:\\logs\\ccm1.log"), file, 7).enabled).toBe(false);
  });

  it("always starts the name with the button's visible label, enabled or not (WCAG 2.5.3)", () => {
    expect(OPEN_IN_LOG_VIEWER_LABEL).toBe("Open in Log Viewer");
    for (const mode of ["single-file", "merged", "diff", "aggregate-folder", null] as const) {
      expect(check(viewer(file, mode), file, 7).name.startsWith(`${OPEN_IN_LOG_VIEWER_LABEL}: `), String(mode)).toBe(true);
    }
    expect(check(viewer(file), file, 7, true).name.startsWith(`${OPEN_IN_LOG_VIEWER_LABEL}: `)).toBe(true);
  });

  it("always names the button 'near line n', enabled or not", () => {
    for (const mode of ["single-file", "merged", "diff", "aggregate-folder", null] as const) {
      expect(check(viewer(file, mode), file, 7).name, String(mode)).toContain("near line 7");
    }
    expect(check(viewer(file), file, 7, true).name).toContain("near line 7");
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
        "../../lib/tab-snapshot-cache",
        "./evtx-insights-data",
        "./evtx-kind-chip-value",
        "./evtx-timeline-paging",
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
