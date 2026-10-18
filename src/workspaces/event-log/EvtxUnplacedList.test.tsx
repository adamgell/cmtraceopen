/**
 * The "Not placed" pane: the engine's unplaced items, listed and counted from the same reply, never
 * positioned; Copy as text through the view's action regions; and "Open in Log Viewer", which is
 * judged from the log store at render AND at click time.
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ComponentProps } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tokens } from "@fluentui/react-components";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import type { ThemeId } from "../../lib/themes/types";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import type { LogEntry } from "../../types/log";
import { EvtxUnplacedList } from "./EvtxUnplacedList";
import { correlationSizes } from "./evtx-correlation-sizes";
import { EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT } from "./evtx-timeline-paging";
import { unplacedCopyText, describeUnplaced } from "./evtx-unplaced";
import { resolveToken } from "./evtx-visual-tokens";
import listSource from "./EvtxUnplacedList.tsx?raw";
import type { UnplacedItem } from "./unified-timeline";

const FILE = "C:\\Logs\\IntuneManagementExtension.log";

function logItem(n: number, file = FILE): UnplacedItem {
  return {
    reason: "missingTimestamp",
    origin: {
      kind: "log",
      file,
      component: null,
      line: n,
      source: "writer.cpp",
      machine: null,
      bundle: null,
      recordId: n,
    },
  };
}

function eventItem(n: number): UnplacedItem {
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
      recordIdText: String(88_000 + n),
      recordId: 88_000 + n,
    },
  };
}

const entry = (filePath: string, lineNumber: number, timestamp: number | null = null) =>
  ({ filePath, lineNumber, timestamp, message: `line ${lineNumber}` }) as unknown as LogEntry;

type EvtxUnplacedListProps = ComponentProps<typeof EvtxUnplacedList>;

let onReply: ReturnType<typeof vi.fn>;
let onFail: ReturnType<typeof vi.fn>;
let onEscape: ReturnType<typeof vi.fn>;

function mount(extra: Partial<EvtxUnplacedListProps> = {}, fontSize = 13) {
  const props: EvtxUnplacedListProps = {
    list: { items: [logItem(7), logItem(9), eventItem(1)], total: 3 },
    updating: false,
    sizes: correlationSizes(fontSize),
    onReply: onReply as unknown as EvtxUnplacedListProps["onReply"],
    onFail: onFail as unknown as EvtxUnplacedListProps["onFail"],
    onEscape: onEscape as unknown as EvtxUnplacedListProps["onEscape"],
    ...extra,
  };
  const view = render(<EvtxUnplacedList {...props} />);
  return { ...view, rerenderWith: (next: Partial<EvtxUnplacedListProps>) => view.rerender(<EvtxUnplacedList {...props} {...next} />) };
}

/** The Log Viewer with FILE open as a single file, holding lines 7 and 9 with no timestamp. */
function singleFileViewer(overrides: Record<string, unknown> = {}) {
  useLogStore.setState({
    openFilePath: FILE,
    sourceOpenMode: "single-file",
    entries: [entry(FILE, 1, 100), entry(FILE, 7), entry(FILE, 8, 800), entry(FILE, 9)],
    pendingScrollTarget: null,
    ...overrides,
  });
}

const openButtons = () => screen.getAllByRole("button", { name: /^Open in Log Viewer: / });

beforeEach(() => {
  onReply = vi.fn();
  onFail = vi.fn();
  onEscape = vi.fn();
  vi.mocked(writeText).mockReset();
  vi.mocked(writeText).mockResolvedValue(undefined);
  useUiStore.setState({
    themeId: "light",
    logListFontSize: 13,
    activeWorkspace: "event-log",
    activeView: "event-log",
    enabledWorkspaces: null,
  });
  useLogStore.setState({ openFilePath: null, sourceOpenMode: null, entries: [], pendingScrollTarget: null });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("what it shows", () => {
  it("states the header with the engine's count, the caption, and one row per item with its kind chip", () => {
    mount();
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(
      "3 items carry no timestamp. Placing them would invent an order the evidence does not support.",
    );
    // An event is in the list, so the spec's text-log sentence is not used.
    expect(screen.getByText("Entries without timestamps are listed, never guessed onto the timeline.")).toBeInTheDocument();
    const rows = within(screen.getByRole("list", { name: "Unplaced entries" })).getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("LOG");
    expect(rows[0]).toHaveTextContent("IntuneManagementExtension.log");
    expect(rows[0]).toHaveTextContent("line 7");
    expect(rows[2]).toHaveTextContent("EVT");
    expect(rows[2]).toHaveTextContent("record 88001");
  });

  it("draws each row's kind with the shared chip, named in words, and keeps no chip style of its own", () => {
    mount();
    const rows = within(screen.getByRole("list", { name: "Unplaced entries" })).getAllByRole("listitem");
    expect(within(rows[0] as HTMLElement).getByRole("img", { name: "Text log line" })).toHaveAttribute("data-chip", "LOG");
    expect(within(rows[2] as HTMLElement).getByRole("img", { name: "Windows event" })).toHaveAttribute("data-chip", "EVT");
    expect(listSource).toContain("EvtxKindChip");
    expect(listSource).not.toMatch(/colorNeutralBackground3|visuals\.selection\.background|data-chip=/);
  });

  it("uses the spec's sentence for a complete list of log lines", () => {
    mount({ list: { items: [logItem(7), logItem(9)], total: 2 } });
    expect(
      screen.getByText("Text-log lines without timestamps are listed, never guessed onto the timeline."),
    ).toBeInTheDocument();
  });

  it("lists at most the engine's preview limit and says how many it left out, from the count", () => {
    const items = Array.from({ length: EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT + 20 }, (_, i) => logItem(i + 1));
    mount({ list: { items, total: 5_000 } });
    expect(within(screen.getByRole("list", { name: "Unplaced entries" })).getAllByRole("listitem")).toHaveLength(100);
    expect(screen.getByTestId("unplaced-omitted")).toHaveTextContent(
      "Showing the first 100 of 5,000; 4,900 omitted. The engine returns a bounded preview, so the others cannot be listed here.",
    );
  });

  it("says the number is not known, not 0, when the count is unknown, even with nothing listed", () => {
    mount({ list: { items: [], total: null } });
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(
      "The number of items that carry no timestamp is not known.",
    );
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
    expect(screen.getByTestId("unplaced-pane").textContent).not.toMatch(/\b0\b/);
  });

  it("shows nothing for no run, and nothing for a counted zero", () => {
    mount({ list: null });
    expect(screen.queryByTestId("unplaced-pane")).toBeNull();
    cleanup();
    mount({ list: { items: [], total: 0 } });
    expect(screen.queryByTestId("unplaced-pane")).toBeNull();
  });

  it("never prints a time, a position on a timeline, or a dash", () => {
    mount();
    const text = screen.getByTestId("unplaced-pane").textContent ?? "";
    expect(text).not.toMatch(/\b\d{1,2}:\d{2}(:\d{2})?\b/);
    expect(text).not.toMatch(/[\u2013\u2014]/);
    expect(screen.getByTestId("unplaced-pane").querySelector("svg line, [data-marker], [data-lane]")).toBeNull();
  });

  it("sizes its text from the log list font setting, with no px font of its own", () => {
    mount();
    expect(screen.getByRole("heading", { level: 2 }).style.fontSize).toBe("13px");
    cleanup();
    mount({}, 20);
    expect(screen.getByRole("heading", { level: 2 }).style.fontSize).toBe("20px");
    const code = listSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    expect(code).not.toMatch(/fontSize:\s*"?\d/);
    expect(code).not.toMatch(/#[0-9a-fA-F]{3,8}\b|\brgba?\(/);
  });
});

describe("Copy as text", () => {
  it("copies the pane's own text and says so in the view's reply region", async () => {
    const list = { items: [logItem(7), eventItem(1)], total: 2 };
    mount({ list });
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(onReply).toHaveBeenCalledWith("Copied the unplaced list as text."));
    expect(vi.mocked(writeText)).toHaveBeenCalledWith(unplacedCopyText(describeUnplaced(list)));
    expect(onFail).not.toHaveBeenCalled();
  });

  it("reports a failed copy as a failure, not a reply", async () => {
    vi.mocked(writeText).mockRejectedValue(new Error("clipboard denied"));
    mount();
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(onFail).toHaveBeenCalledWith("Copy failed: clipboard denied"));
    expect(onReply).not.toHaveBeenCalled();
  });

  it("waits while the data is updating: the list on show belongs to an earlier session", () => {
    mount({ updating: true });
    const copy = screen.getByRole("button", { name: "Copy as text" });
    expect(copy).toHaveAttribute("aria-disabled", "true");
    // The same reason the chain's Copy gives, spoken and shown.
    expect(copy).toHaveAttribute("aria-description", "Wait for the update to finish.");
    expect(copy).toHaveAttribute("title", "Wait for the update to finish.");
    // It stays focusable, and a click copies nothing and says nothing.
    copy.focus();
    expect(copy).toHaveFocus();
    fireEvent.click(copy);
    expect(vi.mocked(writeText)).not.toHaveBeenCalled();
    expect(onReply).not.toHaveBeenCalled();
    expect(onFail).not.toHaveBeenCalled();
  });

  it("copies again once the update has finished", async () => {
    const view = mount({ updating: true });
    view.rerenderWith({ updating: false });
    const copy = screen.getByRole("button", { name: "Copy as text" });
    expect(copy).not.toHaveAttribute("aria-disabled", "true");
    expect(copy).not.toHaveAttribute("title");
    expect(copy).not.toHaveAttribute("aria-description");
    fireEvent.click(copy);
    await waitFor(() => expect(onReply).toHaveBeenCalledWith("Copied the unplaced list as text."));
  });

  it("adds no live region of its own, so the view keeps exactly its two", () => {
    mount();
    expect(document.querySelectorAll("[role='status'],[role='alert'],[aria-live]")).toHaveLength(0);
  });
});

describe("Escape", () => {
  it("is spent with preventDefault and handed to the view, so the time range is not cleared", () => {
    mount();
    const notPrevented = fireEvent.keyDown(openButtons()[0]!, { key: "Escape" });
    expect(notPrevented).toBe(false);
    expect(onEscape).toHaveBeenCalledTimes(1);
  });

  it("leaves other keys alone", () => {
    mount();
    expect(fireEvent.keyDown(openButtons()[0]!, { key: "Enter" })).toBe(true);
    expect(onEscape).not.toHaveBeenCalled();
  });
});

describe("Open in Log Viewer: which rows get a button, and its name", () => {
  it("is on log rows only, named for what it does ('near line n'), and never on an event row", () => {
    singleFileViewer();
    mount();
    const buttons = openButtons();
    expect(buttons).toHaveLength(2);
    expect(buttons[0]).toHaveAccessibleName("Open in Log Viewer: IntuneManagementExtension.log, near line 7");
    expect(buttons[1]).toHaveAccessibleName("Open in Log Viewer: IntuneManagementExtension.log, near line 9");
    const eventRow = screen.getAllByRole("listitem")[2]!;
    expect(within(eventRow).queryByRole("button")).toBeNull();
  });

  it("is named by its visible words first (WCAG 2.5.3), whether it is enabled or disabled", () => {
    // Enabled: the open single file. Disabled: a merged view. The name is read from the DOM against the
    // text the button shows, so a rewording of either side is caught.
    for (const [state, setup] of [
      ["enabled", () => singleFileViewer()],
      ["disabled", () => singleFileViewer({ sourceOpenMode: "merged" })],
    ] as const) {
      setup();
      const { unmount } = mount();
      for (const button of openButtons()) {
        const visible = button.textContent?.trim() ?? "";
        expect(visible, state).toBe("Open in Log Viewer");
        expect(button.getAttribute("aria-label"), state).toMatch(/^Open in Log Viewer(?=: )/);
        expect(button.getAttribute("aria-label")?.startsWith(visible), state).toBe(true);
        expect(button).toHaveAccessibleName(expect.stringMatching(/near line \d+$/));
      }
      unmount();
    }
  });

  it("is enabled for the open single file when the loaded line is untimed", () => {
    singleFileViewer();
    mount();
    for (const button of openButtons()) expect(button).not.toHaveAttribute("aria-disabled", "true");
  });
});

describe("Open in Log Viewer: arming the target", () => {
  it("sets the pending target for the exact file and line, then switches to the Log view, with no reload", () => {
    singleFileViewer();
    mount();
    const entriesBefore = useLogStore.getState().entries;
    expect(useUiStore.getState().activeView).toBe("event-log");
    fireEvent.click(openButtons()[1]!);
    expect(useLogStore.getState().pendingScrollTarget).toEqual({ filePath: FILE, lineNumber: 9 });
    expect(useUiStore.getState().activeView).toBe("log");
    // No reload: the entries are the very ones that were loaded.
    expect(useLogStore.getState().entries).toBe(entriesBefore);
    expect(onFail).not.toHaveBeenCalled();
  });

  it("leaves no target armed when the switch to the Log view is refused", () => {
    // The Log view is always available in a build, but setActiveView refuses a workspace that is not
    // enabled, and a target armed with no Log view to consume it would scroll a later load.
    singleFileViewer();
    useUiStore.setState({ enabledWorkspaces: ["event-log"] });
    mount();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    fireEvent.click(openButtons()[0]!);
    expect(useUiStore.getState().activeView).toBe("event-log");
    expect(useLogStore.getState().pendingScrollTarget).toBeNull();
    expect(onFail).toHaveBeenCalledWith("Not opened: the Log Viewer is not available here.");
  });

  // One test per state that must not arm. In each the button is disabled with its reason and a click
  // arms nothing and leaves the view where it is.
  const refused: [string, Record<string, unknown>, RegExp][] = [
    ["a merged view with the other files hidden", { sourceOpenMode: "merged" }, /merged view/],
    ["diff mode", { sourceOpenMode: "diff" }, /comparison/],
    ["an aggregate folder", { sourceOpenMode: "aggregate-folder", openFilePath: null }, /folder of files/],
    ["no mode (after a diff closed)", { sourceOpenMode: null }, /no single file open/],
    ["a different file open", { openFilePath: "C:\\Logs\\other.log" }, /different file open/],
    [
      "entries out of line order (the firewall tail, #967)",
      { entries: [entry(FILE, 1, 100), entry(FILE, 8, 800), entry(FILE, 7), entry(FILE, 9)] },
      /own line order/,
    ],
    [
      "a rotated file whose line 7 is timed now",
      { entries: [entry(FILE, 1, 100), entry(FILE, 7, 700), entry(FILE, 8, 800), entry(FILE, 9)] },
      /now has a timestamp/,
    ],
    ["a file that no longer holds the line", { entries: [entry(FILE, 1, 100), entry(FILE, 9)] }, /not among the lines/],
  ];

  it.each(refused)("is disabled, with its reason, and arms nothing in %s", (_state, store, reason) => {
    singleFileViewer(store);
    mount();
    const first = openButtons()[0]!;
    expect(first).toHaveAttribute("aria-disabled", "true");
    expect(first.getAttribute("title")).toMatch(reason);
    expect(first.getAttribute("aria-description")).toMatch(reason);
    const view = useUiStore.getState().activeView;
    fireEvent.click(first);
    expect(useLogStore.getState().pendingScrollTarget).toBeNull();
    expect(useUiStore.getState().activeView).toBe(view);
  });

  it("is disabled while the correlation data is updating, however the Log Viewer looks", () => {
    singleFileViewer();
    mount({ updating: true });
    const first = openButtons()[0]!;
    expect(first).toHaveAttribute("aria-disabled", "true");
    expect(first.getAttribute("title")).toMatch(/being updated/);
    fireEvent.click(first);
    expect(useLogStore.getState().pendingScrollTarget).toBeNull();
  });

  it("judges the click from the log store as it is NOW, not from what it drew", () => {
    singleFileViewer();
    mount();
    const first = openButtons()[0]!;
    expect(first).not.toHaveAttribute("aria-disabled", "true");
    // The store changes after the render and before the click (a diff was opened elsewhere).
    const real = useLogStore.getState();
    vi.spyOn(useLogStore, "getState").mockReturnValue({ ...real, sourceOpenMode: "diff" });
    fireEvent.click(first);
    expect(real.pendingScrollTarget).toBeNull();
    expect(useUiStore.getState().activeView).not.toBe("log");
    expect(onFail).toHaveBeenCalledTimes(1);
    expect(onFail.mock.calls[0]![0]).toMatch(/^Not opened: .*comparison/);
  });

  it("judges the click from the stored entries, not from a derived list", () => {
    singleFileViewer();
    mount();
    const first = openButtons()[0]!;
    const real = useLogStore.getState();
    // The line became timed in the store after the render.
    vi.spyOn(useLogStore, "getState").mockReturnValue({
      ...real,
      entries: [entry(FILE, 1, 100), entry(FILE, 7, 700), entry(FILE, 8, 800), entry(FILE, 9)],
    });
    fireEvent.click(first);
    expect(real.pendingScrollTarget).toBeNull();
    expect(onFail.mock.calls[0]![0]).toMatch(/now has a timestamp/);
  });

  it("refuses a click that arrives while the data is updating, even if the button was drawn enabled", () => {
    singleFileViewer();
    const { rerenderWith } = mount();
    const first = openButtons()[0]!;
    rerenderWith({ updating: true });
    fireEvent.click(first);
    expect(useLogStore.getState().pendingScrollTarget).toBeNull();
  });

  it("does not rescan the entries when it re-renders for nothing the scan reads (a large tailed file)", () => {
    // A proxy counts the passes over the stored entries: the pass is O(n), so it is memoized.
    let passes = 0;
    const counted = new Proxy([entry(FILE, 1, 100), entry(FILE, 7), entry(FILE, 8, 800), entry(FILE, 9)], {
      get(target, property, receiver) {
        if (property === Symbol.iterator) passes += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    singleFileViewer({ entries: counted });
    const { rerenderWith } = mount();
    const first = passes;
    expect(first).toBeGreaterThan(0);
    rerenderWith({ onReply: vi.fn() });
    rerenderWith({ updating: false });
    rerenderWith({ sizes: correlationSizes(13) });
    expect(passes).toBe(first);
    // A new batch of entries is read again, once.
    useLogStore.setState({ entries: [...counted, entry(FILE, 10, 1000)] });
    expect(passes).toBeGreaterThanOrEqual(first);
  });
});

describe("the text reads at 4.5:1 in all seven themes", () => {
  const themes = getAllThemes();

  /** `rgb(r, g, b)` as `#rrggbb`; anything else as given. */
  const toHex = (color: string) => {
    const rgb = /^rgb\(\s*(\d+),\s*(\d+),\s*(\d+)\s*\)$/.exec(color);
    if (!rgb) return color;
    return `#${[rgb[1], rgb[2], rgb[3]].map((part) => Number(part).toString(16).padStart(2, "0")).join("")}`;
  };

  it.each(themes.map((theme) => [theme.id] as const))("in %s: the chips, the header, the caption and the rows", (themeId) => {
    useUiStore.setState({ themeId: themeId as ThemeId });
    mount();
    const theme = themes.find((candidate) => candidate.id === themeId)!;
    const color = (value: string) => toHex(resolveToken(value, theme));
    const surface = color(tokens.colorNeutralBackground1);
    const pairs: [string, string, string][] = [];
    for (const chip of document.querySelectorAll<HTMLElement>("[data-chip]")) {
      pairs.push([`${chip.dataset.chip} chip`, color(chip.style.color), color(chip.style.backgroundColor)]);
    }
    pairs.push(["header", color(screen.getByRole("heading", { level: 2 }).style.color), surface]);
    pairs.push(["caption", color((screen.getByRole("heading", { level: 2 }).nextElementSibling as HTMLElement).style.color), surface]);
    const row = screen.getAllByRole("listitem")[0]!;
    for (const span of Array.from(row.querySelectorAll<HTMLElement>(":scope > span:not([data-chip])"))) {
      pairs.push([`row text ${span.textContent}`, color(span.style.color || row.style.color), surface]);
    }
    expect(pairs.length).toBeGreaterThanOrEqual(6);
    for (const [name, foreground, background] of pairs) {
      expect(contrastRatio(foreground, background), `${themeId} ${name}`).toBeGreaterThanOrEqual(4.5);
    }
  });
});
