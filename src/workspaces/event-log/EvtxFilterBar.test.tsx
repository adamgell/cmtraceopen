import { Button, tokens } from "@fluentui/react-components";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { deferred } from "../../test-utils/deferred";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import {
  EVTX_SEARCH_ERROR_ID,
  EVTX_SEARCH_PLACEHOLDER,
  EvtxFilterBar,
  eventLogTimeWindowSnapshotLabel,
} from "./EvtxFilterBar";
import { buildFilterChips, EvtxFilterChips, type EvtxFilterChipInput } from "./EvtxFilterChips";
import { moreFiltersActiveCount } from "./EvtxMoreFilters";
import { EVTX_LEVELS } from "./evtx-filter";
import { buildFilterExport, parseFilterExport, SAVED_FILTER_SCHEMA } from "./evtx-saved-filters";
import { useSavedFilterStore } from "./evtx-filter-store";
import { QUERY_ERROR_SETTLE_MS } from "./evtx-query-error";
import {
  LEVEL_TOGGLE_BACKGROUNDS,
  LEVEL_TOGGLE_STATES,
  levelToggleStates,
  type LevelToggleState,
} from "./evtx-level-toggle";
import { serverFilterKey, useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import { EVTX_TIME_WINDOW_LABELS } from "./types";
import type { EvtxLevel, EvtxRecord, EvtxTimeWindow } from "./types";
import { useUiStore } from "../../stores/ui-store";

let nextId = 1;
const record = (overrides: Partial<EvtxRecord> = {}): EvtxRecord => {
  const id = nextId++;
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-18T12:00:00.000Z",
    timestampEpoch: Date.parse("2026-08-18T12:00:00.000Z"),
    provider: "Example Provider",
    channel: "Application",
    eventId: 42,
    level: "Information",
    computer: "TEST-PC",
    message: "Example event message",
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "Application",
    ...overrides,
  };
};

const withLevel = (level: EvtxLevel, count: number) =>
  Array.from({ length: count }, () => record({ level }));

const ALL_LEVELS = new Set<EvtxLevel>(EVTX_LEVELS);

type EvtxStateValues = Partial<ReturnType<typeof useEvtxStore.getState>>;

function seed(state: EvtxStateValues = {}) {
  useEvtxStore.setState({
    records: [...withLevel("Critical", 1), ...withLevel("Error", 12), ...withLevel("Information", 3)],
    channels: [{ name: "Application", eventCount: 16, sourceType: "live" }],
    selectedChannels: new Set(["Application"]),
    loadedChannels: new Set(["Application"]),
    sourceMode: "files",
    timeWindow: "all",
    filterLevels: new Set(ALL_LEVELS),
    isLoading: false,
    ...state,
  });
}

/** The spec's glyph for a value with no source (section 15.1), as an escape like Phase 8's. */
const UNKNOWN = "\u2014";

const toggle = (level: EvtxLevel) => screen.getByRole("button", { name: `Toggle ${level} events` });
const visibleCount = (button: HTMLElement) => {
  // The count is the last visible (aria-hidden) text in the button.
  const spans = button.querySelectorAll<HTMLElement>(":scope > span[aria-hidden]");
  return spans[spans.length - 1].textContent;
};

beforeEach(() => {
  nextId = 1;
  invoke.mockReset();
  invoke.mockResolvedValue(undefined);
  localStorage.clear();
  useUiStore.setState(useUiStore.getInitialState(), true);
  useEvtxStore.getState().reset();
  useSavedFilterStore.setState({ savedFilters: [] });
});
afterEach(cleanup);

describe("eventLogTimeWindowSnapshotLabel", () => {
  it("labels a relative live window with the passed snapshot time", () => {
    const nowEpoch = Date.UTC(2026, 7, 30, 17, 42, 13);

    expect(eventLogTimeWindowSnapshotLabel("7d", nowEpoch)).toBe(
      `Last 7 days · as of ${new Date(nowEpoch).toLocaleString()}`,
    );
  });

  it("hides the snapshot time for the all-time window", () => {
    expect(eventLogTimeWindowSnapshotLabel("all", 123)).toBe("All time");
  });
});

describe("EvtxFilterBar row", () => {
  it("renders search, the Level group in spec order, and More filters with no active criteria", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);

    // The Main mockup's placeholder, its spacing included (spec 8.3).
    expect(EVTX_SEARCH_PLACEHOLDER).toBe("Search\u2026   id:76  level:error  provider:AAD");
    expect(screen.getByRole("textbox", { name: "Search events" })).toHaveAttribute(
      "placeholder",
      EVTX_SEARCH_PLACEHOLDER,
    );
    const group = screen.getByRole("group", { name: "Level" });
    const buttons = within(group).getAllByRole("button");
    expect(buttons.map((button) => button.getAttribute("aria-label"))).toEqual(
      EVTX_LEVELS.map((level) => `Toggle ${level} events`),
    );
    // Information reads "Info" on the toggle, as the spec writes it; the accessible name stays whole.
    expect(buttons.map((button) => button.querySelectorAll("span")[1].textContent)).toEqual([
      "Critical",
      "Error",
      "Warning",
      "Info",
      "Verbose",
    ]);
    expect(screen.getByRole("button", { name: "More filters · 0" })).toBeInTheDocument();
  });

  it("keeps the Preview label the epic put on the workspace", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByText("Preview")).toBeInTheDocument();
  });

  it("types into the search box through setFilterSearch", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    fireEvent.change(screen.getByRole("textbox", { name: "Search events" }), {
      target: { value: "bitlocker" },
    });
    expect(useEvtxStore.getState().filterSearch).toBe("bitlocker");
  });

  it("sizes the toggles at f - 2 and the other controls at f - 1 from the list font", () => {
    seed();
    act(() => useUiStore.getState().setLogListFontSize(20));
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(toggle("Critical").style.fontSize).toBe("18px");
    expect(screen.getByRole("button", { name: "More filters · 0" }).style.fontSize).toBe("19px");
  });
});

describe("the search box's field grammar (issue #833)", () => {
  const search = () => screen.getByRole("textbox", { name: "Search events" });
  const status = () => document.getElementById(EVTX_SEARCH_ERROR_ID)!;
  const type = (value: string) => fireEvent.change(search(), { target: { value } });
  const wait = (ms: number) => act(() => vi.advanceTimersByTime(ms));
  const warningOf = () =>
    buildEvtxVisualTokens(
      getAllThemes().find((theme) => theme.id === useUiStore.getState().themeId)!,
    ).levels.Warning.textColor;
  const notApplied = (value: string) =>
    `Not applied: level: takes critical, error, warning, info, information or verbose, not "${value}".`;

  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("keeps an empty polite status region under the row while the search is applied", () => {
    seed({ filterSearch: "id:76  level:error  provider:AAD" });
    render(<EvtxFilterBar nowEpoch={0} />);

    expect(search()).toHaveValue("id:76  level:error  provider:AAD");
    expect(status()).toHaveAttribute("role", "status");
    expect(status()).toBeEmptyDOMElement();
    // No margin while empty, so the row is as tall as it was before the grammar.
    expect(status().style.marginTop).toBe("0px");
    expect(search()).toHaveAttribute("aria-invalid", "false");
    expect(search()).not.toHaveAccessibleDescription();
    expect(search().closest("[data-evtx-region='filter-row']")!.lastElementChild).toBe(status());
  });

  it("keeps applying the last search that parsed, and the chip names that one, not the text typed", () => {
    seed();
    render(
      <>
        <EvtxFilterBar nowEpoch={0} />
        <EvtxFilterChips visibleCount={1} loadedCount={16} />
      </>,
    );

    type("level:error");
    expect(useEvtxStore.getState()).toMatchObject({
      filterSearch: "level:error",
      filterSearchDraft: null,
    });

    type("level:error -id:");
    // The box keeps the operator's text; the view, its counts and the chip keep the last valid one.
    expect(search()).toHaveValue("level:error -id:");
    expect(useEvtxStore.getState()).toMatchObject({
      filterSearch: "level:error",
      filterSearchDraft: "level:error -id:",
    });
    expect(screen.getByRole("button", { name: "Remove Search: level:error" })).toBeInTheDocument();

    type("level:error -id:76");
    expect(useEvtxStore.getState()).toMatchObject({
      filterSearch: "level:error -id:76",
      filterSearchDraft: null,
    });
  });

  it("applies no search when none parsed before", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    type("provider:");
    expect(useEvtxStore.getState()).toMatchObject({ filterSearch: "", filterSearchDraft: "provider:" });
  });

  it("says it was not applied only after 400 ms without a keystroke", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const region = status();

    // A half-typed term does not flash a message: each key restarts the wait.
    type("level:");
    wait(QUERY_ERROR_SETTLE_MS - 1);
    expect(region).toBeEmptyDOMElement();
    type("level:e");
    wait(QUERY_ERROR_SETTLE_MS - 1);
    expect(region).toBeEmptyDOMElement();
    expect(search()).toHaveAttribute("aria-invalid", "false");

    wait(1);
    expect(QUERY_ERROR_SETTLE_MS).toBe(400);
    expect(region).toHaveTextContent(notApplied("e"));
    // The node that was mounted empty now holds the message, so it is announced, politely.
    expect(status()).toBe(region);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(region.style.marginTop).toBe("2px");
    expect(search()).toHaveAttribute("aria-invalid", "true");
    expect(search()).toHaveAccessibleDescription(notApplied("e"));
  });

  it("clears the message at once when the text parses again", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    type("level:e");
    wait(QUERY_ERROR_SETTLE_MS);
    expect(status()).toHaveTextContent(notApplied("e"));

    type("level:error");
    expect(status()).toBeEmptyDOMElement();
    expect(status().style.marginTop).toBe("0px");
    expect(search()).toHaveAttribute("aria-invalid", "false");
    expect(search()).not.toHaveAccessibleDescription();
  });

  it("waits the full 400 ms again for a new problem once the text has parsed in between", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    type("level:e");
    wait(QUERY_ERROR_SETTLE_MS);
    expect(status()).toHaveTextContent(notApplied("e"));

    type("level:error");
    expect(status()).toBeEmptyDOMElement();

    // The old message must not come back the moment the text breaks again.
    type('level:error "x');
    wait(QUERY_ERROR_SETTLE_MS - 1);
    expect(status()).toBeEmptyDOMElement();
    expect(search()).toHaveAttribute("aria-invalid", "false");
    expect(search().parentElement!.style.borderColor).toBe("");

    wait(1);
    expect(status()).toHaveTextContent("Not applied: The quote at character 13 is not closed.");
  });

  it("keeps the shown message while a different problem settles, then replaces it", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    type("level:e");
    wait(QUERY_ERROR_SETTLE_MS);

    type('level:e "x');
    wait(QUERY_ERROR_SETTLE_MS - 1);
    // Not blanked while typing, so the row does not jump.
    expect(status()).toHaveTextContent(notApplied("e"));
    wait(1);
    expect(status()).toHaveTextContent("Not applied: The quote at character 9 is not closed.");
  });

  it("announces a message once: the same problem settling again does not rewrite the region", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    type("level:e");
    wait(QUERY_ERROR_SETTLE_MS);

    const observer = new MutationObserver(() => undefined);
    observer.observe(status(), { childList: true, characterData: true, subtree: true });
    type("level:e ");
    wait(QUERY_ERROR_SETTLE_MS);
    expect(status()).toHaveTextContent(notApplied("e"));
    expect(observer.takeRecords()).toEqual([]);
    observer.disconnect();
  });

  it("colors the message and the search border with the Warning text color from the token map", () => {
    seed({ filterSearchDraft: 'boot "failed' });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(search().parentElement!.style.borderColor).toBe("");
    wait(QUERY_ERROR_SETTLE_MS);
    expect(status()).toHaveTextContent("Not applied: The quote at character 6 is not closed.");
    expect(status().style.color).toBe(hexToRgb(warningOf()));
    expect(search().parentElement!.style.borderColor).toBe(hexToRgb(warningOf()));
  });

  it("sizes the message at f - 2 from the list font", () => {
    seed({ filterSearchDraft: "level:" });
    act(() => useUiStore.getState().setLogListFontSize(20));
    render(<EvtxFilterBar nowEpoch={0} />);
    wait(QUERY_ERROR_SETTLE_MS);
    expect(status().style.fontSize).toBe("18px");
    expect(status().style.lineHeight).toBe("26px");
  });

  it("never reloads in live mode: a field query is a local criterion, not a server one", async () => {
    invoke.mockImplementation(async (name: string) =>
      name === "evtx_query_channels" ? new Promise(() => undefined) : undefined,
    );
    seed({ sourceMode: "live" });
    const before = useEvtxStore.getState();
    const keyBefore = serverFilterKey(before.timeWindow, before.filterEventIds, before.filterLevels);
    const recordsBefore = before.records;
    render(<EvtxFilterBar nowEpoch={0} />);

    type("id:76 level:error -provider:AAD");
    type("id:76 level:");
    act(() => {
      const store = useEvtxStore.getState();
      store.setQuickFilter({ ...store.quickFilter, mode: "fieldQuery", query: "id:1098 OR level:critical" });
      store.setQuickFilter({ ...store.quickFilter, mode: "fieldQuery", query: "id:1098 OR" });
      store.setOnLoadCriteria({ search: "provider:", quickFilter: store.quickFilter });
    });
    await act(async () => {
      for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
    });

    const after = useEvtxStore.getState();
    expect(invoke.mock.calls.filter(([name]) => name === "evtx_query_channels")).toHaveLength(0);
    expect(after.isLoading).toBe(false);
    expect(after.records).toBe(recordsBefore);
    expect(serverFilterKey(after.timeWindow, after.filterEventIds, after.filterLevels)).toBe(
      keyBefore,
    );
    expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "false");
  });
});

describe("the store's applied and typed on-load criteria", () => {
  const fieldQuick = (query: string) => ({
    ...useEvtxStore.getState().quickFilter,
    mode: "fieldQuery" as const,
    query,
    action: "hide" as const,
  });

  it("keeps the last field quick filter that parsed applied, and the edited one as the draft", () => {
    const store = useEvtxStore.getState();
    store.setQuickFilter(fieldQuick("level:error"));
    expect(useEvtxStore.getState().quickFilter).toEqual(fieldQuick("level:error"));
    expect(useEvtxStore.getState().quickFilterDraft).toBeNull();

    store.setQuickFilter({ ...fieldQuick("level:error -id:"), action: "show" });
    // Not applied at all: neither the new query nor the new action.
    expect(useEvtxStore.getState().quickFilter).toEqual(fieldQuick("level:error"));
    expect(useEvtxStore.getState().quickFilterDraft).toEqual({
      ...fieldQuick("level:error -id:"),
      action: "show",
    });
  });

  it("applies an invalid Event IDs quick filter as before: that mode keeps its own rule", () => {
    const store = useEvtxStore.getState();
    const ids = { ...store.quickFilter, mode: "eventIds" as const, query: "4624,abc" };
    store.setQuickFilter(ids);
    expect(useEvtxStore.getState().quickFilter).toEqual(ids);
    expect(useEvtxStore.getState().quickFilterDraft).toBeNull();
  });

  it("loads criteria that parse as applied, with no drafts", () => {
    useEvtxStore.getState().setFilterSearch("level:");
    useEvtxStore.getState().setOnLoadCriteria({
      search: "level:error",
      quickFilter: fieldQuick("id:76"),
    });
    expect(useEvtxStore.getState()).toMatchObject({
      filterSearch: "level:error",
      filterSearchDraft: null,
      quickFilter: fieldQuick("id:76"),
      quickFilterDraft: null,
    });
  });

  it("loads criteria that do not parse as drafts, and applies none rather than the ones before", () => {
    const store = useEvtxStore.getState();
    store.setFilterSearch("token");
    store.setQuickFilter(fieldQuick("level:error"));

    store.setOnLoadCriteria({ search: "Event ID: 7036", quickFilter: fieldQuick("level:erro") });
    expect(useEvtxStore.getState()).toMatchObject({
      filterSearch: "",
      filterSearchDraft: "Event ID: 7036",
      quickFilter: fieldQuick(""),
      quickFilterDraft: fieldQuick("level:erro"),
    });
  });

  it("drops both drafts on reset", () => {
    const store = useEvtxStore.getState();
    store.setFilterSearch("level:");
    store.setQuickFilter(fieldQuick("level:"));
    store.reset();
    expect(useEvtxStore.getState().filterSearchDraft).toBeNull();
    expect(useEvtxStore.getState().quickFilterDraft).toBeNull();
  });
});

describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "the search error in the %s theme",
  (_id, theme) => {
    it("reads at 4.5:1 or more on the filter row, which also clears 3:1 for the border", () => {
      const color = resolveToken(buildEvtxVisualTokens(theme).levels.Warning.textColor, theme);
      const row = resolveToken(tokens.colorNeutralBackground1, theme);
      expect(contrastRatio(color, row)).toBeGreaterThanOrEqual(4.5);
    });

    it("paints the measured color", () => {
      vi.useFakeTimers();
      try {
        useUiStore.setState({ themeId: theme.id });
        seed({ filterSearchDraft: "id:abc" });
        render(<EvtxFilterBar nowEpoch={0} />);
        act(() => vi.advanceTimersByTime(QUERY_ERROR_SETTLE_MS));
        const region = document.getElementById(EVTX_SEARCH_ERROR_ID)!;
        expect(region).toHaveTextContent(/^Not applied: id: takes Event IDs/);
        expect(region.style.color).toBe(
          hexToRgb(buildEvtxVisualTokens(theme).levels.Warning.textColor),
        );
      } finally {
        vi.useRealTimers();
      }
    });
  },
);

describe("level toggles", () => {
  it("shows the loaded totals per level, set against what is on screen", () => {
    seed({ filterLevels: new Set<EvtxLevel>(["Error"]) });
    render(<EvtxFilterBar nowEpoch={0} />);

    expect(EVTX_LEVELS.map((level) => visibleCount(toggle(level)))).toEqual(["1", "12", "0", "3", "0"]);
    expect(toggle("Error")).toHaveAccessibleDescription("12 events loaded");
    expect(toggle("Error")).toHaveAttribute("aria-pressed", "true");
    expect(toggle("Critical")).toHaveAttribute("aria-pressed", "false");
    // A deselected level still reports what is loaded, so the operator can see what turning it on adds.
    expect(toggle("Critical")).toHaveAccessibleDescription("1 event loaded");
  });

  it("toggles a level in the store", () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    fireEvent.click(toggle("Warning"));
    expect(useEvtxStore.getState().filterLevels.has("Warning")).toBe(false);
    expect(toggle("Warning")).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(toggle("Warning"));
    expect(useEvtxStore.getState().filterLevels.has("Warning")).toBe(true);
  });

  it("shows a deselected level's count as unknown, not zero, when the live query leaves that level out", () => {
    // Information is deselected, so the strict subset {Critical, Error, Warning, Verbose} goes to
    // the service and no Information record was ever requested.
    seed({
      sourceMode: "live",
      records: [...withLevel("Error", 4), ...withLevel("Verbose", 2)],
      filterLevels: new Set<EvtxLevel>(["Critical", "Error", "Warning", "Verbose"]),
    });
    render(<EvtxFilterBar nowEpoch={0} />);

    expect(visibleCount(toggle("Information"))).toBe(UNKNOWN);
    // Read out as "count not available" for a screen reader; the reason is the sighted tooltip.
    expect(toggle("Information")).toHaveAccessibleDescription(/^Count not available/);
    expect(toggle("Information").querySelector("[title]")?.getAttribute("title")).toMatch(
      /live query leaves out Information events/,
    );
    // Levels that were requested are real counts, including a real zero.
    expect(visibleCount(toggle("Error"))).toBe("4");
    expect(visibleCount(toggle("Warning"))).toBe("0");
  });

  it("keeps real counts for every level while Information is selected, because nothing is left out at the source", () => {
    seed({
      sourceMode: "live",
      records: withLevel("Information", 5),
      filterLevels: new Set<EvtxLevel>(["Information", "Error"]),
    });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(EVTX_LEVELS.map((level) => visibleCount(toggle(level)))).toEqual(["0", "0", "0", "5", "0"]);
  });

  it("keeps real counts in file mode even for a deselected level, because every record is loaded", () => {
    seed({
      sourceMode: "files",
      records: withLevel("Error", 4),
      filterLevels: new Set<EvtxLevel>(["Critical", "Error"]),
    });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(visibleCount(toggle("Information"))).toBe("0");
    expect(toggle("Information")).toHaveAccessibleDescription("0 events loaded");
  });

  it("does not query anything when a level is toggled in file mode", async () => {
    seed({ sourceMode: "files" });
    render(<EvtxFilterBar nowEpoch={0} />);
    fireEvent.click(toggle("Verbose"));
    await act(async () => {
      await Promise.resolve();
    });
    expect(invoke).not.toHaveBeenCalled();
    expect(useEvtxStore.getState().isLoading).toBe(false);
    expect(toggle("Verbose")).not.toHaveAccessibleDescription(/reloads/);
    expect(toggle("Information")).not.toHaveAccessibleDescription(/reloads/);
  });

  describe("live mode (issue #832: do the toggles re-query?)", () => {
    const queryCalls = () => invoke.mock.calls.filter(([name]) => name === "evtx_query_channels");
    const settle = () =>
      act(async () => {
        for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
      });

    it("re-queries every loaded channel when a toggle changes what is sent, and shows the loading state", async () => {
      const reply = deferred<unknown>();
      invoke.mockImplementation(async (name: string) =>
        name === "evtx_query_channels" ? reply.promise : undefined,
      );
      seed({ sourceMode: "live" });
      render(<EvtxFilterBar nowEpoch={0} />);

      // Said before the click: deselecting Information pushes a level subset to the service, so
      // that toggle names the reload, in its tooltip and its description.
      expect(toggle("Information")).toHaveAccessibleDescription(/Changing this level reloads the loaded channels/);
      expect(toggle("Information").title).toMatch(/reloads the loaded channels/);
      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "false");

      fireEvent.click(toggle("Information"));
      await waitFor(() => expect(queryCalls()).toHaveLength(1));

      const [, args] = queryCalls()[0] as [string, { channels: string[]; filter: { levels?: number[] } }];
      expect(args.channels).toEqual(["Application"]);
      expect(args.filter.levels).toEqual([1, 2, 3, 5]);
      expect(useEvtxStore.getState().isLoading).toBe(true);
      expect(useEvtxStore.getState().records).toEqual([]);

      // The row does not pretend the toggle was instant.
      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "true");
      expect(screen.getByRole("progressbar", { name: "Reloading events" })).toBeInTheDocument();
      // And an emptied record list is not available, never zero.
      expect(EVTX_LEVELS.map((level) => visibleCount(toggle(level)))).toEqual(Array(5).fill(UNKNOWN));
      expect(toggle("Error")).toHaveAccessibleDescription(/^Count not available/);
    });

    it("does not re-query when the toggle leaves the server filter alone, and does not claim it will", async () => {
      invoke.mockImplementation(async (name: string) =>
        name === "evtx_query_channels" ? new Promise(() => undefined) : undefined,
      );
      seed({ sourceMode: "live" });
      render(<EvtxFilterBar nowEpoch={0} />);

      // Information stays selected, so the level predicate is not sent either way.
      expect(toggle("Verbose")).not.toHaveAccessibleDescription(/reloads/);
      expect(toggle("Verbose").title).not.toMatch(/reloads/);

      fireEvent.click(toggle("Verbose"));
      await settle();
      expect(queryCalls()).toHaveLength(0);
      expect(useEvtxStore.getState().isLoading).toBe(false);
      expect(toggle("Verbose")).toHaveAttribute("aria-pressed", "false");
      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "false");
    });

    it("names the reload on a toggle that changes the pushed subset while Information is hidden", () => {
      seed({ sourceMode: "live", filterLevels: new Set<EvtxLevel>(["Critical", "Error"]) });
      render(<EvtxFilterBar nowEpoch={0} />);
      expect(toggle("Warning")).toHaveAccessibleDescription(/reloads the loaded channels/);
      expect(toggle("Critical")).toHaveAccessibleDescription(/reloads the loaded channels/);
    });
  });
});

describe("time window", () => {
  const openWindowOptions = async () => {
    fireEvent.click(screen.getByRole("combobox", { name: "Time window" }));
    return (await screen.findAllByRole("option")).map((option) => option.textContent);
  };

  it("offers the five windows and no Custom entry (Q-2) in live mode", async () => {
    seed({ sourceMode: "live", timeWindow: "24h" });
    render(<EvtxFilterBar nowEpoch={0} />);
    const labels = await openWindowOptions();
    expect(labels).toEqual(
      (["1h", "24h", "7d", "30d", "all"] as EvtxTimeWindow[]).map((window) => EVTX_TIME_WINDOW_LABELS[window]),
    );
    expect(labels.join(" ")).not.toMatch(/custom/i);
  });

  it("sets the window through the store", async () => {
    seed({ sourceMode: "live", timeWindow: "24h" });
    render(<EvtxFilterBar nowEpoch={0} />);
    await openWindowOptions();
    fireEvent.click(screen.getByRole("option", { name: EVTX_TIME_WINDOW_LABELS["7d"] }));
    expect(useEvtxStore.getState().timeWindow).toBe("7d");
  });

  it("is 28 px tall like the search box and More filters (spec 8.3)", () => {
    seed({ sourceMode: "live", timeWindow: "24h" });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByRole("combobox", { name: "Time window" }).style.minHeight).toBe("28px");
  });

  it("stays enabled while events load: the store queues a change made during a load", () => {
    // Disabling it would drop keyboard focus from the control just used, since the rows now stay
    // mounted through a refetch. A change made during a load is replayed when the load ends
    // (evtx-store-server-filter.test.ts), with one exception: a change that will not be replayed (the
    // operator stopped the load, or the source dropped, or the load failed before reading anything)
    // is not applied; the criteria go back to those the read used, so the control and the data
    // never disagree (evtx-store-replay.test.ts).
    seed({ sourceMode: "live", timeWindow: "24h", isLoading: true });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByRole("combobox", { name: "Time window" })).toBeEnabled();
  });

  it("stays the same enabled control after a live change reloads the channels", async () => {
    invoke.mockImplementation(async (name: string) =>
      name === "evtx_query_channels" ? new Promise(() => undefined) : undefined,
    );
    seed({ sourceMode: "live", timeWindow: "24h" });
    render(<EvtxFilterBar nowEpoch={0} />);
    const combobox = screen.getByRole("combobox", { name: "Time window" });
    fireEvent.click(combobox);
    fireEvent.click(await screen.findByRole("option", { name: EVTX_TIME_WINDOW_LABELS["7d"] }));

    await waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(true));
    expect(useEvtxStore.getState().timeWindow).toBe("7d");
    const after = screen.getByRole("combobox", { name: "Time window" });
    // The same element, still enabled. (Whether the browser keeps focus on a control that becomes
    // disabled is not something jsdom models, so focus is not asserted here; `toBeEnabled` is what
    // fails if `disabled` comes back.)
    expect(after).toBe(combobox);
    expect(after).toBeEnabled();
  });

  it("is hidden in file mode while the window is All, as before", () => {
    seed({ sourceMode: "files", timeWindow: "all" });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.queryByRole("combobox", { name: "Time window" })).toBeNull();
  });

  it("stays visible in file mode when a saved filter left a window active, so nothing hides unseen", () => {
    seed({ sourceMode: "files", timeWindow: "24h" });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByRole("combobox", { name: "Time window" })).toBeInTheDocument();
  });
});

describe("More filters", () => {
  const openPopover = async () => {
    fireEvent.click(screen.getByRole("button", { name: /^More filters/ }));
    return screen.findByRole("dialog", { name: "More filters" });
  };

  it("counts every active criterion that is not a level toggle, the search box or the time window", () => {
    const base: EvtxFilterChipInput = {
      filterEventIds: "",
      filterSearch: "",
      quickFilter: { ...useEvtxStore.getState().quickFilter },
      selectedChannels: new Set(["System", "Application"]),
      heldChannels: new Set(["System", "Application"]),
    };
    const count = (overrides: Partial<EvtxFilterChipInput> = {}) =>
      moreFiltersActiveCount(buildFilterChips({ ...base, ...overrides }));
    const quick = (overrides: Partial<EvtxFilterChipInput["quickFilter"]>) => ({
      ...base.quickFilter,
      ...overrides,
    });

    expect(count()).toBe(0);
    expect(count({ filterEventIds: "  ", quickFilter: quick({ query: "  " }) })).toBe(0);
    expect(count({ filterEventIds: "4624" })).toBe(1);
    expect(count({ quickFilter: quick({ query: "bitlocker" }) })).toBe(1);
    // A channel subset is a criterion too (spec 8.4 gives it a chip).
    expect(count({ selectedChannels: new Set(["System"]) })).toBe(1);
    expect(
      count({
        filterEventIds: "4624",
        quickFilter: quick({ query: "bitlocker" }),
        selectedChannels: new Set(["System"]),
      }),
    ).toBe(3);
    // The search box is on the row, so it never counts.
    expect(count({ filterSearch: "logon" })).toBe(0);
    // Options of the quick filter are not criteria.
    expect(count({ quickFilter: quick({ caseSensitive: true, highlight: false, action: "hide" }) })).toBe(0);
  });

  it("shows the active count on the button, a channel subset included", () => {
    seed({
      filterEventIds: "4624",
      quickFilter: { ...useEvtxStore.getState().quickFilter, query: "bitlocker" },
      filterSearch: "ignored here",
      sourceMode: "files",
      channels: [
        { name: "Application", eventCount: 1, sourceType: "live" },
        { name: "System", eventCount: 1, sourceType: "live" },
      ],
      selectedChannels: new Set(["Application"]),
    });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByRole("button", { name: "More filters · 3" })).toBeInTheDocument();
  });

  it("keeps the More filters number through a live refetch that empties the loaded channels", () => {
    seed({
      sourceMode: "live",
      channels: [
        { name: "System", eventCount: 1, sourceType: "live" },
        { name: "Application", eventCount: 1, sourceType: "live" },
      ],
      loadedChannels: new Set(["System", "Application"]),
      selectedChannels: new Set(["System"]),
    });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByRole("button", { name: "More filters · 1" })).toBeInTheDocument();

    act(() =>
      useEvtxStore.setState({ isLoading: true, records: [], loadedChannels: new Set<string>() }),
    );
    expect(screen.getByRole("button", { name: "More filters · 1" })).toBeInTheDocument();
  });

  it("holds every control the old filter bar had besides Group by, Columns and Export", async () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const surface = await openPopover();
    const popover = within(surface);

    expect(popover.getByRole("textbox", { name: "Event IDs" })).toBeInTheDocument();
    expect(popover.getByRole("textbox", { name: "Quick filter query" })).toBeInTheDocument();
    for (const name of [
      "Quick filter matching grammar",
      "Quick filter column scope",
      "Quick filter show or hide behavior",
      "Saved filters",
      "Sort by",
    ]) {
      expect(popover.getByRole("combobox", { name })).toBeInTheDocument();
    }
    expect(popover.getByRole("checkbox", { name: "Case" })).toBeInTheDocument();
    expect(popover.getByRole("checkbox", { name: "Highlight" })).toBeInTheDocument();
    expect(popover.getByRole("button", { name: "Change sort direction to descending" })).toBeInTheDocument();
    expect(popover.getByTitle(/Click for UTC/)).toBeInTheDocument();
  });

  it("applies Event IDs, the quick filter, case and highlight through the store", async () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());

    const eventIds = popover.getByRole("textbox", { name: "Event IDs" });
    fireEvent.change(eventIds, { target: { value: "4624-4626" } });
    fireEvent.keyDown(eventIds, { key: "Enter" });
    expect(useEvtxStore.getState().filterEventIds).toBe("4624-4626");

    fireEvent.change(popover.getByRole("textbox", { name: "Quick filter query" }), {
      target: { value: "gpsvc" },
    });
    fireEvent.click(popover.getByRole("checkbox", { name: "Case" }));
    fireEvent.click(popover.getByRole("checkbox", { name: "Highlight" }));
    const quick = useEvtxStore.getState().quickFilter;
    expect(quick.query).toBe("gpsvc");
    expect(quick.caseSensitive).toBe(true);
    expect(quick.highlight).toBe(false);
  });

  describe("Event IDs are a draft until committed", () => {
    it("does not touch the store per keystroke, and commits on Enter", async () => {
      seed();
      render(<EvtxFilterBar nowEpoch={0} />);
      const eventIds = within(await openPopover()).getByRole("textbox", { name: "Event IDs" });

      for (const typed of ["4", "46", "462", "4624"]) {
        fireEvent.change(eventIds, { target: { value: typed } });
        expect(useEvtxStore.getState().filterEventIds).toBe("");
      }
      expect(eventIds).toHaveValue("4624");

      fireEvent.keyDown(eventIds, { key: "Enter" });
      expect(useEvtxStore.getState().filterEventIds).toBe("4624");
    });

    it("commits on blur", async () => {
      seed();
      render(<EvtxFilterBar nowEpoch={0} />);
      const eventIds = within(await openPopover()).getByRole("textbox", { name: "Event IDs" });
      fireEvent.change(eventIds, { target: { value: "7036" } });
      expect(useEvtxStore.getState().filterEventIds).toBe("");
      fireEvent.blur(eventIds);
      expect(useEvtxStore.getState().filterEventIds).toBe("7036");
    });

    it("never commits an invalid list, on Enter or on blur, and says it is invalid while typing", async () => {
      seed({ filterEventIds: "7036" });
      render(<EvtxFilterBar nowEpoch={0} />);
      const popover = within(await openPopover());
      const eventIds = popover.getByRole("textbox", { name: "Event IDs" });

      fireEvent.change(eventIds, { target: { value: "7036,abc" } });
      expect(popover.getByRole("alert", { name: "Invalid Event IDs" })).toBeVisible();
      fireEvent.keyDown(eventIds, { key: "Enter" });
      fireEvent.blur(eventIds);
      expect(useEvtxStore.getState().filterEventIds).toBe("7036");

      fireEvent.change(eventIds, { target: { value: "7036,7040" } });
      expect(popover.queryByRole("alert")).toBeNull();
      fireEvent.keyDown(eventIds, { key: "Enter" });
      expect(useEvtxStore.getState().filterEventIds).toBe("7036,7040");
    });

    it("follows the store when something else changes the list, such as a chip or Clear all", async () => {
      seed({ filterEventIds: "7036" });
      render(<EvtxFilterBar nowEpoch={0} />);
      const eventIds = within(await openPopover()).getByRole("textbox", { name: "Event IDs" });
      expect(eventIds).toHaveValue("7036");

      act(() => useEvtxStore.getState().setFilterEventIds(""));
      expect(eventIds).toHaveValue("");
    });

    it("resyncs the visible field to the list a Stop restored, even while it has focus", async () => {
      // Event IDs committed while a load runs are put back by a Stop, in the update that ends the
      // load. The draft must show the restored list, and it is the field the operator is in.
      seed({ filterEventIds: "7036" });
      render(<EvtxFilterBar nowEpoch={0} />);
      const eventIds = within(await openPopover()).getByRole("textbox", { name: "Event IDs" });
      eventIds.focus();
      fireEvent.change(eventIds, { target: { value: "7036,7040" } });
      fireEvent.keyDown(eventIds, { key: "Enter" });
      expect(useEvtxStore.getState().filterEventIds).toBe("7036,7040");
      expect(eventIds).toHaveValue("7036,7040");

      // What the store's settle step writes: the criteria the read used, nothing else.
      act(() => useEvtxStore.setState({ filterEventIds: "7036" }));

      expect(eventIds).toHaveValue("7036");
      expect(eventIds).toHaveFocus();
    });

    it("also resyncs a half-typed draft when a Stop restores the list under it", async () => {
      seed({ filterEventIds: "" });
      render(<EvtxFilterBar nowEpoch={0} />);
      const eventIds = within(await openPopover()).getByRole("textbox", { name: "Event IDs" });
      eventIds.focus();
      fireEvent.change(eventIds, { target: { value: "4624" } });
      fireEvent.keyDown(eventIds, { key: "Enter" });
      fireEvent.change(eventIds, { target: { value: "4624,46" } });

      act(() => useEvtxStore.setState({ filterEventIds: "" }));

      expect(eventIds).toHaveValue("");
      expect(eventIds).toHaveFocus();
    });

    it("keeps the popover open and sends one query on commit in live mode", async () => {
      invoke.mockImplementation(async (name: string) =>
        name === "evtx_query_channels" ? new Promise(() => undefined) : undefined,
      );
      seed({ sourceMode: "live" });
      render(<EvtxFilterBar nowEpoch={0} />);
      const eventIds = within(await openPopover()).getByRole("textbox", { name: "Event IDs" });

      for (const typed of ["4", "46", "462", "4624"]) {
        fireEvent.change(eventIds, { target: { value: typed } });
      }
      await act(async () => {
        await Promise.resolve();
      });
      expect(invoke).not.toHaveBeenCalledWith("evtx_query_channels", expect.anything());

      fireEvent.keyDown(eventIds, { key: "Enter" });
      await waitFor(() =>
        expect(invoke.mock.calls.filter(([name]) => name === "evtx_query_channels")).toHaveLength(1),
      );
      expect(screen.getByRole("dialog", { name: "More filters" })).toBeInTheDocument();
    });
  });

  it("changes the quick filter grammar, scope and action without closing the popover", async () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());

    fireEvent.click(popover.getByRole("combobox", { name: "Quick filter matching grammar" }));
    fireEvent.click(await screen.findByRole("option", { name: "Event IDs" }));
    expect(useEvtxStore.getState().quickFilter.mode).toBe("eventIds");

    fireEvent.click(popover.getByRole("combobox", { name: "Quick filter show or hide behavior" }));
    fireEvent.click(await screen.findByRole("option", { name: "Hide matches" }));
    expect(useEvtxStore.getState().quickFilter.action).toBe("hide");

    fireEvent.click(popover.getByRole("combobox", { name: "Quick filter column scope" }));
    fireEvent.click(await screen.findByRole("option", { name: "Visible columns" }));
    expect(useEvtxStore.getState().quickFilter.scope).toBe("visibleColumns");

    expect(screen.getByRole("dialog", { name: "More filters" })).toBeInTheDocument();
  });

  it("names the sort-direction action that the button will perform and sorts by a field", async () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());

    const direction = popover.getByRole("button", { name: "Change sort direction to descending" });
    expect(direction).toHaveAttribute("title", "Change sort direction to descending");
    fireEvent.click(direction);
    expect(useEvtxStore.getState().sortDirection).toBe("desc");
    expect(direction).toHaveAttribute("aria-label", "Change sort direction to ascending");
    expect(direction.querySelector("svg")).not.toBeNull();

    fireEvent.click(popover.getByRole("combobox", { name: "Sort by" }));
    fireEvent.click(await screen.findByRole("option", { name: "Event ID" }));
    expect(useEvtxStore.getState().sortField).toBe("eventId");
  });

  it("switches the time zone between local and UTC", async () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());
    fireEvent.click(popover.getByTitle(/Click for UTC/));
    expect(useEvtxStore.getState().timeZoneMode).toBe("utc");
    expect(popover.getByText("UTC")).toBeInTheDocument();
  });

  it("saves the current criteria under a name and applies a saved filter", async () => {
    seed({ filterEventIds: "7036", filterSearch: "service" });
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());

    fireEvent.click(popover.getByRole("combobox", { name: "Saved filters" }));
    fireEvent.click(await screen.findByRole("option", { name: "Save current..." }));
    const name = popover.getByRole("textbox", { name: "Name this filter" });
    fireEvent.change(name, { target: { value: "Service noise" } });
    fireEvent.keyDown(name, { key: "Enter" });

    expect(popover.getByText('Saved "Service noise"')).toBeInTheDocument();
    const saved = useSavedFilterStore.getState().savedFilters;
    expect(saved.map((filter) => filter.name)).toEqual(["Service noise"]);
    expect(saved[0].criteria.beforeLoad.eventIds).toBe("7036");
    expect(saved[0].criteria.onLoad.search).toBe("service");

    act(() => {
      useEvtxStore.getState().setFilterEventIds("");
      useEvtxStore.getState().setFilterSearch("");
    });
    fireEvent.click(popover.getByRole("combobox", { name: "Saved filters" }));
    fireEvent.click(await screen.findByRole("option", { name: "Service noise" }));
    expect(useEvtxStore.getState().filterEventIds).toBe("7036");
    expect(useEvtxStore.getState().filterSearch).toBe("service");
  });

  describe("with a transient time range and record scope set", () => {
    const narrow = () => {
      const [first, second] = useEvtxStore.getState().records;
      act(() => {
        useEvtxStore.getState().setTimeRange({
          startMs: Date.parse("2026-08-18T11:00:00.000Z"),
          endMs: Date.parse("2026-08-18T13:00:00.000Z"),
        });
        useEvtxStore.getState().setRecordScope({
          kind: "finding",
          title: "Service noise finding",
          records: new Set([first, second]),
          counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
        });
      });
    };
    const saveAs = async (name: string) => {
      const popover = within(await openPopover());
      fireEvent.click(popover.getByRole("combobox", { name: "Saved filters" }));
      fireEvent.click(await screen.findByRole("option", { name: "Save current..." }));
      const field = popover.getByRole("textbox", { name: "Name this filter" });
      fireEvent.change(field, { target: { value: name } });
      fireEvent.keyDown(field, { key: "Enter" });
      return popover;
    };

    it("does not save either one: not in the stored filter, its export or an import of it", async () => {
      seed({ filterEventIds: "7036" });
      render(<EvtxFilterBar nowEpoch={0} />);
      narrow();
      expect(useEvtxStore.getState().timeRange).not.toBeNull();
      expect(useEvtxStore.getState().recordScope).not.toBeNull();

      await saveAs("Narrowed");

      const [saved] = useSavedFilterStore.getState().savedFilters;
      expect(saved.criteria.beforeLoad.eventIds).toBe("7036");
      const stored = JSON.stringify(useSavedFilterStore.getState().savedFilters);
      const exported = buildFilterExport(useSavedFilterStore.getState().savedFilters);
      for (const text of [stored, exported, JSON.stringify(parseFilterExport(exported).filters)]) {
        expect(text).not.toMatch(/timeRange|startMs|endMs|recordScope|scopeRecord|Service noise finding/i);
      }
      expect(JSON.parse(exported).schema).toBe(SAVED_FILTER_SCHEMA);
      expect(localStorage.getItem("cmtraceopen-evtx-saved-filters") ?? "").not.toMatch(
        /timeRange|startMs|endMs|recordScope|scopeRecord|Service noise finding/i,
      );
    });

    it("leaves both in place when a saved filter is applied", async () => {
      seed({ filterEventIds: "7036" });
      render(<EvtxFilterBar nowEpoch={0} />);
      const popover = await saveAs("Plain");
      narrow();
      const range = useEvtxStore.getState().timeRange;
      const scope = useEvtxStore.getState().recordScope;

      fireEvent.click(popover.getByRole("combobox", { name: "Saved filters" }));
      fireEvent.click(await screen.findByRole("option", { name: "Plain" }));

      expect(useEvtxStore.getState().timeRange).toBe(range);
      expect(useEvtxStore.getState().recordScope).toBe(scope);
    });
  });

  it("flags invalid ordinary and quick Event IDs in the Warning text color from the token map", async () => {
    seed({
      filterEventIds: "1000,broken",
      quickFilter: { ...useEvtxStore.getState().quickFilter, mode: "eventIds", query: "1000,broken" },
    });
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());
    const warning = buildEvtxVisualTokens(
      getAllThemes().find((theme) => theme.id === useUiStore.getState().themeId)!,
    ).levels.Warning.textColor;

    const eventIds = popover.getByRole("textbox", { name: "Event IDs" });
    expect(eventIds).toHaveAttribute("aria-invalid", "true");
    expect(eventIds).toHaveAccessibleDescription("Invalid Event IDs");
    const quick = popover.getByRole("textbox", { name: "Quick filter query" });
    expect(quick).toHaveAttribute("aria-invalid", "true");
    expect(quick).toHaveAccessibleDescription("Invalid quick Event IDs");

    for (const name of ["Invalid Event IDs", "Invalid quick Event IDs"]) {
      const alert = popover.getByRole("alert", { name });
      expect(alert).toBeVisible();
      expect(alert.style.color).toBe(hexToRgb(warning));
    }

    fireEvent.change(eventIds, { target: { value: "1000" } });
    fireEvent.change(quick, { target: { value: "1000" } });
    expect(popover.queryByRole("alert")).toBeNull();
  });

  it("offers the Field query grammar and says politely, once typing settles, that a query is not applied", async () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());
    const warning = buildEvtxVisualTokens(
      getAllThemes().find((theme) => theme.id === useUiStore.getState().themeId)!,
    ).levels.Warning.textColor;

    fireEvent.click(popover.getByRole("combobox", { name: "Quick filter matching grammar" }));
    fireEvent.click(await screen.findByRole("option", { name: "Field query" }));
    expect(useEvtxStore.getState().quickFilter.mode).toBe("fieldQuery");

    const query = popover.getByRole("textbox", { name: "Quick filter query" });
    expect(query).toHaveAttribute("placeholder", "Field query (e.g. id:76 level:error)");
    // Mounted empty before there is anything to say, so the message is announced when it appears.
    const status = popover.getByRole("status");
    expect(status).toBeEmptyDOMElement();
    expect(query).toHaveAttribute("aria-invalid", "false");
    expect(query).not.toHaveAccessibleDescription();

    fireEvent.change(query, { target: { value: "level:error" } });
    expect(useEvtxStore.getState().quickFilter.query).toBe("level:error");

    fireEvent.change(query, { target: { value: "level:erro" } });
    const message =
      'Not applied: level: takes critical, error, warning, info, information or verbose, not "erro".';
    // The operator's text stays as typed, and the view keeps the last query that parsed.
    expect(query).toHaveValue("level:erro");
    expect(useEvtxStore.getState().quickFilterDraft?.query).toBe("level:erro");
    expect(useEvtxStore.getState().quickFilter.query).toBe("level:error");
    // Nothing yet: the message waits for the typing to settle.
    expect(status).toBeEmptyDOMElement();

    await waitFor(() => expect(status).toHaveTextContent(message));
    expect(popover.getByRole("status")).toBe(status);
    expect(query).toHaveAttribute("aria-invalid", "true");
    expect(query).toHaveAccessibleDescription(message);
    expect(status.style.color).toBe(hexToRgb(warning));
    // Polite, not an assertive alert.
    expect(popover.queryByRole("alert")).toBeNull();

    fireEvent.change(query, { target: { value: "level:error" } });
    expect(status).toBeEmptyDOMElement();
    expect(query).toHaveAttribute("aria-invalid", "false");
    expect(useEvtxStore.getState().quickFilterDraft).toBeNull();
  });

  it("never reports a field-grammar problem for a quick filter in another mode", async () => {
    seed();
    render(<EvtxFilterBar nowEpoch={0} />);
    const popover = within(await openPopover());
    const query = popover.getByRole("textbox", { name: "Quick filter query" });
    expect(useEvtxStore.getState().quickFilter.mode).toBe("oneString");

    vi.useFakeTimers();
    try {
      // Both fail the field grammar; neither means anything to One string, which applies them.
      for (const text of ['abc"d', "id:"]) {
        fireEvent.change(query, { target: { value: text } });
        act(() => vi.advanceTimersByTime(QUERY_ERROR_SETTLE_MS));
        expect(useEvtxStore.getState().quickFilter).toMatchObject({ mode: "oneString", query: text });
        expect(query).toHaveAttribute("aria-invalid", "false");
        expect(query).not.toHaveAccessibleDescription();
        expect(query.parentElement!.style.borderColor).toBe("");
        expect(popover.queryByRole("status")).toBeNull();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("saves the search and quick filter as typed, and loads a query that does not parse as not applied", async () => {
    seed({ filterSearch: "token" });
    render(<EvtxFilterBar nowEpoch={0} />);
    fireEvent.change(screen.getByRole("textbox", { name: "Search events" }), {
      target: { value: "Event ID: 7036" },
    });
    act(() =>
      useEvtxStore.getState().setQuickFilter({
        ...useEvtxStore.getState().quickFilter,
        mode: "fieldQuery",
        query: "level:erro",
      }),
    );
    const popover = within(await openPopover());

    fireEvent.click(popover.getByRole("combobox", { name: "Saved filters" }));
    fireEvent.click(await screen.findByRole("option", { name: "Save current..." }));
    const name = popover.getByRole("textbox", { name: "Name this filter" });
    fireEvent.change(name, { target: { value: "Typed" } });
    fireEvent.keyDown(name, { key: "Enter" });
    const [saved] = useSavedFilterStore.getState().savedFilters;
    expect(saved.criteria.onLoad.search).toBe("Event ID: 7036");
    expect(saved.criteria.onLoad.quickFilter).toMatchObject({ mode: "fieldQuery", query: "level:erro" });

    act(() => {
      useEvtxStore.getState().setFilterSearch("token");
      useEvtxStore.getState().setQuickFilter({ ...saved.criteria.onLoad.quickFilter, query: "id:76" });
    });
    fireEvent.click(popover.getByRole("combobox", { name: "Saved filters" }));
    fireEvent.click(await screen.findByRole("option", { name: "Typed" }));

    // Neither query is applied, and neither is the one from before the load.
    expect(useEvtxStore.getState()).toMatchObject({
      filterSearch: "",
      filterSearchDraft: "Event ID: 7036",
    });
    expect(useEvtxStore.getState().quickFilter.query).toBe("");
    expect(useEvtxStore.getState().quickFilterDraft?.query).toBe("level:erro");
    expect(screen.getByRole("textbox", { name: "Search events" })).toHaveValue("Event ID: 7036");
    await waitFor(() =>
      expect(document.getElementById(EVTX_SEARCH_ERROR_ID)).toHaveTextContent(
        "Not applied: id: needs a value.",
      ),
    );
  });
});

function hexToRgb(hex: string): string {
  const value = hex.replace("#", "");
  const full = value.length === 3 ? [...value].map((c) => c + c).join("") : value;
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
  return `rgb(${r}, ${g}, ${b})`;
}

/**
 * What the rendered toggle paints. The contrast test (evtx-level-toggle.test.ts) measures the
 * state table; this half reads the Griffel rules the button actually carries and checks that each
 * state paints from that table, so a measured color the button never uses cannot pass.
 */
describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "the level toggle paint in the %s theme",
  (id, theme) => {
    const DOT = "evtx-level-dot";
    const COUNT = "evtx-level-count";

    /** Declarations of `property` that apply to `element` under `pseudo`, optionally on a descendant. */
    function declared(
      element: HTMLElement,
      pseudo: "" | ":hover" | ":active",
      descendant: "" | typeof DOT | typeof COUNT,
      property: string,
    ): string[] {
      const classes = Array.from(element.classList).filter((name) => name !== DOT && name !== COUNT);
      const selectors = classes.map(
        (name) => `.${name}${pseudo}${descendant ? ` .${descendant}` : ""}`,
      );
      const values: string[] = [];
      for (const sheet of Array.from(document.styleSheets)) {
        for (const rule of Array.from(sheet.cssRules)) {
          if (!(rule instanceof CSSStyleRule)) continue;
          if (selectors.includes(rule.selectorText)) {
            const value = rule.style.getPropertyValue(property);
            if (value) values.push(value);
          }
        }
      }
      return values;
    }

    function dotOf(button: HTMLElement) {
      return button.querySelector<HTMLElement>(`.${DOT}`)!;
    }
    function countOf(button: HTMLElement) {
      return button.querySelector<HTMLElement>(`.${COUNT}`)!;
    }

    beforeEach(() => {
      useUiStore.setState({ themeId: theme.id });
      seed({ filterLevels: new Set<EvtxLevel>(["Error"]) });
    });

    it("hands the group the measured colors for every state", () => {
      const states = levelToggleStates(theme, buildEvtxVisualTokens(theme));
      render(<EvtxFilterBar nowEpoch={0} />);
      const group = screen.getByRole("group", { name: "Level" });
      for (const state of LEVEL_TOGGLE_STATES) {
        expect(group.style.getPropertyValue(`--evtx-level-label-${state}`), `${id} ${state} label`).toBe(
          states[state].label,
        );
        expect(group.style.getPropertyValue(`--evtx-level-count-${state}`), `${id} ${state} count`).toBe(
          states[state].count,
        );
        expect(group.style.getPropertyValue(`--evtx-level-ring-${state}`), `${id} ${state} ring`).toBe(
          states[state].dotRing ?? "transparent",
        );
      }
    });

    it("paints the unpressed toggle from the rest, hover and mouse-down rows of the table", () => {
      render(<EvtxFilterBar nowEpoch={0} />);
      const button = toggle("Warning"); // Warning is deselected in this seed.
      const cases: Array<[LevelToggleState, "" | ":hover" | ":active"]> = [
        ["rest", ""],
        ["hover", ":hover"],
        ["active", ":active"],
      ];
      for (const [state, pseudo] of cases) {
        const label = `${id} ${state}`;
        expect(declared(button, pseudo, "", "background-color"), `${label} surface`).toEqual([
          LEVEL_TOGGLE_BACKGROUNDS[state],
        ]);
        expect(declared(button, pseudo, "", "color"), `${label} label`).toEqual([
          `var(--evtx-level-label-${state})`,
        ]);
        expect(declared(button, pseudo, COUNT, "color"), `${label} count`).toEqual([
          `var(--evtx-level-count-${state})`,
        ]);
        expect(declared(button, pseudo, DOT, "outline-color"), `${label} ring`).toEqual([
          state === "rest" ? "transparent" : `var(--evtx-level-ring-${state})`,
        ]);
      }
    });

    it("paints a pressed toggle from the pressed row whether it rests, is hovered or is held", () => {
      render(<EvtxFilterBar nowEpoch={0} />);
      const button = toggle("Error"); // Error is the one selected level in this seed.
      expect(button).toHaveAttribute("aria-pressed", "true");
      for (const pseudo of ["", ":hover", ":active"] as const) {
        const label = `${id} pressed${pseudo}`;
        expect(declared(button, pseudo, "", "background-color"), `${label} surface`).toEqual([
          LEVEL_TOGGLE_BACKGROUNDS.pressed,
        ]);
        expect(declared(button, pseudo, "", "color"), `${label} label`).toEqual([
          "var(--evtx-level-label-pressed)",
        ]);
        expect(declared(button, pseudo, COUNT, "color"), `${label} count`).toEqual([
          "var(--evtx-level-count-pressed)",
        ]);
        expect(declared(button, pseudo, DOT, "outline-color"), `${label} ring`).toEqual([
          "var(--evtx-level-ring-pressed)",
        ]);
      }
    });

    it("draws a 1 px ring box around the dot and fills it with the level's dot color", () => {
      render(<EvtxFilterBar nowEpoch={0} />);
      const visual = buildEvtxVisualTokens(theme);
      for (const level of EVTX_LEVELS) {
        const dot = dotOf(toggle(level));
        expect(dot.style.backgroundColor, `${id} ${level}`).not.toBe("");
        expect(declared(dot, "", "", "outline-width").concat(declared(dot, "", "", "outline-style"))).toEqual([
          "1px",
          "solid",
        ]);
        // The fill is the token map's dot color, never a literal in the component.
        const probe = document.createElement("span");
        probe.style.backgroundColor = visual.levels[level].dotColor;
        expect(dot.style.backgroundColor).toBe(probe.style.backgroundColor);
      }
      expect(countOf(toggle("Error")).classList.contains(COUNT)).toBe(true);
    });
  },
);

/**
 * Windows contrast themes force every color to a system color, which would leave a pressed toggle
 * with nothing but a heavier weight. The pressed toggle must paint a Highlight block in that mode,
 * and the dots must keep a ring. jsdom cannot apply forced colors, so this reads the rules.
 */
describe("the level toggle in forced-colors mode", () => {
  const DOT = "evtx-level-dot";
  const COUNT = "evtx-level-count";

  function forced(
    element: HTMLElement,
    pseudo: "" | ":hover" | ":active",
    descendant: "" | typeof DOT | typeof COUNT,
    property: string,
  ): string[] {
    const classes = Array.from(element.classList).filter((name) => name !== DOT && name !== COUNT);
    const selectors = classes.map((name) => `.${name}${pseudo}${descendant ? ` .${descendant}` : ""}`);
    const values: string[] = [];
    for (const sheet of Array.from(document.styleSheets)) {
      for (const rule of Array.from(sheet.cssRules)) {
        if (!(rule instanceof CSSMediaRule)) continue;
        if (!rule.media.mediaText.includes("forced-colors: active")) continue;
        for (const inner of Array.from(rule.cssRules)) {
          if (inner instanceof CSSStyleRule && selectors.includes(inner.selectorText)) {
            // System color keywords are case-insensitive and jsdom lowercases them.
            const value = inner.style.getPropertyValue(property).toLowerCase();
            if (value) values.push(value);
          }
        }
      }
    }
    return values;
  }

  beforeEach(() => seed({ filterLevels: new Set<EvtxLevel>(["Error"]) }));

  it("paints a pressed toggle as a Highlight block at rest, hovered and held", () => {
    render(<EvtxFilterBar nowEpoch={0} />);
    const pressed = toggle("Error");
    expect(pressed).toHaveAttribute("aria-pressed", "true");
    for (const pseudo of ["", ":hover", ":active"] as const) {
      expect(forced(pressed, pseudo, "", "background-color"), `pressed${pseudo} surface`).toEqual(["highlight"]);
      expect(forced(pressed, pseudo, "", "color"), `pressed${pseudo} label`).toEqual(["highlighttext"]);
      expect(forced(pressed, pseudo, COUNT, "color"), `pressed${pseudo} count`).toEqual(["highlighttext"]);
      expect(forced(pressed, pseudo, DOT, "outline-color"), `pressed${pseudo} ring`).toEqual(["highlighttext"]);
    }
  });

  it("leaves an unpressed toggle on system colors and rings its dot in CanvasText", () => {
    render(<EvtxFilterBar nowEpoch={0} />);
    const unpressed = toggle("Warning");
    expect(unpressed).toHaveAttribute("aria-pressed", "false");
    for (const pseudo of ["", ":hover", ":active"] as const) {
      expect(forced(unpressed, pseudo, "", "background-color"), `unpressed${pseudo}`).toEqual([]);
      expect(forced(unpressed, pseudo, DOT, "outline-color"), `unpressed${pseudo} ring`).toEqual(["canvastext"]);
    }
  });

  it("keeps every dot's level color, so only the ring and label change", () => {
    render(<EvtxFilterBar nowEpoch={0} />);
    const dot = toggle("Error").querySelector<HTMLElement>(`.${DOT}`)!;
    expect(forced(dot, "", "", "forced-color-adjust")).toEqual(["none"]);
  });
});

/**
 * Styles the filter row takes from Fluent or overrides, read from the rules each element carries
 * (jsdom has no layout, so this is how a regression in them is caught).
 */
describe("the filter row's Fluent-default styles", () => {
  interface CssHit {
    selector: string;
    css: string;
    forcedColors: boolean;
    /** Where the rule sits in the document's stylesheets: a later rule of equal weight wins. */
    order: number;
  }
  /** Every rule, including those inside @media blocks, whose selector targets one of the element's classes. */
  function rulesFor(element: Element): CssHit[] {
    const classes = Array.from(element.classList);
    const hits: CssHit[] = [];
    let order = 0;
    const visit = (rules: CSSRuleList, forcedColors: boolean) => {
      for (const rule of Array.from(rules)) {
        order += 1;
        if (rule instanceof CSSStyleRule) {
          if (classes.some((name) => rule.selectorText.includes(`.${name}`))) {
            hits.push({ selector: rule.selectorText, css: rule.cssText, forcedColors, order });
          }
        } else if (rule instanceof CSSMediaRule) {
          visit(rule.cssRules, forcedColors || rule.media.mediaText.includes("forced-colors: active"));
        }
      }
    };
    for (const sheet of Array.from(document.styleSheets)) visit(sheet.cssRules, false);
    return hits;
  }
  const RING = /\[data-fui-focus-visible\]::after/;

  beforeEach(() => seed({ filterLevels: new Set<EvtxLevel>(["Error"]), filterSearch: "logon" }));

  it("gives More filters Fluent's default secondary appearance at 28 px", () => {
    render(
      <>
        <EvtxFilterBar nowEpoch={0} />
        <Button size="small" data-reference>
          reference
        </Button>
      </>,
    );
    const trigger = screen.getByRole("button", { name: /^More filters/ });
    const reference = document.querySelector<HTMLElement>("[data-reference]")!;
    // The same Griffel classes as a plain small Button: no outline, subtle or primary appearance.
    expect(trigger.className).toBe(reference.className);
    expect(trigger.style.minHeight).toBe("28px");
  });

  it("draws the search box with a 1 px colorNeutralStroke1 border all round, bottom edge included", () => {
    render(<EvtxFilterBar nowEpoch={0} />);
    const root = screen.getByRole("textbox", { name: "Search events" }).parentElement!;
    const hits = rulesFor(root);
    const bottom = (pseudo: string, token: string) =>
      hits.filter(
        (hit) =>
          hit.selector.endsWith(pseudo) &&
          /border-bottom-color/.test(hit.css) &&
          hit.css.includes(`var(--${token})`),
      );
    // Fluent's own rule for the same edge, which is the accessible stroke the spec does not want.
    const fluentBottom = hits.filter(
      (hit) => /border-bottom-color/.test(hit.css) && hit.css.includes("colorNeutralStrokeAccessible)"),
    );
    expect(fluentBottom.length).toBeGreaterThan(0);

    for (const [pseudo, token, fluent] of [
      ["", "colorNeutralStroke1", "colorNeutralStrokeAccessible)"],
      [":hover", "colorNeutralStroke1Hover", "colorNeutralStrokeAccessibleHover)"],
      [":focus-within", "colorNeutralStroke1Pressed", "colorNeutralStrokeAccessiblePressed)"],
    ] as const) {
      const override = bottom(pseudo, token);
      expect(override.length, `${pseudo || "rest"} bottom edge ${token}`).toBe(1);
      const theirs = hits.filter(
        (hit) =>
          /border-bottom-color/.test(hit.css) &&
          hit.css.includes(fluent) &&
          (pseudo === "" ? !/:hover|:focus-within|:active/.test(hit.selector) : hit.selector.includes(pseudo)),
      );
      if (pseudo === "") {
        // Fluent draws the rest edge from a reset style, which cannot be replaced by class: ours
        // is the later rule of equal weight, so it wins.
        for (const rule of theirs) expect(override[0].order).toBeGreaterThan(rule.order);
      } else {
        // The hover and focus keys are Fluent's own atomic classes, so ours replaced them outright.
        expect(theirs, `${pseudo} left Fluent's accessible stroke on the element`).toEqual([]);
      }
    }
  });

  it("draws the toggle's focus ring with Fluent's focus indicator, not a custom outline", () => {
    render(<EvtxFilterBar nowEpoch={0} />);
    for (const level of ["Error", "Warning"] as const) {
      const hits = rulesFor(toggle(level)).filter((hit) => !hit.forcedColors);
      const ring = hits.filter((hit) => RING.test(hit.selector));
      expect(ring.map((hit) => hit.css).join(" "), `${level} ring`).toMatch(/colorStrokeFocus2/);
      // No hand-written :focus-visible outline in the toggle's own classes.
      expect(
        hits.filter((hit) => /:focus-visible/.test(hit.selector) && /outline-color/.test(hit.css) && /colorStrokeFocus2/.test(hit.css)),
        `${level} custom outline`,
      ).toEqual([]);
    }
  });

  it("keeps the ring visible in forced colors on a pressed toggle that is not color-adjusted", () => {
    render(<EvtxFilterBar nowEpoch={0} />);
    const pressed = toggle("Error");
    expect(pressed).toHaveAttribute("aria-pressed", "true");
    const forced = rulesFor(pressed).filter((hit) => hit.forcedColors);
    // The block opts out of forced colors, which would also exempt a ring left on its theme color.
    expect(forced.some((hit) => /forced-color-adjust:\s*none/.test(hit.css))).toBe(true);
    // So the ring is drawn in a system color that contrasts with the page behind the block.
    const ring = forced.filter((hit) => RING.test(hit.selector));
    expect(ring.map((hit) => hit.css).join(" ")).toMatch(/canvastext/i);
    expect(ring.map((hit) => hit.css).join(" ")).not.toMatch(/\bHighlight\b(?!Text)/i);
  });
});
