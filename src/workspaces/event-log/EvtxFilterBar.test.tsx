import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getAllThemes } from "../../lib/themes";
import { deferred } from "../../test-utils/deferred";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { EvtxFilterBar, eventLogTimeWindowSnapshotLabel } from "./EvtxFilterBar";
import { moreFiltersActiveCount } from "./EvtxMoreFilters";
import { EVTX_LEVELS } from "./evtx-filter";
import { useSavedFilterStore } from "./evtx-filter-store";
import {
  LEVEL_TOGGLE_BACKGROUNDS,
  LEVEL_TOGGLE_STATES,
  levelToggleStates,
  type LevelToggleState,
} from "./evtx-level-toggle";
import { useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";
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

    expect(screen.getByRole("textbox", { name: "Search events" })).toHaveAttribute(
      "placeholder",
      "Search…",
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

describe("level toggles", () => {
  it("shows the loaded totals per level, set against what is on screen", () => {
    seed({ filterLevels: new Set<EvtxLevel>(["Error"]) });
    render(<EvtxFilterBar nowEpoch={0} />);

    expect(EVTX_LEVELS.map((level) => visibleCount(toggle(level)))).toEqual(["1", "12", "0", "3", "0"]);
    expect(toggle("Error")).toHaveAccessibleDescription("12 events loaded");
    expect(toggle("Error")).toHaveAttribute("aria-pressed", "true");
    expect(toggle("Critical")).toHaveAttribute("aria-pressed", "false");
    // A deselected level still reports what is loaded, so the operator can see what turning it on adds.
    expect(toggle("Critical")).toHaveAccessibleDescription("1 events loaded");
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

    expect(visibleCount(toggle("Information"))).toBe("?");
    expect(toggle("Information")).toHaveAccessibleDescription(
      /Count unavailable: the live query leaves out Information events/,
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
  });

  describe("live mode (issue #832: do the toggles re-query?)", () => {
    const queryCalls = () => invoke.mock.calls.filter(([name]) => name === "evtx_query_channels");

    it("re-queries every loaded channel on a toggle, empties the records, and shows the loading state", async () => {
      const reply = deferred<unknown>();
      invoke.mockImplementation(async (name: string) =>
        name === "evtx_query_channels" ? reply.promise : undefined,
      );
      seed({ sourceMode: "live" });
      render(<EvtxFilterBar nowEpoch={0} />);

      // Said before the click: each toggle names the reload, in its tooltip and its description.
      expect(toggle("Verbose")).toHaveAccessibleDescription(/Changing a level reloads the loaded channels/);
      expect(toggle("Verbose").title).toMatch(/reloads the loaded channels/);
      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "false");

      fireEvent.click(toggle("Verbose"));
      await waitFor(() => expect(queryCalls()).toHaveLength(1));

      const [, args] = queryCalls()[0] as [string, { channels: string[]; filter: Record<string, unknown> }];
      expect(args.channels).toEqual(["Application"]);
      // Information is still selected, so the level stays a local filter and is not sent: the
      // reload happens anyway.
      expect(args.filter).not.toHaveProperty("levels");
      expect(useEvtxStore.getState().isLoading).toBe(true);
      expect(useEvtxStore.getState().records).toEqual([]);

      // The row does not pretend the toggle was instant.
      expect(screen.getByRole("group", { name: "Level" })).toHaveAttribute("aria-busy", "true");
      expect(screen.getByRole("progressbar", { name: "Reloading events" })).toBeInTheDocument();
      // And an emptied record list is unknown, never zero.
      expect(EVTX_LEVELS.map((level) => visibleCount(toggle(level)))).toEqual(["?", "?", "?", "?", "?"]);
      expect(toggle("Error")).toHaveAccessibleDescription(/Count unavailable while events load/);
    });

    it("sends the level predicate once Information is deselected", async () => {
      invoke.mockImplementation(
        async (name: string) => (name === "evtx_query_channels" ? new Promise(() => undefined) : undefined),
      );
      seed({ sourceMode: "live" });
      render(<EvtxFilterBar nowEpoch={0} />);

      fireEvent.click(toggle("Information"));
      await waitFor(() => expect(queryCalls()).toHaveLength(1));
      const [, args] = queryCalls()[0] as [string, { filter: { levels?: number[] } }];
      expect(args.filter.levels).toEqual([1, 2, 3, 5]);
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

  it("is disabled while events load", () => {
    seed({ sourceMode: "live", timeWindow: "24h", isLoading: true });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByRole("combobox", { name: "Time window" })).toBeDisabled();
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

  it("counts the event IDs and the quick filter, and nothing else", () => {
    const quick = { ...useEvtxStore.getState().quickFilter };
    expect(moreFiltersActiveCount("", quick)).toBe(0);
    expect(moreFiltersActiveCount("  ", { ...quick, query: "  " })).toBe(0);
    expect(moreFiltersActiveCount("4624", quick)).toBe(1);
    expect(moreFiltersActiveCount("", { ...quick, query: "bitlocker" })).toBe(1);
    expect(moreFiltersActiveCount("4624", { ...quick, query: "bitlocker" })).toBe(2);
    // Options of the quick filter are not criteria.
    expect(
      moreFiltersActiveCount("", { ...quick, caseSensitive: true, highlight: false, action: "hide" }),
    ).toBe(0);
  });

  it("shows the active count on the button", () => {
    seed({
      filterEventIds: "4624",
      quickFilter: { ...useEvtxStore.getState().quickFilter, query: "bitlocker" },
      filterSearch: "ignored here",
    });
    render(<EvtxFilterBar nowEpoch={0} />);
    expect(screen.getByRole("button", { name: "More filters · 2" })).toBeInTheDocument();
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

    fireEvent.change(popover.getByRole("textbox", { name: "Event IDs" }), { target: { value: "4624-4626" } });
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
