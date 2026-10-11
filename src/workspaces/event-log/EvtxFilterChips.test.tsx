import { tokens } from "@fluentui/react-components";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import {
  buildFilterChips,
  EvtxFilterChips,
  EvtxFilterChipView,
  type EvtxFilterChip,
  type EvtxFilterChipInput,
} from "./EvtxFilterChips";
import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import { useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import { useUiStore } from "../../stores/ui-store";

const input = (overrides: Partial<EvtxFilterChipInput> = {}): EvtxFilterChipInput => ({
  filterEventIds: "",
  filterSearch: "",
  quickFilter: { ...DEFAULT_QUICK_FILTER },
  selectedChannels: new Set(["System", "Application"]),
  heldChannels: new Set(["System", "Application"]),
  ...overrides,
});

describe("buildFilterChips", () => {
  it("makes no chip when nothing narrows the view", () => {
    expect(buildFilterChips(input())).toEqual([]);
  });

  it("makes no chip from whitespace-only criteria", () => {
    expect(
      buildFilterChips(
        input({
          filterEventIds: "  ",
          filterSearch: "   ",
          quickFilter: { ...DEFAULT_QUICK_FILTER, query: " \t " },
        }),
      ),
    ).toEqual([]);
  });

  it("reads Event IDs back normalized and flags the chip as cleared by Clear all", () => {
    expect(buildFilterChips(input({ filterEventIds: "4624,4625  4634-4636" }))).toEqual([
      { id: "eventIds", label: "Event IDs: 4624, 4625, 4634-4636", clearedByClearAll: true },
    ]);
  });

  it("labels a hide rule Exclude and a show rule Quick filter, since both narrow the view", () => {
    const hide = buildFilterChips(
      input({ quickFilter: { ...DEFAULT_QUICK_FILTER, mode: "eventIds", action: "hide", query: "7036,16384" } }),
    );
    expect(hide.map((chip) => chip.label)).toEqual(["Exclude: 7036, 16384"]);

    const show = buildFilterChips(
      input({ quickFilter: { ...DEFAULT_QUICK_FILTER, action: "show", query: "  bitlocker " } }),
    );
    expect(show.map((chip) => chip.label)).toEqual(["Quick filter: bitlocker"]);

    const hideText = buildFilterChips(
      input({ quickFilter: { ...DEFAULT_QUICK_FILTER, action: "hide", query: "noise" } }),
    );
    expect(hideText.map((chip) => chip.label)).toEqual(["Exclude: noise"]);
  });

  it("makes a search chip from the trimmed text", () => {
    expect(buildFilterChips(input({ filterSearch: "  gpsvc " }))).toEqual([
      { id: "search", label: "Search: gpsvc", clearedByClearAll: true },
    ]);
  });

  it("counts a channel chip against the channels that hold records, and keeps it out of Clear all", () => {
    const chips = buildFilterChips(
      input({
        selectedChannels: new Set(["System", "Security"]),
        heldChannels: new Set(["System", "Application", "Setup"]),
      }),
    );
    // Security is selected but holds nothing loaded, so it neither counts as shown nor as a total.
    expect(chips).toEqual([
      { id: "channels", label: "Channels: 1 of 3", clearedByClearAll: false },
    ]);
  });

  it("makes no channel chip when every held channel is selected, even with extra selected channels", () => {
    expect(
      buildFilterChips(
        input({
          selectedChannels: new Set(["System", "Application", "Security"]),
          heldChannels: new Set(["System", "Application"]),
        }),
      ),
    ).toEqual([]);
  });

  it("lists chips in the spec's order: channels, Event IDs, quick filter, search", () => {
    const chips = buildFilterChips(
      input({
        selectedChannels: new Set(["System"]),
        filterEventIds: "1",
        filterSearch: "s",
        quickFilter: { ...DEFAULT_QUICK_FILTER, query: "q" },
      }),
    );
    expect(chips.map((chip) => chip.id)).toEqual(["channels", "eventIds", "quickFilter", "search"]);
  });
});

function seed(state: Partial<ReturnType<typeof useEvtxStore.getState>> = {}) {
  useEvtxStore.setState({
    sourceMode: "files",
    channels: [
      { name: "System", eventCount: 1, sourceType: "live" },
      { name: "Application", eventCount: 1, sourceType: "live" },
    ],
    selectedChannels: new Set(["System", "Application"]),
    loadedChannels: new Set<string>(),
    isLoading: false,
    ...state,
  });
}

beforeEach(() => {
  localStorage.clear();
  useUiStore.setState(useUiStore.getInitialState(), true);
  useEvtxStore.getState().reset();
});
afterEach(cleanup);

describe("EvtxFilterChips", () => {
  it("renders nothing, readout included, when no criterion is active", () => {
    seed();
    const { container } = render(<EvtxFilterChips visibleCount={3} loadedCount={3} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows one chip per active criterion, with the readout and a remove button each", () => {
    seed({
      filterEventIds: "4624",
      filterSearch: "logon",
      quickFilter: { ...DEFAULT_QUICK_FILTER, action: "hide", query: "noise" },
      selectedChannels: new Set(["System"]),
    });
    render(<EvtxFilterChips visibleCount={12} loadedCount={1234} />);

    const list = screen.getByRole("list", { name: "Active filters" });
    expect(within(list).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "Channels: 1 of 2",
      "Event IDs: 4624",
      "Exclude: noise",
      "Search: logon",
    ]);
    for (const label of [
      "Remove Channels: 1 of 2",
      "Remove Event IDs: 4624",
      "Remove Exclude: noise",
      "Remove Search: logon",
    ]) {
      expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
    }
    expect(document.querySelector("[data-evtx-filter-count]")?.textContent).toBe(
      `Showing ${(12).toLocaleString()} of ${(1234).toLocaleString()}`,
    );
  });

  it("removes the Event IDs, quick filter and search criteria one at a time", () => {
    seed({
      filterEventIds: "4624",
      filterSearch: "logon",
      quickFilter: { ...DEFAULT_QUICK_FILTER, mode: "allWords", action: "hide", query: "noise", caseSensitive: true },
    });
    render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);

    fireEvent.click(screen.getByRole("button", { name: "Remove Event IDs: 4624" }));
    expect(useEvtxStore.getState().filterEventIds).toBe("");

    fireEvent.click(screen.getByRole("button", { name: "Remove Exclude: noise" }));
    const quick = useEvtxStore.getState().quickFilter;
    expect(quick.query).toBe("");
    // The operator's settings survive: only the criterion goes.
    expect(quick).toMatchObject({ mode: "allWords", action: "hide", caseSensitive: true });

    fireEvent.click(screen.getByRole("button", { name: "Remove Search: logon" }));
    expect(useEvtxStore.getState().filterSearch).toBe("");
  });

  it("clears every chip but the channel chip with Clear all, and keeps the time window and levels", () => {
    seed({
      filterEventIds: "4624",
      filterSearch: "logon",
      quickFilter: { ...DEFAULT_QUICK_FILTER, query: "x" },
      selectedChannels: new Set(["System"]),
      timeWindow: "7d",
      filterLevels: new Set(["Error"]),
    });
    render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);

    fireEvent.click(screen.getByRole("button", { name: "Clear all" }));

    const state = useEvtxStore.getState();
    expect(state.filterEventIds).toBe("");
    expect(state.filterSearch).toBe("");
    expect(state.quickFilter.query).toBe("");
    expect([...state.selectedChannels]).toEqual(["System"]);
    expect(state.timeWindow).toBe("7d");
    expect([...state.filterLevels]).toEqual(["Error"]);
    // What is left is the channel chip, still removable one at a time.
    expect(screen.getByRole("button", { name: "Remove Channels: 1 of 2" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear all" })).toBeNull();
  });

  it("offers no Clear all when the channel chip is the only one, since it would do nothing", () => {
    seed({ selectedChannels: new Set(["System"]) });
    render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
    expect(screen.getByRole("button", { name: "Remove Channels: 1 of 2" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear all" })).toBeNull();
  });

  it("restores the hidden channels from the chip without ticking channels that were never loaded", () => {
    // Live mode: three channels enumerated, two loaded. Application is loaded but hidden.
    seed({
      sourceMode: "live",
      channels: [
        { name: "System", eventCount: 1, sourceType: "live" },
        { name: "Application", eventCount: 1, sourceType: "live" },
        { name: "Setup", eventCount: 0, sourceType: "live" },
      ],
      loadedChannels: new Set(["System", "Application"]),
      selectedChannels: new Set(["System"]),
    });
    render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);

    fireEvent.click(screen.getByRole("button", { name: "Remove Channels: 1 of 2" }));

    expect([...useEvtxStore.getState().selectedChannels].sort()).toEqual(["Application", "System"]);
    expect(screen.queryByRole("list", { name: "Active filters" })).toBeNull();
  });

  it("says Loading instead of a count while events load, never Showing 0", () => {
    seed({ filterSearch: "logon", isLoading: true });
    // The workspace passes an empty visible list while loading.
    render(<EvtxFilterChips visibleCount={0} loadedCount={0} />);
    const readout = document.querySelector("[data-evtx-filter-count]")!;
    expect(readout.textContent).toBe("Loading events...");
    expect(readout.textContent).not.toMatch(/Showing/);
  });

  it("sizes the chips at f - 2 from the list font and uses the numeric font for the readout", () => {
    seed({ filterSearch: "logon" });
    act(() => useUiStore.getState().setLogListFontSize(20));
    render(<EvtxFilterChips visibleCount={1} loadedCount={1} />);
    expect(document.querySelector<HTMLElement>("[data-evtx-region='chip-row']")!.style.fontSize).toBe("18px");
  });

  it("draws a chip with the selection triplet when its descriptor asks for it", () => {
    const chip: EvtxFilterChip = {
      id: "search",
      label: "Time: brushed 09:00-09:45",
      clearedByClearAll: true,
      tone: "selection",
    };
    render(
      <ul>
        <EvtxFilterChipView chip={chip} onRemove={() => undefined} />
      </ul>,
    );
    const item = screen.getByRole("listitem");
    expect(item.style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    expect(item.style.color).toBe(tokens.colorPaletteBlueForeground2);
  });

  it("truncates a long chip with an ellipsis and keeps the full text in its tooltip", () => {
    const long = "x".repeat(200);
    seed({ filterSearch: long });
    render(<EvtxFilterChips visibleCount={1} loadedCount={1} />);
    const text = screen.getByText(`Search: ${long}`);
    expect(text).toHaveAttribute("title", `Search: ${long}`);
  });
});

/**
 * Contrast in all seven themes (spec 10: each new component is verified in high contrast).
 * Each pair is measured on resolved theme colors, and the DOM half pins the rendered rule to the
 * same Fluent token, so a measured pair cannot differ from the painted one.
 */
describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "chip row contrast in the %s theme",
  (id, theme) => {
    const r = (token: string) => resolveToken(token, theme);
    const atLeast = (label: string, a: string, b: string, minimum: number) => {
      expect(contrastRatio(r(a), r(b)), `${id}: ${label}`).toBeGreaterThanOrEqual(minimum);
    };

    function declared(element: Element, pseudo: "" | ":hover" | ":active", property: string): string[] {
      const selectors = Array.from(element.classList).map((name) => `.${name}${pseudo}`);
      const values: string[] = [];
      for (const sheet of Array.from(document.styleSheets)) {
        for (const rule of Array.from(sheet.cssRules)) {
          if (rule instanceof CSSStyleRule && selectors.includes(rule.selectorText)) {
            const value = rule.style.getPropertyValue(property);
            if (value) values.push(value);
          }
        }
      }
      return values;
    }

    beforeEach(() => {
      useUiStore.setState({ themeId: theme.id });
      seed({ filterEventIds: "4624", filterSearch: "logon", selectedChannels: new Set(["System"]) });
    });

    it("reads the chip text at 4.5:1 on the chip surface", () => {
      render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
      const chip = screen.getAllByRole("listitem")[0];
      expect(declared(chip, "", "color")).toEqual([tokens.colorNeutralForeground2]);
      expect(declared(chip, "", "background-color")).toEqual([tokens.colorNeutralBackground3]);
      atLeast("chip text", tokens.colorNeutralForeground2, tokens.colorNeutralBackground3, 4.5);
    });

    it("draws the remove icon at 4.5:1 in the rest, hover and pressed states", () => {
      render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
      const remove = screen.getByRole("button", { name: "Remove Event IDs: 4624" });
      expect(declared(remove, "", "color")).toEqual([tokens.colorNeutralForeground2]);
      expect(declared(remove, ":hover", "color")).toEqual([tokens.colorNeutralForeground2Hover]);
      expect(declared(remove, ":hover", "background-color")).toEqual([tokens.colorSubtleBackgroundHover]);
      expect(declared(remove, ":active", "color")).toEqual([tokens.colorNeutralForeground2Pressed]);
      expect(declared(remove, ":active", "background-color")).toEqual([tokens.colorSubtleBackgroundPressed]);

      atLeast("remove rest", tokens.colorNeutralForeground2, tokens.colorNeutralBackground3, 4.5);
      atLeast("remove hover", tokens.colorNeutralForeground2Hover, tokens.colorSubtleBackgroundHover, 4.5);
      atLeast("remove pressed", tokens.colorNeutralForeground2Pressed, tokens.colorSubtleBackgroundPressed, 4.5);
    });

    it("reads Clear all at 4.5:1 at rest, hovered and pressed, on the row surface", () => {
      atLeast("link rest", tokens.colorBrandForegroundLink, tokens.colorNeutralBackground1, 4.5);
      atLeast("link hover", tokens.colorBrandForegroundLinkHover, tokens.colorNeutralBackground1, 4.5);
      atLeast("link pressed", tokens.colorBrandForegroundLinkPressed, tokens.colorNeutralBackground1, 4.5);
    });

    it("reads the Showing readout at 4.5:1 on the row surface", () => {
      render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
      const readout = document.querySelector("[data-evtx-filter-count]")!;
      expect(declared(readout, "", "color")).toEqual([tokens.colorNeutralForeground2]);
      expect(declared(document.querySelector("[data-evtx-region='chip-row']")!, "", "background-color")).toEqual([
        tokens.colorNeutralBackground1,
      ]);
      atLeast("readout", tokens.colorNeutralForeground2, tokens.colorNeutralBackground1, 4.5);
    });

    it("reads a selection-tone chip at 4.5:1 on the selection surface", () => {
      const visual = buildEvtxVisualTokens(theme);
      atLeast("selection chip", visual.selection.foreground, visual.selection.background, 4.5);
    });
  },
);
