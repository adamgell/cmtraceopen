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
  EVTX_SEARCH_INPUT_ID,
  EvtxFilterChips,
  type EvtxFilterChipInput,
} from "./EvtxFilterChips";
import chipsSource from "./EvtxFilterChips.tsx?raw";
import { moreFiltersActiveCount } from "./EvtxMoreFilters";
import {
  DEFAULT_QUICK_FILTER,
  type EvtxRecordScope,
  type EvtxRecordScopeCounts,
  type EvtxRecordScopeKind,
} from "./evtx-filter";
import { useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxRecord } from "./types";
import { useUiStore } from "../../stores/ui-store";
import { LONDON_2026, modelZone } from "./__fixtures__/model-zone";

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

/** The en dash the spec writes between the two times of the brushed-time chip, as an escape. */
const SEP = "\u2013";
const NO_GAPS: EvtxRecordScopeCounts = { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false };

function recordOf(n: number): EvtxRecord {
  return {
    id: n,
    eventRecordId: n,
    timestamp: "",
    timestampEpoch: n,
    provider: "P",
    channel: "System",
    eventId: 1,
    level: "Error",
    computer: "PC",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "s",
  };
}

function scopeOf(
  size: number,
  title = "MDM enrollment failed",
  kind: EvtxRecordScopeKind = "finding",
  counts = NO_GAPS,
): EvtxRecordScope {
  return { kind, title, records: new Set(Array.from({ length: size }, (_, i) => recordOf(i + 1))), counts };
}

const RANGE = { startMs: Date.UTC(2026, 9, 16, 9, 0), endMs: Date.UTC(2026, 9, 16, 9, 45) };

describe("buildFilterChips, the transient criteria", () => {
  it("makes a Time chip, in the selection colors, that Clear all takes", () => {
    const chips = buildFilterChips(input({ timeRange: RANGE, timeZoneMode: "utc" }));
    expect(chips).toEqual([
      {
        id: "timeRange",
        label: `Time: brushed 09:00${SEP}09:45`,
        title: `Time: brushed 09:00${SEP}09:45 (UTC)`,
        selected: true,
        clearedByClearAll: true,
      },
    ]);
  });

  it("writes the Time chip's times in the chosen zone and names the zone in the tooltip", () => {
    const utc = buildFilterChips(input({ timeRange: RANGE, timeZoneMode: "utc" }))[0];
    const local = buildFilterChips(input({ timeRange: RANGE, timeZoneMode: "local" }))[0];
    expect(utc.title).toMatch(/\(UTC\)$/);
    expect(local.title).toMatch(/\(UTC[+-]\d\d:\d\d\)$/);
  });

  it("adds the date when the range crosses a day, and seconds below two minutes", () => {
    const across = buildFilterChips(
      input({
        timeRange: { startMs: Date.UTC(2026, 9, 16, 22), endMs: Date.UTC(2026, 9, 17, 3) },
        timeZoneMode: "utc",
      }),
    )[0];
    expect(across.label).toBe(`Time: brushed Oct 16 22:00${SEP}Oct 17 03:00`);
    const short = buildFilterChips(
      input({
        timeRange: { startMs: Date.UTC(2026, 9, 16, 9, 0, 10), endMs: Date.UTC(2026, 9, 16, 9, 1, 5) },
        timeZoneMode: "utc",
      }),
    )[0];
    expect(short.label).toBe(`Time: brushed 09:00:10${SEP}09:01:05`);
  });

  describe("the year", () => {
    const NOW = Date.UTC(2026, 9, 16, 12, 0);
    const timeChip = (startMs: number, endMs: number, nowMs = NOW) =>
      buildFilterChips(input({ timeRange: { startMs, endMs }, timeZoneMode: "utc", nowMs }))[0];

    it("leaves the year out of a range inside the current year", () => {
      const chip = timeChip(Date.UTC(2026, 0, 15, 11), Date.UTC(2026, 0, 15, 13));
      expect(chip.label).toBe(`Time: brushed 11:00${SEP}13:00`);
      expect(timeChip(Date.UTC(2026, 2, 3), Date.UTC(2026, 3, 2)).label).toBe(
        `Time: brushed Mar 3 00:00${SEP}Apr 2 00:00`,
      );
    });

    it("names the year of a range in a past year, in the label, the tooltip and the remove name", () => {
      const chip = timeChip(Date.UTC(2024, 2, 3), Date.UTC(2024, 3, 2));
      expect(chip.label).toBe(`Time: brushed Mar 3 2024 00:00${SEP}Apr 2 2024 00:00`);
      expect(chip.title).toBe(`${chip.label} (UTC)`);
    });

    it("names the year of a range across New Year", () => {
      const chip = timeChip(Date.UTC(2025, 11, 31, 22), Date.UTC(2026, 0, 1, 3));
      expect(chip.label).toBe(`Time: brushed Dec 31 2025 22:00${SEP}Jan 1 2026 03:00`);
    });

    it("names the year of a range of 365 days, which would otherwise read with its start equal to its end", () => {
      const chip = timeChip(Date.UTC(2026, 1, 14), Date.UTC(2027, 1, 14));
      expect(chip.label).toBe(`Time: brushed Feb 14 2026 00:00${SEP}Feb 14 2027 00:00`);
    });

    it("never writes a range with its ends alike across a DST fall-back, in the host's own zone", () => {
      // Run under TZ=Europe/London or TZ=America/New_York to cover a repeated hour; under UTC this
      // checks only that nothing reads alike. Each hour of 2025, as the current year and as a past one.
      const from = Date.UTC(2025, 0, 1);
      let checked = 0;
      for (const nowMs of [Date.UTC(2025, 5, 1), Date.UTC(2026, 9, 16)]) {
        for (let at = from; at < from + 365 * 24 * 3600_000; at += 3600_000) {
          for (const span of [20 * 60_000, 3600_000]) {
            const chip = buildFilterChips(
              input({ timeRange: { startMs: at, endMs: at + span }, timeZoneMode: "local", nowMs }),
            )[0];
            const [start, end] = chip.label.replace("Time: brushed ", "").split(SEP);
            if (start === end) throw new Error(`${new Date(at).toISOString()} + ${span}: ${chip.label}`);
            checked += 1;
          }
        }
      }
      expect(checked).toBe(2 * 365 * 24 * 2);
    });

    it("names the dates of a range from one midnight to the next, which is not 00:00 to 00:00", () => {
      // The last instant inside such a range is on its first day, so a clock-only label read alike.
      const chip = timeChip(Date.UTC(2026, 9, 6), Date.UTC(2026, 9, 7));
      expect(chip.label).toBe(`Time: brushed Oct 6 00:00${SEP}Oct 7 00:00`);
      const span = (a: number, b: number) => timeChip(a, b).label.replace("Time: brushed ", "").split(SEP);
      // The 23 hour and the 25 hour days of a modelled London year, midnight to midnight in the zone.
      const restore = modelZone(LONDON_2026);
      try {
        const local = (a: number, b: number) =>
          buildFilterChips(input({ timeRange: { startMs: a, endMs: b }, timeZoneMode: "local", nowMs: PINNED_NOW }))[0]
            .label.replace("Time: brushed ", "")
            .split(SEP);
        expect(local(Date.UTC(2026, 2, 29, 0), Date.UTC(2026, 2, 29, 23))).toEqual(["Mar 29 00:00", "Mar 30 00:00"]);
        expect(local(Date.UTC(2026, 9, 24, 23), Date.UTC(2026, 9, 26, 0))).toEqual(["Oct 25 00:00", "Oct 26 00:00"]);
      } finally {
        restore();
      }
      expect(span(Date.UTC(2026, 0, 1), Date.UTC(2026, 0, 2))[0]).not.toBe(span(Date.UTC(2026, 0, 1), Date.UTC(2026, 0, 2))[1]);
    });

    it("never writes a midnight-to-midnight day with its ends alike, for every day of the current year in the host's zone", () => {
      // Run under TZ=Europe/London or America/New_York to include the 23 and 25 hour days.
      let checked = 0;
      for (let day = 0; day < 365; day += 1) {
        const startMs = new Date(2026, 0, 1 + day).getTime();
        const endMs = new Date(2026, 0, 2 + day).getTime();
        for (const mode of ["local", "utc"] as const) {
          const chip = buildFilterChips(
            input({ timeRange: { startMs, endMs }, timeZoneMode: mode, nowMs: PINNED_NOW }),
          )[0];
          const [start, end] = chip.label.replace("Time: brushed ", "").split(SEP);
          if (start === end) throw new Error(`${mode} ${new Date(startMs).toISOString()}: ${chip.label}`);
          checked += 1;
        }
      }
      expect(checked).toBe(730);
    });

    it("compares with the clock it is given, not the real one", () => {
      const march2026 = [Date.UTC(2026, 2, 3), Date.UTC(2026, 3, 2)] as const;
      // The file pins the real clock to 2026, so only the given clock can make 2026 a past year.
      expect(timeChip(...march2026, Date.UTC(2026, 9, 16)).label).toBe(`Time: brushed Mar 3 00:00${SEP}Apr 2 00:00`);
      expect(timeChip(...march2026, Date.UTC(2030, 0, 1)).label).toBe(
        `Time: brushed Mar 3 2026 00:00${SEP}Apr 2 2026 00:00`,
      );
    });

    it("reads the current year from the clock when no time is given", () => {
      const chip = buildFilterChips(
        input({
          timeRange: { startMs: Date.UTC(2024, 2, 3), endMs: Date.UTC(2024, 3, 2) },
          timeZoneMode: "utc",
        }),
      )[0];
      expect(chip.label).toMatch(/ 2024 /);
    });

    it("never writes a range with its start text equal to its end text", () => {
      const starts = [Date.UTC(2026, 9, 16, 9), Date.UTC(2024, 0, 1), Date.UTC(2025, 11, 31, 23, 59, 59, 500)];
      for (const start of starts) {
        for (const span of [500, 1000, 90_000, 3_600_000, 86_400_000, 364 * 86_400_000, 365 * 86_400_000, 800 * 86_400_000]) {
          const label = timeChip(start, start + span).label.replace("Time: brushed ", "");
          const [from, to] = label.split(SEP);
          expect(from, `${start} + ${span}`).not.toBe(to);
        }
      }
    });
  });

  it("says in the tooltip how many events the range hides for want of a timestamp, and leaves the line out at zero", () => {
    const tooltip = (untimedHiddenCount: number) =>
      buildFilterChips(input({ timeRange: RANGE, timeZoneMode: "utc", untimedHiddenCount }))[0].title;
    expect(tooltip(0)).not.toMatch(/timestamp/);
    expect(tooltip(1)).toBe(
      `Time: brushed 09:00${SEP}09:45 (UTC)\n1 event without a timestamp is hidden by this range`,
    );
    expect(tooltip(1234)).toMatch(/\n1,234 events without a timestamp are hidden by this range$/);
  });

  it("makes a Finding chip and a Chain chip from the scope's kind and title", () => {
    const finding = buildFilterChips(input({ recordScope: scopeOf(3) }));
    expect(finding.map((chip) => [chip.id, chip.label, chip.clearedByClearAll])).toEqual([
      ["recordScope", "Finding: MDM enrollment failed", true],
    ]);
    expect(finding[0].selected).toBeUndefined();
    const chain = buildFilterChips(input({ recordScope: scopeOf(2, "Enrollment 7a", "chain") }));
    expect(chain[0].label).toBe("Chain: Enrollment 7a");
  });

  it("states in the Finding chip's tooltip what the scope could not resolve, each class on its own line", () => {
    const whole = buildFilterChips(input({ recordScope: scopeOf(3) }))[0];
    expect(whole.title).toBe("Finding: MDM enrollment failed\n3 events in this scope.");
    const gaps = buildFilterChips(
      input({
        recordScope: scopeOf(1, "T", "finding", {
          notLoaded: 2,
          noUsableIdentity: 1,
          ambiguous: 1,
          bounded: true,
        }),
      }),
    )[0];
    expect(gaps.title?.split("\n")).toEqual([
      "Finding: T",
      "1 event in this scope.",
      "2 cited events are not loaded.",
      "1 cited event cannot be matched to a loaded event: no usable record identity.",
      "1 cited reference matches more than one loaded event. Every match is included.",
      "The diagnosis response is bounded, so this finding may cite more events than were sent.",
    ]);
  });

  it("says in a Chain chip's tooltip that entries whose items were not read could not be matched, and that no absence is claimed", () => {
    const chip = buildFilterChips(
      input({ recordScope: scopeOf(2, "Enrollment 7a", "chain", { ...NO_GAPS, unresolved: 3 }) }),
    )[0];
    expect(chip.label).toBe("Chain: Enrollment 7a");
    expect(chip.title?.split("\n")).toEqual([
      "Chain: Enrollment 7a",
      "2 events in this scope.",
      "3 entries of this chain could not be matched to a record because their timeline items were not read.",
    ]);
    expect(chip.title).not.toMatch(/not loaded/);
  });

  it("words a Chain chip's tooltip for a chain and a Finding chip's for a finding, whatever the counts", () => {
    const gaps = { notLoaded: 1, noUsableIdentity: 0, ambiguous: 0, bounded: true };
    const chain = buildFilterChips(input({ recordScope: scopeOf(2, "Enrollment 7a", "chain", gaps) }))[0];
    expect(chain.title?.split("\n")).toEqual([
      "Chain: Enrollment 7a",
      "2 events in this scope.",
      "1 event of this chain is not loaded.",
      "Edges were not all loaded, so this chain may include more events.",
    ]);
    const finding = buildFilterChips(input({ recordScope: scopeOf(2, "Enrollment 7a", "finding", gaps) }))[0];
    expect(finding.title?.split("\n")).toEqual([
      "Finding: Enrollment 7a",
      "2 events in this scope.",
      "1 cited event is not loaded.",
      "The diagnosis response is bounded, so this finding may cite more events than were sent.",
    ]);
  });

  it("lists them last, in the spec's order: time range, then record scope", () => {
    const chips = buildFilterChips(
      input({
        selectedChannels: new Set(["System"]),
        filterEventIds: "1",
        filterSearch: "s",
        quickFilter: { ...DEFAULT_QUICK_FILTER, query: "q" },
        timeRange: RANGE,
        recordScope: scopeOf(1),
      }),
    );
    expect(chips.map((chip) => chip.id)).toEqual([
      "channels",
      "eventIds",
      "quickFilter",
      "search",
      "timeRange",
      "recordScope",
    ]);
  });

  it("counts both in the More filters number, since neither is on the filter row", () => {
    expect(moreFiltersActiveCount(buildFilterChips(input({ timeRange: RANGE })))).toBe(1);
    expect(moreFiltersActiveCount(buildFilterChips(input({ recordScope: scopeOf(1) })))).toBe(1);
    expect(
      moreFiltersActiveCount(buildFilterChips(input({ timeRange: RANGE, recordScope: scopeOf(1), filterSearch: "x" }))),
    ).toBe(2);
  });

  it("makes no chip for a null range or scope", () => {
    expect(buildFilterChips(input({ timeRange: null, recordScope: null }))).toEqual([]);
  });
});

/**
 * Seeds the store, then the transient criteria in a second step: a source that changes in the same
 * `setState` clears them, which is the store's rule for a change of source.
 */
function seedWithTransient(
  transient: Partial<Pick<ReturnType<typeof useEvtxStore.getState>, "timeRange" | "recordScope">>,
  state: Partial<ReturnType<typeof useEvtxStore.getState>> = {},
) {
  seed(state);
  useEvtxStore.setState(transient);
}

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

/** The CSS of every rule that targets one of the element's classes, for pinning styles in jsdom. */
function rulesText(element: Element): string {
  const classes = Array.from(element.classList);
  const out: string[] = [];
  const visit = (rules: CSSRuleList) => {
    for (const rule of Array.from(rules)) {
      if (rule instanceof CSSStyleRule) {
        if (classes.some((name) => rule.selectorText.includes(`.${name}`))) out.push(rule.cssText);
      } else if (rule instanceof CSSMediaRule) {
        visit(rule.cssRules);
      }
    }
  };
  for (const sheet of Array.from(document.styleSheets)) visit(sheet.cssRules);
  return out.join("\n");
}

/**
 * The Time chip names the year of a range that is not in the current one, so the labels pinned below
 * would change on 1 January. Only Date is faked: timers stay real.
 */
const PINNED_NOW = Date.UTC(2026, 9, 16, 12, 0);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(PINNED_NOW);
  localStorage.clear();
  useUiStore.setState(useUiStore.getInitialState(), true);
  useEvtxStore.getState().reset();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

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

  describe("in live mode during a refetch", () => {
    const liveSeed = () =>
      seed({
        sourceMode: "live",
        channels: [
          { name: "System", eventCount: 1, sourceType: "live" },
          { name: "Application", eventCount: 1, sourceType: "live" },
        ],
        loadedChannels: new Set(["System", "Application"]),
        selectedChannels: new Set(["System"]),
        filterEventIds: "4624",
      });
    /** What a live refetch does to the store: loading, nothing loaded, selection untouched. */
    const startRefetch = () =>
      act(() => useEvtxStore.setState({ isLoading: true, records: [], loadedChannels: new Set<string>() }));
    const finishRefetch = () =>
      act(() =>
        useEvtxStore.setState({ isLoading: false, loadedChannels: new Set(["System", "Application"]) }),
      );
    const labels = () => screen.getAllByRole("listitem").map((item) => item.textContent);

    it("keeps the channel chip while the refetch has emptied the loaded channels", () => {
      liveSeed();
      render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
      expect(labels()).toEqual(["Channels: 1 of 2", "Event IDs: 4624"]);

      startRefetch();
      expect(labels()).toEqual(["Channels: 1 of 2", "Event IDs: 4624"]);

      finishRefetch();
      expect(labels()).toEqual(["Channels: 1 of 2", "Event IDs: 4624"]);
    });

    it("keeps the row, and the focused channel chip's button, when it is the only chip", () => {
      liveSeed();
      useEvtxStore.setState({ filterEventIds: "" });
      render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
      const button = screen.getByRole("button", { name: "Remove Channels: 1 of 2" });
      button.focus();

      startRefetch();
      expect(screen.getByRole("button", { name: "Remove Channels: 1 of 2" })).toBe(button);
      expect(button).toHaveFocus();
    });

    it("follows a real change to the loaded channels once the refetch is over", () => {
      liveSeed();
      render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
      startRefetch();
      act(() =>
        useEvtxStore.setState({
          isLoading: false,
          loadedChannels: new Set(["System", "Application", "Setup"]),
        }),
      );
      expect(labels()[0]).toBe("Channels: 1 of 3");
    });
  });

  it("says Loading instead of a count while events load, never Showing 0", () => {
    seed({ filterSearch: "logon", isLoading: true });
    // The workspace passes an empty visible list while loading.
    render(<EvtxFilterChips visibleCount={0} loadedCount={0} />);
    const readout = document.querySelector("[data-evtx-filter-count]")!;
    expect(readout.textContent).toBe("Loading events...");
    expect(readout.textContent).not.toMatch(/Showing/);
  });

  it("sizes the chips at f - 2 from the list font with an explicit line height", () => {
    seed({ filterSearch: "logon" });
    const { unmount } = render(<EvtxFilterChips visibleCount={1} loadedCount={1} />);
    const row = () => document.querySelector<HTMLElement>("[data-evtx-region='chip-row']")!;
    // The default list size is 13: chips at 11 px on a 16 px line, so a chip is 16 + 2 x 2 padding
    // + 2 x 1 border = 22 px and the row 22 + 6 = 28 px (spec 5.1: about 26). Inherited, the
    // provider's 20 px line made the chip 26 px and the row 32.
    expect(row().style.fontSize).toBe("11px");
    expect(row().style.lineHeight).toBe("16px");
    unmount();

    act(() => useUiStore.getState().setLogListFontSize(20));
    render(<EvtxFilterChips visibleCount={1} loadedCount={1} />);
    expect(row().style.fontSize).toBe("18px");
    expect(row().style.lineHeight).toBe("26px");
  });

  it("draws the readout in the numeric font with tabular figures", () => {
    seed({ filterSearch: "logon" });
    render(<EvtxFilterChips visibleCount={1} loadedCount={1} />);
    const readout = document.querySelector("[data-evtx-filter-count]")!;
    expect(rulesText(readout)).toMatch(/font-family:\s*var\(--fontFamilyNumeric\)/);
    expect(rulesText(readout)).toMatch(/font-variant-numeric:\s*tabular-nums/);
  });

  it("gives the remove button Fluent's focus ring, not a custom outline", () => {
    seed({ filterSearch: "logon" });
    render(<EvtxFilterChips visibleCount={1} loadedCount={1} />);
    const remove = screen.getByRole("button", { name: "Remove Search: logon" });
    const rules = rulesText(remove);
    expect(rules).toMatch(/\[data-fui-focus-visible\]::after/);
    expect(rules).toMatch(/colorStrokeFocus2/);
    expect(rules).not.toMatch(/:focus-visible[^}]*outline-color/);
  });

  describe("focus after a removal", () => {
    /** The chip row beside a stand-in for the filter row's search box. */
    const renderWithSearch = () =>
      render(
        <>
          <input id={EVTX_SEARCH_INPUT_ID} aria-label="Search events" />
          <EvtxFilterChips visibleCount={1} loadedCount={2} />
        </>,
      );
    const remove = (label: string) => screen.getByRole("button", { name: `Remove ${label}` });
    const clickRemove = (label: string) => {
      remove(label).focus();
      expect(remove(label)).toHaveFocus();
      fireEvent.click(remove(label));
    };
    const seedThree = () =>
      seed({ filterEventIds: "4624", filterSearch: "logon", quickFilter: { ...DEFAULT_QUICK_FILTER, query: "x" } });

    it("moves to the next chip's remove button", () => {
      seedThree();
      renderWithSearch();
      clickRemove("Event IDs: 4624");
      expect(remove("Quick filter: x")).toHaveFocus();
    });

    it("moves to the Search chip's remove button, not the search box, when Search is the next chip", () => {
      // The search chip's id must not be read as "focus the search box".
      seed({ filterEventIds: "4624", filterSearch: "logon" });
      renderWithSearch();
      clickRemove("Event IDs: 4624");
      expect(remove("Search: logon")).toHaveFocus();
      expect(screen.getByRole("textbox", { name: "Search events" })).not.toHaveFocus();

      cleanup();
      seedThree();
      renderWithSearch();
      clickRemove("Quick filter: x");
      expect(remove("Search: logon")).toHaveFocus();
    });

    it("moves to the previous chip's remove button when the last chip is removed", () => {
      seedThree();
      renderWithSearch();
      clickRemove("Search: logon");
      expect(remove("Quick filter: x")).toHaveFocus();
    });

    it("moves to the search box when the only chip is removed and the row goes away", () => {
      seed({ filterSearch: "logon" });
      renderWithSearch();
      clickRemove("Search: logon");
      expect(screen.queryByRole("list", { name: "Active filters" })).toBeNull();
      expect(screen.getByRole("textbox", { name: "Search events" })).toHaveFocus();
    });

    it("moves to the search box after Clear all, whether or not a channel chip stays", () => {
      seedThree();
      renderWithSearch();
      const clear = screen.getByRole("button", { name: "Clear all" });
      clear.focus();
      fireEvent.click(clear);
      expect(screen.getByRole("textbox", { name: "Search events" })).toHaveFocus();

      cleanup();
      seed({
        filterSearch: "logon",
        selectedChannels: new Set(["System"]),
      });
      renderWithSearch();
      const again = screen.getByRole("button", { name: "Clear all" });
      again.focus();
      fireEvent.click(again);
      // The channel chip stays, and so does the row; focus still lands on the search box.
      expect(screen.getByRole("button", { name: "Remove Channels: 1 of 2" })).toBeInTheDocument();
      expect(screen.getByRole("textbox", { name: "Search events" })).toHaveFocus();
    });
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
 * Focus when the row loses the control that had it, by any path but a click on a remove button: the
 * store clears a criterion (a load start, a change of source, a cleared channel's prune) and the chip
 * or the whole row unmounts under the focus. The row watches the focus, so none of these is listed.
 */
describe("focus when a chip, Clear all or the row unmounts under it", () => {
  const renderWithSearch = () =>
    render(
      <>
        <input id={EVTX_SEARCH_INPUT_ID} aria-label="Search events" />
        <EvtxFilterChips visibleCount={1} loadedCount={2} />
      </>,
    );
  const remove = (label: string) => screen.getByRole("button", { name: `Remove ${label}` });
  const TIME = `Time: brushed 09:00${SEP}09:45`;
  const SCOPE = "Finding: MDM enrollment failed";
  const search = () => screen.getByRole("textbox", { name: "Search events" });
  /** The store clears both criteria the way a load start does: a second `set` on the store. */
  const startLoad = () => act(() => useEvtxStore.setState({ isLoading: true }));

  /** channels, time range, record scope: three chips, two of them transient. */
  const seedThree = () =>
    seedWithTransient(
      { timeRange: RANGE, recordScope: scopeOf(3) },
      { timeZoneMode: "utc", selectedChannels: new Set(["System"]) },
    );

  it("moves to the neighbouring chip when a load starts under the focused Time chip", () => {
    seedThree();
    renderWithSearch();
    remove(TIME).focus();
    startLoad();
    // Both transient chips are gone, so the neighbour is the one before: the channels chip.
    expect(remove("Channels: 1 of 2")).toHaveFocus();
  });

  it("moves to the next chip when only the focused chip goes", () => {
    seedThree();
    renderWithSearch();
    remove(TIME).focus();
    act(() => {
      useEvtxStore.getState().setTimeRange(null);
    });
    expect(remove(SCOPE)).toHaveFocus();
  });

  it("moves to the previous chip when the focused chip was the last one", () => {
    seedThree();
    renderWithSearch();
    remove(SCOPE).focus();
    act(() => {
      useEvtxStore.getState().setRecordScope(null);
    });
    expect(remove(TIME)).toHaveFocus();
  });

  it("moves to the search box when the whole row unmounts under the focused chip", () => {
    seedWithTransient({ timeRange: RANGE, recordScope: scopeOf(3) }, { timeZoneMode: "utc" });
    renderWithSearch();
    remove(TIME).focus();
    startLoad();
    expect(screen.queryByRole("list", { name: "Active filters" })).toBeNull();
    expect(search()).toHaveFocus();
  });

  it("does the same when the source changes", () => {
    seedWithTransient({ timeRange: RANGE }, { timeZoneMode: "utc" });
    renderWithSearch();
    remove(TIME).focus();
    act(() => useEvtxStore.setState({ sourceMode: "live" }));
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(search()).toHaveFocus();
  });

  it("moves to the search box when the focused Clear all link goes with its last clearable chip", () => {
    seedWithTransient({ timeRange: RANGE }, { timeZoneMode: "utc", selectedChannels: new Set(["System"]) });
    renderWithSearch();
    screen.getByRole("button", { name: "Clear all" }).focus();
    startLoad();
    // The channels chip is not cleared by Clear all, so the row stays and the link does not.
    expect(screen.queryByRole("button", { name: "Clear all" })).toBeNull();
    expect(screen.getByRole("list", { name: "Active filters" })).toBeInTheDocument();
    expect(search()).toHaveFocus();
  });

  it("leaves focus where it is when the chip that goes did not have it", () => {
    seedThree();
    renderWithSearch();
    remove("Channels: 1 of 2").focus();
    startLoad();
    expect(remove("Channels: 1 of 2")).toHaveFocus();
  });

  it("does not take focus from the search box", () => {
    seedThree();
    renderWithSearch();
    remove(TIME).focus();
    search().focus();
    startLoad();
    expect(search()).toHaveFocus();
    // Nor from a control elsewhere in the document.
    cleanup();
    seedThree();
    const outside = document.createElement("button");
    document.body.appendChild(outside);
    try {
      renderWithSearch();
      remove(TIME).focus();
      outside.focus();
      startLoad();
      expect(outside).toHaveFocus();
    } finally {
      outside.remove();
    }
  });

  it("keeps following focus as it moves from one control of the row to another", async () => {
    seedThree();
    renderWithSearch();
    remove("Channels: 1 of 2").focus();
    remove(TIME).focus();
    // Let the blur of the first control settle before the criteria go.
    await act(async () => {
      await Promise.resolve();
    });
    startLoad();
    expect(remove("Channels: 1 of 2")).toHaveFocus();
  });

  it("does not bring focus back after the operator clicked away from a chip", async () => {
    seedThree();
    renderWithSearch();
    remove(TIME).focus();
    remove(TIME).blur();
    await act(async () => {
      await Promise.resolve();
    });
    startLoad();
    expect(document.body).toHaveFocus();
  });
});

describe("the Time chip's colors", () => {
  it("come from the token map, not from the Fluent palette tokens the map happens to hold", () => {
    expect(chipsSource).not.toMatch(/colorPaletteBlue/);
  });
});

describe("EvtxFilterChips with the transient criteria", () => {
  const arm = () => {
    seedWithTransient(
      { timeRange: RANGE, recordScope: scopeOf(3) },
      { timeZoneMode: "utc", timeWindow: "7d", selectedChannels: new Set(["System"]) },
    );
  };

  it("shows the Time chip and the Finding chip after the others, with the remove buttons named for them", () => {
    arm();
    render(<EvtxFilterChips visibleCount={3} loadedCount={9} />);
    const items = within(screen.getByRole("list", { name: "Active filters" })).getAllByRole("listitem");
    expect(items.map((item) => item.textContent)).toEqual([
      "Channels: 1 of 2",
      `Time: brushed 09:00${SEP}09:45`,
      "Finding: MDM enrollment failed",
    ]);
    expect(screen.getByRole("button", { name: `Remove Time: brushed 09:00${SEP}09:45` })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove Finding: MDM enrollment failed" })).toBeInTheDocument();
  });

  it("names the year in the Time chip and its remove button for a range in a past year", () => {
    seedWithTransient(
      {
        timeRange: { startMs: Date.UTC(2024, 2, 3), endMs: Date.UTC(2024, 3, 2) },
        recordScope: null,
      },
      { timeZoneMode: "utc", selectedChannels: new Set(["System", "Application"]) },
    );
    render(<EvtxFilterChips visibleCount={3} loadedCount={9} />);
    const label = `Time: brushed Mar 3 2024 00:00${SEP}Apr 2 2024 00:00`;
    expect(screen.getByText(label)).toHaveAttribute("title", `${label} (UTC)`);
    expect(screen.getByRole("button", { name: `Remove ${label}` })).toBeInTheDocument();
  });

  it("draws the Time chip in the selection colors and no other chip", () => {
    arm();
    render(<EvtxFilterChips visibleCount={3} loadedCount={9} />);
    const selection = buildEvtxVisualTokens(
      getAllThemes().find((theme) => theme.id === useUiStore.getState().themeId)!,
    ).selection;
    const time = document.querySelector<HTMLElement>("[data-evtx-chip='timeRange']")!;
    expect(time.style.backgroundColor).toBe(selection.background);
    expect(time.style.borderColor).toBe(selection.border);
    expect(time.style.color).toBe(selection.foreground);
    for (const other of ["channels", "recordScope"]) {
      const li = document.querySelector<HTMLElement>(`[data-evtx-chip='${other}']`)!;
      expect(li.style.backgroundColor).toBe("");
    }
  });

  it("carries the tooltips: the zone on the Time chip, and the scope's size on the Finding chip", () => {
    arm();
    render(<EvtxFilterChips visibleCount={3} loadedCount={9} untimedHiddenCount={2} />);
    expect(screen.getByText(`Time: brushed 09:00${SEP}09:45`)).toHaveAttribute(
      "title",
      `Time: brushed 09:00${SEP}09:45 (UTC)\n2 events without a timestamp are hidden by this range`,
    );
    expect(screen.getByText("Finding: MDM enrollment failed")).toHaveAttribute(
      "title",
      "Finding: MDM enrollment failed\n3 events in this scope.",
    );
  });

  it("removes the time range alone, and the scope alone", () => {
    arm();
    render(<EvtxFilterChips visibleCount={3} loadedCount={9} />);
    fireEvent.click(screen.getByRole("button", { name: `Remove Time: brushed 09:00${SEP}09:45` }));
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(useEvtxStore.getState().recordScope).not.toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Remove Finding: MDM enrollment failed" }));
    expect(useEvtxStore.getState().recordScope).toBeNull();
    expect(useEvtxStore.getState().timeRange).toBeNull();
  });

  it("clears both with Clear all and leaves the channel selection and the time window alone", () => {
    arm();
    render(<EvtxFilterChips visibleCount={3} loadedCount={9} />);
    fireEvent.click(screen.getByRole("button", { name: "Clear all" }));
    const state = useEvtxStore.getState();
    expect(state.timeRange).toBeNull();
    expect(state.recordScope).toBeNull();
    expect(state.timeWindow).toBe("7d");
    expect([...state.selectedChannels]).toEqual(["System"]);
    expect(screen.getByRole("button", { name: "Remove Channels: 1 of 2" })).toBeInTheDocument();
  });

  it("is shown on its own, with the readout, when nothing else is active", () => {
    seedWithTransient({ timeRange: RANGE });
    render(<EvtxFilterChips visibleCount={4} loadedCount={9} />);
    expect(screen.getByRole("list", { name: "Active filters" })).toBeInTheDocument();
    expect(document.querySelector("[data-evtx-filter-count]")?.textContent).toBe("Showing 4 of 9");
  });

  it("hands focus to the neighbouring chip when the Time chip is removed", () => {
    arm();
    render(<EvtxFilterChips visibleCount={3} loadedCount={9} />);
    const remove = screen.getByRole("button", { name: `Remove Time: brushed 09:00${SEP}09:45` });
    remove.focus();
    fireEvent.click(remove);
    expect(screen.getByRole("button", { name: "Remove Finding: MDM enrollment failed" })).toHaveFocus();
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
  },
);

/**
 * The Time chip is drawn in the selection colors (spec 6.2, Q-1). Each pair is measured on resolved
 * theme colors, and the DOM half pins what is painted to the same tokens. The remove icon at rest
 * uses the selection foreground: Foreground2 on the selection fill measures 3.80:1 in solarized-dark.
 */
describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "Time chip contrast in the %s theme",
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
    const selection = buildEvtxVisualTokens(theme).selection;
    const renderChip = () => {
      useUiStore.setState({ themeId: theme.id });
      seedWithTransient({ timeRange: RANGE }, { timeZoneMode: "utc" });
      render(<EvtxFilterChips visibleCount={1} loadedCount={2} />);
      return screen.getByRole("button", { name: `Remove Time: brushed 09:00${SEP}09:45` });
    };

    it("reads the chip text at 4.5:1 on the selection fill", () => {
      renderChip();
      const chip = document.querySelector<HTMLElement>("[data-evtx-chip='timeRange']")!;
      expect(chip.style.color).toBe(tokens.colorPaletteBlueForeground2);
      expect(chip.style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
      expect(selection).toMatchObject({
        foreground: tokens.colorPaletteBlueForeground2,
        background: tokens.colorPaletteBlueBackground2,
        border: tokens.colorPaletteBlueBorderActive,
      });
      atLeast("chip text", selection.foreground, selection.background, 4.5);
    });

    it("draws the remove icon at rest in the token map's selection foreground, at 4.5:1 on the fill", () => {
      const remove = renderChip();
      const chip = document.querySelector<HTMLElement>("[data-evtx-chip='timeRange']")!;
      // The class reads a variable and the chip sets it from the map, so the painted color is the
      // map's selection foreground, whatever token that is.
      expect(declared(remove, "", "color")).toEqual(["var(--evtx-chip-remove-color)"]);
      expect(chip.style.getPropertyValue("--evtx-chip-remove-color")).toBe(selection.foreground);
      expect(chip.style.color).toBe(selection.foreground);
      atLeast("remove rest", selection.foreground, selection.background, 4.5);
    });


    it("keeps the hover and pressed pairs of every chip, at 4.5:1 on their own surfaces", () => {
      const remove = renderChip();
      expect(declared(remove, ":hover", "color")).toEqual([tokens.colorNeutralForeground2Hover]);
      expect(declared(remove, ":hover", "background-color")).toEqual([tokens.colorSubtleBackgroundHover]);
      expect(declared(remove, ":active", "color")).toEqual([tokens.colorNeutralForeground2Pressed]);
      expect(declared(remove, ":active", "background-color")).toEqual([tokens.colorSubtleBackgroundPressed]);
      atLeast("remove hover", tokens.colorNeutralForeground2Hover, tokens.colorSubtleBackgroundHover, 4.5);
      atLeast("remove pressed", tokens.colorNeutralForeground2Pressed, tokens.colorSubtleBackgroundPressed, 4.5);
    });

    it("bounds the chip with a border at 3:1 on the row surface", () => {
      renderChip();
      const row = document.querySelector("[data-evtx-region='chip-row']")!;
      expect(declared(row, "", "background-color")).toEqual([tokens.colorNeutralBackground1]);
      atLeast("chip border", selection.border, tokens.colorNeutralBackground1, 3);
    });
  },
);
