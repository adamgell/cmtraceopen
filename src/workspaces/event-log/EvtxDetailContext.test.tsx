/**
 * The Details "Context ±5 min" section (spec 8.13 Details item 7, #843), rendered with the window
 * and the counts it is given: no IPC, no hook. The model has its own tests; this file protects what
 * the component adds: what is drawn for each state, that a row carries no relationship words, that
 * nothing is announced, that the link goes where it says, that sizes follow the log list size, and
 * that everything drawn reaches its contrast floor in every theme.
 */
import { tokens } from "@fluentui/react-components";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

// The real model, counted: "is the list rebuilt?" is a question about calls, not about DOM nodes.
vi.mock("./evtx-detail-context-model", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-detail-context-model")>();
  return { ...actual, buildDetailContext: vi.fn(actual.buildDetailContext) };
});

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes, type ThemeId } from "../../lib/themes";
import {
  MAX_LOG_LIST_FONT_SIZE,
  MIN_LOG_LIST_FONT_SIZE,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import {
  ANALYSIS_BUILDING_TEXT,
  NOT_IN_TIMELINE_NOTE,
  READING_WINDOW_TEXT,
  UNTIMED_TEXT,
  UPDATING_CORRELATION_TEXT,
  windowFailureText,
} from "./evtx-correlation-copy";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import { eventItem, recordFor, rid, synthetic, T0 } from "./evtx-correlation-test-fixtures";
import {
  DETAIL_CONTEXT_TITLE,
  LINKS_MAY_BE_MISSING_TEXT,
  LINK_LEGEND_TEXT,
  buildDetailContext,
} from "./evtx-detail-context-model";
import {
  countsFor,
  logItem,
  stoppedWindow,
  twinOf,
  unnumbered,
  windowAround,
} from "./evtx-detail-context-test-helpers";
import { correlationSizes } from "./evtx-correlation-sizes";
import { evtxViewTabId, useEvtxLayoutStore } from "./evtx-layout-store";
import { resolveToken } from "./evtx-visual-tokens";
import { EvtxDetailContext, type EvtxDetailContextProps } from "./EvtxDetailContext";
import chipSource from "./EvtxKindChip.tsx?raw";
import componentSource from "./EvtxDetailContext.tsx?raw";
import modelSource from "./evtx-detail-context-model.ts?raw";
import type { TimelineItem } from "./unified-timeline";

const record = recordFor(20);
const t = record.timestampEpoch;

/** Record 20 and five entries around it; 21 is an exact partner, 22 a candidate one. */
const items = (): TimelineItem[] => [
  eventItem(18, t - 2_000),
  eventItem(19, t - 1_000),
  eventItem(20, t),
  eventItem(21, t + 3_300),
  logItem(7, t + 4_000),
  eventItem(22, t + 9_000),
];
const edges = () => [synthetic("e", rid(20), rid(21)), synthetic("c", rid(20), rid(22), "candidate")];

function props(extra: Partial<EvtxDetailContextProps> = {}): EvtxDetailContextProps {
  return {
    record,
    window: windowAround(record, items()),
    counts: countsFor(edges()),
    unreadSources: false,
    session: "available",
    timeZoneMode: "utc",
    ...extra,
  };
}

/** The rail the section sits on (bg2), so the contrast walk finds the surface under the section. */
function draw(extra: Partial<EvtxDetailContextProps> = {}) {
  return render(
    <div style={{ backgroundColor: tokens.colorNeutralBackground2 }}>
      <EvtxDetailContext {...props(extra)} />
    </div>,
  );
}

const section = () => screen.getByRole("group", { name: DETAIL_CONTEXT_TITLE });
const rows = () => within(section()).getAllByRole("listitem");

beforeEach(() => {
  vi.mocked(buildDetailContext).mockClear();
  useUiStore.setState({ themeId: "light" as ThemeId, logListFontSize: 14 });
  useEvtxLayoutStore.setState({ activeView: "table" });
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false });
});

afterEach(() => {
  cleanup();
});

describe("a section with a window", () => {
  it("names itself, and titles the list with the window and the kinds it holds", () => {
    draw();
    expect(section()).toHaveAttribute("aria-busy", "false");
    expect(within(section()).getByText(DETAIL_CONTEXT_TITLE)).toBeInTheDocument();
    expect(within(section()).getByText("events + text logs")).toBeInTheDocument();
    expect(DETAIL_CONTEXT_TITLE).toBe("Context ±5 min");
  });

  it("lists every row in time order with its time, kind, message, offset and source", () => {
    draw();
    const listed = rows();
    expect(listed).toHaveLength(6);
    expect(within(section()).getByRole("list", { name: "Entries around this event" })).toBeInTheDocument();
    expect(listed.map((row) => row.querySelector("[data-evtx-ctx='time']")?.textContent)).toEqual([
      "10:20:18",
      "10:20:19",
      "10:20:20",
      "10:20:23",
      "10:20:24",
      "10:20:29",
    ]);
    expect(listed.map((row) => row.querySelector("[data-chip]")?.textContent)).toEqual(["EVT", "EVT", "EVT", "EVT", "LOG", "EVT"]);
    expect(listed.map((row) => row.querySelector("[data-evtx-ctx='offset']")?.textContent)).toEqual([
      "-2 s · 118 · System",
      "-1 s · 119 · System",
      "this event · 120 · System",
      "+3.3 s · 121 · System",
      "+4 s · AgentExecutor.log · line 7",
      "+9 s · 122 · System",
    ]);
    expect(listed[4]).toHaveTextContent("Starting Powershell Execution");
  });

  it("shows the time in the zone it is given", () => {
    draw({ timeZoneMode: "local" });
    const expected = new Date(t).getHours().toString().padStart(2, "0");
    expect(rows()[2]?.querySelector("[data-evtx-ctx='time']")?.textContent?.slice(0, 2)).toBe(expected);
  });

  it("marks the selected event with aria-current, in words, and with the selection colors", () => {
    draw();
    const marked = rows().filter((row) => row.getAttribute("aria-current") === "true");
    expect(marked).toHaveLength(1);
    expect(marked[0]).toHaveTextContent("this event");
    expect(marked[0]?.style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    expect(marked[0]?.style.color).toBe(tokens.colorPaletteBlueForeground2);
    expect(rows().filter((row) => row !== marked[0]).every((row) => !row.hasAttribute("aria-current"))).toBe(true);
  });

  it("puts the link icon on a direct Exact or Candidate edge only, named for what it is", () => {
    draw();
    const icons = within(section()).getAllByRole("img", { name: /link to this event/ });
    expect(icons.map((icon) => icon.getAttribute("aria-label"))).toEqual([
      "Exact link to this event by ActivityId",
      "Candidate link to this event by ActivityId",
    ]);
    expect(icons.every((icon) => icon.getAttribute("title") === icon.getAttribute("aria-label"))).toBe(true);
    const owners = icons.map((icon) => icon.closest("li")?.querySelector("[data-evtx-ctx='offset']")?.textContent);
    expect(owners).toEqual(["+3.3 s · 121 · System", "+9 s · 122 · System"]);
    expect(within(section()).getByText(LINK_LEGEND_TEXT)).toBeInTheDocument();
  });

  it("shows no icon and no legend when nothing is linked to the event", () => {
    draw({ counts: countsFor([]) });
    expect(within(section()).queryAllByRole("img", { name: /link to this event/ })).toEqual([]);
    expect(within(section()).queryByText(LINK_LEGEND_TEXT)).toBeNull();
  });

  it("says how the rows were chosen, and what the session could not show", () => {
    draw({ counts: countsFor(edges(), { totalEdges: 9 }) });
    expect(within(section()).getByText("6 entries within ±5 min")).toBeInTheDocument();
    expect(within(section()).getByText(LINKS_MAY_BE_MISSING_TEXT)).toBeInTheDocument();
    expect(section()).toHaveTextContent("were not loaded");
  });

  it("says nearest only when it is proven, and otherwise of what was read", () => {
    const many = Array.from({ length: 41 }, (_, index) => eventItem(index + 1, T0 + (index + 1) * 1_000));
    draw({ window: stoppedWindow(record, many.slice(0, 25), 500) });
    expect(within(section()).getByText("12 nearest of the 25 entries read")).toBeInTheDocument();
    cleanup();
    draw({ window: stoppedWindow(record, many, 500) });
    expect(within(section()).getByText("12 nearest entries within ±5 min")).toBeInTheDocument();
    expect(section()).toHaveTextContent("Showing 41 of 500 entries");
  });

  it("says no other entries only when the model may, and qualifies it otherwise", () => {
    draw({ window: windowAround(record, [eventItem(20, t)]) });
    expect(within(section()).getByText("No other entries within ±5 min.")).toBeInTheDocument();
    cleanup();
    draw({ window: windowAround(record, [eventItem(20, t)]), unreadSources: true });
    expect(section()).toHaveTextContent("No other visible entries within ±5 min.");
    expect(section()).toHaveTextContent("Some sources were not fully read, so entries may be missing.");
  });

  it("lists nothing, and says why, for an event that cannot be told from the entries", () => {
    const unmatchable = unnumbered(t);
    draw({ record: unmatchable, window: windowAround(unmatchable, items()) });
    expect(within(section()).queryByRole("list")).toBeNull();
    expect(section()).toHaveTextContent("This event has no record identity the timeline can match");
    expect(section()).toHaveTextContent("They are not listed");
    cleanup();
    draw({ window: windowAround(record, [...items(), twinOf(eventItem(20, t), rid(88))]) });
    expect(section()).toHaveTextContent("They are not listed");
    expect(section()).not.toHaveTextContent("drawn");
  });
});

describe("a section follows its inputs", () => {
  it("shows the new window, the new counts and the new record when they change", () => {
    const view = render(<EvtxDetailContext {...props()} />);
    expect(within(section()).getAllByRole("listitem")).toHaveLength(6);
    expect(within(section()).getAllByRole("img", { name: /link to this event/ })).toHaveLength(2);

    view.rerender(<EvtxDetailContext {...props({ window: windowAround(record, items().slice(0, 4)) })} />);
    expect(within(section()).getAllByRole("listitem")).toHaveLength(4);

    view.rerender(<EvtxDetailContext {...props({ counts: countsFor([]) })} />);
    expect(within(section()).queryAllByRole("img", { name: /link to this event/ })).toEqual([]);

    view.rerender(<EvtxDetailContext {...props({ counts: countsFor([synthetic("e", rid(20), rid(18))]) })} />);
    expect(within(section()).getAllByRole("img", { name: /link to this event/ })).toHaveLength(1);

    const other = recordFor(21);
    view.rerender(<EvtxDetailContext {...props({ record: other, window: windowAround(other, items()) })} />);
    const marked = within(section()).getAllByRole("listitem").filter((row) => row.getAttribute("aria-current") === "true");
    expect(marked).toHaveLength(1);
    expect(marked[0]).toHaveTextContent("121 \u00b7 System");
  });

  describe("reads each part of what it is given, one at a time", () => {
    // The window and the record are fixed objects here, so only the part under test can change the
    // model's input: a part the component forgot would leave the old words on the screen.
    const counts = countsFor(edges());
    const base = props({ counts });
    const text = () => section().textContent ?? "";

    it("reads the window", () => {
      const view = render(<EvtxDetailContext {...base} />);
      view.rerender(<EvtxDetailContext {...base} window={windowAround(record, items().slice(0, 4))} />);
      expect(within(section()).getAllByRole("listitem")).toHaveLength(4);
    });

    it("reads the record", () => {
      const view = render(<EvtxDetailContext {...base} />);
      expect(within(section()).getByRole("listitem", { current: true })).toHaveTextContent("120 \u00b7 System");
      // The same instant, so the same window answers it, but no entry of the window names this event.
      view.rerender(<EvtxDetailContext {...base} record={{ ...record, eventId: 999 }} />);
      expect(within(section()).queryByRole("listitem", { current: true })).toBeNull();
      expect(text()).toContain(NOT_IN_TIMELINE_NOTE);
    });

    it.each([
      ["the session they belong to", { builtFor: "session:2" }, "still loading"],
      ["the gaps", { gaps: classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1) }, "The engine limited correlation"],
      ["the scope", { scope: { visibleCount: 2, loadedCount: 9, textLogCount: 0 } }, "computed over the 2 events visible"],
      ["whether they are an earlier session's", { updating: true }, UPDATING_CORRELATION_TEXT],
    ] as const)("reads %s of the counts", (_part, change, expected) => {
      const view = render(<EvtxDetailContext {...base} />);
      expect(text()).not.toContain(expected);
      view.rerender(<EvtxDetailContext {...base} counts={{ ...counts, ...change }} />);
      expect(text()).toContain(expected);
    });

    it("reads the model of the counts", () => {
      const view = render(<EvtxDetailContext {...base} />);
      expect(within(section()).getAllByRole("img", { name: /link to this event/ })).toHaveLength(2);
      view.rerender(<EvtxDetailContext {...base} counts={{ ...counts, model: countsFor([]).model }} />);
      expect(within(section()).queryAllByRole("img", { name: /link to this event/ })).toEqual([]);
    });

    it("reads the unplaced list of the counts", () => {
      const alone = props({ counts, window: windowAround(record, [eventItem(20, t)]) });
      const view = render(<EvtxDetailContext {...alone} />);
      expect(text()).toContain("No other entries within \u00b15 min.");
      view.rerender(<EvtxDetailContext {...alone} counts={{ ...counts, unplacedList: { items: [], total: 3 } }} />);
      expect(text()).toContain("No other visible entries within \u00b15 min.");
      expect(text()).toContain("3 entries have no usable time");
    });

    it("reads whether a source went unread", () => {
      const view = render(<EvtxDetailContext {...base} />);
      view.rerender(<EvtxDetailContext {...base} unreadSources />);
      expect(text()).toContain("Some sources were not fully read");
    });

    it("reads the session, while there is no window", () => {
      const waiting = props({ window: null, session: "available" });
      const view = render(<EvtxDetailContext {...waiting} />);
      expect(text()).toContain(READING_WINDOW_TEXT);
      view.rerender(<EvtxDetailContext {...waiting} session="building" />);
      expect(text()).toContain(ANALYSIS_BUILDING_TEXT);
    });
  });

  describe("does not rebuild the model when nothing it reads has changed", () => {
    // One window, one record and one counts object for every render, so only the part under test
    // can change what the model is given. The hook hands over a NEW counts object on every run
    // change, scan progress included, and each of those must cost nothing.
    const counts = countsFor(edges());
    const fixed = props({ counts });
    const builds = () => vi.mocked(buildDetailContext).mock.calls.length;

    it("builds once for the first render, and not again for the same props", () => {
      const view = render(<EvtxDetailContext {...fixed} />);
      expect(builds()).toBe(1);
      view.rerender(<EvtxDetailContext {...fixed} />);
      expect(builds()).toBe(1);
    });

    it("does not rebuild for a new counts object that holds the same parts", () => {
      const view = render(<EvtxDetailContext {...fixed} />);
      view.rerender(<EvtxDetailContext {...fixed} counts={{ ...counts }} />);
      view.rerender(<EvtxDetailContext {...fixed} counts={{ ...counts }} />);
      expect(builds()).toBe(1);
    });

    it("does not rebuild for what the model does not read: link partners, the time zone", () => {
      const view = render(<EvtxDetailContext {...fixed} />);
      view.rerender(<EvtxDetailContext {...fixed} counts={{ ...counts, linkPartners: new Map([["x", 1]]) }} />);
      view.rerender(<EvtxDetailContext {...fixed} counts={{ ...counts }} timeZoneMode="local" />);
      expect(builds()).toBe(1);
    });

    it("does rebuild when a part it reads changes, so the count above can fail", () => {
      const view = render(<EvtxDetailContext {...fixed} />);
      view.rerender(<EvtxDetailContext {...fixed} counts={{ ...counts, updating: true }} />);
      expect(builds()).toBe(2);
      view.rerender(<EvtxDetailContext {...fixed} counts={{ ...counts, updating: true }} unreadSources />);
      expect(builds()).toBe(3);
    });
  });
});

describe("a section before there is a window to list", () => {
  it.each([
    ["no record time", { record: { ...record, timestampEpoch: 0 } }, UNTIMED_TEXT],
    ["no session", { window: null, session: "none" as const }, "No event analysis is available. Load events to see what is around an event."],
    ["a session being built", { window: null, session: "building" as const }, ANALYSIS_BUILDING_TEXT],
    ["a window being read", { window: null }, READING_WINDOW_TEXT],
    [
      "a window that failed",
      { window: windowAround(record, [], { windowItems: null, omittedItems: null, complete: false, error: "down" }) },
      windowFailureText("down"),
    ],
  ] as [string, Partial<EvtxDetailContextProps>, string][])("says so for %s, with no list", (_why, extra, text) => {
    draw(extra);
    expect(within(section()).getByText(text)).toBeInTheDocument();
    expect(within(section()).queryByRole("list")).toBeNull();
    expect(within(section()).queryAllByRole("listitem")).toEqual([]);
    // The way to the full view is there whatever the state.
    expect(within(section()).getByRole("button", { name: /^Open full correlation timeline/ })).toBeInTheDocument();
  });

  it("is busy only while a window is being read", () => {
    draw({ window: null });
    expect(section()).toHaveAttribute("aria-busy", "true");
    cleanup();
    draw({ window: null, session: "none" });
    expect(section()).toHaveAttribute("aria-busy", "false");
  });
});

describe("nothing in the section is announced", () => {
  const scenes: [string, Partial<EvtxDetailContextProps>][] = [
    ["a window", {}],
    ["no window", { window: null }],
    ["a failure", { window: windowAround(record, [], { windowItems: null, omittedItems: null, complete: false, error: "x" }) }],
    ["a stopped read with every note", { window: stoppedWindow(record, items(), 500), unreadSources: true, counts: countsFor(edges(), { totalEdges: 9, updating: true }) }],
  ];

  it.each(scenes)("has no live region for %s", (_why, extra) => {
    const view = draw(extra);
    for (const role of ["status", "alert", "log", "marquee", "timer"]) {
      expect(within(view.container).queryAllByRole(role), role).toEqual([]);
    }
    expect(view.container.querySelectorAll("[aria-live], [aria-atomic], [role='status'], [role='alert']")).toHaveLength(0);
  });
});

describe("a row carries no relationship words (the class test, on what is drawn)", () => {
  const RELATIONSHIP_WORDS =
    /not linked|no loaded link|in another chain|not in this chain|link to this event not known|ambiguous with this event|coverage blocked with this event|linked, but its link|time only[,;]/i;
  const blocked = {
    ...synthetic("g", rid(20), rid(19)),
    coverage: { state: "gap" as const, gap: { source: "Live", reason: "channel not collected" } },
  };
  const scenes: [string, Partial<EvtxDetailContextProps>][] = [
    ["a clear session", {}],
    ["an ambiguous and a blocked row", { counts: countsFor([...edges(), synthetic("a", rid(20), rid(18), "ambiguous"), blocked]) }],
    ["another session's counts", { counts: countsFor(edges(), { builtFor: "session:2" }) }],
    ["no counts", { counts: null }],
    ["a narrowed scope", { counts: countsFor(edges(), { scope: { visibleCount: 2, loadedCount: 9, textLogCount: 1 } }) }],
    ["a gap that names a row", { counts: countsFor(edges(), { gaps: classifyCoverageGaps([{ source: rid(19), reason: "x" }], 1) }) }],
    ["unread sources", { unreadSources: true }],
    ["a stopped read", { window: stoppedWindow(record, items().slice(0, 4), 500) }],
  ];

  it.each(scenes)("uses none of those words anywhere: %s", (_why, extra) => {
    const view = draw(extra);
    expect(view.container.textContent).not.toMatch(RELATIONSHIP_WORDS);
    for (const row of within(view.container).queryAllByRole("listitem")) {
      const linked = row.querySelector("[role='img'][aria-label*='link to this event']") !== null;
      if (!linked) {
        expect(row.textContent).not.toMatch(/linked|link/i);
        expect(row.querySelector("[aria-label*='link']")).toBeNull();
      }
    }
  });
});

describe("Open full correlation timeline", () => {
  it("opens the Correlation view and leaves the chain selection alone", () => {
    useEvtxCorrelationStore.setState({ selectedChainId: "kept" });
    draw();
    fireEvent.click(screen.getByRole("button", { name: /^Open full correlation timeline/ }));
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe("kept");
  });

  it("moves focus to the Correlation tab", () => {
    render(
      <>
        <button id={evtxViewTabId("correlation")}>Correlation</button>
        <EvtxDetailContext {...props()} />
      </>,
    );
    const link = screen.getByRole("button", { name: /^Open full correlation timeline/ });
    act(() => link.focus());
    fireEvent.click(link);
    expect(screen.getByRole("button", { name: "Correlation" })).toHaveFocus();
  });

  it("is named by its visible words first, and says where it goes", () => {
    draw();
    const link = screen.getByRole("button", { name: /^Open full correlation timeline/ });
    expect(link).toHaveTextContent("Open full correlation timeline");
    expect(link).toHaveAttribute("aria-description", "Switches the main view to Correlation.");
  });
});

describe("sizes follow the log list font size", () => {
  const sizesOf = (fontSize: number) => {
    useUiStore.setState({ logListFontSize: fontSize });
    const view = draw();
    const style = (selector: string) => (view.container.querySelector(selector) as HTMLElement).style;
    const measured = {
      eyebrow: style("[data-evtx-ctx='eyebrow']").fontSize,
      kinds: style("[data-evtx-ctx='kinds']").fontSize,
      time: style("[data-evtx-ctx='time']").fontSize,
      timeWidth: style("[data-evtx-ctx='time']").width,
      message: style("[data-evtx-ctx='message']").fontSize,
      offset: style("[data-evtx-ctx='offset']").fontSize,
      caption: style("[data-evtx-ctx='caption']").fontSize,
      chip: style("[data-chip]").fontSize,
      open: style("[data-evtx-ctx='open']").fontSize,
    };
    view.unmount();
    return measured;
  };

  it("derives every size from getLogListMetrics, with the spec's floors, at the smallest and the largest", () => {
    for (const fontSize of [MIN_LOG_LIST_FONT_SIZE, 14, MAX_LOG_LIST_FONT_SIZE]) {
      const f = getLogListMetrics(fontSize).fontSize;
      const label = `${Math.max(10, f - 3)}px`;
      expect(sizesOf(fontSize), `at ${fontSize}`).toEqual({
        eyebrow: label,
        kinds: label,
        time: label,
        // Wide enough for eight digits at this size, so it never clips at the largest.
        timeWidth: "8ch",
        message: `${Math.max(10, f - 2)}px`,
        offset: label,
        caption: label,
        chip: `${Math.max(10, f - 4)}px`,
        open: `${Math.max(10, f - 2)}px`,
      });
    }
  });

  it("takes its sizes from the correlation sizes, with a floor of 10 px on the message and the chip", () => {
    expect(componentSource).toContain('from "./evtx-correlation-sizes"');
    expect(componentSource).toMatch(/correlationSizes\(logListFontSize\)/);
    expect(componentSource).not.toMatch(/logListFontSize\s*-\s*\d/);
    expect(componentSource).not.toContain("getLogListMetrics");
    // The correlation sizes alone go under 10 px at the smallest font; the section's floor is its own.
    expect(correlationSizes(MIN_LOG_LIST_FONT_SIZE)).toMatchObject({ lane: 9, label: 10, tick: 9 });
  });

  it("never sets a text size under 10 px", () => {
    useUiStore.setState({ logListFontSize: MIN_LOG_LIST_FONT_SIZE });
    const view = draw();
    for (const element of view.container.querySelectorAll<HTMLElement>("[style*='font-size']")) {
      expect(Number.parseFloat(element.style.fontSize), element.textContent ?? "").toBeGreaterThanOrEqual(10);
    }
  });
});

describe("contrast, in every theme, measured on what is drawn", () => {
  const themes = getAllThemes();

  /** The nearest value of `property` set inline on the element or an ancestor. */
  function inherited(element: HTMLElement, property: "color" | "backgroundColor"): string | null {
    for (let node: HTMLElement | null = element; node !== null; node = node.parentElement) {
      if (node.style[property] !== "") return node.style[property];
    }
    return null;
  }

  const hasOwnText = (element: HTMLElement) =>
    [...element.childNodes].some((node) => node.nodeType === Node.TEXT_NODE && (node.textContent ?? "").trim() !== "");

  /** A scene that draws every kind of text and both icons. */
  const full = () =>
    props({
      window: stoppedWindow(record, items(), 500),
      counts: countsFor(edges(), { totalEdges: 9, scope: { visibleCount: 3, loadedCount: 9, textLogCount: 2 }, updating: true }),
      unreadSources: true,
    });

  it("measures seven themes", () => {
    expect(themes).toHaveLength(7);
  });

  it("reaches 4.5:1 for every text against what is behind it", () => {
    const floor = 4.5;
    const figures: string[] = [];
    for (const theme of themes) {
      useUiStore.setState({ themeId: theme.id });
      const view = render(
        <div style={{ backgroundColor: tokens.colorNeutralBackground2 }}>
          <EvtxDetailContext {...full()} />
        </div>,
      );
      let lowest = Number.POSITIVE_INFINITY;
      let measured = 0;
      for (const element of view.container.querySelectorAll<HTMLElement>("*")) {
        if (!hasOwnText(element)) continue;
        const color = inherited(element, "color");
        const background = inherited(element, "backgroundColor");
        expect(color, `${theme.id}: "${element.textContent}" sets its color`).not.toBeNull();
        expect(background, `${theme.id}: "${element.textContent}" sits on a surface`).not.toBeNull();
        const ratio = contrastRatio(resolveToken(color as string, theme), resolveToken(background as string, theme));
        lowest = Math.min(lowest, ratio);
        measured += 1;
        expect(ratio, `${theme.id}: "${element.textContent?.slice(0, 40)}"`).toBeGreaterThanOrEqual(floor);
      }
      expect(measured, theme.id).toBeGreaterThan(20);
      figures.push(`${theme.id} ${lowest.toFixed(2)}`);
      view.unmount();
    }
    console.info(`Details context, lowest text contrast per theme: ${figures.join(", ")}`);
  });

  it("reaches 3:1 for the link icons against the list surface", () => {
    const figures: string[] = [];
    for (const theme of themes) {
      useUiStore.setState({ themeId: theme.id });
      const view = render(
        <div style={{ backgroundColor: tokens.colorNeutralBackground2 }}>
          <EvtxDetailContext {...full()} />
        </div>,
      );
      const icons = [...view.container.querySelectorAll<HTMLElement>("[role='img'][aria-label*='link to this event']")];
      expect(icons).toHaveLength(2);
      for (const icon of icons) {
        const ratio = contrastRatio(
          resolveToken(inherited(icon, "color") as string, theme),
          resolveToken(inherited(icon, "backgroundColor") as string, theme),
        );
        figures.push(`${theme.id} ${icon.getAttribute("aria-label")?.split(" ")[0]} ${ratio.toFixed(2)}`);
        expect(ratio, `${theme.id} ${icon.getAttribute("aria-label")}`).toBeGreaterThanOrEqual(3);
      }
      view.unmount();
    }
    console.info(`Details context, link icon contrast: ${figures.join(", ")}`);
  });

  it("marks the selected row by more than its color: a current marker, words and an inset bar", () => {
    const view = draw();
    const selected = view.container.querySelector("[aria-current='true']") as HTMLElement;
    expect(selected.style.boxShadow).toContain("inset");
    expect(selected).toHaveTextContent("this event");
  });
});

describe("what the section pulls into the Details chunk", () => {
  const importsOf = (source: string) => [...source.matchAll(/^import[^;]*?from "([^"]+)";/gms)].map((match) => match[1]);

  it("imports nothing from the plot or from the lazy Correlation view", () => {
    for (const source of [componentSource, chipSource, modelSource]) {
      const modules = importsOf(source);
      expect(modules.length).toBeGreaterThan(0);
      expect(modules.filter((module) => /EvtxCorrelationLanes|EvtxCorrelationView|EvtxCorrelationDock/.test(module))).toEqual([]);
    }
  });

  it("reads no store of record data and runs no query itself", () => {
    expect(importsOf(componentSource).filter((module) => /evtx-store$|lib\/commands|@tauri-apps/.test(module))).toEqual([]);
  });
});
