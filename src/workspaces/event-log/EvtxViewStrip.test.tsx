import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { readTextFile, writeTextFile } from "@tauri-apps/plugin-fs";
import { tokens } from "@fluentui/react-components";

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => undefined);
  }),
}));

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes, getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { deferred } from "../../test-utils/deferred";
import { viewImportSummary } from "./EvtxViewDialogs";
import { EvtxViewStrip, exportFileStem } from "./EvtxViewStrip";
import { pickRailTextColors } from "./evtx-rail-text";
import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { captureCriteria, sanitizeCriteria } from "./evtx-saved-filters";
import { cancelActiveLoad, useEvtxStore } from "./evtx-store";
import {
  buildViewExport,
  ENROLLMENT_TRIAGE_ID,
  EVTX_BUILT_IN_VIEWS,
  listViews,
  MAX_CUSTOM_VIEWS,
  MAX_VIEW_FILE_LENGTH,
  parseViewExport,
  type EvtxViewBody,
} from "./evtx-views";
import { EVTX_VIEWS_STORAGE_KEY, useEvtxViewStore } from "./evtx-views-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxRecord } from "./types";

const TRANSIENT = /timeRange|startMs|endMs|recordScope|scopeRecord/i;
const DMEDP = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin";
const AAD = "Microsoft-Windows-AAD/Operational";
const TRIAGE = EVTX_BUILT_IN_VIEWS[0];

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: 1_790_000_000_000,
  provider: "Example Provider",
  channel: "System",
  eventId: 42,
  level: "Information",
  computer: "CONTOSO-PC01",
  message: "m",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "fixture.evtx",
};

const channelInfo = (name: string) => ({ name, eventCount: 1, sourceType: "live" as const, enabledState: "enabled" as const });

const store = () => useEvtxStore.getState();
const card = (name: string) => screen.getByRole("button", { name });
const pressed = (name: string) => card(name).getAttribute("aria-pressed");

function reset() {
  cleanup();
  localStorage.clear();
  useEvtxViewStore.setState({ views: [] });
  useEvtxLayoutStore.setState(sanitizeLayout(undefined));
  useUiStore.setState({ logListFontSize: 13 });
  useEvtxStore.getState().reset();
}

/** A custom view whose criteria are the current ones, made through the library. */
function makeView(name: string, patch: Partial<EvtxViewBody> = {}) {
  const criteria = patch.criteria ?? captureCriteria(store());
  const result = useEvtxViewStore.getState().create(name, criteria, patch.layout ?? null);
  if (!result.ok) throw new Error(result.reason);
  return result.view;
}

const SELECTION_FILES = () => {
  useEvtxStore.setState({
    sourceMode: "files",
    channels: [channelInfo("System"), channelInfo("Application"), channelInfo(AAD), channelInfo(DMEDP)],
    records: [RECORD],
    selectedChannels: new Set(["System", "Application", AAD, DMEDP]),
  });
};

describe("EvtxViewStrip", () => {
  beforeEach(reset);
  afterEach(cleanup);

  describe("anatomy (spec 8.15, 5.1, 7.1)", () => {
    it("is a labelled toolbar with the built-in first and the dashed New view button last", () => {
      render(<EvtxViewStrip />);
      const toolbar = screen.getByRole("toolbar", { name: "Views" });
      expect(toolbar.closest("[data-evtx-region='view-strip']")).not.toBeNull();
      expect(within(toolbar).getAllByRole("button").map((b) => b.textContent)).toEqual([
        "Enrollment triageBuilt-in, 3 filters",
        "New view",
      ]);
      expect(card("New view").tagName).toBe("BUTTON");
      expect(card("New view")).toHaveAttribute("type", "button");
    });

    it("lists custom views after the built-in in the order they were made", () => {
      makeView("Second made first");
      makeView("Made next", { layout: { activeView: "table", panels: { channels: true, insights: true, dock: false } } });
      render(<EvtxViewStrip />);
      const toolbar = screen.getByRole("toolbar", { name: "Views" });
      expect(within(toolbar).getAllByRole("button").map((b) => b.getAttribute("aria-label") ?? b.textContent)).toEqual([
        "Enrollment triage",
        "Second made first",
        "Made next",
        "New view",
      ]);
      expect(screen.getByText("Filters and layout")).toBeInTheDocument();
      expect(screen.getByText("Filters")).toBeInTheDocument();
    });

    it("shows the eyebrow in the 7.1 treatment, hidden from assistive technology", () => {
      render(<EvtxViewStrip />);
      const eyebrow = screen.getByText("Views", { selector: "span" });
      expect(eyebrow).toHaveAttribute("aria-hidden", "true");
      expect(eyebrow.style.textTransform).toBe("uppercase");
      expect(eyebrow.style.fontWeight).toBe("600");
      expect(eyebrow.style.letterSpacing).toBe("0.08em");
    });

    it("has the strip padding of 5.1 and card text at f - 2 on one line", () => {
      render(<EvtxViewStrip />);
      const strip = document.querySelector<HTMLElement>("[data-evtx-region='view-strip']")!;
      expect(strip).toHaveStyle({ padding: "6px 12px 0px", columnGap: "6px", fontSize: "11px" });
      const triage = card("Enrollment triage");
      const [name, subtitle] = Array.from(triage.querySelectorAll("span"));
      expect(name).toHaveStyle({ fontWeight: "600" });
      expect(name.textContent).toBe("Enrollment triage");
      expect(subtitle.textContent).toBe("Built-in, 3 filters");
      const style = getComputedStyle(triage);
      expect(style.padding).toBe("4px 10px");
      expect(style.display).toBe("inline-flex");
      expect(style.whiteSpace).toBe("nowrap");
    });

    it("makes every item the same height: the New view icon takes the line height, not its own 16 px (T4)", () => {
      makeView("Mine");
      const { unmount } = render(<EvtxViewStrip />);
      const strip = document.querySelector<HTMLElement>("[data-evtx-region='view-strip']")!;
      const icon = () => document.querySelector<SVGElement>("[data-evtx-new-view-icon]")!;
      // A card is 4 + 4 padding, 2 border and one line; the button is the same with the icon as its line.
      expect(strip.style.lineHeight).toBe("14px");
      expect(icon().style.width).toBe("14px");
      expect(icon().style.height).toBe("14px");
      expect(icon()).toHaveAttribute("aria-hidden", "true");
      const cardHeight = (button: HTMLElement) => {
        const style = getComputedStyle(button);
        const content = button === card("New view") ? parseFloat(icon().style.height) : parseFloat(strip.style.lineHeight);
        return parseFloat(style.paddingTop) + parseFloat(style.paddingBottom) + 2 * parseFloat(style.borderTopWidth) + content;
      };
      expect(cardHeight(card("New view"))).toBe(24);
      expect(cardHeight(card("Mine"))).toBe(24);
      expect(cardHeight(card("Enrollment triage"))).toBe(24);
      unmount();

      // It follows the font size: the icon is the line, whatever the line is.
      useUiStore.setState({ logListFontSize: 20 });
      render(<EvtxViewStrip />);
      const bigLine = document.querySelector<HTMLElement>("[data-evtx-region='view-strip']")!.style.lineHeight;
      expect(bigLine).toBe("23px");
      expect(icon().style.width).toBe(bigLine);
      expect(icon().style.height).toBe(bigLine);
    });

    it("sizes its text from the log list font size", () => {
      useUiStore.setState({ logListFontSize: 20 });
      render(<EvtxViewStrip />);
      const strip = document.querySelector<HTMLElement>("[data-evtx-region='view-strip']")!;
      expect(strip.style.fontSize).toBe("18px");
      expect(screen.getByText("Views", { selector: "span" }).style.fontSize).toBe("17px");
    });

    it("shows the source on the right, from the one rule, and none while no source is open", () => {
      const { rerender } = render(<EvtxViewStrip />);
      expect(document.querySelector("[data-evtx-view-source]")).toBeNull();
      SELECTION_FILES();
      rerender(<EvtxViewStrip />);
      const source = document.querySelector<HTMLElement>("[data-evtx-view-source]")!;
      expect(source.textContent).toBe("Source: CONTOSO-PC01 · files");
      expect(source).toHaveStyle({ marginLeft: "auto" });
      act(() => useEvtxStore.setState({ sourceMode: "live", remoteMachine: "SERVER01" }));
      expect(document.querySelector("[data-evtx-view-source]")!.textContent).toBe("Source: SERVER01 · live");
    });
  });

  describe("applying a view", () => {
    it("applies every criterion of the built-in and says so politely", () => {
      render(<EvtxViewStrip />);
      fireEvent.click(card("Enrollment triage"));
      const state = store();
      expect(state.timeWindow).toBe("all");
      expect([...state.selectedChannels]).toEqual([DMEDP, AAD, "System"]);
      expect(state.filterSearch).toBe(TRIAGE.criteria.onLoad.search);
      expect(state.quickFilter.query).toBe("");
      expect(state.groupBy).toEqual([]);
      expect(screen.getByRole("status")).toHaveTextContent(/^Applied Enrollment triage\./);
    });

    it("applies a custom view's criteria and, when it has one, its layout", () => {
      store().setFilterEventIds("41,6008");
      store().setTimeWindow("7d");
      store().setGroupBy(["provider"]);
      const view = makeView("Mine", { layout: { activeView: "grouped", panels: { channels: false, insights: false, dock: false } } });
      store().setFilterEventIds("");
      store().setTimeWindow("24h");
      store().setGroupBy([]);
      render(<EvtxViewStrip />);
      fireEvent.click(card(view.name));
      expect(store().filterEventIds).toBe("41,6008");
      expect(store().timeWindow).toBe("7d");
      expect(store().groupBy).toEqual(["provider"]);
      expect(useEvtxLayoutStore.getState().activeView).toBe("grouped");
      expect(useEvtxLayoutStore.getState().panels.insights).toBe(false);
    });

    it("clears a brushed time range and a record scope", () => {
      SELECTION_FILES();
      useEvtxStore.setState({ timeRange: { startMs: 1_700_000_000_000, endMs: 1_700_000_060_000 } });
      render(<EvtxViewStrip />);
      fireEvent.click(card("Enrollment triage"));
      expect(store().timeRange).toBeNull();
      expect(store().recordScope).toBeNull();
    });
  });

  describe("which card is active: derived from the criteria on screen", () => {
    it("marks the applied view, and only it", () => {
      const other = makeView("Other", { criteria: sanitizeCriteria({ beforeLoad: { levels: ["Error"], timeWindow: "1h" } }) });
      render(<EvtxViewStrip />);
      expect(pressed("Enrollment triage")).toBe("false");
      fireEvent.click(card("Enrollment triage"));
      expect(pressed("Enrollment triage")).toBe("true");
      expect(pressed(other.name)).toBe("false");
      fireEvent.click(card(other.name));
      expect(pressed(other.name)).toBe("true");
      expect(pressed("Enrollment triage")).toBe("false");
    });

    it("draws the active card in the selection colors, and no other card", () => {
      render(<EvtxViewStrip />);
      const { selection } = buildEvtxVisualTokens(getThemeById(useUiStore.getState().themeId));
      expect(card("Enrollment triage").style.backgroundColor).toBe("");
      fireEvent.click(card("Enrollment triage"));
      const active = card("Enrollment triage");
      expect(active.style.backgroundColor).toBe(selection.background);
      expect(active.style.color).toBe(selection.foreground);
      expect(active.style.borderColor).toBe(selection.border);
      // The subtitle reads in the selection foreground too, not the secondary text.
      expect(screen.getByText(/^Built-in, 3 filters/).style.color).toBe(selection.foreground);
      expect(card("New view").style.backgroundColor).toBe("");
    });

    it("stops being active when any criterion is edited", () => {
      SELECTION_FILES();
      render(<EvtxViewStrip />);
      const edits: Array<[string, () => void]> = [
        ["a level", () => store().toggleFilterLevel("Verbose")],
        ["the Event IDs", () => store().setFilterEventIds("1")],
        ["the time window", () => store().setTimeWindow("7d")],
        ["a channel", () => store().toggleChannel("Application")],
        ["the search", () => store().setFilterSearch("id:1")],
        ["the quick filter query", () => store().setQuickFilter({ ...DEFAULT_QUICK_FILTER, query: "boot" })],
        ["the quick filter action", () => store().setQuickFilter({ ...DEFAULT_QUICK_FILTER, action: "hide" })],
        ["the grouping", () => store().setGroupBy(["level"])],
      ];
      for (const [label, edit] of edits) {
        fireEvent.click(card("Enrollment triage"));
        expect(pressed("Enrollment triage"), `before ${label}`).toBe("true");
        act(edit);
        expect(pressed("Enrollment triage"), `after ${label}`).toBe("false");
      }
    });

    it("reads the text as typed: a search that is not applied still counts as the view's", () => {
      const unparsed = sanitizeCriteria({ onLoad: { search: "provider:", quickFilter: DEFAULT_QUICK_FILTER } });
      makeView("Draft search", { criteria: unparsed });
      render(<EvtxViewStrip />);
      fireEvent.click(card("Draft search"));
      expect(store().filterSearch).toBe("");
      expect(store().filterSearchDraft).toBe("provider:");
      expect(pressed("Draft search")).toBe("true");
    });

    it("is not turned off by a layout change, a brushed range, a record scope or a column change", () => {
      SELECTION_FILES();
      render(<EvtxViewStrip />);
      fireEvent.click(card("Enrollment triage"));
      act(() => {
        useEvtxLayoutStore.getState().setActiveView("timeline");
        useEvtxLayoutStore.getState().setPanel("insights", false);
        useEvtxStore.setState({ timeRange: { startMs: 1, endMs: 2 }, sortField: "eventId" });
      });
      expect(pressed("Enrollment triage")).toBe("true");
    });

    it("marks every view whose criteria are the current ones", () => {
      makeView("Twin A");
      makeView("Twin B");
      render(<EvtxViewStrip />);
      expect(pressed("Twin A")).toBe("true");
      expect(pressed("Twin B")).toBe("true");
    });

    it("lets a view with no saved channels match whatever is selected", () => {
      const criteria = captureCriteria(store());
      delete criteria.beforeLoad.selectedChannels;
      makeView("Any channels", { criteria });
      store().setBeforeLoadCriteria({ ...captureCriteria(store()).beforeLoad, selectedChannels: ["Whatever"] });
      render(<EvtxViewStrip />);
      expect(pressed("Any channels")).toBe("true");
    });
  });

  describe("a Stop that restores the criteria leaves the card inactive", () => {
    const query = (args: unknown) => args as { requestId?: string; channels: string[] };
    it("drops the applied view's card when the load is stopped and the queued window is put back", async () => {
      const stopped = deferred<void>();
      vi.mocked(invoke).mockReset();
      vi.mocked(invoke).mockImplementation(async (name: string, args?: unknown) => {
        if (name === "evtx_cancel_channel_query") {
          stopped.resolve();
          return undefined;
        }
        if (name !== "evtx_query_channels") return undefined;
        const { requestId, channels } = query(args);
        const channel = channels[0];
        listeners.get("evtx-record-batch")?.({ payload: { requestId, channel, sequence: 0, records: [{ ...RECORD, id: 1, channel }] } });
        listeners.get("evtx-record-stream-complete")?.({ payload: { requestId, channel, sequenceCount: 1, totalRecords: 1 } });
        await stopped.promise;
        return {
          records: [],
          channels: [channelInfo(channel)],
          totalRecords: 1,
          parseErrors: 0,
          errorMessages: [],
          coverageGaps: [{ source: channel, kind: "cancelled", reason: "operator stopped the load after 1 events were fetched" }],
        };
      });
      useEvtxStore.setState({
        sourceMode: "live",
        channels: [channelInfo("Application")],
        loadedChannels: new Set(["Application"]),
        selectedChannels: new Set(["Application"]),
        timeWindow: "24h",
        isLoading: false,
      });
      // The two differ in the time window alone, which is what a Stop puts back.
      const errorsAt = (timeWindow: "24h" | "7d") =>
        sanitizeCriteria({
          beforeLoad: { levels: ["Error"], timeWindow, selectedChannels: ["Application"] },
          onLoad: { search: "id:1", quickFilter: DEFAULT_QUICK_FILTER },
        });
      const first = makeView("Errors a day", { criteria: errorsAt("24h") });
      const second = makeView("Errors a week", { criteria: errorsAt("7d") });
      render(<EvtxViewStrip />);

      // The first view changes what the service is asked for, so a refetch starts; the second
      // arrives during it and is queued, and is shown as applied.
      fireEvent.click(card(first.name));
      await waitFor(() => expect(vi.mocked(invoke).mock.calls.filter(([n]) => n === "evtx_query_channels")).toHaveLength(1));
      fireEvent.click(card(second.name));
      expect(store().timeWindow).toBe("7d");
      expect(pressed(second.name)).toBe("true");

      void cancelActiveLoad();
      await waitFor(() => expect(store().isLoading).toBe(false));
      await act(async () => {
        for (let turn = 0; turn < 20; turn += 1) await Promise.resolve();
      });

      // Stop means stop: no replay, and the window is put back to what the cut read used. The week
      // is no longer what is on screen, so its card is not active; the day, which is, is.
      expect(vi.mocked(invoke).mock.calls.filter(([n]) => n === "evtx_query_channels")).toHaveLength(1);
      expect(store().timeWindow).toBe("24h");
      expect(pressed(second.name)).toBe("false");
      expect(pressed(first.name)).toBe("true");
    });
  });

  describe("what a view cannot show is said, not left as an empty grid", () => {
    it("says how many channels of the active view are not loaded, live", () => {
      useEvtxStore.setState({
        sourceMode: "live",
        channels: [channelInfo("System"), channelInfo(AAD), channelInfo(DMEDP)],
        loadedChannels: new Set(["System"]),
      });
      render(<EvtxViewStrip />);
      fireEvent.click(card("Enrollment triage"));
      expect(screen.getByText("Built-in, 3 filters · 2 channels not loaded")).toBeInTheDocument();
      expect(screen.getByRole("status")).toHaveTextContent("Applied Enrollment triage. 2 of its channels are not loaded.");
    });

    it("says how many are not in the files, and says it in the singular for one", () => {
      useEvtxStore.setState({
        sourceMode: "files",
        channels: [channelInfo("System"), channelInfo(AAD)],
        records: [RECORD],
      });
      render(<EvtxViewStrip />);
      fireEvent.click(card("Enrollment triage"));
      expect(screen.getByText("Built-in, 3 filters · 1 channel not in these files")).toBeInTheDocument();
      expect(screen.getByRole("status")).toHaveTextContent("Applied Enrollment triage. 1 of its channels is not in these files.");
    });

    it("says nothing when every channel is there, and nothing on a card that is not active", () => {
      SELECTION_FILES();
      render(<EvtxViewStrip />);
      expect(screen.getByText("Built-in, 3 filters")).toBeInTheDocument();
      fireEvent.click(card("Enrollment triage"));
      expect(screen.getByText("Built-in, 3 filters")).toBeInTheDocument();
      expect(screen.queryByText(/not loaded|not in these files/)).toBeNull();
    });
  });

  describe("the strip makes no claim that the built-in's events are related (acceptance B, at run time)", () => {
    // The same words the view's own test scans for, over what the strip renders.
    const RELATIONAL =
      /\b(relat\w*|caus\w*|because|lead\w*|led|precede\w*|follow\w*|then|after|before|chain\w*|link\w*|correlat\w*|due to|root cause|result\w*|trigger\w*|impl(y|ies|ied)|together)\b/i;

    it("holds for the card, its tooltip and label, the suffixes, the announcement and the menu, in each state", async () => {
      const seen: string[] = [];
      const collect = () => {
        const triage = card("Enrollment triage");
        seen.push(
          triage.textContent ?? "",
          triage.getAttribute("title") ?? "",
          triage.getAttribute("aria-label") ?? "",
          document.getElementById(triage.getAttribute("aria-describedby") ?? "")?.textContent ?? "",
          screen.getByRole("status").textContent ?? "",
        );
      };
      // Files with two of the three channels: the singular suffix and announcement.
      useEvtxStore.setState({ sourceMode: "files", channels: [channelInfo("System"), channelInfo(AAD)], records: [RECORD] });
      const { unmount } = render(<EvtxViewStrip />);
      collect();
      fireEvent.click(card("Enrollment triage"));
      collect();
      fireEvent.contextMenu(card("Enrollment triage"));
      seen.push(...within(await screen.findByRole("menu")).getAllByRole("menuitem").map((i) => i.textContent ?? ""));
      unmount();
      // Live with one channel loaded: the plural.
      useEvtxStore.setState({ sourceMode: "live", channels: [channelInfo("System"), channelInfo(AAD), channelInfo(DMEDP)], loadedChannels: new Set(["System"]) });
      render(<EvtxViewStrip />);
      fireEvent.click(card("Enrollment triage"));
      collect();

      expect(seen.join(" | ")).toContain("channels are not loaded");
      expect(seen.join(" | ")).toContain("channels is not in these files");
      for (const text of seen) expect(text).not.toMatch(RELATIONAL);
    });
  });

  describe("keyboard (a roving tab stop, arrows, Home and End)", () => {
    beforeEach(() => {
      makeView("Mine");
      store().setFilterEventIds("1");
    });

    const items = () => within(screen.getByRole("toolbar", { name: "Views" })).getAllByRole("button");

    it("puts one item in the tab sequence: the first, or the active card", () => {
      render(<EvtxViewStrip />);
      expect(items().map((b) => b.tabIndex)).toEqual([0, -1, -1]);
      fireEvent.click(card("Enrollment triage"));
      expect(items().filter((b) => b.tabIndex === 0)).toHaveLength(1);
    });

    it("moves focus with the arrows, wrapping, without applying anything", () => {
      render(<EvtxViewStrip />);
      const [triage, mine, create] = items();
      triage.focus();
      fireEvent.keyDown(triage, { key: "ArrowRight" });
      expect(mine).toHaveFocus();
      expect(mine.tabIndex).toBe(0);
      expect(triage.tabIndex).toBe(-1);
      fireEvent.keyDown(mine, { key: "ArrowRight" });
      expect(create).toHaveFocus();
      fireEvent.keyDown(create, { key: "ArrowRight" });
      expect(triage).toHaveFocus();
      fireEvent.keyDown(triage, { key: "ArrowLeft" });
      expect(create).toHaveFocus();
      fireEvent.keyDown(create, { key: "Home" });
      expect(triage).toHaveFocus();
      fireEvent.keyDown(triage, { key: "End" });
      expect(create).toHaveFocus();
      // Moving is not applying: no card is active and the Event IDs are as they were.
      expect(store().filterEventIds).toBe("1");
      expect(pressed("Enrollment triage")).toBe("false");
    });

    it("leaves other keys alone", () => {
      render(<EvtxViewStrip />);
      const [triage] = items();
      triage.focus();
      const notPrevented = fireEvent.keyDown(triage, { key: "a" });
      expect(notPrevented).toBe(true);
      expect(triage).toHaveFocus();
    });
  });

  describe("the New view dialog", () => {
    const openDialog = () => {
      render(<EvtxViewStrip />);
      fireEvent.click(card("New view"));
      return screen.getByRole("dialog", { name: "New view" });
    };

    it("opens a modal dialog with a required name and Include current layout checked", async () => {
      const dialog = openDialog();
      expect(dialog).toHaveAttribute("aria-modal", "true");
      await waitFor(() => expect(within(dialog).getByRole("textbox", { name: /Name/ })).toHaveFocus());
      expect(within(dialog).getByRole("checkbox", { name: "Include current layout" })).toBeChecked();
      expect(within(dialog).getByRole("button", { name: "Save" })).toBeInTheDocument();
      expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeInTheDocument();
    });

    it("saves the filters and the layout that are applied now", async () => {
      store().setFilterEventIds("41");
      store().setTimeWindow("7d");
      useEvtxLayoutStore.getState().setActiveView("grouped");
      const dialog = openDialog();
      fireEvent.change(within(dialog).getByRole("textbox", { name: /Name/ }), { target: { value: "  My view " } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      const [saved] = useEvtxViewStore.getState().views;
      expect(saved.name).toBe("My view");
      expect(saved.criteria.beforeLoad).toMatchObject({ eventIds: "41", timeWindow: "7d" });
      expect(saved.layout?.activeView).toBe("grouped");
      // It is what is applied, so it is the active card, and the dialog said so.
      expect(pressed("My view")).toBe("true");
      expect(screen.getByRole("status")).toHaveTextContent("Saved view My view.");
    });

    it("saves filters only when Include current layout is cleared", () => {
      const dialog = openDialog();
      fireEvent.change(within(dialog).getByRole("textbox", { name: /Name/ }), { target: { value: "Filters only" } });
      fireEvent.click(within(dialog).getByRole("checkbox", { name: "Include current layout" }));
      fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
      expect(useEvtxViewStore.getState().views[0].layout).toBeNull();
    });

    it("submits on Enter", () => {
      const dialog = openDialog();
      const name = within(dialog).getByRole("textbox", { name: /Name/ });
      fireEvent.change(name, { target: { value: "By enter" } });
      fireEvent.keyDown(name, { key: "Enter" });
      expect(useEvtxViewStore.getState().views.map((v) => v.name)).toEqual(["By enter"]);
    });

    it("refuses an empty name, a name that is taken, and a full library, and says why", async () => {
      const dialog = openDialog();
      const name = within(dialog).getByRole("textbox", { name: /Name/ });
      fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
      expect(within(dialog).getByRole("alert")).toHaveTextContent("Enter a name.");
      expect(name).toHaveAttribute("aria-invalid", "true");
      fireEvent.change(name, { target: { value: "enrollment TRIAGE" } });
      expect(within(dialog).queryByRole("alert")).toBeNull();
      fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
      expect(within(dialog).getByRole("alert")).toHaveTextContent("A view with that name already exists.");
      expect(useEvtxViewStore.getState().views).toEqual([]);
      for (let i = 0; i < MAX_CUSTOM_VIEWS; i += 1) {
        useEvtxViewStore.getState().create(`V${i}`, captureCriteria(store()), null);
      }
      fireEvent.change(name, { target: { value: "One more" } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
      expect(within(dialog).getByRole("alert")).toHaveTextContent(`The library holds ${MAX_CUSTOM_VIEWS} views.`);
    });

    it("limits the name's length in the field", () => {
      const dialog = openDialog();
      expect(within(dialog).getByRole("textbox", { name: /Name/ })).toHaveAttribute("maxlength", "60");
    });

    it("cancels on the Cancel button and on Escape, and gives focus back to New view", async () => {
      const dialog = openDialog();
      fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      await waitFor(() => expect(card("New view")).toHaveFocus());

      fireEvent.click(card("New view"));
      const again = screen.getByRole("dialog", { name: "New view" });
      fireEvent.keyDown(within(again).getByRole("textbox", { name: /Name/ }), { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      await waitFor(() => expect(card("New view")).toHaveFocus());
      expect(useEvtxViewStore.getState().views).toEqual([]);
    });

    it("starts blank each time it opens", async () => {
      let dialog = openDialog();
      fireEvent.change(within(dialog).getByRole("textbox", { name: /Name/ }), { target: { value: "Leftover" } });
      fireEvent.click(within(dialog).getByRole("checkbox", { name: "Include current layout" }));
      fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      fireEvent.click(card("New view"));
      dialog = screen.getByRole("dialog", { name: "New view" });
      expect(within(dialog).getByRole("textbox", { name: /Name/ })).toHaveValue("");
      expect(within(dialog).getByRole("checkbox", { name: "Include current layout" })).toBeChecked();
    });

    it("never stores a brushed range or a record scope in the view it saves", () => {
      SELECTION_FILES();
      useEvtxStore.setState({
        timeRange: { startMs: 1_700_000_000_000, endMs: 1_700_000_060_000 },
        recordScope: {
          kind: "finding",
          title: "A finding",
          records: new Set(),
          counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
        },
      });
      expect(store().timeRange).not.toBeNull();
      const dialog = openDialog();
      fireEvent.change(within(dialog).getByRole("textbox", { name: /Name/ }), { target: { value: "Made with a brush" } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
      expect(useEvtxViewStore.getState().views).toHaveLength(1);
      expect(JSON.stringify(useEvtxViewStore.getState().views)).not.toMatch(TRANSIENT);
      expect(localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)).not.toMatch(TRANSIENT);
      // And the brush is still there: saving a view takes nothing from the session.
      expect(store().timeRange).not.toBeNull();
    });
  });
});

describe("EvtxViewStrip context menu", () => {
  beforeEach(reset);
  afterEach(cleanup);

  const openMenu = async (name: string) => {
    fireEvent.contextMenu(card(name));
    return screen.findByRole("menu");
  };
  const choose = async (name: string, item: string | RegExp) => {
    const menu = await openMenu(name);
    fireEvent.click(within(menu).getByRole("menuitem", { name: item }));
  };
  const itemNames = (menu: HTMLElement) => within(menu).getAllByRole("menuitem").map((i) => i.textContent);

  describe("what it offers", () => {
    it("offers the five actions on a custom view, in the spec's order", async () => {
      makeView("Mine");
      render(<EvtxViewStrip />);
      expect(itemNames(await openMenu("Mine"))).toEqual([
        "Rename...",
        "Update from current",
        "Duplicate",
        "Delete...",
        "Export...",
      ]);
    });

    it("offers only Duplicate and Export on a built-in, which is read-only", async () => {
      render(<EvtxViewStrip />);
      expect(itemNames(await openMenu("Enrollment triage"))).toEqual(["Duplicate", "Export..."]);
    });

    it("opens from the keyboard: the menu key and Shift+F10, and no other key", async () => {
      makeView("Mine");
      render(<EvtxViewStrip />);
      fireEvent.keyDown(card("Mine"), { key: "a" });
      expect(screen.queryByRole("menu")).toBeNull();
      fireEvent.keyDown(card("Mine"), { key: "F10" });
      expect(screen.queryByRole("menu")).toBeNull();
      fireEvent.keyDown(card("Mine"), { key: "ContextMenu" });
      expect(await screen.findByRole("menu")).toBeInTheDocument();
      fireEvent.keyDown(card("Mine"), { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
      fireEvent.keyDown(card("Mine"), { key: "F10", shiftKey: true });
      expect(await screen.findByRole("menu")).toBeInTheDocument();
    });

    // The arrow keys between items are Fluent's (tabster), which jsdom does not run: that part is
    // for the browser, and is asserted in the event-logs views capture test.
    it("moves focus to the first item when it opens, from the keyboard or the mouse", async () => {
      makeView("Mine");
      render(<EvtxViewStrip />);
      const items = () => within(screen.getByRole("menu")).getAllByRole("menuitem");

      card("Mine").focus();
      fireEvent.keyDown(card("Mine"), { key: "ContextMenu" });
      await screen.findByRole("menu");
      await waitFor(() => expect(items()[0]).toHaveFocus());
      // Escape inside the menu closes it, and the card has the focus again.
      fireEvent.keyDown(items()[0], { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
      await waitFor(() => expect(card("Mine")).toHaveFocus());

      fireEvent.contextMenu(card("Mine"));
      await screen.findByRole("menu");
      await waitFor(() => expect(items()[0]).toHaveFocus());
    });

    it("runs the item that has the focus, with Enter", async () => {
      makeView("Mine");
      render(<EvtxViewStrip />);
      card("Mine").focus();
      fireEvent.keyDown(card("Mine"), { key: "F10", shiftKey: true });
      const menu = await screen.findByRole("menu");
      const rename = within(menu).getByRole("menuitem", { name: "Rename..." });
      await waitFor(() => expect(rename).toHaveFocus());
      fireEvent.keyDown(rename, { key: "Enter" });
      expect(await screen.findByRole("dialog", { name: "Rename view" })).toBeInTheDocument();
    });

    it("does not apply the view when it opens, and a card says it has a menu", async () => {
      makeView("Mine");
      store().setFilterEventIds("1");
      render(<EvtxViewStrip />);
      expect(card("Mine")).toHaveAttribute("aria-haspopup", "menu");
      await openMenu("Mine");
      expect(store().filterEventIds).toBe("1");
    });

    it("uses the Escape key to close, so the workspace does not also clear a brushed range with it", async () => {
      makeView("Mine");
      render(<EvtxViewStrip />);
      // Escape on a card with no menu open is not used here, so it reaches the workspace's listener.
      expect(fireEvent.keyDown(card("Mine"), { key: "Escape" })).toBe(true);
      await openMenu("Mine");
      card("Mine").focus();
      // The key is used (default prevented), so a window listener that honours that steps aside.
      expect(fireEvent.keyDown(card("Mine"), { key: "Escape" })).toBe(false);
      await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
    });
  });

  describe("Rename", () => {
    it("renames from a dialog that starts with the current name, and gives focus back to the card", async () => {
      makeView("Old name");
      render(<EvtxViewStrip />);
      await choose("Old name", "Rename...");
      const dialog = await screen.findByRole("dialog", { name: "Rename view" });
      const name = within(dialog).getByRole("textbox", { name: /Name/ });
      expect(name).toHaveValue("Old name");
      expect(within(dialog).queryByRole("checkbox")).toBeNull();
      fireEvent.change(name, { target: { value: "New name" } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Rename" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(useEvtxViewStore.getState().views[0].name).toBe("New name");
      expect(screen.getByRole("status")).toHaveTextContent("Renamed to New name.");
      await waitFor(() => expect(card("New name")).toHaveFocus());
    });

    it("refuses a name another view or a built-in has, or an empty one, and keeps the dialog open", async () => {
      makeView("A");
      makeView("B");
      render(<EvtxViewStrip />);
      await choose("A", "Rename...");
      const dialog = await screen.findByRole("dialog", { name: "Rename view" });
      const name = within(dialog).getByRole("textbox", { name: /Name/ });
      fireEvent.change(name, { target: { value: "b" } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Rename" }));
      expect(within(dialog).getByRole("alert")).toHaveTextContent("A view with that name already exists.");
      fireEvent.change(name, { target: { value: "Enrollment Triage" } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Rename" }));
      expect(within(dialog).getByRole("alert")).toHaveTextContent("already exists");
      fireEvent.change(name, { target: { value: "" } });
      fireEvent.click(within(dialog).getByRole("button", { name: "Rename" }));
      expect(within(dialog).getByRole("alert")).toHaveTextContent("Enter a name.");
      expect(useEvtxViewStore.getState().views.map((v) => v.name)).toEqual(["A", "B"]);
    });

    it("cancels with Escape and gives focus back", async () => {
      makeView("Keep");
      render(<EvtxViewStrip />);
      await choose("Keep", "Rename...");
      const dialog = await screen.findByRole("dialog", { name: "Rename view" });
      fireEvent.keyDown(within(dialog).getByRole("textbox", { name: /Name/ }), { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(useEvtxViewStore.getState().views[0].name).toBe("Keep");
      await waitFor(() => expect(card("Keep")).toHaveFocus());
    });
  });

  describe("Update from current", () => {
    it("replaces the criteria with the ones on screen, and the layout of a view that has one", async () => {
      makeView("Mine", { layout: { activeView: "table", panels: { channels: true, insights: true, dock: false } } });
      store().setFilterEventIds("41");
      store().setTimeWindow("7d");
      useEvtxLayoutStore.getState().setActiveView("grouped");
      render(<EvtxViewStrip />);
      expect(pressed("Mine")).toBe("false");
      await choose("Mine", "Update from current");
      const [view] = useEvtxViewStore.getState().views;
      expect(view.criteria.beforeLoad).toMatchObject({ eventIds: "41", timeWindow: "7d" });
      expect(view.layout?.activeView).toBe("grouped");
      expect(view.name).toBe("Mine");
      expect(pressed("Mine")).toBe("true");
      expect(screen.getByRole("status")).toHaveTextContent("Updated Mine from the current filters.");
    });

    it("keeps a view saved without a layout without one", async () => {
      makeView("Filters only");
      store().setFilterEventIds("41");
      useEvtxLayoutStore.getState().setActiveView("charts");
      render(<EvtxViewStrip />);
      await choose("Filters only", "Update from current");
      expect(useEvtxViewStore.getState().views[0].layout).toBeNull();
      expect(useEvtxViewStore.getState().views[0].criteria.beforeLoad.eventIds).toBe("41");
    });

    it("never stores a brushed range or a record scope", async () => {
      makeView("Mine");
      SELECTION_FILES();
      useEvtxStore.setState({ timeRange: { startMs: 1_700_000_000_000, endMs: 1_700_000_060_000 } });
      render(<EvtxViewStrip />);
      await choose("Mine", "Update from current");
      expect(store().timeRange).not.toBeNull();
      expect(JSON.stringify(useEvtxViewStore.getState().views)).not.toMatch(TRANSIENT);
      expect(localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)).not.toMatch(TRANSIENT);
    });

    it("says so when the filters on screen cannot be saved, and changes nothing", async () => {
      makeView("Mine");
      const before = JSON.stringify(useEvtxViewStore.getState().views);
      useEvtxStore.setState({ filterEventIds: "4624,abc" });
      render(<EvtxViewStrip />);
      await choose("Mine", "Update from current");
      expect(screen.getByRole("alert")).toHaveTextContent("Mine was not updated.");
      expect(JSON.stringify(useEvtxViewStore.getState().views)).toBe(before);
    });
  });

  describe("Duplicate", () => {
    it("copies a custom view under a new name and puts focus on the copy", async () => {
      makeView("Mine", { layout: { activeView: "grouped", panels: { channels: true, insights: false, dock: false } } });
      render(<EvtxViewStrip />);
      await choose("Mine", "Duplicate");
      const views = useEvtxViewStore.getState().views;
      expect(views.map((v) => v.name)).toEqual(["Mine", "Mine copy"]);
      expect(views[1].criteria).toEqual(views[0].criteria);
      expect(views[1].layout).toEqual(views[0].layout);
      expect(views[1].id).not.toBe(views[0].id);
      expect(screen.getByRole("status")).toHaveTextContent("Duplicated Mine as Mine copy.");
      await waitFor(() => expect(card("Mine copy")).toHaveFocus());
    });

    it("turns a built-in into a view that can be edited", async () => {
      render(<EvtxViewStrip />);
      await choose("Enrollment triage", "Duplicate");
      expect(useEvtxViewStore.getState().views.map((v) => v.name)).toEqual(["Enrollment triage copy"]);
      const menu = await openMenu("Enrollment triage copy");
      expect(itemNames(menu)).toContain("Rename...");
      expect(card("Enrollment triage copy")).toHaveAttribute("data-evtx-view-card", "custom");
    });

    it("says so when the library is full", async () => {
      for (let i = 0; i < MAX_CUSTOM_VIEWS; i += 1) makeView(`V${i}`);
      render(<EvtxViewStrip />);
      await choose("V0", "Duplicate");
      expect(screen.getByRole("alert")).toHaveTextContent("V0 was not duplicated. The library holds");
      expect(useEvtxViewStore.getState().views).toHaveLength(MAX_CUSTOM_VIEWS);
    });
  });

  describe("Delete", () => {
    it("asks first, with Cancel focused, and deletes nothing on Cancel", async () => {
      makeView("Mine");
      render(<EvtxViewStrip />);
      await choose("Mine", "Delete...");
      const dialog = await screen.findByRole("dialog", { name: "Delete view" });
      expect(dialog).toHaveTextContent('Delete the view "Mine"?');
      await waitFor(() => expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus());
      fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(useEvtxViewStore.getState().views).toHaveLength(1);
      await waitFor(() => expect(card("Mine")).toHaveFocus());
    });

    it("deletes on confirmation, announces it, and moves focus to the next card", async () => {
      makeView("First");
      makeView("Second");
      render(<EvtxViewStrip />);
      await choose("First", "Delete...");
      const dialog = await screen.findByRole("dialog", { name: "Delete view" });
      fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(useEvtxViewStore.getState().views.map((v) => v.name)).toEqual(["Second"]);
      expect(screen.getByRole("status")).toHaveTextContent("Deleted First.");
      await waitFor(() => expect(card("Second")).toHaveFocus());
    });

    it("moves focus to New view when the last card goes: the next item, which always exists", async () => {
      makeView("Only");
      render(<EvtxViewStrip />);
      await choose("Only", "Delete...");
      fireEvent.click(within(await screen.findByRole("dialog", { name: "Delete view" })).getByRole("button", { name: "Delete" }));
      await waitFor(() => expect(card("New view")).toHaveFocus());
    });

    it("cancels on Escape", async () => {
      makeView("Mine");
      render(<EvtxViewStrip />);
      await choose("Mine", "Delete...");
      const dialog = await screen.findByRole("dialog", { name: "Delete view" });
      fireEvent.keyDown(within(dialog).getByRole("button", { name: "Cancel" }), { key: "Escape" });
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(useEvtxViewStore.getState().views).toHaveLength(1);
    });
  });

  describe("Export", () => {
    beforeEach(() => {
      vi.mocked(save).mockReset();
      vi.mocked(writeTextFile).mockReset();
    });

    it("writes the view as a schema 1 file that reads back as the view, without its id", async () => {
      const view = makeView("Mine", { layout: { activeView: "grouped", panels: { channels: true, insights: false, dock: false } } });
      vi.mocked(save).mockResolvedValue("C:\\out\\mine.json");
      vi.mocked(writeTextFile).mockResolvedValue(undefined);
      render(<EvtxViewStrip />);
      await choose("Mine", "Export...");
      await waitFor(() => expect(writeTextFile).toHaveBeenCalledTimes(1));
      expect(save).toHaveBeenCalledWith(expect.objectContaining({ defaultPath: "mine.json" }));
      const [path, text] = vi.mocked(writeTextFile).mock.calls[0] as [string, string];
      expect(path).toBe("C:\\out\\mine.json");
      expect(JSON.parse(text).schema).toBe(1);
      expect(text).not.toContain(view.id);
      expect(text).not.toMatch(/builtIn|lastUsed/);
      expect(parseViewExport(text)).toEqual({ ok: true, views: [{ name: view.name, criteria: view.criteria, layout: view.layout }], skipped: 0 });
      await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Exported Mine."));
    });

    it("exports a built-in as an ordinary view, named for it", async () => {
      vi.mocked(save).mockResolvedValue("/tmp/e.json");
      vi.mocked(writeTextFile).mockResolvedValue(undefined);
      render(<EvtxViewStrip />);
      await choose("Enrollment triage", "Export...");
      await waitFor(() => expect(writeTextFile).toHaveBeenCalled());
      expect(save).toHaveBeenCalledWith(expect.objectContaining({ defaultPath: "enrollment-triage.json" }));
      const parsed = parseViewExport(vi.mocked(writeTextFile).mock.calls[0][1] as string);
      expect(parsed.ok && parsed.views[0].criteria).toEqual(EVTX_BUILT_IN_VIEWS[0].criteria);
    });

    it("writes nothing when the save dialog is cancelled", async () => {
      makeView("Mine");
      vi.mocked(save).mockResolvedValue(null);
      render(<EvtxViewStrip />);
      await choose("Mine", "Export...");
      await waitFor(() => expect(save).toHaveBeenCalled());
      expect(writeTextFile).not.toHaveBeenCalled();
      expect(screen.queryByRole("alert")).toBeNull();
    });

    it("shows the failure in full, as an alert", async () => {
      makeView("Mine");
      vi.mocked(save).mockResolvedValue("/tmp/e.json");
      vi.mocked(writeTextFile).mockRejectedValue(new Error("Access is denied. (os error 5)"));
      render(<EvtxViewStrip />);
      await choose("Mine", "Export...");
      expect(await screen.findByRole("alert")).toHaveTextContent("Mine was not exported. Access is denied. (os error 5)");
    });

    it("does not start a second export while the first is choosing a file", async () => {
      makeView("Mine");
      const chosen = deferred<string | null>();
      vi.mocked(save).mockReturnValue(chosen.promise);
      vi.mocked(writeTextFile).mockResolvedValue(undefined);
      render(<EvtxViewStrip />);
      await choose("Mine", "Export...");
      await choose("Mine", "Export...");
      expect(save).toHaveBeenCalledTimes(1);
      chosen.resolve("/tmp/e.json");
      await waitFor(() => expect(writeTextFile).toHaveBeenCalledTimes(1));
    });

    it("never writes a brushed range or a record scope", async () => {
      makeView("Mine");
      SELECTION_FILES();
      useEvtxStore.setState({ timeRange: { startMs: 1_700_000_000_000, endMs: 1_700_000_060_000 } });
      vi.mocked(save).mockResolvedValue("/tmp/e.json");
      vi.mocked(writeTextFile).mockResolvedValue(undefined);
      render(<EvtxViewStrip />);
      await choose("Mine", "Export...");
      await waitFor(() => expect(writeTextFile).toHaveBeenCalled());
      expect(vi.mocked(writeTextFile).mock.calls[0][1] as string).not.toMatch(TRANSIENT);
    });
  });

  describe("the default file name", () => {
    it.each([
      ["Enrollment triage", "enrollment-triage"],
      ["  Spaced   out  ", "spaced-out"],
      ["../../etc/passwd", "etcpasswd"],
      ["a\\b/c:d*e?f", "abcdef"],
      ["", "view"],
      ["...", "view"],
      ["x".repeat(100), "x".repeat(40)],
    ])("turns %j into %j", (name, stem) => {
      expect(exportFileStem(name)).toBe(stem);
    });
  });
});

describe("EvtxViewStrip Import views...", () => {
  beforeEach(() => {
    reset();
    vi.mocked(open).mockReset();
    vi.mocked(readTextFile).mockReset();
  });
  afterEach(cleanup);

  const bodyOf = (name: string, patch: Partial<EvtxViewBody> = {}): EvtxViewBody => ({
    name,
    criteria: sanitizeCriteria({ beforeLoad: { levels: ["Error"], eventIds: "41", timeWindow: "7d" } }),
    layout: null,
    ...patch,
  });
  const importNotice = () => document.querySelector("[data-evtx-import-notice]");
  const openNewDialog = () => {
    render(<EvtxViewStrip />);
    fireEvent.click(card("New view"));
    return screen.getByRole("dialog", { name: "New view" });
  };
  const importFile = async (text: string | Promise<string>) => {
    vi.mocked(open).mockResolvedValue("C:\\views\\shared.json");
    vi.mocked(readTextFile).mockReturnValue(Promise.resolve(text));
    const dialog = openNewDialog();
    fireEvent.click(within(dialog).getByRole("button", { name: "Import views..." }));
    return dialog;
  };

  it("is offered in the New view dialog, and not in the Rename dialog", async () => {
    makeView("Mine");
    const dialog = openNewDialog();
    expect(within(dialog).getByRole("button", { name: "Import views..." })).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    fireEvent.contextMenu(card("Mine"));
    fireEvent.click(await screen.findByRole("menuitem", { name: "Rename..." }));
    const rename = await screen.findByRole("dialog", { name: "Rename view" });
    expect(within(rename).queryByRole("button", { name: "Import views..." })).toBeNull();
  });

  it("imports the views in a file, says how many it added, replaced and skipped, and closes", async () => {
    const mine = makeView("Mine");
    const file = JSON.parse(buildViewExport([bodyOf("Mine", { layout: null }), bodyOf("Shared"), bodyOf("Enrollment triage")]));
    file.views.push({ name: "Broken", criteria: { beforeLoad: { levels: ["Nonsense"] } } });
    await importFile(JSON.stringify(file));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // For the eye, and (T6) through the persistent polite region for the ear: the notice is not a
    // second live region that mounts already holding its text.
    const summary = "Imported 2 views, 1 replaced, 1 skipped.";
    expect(importNotice()).toHaveTextContent(summary);
    expect(importNotice()).not.toHaveAttribute("role");
    expect(screen.getByRole("status")).toHaveTextContent(summary);
    expect(screen.getByRole("status")).toHaveAttribute("aria-live", "polite");
    const views = useEvtxViewStore.getState().views;
    expect(views.map((v) => v.name)).toEqual(["Mine", "Shared", "Enrollment triage (2)"]);
    expect(views[0].id).toBe(mine.id);
    expect(views[0].criteria.beforeLoad.eventIds).toBe("41");
    // The built-in is still the only built-in, and still its own.
    expect(listViews(views).filter((v) => v.builtIn)).toHaveLength(1);
    expect(views.some((v) => v.id === ENROLLMENT_TRIAGE_ID)).toBe(false);
    await waitFor(() => expect(card("New view")).toHaveFocus());
    // The next thing the operator does clears it.
    fireEvent.click(card("Shared"));
    expect(importNotice()).toBeNull();
  });

  it("announces the summary again when a second import says the same thing (a keyed node, not a text change)", async () => {
    const file = buildViewExport([bodyOf("Once")]);
    await importFile(file);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const first = within(screen.getByRole("status")).getByText("Imported 1 view.");
    useEvtxViewStore.getState().remove(useEvtxViewStore.getState().views[0].id);
    vi.mocked(open).mockResolvedValue("C:\\views\\again.json");
    vi.mocked(readTextFile).mockReturnValue(Promise.resolve(file));
    fireEvent.click(card("New view"));
    fireEvent.click(within(screen.getByRole("dialog", { name: "New view" })).getByRole("button", { name: "Import views..." }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const second = within(screen.getByRole("status")).getByText("Imported 1 view.");
    expect(second).not.toBe(first);
  });

  it("stays open and changes nothing when the picker is cancelled", async () => {
    vi.mocked(open).mockResolvedValue(null);
    const dialog = openNewDialog();
    fireEvent.click(within(dialog).getByRole("button", { name: "Import views..." }));
    await waitFor(() => expect(open).toHaveBeenCalled());
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Import views..." })).toBeEnabled());
    expect(readTextFile).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog", { name: "New view" })).toBeInTheDocument();
    expect(within(dialog).queryByRole("alert")).toBeNull();
    expect(useEvtxViewStore.getState().views).toEqual([]);
  });

  it.each<[string, string, RegExp]>([
    ["text that is not JSON", "{not json", /not JSON/],
    ["a file of another schema", JSON.stringify({ schema: 2, views: [] }), /schema 1/],
    ["a saved-filter file", JSON.stringify({ schema: 2, filters: [] }), /schema 1/],
    ["no schema", JSON.stringify({ views: [] }), /schema 1/],
    ["a list that is not a list", JSON.stringify({ schema: 1, views: {} }), /no list of views/],
    ["a file over the limit", "x".repeat(MAX_VIEW_FILE_LENGTH + 1), /larger than 1 MB/],
  ])("says why %s was not imported, and keeps the dialog open", async (_label, text, message) => {
    makeView("Existing");
    const before = JSON.stringify(useEvtxViewStore.getState().views);
    const dialog = await importFile(text);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(message);
    expect(screen.getByRole("dialog", { name: "New view" })).toBeInTheDocument();
    expect(JSON.stringify(useEvtxViewStore.getState().views)).toBe(before);
  });

  it("says so when the file cannot be read", async () => {
    vi.mocked(open).mockResolvedValue("C:\\views\\gone.json");
    vi.mocked(readTextFile).mockRejectedValue(new Error("The system cannot find the file specified. (os error 2)"));
    const dialog = openNewDialog();
    fireEvent.click(within(dialog).getByRole("button", { name: "Import views..." }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "That file could not be read. The system cannot find the file specified. (os error 2)",
    );
  });

  it("takes in nothing a hostile file asks for: no transient criteria, no built-in, no id", async () => {
    const hostile = {
      name: "Hostile",
      id: ENROLLMENT_TRIAGE_ID,
      builtIn: true,
      timeRange: { startMs: 1, endMs: 2 },
      criteria: { ...bodyOf("x").criteria, recordScope: { kind: "finding" }, scopeRecordIds: [1] },
      layout: { activeView: "table", panels: { channels: true, insights: true, dock: true }, timeRange: 1 },
    };
    // The second view is complete, with a __proto__ key written in (JSON.parse makes it an own property).
    const proto = JSON.stringify({ name: "Proto", criteria: bodyOf("x").criteria, layout: null }).replace(
      /^\{/,
      '{"__proto__":{"polluted":1},',
    );
    await importFile(`{"schema":1,"views":[${JSON.stringify(hostile)},${proto}]}`);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(importNotice()).toHaveTextContent("Imported 2 views.");
    const views = useEvtxViewStore.getState().views;
    expect(views.map((v) => v.name)).toEqual(["Hostile", "Proto"]);
    expect(views.every((v) => v.id !== ENROLLMENT_TRIAGE_ID)).toBe(true);
    expect(views[0].layout?.panels.dock).toBe(false);
    expect(JSON.stringify(views)).not.toMatch(TRANSIENT);
    expect(JSON.stringify(views)).not.toMatch(/builtIn|polluted/);
    expect(localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)).not.toMatch(TRANSIENT);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(listViews(views).filter((v) => v.builtIn)).toHaveLength(1);
  });

  it("leaves out what does not fit in the library and counts it", async () => {
    for (let i = 0; i < MAX_CUSTOM_VIEWS - 1; i += 1) makeView(`V${i}`);
    await importFile(buildViewExport([bodyOf("One more"), bodyOf("Too many")]));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(importNotice()).toHaveTextContent("Imported 1 view, 1 skipped.");
    expect(useEvtxViewStore.getState().views).toHaveLength(MAX_CUSTOM_VIEWS);
  });

  it("does not open a second picker while one is open", async () => {
    const picking = deferred<string | null>();
    vi.mocked(open).mockReturnValue(picking.promise);
    const dialog = openNewDialog();
    const button = within(dialog).getByRole("button", { name: "Import views..." });
    fireEvent.click(button);
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(open).toHaveBeenCalledTimes(1);
    picking.resolve(null);
    await waitFor(() => expect(button).toBeEnabled());
  });

  it("round-trips: what Export wrote is what Import reads", async () => {
    const made = makeView("Round trip", { layout: { activeView: "grouped", panels: { channels: true, insights: false, dock: false } } });
    const exported = buildViewExport([made]);
    useEvtxViewStore.getState().remove(made.id);
    await importFile(exported);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const [again] = useEvtxViewStore.getState().views;
    expect({ name: again.name, criteria: again.criteria, layout: again.layout }).toEqual({
      name: made.name,
      criteria: made.criteria,
      layout: made.layout,
    });
    expect(again.id).not.toBe(made.id);
  });

  describe("the summary", () => {
    it.each([
      [{ added: 1, replaced: 0, skipped: 0 }, "Imported 1 view."],
      [{ added: 0, replaced: 0, skipped: 0 }, "Imported 0 views."],
      [{ added: 3, replaced: 0, skipped: 0 }, "Imported 3 views."],
      [{ added: 2, replaced: 1, skipped: 0 }, "Imported 2 views, 1 replaced."],
      [{ added: 0, replaced: 0, skipped: 4 }, "Imported 0 views, 4 skipped."],
      [{ added: 2, replaced: 3, skipped: 1 }, "Imported 2 views, 3 replaced, 1 skipped."],
    ])("%j reads %j", (counts, text) => {
      expect(viewImportSummary(counts)).toBe(text);
    });
  });
});

describe("the strip's colors in all seven themes", () => {
  const themes = getAllThemes().map((theme) => [theme.id, theme] as const);

  describe.each(themes)("%s", (id, theme) => {
    const r = (value: string) => resolveToken(value, theme);
    const surface = r(tokens.colorNeutralBackground1);

    it("reads the active card's name and subtitle at 4.5:1 on the selection fill", () => {
      const { selection } = buildEvtxVisualTokens(theme);
      expect(contrastRatio(r(selection.foreground), r(selection.background))).toBeGreaterThanOrEqual(4.5);
    });

    it("reads the subtitle, the eyebrow and the source line at 4.5:1 on the strip, in the rail's own rule (T5)", () => {
      expect(contrastRatio(r(pickRailTextColors(theme).cardSecondary), surface)).toBeGreaterThanOrEqual(4.5);
    });

    it("reads a card's name and the New view text at 4.5:1 on the strip", () => {
      expect(contrastRatio(r(tokens.colorNeutralForeground1), surface)).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(r(tokens.colorNeutralForeground2), surface)).toBeGreaterThanOrEqual(4.5);
    });

    it("draws the eyebrow, an idle subtitle and the source line in the rail's card secondary color", () => {
      cleanup();
      useUiStore.setState({ themeId: id });
      useEvtxStore.setState({ sourceMode: "files", channels: [channelInfo("System")], records: [RECORD] });
      render(<EvtxViewStrip />);
      const expected = pickRailTextColors(theme).cardSecondary;
      expect(screen.getByText("Views", { selector: "span" }).style.color).toBe(expected);
      expect(screen.getByText("Built-in, 3 filters").style.color).toBe(expected);
      expect(document.querySelector<HTMLElement>("[data-evtx-view-source]")!.style.color).toBe(expected);
      useUiStore.setState({ themeId: "light" });
    });
  });

  it("steps up from fg3 to fg2 only where fg3 is below 4.5:1: solarized-dark and dracula", () => {
    const stepped = getAllThemes()
      .filter((theme) => pickRailTextColors(theme).cardSecondary !== tokens.colorNeutralForeground3)
      .map((theme) => theme.id)
      .sort();
    expect(stepped).toEqual(["dracula", "solarized-dark"]);
  });
});
