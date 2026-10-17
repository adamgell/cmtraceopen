import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
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
import { EvtxViewStrip, evtxStripMutedTextColor } from "./EvtxViewStrip";
import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { captureCriteria, sanitizeCriteria } from "./evtx-saved-filters";
import { cancelActiveLoad, useEvtxStore } from "./evtx-store";
import { EVTX_BUILT_IN_VIEWS, MAX_CUSTOM_VIEWS, type EvtxViewBody } from "./evtx-views";
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
      expect(screen.getByRole("status")).toHaveTextContent("Applied Enrollment triage. 1 of its channel is not in these files.");
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

describe("the strip's colors in all seven themes", () => {
  const themes = getAllThemes().map((theme) => [theme.id, theme] as const);

  describe.each(themes)("%s", (_id, theme) => {
    const r = (value: string) => resolveToken(value, theme);
    const surface = r(tokens.colorNeutralBackground1);

    it("reads the active card's name and subtitle at 4.5:1 on the selection fill", () => {
      const { selection } = buildEvtxVisualTokens(theme);
      expect(contrastRatio(r(selection.foreground), r(selection.background))).toBeGreaterThanOrEqual(4.5);
    });

    it("reads the subtitle, the eyebrow and the source line at 4.5:1 on the strip", () => {
      expect(contrastRatio(evtxStripMutedTextColor(theme), surface)).toBeGreaterThanOrEqual(4.5);
    });

    it("reads a card's name and the New view text at 4.5:1 on the strip", () => {
      expect(contrastRatio(r(tokens.colorNeutralForeground1), surface)).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(r(tokens.colorNeutralForeground2), surface)).toBeGreaterThanOrEqual(4.5);
    });

    it("keeps the third-level foreground where it is readable, and steps up only where it is not", () => {
      const fg3 = r(tokens.colorNeutralForeground3);
      const muted = evtxStripMutedTextColor(theme);
      if (contrastRatio(fg3, surface) >= 4.5) expect(muted).toBe(fg3);
      else expect(muted).not.toBe(fg3);
    });
  });
});
