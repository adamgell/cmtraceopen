import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { save } from "@tauri-apps/plugin-dialog";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
const exportMock = vi.hoisted(() => ({ stream: vi.fn() }));
vi.mock("./event-export-session", () => ({ streamEventLogExport: exportMock.stream }));

import { EvtxViewBar } from "./EvtxViewBar";
import { EVTX_EXPORT_FORMATS } from "./evtx-export";
import { defaultColumnConfig } from "./evtx-columns";
import { evtxPanelToggleId, sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import { useUiStore } from "../../stores/ui-store";
import type { EvtxRecord } from "./types";

const TAB_ORDER = ["Table", "Grouped", "Timeline", "Charts", "Correlation"];

const CHANNEL = { name: "Application", eventCount: 1, sourceType: "live" as const };
const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: 1,
  provider: "Example Provider",
  channel: "Application",
  eventId: 42,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event message",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
};

function seedChannels() {
  useEvtxStore.setState({
    channels: [CHANNEL],
    records: [RECORD],
    selectedChannels: new Set(["Application"]),
    loadedChannels: new Set(["Application"]),
    timeWindow: "all",
  });
}

function resetStores() {
  localStorage.clear();
  useEvtxLayoutStore.setState(sanitizeLayout(undefined));
  useEvtxStore.getState().reset();
}

describe("EvtxViewBar", () => {
  beforeEach(resetStores);
  afterEach(cleanup);

  it("renders the Layout tablist in spec order with only the active tab in the tab sequence", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const list = screen.getByRole("tablist", { name: "Layout" });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs.map((tab) => tab.textContent)).toEqual(TAB_ORDER);
    expect(tabs.map((tab) => tab.getAttribute("aria-selected"))).toEqual([
      "true",
      "false",
      "false",
      "false",
      "false",
    ]);
    expect(tabs.map((tab) => tab.tabIndex)).toEqual([0, -1, -1, -1, -1]);
  });

  it("moves with Left, Right, Home and End, wrapping at the ends", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const tab = (name: string) => screen.getByRole("tab", { name });

    fireEvent.keyDown(tab("Table"), { key: "ArrowRight" });
    expect(tab("Grouped")).toHaveAttribute("aria-selected", "true");
    expect(tab("Grouped")).toHaveFocus();
    expect(useEvtxLayoutStore.getState().activeView).toBe("grouped");

    fireEvent.keyDown(tab("Grouped"), { key: "End" });
    expect(tab("Correlation")).toHaveAttribute("aria-selected", "true");
    expect(tab("Correlation")).toHaveFocus();

    fireEvent.keyDown(tab("Correlation"), { key: "ArrowRight" });
    expect(tab("Table")).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(tab("Table"), { key: "ArrowLeft" });
    expect(tab("Correlation")).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(tab("Correlation"), { key: "Home" });
    expect(tab("Table")).toHaveAttribute("aria-selected", "true");
    expect(tab("Table").tabIndex).toBe(0);
    expect(tab("Correlation").tabIndex).toBe(-1);
  });

  it("selects a view on click", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    fireEvent.click(screen.getByRole("tab", { name: "Charts" }));
    expect(useEvtxLayoutStore.getState().activeView).toBe("charts");
    expect(screen.getByRole("tab", { name: "Charts" })).toHaveAttribute("aria-selected", "true");
  });

  it("exposes the panel toggles with aria-pressed and flips the channel pane", () => {
    seedChannels();
    render(<EvtxViewBar nowEpoch={0} />);
    const channels = screen.getByRole("button", { name: "Channels" });
    expect(channels).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(channels);
    expect(channels).toHaveAttribute("aria-pressed", "false");
    expect(useEvtxLayoutStore.getState().panels.channels).toBe(false);
  });

  it("ships Insights and the Correlation dock as normal toggles: pressed state, no reason, each with its own id", () => {
    seedChannels();
    render(<EvtxViewBar nowEpoch={0} />);
    const insights = screen.getByRole("button", { name: "Insights" });
    expect(insights).toHaveAttribute("aria-pressed", "true");
    expect(insights).not.toHaveAttribute("aria-disabled");
    expect(insights).not.toHaveAccessibleDescription();
    fireEvent.click(insights);
    expect(insights).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(insights);
    expect(insights).toHaveAttribute("aria-pressed", "true");

    const dock = screen.getByRole("button", { name: "Correlation dock" });
    // Off by default (R4), and nothing about it is unavailable.
    expect(dock).toHaveAttribute("aria-pressed", "false");
    expect(dock).not.toHaveAttribute("aria-disabled");
    expect(dock).not.toHaveAccessibleDescription();
    expect(screen.queryByText(/Available when the correlation dock ships/)).toBeNull();
    fireEvent.click(dock);
    expect(dock).toHaveAttribute("aria-pressed", "true");
    expect(useEvtxLayoutStore.getState().panels).toEqual({ channels: true, insights: true, dock: true });
    fireEvent.click(dock);
    expect(dock).toHaveAttribute("aria-pressed", "false");
    expect(useEvtxLayoutStore.getState().panels.dock).toBe(false);
    // The ids the dock's Close uses to give focus back.
    expect(dock.id).toBe(evtxPanelToggleId("dock"));
    expect(insights.id).toBe(evtxPanelToggleId("insights"));
    expect(dock.id).not.toBe(insights.id);
  });

  it("makes the Channels toggle unavailable, with a reason, when no channels are loaded", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const toggle = screen.getByRole("button", { name: "Channels" });
    expect(toggle).toHaveAttribute("aria-disabled", "true");
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    expect(toggle).toHaveAccessibleDescription("No event log channels loaded");
    fireEvent.click(toggle);
    expect(useEvtxLayoutStore.getState().panels.channels).toBe(true);
    cleanup();

    seedChannels();
    render(<EvtxViewBar nowEpoch={0} />);
    expect(screen.getByRole("button", { name: "Channels" })).toHaveAttribute("aria-pressed", "true");
  });

  it("sets the active text color from the theme, in classes rather than inline styles", () => {
    seedChannels();
    const original = useUiStore.getState().themeId;
    useUiStore.setState({ themeId: "high-contrast" });
    try {
      render(<EvtxViewBar nowEpoch={0} />);
      const bar = document.querySelector<HTMLElement>("[data-evtx-region=view-bar]")!;
      // High-contrast fails 4.5:1 with the brand foreground, so the fallback is black.
      expect(bar.style.getPropertyValue("--evtx-active-text")).toBe("#000000");
      const tab = screen.getByRole("tab", { name: "Table" });
      const toggle = screen.getByRole("button", { name: "Channels" });
      for (const el of [tab, toggle]) {
        expect(el.style.color).toBe("");
        expect(el.style.backgroundColor).toBe("");
      }
    } finally {
      useUiStore.setState({ themeId: original });
    }
  });

  it("draws the Layout tab focus ring inside the tab so the clipped group cannot cut it off", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const tab = screen.getByRole("tab", { name: "Table" });
    const classes = tab.className.split(/\s+/).filter(Boolean);
    expect(classes.length).toBeGreaterThan(0);
    const rules: CSSStyleRule[] = [];
    for (const sheet of Array.from(document.styleSheets)) {
      for (const rule of Array.from(sheet.cssRules)) {
        if (rule instanceof CSSStyleRule) rules.push(rule);
      }
    }
    // Griffel emits one atomic rule per declaration, so gather every focus-visible rule that
    // targets one of the tab's classes.
    const focusCss = rules
      .filter(
        (rule) =>
          rule.selectorText.includes(":focus-visible") &&
          classes.some((name) => rule.selectorText.includes(`.${name}`)),
      )
      .map((rule) => rule.cssText)
      .join(" ");
    expect(focusCss).toMatch(/outline-offset:\s*-2px/);
    expect(focusCss).toMatch(/outline-style:\s*solid/);
  });

  it("keeps the export status in the spacer with overflow ellipsis and the full text in the title", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const status = document.querySelector<HTMLElement>("[data-evtx-export-status]")!;
    // Visible progress is not a live region; the announcement element is separate.
    expect(status).not.toHaveAttribute("aria-live");
    expect(status).toHaveStyle({
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap",
      minWidth: "0",
    });
  });

  it("calls setGroupBy with the chosen field, nests further fields, and clears with None", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const combo = screen.getByRole("combobox", { name: "Group by" });
    fireEvent.click(combo);
    fireEvent.click(await screen.findByRole("menuitemcheckbox", { name: "Provider" }));
    expect(useEvtxStore.getState().groupBy).toEqual(["provider"]);

    fireEvent.click(await screen.findByRole("menuitemcheckbox", { name: "Level" }));
    expect(useEvtxStore.getState().groupBy).toEqual(["provider", "level"]);

    fireEvent.click(await screen.findByRole("menuitemcheckbox", { name: "None" }));
    expect(useEvtxStore.getState().groupBy).toEqual([]);
  });

  it("opens the column picker from Columns (n) and toggles a column", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const count = useEvtxStore.getState().columnConfig.order.length;
    fireEvent.click(screen.getByRole("button", { name: `Columns (${count})` }));
    expect(await screen.findByRole("button", { name: "Reset columns" })).toBeInTheDocument();

    fireEvent.click(await screen.findByRole("combobox", { name: "Visible columns" }));
    const options = await screen.findAllByRole("menuitemcheckbox");
    const hidden = options.find((option) => option.getAttribute("aria-checked") === "false");
    expect(hidden).toBeDefined();
    await act(async () => {
      fireEvent.click(hidden!);
    });
    expect(useEvtxStore.getState().columnConfig.order.length).toBe(count + 1);
  });

  it("lists exactly the existing export formats", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    fireEvent.click(
      screen.getByTitle("Export the events currently shown, using the same filters as the list"),
    );
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((item) => item.textContent)).toEqual(
      EVTX_EXPORT_FORMATS.map((format) => format.label),
    );
  });

  it("reorders a column and resets columns inside the Columns popover, with icon arrows", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const defaults = defaultColumnConfig().order;
    fireEvent.click(screen.getByRole("button", { name: `Columns (${defaults.length})` }));

    fireEvent.click(await screen.findByRole("combobox", { name: "Column to reorder" }));
    const options = await screen.findAllByRole("option");
    await act(async () => {
      fireEvent.click(options[0]);
    });
    const later = screen.getByRole("button", { name: "Move the selected column later" });
    const earlier = screen.getByRole("button", { name: "Move the selected column earlier" });
    expect(later.querySelector("svg")).not.toBeNull();
    expect(earlier.querySelector("svg")).not.toBeNull();
    expect(later.textContent).toBe("");
    expect(earlier).toBeDisabled();

    fireEvent.click(later);
    const moved = useEvtxStore.getState().columnConfig.order;
    expect(moved[1]).toBe(defaults[0]);
    expect(moved[0]).toBe(defaults[1]);

    fireEvent.click(screen.getByRole("button", { name: "Reset columns" }));
    expect(useEvtxStore.getState().columnConfig.order).toEqual(defaults);
  });

  describe("export reporting", () => {
    const exportJson = async () => {
      fireEvent.click(
        screen.getByTitle("Export the events currently shown, using the same filters as the list"),
      );
      fireEvent.click(await screen.findByRole("menuitem", { name: "JSON" }));
    };

    beforeEach(() => {
      seedChannels();
      vi.mocked(save).mockReset().mockResolvedValue("/tmp/events.json");
      exportMock.stream.mockReset();
    });

    describe("with a transient time range or record scope", () => {
      const timed = (id: number, timestampEpoch: number): EvtxRecord => ({
        ...RECORD,
        id,
        eventRecordId: 100 + id,
        timestampEpoch,
      });
      const exportedIds = () =>
        (exportMock.stream.mock.calls[0][0] as { records: EvtxRecord[] }).records.map((r) => r.id);
      const seedFour = () => {
        const records = [timed(1, 1000), timed(2, 2000), timed(3, 3000), timed(4, 4000)];
        useEvtxStore.setState({ records });
        return records;
      };

      beforeEach(() => {
        exportMock.stream.mockResolvedValue({ records: 0, bytes: 0 });
      });

      it("exports only the events in the time range, which is half open", async () => {
        seedFour();
        act(() => {
          useEvtxStore.getState().setTimeRange({ startMs: 2000, endMs: 4000 });
        });
        render(<EvtxViewBar nowEpoch={0} />);
        await exportJson();
        await waitFor(() => expect(exportMock.stream).toHaveBeenCalledTimes(1));
        expect(exportedIds()).toEqual([2, 3]);
      });

      it("exports only the scoped events", async () => {
        const records = seedFour();
        act(() => {
          useEvtxStore.getState().setRecordScope({
            kind: "finding",
            title: "A finding",
            records: new Set([records[0], records[3]]),
            counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
          });
        });
        render(<EvtxViewBar nowEpoch={0} />);
        await exportJson();
        await waitFor(() => expect(exportMock.stream).toHaveBeenCalledTimes(1));
        expect(exportedIds()).toEqual([1, 4]);
      });

      it("exports the whole view without either", async () => {
        seedFour();
        render(<EvtxViewBar nowEpoch={0} />);
        await exportJson();
        await waitFor(() => expect(exportMock.stream).toHaveBeenCalledTimes(1));
        expect(exportedIds()).toEqual([1, 2, 3, 4]);
      });
    });

    it("announces only the start and the final result for a multi-chunk export", async () => {
      exportMock.stream.mockImplementation(
        async ({ onProgress }: { onProgress: (received: number, expected: number) => void }) => {
          for (let received = 1000; received <= 5000; received += 1000) {
            await act(async () => onProgress(received, 5000));
          }
          return { records: 5000, bytes: 1234 };
        },
      );
      render(<EvtxViewBar nowEpoch={0} />);
      const live = document.querySelector<HTMLElement>("[data-evtx-export-announcement]")!;
      expect(live).toHaveAttribute("role", "status");
      expect(live).toHaveAttribute("aria-live", "polite");
      const heard: string[] = [];
      const observer = new MutationObserver(() => heard.push(live.textContent ?? ""));
      observer.observe(live, { childList: true, characterData: true, subtree: true });

      await exportJson();
      const status = document.querySelector<HTMLElement>("[data-evtx-export-status]")!;
      await waitFor(() => expect(status).toHaveTextContent("Exported 5,000 events (1,234 bytes)"));
      await Promise.resolve();
      observer.disconnect();

      expect(heard).toEqual(["Export started", "Exported 5,000 events (1,234 bytes)"]);
    });

    const heardAnnouncements = () => {
      const live = document.querySelector<HTMLElement>("[data-evtx-export-announcement]")!;
      const heard: string[] = [];
      const observer = new MutationObserver(() => heard.push(live.textContent ?? ""));
      observer.observe(live, { childList: true, characterData: true, subtree: true });
      return { heard, stop: () => observer.disconnect() };
    };

    it("announces the same message again, and announces nothing for a failure", async () => {
      useEvtxStore.setState({ records: [] });
      render(<EvtxViewBar nowEpoch={0} />);
      const { heard, stop } = heardAnnouncements();
      await exportJson();
      await waitFor(() => expect(heard).toEqual(["Nothing to export"]));
      await exportJson();
      await waitFor(() => expect(heard).toEqual(["Nothing to export", "Nothing to export"]));
      stop();
      cleanup();

      seedChannels();
      // Fail after a tick so the start is committed (and announced) before the failure.
      exportMock.stream.mockImplementationOnce(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        throw new Error("boom");
      });
      render(<EvtxViewBar nowEpoch={0} />);
      const second = heardAnnouncements();
      await exportJson();
      await screen.findByRole("alert");
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
      });
      // Started, then silence for the failure (the alert carries it).
      expect(second.heard).toEqual(["Export started", ""]);
      exportMock.stream.mockImplementationOnce(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        return { records: 1, bytes: 1 };
      });
      await exportJson();
      await waitFor(() => expect(second.heard).toContain("Exported 1 events (1 bytes)"));
      expect(second.heard.filter((text) => text === "Export started")).toHaveLength(2);
      second.stop();
    });

    it("clears an old failure when a later attempt ends early, and restores focus on dismiss", async () => {
      exportMock.stream.mockRejectedValueOnce(new Error("boom"));
      render(<EvtxViewBar nowEpoch={0} />);
      await exportJson();
      fireEvent.click(await screen.findByRole("button", { name: "Dismiss export error" }));
      expect(screen.getByTitle(/Export the events currently shown/)).toHaveFocus();

      exportMock.stream.mockRejectedValueOnce(new Error("boom again"));
      await exportJson();
      await screen.findByRole("alert");
      // A cancelled save dialog leaves no stale failure behind.
      vi.mocked(save).mockResolvedValueOnce(null);
      await exportJson();
      await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
      // Neither does "Nothing to export".
      exportMock.stream.mockRejectedValueOnce(new Error("third"));
      await exportJson();
      await screen.findByRole("alert");
      useEvtxStore.setState({ records: [] });
      await exportJson();
      await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    });

    it("shows a long failure in full as a dismissable alert under the bar, never truncated", async () => {
      const detail = "disk full ".repeat(60).trim();
      exportMock.stream.mockRejectedValue(new Error(detail));
      render(<EvtxViewBar nowEpoch={0} />);
      await exportJson();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(`Export failed: ${detail}`);
      expect(alert.style.textOverflow).not.toBe("ellipsis");
      expect(alert.style.whiteSpace).not.toBe("nowrap");
      expect(alert.closest("[data-evtx-region=view-bar]")).toBeNull();

      fireEvent.click(screen.getByRole("button", { name: "Dismiss export error" }));
      expect(screen.queryByRole("alert")).toBeNull();
    });
  });
});
