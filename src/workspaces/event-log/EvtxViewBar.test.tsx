import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
const exportMock = vi.hoisted(() => ({ stream: vi.fn() }));
vi.mock("./event-export-session", () => ({ streamEventLogExport: exportMock.stream }));

import { EvtxViewBar } from "./EvtxViewBar";
import { requireElement, requireSelector } from "./evtx-test-dom";
import { EVTX_EXPORT_FORMATS } from "./evtx-export";
import { defaultColumnConfig } from "./evtx-columns";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
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

  it("ships the Insights and Correlation dock toggles disabled, with the reason as a description", () => {
    seedChannels();
    render(<EvtxViewBar nowEpoch={0} />);
    const cases: Array<[string, string]> = [
      ["Insights", "Available when the Insights rail ships"],
      ["Correlation dock", "Available when the correlation dock ships"],
    ];
    for (const [name, reason] of cases) {
      const toggle = screen.getByRole("button", { name });
      expect(toggle).toHaveAttribute("aria-pressed", "false");
      expect(toggle).toHaveAttribute("aria-disabled", "true");
      expect(toggle).not.toHaveAttribute("title");
      expect(toggle).toHaveAccessibleDescription(reason);
      // Once in the document: no hand-built duplicate for browse mode to read twice.
      expect(screen.getAllByText(reason)).toHaveLength(1);
      fireEvent.click(toggle);
      expect(toggle).toHaveAttribute("aria-pressed", "false");
    }
    expect(useEvtxLayoutStore.getState().panels).toEqual({
      channels: true,
      insights: false,
      dock: false,
    });
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
      const bar = requireSelector("[data-evtx-region=view-bar]");
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
    const status = requireSelector("[data-evtx-export-status]");
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
    const target = requireElement(hidden, "a column option that is not yet shown");
    await act(async () => {
      fireEvent.click(target);
    });
    expect(useEvtxStore.getState().columnConfig.order.length).toBe(count + 1);
  });

  it("lists the existing export formats, then the Windows-only EVTX subset item", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    fireEvent.click(
      screen.getByTitle("Export the events currently shown, using the same filters as the list"),
    );
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((item) => item.textContent)).toEqual([
      ...EVTX_EXPORT_FORMATS.map((format) => format.label),
      "EVTX subset\u2026",
    ]);
    // Set off from the report formats by a divider that sits between them and the new item.
    const divider = document.querySelector(".fui-MenuDivider");
    expect(divider).not.toBeNull();
    const follows = (a: Element, b: Element) =>
      Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(follows(items[EVTX_EXPORT_FORMATS.length - 1], divider as Element)).toBe(true);
    expect(follows(divider as Element, items[EVTX_EXPORT_FORMATS.length])).toBe(true);
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
      const live = requireSelector("[data-evtx-export-announcement]");
      expect(live).toHaveAttribute("role", "status");
      expect(live).toHaveAttribute("aria-live", "polite");
      const heard: string[] = [];
      const observer = new MutationObserver(() => heard.push(live.textContent ?? ""));
      observer.observe(live, { childList: true, characterData: true, subtree: true });

      await exportJson();
      const status = requireSelector("[data-evtx-export-status]");
      await waitFor(() => expect(status).toHaveTextContent("Exported 5,000 events (1,234 bytes)"));
      await Promise.resolve();
      observer.disconnect();

      expect(heard).toEqual(["Export started", "Exported 5,000 events (1,234 bytes)"]);
    });

    const heardAnnouncements = () => {
      const live = requireSelector("[data-evtx-export-announcement]");
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

const EXPORT_BUTTON_TITLE =
  "Export the events currently shown, using the same filters as the list";

const subsetRecord = (partial: Partial<EvtxRecord> = {}): EvtxRecord => ({
  id: 1,
  eventRecordId: 1,
  timestamp: "2026-08-09T12:00:00Z",
  timestampEpoch: 0,
  provider: "Provider",
  channel: "System",
  eventId: 1,
  level: "Error",
  computer: "HOST",
  message: "event",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "Live",
  ...partial,
});

async function openExportMenu() {
  fireEvent.click(screen.getByTitle(EXPORT_BUTTON_TITLE));
  return screen.findAllByRole("menuitem");
}

describe("EVTX subset menu entry", () => {
  beforeEach(() => {
    resetStores();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useEvtxStore.setState({
      records: [
        subsetRecord({ id: 1, channel: "System", eventRecordId: 10, level: "Error" }),
        subsetRecord({ id: 2, channel: "System", eventRecordId: 11, level: "Warning" }),
        subsetRecord({ id: 3, channel: "Application", eventRecordId: 5, level: "Error" }),
      ],
      selectedChannels: new Set(["System", "Application"]),
      timeWindow: "all",
      sourceMode: "live",
    });
  });
  afterEach(cleanup);

  it.each(["macos", "linux"] as const)("is not offered on %s", async (platform) => {
    useUiStore.setState({ currentPlatform: platform });
    render(<EvtxViewBar nowEpoch={0} />);
    const items = await openExportMenu();
    expect(items.map((item) => item.textContent)).toEqual(
      EVTX_EXPORT_FORMATS.map((format) => format.label),
    );
    expect(screen.queryByRole("menuitem", { name: /EVTX subset/ })).toBeNull();
    expect(document.querySelector(".fui-MenuDivider")).toBeNull();
  });

  it("is disabled for a remote source, with the spec's reason reachable", async () => {
    useEvtxStore.setState({ remoteMachine: "SRV01" });
    render(<EvtxViewBar nowEpoch={0} />);
    await openExportMenu();
    const item = screen.getByRole("menuitem", { name: /EVTX subset/ });
    expect(item).toHaveAttribute("aria-disabled", "true");
    // Same treatment as the disabled panel toggles: the reason is the item's description, from a
    // tooltip that shows on hover and focus, not a title and not a hand-built hidden span.
    expect(item).not.toHaveAttribute("title");
    expect(item).toHaveAccessibleDescription("Not available for remote sources.");
    expect(screen.getAllByText("Not available for remote sources.")).toHaveLength(1);
    fireEvent.click(item);
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("keeps the disabled item in the focus order, like the enabled items, so its reason can be read", async () => {
    useEvtxStore.setState({ remoteMachine: "SRV01" });
    render(<EvtxViewBar nowEpoch={0} />);
    const items = await openExportMenu();
    const item = screen.getByRole("menuitem", { name: /EVTX subset/ });
    // Fluent maps a disabled MenuItem to a focusable, aria-disabled one (disabledFocusable): it
    // is not `disabled`, and it takes part in the focus order exactly as the enabled items do.
    // jsdom has no layout, so arrow-key movement and the tooltip appearing on focus cannot be
    // exercised here; that is a check for a real browser.
    expect(item).not.toHaveAttribute("disabled");
    expect(item.tabIndex).toBe(items[0].tabIndex);
    act(() => item.focus());
    expect(item).toHaveFocus();
  });

  it("opens the dialog with exactly the records the list shows", async () => {
    // The Warning event is filtered out of the list, so it must not be offered for export.
    useEvtxStore.setState({ filterLevels: new Set(["Error"]) });
    render(<EvtxViewBar nowEpoch={0} />);
    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: /EVTX subset/ }));

    const dialog = await screen.findByRole("alertdialog");
    const sources = within(within(dialog).getByRole("list", { name: "Sources" }));
    expect(sources.getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "Application1 event",
      "System1 event",
    ]);
  });

  it("reports Nothing to export instead of opening an empty dialog", async () => {
    useEvtxStore.setState({ records: [] });
    render(<EvtxViewBar nowEpoch={0} />);
    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: /EVTX subset/ }));
    expect(document.querySelector("[data-evtx-export-status]")).toHaveTextContent(
      "Nothing to export",
    );
    // Announced like the other exports' empty case, and again if it is chosen again.
    expect(document.querySelector("[data-evtx-export-announcement]")).toHaveTextContent(
      "Nothing to export",
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("clears an old export failure line when a subset is started", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    exportMock.stream.mockReset().mockRejectedValueOnce(new Error("boom"));
    vi.mocked(save).mockReset().mockResolvedValue("/tmp/events.json");
    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: "JSON" }));
    await screen.findByText(/Export failed: boom/);
    expect(document.querySelector("[data-evtx-export-error]")).not.toBeNull();

    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: /EVTX subset/ }));
    await screen.findByRole("alertdialog");
    expect(document.querySelector("[data-evtx-export-error]")).toBeNull();
  });

  it("reports a finished subset as visible status without touching the polite announcement region", async () => {
    vi.mocked(open).mockReset().mockResolvedValue("C:\\out");
    vi.mocked(invoke).mockReset().mockImplementation(async (_command, args) => {
      const { sources } = args as {
        sources: Array<{ path: string; recordGroups: Array<{ recordIds: string[] }> }>;
      };
      return {
        folder: "C:\\out",
        files: sources.map((source) => {
          const events = source.recordGroups.reduce((sum, group) => sum + group.recordIds.length, 0);
          return {
          kind: "channel",
          sourcePath: source.path,
          fileName: `${source.path}-subset.evtx`,
          outputPath: `C:\\out\\${source.path}-subset.evtx`,
          requestedRecords: events,
          status: "exported",
          exportedRecords: events,
          missing: { count: 0, sample: [] },
          unrequested: { count: 0, sample: [] },
          messagesArchived: true,
          error: null,
          warnings: [],
          };
        }),
      };
    });
    render(<EvtxViewBar nowEpoch={0} />);
    const live = document.querySelector<HTMLElement>("[data-evtx-export-announcement]")!;
    const heard: string[] = [];
    const observer = new MutationObserver(() => heard.push(live.textContent ?? ""));
    observer.observe(live, { childList: true, characterData: true, subtree: true });

    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: /EVTX subset/ }));
    await screen.findByRole("alertdialog");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Choose folder\u2026" }));
    });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Export unredacted" })).not.toHaveAttribute(
        "aria-disabled",
        "true",
      ),
    );
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Export unredacted" }));
    });
    await screen.findByRole("list", { name: "Exported files" });
    await waitFor(() =>
      expect(document.querySelector("[data-evtx-export-status]")).toHaveTextContent(
        "Exported 2 EVTX subset files (3 events).",
      ),
    );
    observer.disconnect();
    // The dialog announces its own start and result; the bar's region stays quiet, so it still
    // carries only the other exports' start and final result.
    expect(heard).toEqual([]);
    // A subset that works never uses the failure line under the bar.
    expect(document.querySelector("[data-evtx-export-error]")).toBeNull();
  });

  it("shows a refused subset request in the dialog, where it can be retried, not under the bar", async () => {
    vi.mocked(open).mockReset().mockResolvedValue("C:\\out");
    vi.mocked(invoke)
      .mockReset()
      .mockRejectedValue("These files already exist in C:\\out and are never overwritten: System-subset.evtx.");
    render(<EvtxViewBar nowEpoch={0} />);
    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: /EVTX subset/ }));
    await screen.findByRole("alertdialog");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Choose folder\u2026" }));
    });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Export unredacted" })).not.toHaveAttribute(
        "aria-disabled",
        "true",
      ),
    );
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Export unredacted" }));
    });
    const alert = await within(screen.getByRole("alertdialog")).findByRole("alert");
    expect(alert).toHaveTextContent("never overwritten");
    expect(document.querySelector("[data-evtx-export-error]")).toBeNull();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("puts focus on Cancel when the dialog is opened from the menu, and keeps it there", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: /EVTX subset/ }));
    await screen.findByRole("alertdialog");
    const cancel = screen.getByRole("button", { name: "Cancel" });
    await waitFor(() => expect(cancel).toHaveFocus());
    // Closing the menu makes Fluent restore focus to the Export button. If that landed after the
    // dialog's own focus it would take it back, so look again after the menu has finished closing.
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 100));
    });
    expect(cancel).toHaveFocus();
    expect(screen.getByTitle(EXPORT_BUTTON_TITLE)).not.toHaveFocus();
  });

  it("returns focus to the Export button when the dialog is cancelled", async () => {
    render(<EvtxViewBar nowEpoch={0} />);
    await openExportMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: /EVTX subset/ }));
    await screen.findByRole("alertdialog");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    await waitFor(() => expect(screen.getByTitle(EXPORT_BUTTON_TITLE)).toHaveFocus());
  });
});
