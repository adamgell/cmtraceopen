import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { EvtxViewBar } from "./EvtxViewBar";
import { useUiStore } from "../../stores/ui-store";
import type { EvtxRecord } from "./types";
import { EVTX_EXPORT_FORMATS } from "./evtx-export";
import { defaultColumnConfig } from "./evtx-columns";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";

const TAB_ORDER = ["Table", "Grouped", "Timeline", "Charts", "Correlation"];

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
    render(<EvtxViewBar nowEpoch={0} />);
    const channels = screen.getByRole("button", { name: "Channels" });
    expect(channels).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(channels);
    expect(channels).toHaveAttribute("aria-pressed", "false");
    expect(useEvtxLayoutStore.getState().panels.channels).toBe(false);
  });

  it("ships the Insights and Correlation dock toggles disabled, with an accessible reason", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const cases: Array<[string, string]> = [
      ["Insights", "Available when the Insights rail ships"],
      ["Correlation dock", "Available when the correlation dock ships"],
    ];
    for (const [name, reason] of cases) {
      const toggle = screen.getByRole("button", { name });
      expect(toggle).toHaveAttribute("aria-pressed", "false");
      expect(toggle).toHaveAttribute("aria-disabled", "true");
      expect(toggle).toHaveAttribute("title", reason);
      expect(toggle).toHaveAccessibleDescription(reason);
      fireEvent.click(toggle);
      expect(toggle).toHaveAttribute("aria-pressed", "false");
    }
    expect(useEvtxLayoutStore.getState().panels).toEqual({
      channels: true,
      insights: false,
      dock: false,
    });
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
    expect(status).toHaveAttribute("role", "status");
    expect(status).toHaveAttribute("aria-live", "polite");
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
    expect(item).toHaveAttribute("title", "Not available for remote sources.");
    expect(item).toHaveAccessibleDescription("Not available for remote sources.");
    fireEvent.click(item);
    expect(screen.queryByRole("alertdialog")).toBeNull();
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
    expect(screen.queryByRole("alertdialog")).toBeNull();
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
