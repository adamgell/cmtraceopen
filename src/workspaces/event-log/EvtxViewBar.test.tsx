import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { EvtxViewBar } from "./EvtxViewBar";
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

  it("ships Insights as a normal toggle and the Correlation dock disabled, with an accessible reason", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const insights = screen.getByRole("button", { name: "Insights" });
    expect(insights).toHaveAttribute("aria-pressed", "true");
    expect(insights).not.toHaveAttribute("aria-disabled");
    expect(insights).not.toHaveAttribute("title");
    fireEvent.click(insights);
    expect(insights).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(insights);
    expect(insights).toHaveAttribute("aria-pressed", "true");

    const reason = "Available when the correlation dock ships";
    const dock = screen.getByRole("button", { name: "Correlation dock" });
    expect(dock).toHaveAttribute("aria-pressed", "false");
    expect(dock).toHaveAttribute("aria-disabled", "true");
    expect(dock).toHaveAttribute("title", reason);
    expect(dock).toHaveAccessibleDescription(reason);
    fireEvent.click(dock);
    expect(dock).toHaveAttribute("aria-pressed", "false");
    expect(useEvtxLayoutStore.getState().panels).toEqual({
      channels: true,
      insights: true,
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
});
