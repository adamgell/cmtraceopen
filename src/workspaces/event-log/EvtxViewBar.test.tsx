import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { EvtxViewBar } from "./EvtxViewBar";
import { EVTX_EXPORT_FORMATS } from "./evtx-export";
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

  it("exposes the three panel toggles with aria-pressed and flips the layout store", () => {
    render(<EvtxViewBar nowEpoch={0} />);
    const channels = screen.getByRole("button", { name: "Channels" });
    const insights = screen.getByRole("button", { name: "Insights" });
    const dock = screen.getByRole("button", { name: "Correlation dock" });
    expect(channels).toHaveAttribute("aria-pressed", "true");
    expect(insights).toHaveAttribute("aria-pressed", "true");
    expect(dock).toHaveAttribute("aria-pressed", "false");

    fireEvent.click(dock);
    expect(dock).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(channels);
    expect(channels).toHaveAttribute("aria-pressed", "false");
    expect(useEvtxLayoutStore.getState().panels).toEqual({
      channels: false,
      insights: true,
      dock: true,
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
});
