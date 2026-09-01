import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TabState } from "../../stores/ui-store";
import { useUiStore } from "../../stores/ui-store";
import { MergeTabsDialog } from "./MergeTabsDialog";

function tab(filePath: string, fileKind: TabState["fileKind"] = "log"): TabState {
  return {
    id: filePath,
    filePath,
    fileName: filePath.split(/[\\/]/).pop() ?? filePath,
    scrollPosition: 0,
    selectedLineId: null,
    sourceContext: null,
    fileKind,
  };
}

describe("MergeTabsDialog (LOG-015)", () => {
  beforeEach(() => {
    useUiStore.setState({ openTabs: [] });
  });

  afterEach(() => {
    cleanup();
  });

  it("tells the user to open two logs when fewer than two mergeable tabs exist", () => {
    useUiStore.setState({
      openTabs: [tab("C:/logs/AppEnforce.log"), tab("C:/logs/hardware.reg", "registry")],
    });
    render(<MergeTabsDialog isOpen onClose={() => {}} onMerge={() => {}} />);

    expect(screen.getByRole("dialog", { name: "Merge Tabs into Unified Timeline" })).toBeVisible();
    expect(screen.getByText("Open at least two log files to use this feature.")).toBeVisible();
    expect(screen.getByRole("button", { name: /Merge/ })).toBeDisabled();
  });

  it("enables Merge only after two log tabs are checked", () => {
    const onMerge = vi.fn();
    const onClose = vi.fn();
    useUiStore.setState({
      openTabs: [tab("C:/logs/AppEnforce.log"), tab("C:/logs/CIAgent.log")],
    });
    render(<MergeTabsDialog isOpen onClose={onClose} onMerge={onMerge} />);

    expect(screen.getByRole("button", { name: "Merge (0 files)" })).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: "AppEnforce.log" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "CIAgent.log" }));
    expect(screen.getByRole("button", { name: "Merge (2 files)" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Merge (2 files)" }));
    expect(onMerge).toHaveBeenCalledWith(
      expect.arrayContaining(["C:/logs/AppEnforce.log", "C:/logs/CIAgent.log"]),
    );
    expect(onClose).toHaveBeenCalled();
  });
});
