import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../../stores/ui-store";
import { SettingsDialog } from "./SettingsDialog";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockResolvedValue({ families: [] }),
}));

vi.mock("@tauri-apps/api/app", () => ({
  getVersion: vi.fn().mockResolvedValue("1.3.1"),
}));

vi.mock("../../lib/commands", () => ({
  getUpdatePolicy: vi.fn().mockResolvedValue({
    updateChecksDisabledByPolicy: false,
  }),
}));

describe("SettingsDialog tab keyboard navigation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState({ currentPlatform: "macos" });
  });

  it("exposes a dialog landmark", () => {
    render(<SettingsDialog isOpen onClose={() => {}} />);
    expect(screen.getByRole("dialog", { name: "Settings" })).toHaveAttribute(
      "aria-modal",
      "true",
    );
  });

  it("keeps only the selected tab in the page tab order", () => {
    render(<SettingsDialog isOpen onClose={() => {}} />);

    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(4);
    expect(tabs[0]).toHaveAccessibleName("Appearance");
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(tabs[0]).toHaveAttribute("tabindex", "0");

    for (const tab of tabs.slice(1)) {
      expect(tab).toHaveAttribute("aria-selected", "false");
      expect(tab).toHaveAttribute("tabindex", "-1");
    }
  });

  it("moves focus and selection together with horizontal arrow keys", () => {
    render(<SettingsDialog isOpen onClose={() => {}} />);

    const appearanceTab = screen.getByRole("tab", { name: "Appearance" });
    const columnsTab = screen.getByRole("tab", { name: "Columns" });
    appearanceTab.focus();

    fireEvent.keyDown(appearanceTab, { key: "ArrowRight" });

    expect(columnsTab).toHaveAttribute("aria-selected", "true");
    expect(columnsTab).toHaveFocus();
    expect(columnsTab).toHaveAttribute("tabindex", "0");
    expect(appearanceTab).toHaveAttribute("aria-selected", "false");
    expect(appearanceTab).toHaveAttribute("tabindex", "-1");

    fireEvent.keyDown(columnsTab, { key: "ArrowLeft" });

    expect(appearanceTab).toHaveAttribute("aria-selected", "true");
    expect(appearanceTab).toHaveAttribute("tabindex", "0");
    expect(appearanceTab).toHaveFocus();
    expect(columnsTab).toHaveAttribute("aria-selected", "false");
    expect(columnsTab).toHaveAttribute("tabindex", "-1");
  });

  it("mounts Appearance, Columns, Behavior, and Updates contracts when those tabs are selected", async () => {
    render(<SettingsDialog isOpen onClose={() => {}} />);

    expect(
      screen.getByRole("combobox", { name: "Select application theme" }),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Reset Defaults" })).toBeVisible();
    expect(
      await screen.findByRole("button", { name: "Default (System)" }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("tab", { name: "Columns" }));
    expect(screen.getByText("Using default column order and widths.")).toBeVisible();

    fireEvent.click(screen.getByRole("tab", { name: "Behavior" }));
    expect(
      screen.getByRole("checkbox", { name: /show info pane by default/i }),
    ).toBeVisible();
    expect(
      screen.getByRole("checkbox", { name: /confirm before closing tabs/i }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("tab", { name: "Updates" }));
    expect(
      screen.getByRole("checkbox", { name: /check for updates on startup/i }),
    ).toBeVisible();
    expect(await screen.findByText("Main channel")).toBeVisible();
  });
});
