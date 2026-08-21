import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_LOG_DETAILS_FONT_SIZE,
  DEFAULT_LOG_LIST_FONT_SIZE,
} from "../../../lib/log-accessibility";
import { DEFAULT_THEME_ID } from "../../../lib/themes";
import { useUiStore } from "../../../stores/ui-store";
import { AppearanceTab } from "./AppearanceTab";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const invokeMock = vi.mocked(invoke);

describe("AppearanceTab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invokeMock.mockResolvedValue({ families: ["Consolas", "Segoe UI"] });
    useUiStore.setState({
      themeId: DEFAULT_THEME_ID,
      logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE,
      logDetailsFontSize: DEFAULT_LOG_DETAILS_FONT_SIZE,
      fontFamily: null,
    });
  });

  it("shows theme, size sliders, Default (System) font, preview, and Reset Defaults", async () => {
    render(<AppearanceTab />);

    const themeSelect = screen.getByRole("combobox", {
      name: "Select application theme",
    });
    expect(themeSelect).toBeVisible();
    expect(screen.getByRole("option", { name: "Classic CMTrace" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "Light" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "Dark" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "Dracula" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "Nord" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "Solarized Dark" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "High Contrast" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "Hot Dog Stand" })).toBeEnabled();

    expect(screen.getByText("Application text size")).toBeVisible();
    expect(screen.getByText("Details pane text size")).toBeVisible();
    expect(screen.getAllByRole("slider")).toHaveLength(2);
    expect(
      screen.getByRole("slider", {
        name: `Application text size: ${DEFAULT_LOG_LIST_FONT_SIZE} pixels`,
      }),
    ).toHaveValue(String(DEFAULT_LOG_LIST_FONT_SIZE));

    expect(screen.getByText("Font family")).toBeVisible();
    expect(
      await screen.findByRole("button", { name: "Default (System)" }),
    ).toBeVisible();
    expect(await screen.findByRole("button", { name: "Consolas" })).toBeVisible();

    expect(screen.getByText("Preview")).toBeVisible();
    expect(screen.getByText(/Preview message row/)).toBeVisible();
    expect(
      screen.getByText("The details pane preview uses its own independent reading size."),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Reset Defaults" }),
    ).toBeVisible();
  });

  it("applies theme, font, and Reset Defaults through the store", async () => {
    render(<AppearanceTab />);

    fireEvent.change(screen.getByRole("combobox", { name: "Select application theme" }), {
      target: { value: "classic-cmtrace" },
    });
    expect(useUiStore.getState().themeId).toBe("classic-cmtrace");

    fireEvent.click(await screen.findByRole("button", { name: "Consolas" }));
    expect(useUiStore.getState().fontFamily).toBe("Consolas");
    expect(screen.getByText("Selected: Consolas")).toBeVisible();

    fireEvent.change(
      screen.getByRole("slider", {
        name: `Application text size: ${DEFAULT_LOG_LIST_FONT_SIZE} pixels`,
      }),
      { target: { value: "16" } },
    );
    expect(useUiStore.getState().logListFontSize).toBe(16);

    fireEvent.click(screen.getByRole("button", { name: "Reset Defaults" }));
    expect(useUiStore.getState()).toMatchObject({
      themeId: DEFAULT_THEME_ID,
      logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE,
      logDetailsFontSize: DEFAULT_LOG_DETAILS_FONT_SIZE,
      fontFamily: null,
    });

    await waitFor(() => {
      expect(screen.queryByText("Selected: Consolas")).not.toBeInTheDocument();
    });
  });
});
