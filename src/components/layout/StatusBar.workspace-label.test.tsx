import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// evtx-store subscribes at module load; the log view's listener is not under
// test here.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { StatusBar } from "./StatusBar";
import { useUiStore } from "../../stores/ui-store";
import { getAllThemes } from "../../lib/themes";
import {
  contrastRatio,
  pickStatusBarForeground,
} from "./status-bar-foreground";

describe("StatusBar workspace label", () => {
  beforeEach(() => {
    useUiStore.setState(useUiStore.getInitialState(), true);
  });

  afterEach(() => {
    cleanup();
  });

  it("labels the macOS JAMF workspace instead of showing its id", () => {
    useUiStore.setState({
      currentPlatform: "macos",
      activeWorkspace: "macos-jamf",
      activeView: "macos-jamf",
    });

    render(<StatusBar />);

    expect(screen.getByText("macOS JAMF")).toBeInTheDocument();
    expect(screen.queryByText("macos-jamf")).not.toBeInTheDocument();
  });
});

/// The status bar sits on `colorBrandBackground`. Some themes ship an on-brand
/// foreground that does not reach WCAG AA against their own brand color
/// (hotdog-stand even sets both to #FFFF00), so the bar picks a readable
/// foreground per theme instead of trusting the token.
describe("status bar foreground", () => {
  it("measures black on white as 21:1", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
  });

  it("keeps the on-brand foreground when it already meets 4.5:1", () => {
    expect(pickStatusBarForeground("#007768", "#ffffff")).toBe("#ffffff");
  });

  it("falls back to the higher-contrast of black and white below 4.5:1", () => {
    expect(pickStatusBarForeground("#2AA198", "#ffffff")).toBe("#000000");
    expect(pickStatusBarForeground("#FFFF00", "#FFFF00")).toBe("#000000");
  });

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "meets WCAG AA against the brand background in the %s theme",
    (_id, theme) => {
      const fluent = theme.fluentTheme as unknown as Record<string, string>;
      const foreground = pickStatusBarForeground(
        fluent.colorBrandBackground,
        fluent.colorNeutralForegroundOnBrand,
      );
      expect(
        contrastRatio(foreground, fluent.colorBrandBackground),
      ).toBeGreaterThanOrEqual(4.5);
    },
  );
});
