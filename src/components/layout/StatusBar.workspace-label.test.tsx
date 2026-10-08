import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// evtx-store subscribes at module load; the log view's listener is not under
// test here.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { tokens } from "@fluentui/react-components";
import { StatusBar } from "./StatusBar";
import { useUiStore } from "../../stores/ui-store";
import { useFilterStore } from "../../stores/filter-store";
import { getAllThemes, getThemeById, type ThemeId } from "../../lib/themes";
import { getWorkspace } from "../../workspaces/registry";
import { EspStatusBarContent } from "../../workspaces/esp-diagnostics/EspStatusBarContent";
import { useEspDiagnosticsStore } from "../../workspaces/esp-diagnostics/esp-diagnostics-store";
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

  // Workspaces without a status branch of their own used to fall into the
  // dsregcmd branch and report "dsregcmd • No analysis".
  it.each([
    ["macos-diag", "macos"],
    ["macos-jamf", "macos"],
    ["sccm", "windows"],
    ["timeline", "windows"],
    ["dns-dhcp", "windows"],
  ] as const)(
    "gives the %s workspace its own status instead of dsregcmd's",
    (workspaceId, platform) => {
      useUiStore.setState({
        currentPlatform: platform,
        activeWorkspace: workspaceId,
        activeView: workspaceId,
      });
      const workspace = getWorkspace(workspaceId);

      render(<StatusBar />);

      const bar = screen.getByTestId("global-status-bar");
      expect(bar).not.toHaveTextContent(/dsregcmd/i);
      expect(screen.queryByText(workspaceId)).not.toBeInTheDocument();
      expect(screen.getAllByText(workspace.label).length).toBeGreaterThan(0);
      expect(
        screen.getAllByText(
          workspace.statusLabel ?? `${workspace.label} workspace`,
        ).length,
      ).toBeGreaterThan(0);
    },
  );
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

function expectedForeground(themeId: ThemeId): string {
  const fluent = getThemeById(themeId).fluentTheme as unknown as Record<
    string,
    string
  >;
  return pickStatusBarForeground(
    fluent.colorBrandBackground,
    fluent.colorNeutralForegroundOnBrand,
  );
}

/// Phase 0b (#826): the global bar is 24px on the brand background in every
/// workspace, with one readable foreground for all text and icons.
describe("status bar chrome", () => {
  beforeEach(() => {
    useUiStore.setState(useUiStore.getInitialState(), true);
    useFilterStore.setState(useFilterStore.getInitialState(), true);
    useEspDiagnosticsStore.setState(
      useEspDiagnosticsStore.getInitialState(),
      true,
    );
  });

  afterEach(() => {
    cleanup();
  });

  it("renders 24px tall on the brand background with no top border", () => {
    render(<StatusBar />);

    const bar = screen.getByTestId("global-status-bar");
    expect(bar.style.height).toBe("24px");
    expect(bar.style.minHeight).toBe("");
    expect(bar.style.padding).toBe("0px 10px");
    expect(bar.style.borderTop).toBe("");
    expect(bar.style.backgroundColor).toBe(tokens.colorBrandBackground);
  });

  it.each(["light", "dark", "high-contrast", "solarized-dark", "hotdog-stand"] as const)(
    "uses the readable foreground for the %s theme",
    (themeId) => {
      useUiStore.setState({ themeId });
      render(<StatusBar />);

      expect(screen.getByTestId("global-status-bar")).toHaveStyle({
        color: expectedForeground(themeId),
      });
    },
  );

  it("conveys an error with an icon and label instead of colored text", () => {
    useFilterStore.setState({ filterError: "bad clause" });
    render(<StatusBar />);

    expect(screen.getByRole("img", { name: "Error" })).toBeInTheDocument();
    const status = screen.getByText(/Filter error: bad clause/);
    expect(status.style.color).toBe("");
  });

  it("keeps the ESP contribution on the bar foreground", () => {
    useUiStore.setState({ themeId: "solarized-dark" });
    useEspDiagnosticsStore.setState({ graphPhase: "error" });
    render(<EspStatusBarContent />);

    expect(screen.getByText("Graph error").style.color).toBe("");
    expect(screen.getByRole("img", { name: "Error" })).toBeInTheDocument();
    expect(screen.getByText("ESP")).toHaveStyle({
      color: expectedForeground("solarized-dark"),
    });
  });
});
