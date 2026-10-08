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
import { getAllThemes } from "../../lib/themes";
import { EspStatusBarContent } from "../../workspaces/esp-diagnostics/EspStatusBarContent";
import { useEspDiagnosticsStore } from "../../workspaces/esp-diagnostics/esp-diagnostics-store";
import { useEvtxStore } from "../../workspaces/event-log/evtx-store";
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

  it.each(["red", "rgb(0, 0, 0)", "#ffffff80", "#ggg", "", "ffffff"])(
    "rejects %j instead of producing NaN",
    (color) => {
      expect(() => contrastRatio(color, "#ffffff")).toThrow(
        /#rgb or #rrggbb/,
      );
    },
  );

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

/// Independent oracle: the foreground each theme must render, written out by
/// hand so the test does not recompute it with the code under test.
const EXPECTED_FOREGROUND = [
  ["light", "#ffffff"],
  ["dark", "#ffffff"],
  ["high-contrast", "#000000"],
  ["solarized-dark", "#000000"],
  ["hotdog-stand", "#000000"],
] as const;

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
    useEvtxStore.setState(useEvtxStore.getInitialState(), true);
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

  it.each(EXPECTED_FOREGROUND)(
    "uses the readable foreground for the %s theme",
    (themeId, color) => {
      useUiStore.setState({ themeId });
      render(<StatusBar />);

      expect(screen.getByTestId("global-status-bar")).toHaveStyle({ color });
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
      color: "#000000",
    });
  });

  it("never renders a success check for a ready Graph phase", () => {
    useEspDiagnosticsStore.setState({ graphPhase: "ready" });
    render(<EspStatusBarContent />);

    expect(screen.queryAllByRole("img")).toHaveLength(0);
  });

  it("marks a partial Graph phase with a warning icon", () => {
    useEspDiagnosticsStore.setState({ graphPhase: "partial" });
    render(<EspStatusBarContent />);

    expect(screen.getByRole("img", { name: "Warning" })).toBeInTheDocument();
  });

  it("marks a loading Graph phase with the progress icon", () => {
    useEspDiagnosticsStore.setState({ graphPhase: "loading" });
    render(<EspStatusBarContent />);

    expect(screen.getByRole("img", { name: "In progress" })).toBeInTheDocument();
  });

  function getLiveDot(container: HTMLElement): HTMLElement {
    const dot = Array.from(
      container.querySelectorAll<HTMLElement>('span[aria-hidden="true"]'),
    ).find((el) => el.style.width === "7px");
    if (!dot) throw new Error("live dot not found");
    return dot;
  }

  it("fills the live dot with the bar foreground when the session is live", () => {
    useEspDiagnosticsStore.setState({ phase: "live" });
    const { container } = render(<EspStatusBarContent />);

    const dot = getLiveDot(container);
    const root = container.querySelector<HTMLElement>(
      "[data-status-content]",
    ) as HTMLElement;
    expect(dot.style.backgroundColor).not.toBe("transparent");
    expect(dot.style.backgroundColor).toBe(root.style.color);
  });

  it("renders the live dot hollow when the session is not live", () => {
    useEspDiagnosticsStore.setState({ phase: "idle" });
    const { container } = render(<EspStatusBarContent />);

    expect(getLiveDot(container).style.backgroundColor).toBe("transparent");
  });

  it("shows the progress icon, not a spinner, while the event log loads", () => {
    useEvtxStore.setState({ isLoading: true });
    useUiStore.setState({
      activeWorkspace: "event-log",
      activeView: "event-log",
    });
    const { container } = render(<StatusBar />);

    expect(screen.getByRole("img", { name: "In progress" })).toBeInTheDocument();
    expect(container.querySelector(".fui-Spinner")).toBeNull();
  });
});
