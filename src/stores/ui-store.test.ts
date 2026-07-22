import { describe, it, expect, beforeEach } from "vitest";
import { useUiStore, getAvailableWorkspaces, isIntuneWorkspace } from "./ui-store";

describe("ui-store", () => {
  beforeEach(() => {
    // Reset key state without triggering workspace guards
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
      openTabs: [],
      activeTabIndex: -1,
    });
  });

  describe("activeView", () => {
    it("defaults to log workspace", () => {
      expect(useUiStore.getState().activeView).toBe("log");
    });

    it("disables startup update checks by default", () => {
      expect(useUiStore.getInitialState().autoUpdateEnabled).toBe(false);
    });

    it("switches workspace", () => {
      useUiStore.getState().setActiveView("intune");
      expect(useUiStore.getState().activeView).toBe("intune");
    });
  });

  describe("always on top", () => {
    it("defaults to off", () => {
      expect(useUiStore.getInitialState().alwaysOnTop).toBe(false);
    });

    it("toggles the preference", () => {
      useUiStore.getState().setAlwaysOnTop(true);
      expect(useUiStore.getState().alwaysOnTop).toBe(true);
      useUiStore.getState().setAlwaysOnTop(false);
      expect(useUiStore.getState().alwaysOnTop).toBe(false);
    });

    it("persists the preference so it survives a restart", () => {
      useUiStore.getState().setAlwaysOnTop(true);
      const persisted = JSON.parse(
        localStorage.getItem("cmtraceopen-ui-preferences") ?? "{}",
      );
      expect(persisted.state?.alwaysOnTop).toBe(true);
    });
  });

  describe("persisted preferences", () => {
    it("finishes hydration when no preferences have been stored yet", async () => {
      await useUiStore.persist.clearStorage();

      await useUiStore.persist.rehydrate();

      expect(useUiStore.persist.hasHydrated()).toBe(true);
      expect(useUiStore.getState().activeView).toBe("log");
    });
  });

  describe("font size controls", () => {
    it("increases log list font size", () => {
      const initial = useUiStore.getState().logListFontSize;
      useUiStore.getState().increaseLogListFontSize();
      expect(useUiStore.getState().logListFontSize).toBe(initial + 1);
    });

    it("decreases log list font size", () => {
      useUiStore.getState().increaseLogListFontSize();
      useUiStore.getState().increaseLogListFontSize();
      const increased = useUiStore.getState().logListFontSize;
      useUiStore.getState().decreaseLogListFontSize();
      expect(useUiStore.getState().logListFontSize).toBe(increased - 1);
    });

    it("resets log list font size to default", () => {
      useUiStore.getState().increaseLogListFontSize();
      useUiStore.getState().resetLogListFontSize();
      expect(useUiStore.getState().logListFontSize).toBe(13);
    });
  });

  describe("theme", () => {
    it("sets theme ID", () => {
      useUiStore.getState().setThemeId("dark");
      expect(useUiStore.getState().themeId).toBe("dark");

      useUiStore.getState().setThemeId("solarized-dark");
      expect(useUiStore.getState().themeId).toBe("solarized-dark");
    });
  });

  describe("tab management", () => {
    it("opens a tab", () => {
      useUiStore.getState().openTab("/test.log", "test.log");

      expect(useUiStore.getState().openTabs).toHaveLength(1);
      expect(useUiStore.getState().openTabs[0].filePath).toBe("/test.log");
      expect(useUiStore.getState().activeTabIndex).toBe(0);
    });

    it("does not duplicate tabs for same file path", () => {
      useUiStore.getState().openTab("/test.log", "test.log");
      useUiStore.getState().openTab("/test.log", "test.log");

      expect(useUiStore.getState().openTabs).toHaveLength(1);
    });

    it("closes a tab", () => {
      useUiStore.getState().openTab("/a.log", "a.log");
      useUiStore.getState().openTab("/b.log", "b.log");

      expect(useUiStore.getState().openTabs).toHaveLength(2);
      useUiStore.getState().closeTab(0);
      expect(useUiStore.getState().openTabs).toHaveLength(1);
      expect(useUiStore.getState().openTabs[0].filePath).toBe("/b.log");
    });

    it("switches active tab", () => {
      useUiStore.getState().openTab("/a.log", "a.log");
      useUiStore.getState().openTab("/b.log", "b.log");

      useUiStore.getState().switchTab(0);
      expect(useUiStore.getState().activeTabIndex).toBe(0);
    });
  });

  describe("column widths", () => {
    it("sets and retrieves column width", () => {
      useUiStore.getState().setColumnWidth("message", 500);
      expect(useUiStore.getState().columnWidths["message"]).toBe(500);
    });

    it("resets column widths", () => {
      useUiStore.getState().setColumnWidth("message", 500);
      useUiStore.getState().resetColumnWidths();
      expect(useUiStore.getState().columnWidths).toEqual({});
    });
  });

  describe("toggle panels", () => {
    it("toggles sidebar", () => {
      const initial = useUiStore.getState().sidebarCollapsed;
      useUiStore.getState().toggleSidebar();
      expect(useUiStore.getState().sidebarCollapsed).toBe(!initial);
    });

    it("toggles info pane", () => {
      const initial = useUiStore.getState().showInfoPane;
      useUiStore.getState().toggleInfoPane();
      expect(useUiStore.getState().showInfoPane).toBe(!initial);
    });

    it("toggles details", () => {
      const initial = useUiStore.getState().showDetails;
      useUiStore.getState().toggleDetails();
      expect(useUiStore.getState().showDetails).toBe(!initial);
    });
  });

  describe("dialogs", () => {
    it("closes all transient dialogs", () => {
      useUiStore.getState().setShowFindBar(true);
      useUiStore.getState().setShowFilterDialog(true);

      useUiStore.getState().closeTransientDialogs("test");

      const state = useUiStore.getState();
      expect(state.showFindBar).toBe(false);
      expect(state.showFilterDialog).toBe(false);
    });
  });

  describe("error lookup history", () => {
    it("adds and caps at 10 entries", () => {
      for (let i = 0; i < 12; i++) {
        useUiStore.getState().addErrorLookupHistoryEntry({
          codeHex: `0x8007000${i}`,
          codeDecimal: `${i}`,
          description: `Error ${i}`,
          category: "Windows",
          found: true,
          timestamp: Date.now(),
        });
      }

      expect(useUiStore.getState().errorLookupHistory).toHaveLength(10);
    });

    it("clears history", () => {
      useUiStore.getState().addErrorLookupHistoryEntry({
        codeHex: "0x80070001",
        codeDecimal: "1",
        description: "Test",
        category: "Windows",
        found: true,
        timestamp: Date.now(),
      });

      useUiStore.getState().clearErrorLookupHistory();
      expect(useUiStore.getState().errorLookupHistory).toHaveLength(0);
    });
  });
});

describe("getAvailableWorkspaces", () => {
  it("returns all workspaces for windows", () => {
    const workspaces = getAvailableWorkspaces("windows");
    expect(workspaces).toContain("log");
    expect(workspaces).toContain("intune");
    expect(workspaces).toContain("dsregcmd");
    expect(workspaces).toContain("deployment");
    expect(workspaces).toContain("sysmon");
    expect(workspaces).not.toContain("macos-diag");
  });

  it("returns macos workspaces for macos", () => {
    const workspaces = getAvailableWorkspaces("macos");
    expect(workspaces).toContain("log");
    expect(workspaces).toContain("macos-diag");
    expect(workspaces).not.toContain("sysmon");
    expect(workspaces).not.toContain("dsregcmd");
    expect(workspaces).not.toContain("deployment");
  });

  it("returns linux workspaces for linux", () => {
    const workspaces = getAvailableWorkspaces("linux");
    expect(workspaces).toContain("log");
    expect(workspaces).not.toContain("sysmon");
    expect(workspaces).not.toContain("dsregcmd");
    expect(workspaces).not.toContain("macos-diag");
  });

  it("filters workspaces to the backend-enabled set", () => {
    const workspaces = getAvailableWorkspaces("windows", ["log"]);
    expect(workspaces).toEqual(["log"]);
  });

  it("falls back to log when the backend disables the active workspace", () => {
    useUiStore.getState().setActiveView("intune");

    useUiStore.getState().setEnabledWorkspaces(["log"]);

    expect(useUiStore.getState().activeWorkspace).toBe("log");
    expect(useUiStore.getState().activeView).toBe("log");
  });
});

describe("isIntuneWorkspace", () => {
  it("identifies intune workspaces", () => {
    expect(isIntuneWorkspace("intune")).toBe(true);
    expect(isIntuneWorkspace("new-intune")).toBe(true);
    expect(isIntuneWorkspace("log")).toBe(false);
    expect(isIntuneWorkspace("dsregcmd")).toBe(false);
  });
});
