import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const logRenderer = vi.hoisted(() => ({ throws: false }));
vi.mock("../log-view/LogListView", () => ({
  LogListView: () => {
    const filePath = useLogStore((state) => state.openFilePath);
    if (logRenderer.throws || filePath === "/logs/broken.log") {
      throw new Error("log rendering failed");
    }
    return <div>log content</div>;
  },
}));

vi.mock("../registry-view/RegistryViewer", () => ({
  RegistryViewer: () => {
    const filePath = useRegistryStore((state) => state.registryData?.filePath);
    if (filePath === "/logs/broken.reg") throw new Error("registry rendering failed");
    return <div>registry content</div>;
  },
}));

// The status bar and workspaces lazily subscribe to native events; this test
// only exercises view routing.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

// jsdom has no OS plugin; the toolbar maps the host platform to a workspace set.
vi.mock("@tauri-apps/plugin-os", () => ({
  platform: () => "macos",
}));

// The drag-drop hook binds to a native window that does not exist in jsdom.
vi.mock("@tauri-apps/api/webviewWindow", () => ({
  getCurrentWebviewWindow: () => ({
    onDragDropEvent: vi.fn().mockResolvedValue(() => undefined),
  }),
}));

import { AppShell } from "./AppShell";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import * as logSource from "../../lib/log-source";
import { useRegistryStore } from "../../stores/registry-store";

describe("AppShell workspace routing", () => {
  beforeEach(() => {
    logRenderer.throws = false;
    vi.spyOn(logSource, "switchToTab").mockResolvedValue(undefined);
    vi.stubGlobal("ResizeObserver", class {
      observe() {}
      disconnect() {}
    });
    useLogStore.getState().clear();
    useRegistryStore.getState().clear();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ currentPlatform: "macos" });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("contains a failed log renderer and recovers when switching workspace", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    logRenderer.throws = true;
    render(<AppShell />);
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");
    await act(async () => useUiStore.getState().setActiveWorkspace("macos-jamf"));
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
  });

  it("recovers by opening another file in the log-only workspace", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    useUiStore.getState().setEnabledWorkspaces(["log"]);
    useLogStore.getState().setOpenFilePath("/logs/broken.log");
    useUiStore.getState().openTab("/logs/broken.log", "broken.log");
    render(<AppShell />);
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");
    expect(screen.getByRole("alert").textContent).toContain("Open another file");

    await act(async () => {
      // File loading publishes the new source before opening its tab.
      useLogStore.getState().setOpenFilePath("/logs/healthy.log");
      useUiStore.getState().openTab("/logs/healthy.log", "healthy.log");
    });

    expect(useUiStore.getState().activeView).toBe("log");
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
    expect(screen.getByText("log content")).toBeTruthy();
  });

  it("recovers after a healthy tab finishes loading without changing workspace", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    useUiStore.getState().openTab("/logs/healthy.log", "healthy.log");
    useUiStore.getState().openTab("/logs/broken.log", "broken.log");
    useLogStore.getState().setOpenFilePath("/logs/broken.log");
    render(<AppShell />);
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");

    await act(async () => useUiStore.getState().switchTab(0));
    // A tab selection precedes the async loader replacing the broken source.
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");
    await act(async () => useLogStore.getState().setOpenFilePath("/logs/healthy.log"));

    expect(useUiStore.getState().activeView).toBe("log");
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
    expect(screen.getByText("log content")).toBeTruthy();

    await act(async () => {
      useUiStore.getState().switchTab(1);
      useLogStore.getState().setOpenFilePath("/logs/broken.log");
    });
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");
    await act(async () => {
      useUiStore.getState().switchTab(0);
      useLogStore.getState().setOpenFilePath("/logs/healthy.log");
    });
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
    expect(screen.getByText("log content")).toBeTruthy();
  });

  it("recovers when closing the failed file in the log-only workspace", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    useUiStore.getState().setEnabledWorkspaces(["log"]);
    useLogStore.getState().setOpenFilePath("/logs/broken.log");
    useUiStore.getState().openTab("/logs/broken.log", "broken.log");
    render(<AppShell />);
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");

    await act(async () => useUiStore.getState().closeTab(0));

    expect(useUiStore.getState().activeView).toBe("log");
    expect(useUiStore.getState().openTabs).toHaveLength(0);
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
    expect(screen.getByText("log content")).toBeTruthy();
  });

  it("loads a healthy successor when closing the failed first tab", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(logSource.switchToTab).mockImplementation(async (filePath) => {
      // Model completion of the native file read after tab selection.
      await Promise.resolve();
      useLogStore.getState().setOpenFilePath(filePath);
    });
    useUiStore.getState().setEnabledWorkspaces(["log"]);
    useUiStore.getState().openTab("/logs/broken.log", "broken.log");
    useUiStore.getState().openTab("/logs/healthy.log", "healthy.log");
    useUiStore.getState().switchTab(0);
    useLogStore.getState().setOpenFilePath("/logs/broken.log");
    await act(async () => { render(<AppShell />); });
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");

    await act(async () => useUiStore.getState().closeTab(0));

    expect(useUiStore.getState().activeView).toBe("log");
    expect(useUiStore.getState().activeTabIndex).toBe(0);
    expect(useLogStore.getState().openFilePath).toBe("/logs/healthy.log");
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
    expect(screen.getByText("log content")).toBeTruthy();
  });

  it("recovers when registry data arrives after the selected file changes", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const registryData = {
      keys: [], filePath: "/logs/broken.reg", fileSize: 0,
      totalKeys: 0, totalValues: 0, parseErrors: 0,
    };
    useRegistryStore.getState().setRegistryData(registryData);
    useUiStore.getState().setEnabledWorkspaces(["log"]);
    useUiStore.getState().openTab("/logs/healthy.reg", "healthy.reg", null, "registry");
    useUiStore.getState().openTab("/logs/broken.reg", "broken.reg", null, "registry");
    useLogStore.getState().setOpenFilePath("/logs/broken.reg");
    render(<AppShell />);
    expect(screen.getByRole("alert").textContent).toContain("registry rendering failed");

    await act(async () => {
      useUiStore.getState().switchTab(0);
      // Registry tab loading publishes the path before awaiting its data.
      useLogStore.getState().setOpenFilePath("/logs/healthy.reg");
    });
    expect(screen.getByRole("alert").textContent).toContain("registry rendering failed");
    await act(async () => {
      useRegistryStore.getState().setRegistryData({ ...registryData, filePath: "/logs/healthy.reg" });
    });

    expect(useUiStore.getState().activeView).toBe("log");
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
    expect(screen.getByText("registry content")).toBeTruthy();
  });

  it("keeps the macOS JAMF workspace active when a log opens from its log list", async () => {
    useUiStore.getState().setActiveWorkspace("macos-jamf");
    render(<AppShell />);

    // A file selected in the workspace's own log list loads it and opens a tab.
    await act(async () => {
      useUiStore
        .getState()
        .openTab("/var/log/jamf/install.log", "install.log");
    });

    const state = useUiStore.getState();
    expect(state.openTabs).toHaveLength(1);
    expect(state.activeWorkspace).toBe("macos-jamf");
    expect(state.activeView).toBe("macos-jamf");
  });
});
