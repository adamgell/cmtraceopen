import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const logRenderer = vi.hoisted(() => ({ throws: false }));
vi.mock("../log-view/LogListView", () => ({
  LogListView: () => {
    if (logRenderer.throws) throw new Error("log rendering failed");
    return <div>log content</div>;
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

describe("AppShell workspace routing", () => {
  beforeEach(() => {
    logRenderer.throws = false;
    useLogStore.getState().clear();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ currentPlatform: "macos" });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("contains a failed log renderer and recovers when switching workspace", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    logRenderer.throws = true;
    render(<AppShell />);
    expect(screen.getByRole("alert").textContent).toContain("log rendering failed");
    await act(async () => useUiStore.getState().setActiveWorkspace("macos-jamf"));
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
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
