import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
    useLogStore.getState().clear();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ currentPlatform: "macos" });
  });

  afterEach(() => {
    cleanup();
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
