import { act, cleanup, fireEvent, renderHook, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import type { WorkspaceId } from "../types/log";
import { useAppMenu } from "./use-app-menu";
import { useKeyboard } from "./use-keyboard";

const eventMocks = vi.hoisted(() => {
  const state: { callback: unknown } = { callback: null };
  const unlisten = vi.fn();
  const listen = vi.fn(async (_eventName: string, callback: unknown) => {
    state.callback = callback;
    return unlisten;
  });

  return { state, listen, unlisten };
});

const actionMocks = vi.hoisted(() => ({
  current: {
    commandState: {
      canOpenSources: true,
      canOpenKnownSources: true,
      canPauseResume: true,
      canFind: true,
      hasFindSession: false,
      canFilter: true,
      canRefresh: true,
      canToggleSidebar: true,
      canToggleDetailsPane: true,
      canToggleInfoPane: true,
      canAdjustTextSize: true,
      canShowEvidenceBundle: false,
      canSaveSession: false,
      canCollectDiagnostics: true,
      isLoading: false,
      isPaused: false,
      hasActiveSource: true,
      isSidebarVisible: true,
      isDetailsVisible: true,
      isInfoPaneVisible: true,
      activeFilterCount: 0,
      isFiltering: false,
      filterError: null as string | null,
      activeWorkspace: "log" as WorkspaceId,
      openFileLabel: "Open file…",
      openFolderLabel: "Open folder…",
    },
    openSourceFileDialog: vi.fn(async () => undefined),
    openSourceFolderDialog: vi.fn(async () => undefined),
    openKnownSourceCatalogAction: vi.fn(async () => undefined),
    showFindBar: vi.fn(),
    findNext: vi.fn(),
    findPrevious: vi.fn(),
    showFilterDialog: vi.fn(),
    showErrorLookupDialog: vi.fn(),
    showEvidenceBundleDialog: vi.fn(),
    showAboutDialog: vi.fn(),
    showSettingsDialog: vi.fn(),
    togglePauseResume: vi.fn(),
    refreshActiveSource: vi.fn(async () => undefined),
    toggleSidebar: vi.fn(),
    toggleDetailsPane: vi.fn(),
    toggleInfoPane: vi.fn(),
    increaseLogListTextSize: vi.fn(),
    decreaseLogListTextSize: vi.fn(),
    resetLogListTextSize: vi.fn(),
    switchWorkspace: vi.fn(),
    dismissTransientDialogs: vi.fn(),
    openRecentEntry: vi.fn(async () => undefined),
  },
}));

const recentMocks = vi.hoisted(() => ({
  clearRecentEntries: vi.fn(async () => undefined),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: eventMocks.listen,
}));

vi.mock("./use-app-actions", () => ({
  useAppActions: () => actionMocks.current,
}));

vi.mock("../lib/recent-entries", () => ({
  clearRecentEntries: recentMocks.clearRecentEntries,
}));

interface TestMenuPayload {
  version: number;
  menu_id: string;
  action: string;
  category: string;
  trigger: string;
  source_id: string | null;
  target_id: string | null;
  path?: string;
  workspace?: WorkspaceId;
  kind?: "file" | "folder";
}

const initialCommandState = { ...actionMocks.current.commandState };

function expectedMenuState() {
  const state = actionMocks.current.commandState;
  return {
    activeWorkspace: state.activeWorkspace,
    openFileLabel: state.openFileLabel,
    openFolderLabel: state.openFolderLabel,
    canOpenSources: state.canOpenSources,
    canOpenKnownSources: state.canOpenKnownSources,
    canFind: state.canFind,
    hasFindSession: state.hasFindSession,
    canFilter: state.canFilter,
    canPauseResume: state.canPauseResume,
    isPaused: state.isPaused,
    canRefresh: state.canRefresh,
    canToggleSidebar: state.canToggleSidebar,
    isSidebarVisible: state.isSidebarVisible,
    canToggleDetailsPane: state.canToggleDetailsPane,
    isDetailsVisible: state.isDetailsVisible,
    canToggleInfoPane: state.canToggleInfoPane,
    isInfoPaneVisible: state.isInfoPaneVisible,
    canAdjustTextSize: state.canAdjustTextSize,
    canShowEvidenceBundle: state.canShowEvidenceBundle,
    canSaveSession: state.canSaveSession,
    canCollectDiagnostics: state.canCollectDiagnostics,
  };
}

async function emitMenuAction(
  payload: Partial<TestMenuPayload> & Pick<TestMenuPayload, "action">,
) {
  const callback = eventMocks.state.callback as
    | ((event: { payload: TestMenuPayload }) => Promise<void>)
    | null;
  if (!callback) {
    throw new Error("native menu listener was not registered");
  }

  await act(async () => {
    await callback({
      payload: {
        version: 1,
        menu_id: `test.${payload.action}`,
        category: "test",
        trigger: "menu",
        source_id: null,
        target_id: null,
        ...payload,
      },
    });
  });
}

describe("useAppMenu", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(invoke).mockReset().mockResolvedValue(undefined);
    eventMocks.state.callback = null;
    actionMocks.current.commandState = { ...initialCommandState };
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
      currentPlatform: "windows",
      enabledWorkspaces: null,
      showFindBar: false,
      showFilterDialog: false,
      showErrorLookupDialog: false,
      showAboutDialog: false,
      showSettingsDialog: false,
      showEvidenceBundleDialog: false,
      showFileAssociationPrompt: false,
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("projects only native-menu state and serializes updates", async () => {
    let releaseFirstSync: (() => void) | undefined;
    vi.mocked(invoke)
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            releaseFirstSync = resolve;
          }),
      )
      .mockResolvedValue(undefined);

    const { rerender } = renderHook(() => useAppMenu());

    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    expect(invoke).toHaveBeenNthCalledWith(1, "sync_app_menu_state", {
      state: expectedMenuState(),
    });
    expect(
      (vi.mocked(invoke).mock.calls[0]?.[1] as { state: object }).state,
    ).not.toHaveProperty("activeFilterCount");

    actionMocks.current.commandState = {
      ...actionMocks.current.commandState,
      isPaused: true,
      openFileLabel: "Import captured evidence…",
      canToggleInfoPane: false,
      isInfoPaneVisible: false,
    };
    rerender();

    await act(async () => Promise.resolve());
    expect(invoke).toHaveBeenCalledTimes(1);

    await act(async () => {
      releaseFirstSync?.();
      await Promise.resolve();
    });
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(2));
    expect(invoke).toHaveBeenNthCalledWith(2, "sync_app_menu_state", {
      state: expectedMenuState(),
    });
  });

  it("warns once per synchronization failure streak", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    vi.mocked(invoke).mockRejectedValue(new Error("sync unavailable"));
    const { rerender } = renderHook(() => useAppMenu());

    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(warn).toHaveBeenCalledTimes(1));

    actionMocks.current.commandState = {
      ...actionMocks.current.commandState,
      canRefresh: false,
    };
    rerender();
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(2));
    expect(warn).toHaveBeenCalledTimes(1);

    vi.mocked(invoke).mockResolvedValue(undefined);
    actionMocks.current.commandState = {
      ...actionMocks.current.commandState,
      canFilter: false,
    };
    rerender();
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(3));

    vi.mocked(invoke).mockRejectedValue(new Error("sync unavailable again"));
    actionMocks.current.commandState = {
      ...actionMocks.current.commandState,
      canFind: false,
    };
    rerender();
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(4));
    await waitFor(() => expect(warn).toHaveBeenCalledTimes(2));
  });

  it("routes newly exposed menu actions through the shared handlers", async () => {
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    await emitMenuAction({ action: "find_next" });
    await emitMenuAction({ action: "find_previous" });
    await emitMenuAction({ action: "toggle_sidebar" });
    await emitMenuAction({ action: "toggle_pause" });
    await emitMenuAction({ action: "refresh" });
    await emitMenuAction({ action: "toggle_details" });
    await emitMenuAction({ action: "toggle_info_pane" });
    await emitMenuAction({ action: "increase_text_size" });
    await emitMenuAction({ action: "decrease_text_size" });
    await emitMenuAction({ action: "reset_text_size" });

    expect(actionMocks.current.findNext).toHaveBeenCalledWith(
      "native-menu.find-next",
    );
    expect(actionMocks.current.findPrevious).toHaveBeenCalledWith(
      "native-menu.find-previous",
    );
    expect(actionMocks.current.toggleSidebar).toHaveBeenCalledOnce();
    expect(actionMocks.current.togglePauseResume).toHaveBeenCalledOnce();
    expect(actionMocks.current.refreshActiveSource).toHaveBeenCalledOnce();
    expect(actionMocks.current.toggleDetailsPane).toHaveBeenCalledOnce();
    expect(actionMocks.current.toggleInfoPane).toHaveBeenCalledOnce();
    expect(actionMocks.current.increaseLogListTextSize).toHaveBeenCalledOnce();
    expect(actionMocks.current.decreaseLogListTextSize).toHaveBeenCalledOnce();
    expect(actionMocks.current.resetLogListTextSize).toHaveBeenCalledOnce();
  });

  it("validates workspace targets and keeps source and target IDs exclusive", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));

    useUiStore.setState({
      currentPlatform: "windows",
      enabledWorkspaces: ["log", "esp-diagnostics"],
    });
    await emitMenuAction({
      action: "switch_workspace",
      target_id: "esp-diagnostics",
      source_id: null,
    });
    expect(actionMocks.current.switchWorkspace).toHaveBeenCalledWith(
      "esp-diagnostics",
      "menu",
    );

    await emitMenuAction({
      action: "open_known_source",
      source_id: "intune-ime",
      target_id: null,
    });
    expect(
      actionMocks.current.openKnownSourceCatalogAction,
    ).toHaveBeenCalledWith({ sourceId: "intune-ime", trigger: "menu" });

    actionMocks.current.switchWorkspace.mockClear();
    useUiStore.setState({
      currentPlatform: "macos",
      enabledWorkspaces: ["log", "sysmon"],
    });
    await emitMenuAction({
      action: "switch_workspace",
      target_id: "sysmon",
      source_id: null,
    });
    expect(actionMocks.current.switchWorkspace).not.toHaveBeenCalled();
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(2));

    useUiStore.setState({
      currentPlatform: "windows",
      enabledWorkspaces: ["log"],
    });
    await emitMenuAction({
      action: "switch_workspace",
      target_id: "esp-diagnostics",
      source_id: null,
    });
    expect(actionMocks.current.switchWorkspace).not.toHaveBeenCalled();
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(3));
    expect(warn).toHaveBeenCalledWith(
      "[app-menu] rejected unavailable workspace target",
      expect.any(Object),
    );
  });

  it("opens a recent entry in its recorded workspace", async () => {
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    useUiStore.setState({
      currentPlatform: "windows",
      enabledWorkspaces: ["log", "esp-diagnostics"],
    });

    await emitMenuAction({
      action: "open_recent_entry",
      menu_id: "recent.2.a1b2c3d4",
      category: "file",
      target_id: "2",
      path: "/evidence/IME/IntuneManagementExtension.log",
      workspace: "esp-diagnostics",
      kind: "file",
    });

    expect(actionMocks.current.openRecentEntry).toHaveBeenCalledWith(
      "/evidence/IME/IntuneManagementExtension.log",
      "file",
      "esp-diagnostics",
      "menu",
    );
  });

  it("ignores an open_recent_entry payload missing its resolved fields", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    await emitMenuAction({
      action: "open_recent_entry",
      menu_id: "recent.2.a1b2c3d4",
      category: "file",
      target_id: "2",
    });

    expect(actionMocks.current.openRecentEntry).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("rejects a recent entry whose workspace is unavailable on this platform", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    useUiStore.setState({
      currentPlatform: "macos",
      enabledWorkspaces: ["log"],
    });

    await emitMenuAction({
      action: "open_recent_entry",
      menu_id: "recent.0.a1b2c3d4",
      category: "file",
      target_id: "0",
      path: "/evidence/sysmon.evtx",
      workspace: "sysmon",
      kind: "file",
    });

    expect(actionMocks.current.openRecentEntry).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("clears recent entries", async () => {
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    await emitMenuAction({
      action: "clear_recent_entries",
      menu_id: "file.recent.clear",
      category: "file",
    });

    expect(recentMocks.clearRecentEntries).toHaveBeenCalled();
  });

  it("toggles Always on Top and invokes the native pin", async () => {
    useUiStore.setState({ alwaysOnTop: false });
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    await emitMenuAction({ action: "toggle_always_on_top" });

    expect(useUiStore.getState().alwaysOnTop).toBe(true);
    expect(invoke).toHaveBeenCalledWith("set_always_on_top", { enabled: true });
  });

  it("restores Always on Top state when the native pin rejects", async () => {
    const error = new Error("native pin unavailable");
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    useUiStore.setState({ alwaysOnTop: false });
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("sync_app_menu_state", expect.anything()),
    );
    vi.mocked(invoke).mockRejectedValueOnce(error);

    await emitMenuAction({ action: "toggle_always_on_top" });

    expect(useUiStore.getState().alwaysOnTop).toBe(false);
    expect(invoke).toHaveBeenCalledWith("set_always_on_top", { enabled: true });
    expect(consoleError).toHaveBeenCalledWith(
      "[app-menu] failed to handle native menu action",
      expect.objectContaining({
        error,
        payload: expect.objectContaining({ action: "toggle_always_on_top" }),
      }),
    );
  });

  it("opens the Collect Diagnostics dialog from the native menu", async () => {
    useUiStore.setState({ showCollectDiagnosticsDialog: false });
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    await emitMenuAction({ action: "collect_diagnostics" });

    expect(useUiStore.getState().showCollectDiagnosticsDialog).toBe(true);
  });
});

describe("useKeyboard native menu parity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    actionMocks.current.commandState = { ...initialCommandState };
    useUiStore.setState({
      currentPlatform: "macos",
      showFindBar: false,
      showFilterDialog: false,
      showErrorLookupDialog: false,
      showAboutDialog: false,
      showSettingsDialog: false,
      showEvidenceBundleDialog: false,
      showFileAssociationPrompt: false,
    });
  });

  afterEach(() => cleanup());

  it("reserves macOS Command+H for Hide while retaining Control+H for Details", () => {
    renderHook(() => useKeyboard());

    fireEvent.keyDown(window, { key: "h", metaKey: true });
    expect(actionMocks.current.toggleDetailsPane).not.toHaveBeenCalled();

    fireEvent.keyDown(window, { key: "h", ctrlKey: true });
    expect(actionMocks.current.toggleDetailsPane).toHaveBeenCalledOnce();

    actionMocks.current.toggleDetailsPane.mockClear();
    useUiStore.setState({ currentPlatform: "windows" });
    fireEvent.keyDown(window, { key: "h", metaKey: true });
    expect(actionMocks.current.toggleDetailsPane).toHaveBeenCalledOnce();
  });

  it("ignores global shortcuts while the elevation prompt is open", () => {
    useUiStore.setState({
      currentPlatform: "windows",
      elevationPrompt: {
        request: {
          reason: "explicitMenu",
          workspace: "log",
          target: { kind: "workspace" },
        },
      },
    });
    renderHook(() => useKeyboard());

    // The prompt traps focus and dims the app, so a shortcut here would act on
    // content the user can neither see nor reach.
    fireEvent.keyDown(window, { key: "h", ctrlKey: true });
    expect(actionMocks.current.toggleDetailsPane).not.toHaveBeenCalled();

    // Suppressing our handler is not enough: the WebView would still run its
    // own find-in-page or zoom behind the modal.
    expect(
      fireEvent.keyDown(window, { key: "f", ctrlKey: true }),
    ).toBe(false);

    // Plain keys stay untouched, because the dialog's focus trap owns Tab and
    // its own listener owns Escape.
    expect(fireEvent.keyDown(window, { key: "Tab" })).toBe(true);
    expect(fireEvent.keyDown(window, { key: "Escape" })).toBe(true);

    useUiStore.setState({ elevationPrompt: null });
  });

  it("restarts a non-log workspace without dragging a stale source along", async () => {
    useUiStore.setState({ activeWorkspace: "esp-diagnostics" });
    // activeSource survives a workspace switch, so it is still set here even
    // though the user is looking at ESP.
    useLogStore.setState({
      activeSource: { kind: "file", path: "C:\\Logs\\stale.log" },
    });
    renderHook(() => useAppMenu());

    await emitMenuAction({ action: "restart_as_administrator" });

    expect(useUiStore.getState().elevationPrompt?.request).toEqual({
      reason: "explicitMenu",
      workspace: "esp-diagnostics",
      target: { kind: "workspace" },
    });

    useUiStore.setState({ elevationPrompt: null });
  });

  it("leaves a confirmation already on screen alone", async () => {
    useUiStore.setState({ activeWorkspace: "log" });
    renderHook(() => useAppMenu());

    // An Access Denied recovery the user is part-way through.
    const existing = {
      reason: "accessDenied" as const,
      workspace: "log" as const,
      target: { kind: "file" as const, path: "C:\\Windows\\denied.log" },
    };
    useUiStore.getState().setElevationPrompt({ request: existing });

    await emitMenuAction({ action: "restart_as_administrator" });

    // Replacing it would reset the dialog's submitting and failure state
    // mid-flight and discard the source the user was actually recovering.
    expect(useUiStore.getState().elevationPrompt?.request).toEqual(existing);

    useUiStore.setState({ elevationPrompt: null });
  });

  it("restarts the log workspace with the source the user is looking at", async () => {
    useUiStore.setState({ activeWorkspace: "log" });
    useLogStore.setState({
      activeSource: { kind: "file", path: "C:\\Logs\\current.log" },
    });
    renderHook(() => useAppMenu());

    await emitMenuAction({ action: "restart_as_administrator" });

    expect(useUiStore.getState().elevationPrompt?.request).toEqual({
      reason: "explicitMenu",
      workspace: "log",
      target: { kind: "file", path: "C:\\Logs\\current.log" },
    });

    useUiStore.setState({ elevationPrompt: null });
  });
});
