import { act, cleanup, fireEvent, renderHook, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
  },
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: eventMocks.listen,
}));

vi.mock("./use-app-actions", () => ({
  useAppActions: () => actionMocks.current,
}));

interface TestMenuPayload {
  version: number;
  menu_id: string;
  action: string;
  category: string;
  trigger: string;
  source_id: string | null;
  target_id: string | null;
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
});
