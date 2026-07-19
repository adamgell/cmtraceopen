import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { useFilterStore } from "../stores/filter-store";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import type { LogEntry } from "../types/log";
import { useDsregcmdStore } from "../workspaces/dsregcmd/dsregcmd-store";
import {
  type EspWorkspacePhase,
  useEspDiagnosticsStore,
} from "../workspaces/esp-diagnostics/esp-diagnostics-store";
import { useIntuneStore } from "../workspaces/intune/intune-store";
import { useSysmonStore } from "../workspaces/sysmon/sysmon-store";
import { useAppActions } from "./use-app-actions";

function makeEntry(id: number, message = `message ${id}`): LogEntry {
  return {
    id,
    lineNumber: id,
    message,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Plain",
    filePath: "/test.log",
    timezoneOffset: null,
  };
}

describe("useAppActions", () => {
  beforeEach(() => {
    localStorage.clear();
    useLogStore.getState().clear();
    useFilterStore.getState().clearFilter();
    useIntuneStore.getState().clear();
    useDsregcmdStore.getState().clear();
    useEspDiagnosticsStore.setState(
      useEspDiagnosticsStore.getInitialState(),
      true,
    );
    useSysmonStore.getState().clear();
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
      showDetails: true,
      showInfoPane: true,
      showFindBar: false,
      sidebarCollapsed: false,
      openTabs: [],
      collectionProgress: null,
    });
  });

  it("derives log capabilities, visibility, labels, and guarded actions", () => {
    useLogStore.getState().setEntries([makeEntry(1)]);
    useLogStore
      .getState()
      .setActiveSource({ kind: "file", path: "/test.log" });

    const { result } = renderHook(() => useAppActions());

    expect(result.current.commandState).toMatchObject({
      activeWorkspace: "log",
      canFind: true,
      canPauseResume: true,
      canToggleSidebar: true,
      canToggleDetailsPane: true,
      canToggleInfoPane: true,
      canAdjustTextSize: true,
      canSaveSession: false,
      canCollectDiagnostics: true,
      isSidebarVisible: true,
      isDetailsVisible: true,
      isInfoPaneVisible: true,
      openFileLabel: "Open File…",
      openFolderLabel: "Open Folder…",
    });

    const initialFontSize = useUiStore.getState().logListFontSize;
    act(() => {
      result.current.toggleSidebar();
      result.current.increaseLogListTextSize();
    });

    expect(useUiStore.getState().sidebarCollapsed).toBe(true);
    expect(useUiStore.getState().logListFontSize).toBe(initialFontSize + 1);
  });

  it("disables unsupported pane and text actions in ESP Diagnostics", () => {
    useUiStore.setState({
      activeWorkspace: "esp-diagnostics",
      activeView: "esp-diagnostics",
      sidebarCollapsed: false,
      showDetails: true,
      showInfoPane: true,
    });

    const { result } = renderHook(() => useAppActions());

    expect(result.current.commandState).toMatchObject({
      activeWorkspace: "esp-diagnostics",
      canFind: false,
      canToggleSidebar: false,
      canToggleDetailsPane: false,
      canToggleInfoPane: false,
      canAdjustTextSize: false,
      isSidebarVisible: false,
      isDetailsVisible: false,
      isInfoPaneVisible: false,
      openFileLabel: "Import captured evidence…",
      openFolderLabel: "Import evidence folder…",
    });

    const initialFontSize = useUiStore.getState().logListFontSize;
    act(() => {
      result.current.toggleSidebar();
      result.current.toggleDetailsPane();
      result.current.toggleInfoPane();
      result.current.increaseLogListTextSize();
    });

    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
    expect(useUiStore.getState().showDetails).toBe(true);
    expect(useUiStore.getState().showInfoPane).toBe(true);
    expect(useUiStore.getState().logListFontSize).toBe(initialFontSize);
  });

  it.each<{
    phase: EspWorkspacePhase;
    sessionId: string | null;
    canOpenSources: boolean;
  }>([
    { phase: "idle", sessionId: null, canOpenSources: true },
    { phase: "ready", sessionId: null, canOpenSources: true },
    { phase: "error", sessionId: null, canOpenSources: true },
    { phase: "analyzing", sessionId: null, canOpenSources: false },
    { phase: "starting", sessionId: null, canOpenSources: false },
    { phase: "live", sessionId: null, canOpenSources: false },
    { phase: "stopping", sessionId: null, canOpenSources: false },
    { phase: "idle", sessionId: "session-1", canOpenSources: false },
    { phase: "ready", sessionId: "session-1", canOpenSources: false },
  ])(
    "sets ESP source availability for $phase with session $sessionId",
    ({ phase, sessionId, canOpenSources }) => {
      useUiStore.setState({
        activeWorkspace: "esp-diagnostics",
        activeView: "esp-diagnostics",
      });
      useEspDiagnosticsStore.setState({
        phase,
        sessionId,
        graphPhase: "loading",
      });

      const { result } = renderHook(() => useAppActions());

      expect(result.current.commandState.canOpenSources).toBe(canOpenSources);
      expect(result.current.commandState.isLoading).toBe(!canOpenSources);
    },
  );

  it("does not let background workspace activity disable source commands", () => {
    useIntuneStore.setState({ isAnalyzing: true });
    useEspDiagnosticsStore.setState({ phase: "live", sessionId: "session-1" });
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
    });

    const { result } = renderHook(() => useAppActions());

    expect(result.current.commandState.canOpenSources).toBe(true);
    expect(result.current.commandState.isLoading).toBe(false);
  });

  it("does not expose a stale Log refresh source in unsupported workspaces", async () => {
    useLogStore
      .getState()
      .setActiveSource({ kind: "file", path: "/stale.log" });
    const { result } = renderHook(() => useAppActions());

    const unsupportedWorkspaces = [
      "intune",
      "new-intune",
      "esp-diagnostics",
      "timeline",
      "event-log",
      "deployment",
      "secureboot",
      "dns-dhcp",
      "macos-diag",
    ] as const;

    for (const workspace of unsupportedWorkspaces) {
      act(() => {
        useUiStore.setState({
          activeWorkspace: workspace,
          activeView: workspace,
        });
      });
      expect(result.current.commandState.canRefresh).toBe(false);
    }

    await act(async () => {
      await result.current.refreshActiveSource();
    });
    expect(useUiStore.getState().activeWorkspace).toBe("macos-diag");
  });

  it("enables Refresh only for supported workspaces with their own source", () => {
    const { result } = renderHook(() => useAppActions());

    expect(result.current.commandState.canRefresh).toBe(false);
    act(() => {
      useLogStore
        .getState()
        .setActiveSource({ kind: "file", path: "/test.log" });
    });
    expect(result.current.commandState.canRefresh).toBe(true);

    act(() => {
      useUiStore.setState({
        activeWorkspace: "dsregcmd",
        activeView: "dsregcmd",
      });
    });
    expect(result.current.commandState.canRefresh).toBe(false);

    const dsregcmdSourceContext = useDsregcmdStore.getState().sourceContext;
    act(() => {
      useDsregcmdStore.setState({
        sourceContext: {
          ...dsregcmdSourceContext,
          source: { kind: "file", path: "C:\\dsregcmd.txt" },
        },
      });
    });
    expect(result.current.commandState.canRefresh).toBe(true);

    act(() => {
      useUiStore.setState({
        activeWorkspace: "sysmon",
        activeView: "sysmon",
      });
    });
    expect(result.current.commandState.canRefresh).toBe(false);

    act(() => {
      useSysmonStore.setState({ sourcePath: "C:\\sysmon.evtx" });
    });
    expect(result.current.commandState.canRefresh).toBe(true);
  });

  it("opens Find without a session and otherwise navigates matches", () => {
    useLogStore.getState().setEntries([makeEntry(1), makeEntry(2)]);
    const { result } = renderHook(() => useAppActions());

    act(() => result.current.findNext("test.no-session"));
    expect(useUiStore.getState().showFindBar).toBe(true);

    act(() => {
      useUiStore.setState({ showFindBar: false });
      useLogStore.setState({
        findQuery: "message",
        findMatchIds: [1, 2],
        findCurrentIndex: -1,
        selectedId: null,
      });
    });

    act(() => result.current.findNext("test.next"));
    expect(useLogStore.getState().selectedId).toBe(1);

    act(() => result.current.findPrevious("test.previous"));
    expect(useLogStore.getState().selectedId).toBe(2);
  });

  it("tracks session, collection, and evidence-bundle eligibility", () => {
    const { result } = renderHook(() => useAppActions());
    expect(result.current.commandState.canSaveSession).toBe(false);
    expect(result.current.commandState.canCollectDiagnostics).toBe(true);

    act(() => {
      useUiStore.setState({
        collectionProgress: {
          requestId: "request-1",
          message: "Starting",
          currentItem: null,
          completedItems: 0,
          totalItems: 0,
        },
      });
    });
    expect(result.current.commandState.canCollectDiagnostics).toBe(false);

    const sourceContext = useDsregcmdStore.getState().sourceContext;
    act(() => {
      useDsregcmdStore.setState({
        sourceContext: {
          ...sourceContext,
          bundlePath: "C:\\Evidence",
        },
      });
      useUiStore.setState({
        activeWorkspace: "sysmon",
        activeView: "sysmon",
      });
    });
    expect(result.current.commandState.canShowEvidenceBundle).toBe(false);
    expect(result.current.commandState.canSaveSession).toBe(false);

    act(() => {
      useUiStore.getState().openTab("C:\\test.log", "test.log");
    });
    expect(result.current.commandState.canSaveSession).toBe(true);

    act(() => {
      useUiStore.setState({
        activeWorkspace: "dsregcmd",
        activeView: "dsregcmd",
      });
    });
    expect(result.current.commandState.canShowEvidenceBundle).toBe(true);
  });
});
