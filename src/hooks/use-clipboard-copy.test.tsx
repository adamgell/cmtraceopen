import { cleanup, fireEvent, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import type { LogEntry, WorkspaceId } from "../types/log";
import { useKeyboard } from "./use-keyboard";
import { useClipboardHistoryMirror } from "./use-clipboard-history-mirror";

const clipboardMocks = vi.hoisted(() => ({
  writeText: vi.fn(async () => undefined),
}));

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

vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: clipboardMocks.writeText,
}));

vi.mock("./use-app-actions", () => ({
  useAppActions: () => actionMocks.current,
}));

function makeEntry(overrides: Partial<LogEntry> & { id: number }): LogEntry {
  return {
    lineNumber: overrides.id,
    message: `message ${overrides.id}`,
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
    ...overrides,
  };
}

function stubSelection(text: string) {
  vi.spyOn(window, "getSelection").mockReturnValue({
    toString: () => text,
  } as Selection);
}

beforeEach(() => {
  vi.clearAllMocks();
  stubSelection("");
  useUiStore.setState({
    currentPlatform: "windows",
    showFindBar: false,
    showFilterDialog: false,
    showErrorLookupDialog: false,
    showAboutDialog: false,
    showSettingsDialog: false,
    showEvidenceBundleDialog: false,
    showFileAssociationPrompt: false,
    elevationPrompt: null,
  });
  useLogStore.getState().clear();
  useLogStore
    .getState()
    .setEntries([
      makeEntry({ id: 1, message: "alpha beta gamma", component: "CcmExec" }),
    ]);
  useLogStore.getState().selectEntry(1);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("useKeyboard Ctrl+C fallback (#520)", () => {
  it("copies the whole selected entry when no text is selected", () => {
    renderHook(() => useKeyboard());

    const notPrevented = fireEvent.keyDown(window, { key: "c", ctrlKey: true });

    expect(notPrevented).toBe(false);
    expect(clipboardMocks.writeText).toHaveBeenCalledWith(
      "alpha beta gamma\tCcmExec\t\t"
    );
  });

  it("steps aside for a live text selection so the native copy takes it", () => {
    stubSelection("beta");
    renderHook(() => useKeyboard());

    const notPrevented = fireEvent.keyDown(window, { key: "c", ctrlKey: true });

    // Default must NOT be prevented: the WebView's own copy handles the
    // selection, and the history mirror re-writes it through the plugin.
    expect(notPrevented).toBe(true);
    expect(clipboardMocks.writeText).not.toHaveBeenCalled();
  });

  it("still copies the whole entry when the selection is only whitespace", () => {
    stubSelection("   ");
    renderHook(() => useKeyboard());

    fireEvent.keyDown(window, { key: "c", ctrlKey: true });

    expect(clipboardMocks.writeText).toHaveBeenCalledWith(
      "alpha beta gamma\tCcmExec\t\t"
    );
  });
});

describe("useClipboardHistoryMirror (#520)", () => {
  // The hook defers its write with setTimeout so the native copy lands first, so the two tests
  // that assert a write have to let that timer run. The negative cases below need no timer: they
  // assert the write never happens, and a pending timer would not change that.
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("mirrors a native copy of a DOM selection through the clipboard plugin", () => {
    stubSelection("part of the message");
    renderHook(() => useClipboardHistoryMirror());

    fireEvent.copy(document.body);
    vi.runAllTimers();

    expect(clipboardMocks.writeText).toHaveBeenCalledWith("part of the message");
  });

  it("mirrors the selected range of an input element", () => {
    renderHook(() => useClipboardHistoryMirror());

    const input = document.createElement("input");
    input.value = "search term";
    document.body.appendChild(input);
    input.setSelectionRange(0, 6);

    fireEvent.copy(input);
    vi.runAllTimers();

    expect(clipboardMocks.writeText).toHaveBeenCalledWith("search");
    input.remove();
  });

  it("leaves copies alone when an app handler already owns the event", () => {
    stubSelection("owned elsewhere");
    renderHook(() => useClipboardHistoryMirror());

    // jsdom has no ClipboardEvent constructor; the handler only reads
    // defaultPrevented and target, so a plain Event exercises the same path.
    const event = new Event("copy", {
      bubbles: true,
      cancelable: true,
    });
    event.preventDefault();
    document.body.dispatchEvent(event);

    expect(clipboardMocks.writeText).not.toHaveBeenCalled();
  });

  it("does nothing when nothing is selected", () => {
    renderHook(() => useClipboardHistoryMirror());

    fireEvent.copy(document.body);

    expect(clipboardMocks.writeText).not.toHaveBeenCalled();
  });

  it("is inert off Windows, where no clipboard history consumes the mirror", () => {
    useUiStore.setState({ currentPlatform: "macos" });
    stubSelection("mac selection");
    renderHook(() => useClipboardHistoryMirror());

    fireEvent.copy(document.body);

    expect(clipboardMocks.writeText).not.toHaveBeenCalled();
  });
});
