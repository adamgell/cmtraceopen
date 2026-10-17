/**
 * Adding a text log from Event Logs must not move the user out of it.
 *
 * The unit tests on `ensureLogViewVisible` name the seam; this one runs the real helper through the
 * real loaders into a rendered AppShell, because the ejection does not come from the loaders. It
 * comes from AppShell's active-tab effect, which asks for the Log view whenever a tab opens. A test
 * that stopped at the helper would pass while the app still switched workspaces.
 */
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LogEntry, ParseResult } from "../../types/log";

const commands = vi.hoisted(() => ({ overrides: {} as Record<string, ReturnType<typeof vi.fn>> }));
const dialog = vi.hoisted(() => ({ open: vi.fn() }));

vi.mock("../../lib/commands", async (importOriginal) => {
  const original = await importOriginal<typeof import("../../lib/commands")>();
  commands.overrides = {
    getKnownLogSources: vi.fn().mockResolvedValue([]),
    inspectPathKind: vi.fn().mockResolvedValue("file"),
    listLogSourceFolder: vi.fn(),
    openLogFile: vi.fn(),
    openLogSourceFile: vi.fn(),
    parseFilesBatch: vi.fn(),
    parseRegistryFile: vi.fn(),
    stopTail: vi.fn().mockResolvedValue(undefined),
  };
  return { ...original, ...commands.overrides };
});
vi.mock("@tauri-apps/plugin-dialog", () => dialog);

vi.mock("../log-view/LogListView", () => ({ LogListView: () => <div>log content</div> }));
vi.mock("../../workspaces/event-log/EventLogWorkspace", () => ({
  EventLogWorkspace: () => <div>event logs</div>,
}));
vi.mock("../../workspaces/macos-diag/MacosDiagWorkspace", () => ({
  MacosDiagWorkspace: () => <div>macos diagnostics</div>,
}));

// The status bar and workspaces lazily subscribe to native events.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
vi.mock("@tauri-apps/plugin-os", () => ({ platform: () => "macos" }));
vi.mock("@tauri-apps/api/webviewWindow", () => ({
  getCurrentWebviewWindow: () => ({
    onDragDropEvent: vi.fn().mockResolvedValue(() => undefined),
  }),
}));

import { AppShell } from "./AppShell";
import { clearAllTabSnapshots } from "../../lib/tab-snapshot-cache";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { addLogSource } from "../../workspaces/event-log/add-log-source";

function entry(filePath: string, line: number): LogEntry {
  return {
    id: line,
    lineNumber: line,
    message: `line ${line}`,
    component: null,
    timestamp: 1_000 + line,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Ccm",
    filePath,
    timezoneOffset: null,
  };
}

function parsed(filePath: string): ParseResult {
  return {
    entries: [entry(filePath, 1), entry(filePath, 2)],
    formatDetected: "Ccm",
    parserSelection: {
      parser: "ccm",
      implementation: "ccm",
      provenance: "dedicated",
      parseQuality: "structured",
      recordFraming: "physicalLine",
      dateOrder: null,
    },
    totalLines: 2,
    parseErrors: 0,
    filePath,
    fileSize: 1,
    modifiedUnixMs: null,
    byteOffset: 0,
  };
}

const LOG_A = "/var/log/a.log";
const LOG_B = "/var/log/b.log";

describe("adding a text log from the Event Logs channel pane", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        disconnect() {}
      },
    );
    useLogStore.getState().clear();
    clearAllTabSnapshots();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ currentPlatform: "macos" });
    commands.overrides.openLogSourceFile.mockImplementation(async (source: { path: string }) =>
      parsed(source.path),
    );
    commands.overrides.parseFilesBatch.mockImplementation(async (paths: string[]) =>
      paths.map(parsed),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    clearAllTabSnapshots();
  });

  it("keeps Event Logs active when one file opens a tab", async () => {
    useUiStore.getState().setActiveWorkspace("event-log");
    render(<AppShell />);
    dialog.open.mockResolvedValue([LOG_A]);

    let outcome;
    await act(async () => {
      outcome = await addLogSource("file");
    });

    expect(outcome).toEqual({ status: "added", notice: null });
    // The tab opened, so the active-tab effect that asks for the Log view has run.
    expect(useUiStore.getState().openTabs.map((tab) => tab.filePath)).toEqual([LOG_A]);
    expect(useLogStore.getState().entries).toHaveLength(2);
    expect(useUiStore.getState().activeWorkspace).toBe("event-log");
    expect(useUiStore.getState().activeView).toBe("event-log");
  });

  it("keeps Event Logs active when several files load as one aggregate", async () => {
    useUiStore.getState().setActiveWorkspace("event-log");
    render(<AppShell />);
    dialog.open.mockResolvedValue([LOG_A, LOG_B]);

    await act(async () => {
      await addLogSource("file");
    });

    expect(useLogStore.getState().sourceOpenMode).toBe("aggregate-folder");
    expect(useLogStore.getState().entries).toHaveLength(4);
    expect(useUiStore.getState().activeWorkspace).toBe("event-log");
  });

  it("control: the same add from a workspace that keeps no view still opens the Log workspace", async () => {
    // The control. It shows this harness really does eject, which is what gives the two tests
    // above their meaning.
    useUiStore.getState().setActiveWorkspace("macos-diag");
    render(<AppShell />);
    dialog.open.mockResolvedValue([LOG_A]);

    await act(async () => {
      await addLogSource("file");
    });

    expect(useUiStore.getState().openTabs.map((tab) => tab.filePath)).toEqual([LOG_A]);
    expect(useUiStore.getState().activeWorkspace).toBe("log");
  });
});
