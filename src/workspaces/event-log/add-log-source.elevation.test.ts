/**
 * An Access Denied "Add log source" must come back as a TEXT LOG after the elevated restart.
 *
 * The restore ticket names the workspace that was active, and the elevated process opens the
 * target through that workspace's own handler. Event Logs' handler opens EVTX, so a ticket that
 * said "event-log" reopened a text-log folder as an .evtx search and a text-log file as an EVTX
 * parse. These tests run the real helper, the real loaders and the real offer, mint the ticket the
 * backend would store from the request, and feed it through `restoreElevatedSource`.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RestoreTicket } from "../../types/elevation";
import type { LogEntry, ParseResult } from "../../types/log";

const commands = vi.hoisted(() => ({ overrides: {} as Record<string, ReturnType<typeof vi.fn>> }));
const dialog = vi.hoisted(() => ({ open: vi.fn() }));
const eventLog = vi.hoisted(() => ({ openEventLogSource: vi.fn() }));
const elevation = vi.hoisted(() => ({ readElevationState: vi.fn() }));

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
vi.mock("../../lib/elevation", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/elevation")>()),
  readElevationState: elevation.readElevationState,
}));
vi.mock("@tauri-apps/plugin-dialog", () => dialog);
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
// Event Logs' handler imports this lazily; a spy tells an EVTX open from a text-log open.
vi.mock("./open-event-log-source", () => eventLog);

import { restoreElevatedSource } from "../../hooks/use-file-association";
import { resetElevationCoordinatorForTests } from "../../lib/elevation";
import { resetElevationRecoveryForTests } from "../../lib/elevation-recovery";
import { recordAccessDenied } from "../../lib/source-error";
import { clearAllTabSnapshots } from "../../lib/tab-snapshot-cache";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { addLogSource } from "./add-log-source";

const FILE = "C:\\Windows\\CCM\\Logs\\AppEnforce.log";
const FOLDER = "C:\\Windows\\CCM\\Logs";

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

function denied(path: string): Error {
  const error = new Error("Access to this path was denied by Windows.");
  recordAccessDenied(error, {
    kind: "accessDenied",
    operation: "readFile",
    path,
    message: "Access to this path was denied by Windows.",
  });
  return error;
}

/** The ticket the backend stores for the request the offer opened, as the elevated process reads it. */
function ticketFor(request: NonNullable<ReturnType<typeof useUiStore.getState>["elevationPrompt"]>["request"]): RestoreTicket {
  return {
    schemaVersion: 1,
    ticketId: "1487dc30-3bb0-46bf-98ee-76771bd9953e",
    createdAtMs: 1_760_000_000_000,
    originPid: 1234,
    workspace: request.workspace,
    target: request.target,
    reason: request.reason,
    retryAttempted: true,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  resetElevationRecoveryForTests();
  resetElevationCoordinatorForTests();
  useLogStore.getState().clear();
  clearAllTabSnapshots();
  useUiStore.setState(useUiStore.getInitialState(), true);
  useUiStore.setState({ currentPlatform: "windows" });
  elevation.readElevationState.mockResolvedValue({ platformSupported: true, isElevated: false });
  commands.overrides.stopTail.mockResolvedValue(undefined);
});

/** Adds from Event Logs and returns the ticket the Access Denied offer produced. */
async function deniedAddFromEventLogs(kind: "file" | "folder"): Promise<RestoreTicket> {
  useUiStore.getState().setActiveWorkspace("event-log");
  expect(useUiStore.getState().activeWorkspace).toBe("event-log");
  if (kind === "file") {
    dialog.open.mockResolvedValue([FILE]);
    commands.overrides.openLogSourceFile.mockRejectedValueOnce(denied(FILE));
  } else {
    dialog.open.mockResolvedValue(FOLDER);
    commands.overrides.listLogSourceFolder.mockRejectedValueOnce(denied(FOLDER));
  }

  const outcome = await addLogSource(kind);
  expect(outcome.status).toBe("failed");

  // The offer is fire and forget: it opens the confirmation after the probe answers.
  await vi.waitFor(() => expect(useUiStore.getState().elevationPrompt).not.toBeNull());
  return ticketFor(useUiStore.getState().elevationPrompt!.request);
}

describe("a denied add from Event Logs", () => {
  it.each([
    ["file", { kind: "file", path: FILE }],
    ["folder", { kind: "folder", path: FOLDER }],
  ] as const)("records a ticket that reopens the %s as a text log in the Log workspace", async (kind, target) => {
    const ticket = await deniedAddFromEventLogs(kind);

    expect(ticket.workspace).toBe("log");
    expect(ticket.target).toEqual(target);
  });

  it("is reopened by the text-log loader, never by the EVTX open path, when the ticket is restored", async () => {
    const ticket = await deniedAddFromEventLogs("file");

    // The elevated process: a fresh start, the source readable now.
    useLogStore.getState().clear();
    clearAllTabSnapshots();
    useUiStore.setState(useUiStore.getInitialState(), true);
    commands.overrides.openLogSourceFile.mockImplementation(async (source: { path: string }) =>
      parsed(source.path),
    );
    const clearFilter = vi.fn();

    await restoreElevatedSource(ticket, clearFilter);

    expect(commands.overrides.openLogSourceFile).toHaveBeenCalledWith({ kind: "file", path: FILE });
    expect(eventLog.openEventLogSource).not.toHaveBeenCalled();
    expect(useUiStore.getState().activeWorkspace).toBe("log");
    expect(useLogStore.getState().entries.map((e) => e.filePath)).toEqual([FILE, FILE]);
    expect(clearFilter).toHaveBeenCalledTimes(1);
  });

  it("reopens a folder as a text-log folder too", async () => {
    const ticket = await deniedAddFromEventLogs("folder");

    useLogStore.getState().clear();
    clearAllTabSnapshots();
    useUiStore.setState(useUiStore.getInitialState(), true);
    commands.overrides.listLogSourceFolder.mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: FOLDER },
      entries: [{ name: "AppEnforce.log", path: FILE, isDir: false, sizeBytes: 1, modifiedUnixMs: null }],
      bundleMetadata: null,
    });
    commands.overrides.parseFilesBatch.mockImplementation(async (paths: string[]) => paths.map(parsed));

    await restoreElevatedSource(ticket, vi.fn());

    expect(commands.overrides.listLogSourceFolder).toHaveBeenLastCalledWith({
      kind: "folder",
      path: FOLDER,
    });
    expect(eventLog.openEventLogSource).not.toHaveBeenCalled();
    expect(useLogStore.getState().sourceOpenMode).toBe("aggregate-folder");
  });

  it("control: a ticket that names Event Logs is reopened by the EVTX open path", async () => {
    // What the old ticket did. It shows this harness can tell the two paths apart, which is what
    // gives the two tests above their meaning.
    const ticket = { ...(await deniedAddFromEventLogs("file")), workspace: "event-log" as const };
    useUiStore.setState(useUiStore.getInitialState(), true);
    commands.overrides.openLogSourceFile.mockClear();

    await restoreElevatedSource(ticket, vi.fn());

    expect(eventLog.openEventLogSource).toHaveBeenCalledWith({ kind: "file", path: FILE });
    expect(commands.overrides.openLogSourceFile).not.toHaveBeenCalled();
  });
});
