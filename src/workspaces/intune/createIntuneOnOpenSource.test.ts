import { beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeIntuneLogs } from "../../lib/commands";
import { useUiStore } from "../../stores/ui-store";
import { createIntuneOnOpenSource } from "./index";
import { useIntuneStore } from "./intune-store";
import {
  ANALYZED_PATH,
  DIAGNOSTIC,
  GRAPH_GUID_REGISTRY,
  STORY_DOWNLOADS,
  STORY_EVENTS,
  STORY_SOURCE_FILES,
  SUMMARY,
} from "./intune-story-fixtures";

vi.mock("../../lib/commands", () => ({
  analyzeIntuneLogs: vi.fn(),
}));

vi.mock("../../lib/log-source", async () => {
  const actual = await vi.importActual<typeof import("../../lib/log-source")>(
    "../../lib/log-source",
  );
  return {
    ...actual,
    loadLogSource: vi.fn().mockResolvedValue(undefined),
  };
});

const analyzeIntuneLogsMock = vi.mocked(analyzeIntuneLogs);

beforeEach(() => {
  useIntuneStore.getState().clear();
  analyzeIntuneLogsMock.mockReset();
  analyzeIntuneLogsMock.mockResolvedValue({
    events: STORY_EVENTS,
    downloads: STORY_DOWNLOADS,
    summary: SUMMARY,
    diagnostics: [DIAGNOSTIC],
    sourceFile: ANALYZED_PATH,
    sourceFiles: STORY_SOURCE_FILES,
    diagnosticsCoverage: {
      files: [],
      timestampBounds: null,
      hasRotatedLogs: false,
      dominantSource: null,
    },
    diagnosticsConfidence: { level: "Low", score: 0.2, reasons: [] },
    repeatedFailures: [],
    evidenceBundle: null,
    eventLogAnalysis: null,
    guidRegistry: GRAPH_GUID_REGISTRY,
  });
});

describe("INTUNE-009 analyzeIntuneLogs Graph option", () => {
  it("forwards graphApiEnabled and does not include live event logs for a file source", async () => {
    useUiStore.setState({ graphApiEnabled: true });
    const onOpen = createIntuneOnOpenSource("intune");
    if (!onOpen) throw new Error("Intune workspace must expose an open handler");

    await onOpen({ kind: "file", path: "C:/Logs/IME/AppWorkload.log" }, "test.open-file");

    expect(analyzeIntuneLogsMock).toHaveBeenCalledWith(
      "C:/Logs/IME/AppWorkload.log",
      expect.any(String),
      { includeLiveEventLogs: false, graphApiEnabled: true },
    );
  });

  it("includes live event logs only for the known windows-intune-ime-logs source", async () => {
    useUiStore.setState({ graphApiEnabled: false });
    const onOpen = createIntuneOnOpenSource("new-intune");
    if (!onOpen) throw new Error("New Intune workspace must expose an open handler");

    await onOpen(
      {
        kind: "known",
        sourceId: "windows-intune-ime-logs",
        defaultPath: "C:/ProgramData/Microsoft/IntuneManagementExtension/Logs",
        pathKind: "folder",
      },
      "test.known-source",
    );

    expect(analyzeIntuneLogsMock).toHaveBeenCalledWith(
      "C:/ProgramData/Microsoft/IntuneManagementExtension/Logs",
      expect.any(String),
      { includeLiveEventLogs: true, graphApiEnabled: false },
    );
  });
});
