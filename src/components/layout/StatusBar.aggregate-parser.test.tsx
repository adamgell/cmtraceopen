import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workspaces/event-log/evtx-store", () => ({
  useEvtxStore: (selector: (state: {
    records: unknown[];
    sourceMode: string;
    isLoading: boolean;
    loadedChannels: Set<string>;
    loadElapsedMs: number;
  }) => unknown) =>
    selector({
      records: [],
      sourceMode: "idle",
      isLoading: false,
      loadedChannels: new Set(),
      loadElapsedMs: 0,
    }),
}));

import { StatusBar } from "./StatusBar";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { useFilterStore } from "../../stores/filter-store";
import type {
  AggregateSourceFile,
  LogEntry,
  ParserSelectionInfo,
} from "../../types/log";

const DEDICATED_SEMI_STRUCTURED: ParserSelectionInfo = {
  parser: "cbs",
  implementation: "genericTimestamped",
  provenance: "dedicated",
  parseQuality: "semiStructured",
  recordFraming: "logicalRecord",
  dateOrder: null,
};

function aggregateFile(
  filePath: string,
  parserSelection: ParserSelectionInfo,
): AggregateSourceFile {
  return {
    filePath,
    totalLines: 1,
    parseErrors: 0,
    fileSize: 1,
    byteOffset: 1,
    formatDetected: "Timestamped",
    parserSelection,
  };
}

function entry(id: number): LogEntry {
  return {
    id,
    lineNumber: id,
    message: `message ${id}`,
    component: "CBS",
    timestamp: null,
    timestampDisplay: null,
    severity: "Error",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped",
    filePath: "/Windows/Logs/CBS/CBS.log",
    timezoneOffset: null,
  };
}

describe("StatusBar aggregate parser reporting", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
    useFilterStore.setState(useFilterStore.getInitialState(), true);
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ activeView: "log", activeWorkspace: "log" });
    useLogStore.setState({
      sourceOpenMode: "aggregate-folder",
      formatDetected: null,
      parserSelection: null,
      entries: [entry(0), entry(1)],
      totalLines: 2,
      aggregateFiles: [
        aggregateFile("/Windows/Logs/CBS/CBS.log", DEDICATED_SEMI_STRUCTURED),
        aggregateFile("/Windows/Logs/DISM/dism.log", {
          ...DEDICATED_SEMI_STRUCTURED,
          parser: "dism",
        }),
      ],
      sourceStatus: {
        kind: "loaded",
        message: "Loaded 2 files.",
      },
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("reports the parsers behind a merged folder instead of an unknown format", () => {
    // #657: the merged view named no format and no provenance even though every
    // file was read by its dedicated parser.
    const { container } = render(<StatusBar />);
    const text = container.textContent ?? "";

    expect(text).toContain("Timestamped format");
    expect(text).toContain("Dedicated");
    expect(text).toContain("Semi-structured");
    expect(text).toContain("2 parsers");
    expect(text).not.toContain("Unknown format");
  });

  it("names the single parser of a merged folder that holds one file", () => {
    useLogStore.setState({
      aggregateFiles: [
        aggregateFile("/Windows/Logs/CBS/CBS.log", DEDICATED_SEMI_STRUCTURED),
      ],
    });

    const { container } = render(<StatusBar />);

    expect(container.textContent ?? "").toContain("Parser CBS");
  });

  it("reports the merged composition when the files hold no entries", () => {
    // #657: the merged view must not hide its parsers behind a bare load
    // message when every file in it parsed to nothing.
    useLogStore.setState({
      entries: [],
      totalLines: 0,
      sourceStatus: { kind: "loaded", message: "Loaded 2 files." },
    });

    const { container } = render(<StatusBar />);
    const text = container.textContent ?? "";

    expect(text).toContain("Loaded 2 files.");
    expect(text).toContain("Timestamped format");
    expect(text).toContain("Dedicated");
    expect(text).toContain("Semi-structured");
  });
});
