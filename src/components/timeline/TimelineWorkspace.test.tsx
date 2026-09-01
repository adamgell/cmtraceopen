import { cleanup, render, screen } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useTimelineStore } from "../../stores/timeline-store";
import type { TimelineBundle } from "../../types/timeline";
import { TimelineWorkspace } from "./TimelineWorkspace";

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function bundleWithSourceErrors(): TimelineBundle {
  return {
    id: "timeline-with-source-errors",
    sources: [],
    timeRangeMs: [0, 0],
    totalEntries: 0,
    incidents: [],
    deniedGuids: [],
    errors: [
      {
        path: "/tmp/dns-audit.evtx",
        message: "Only DNS audit EVTX files are supported by this parser",
      },
    ],
    tunables: {
      overlapWindowMs: 5_000,
      minSourceCount: 2,
      maxIncidentSpanMs: 60_000,
      enabledSignalKinds: ["errorSeverity"],
    },
  };
}

describe("TimelineWorkspace source errors", () => {
  beforeEach(() => {
    vi.stubGlobal("ResizeObserver", ResizeObserverStub);
    vi.mocked(invoke).mockResolvedValue([]);
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    useTimelineStore.setState({
      bundle: bundleWithSourceErrors(),
      loadError: null,
      laneVisibility: {},
      soloSourceIdx: null,
    });
  });

  afterEach(() => {
    cleanup();
    useTimelineStore.getState().reset();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("keeps backend source failures visible after a bundle is returned", () => {
    render(<TimelineWorkspace />);

    const alert = screen.getByRole("alert", {
      name: "Timeline source errors",
    });
    expect(alert).toHaveTextContent("1 timeline source could not be loaded");
    expect(alert).toHaveTextContent("/tmp/dns-audit.evtx");
    expect(alert).toHaveTextContent(
      "Only DNS audit EVTX files are supported by this parser",
    );
  });
});
