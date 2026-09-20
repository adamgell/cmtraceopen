/**
 * StatusBar event-log preview labeling. Mock Tauri events and the evtx
 * store before importing StatusBar: the workspace stores register event
 * listeners at module scope.
 */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => undefined),
}));

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
import { useUiStore } from "../../stores/ui-store";

describe("StatusBar event-log preview labeling", () => {
  beforeEach(() => {
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ activeView: "event-log", activeWorkspace: "event-log" });
  });

  afterEach(() => {
    cleanup();
  });

  it("labels the event-log status segment and view badge from the registry", () => {
    render(<StatusBar />);

    expect(screen.getByText("Event Log (Preview) • Ready")).toBeInTheDocument();
    expect(screen.getByText("Event Log (Preview)")).toBeInTheDocument();
  });
});
