import { cleanup, render, screen } from "@testing-library/react";
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

describe("StatusBar folder parse progress", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
    useFilterStore.setState(useFilterStore.getInitialState(), true);
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ activeView: "log", activeWorkspace: "log" });
    useLogStore.getState().setFolderLoadProgress({
      current: 3,
      total: 10,
      currentFile: "AppEnforce.log",
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("shows N of M and the current file while a folder load is in progress", () => {
    render(<StatusBar />);
    expect(screen.getByText(/Parsing 3 of 10 files — AppEnforce.log/)).toBeInTheDocument();
  });
});
