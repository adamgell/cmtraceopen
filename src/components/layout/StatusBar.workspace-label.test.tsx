import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// evtx-store subscribes at module load; the log view's listener is not under
// test here.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { StatusBar } from "./StatusBar";
import { useUiStore } from "../../stores/ui-store";

describe("StatusBar workspace label", () => {
  beforeEach(() => {
    useUiStore.setState(useUiStore.getInitialState(), true);
  });

  afterEach(() => {
    cleanup();
  });

  it("labels the macOS JAMF workspace instead of showing its id", () => {
    useUiStore.setState({
      currentPlatform: "macos",
      activeWorkspace: "macos-jamf",
      activeView: "macos-jamf",
    });

    render(<StatusBar />);

    expect(screen.getByText("macOS JAMF")).toBeInTheDocument();
    expect(screen.queryByText("macos-jamf")).not.toBeInTheDocument();
  });
});
