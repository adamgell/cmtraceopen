import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { StatusBar } from "./StatusBar";
import { useUiStore } from "../../stores/ui-store";
import { useDeploymentStore } from "../../workspaces/deployment/deployment-store";

describe("StatusBar deployment coverage", () => {
  beforeEach(() => {
    useUiStore.setState({ ...useUiStore.getInitialState(), activeView: "deployment" }, true);
    useDeploymentStore.getState().reset();
  });

  afterEach(() => {
    cleanup();
    useDeploymentStore.getState().reset();
    useUiStore.setState(useUiStore.getInitialState(), true);
  });

  it.each([
    [[], "No deployment logs found"],
    [["Directory depth budget of 32 was exhausted."], "Scan incomplete"],
  ])("describes empty coverage with limitations %j", (limitations, expected) => {
    useDeploymentStore.setState({
      phase: "empty",
      result: {
        folderPath: "C:\\Logs", files: [], totalFiles: 0,
        succeeded: 0, failed: 0, deferred: 0, unknown: 0, limitations,
      },
    });
    render(<StatusBar />);
    expect(screen.getByText(`Software Deployment • ${expected}`)).toBeInTheDocument();
    if (limitations.length > 0) {
      expect(screen.queryByText(/No deployment logs found/)).not.toBeInTheDocument();
    }
  });
});
