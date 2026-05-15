import { render, screen, waitFor } from "@testing-library/react";
import { getVersion } from "@tauri-apps/api/app";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getUpdatePolicy } from "../../../lib/commands";
import { useUiStore } from "../../../stores/ui-store";
import { UpdatesTab } from "./UpdatesTab";

vi.mock("@tauri-apps/api/app", () => ({
  getVersion: vi.fn(),
}));

vi.mock("../../../lib/commands", () => ({
  getUpdatePolicy: vi.fn(),
}));

const getVersionMock = vi.mocked(getVersion);
const getUpdatePolicyMock = vi.mocked(getUpdatePolicy);

describe("UpdatesTab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    getVersionMock.mockResolvedValue("1.3.1");
    getUpdatePolicyMock.mockResolvedValue({
      updateChecksDisabledByPolicy: false,
    });
    useUiStore.setState({
      autoUpdateEnabled: useUiStore.getInitialState().autoUpdateEnabled,
    });
  });

  it("shows startup update checks disabled by default", async () => {
    render(<UpdatesTab />);

    const checkbox = screen.getByRole("checkbox", {
      name: /check for updates on startup/i,
    });

    expect(checkbox).not.toBeChecked();
    await expect(screen.findByText("CMTrace Open v1.3.1")).resolves.toBeVisible();
    expect(await screen.findByText("Stable channel")).toBeVisible();
  });

  it("marks nightly prerelease builds as the nightly channel", async () => {
    getVersionMock.mockResolvedValue("1.3.2-nightly.20260514.42.gabc123def456");

    render(<UpdatesTab />);

    await expect(
      screen.findByText("CMTrace Open v1.3.2-nightly.20260514.42.gabc123def456")
    ).resolves.toBeVisible();
    expect(screen.getByText("Nightly channel")).toBeVisible();
  });

  it("disables the startup checkbox when update checks are policy-disabled", async () => {
    getUpdatePolicyMock.mockResolvedValue({
      updateChecksDisabledByPolicy: true,
    });
    useUiStore.setState({ autoUpdateEnabled: true });

    render(<UpdatesTab />);

    const checkbox = screen.getByRole("checkbox", {
      name: /check for updates on startup/i,
    });

    await waitFor(() => expect(checkbox).toBeDisabled());
    expect(checkbox).toBeChecked();
    expect(
      screen.getByText("Update checks are disabled by managed policy on this device.")
    ).toBeVisible();
  });
});
