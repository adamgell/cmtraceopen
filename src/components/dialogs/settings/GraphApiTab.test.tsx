import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  graphAuthenticate,
  graphFetchAllApps,
  graphGetAuthStatus,
  graphSignOut,
  type GraphAuthStatus,
} from "../../../lib/commands";
import { useUiStore } from "../../../stores/ui-store";
import { GraphApiTab } from "./GraphApiTab";

vi.mock("../../../lib/commands", () => ({
  graphAuthenticate: vi.fn(),
  graphFetchAllApps: vi.fn(),
  graphGetAuthStatus: vi.fn(),
  graphSignOut: vi.fn(),
}));

const partialStatus = (apps: boolean): GraphAuthStatus =>
  ({
    isAuthenticated: true,
    userPrincipalName: "user@contoso.example",
    tenantId: "tenant-a",
    grantedScopes: apps ? ["DeviceManagementApps.Read.All"] : [],
    missingScopes: [
      "DeviceManagementManagedDevices.Read.All",
      "DeviceManagementServiceConfig.Read.All",
      ...(apps ? [] : ["DeviceManagementApps.Read.All"]),
      "DeviceManagementConfiguration.Read.All",
      "DeviceManagementScripts.Read.All",
    ],
    expiresAt: 2_000_000_000,
    capabilities: {
      managedDevices: false,
      serviceConfig: false,
      apps,
      configuration: false,
      scripts: false,
    },
    error: null,
  }) as GraphAuthStatus;

describe("GraphApiTab delegated capabilities", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState({
      currentPlatform: "windows",
      graphApiEnabled: true,
    });
    vi.mocked(graphAuthenticate).mockResolvedValue(partialStatus(true));
    vi.mocked(graphFetchAllApps).mockResolvedValue([]);
    vi.mocked(graphSignOut).mockResolvedValue();
  });

  it("shows partial delegated permissions without treating missing sections as disconnected", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));

    render(<GraphApiTab />);

    expect(await screen.findByText("Connected with partial permissions")).toBeVisible();
    expect(screen.getByText("Apps · Available")).toBeVisible();
    expect(screen.getByText("Managed devices · Missing permission")).toBeVisible();
    const capabilities = screen.getByLabelText("Graph delegated capabilities");
    expect(
      within(capabilities).getByText(
        /DeviceManagementManagedDevices\.Read\.All/,
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    ).toBeEnabled();
  });

  it("disables app enrichment when the token lacks app-read capability", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(false));

    render(<GraphApiTab />);

    expect(await screen.findByText("Connected with partial permissions")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    ).toBeDisabled();
    expect(screen.getByText(/App cache requires DeviceManagementApps\.Read\.All/)).toBeVisible();
  });
});
