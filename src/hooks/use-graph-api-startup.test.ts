import { describe, expect, it, vi } from "vitest";
import type { GraphAuthStatus } from "../lib/commands";
import {
  connectAndPopulate,
  type GraphStartupDependencies,
} from "./use-graph-api-startup";

const partialStatusWithoutApps = (): GraphAuthStatus => ({
  isAuthenticated: true,
  userPrincipalName: "user@contoso.example",
  tenantId: "tenant-a",
  grantedScopes: ["DeviceManagementManagedDevices.Read.All"],
  missingScopes: [
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementScripts.Read.All",
  ],
  expiresAt: 2_000_000_000,
  capabilities: {
    managedDevices: true,
    serviceConfig: false,
    apps: false,
    configuration: false,
    scripts: false,
  },
  error: null,
});

describe("Graph API persisted startup", () => {
  it("keeps partial authentication connected without requesting the missing Apps capability", async () => {
    const dependencies: GraphStartupDependencies = {
      authenticate: vi.fn().mockResolvedValue(partialStatusWithoutApps()),
      fetchAllApps: vi.fn(),
      mergeApps: vi.fn(),
      setConnectionStatus: vi.fn(),
    };

    await connectAndPopulate(dependencies);

    expect(dependencies.fetchAllApps).not.toHaveBeenCalled();
    expect(dependencies.mergeApps).not.toHaveBeenCalled();
    expect(dependencies.setConnectionStatus).toHaveBeenNthCalledWith(
      1,
      "connecting",
    );
    expect(dependencies.setConnectionStatus).toHaveBeenNthCalledWith(
      2,
      "connected",
    );
  });

  it("keeps authentication connected when optional app-cache hydration fails", async () => {
    const status = partialStatusWithoutApps();
    status.grantedScopes = ["DeviceManagementApps.Read.All"];
    status.missingScopes = [
      "DeviceManagementManagedDevices.Read.All",
      "DeviceManagementServiceConfig.Read.All",
      "DeviceManagementConfiguration.Read.All",
      "DeviceManagementScripts.Read.All",
    ];
    status.capabilities.managedDevices = false;
    status.capabilities.apps = true;
    const dependencies: GraphStartupDependencies = {
      authenticate: vi.fn().mockResolvedValue(status),
      fetchAllApps: vi.fn().mockRejectedValue(new Error("offline")),
      mergeApps: vi.fn(),
      setConnectionStatus: vi.fn(),
    };

    await connectAndPopulate(dependencies);

    expect(dependencies.fetchAllApps).toHaveBeenCalledOnce();
    expect(dependencies.mergeApps).not.toHaveBeenCalled();
    expect(dependencies.setConnectionStatus).toHaveBeenNthCalledWith(
      1,
      "connecting",
    );
    expect(dependencies.setConnectionStatus).toHaveBeenNthCalledWith(
      2,
      "connected",
    );
  });
});
