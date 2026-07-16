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
      isCurrent: () => true,
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
      isCurrent: () => true,
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

  it("does not reconnect or hydrate apps when Graph is disabled during authentication", async () => {
    let enabled = true;
    let resolveAuthentication!: (status: GraphAuthStatus) => void;
    const status = partialStatusWithoutApps();
    status.capabilities.apps = true;
    const dependencies: GraphStartupDependencies = {
      authenticate: vi.fn().mockReturnValue(
        new Promise((resolve) => {
          resolveAuthentication = resolve;
        }),
      ),
      fetchAllApps: vi.fn(),
      mergeApps: vi.fn(),
      setConnectionStatus: vi.fn(),
      isCurrent: () => enabled,
    };

    const pending = connectAndPopulate(dependencies);
    enabled = false;
    resolveAuthentication(status);
    await pending;

    expect(dependencies.setConnectionStatus).toHaveBeenCalledOnce();
    expect(dependencies.setConnectionStatus).toHaveBeenCalledWith("connecting");
    expect(dependencies.fetchAllApps).not.toHaveBeenCalled();
    expect(dependencies.mergeApps).not.toHaveBeenCalled();
  });

  it("does not merge app data when Graph is disabled during cache hydration", async () => {
    let enabled = true;
    let resolveApps!: (
      apps: Awaited<ReturnType<GraphStartupDependencies["fetchAllApps"]>>,
    ) => void;
    const status = partialStatusWithoutApps();
    status.capabilities.apps = true;
    const dependencies: GraphStartupDependencies = {
      authenticate: vi.fn().mockResolvedValue(status),
      fetchAllApps: vi.fn().mockReturnValue(
        new Promise((resolve) => {
          resolveApps = resolve;
        }),
      ),
      mergeApps: vi.fn(),
      setConnectionStatus: vi.fn(),
      isCurrent: () => enabled,
    };

    const pending = connectAndPopulate(dependencies);
    await vi.waitFor(() =>
      expect(dependencies.fetchAllApps).toHaveBeenCalled(),
    );
    enabled = false;
    resolveApps([
      {
        id: "app-a",
        displayName: "App A",
        publisher: null,
        odataType: "#microsoft.graph.win32LobApp",
      },
    ]);
    await pending;

    expect(dependencies.mergeApps).not.toHaveBeenCalled();
  });
});
