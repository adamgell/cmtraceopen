import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { StrictMode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  graphAuthenticate,
  graphCancelAuthentication,
  graphFetchAllApps,
  graphGetAuthStatus,
  graphProbeCapability,
  graphRequestMissingPermissions,
  graphSignOut,
  type GraphAuthStatus,
  type GraphAuthAttemptOutcome,
  type GraphAuthAttemptResult,
  type GraphPermissionUpgradeOutcome,
  type GraphPermissionUpgradeResult,
} from "../../../lib/commands";
import { useUiStore } from "../../../stores/ui-store";
import { useIntuneStore } from "../../../workspaces/intune/intune-store";
import { GraphApiTab } from "./GraphApiTab";

vi.mock("../../../lib/commands", () => ({
  graphAuthenticate: vi.fn(),
  graphCancelAuthentication: vi.fn(),
  graphFetchAllApps: vi.fn(),
  graphGetAuthStatus: vi.fn(),
  graphProbeCapability: vi.fn(),
  graphRequestMissingPermissions: vi.fn(),
  graphSignOut: vi.fn(),
}));

const GRAPH_SCOPES = [
  "DeviceManagementManagedDevices.Read.All",
  "DeviceManagementServiceConfig.Read.All",
  "DeviceManagementApps.Read.All",
  "DeviceManagementConfiguration.Read.All",
  "DeviceManagementScripts.Read.All",
];

const partialStatus = (apps: boolean): GraphAuthStatus =>
  ({
    isAuthenticated: true,
    userPrincipalName: "user@contoso.example",
    objectId: "00000000-0000-0000-0000-0000000000a1",
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
  }) as GraphAuthStatus;

const disconnectedStatus = (): GraphAuthStatus => ({
  isAuthenticated: false,
  userPrincipalName: null,
  objectId: null,
  tenantId: null,
  grantedScopes: [],
  missingScopes: [
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementScripts.Read.All",
  ],
  expiresAt: null,
  capabilities: {
    managedDevices: false,
    serviceConfig: false,
    apps: false,
    configuration: false,
    scripts: false,
  },
});

const fullStatus = (): GraphAuthStatus => ({
  ...partialStatus(true),
  grantedScopes: GRAPH_SCOPES,
  missingScopes: [],
  capabilities: {
    managedDevices: true,
    serviceConfig: true,
    apps: true,
    configuration: true,
    scripts: true,
  },
});

const permissionResult = (
  outcome: GraphPermissionUpgradeOutcome,
  status: GraphAuthStatus = partialStatus(true),
  message: string | null = null,
): GraphPermissionUpgradeResult => ({ outcome, status, message });

const authResult = (
  status: GraphAuthStatus,
  outcome: GraphAuthAttemptOutcome = status.isAuthenticated
    ? "connected"
    : "cancelled",
  message: string | null = null,
): GraphAuthAttemptResult => ({
  outcome,
  status,
  capability: { kind: "available" },
  message,
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

describe("GraphApiTab delegated capabilities", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    useUiStore.setState({
      currentPlatform: "windows",
      graphApiEnabled: true,
      graphApiStatus: "disconnected",
      graphApiCapability: null,
      graphApiLastAttempt: null,
    });
    useIntuneStore.setState({ guidRegistry: {} });
    vi.mocked(graphProbeCapability).mockResolvedValue({ kind: "available" });
    vi.mocked(graphCancelAuthentication).mockResolvedValue(true);
    vi.mocked(graphAuthenticate).mockResolvedValue(authResult(partialStatus(true)));
    vi.mocked(graphFetchAllApps).mockResolvedValue([]);
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("unchanged"),
    );
    vi.mocked(graphSignOut).mockResolvedValue();
  });

  it("shows partial delegated permissions without treating missing sections as disconnected", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));

    render(<GraphApiTab />);

    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(screen.getByText("Apps · Available")).toBeVisible();
    expect(
      screen.getByText("Managed devices · Missing permission"),
    ).toBeVisible();
    const capabilities = screen.getByLabelText("Graph delegated capabilities");
    expect(
      within(capabilities).getByText(
        /DeviceManagementManagedDevices\.Read\.All/,
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Request missing permissions" }),
    ).toBeEnabled();
    expect(
      screen.getAllByRole("button").map((button) => button.textContent),
    ).toEqual([
      "Request missing permissions",
      "Pre-populate app cache",
      "Sign out",
    ]);
    expect(graphRequestMissingPermissions).not.toHaveBeenCalled();
  });

  it.each([
    { name: "full", status: fullStatus(), label: "Connected" },
    {
      name: "disconnected",
      status: disconnectedStatus(),
      label: "Not connected",
    },
  ])(
    "hides the permission action for a $name status",
    async ({ status, label }) => {
      vi.mocked(graphGetAuthStatus).mockResolvedValue(status);

      render(<GraphApiTab />);

      expect(await screen.findByText(label)).toBeVisible();
      expect(
        screen.queryByRole("button", { name: "Request missing permissions" }),
      ).not.toBeInTheDocument();
      expect(graphRequestMissingPermissions).not.toHaveBeenCalled();
    },
  );

  it("requests permissions once and locks authenticated Graph actions while WAM is pending", async () => {
    const request = deferred<GraphPermissionUpgradeResult>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockReturnValue(request.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    await waitFor(() =>
      expect(graphRequestMissingPermissions).toHaveBeenCalledOnce(),
    );
    const requestingButton = screen.getByRole("button", {
      name: "Requesting permissions...",
    });
    expect(requestingButton).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeDisabled();
    expect(screen.getByRole("checkbox")).toBeEnabled();
    expect(useUiStore.getState().graphApiStatus).toBe("connected");

    fireEvent.click(requestingButton);
    expect(graphRequestMissingPermissions).toHaveBeenCalledOnce();

    await act(async () => {
      request.resolve(permissionResult("unchanged"));
      await request.promise;
    });
  });

  it("keeps initial sign-in locked while its Graph action is pending", async () => {
    const authentication = deferred<GraphAuthAttemptResult>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockReturnValue(authentication.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );

    expect(
      await screen.findByRole("button", { name: "Cancel sign-in" }),
    ).toBeEnabled();
    expect(graphRequestMissingPermissions).not.toHaveBeenCalled();

    await act(async () => {
      authentication.resolve(authResult(partialStatus(true)));
      await authentication.promise;
    });
  });

  it("publishes a full permission upgrade and removes the permission action", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(false));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("upgraded", fullStatus()),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    expect(
      await screen.findByRole("status", {
        name: "Permissions updated. Additional Graph capabilities are now available.",
      }),
    ).toBeVisible();
    expect(screen.getByText("Managed devices · Available")).toBeVisible();
    expect(screen.getByText("Scripts · Available")).toBeVisible();
    expect(screen.getByText("Connected")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Request missing permissions" }),
    ).not.toBeInTheDocument();
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });

  it("publishes an improved partial upgrade and keeps the permission action", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(false));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("upgraded", partialStatus(true)),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    expect(
      await screen.findByRole("status", {
        name: "Permissions updated. Additional Graph capabilities are now available.",
      }),
    ).toBeVisible();
    expect(screen.getByText("Apps · Available")).toBeVisible();
    expect(
      screen.getByText("Managed devices · Missing permission"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Request missing permissions" }),
    ).toBeEnabled();
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });

  it.each([
    {
      outcome: "unchanged" as const,
      role: "status" as const,
      guidance:
        "No additional permissions were granted. A tenant administrator may need to approve the missing permissions.",
    },
    {
      outcome: "cancelled" as const,
      role: "status" as const,
      guidance:
        "Permission request cancelled. Your existing Graph permissions are unchanged.",
    },
    {
      outcome: "denied" as const,
      role: "alert" as const,
      guidance:
        "Consent was not granted. Your existing Graph permissions remain available. A tenant administrator may need to approve the missing permissions.",
    },
    {
      outcome: "failed" as const,
      role: "alert" as const,
      guidance:
        "Windows could not complete the permission request. Your existing Graph permissions remain available.",
    },
  ])(
    "retains the partial connection and shows exact $outcome guidance",
    async ({ outcome, role, guidance }) => {
      vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
      vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
        permissionResult(outcome),
      );

      render(<GraphApiTab />);

      fireEvent.click(
        await screen.findByRole("button", {
          name: "Request missing permissions",
        }),
      );

      expect(await screen.findByRole(role, { name: guidance })).toBeVisible();
      expect(
        screen.getByText("Connected with partial permissions"),
      ).toBeVisible();
      expect(screen.getByText("Apps · Available")).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Request missing permissions" }),
      ).toBeEnabled();
      expect(useUiStore.getState().graphApiStatus).toBe("connected");
    },
  );

  it("shows deterministic stale guidance for a current structured stale result", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("stale"),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    expect(
      await screen.findByRole("alert", {
        name: "The permission request was superseded by a newer Graph connection change.",
      }),
    ).toBeVisible();
    expect(
      screen.getByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });

  it("publishes the authoritative disconnected status from a structured stale result", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("stale", disconnectedStatus()),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    expect(
      await screen.findByRole("alert", {
        name: "The permission request was superseded by a newer Graph connection change.",
      }),
    ).toBeVisible();
    expect(screen.getByText("Not connected")).toBeVisible();
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it.each(["denied", "failed", "stale"] as const)(
    "prefers non-empty sanitized native guidance for %s results",
    async (outcome) => {
      const nativeGuidance = `Sanitized native ${outcome} guidance.`;
      vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
      vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
        permissionResult(outcome, partialStatus(true), nativeGuidance),
      );

      render(<GraphApiTab />);

      fireEvent.click(
        await screen.findByRole("button", {
          name: "Request missing permissions",
        }),
      );

      expect(
        await screen.findByRole("alert", { name: nativeGuidance }),
      ).toBeVisible();
      expect(useUiStore.getState().graphApiStatus).toBe("connected");
    },
  );

  it("retains prior state and uses sanitized fallback copy when permission reconciliation fails", async () => {
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(partialStatus(true))
      .mockRejectedValueOnce(
        new Error("secret-token-shaped reconciliation payload"),
      );
    vi.mocked(graphRequestMissingPermissions).mockRejectedValue(
      new Error("secret-token-shaped provider payload"),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    expect(
      await screen.findByRole("alert", {
        name: "Windows could not complete the permission request. Your existing Graph permissions remain available.",
      }),
    ).toBeVisible();
    expect(
      screen.queryByText("secret-token-shaped provider payload"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("secret-token-shaped reconciliation payload"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(graphGetAuthStatus).toHaveBeenCalledTimes(2);
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });

  it("reconciles a rejected permission request to authoritative disconnected state", async () => {
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(partialStatus(true))
      .mockResolvedValueOnce(disconnectedStatus());
    vi.mocked(graphRequestMissingPermissions).mockRejectedValue(
      new Error("secret-token-shaped expired-state payload"),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    expect(await screen.findByText("Not connected")).toBeVisible();
    expect(
      screen.getByRole("alert", {
        name: "Microsoft Graph is no longer connected. Sign in again to request permissions.",
      }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Request missing permissions" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("secret-token-shaped expired-state payload"),
    ).not.toBeInTheDocument();
    expect(graphGetAuthStatus).toHaveBeenCalledTimes(2);
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it("reconciles a rejected permission request to authoritative complete state", async () => {
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(partialStatus(true))
      .mockResolvedValueOnce(fullStatus());
    vi.mocked(graphRequestMissingPermissions).mockRejectedValue(
      new Error("secret-token-shaped complete-state payload"),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );

    expect(
      await screen.findByRole("status", {
        name: "Microsoft Graph permissions are already up to date.",
      }),
    ).toBeVisible();
    expect(screen.getByText("Connected")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Request missing permissions" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("secret-token-shaped complete-state payload"),
    ).not.toBeInTheDocument();
    expect(graphGetAuthStatus).toHaveBeenCalledTimes(2);
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });


  it("retains permission guidance during app cache hydration", async () => {
    const apps = deferred<Awaited<ReturnType<typeof graphFetchAllApps>>>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("unchanged"),
    );
    vi.mocked(graphFetchAllApps).mockReturnValue(apps.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );
    const guidance = await screen.findByRole("status", {
      name: "No additional permissions were granted. A tenant administrator may need to approve the missing permissions.",
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    );

    expect(guidance).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Fetching apps..." }),
    ).toBeDisabled();

    await act(async () => {
      apps.resolve([]);
      await apps.promise;
    });
    expect(guidance).toBeVisible();
  });

  it("clears permission guidance when Graph is disabled", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("unchanged"),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );
    expect(
      await screen.findByRole("status", {
        name: "No additional permissions were granted. A tenant administrator may need to approve the missing permissions.",
      }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(
      screen.getByRole("button", { name: "I understand, enable it" }),
    );

    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("clears permission guidance when a fresh initial sign-in begins", async () => {
    const authentication = deferred<GraphAuthAttemptResult>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("stale", disconnectedStatus()),
    );
    vi.mocked(graphAuthenticate).mockReturnValue(authentication.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );
    expect(
      await screen.findByRole("alert", {
        name: "The permission request was superseded by a newer Graph connection change.",
      }),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", { name: "Sign in with Windows" }),
    );

    expect(
      screen.getByRole("button", { name: "Cancel sign-in" }),
    ).toBeEnabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await act(async () => {
      authentication.resolve(authResult(partialStatus(true)));
      await authentication.promise;
    });
  });

  it("clears permission guidance only after sign-out succeeds", async () => {
    const signOut = deferred<void>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockResolvedValue(
      permissionResult("unchanged"),
    );
    vi.mocked(graphSignOut).mockReturnValue(signOut.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );
    const guidance = await screen.findByRole("status", {
      name: "No additional permissions were granted. A tenant administrator may need to approve the missing permissions.",
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));

    expect(guidance).toBeVisible();

    await act(async () => {
      signOut.resolve();
      await signOut.promise;
    });
    expect(screen.getByText("Not connected")).toBeVisible();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("suppresses a permission result that settles after Graph is disabled", async () => {
    const request = deferred<GraphPermissionUpgradeResult>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockReturnValue(request.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );
    await waitFor(() =>
      expect(graphRequestMissingPermissions).toHaveBeenCalledOnce(),
    );
    fireEvent.click(screen.getByRole("checkbox"));

    await act(async () => {
      request.resolve(permissionResult("upgraded", fullStatus()));
      await request.promise;
    });

    expect(useUiStore.getState().graphApiEnabled).toBe(false);
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
    expect(
      screen.queryByText(
        "Permissions updated. Additional Graph capabilities are now available.",
      ),
    ).not.toBeInTheDocument();
  });


  it("keeps a pending permission action shared across remounts without hydration superseding it", async () => {
    const request = deferred<GraphPermissionUpgradeResult>();
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(partialStatus(true))
      .mockResolvedValueOnce(partialStatus(true));
    vi.mocked(graphRequestMissingPermissions).mockReturnValue(request.promise);

    const firstTab = render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );
    await waitFor(() =>
      expect(graphRequestMissingPermissions).toHaveBeenCalledOnce(),
    );
    firstTab.unmount();

    render(<GraphApiTab />);

    expect(
      await screen.findByRole("button", {
        name: "Requesting permissions...",
      }),
    ).toBeDisabled();
    expect(graphGetAuthStatus).toHaveBeenCalledOnce();

    await act(async () => {
      request.resolve(permissionResult("unchanged"));
      await request.promise;
    });

    await waitFor(() => expect(graphGetAuthStatus).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("publishes a pending sign-in globally after unmount and then hydrates the remounted tab", async () => {
    const authentication = deferred<GraphAuthAttemptResult>();
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(disconnectedStatus())
      .mockResolvedValueOnce(partialStatus(true));
    vi.mocked(graphAuthenticate).mockReturnValue(authentication.promise);

    const firstTab = render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledOnce());
    firstTab.unmount();

    render(<GraphApiTab />);

    expect(
      await screen.findByRole("button", { name: "Cancel sign-in" }),
    ).toBeEnabled();
    expect(graphGetAuthStatus).toHaveBeenCalledOnce();

    await act(async () => {
      authentication.resolve(authResult(partialStatus(true)));
      await authentication.promise;
    });

    expect(useUiStore.getState().graphApiStatus).toBe("connected");
    await waitFor(() => expect(graphGetAuthStatus).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
  });

  it("publishes a pending sign-out globally after unmount and then hydrates the remounted tab", async () => {
    const signOut = deferred<void>();
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(partialStatus(true))
      .mockResolvedValueOnce(disconnectedStatus());
    vi.mocked(graphSignOut).mockReturnValue(signOut.promise);

    const firstTab = render(<GraphApiTab />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(graphSignOut).toHaveBeenCalledOnce());
    firstTab.unmount();

    render(<GraphApiTab />);

    expect(
      await screen.findByRole("button", { name: "Sign out" }),
    ).toBeDisabled();
    expect(graphGetAuthStatus).toHaveBeenCalledOnce();

    await act(async () => {
      signOut.resolve();
      await signOut.promise;
    });

    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
    await waitFor(() => expect(graphGetAuthStatus).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Not connected")).toBeVisible();
  });

  it("publishes permission precondition reconciliation globally after unmount", async () => {
    const reconciliation = deferred<GraphAuthStatus>();
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(partialStatus(true))
      .mockReturnValueOnce(reconciliation.promise)
      .mockResolvedValueOnce(disconnectedStatus());
    vi.mocked(graphRequestMissingPermissions).mockRejectedValue(
      new Error("secret-token-shaped rejected payload"),
    );

    const firstTab = render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Request missing permissions",
      }),
    );
    await waitFor(() => expect(graphGetAuthStatus).toHaveBeenCalledTimes(2));
    firstTab.unmount();

    render(<GraphApiTab />);

    expect(
      await screen.findByRole("button", {
        name: "Requesting permissions...",
      }),
    ).toBeDisabled();
    expect(graphGetAuthStatus).toHaveBeenCalledTimes(2);

    await act(async () => {
      reconciliation.resolve(disconnectedStatus());
      await reconciliation.promise;
    });

    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
    await waitFor(() => expect(graphGetAuthStatus).toHaveBeenCalledTimes(3));
    expect(await screen.findByText("Not connected")).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.queryByText("secret-token-shaped rejected payload"),
    ).not.toBeInTheDocument();
  });



  it("does not let an invalidated sign-out completion overwrite a newer remounted sign-in", async () => {
    const staleSignOut = deferred<void>();
    const currentAuthentication = deferred<GraphAuthAttemptResult>();
    vi.mocked(graphGetAuthStatus)
      .mockResolvedValueOnce(partialStatus(true))
      .mockResolvedValueOnce(disconnectedStatus());
    vi.mocked(graphSignOut).mockReturnValue(staleSignOut.promise);
    vi.mocked(graphAuthenticate).mockReturnValue(currentAuthentication.promise);

    const firstTab = render(<GraphApiTab />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(graphSignOut).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole("checkbox"));
    firstTab.unmount();

    useUiStore.setState({ graphApiEnabled: true });
    render(<GraphApiTab />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledOnce());

    await act(async () => {
      staleSignOut.resolve();
      await staleSignOut.promise;
    });

    expect(useUiStore.getState().graphApiStatus).toBe("signingIn");
    expect(
      screen.getByRole("button", { name: "Cancel sign-in" }),
    ).toBeEnabled();

    await act(async () => {
      currentAuthentication.resolve(authResult(partialStatus(true)));
      await currentAuthentication.promise;
    });
    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
  });

  it("publishes an existing authenticated status after settings refresh", async () => {
    useUiStore.setState({ graphApiStatus: "disconnected" });
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));

    render(<GraphApiTab />);

    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });

  it("disables app enrichment when the token lacks app-read capability", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(false));

    render(<GraphApiTab />);

    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    ).toBeDisabled();
    expect(
      screen.getByText(/App cache requires DeviceManagementApps\.Read\.All/),
    ).toBeVisible();
  });

  it("publishes a successful manual connection for first-use ESP enrichment", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockResolvedValue(authResult(partialStatus(true)));

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );

    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });

  it("restores mounted-local publication after StrictMode effect replay", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockResolvedValue(authResult(partialStatus(true)));

    render(
      <StrictMode>
        <GraphApiTab />
      </StrictMode>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );

    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
    expect(useUiStore.getState().graphApiStatus).toBe("connected");
  });

  it("clears a stale connected phase when manual authentication is rejected", async () => {
    useUiStore.setState({ graphApiStatus: "connected" });
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockResolvedValue(
      authResult(disconnectedStatus(), "failed", "Consent was not granted"),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );

    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledOnce());
    expect(useUiStore.getState().graphApiStatus).toBe("error");
  });

  it("returns the global connection phase to idle when Graph is disabled", async () => {
    useUiStore.setState({ graphApiStatus: "connected" });
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));

    render(<GraphApiTab />);

    fireEvent.click(await screen.findByRole("checkbox"));

    expect(useUiStore.getState().graphApiEnabled).toBe(false);
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it("does not restore connected state when a refresh finishes after Graph is disabled", async () => {
    let resolveStatus!: (status: GraphAuthStatus) => void;
    vi.mocked(graphGetAuthStatus).mockReturnValue(
      new Promise((resolve) => {
        resolveStatus = resolve;
      }),
    );

    render(<GraphApiTab />);

    await waitFor(() => expect(graphGetAuthStatus).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole("checkbox"));
    await act(async () => {
      resolveStatus(partialStatus(true));
      await Promise.resolve();
    });

    expect(useUiStore.getState().graphApiEnabled).toBe(false);
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it("does not restore connected state when manual authentication finishes after Graph is disabled", async () => {
    let resolveAuthentication!: (result: GraphAuthAttemptResult) => void;
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockReturnValue(
      new Promise((resolve) => {
        resolveAuthentication = resolve;
      }),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledOnce());

    fireEvent.click(screen.getByRole("checkbox"));
    expect(useUiStore.getState().graphApiEnabled).toBe(false);
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");

    await act(async () => {
      resolveAuthentication(authResult(partialStatus(true)));
      await Promise.resolve();
    });

    expect(useUiStore.getState().graphApiEnabled).toBe(false);
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it("does not merge app data when Graph is disabled during manual cache hydration", async () => {
    let resolveApps!: (
      apps: Awaited<ReturnType<typeof graphFetchAllApps>>,
    ) => void;
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphFetchAllApps).mockReturnValue(
      new Promise((resolve) => {
        resolveApps = resolve;
      }),
    );

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Pre-populate app cache" }),
    );
    await waitFor(() => expect(graphFetchAllApps).toHaveBeenCalledOnce());

    fireEvent.click(screen.getByRole("checkbox"));
    await act(async () => {
      resolveApps([
        {
          id: "app-a",
          displayName: "App A",
          publisher: null,
          odataType: "#microsoft.graph.win32LobApp",
        },
      ]);
      await Promise.resolve();
    });

    expect(useUiStore.getState().graphApiEnabled).toBe(false);
    expect(useIntuneStore.getState().guidRegistry).toEqual({});
  });

  it("clears the global connection phase after manual sign-out", async () => {
    useUiStore.setState({ graphApiStatus: "connected" });
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));

    render(<GraphApiTab />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    await waitFor(() => expect(graphSignOut).toHaveBeenCalledOnce());
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it("does not let cache hydration supersede an in-flight sign-out", async () => {
    const signOut = deferred<void>();
    useUiStore.setState({ graphApiStatus: "connected" });
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphSignOut).mockReturnValue(signOut.promise);

    render(<GraphApiTab />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    expect(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    );
    expect(graphFetchAllApps).not.toHaveBeenCalled();

    await act(async () => {
      signOut.resolve();
      await signOut.promise;
    });
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it("does not let sign-out supersede in-flight cache hydration", async () => {
    const apps = deferred<Awaited<ReturnType<typeof graphFetchAllApps>>>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(partialStatus(true));
    vi.mocked(graphFetchAllApps).mockReturnValue(apps.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Pre-populate app cache" }),
    );

    expect(screen.getByRole("button", { name: "Sign out" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(graphSignOut).not.toHaveBeenCalled();

    await act(async () => {
      apps.resolve([]);
      await apps.promise;
    });
    expect(
      screen.getByRole("button", { name: "Pre-populate app cache" }),
    ).toBeEnabled();
  });

  it("cancels a disabled sign-in and blocks replacement until native settles", async () => {
    const cancelledAuthentication = deferred<GraphAuthAttemptResult>();
    const currentAuthentication = deferred<GraphAuthAttemptResult>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphCancelAuthentication).mockRejectedValueOnce(
      new Error("cancel transport failed"),
    );
    vi.mocked(graphAuthenticate)
      .mockReturnValueOnce(cancelledAuthentication.promise)
      .mockReturnValueOnce(currentAuthentication.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledTimes(1));
    const firstRequestId = vi.mocked(graphAuthenticate).mock.calls[0][0];
    fireEvent.click(screen.getByRole("checkbox"));
    expect(graphCancelAuthentication).toHaveBeenCalledWith(firstRequestId);
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(
      screen.getByRole("button", { name: "I understand, enable it" }),
    );
    expect(
      await screen.findByRole("button", { name: "Cancelling..." }),
    ).toBeDisabled();
    expect(graphAuthenticate).toHaveBeenCalledTimes(1);

    await act(async () => {
      cancelledAuthentication.resolve(
        authResult(
          disconnectedStatus(),
          "cancelled",
          "Microsoft Graph sign-in was cancelled.",
        ),
      );
      await cancelledAuthentication.promise;
    });
    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledTimes(2));
    expect(vi.mocked(graphAuthenticate).mock.calls[1][0]).not.toBe(
      firstRequestId,
    );

    await act(async () => {
      currentAuthentication.resolve(authResult(partialStatus(true)));
      await currentAuthentication.promise;
    });
    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
  });

  it("probes capability on a persisted opt-in without starting WAM", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());

    render(<GraphApiTab />);

    await waitFor(() => expect(graphProbeCapability).toHaveBeenCalledOnce());
    await screen.findByRole("button", { name: "Sign in with Windows" });
    expect(graphGetAuthStatus).toHaveBeenCalledOnce();
    expect(graphAuthenticate).not.toHaveBeenCalled();
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
  });

  it("reports a personal-only host without opening WAM", async () => {
    vi.mocked(graphProbeCapability).mockResolvedValue({
      kind: "personalAccountOnly",
    });

    render(<GraphApiTab />);

    expect(
      await screen.findByText(/Only a personal Microsoft account is available/),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Sign in with Windows" }),
    ).toBeDisabled();
    expect(graphGetAuthStatus).not.toHaveBeenCalled();
    expect(graphAuthenticate).not.toHaveBeenCalled();
    expect(useUiStore.getState().graphApiStatus).toBe("unsupported");
  });

  it("shows one announced native message when sign-in discovers an unsupported host", async () => {
    const message =
      "Only a personal Microsoft account is available. Connect a Windows work or school account to use Microsoft Graph.";
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockResolvedValue({
      outcome: "unavailable",
      status: disconnectedStatus(),
      capability: { kind: "personalAccountOnly" },
      message,
    });

    render(<GraphApiTab />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(screen.getAllByText(/Only a personal Microsoft account/)).toHaveLength(
      1,
    );
    expect(useUiStore.getState().graphApiStatus).toBe("unsupported");
  });

  it("cancels the matching request and remains cancelling until native settles", async () => {
    const authentication = deferred<GraphAuthAttemptResult>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockReturnValue(authentication.promise);

    render(<GraphApiTab />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledOnce());
    const requestId = vi.mocked(graphAuthenticate).mock.calls[0][0];
    fireEvent.click(screen.getByRole("button", { name: "Cancel sign-in" }));

    expect(graphCancelAuthentication).toHaveBeenCalledWith(requestId);
    expect(useUiStore.getState().graphApiStatus).toBe("cancelling");
    expect(
      screen.getByRole("button", { name: "Cancelling..." }),
    ).toBeDisabled();

    await act(async () => {
      authentication.resolve(
        authResult(
          disconnectedStatus(),
          "cancelled",
          "Microsoft Graph sign-in was cancelled.",
        ),
      );
      await authentication.promise;
    });
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
    expect(useUiStore.getState().graphApiLastAttempt).toEqual({
      outcome: "cancelled",
      message: "Microsoft Graph sign-in was cancelled.",
    });
  });

  it("keeps a timed-out attempt distinct from connection state", async () => {
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate).mockResolvedValue(
      authResult(
        disconnectedStatus(),
        "timedOut",
        "Microsoft Graph sign-in timed out after 120 seconds.",
      ),
    );

    render(<GraphApiTab />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );

    await screen.findByText(
      "Microsoft Graph sign-in timed out after 120 seconds.",
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Microsoft Graph sign-in timed out after 120 seconds.",
    );
    expect(useUiStore.getState().graphApiStatus).toBe("disconnected");
    expect(useUiStore.getState().graphApiLastAttempt?.outcome).toBe("timedOut");
  });
});
