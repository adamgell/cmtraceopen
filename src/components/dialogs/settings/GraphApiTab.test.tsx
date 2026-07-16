import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  graphAuthenticate,
  graphFetchAllApps,
  graphGetAuthStatus,
  graphSignOut,
  type GraphAuthStatus,
} from "../../../lib/commands";
import { useUiStore } from "../../../stores/ui-store";
import { useIntuneStore } from "../../../workspaces/intune/intune-store";
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

const disconnectedStatus = (): GraphAuthStatus => ({
  isAuthenticated: false,
  userPrincipalName: null,
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
  error: null,
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
    vi.clearAllMocks();
    useUiStore.setState({
      currentPlatform: "windows",
      graphApiEnabled: true,
      graphApiStatus: "idle",
    });
    useIntuneStore.setState({ guidRegistry: {} });
    vi.mocked(graphAuthenticate).mockResolvedValue(partialStatus(true));
    vi.mocked(graphFetchAllApps).mockResolvedValue([]);
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
  });

  it("publishes an existing authenticated status after settings refresh", async () => {
    useUiStore.setState({ graphApiStatus: "idle" });
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
    vi.mocked(graphAuthenticate).mockResolvedValue(partialStatus(true));

    render(<GraphApiTab />);

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
    vi.mocked(graphAuthenticate).mockResolvedValue({
      ...disconnectedStatus(),
      error: "Consent was not granted",
    });

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
    expect(useUiStore.getState().graphApiStatus).toBe("idle");
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
    expect(useUiStore.getState().graphApiStatus).toBe("idle");
  });

  it("does not restore connected state when manual authentication finishes after Graph is disabled", async () => {
    let resolveAuthentication!: (status: GraphAuthStatus) => void;
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
    expect(useUiStore.getState().graphApiStatus).toBe("idle");

    await act(async () => {
      resolveAuthentication(partialStatus(true));
      await Promise.resolve();
    });

    expect(useUiStore.getState().graphApiEnabled).toBe(false);
    expect(useUiStore.getState().graphApiStatus).toBe("idle");
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
    expect(useUiStore.getState().graphApiStatus).toBe("idle");
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
    expect(useUiStore.getState().graphApiStatus).toBe("idle");
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

  it("keeps a newer sign-in busy when a disabled operation settles late", async () => {
    const staleAuthentication = deferred<GraphAuthStatus>();
    const currentAuthentication = deferred<GraphAuthStatus>();
    vi.mocked(graphGetAuthStatus).mockResolvedValue(disconnectedStatus());
    vi.mocked(graphAuthenticate)
      .mockReturnValueOnce(staleAuthentication.promise)
      .mockReturnValueOnce(currentAuthentication.promise);

    render(<GraphApiTab />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(
      screen.getByRole("button", { name: "I understand, enable it" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with Windows" }),
    );
    await waitFor(() => expect(graphAuthenticate).toHaveBeenCalledTimes(2));

    await act(async () => {
      staleAuthentication.resolve(partialStatus(true));
      await staleAuthentication.promise;
    });
    expect(
      screen.getByRole("button", { name: "Signing in..." }),
    ).toBeDisabled();

    await act(async () => {
      currentAuthentication.resolve(partialStatus(true));
      await currentAuthentication.promise;
    });
    expect(
      await screen.findByText("Connected with partial permissions"),
    ).toBeVisible();
  });
});
