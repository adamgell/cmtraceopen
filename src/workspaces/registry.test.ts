import {
  createElement,
  lazy,
  type ComponentType,
  type LazyExoticComponent,
} from "react";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  expectTypeOf,
  it,
  vi,
} from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  GlobalWorkspaceListeners,
  shouldRenderWorkspaceSidebar,
} from "../components/layout/AppShell";
import { WorkspaceToolbarAction } from "../components/layout/Toolbar";
import { WorkspaceStatusBarContent } from "../components/layout/StatusBar";
import type { WorkspaceId } from "../types/log";
import { useUiStore } from "../stores/ui-store";
import { useEspDiagnosticsStore } from "./esp-diagnostics/esp-diagnostics-store";
import { EspDiagnosticsWorkspace } from "./esp-diagnostics/EspDiagnosticsWorkspace";
import { EspStatusBarContent } from "./esp-diagnostics/EspStatusBarContent";
import { EspToolbarAction } from "./esp-diagnostics/EspToolbarAction";
import type { EspDiagnosticsSnapshot } from "./esp-diagnostics/types";
import {
  espDiagnosticsWorkspace,
  resolveEspEvidenceSource,
  supportsEspLiveAcquisition,
} from "./esp-diagnostics";
import { eventLogWorkspace } from "./event-log";
import { logWorkspace } from "./log";
import { getAvailableWorkspaces, getWorkspace } from "./registry";
import type { WorkspaceDefinition } from "./types";

const eventMocks = vi.hoisted(() => {
  const unlisten = vi.fn();
  return {
    listen: vi.fn(async () => unlisten),
    unlisten,
  };
});

vi.mock("@tauri-apps/api/event", () => ({
  listen: eventMocks.listen,
}));

vi.mock("./event-log/evtx-store", () => ({
  useEvtxStore: vi.fn(),
}));

const TestWorkspace = lazy(async () => ({ default: () => null }));
const TestToolbarAction = lazy(async () => ({
  default: () =>
    createElement("button", { type: "button" }, "Workspace live action"),
}));
const TestStatusContent = lazy(async () => ({
  default: () => createElement("span", null, "Workspace status content"),
}));

function makeChromeSnapshot(): EspDiagnosticsSnapshot {
  return {
    schemaVersion: 1,
    scenario: "autopilotV1",
    phase: "deviceSetup",
    generatedAtUtc: "2026-07-15T20:00:00Z",
    elevation: {
      isElevated: false,
      restartSupported: true,
      restrictedSources: [],
    },
    identity: {
      deviceName: "host-device-a",
      managedDeviceId: null,
      entraDeviceId: "entra-device-a",
      entdmId: { value: "entdm-a", sensitivity: "sensitive" },
      tenantId: { value: "tenant-a", sensitivity: "sensitive" },
      tenantDomain: { value: "contoso.example", sensitivity: "public" },
      userPrincipalName: {
        value: "user@contoso.example",
        sensitivity: "restricted",
      },
      serialNumber: { value: "serial-device-a", sensitivity: "sensitive" },
      evidence: [],
    },
    profile: null,
    enrollments: [],
    sessions: [],
    workloads: [],
    installerCorrelations: [],
    nodeCache: [],
    registrationEvents: [],
    deliveryOptimization: null,
    hardware: null,
    activity: [],
    findings: [],
    coverage: [],
    rawEvidence: [
      {
        recordId: "evidence-a",
        provenance: {
          sourceKind: "registry",
          sourceArtifactId: "registry-device",
          filePath: null,
          lineNumber: null,
          recordNumber: null,
          registry: {
            hive: "HKLM",
            key: "SOFTWARE\\Microsoft\\Provisioning\\Diagnostics",
            valueName: "AutopilotProfile",
          },
          event: null,
        },
        sourceTimestamp: null,
        observedAtUtc: "2026-07-15T20:00:00Z",
        rawValue: { text: "registry-value" },
        sensitivity: "public",
        parseState: "parsed",
        accessState: "available",
        evidence: [],
      },
      {
        recordId: "evidence-b",
        provenance: {
          sourceKind: "imeLog",
          sourceArtifactId: "ime-log",
          filePath:
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
          lineNumber: 1,
          recordNumber: null,
          registry: null,
          event: null,
        },
        sourceTimestamp: null,
        observedAtUtc: "2026-07-15T20:00:01Z",
        rawValue: { text: "ime-value-a" },
        sensitivity: "public",
        parseState: "parsed",
        accessState: "available",
        evidence: [],
      },
      {
        recordId: "evidence-c",
        provenance: {
          sourceKind: "imeLog",
          sourceArtifactId: "ime-log",
          filePath:
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
          lineNumber: 2,
          recordNumber: null,
          registry: null,
          event: null,
        },
        sourceTimestamp: null,
        observedAtUtc: "2026-07-15T20:00:02Z",
        rawValue: { text: "ime-value-b" },
        sensitivity: "public",
        parseState: "parsed",
        accessState: "available",
        evidence: [],
      },
    ],
    graph: null,
  };
}

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  useEspDiagnosticsStore.setState(
    useEspDiagnosticsStore.getInitialState(),
    true,
  );
  useUiStore.setState({
    activeView: "esp-diagnostics",
    activeWorkspace: "esp-diagnostics",
    currentPlatform: "windows",
    enabledWorkspaces: null,
    graphApiEnabled: false,
    graphApiStatus: "idle",
  });
});

const espWorkspaceId: WorkspaceId = "esp-diagnostics";

const espDefinition = {
  id: espWorkspaceId,
  label: "ESP Diagnostics",
  platforms: "all",
  component: TestWorkspace,
  capabilities: {
    sidebar: false,
    liveAcquisition: true,
  },
  toolbarAction: TestWorkspace,
  statusBarContent: TestWorkspace,
} satisfies WorkspaceDefinition;

function hasSidebar(workspace: WorkspaceDefinition): boolean {
  return workspace.capabilities?.sidebar !== false;
}

describe("workspace definition contract", () => {
  it("treats the sidebar as visible unless a workspace explicitly disables it", () => {
    const defaultWorkspace: WorkspaceDefinition = {
      id: "log",
      label: "Log Explorer",
      platforms: "all",
      component: TestWorkspace,
    };

    expect(hasSidebar(defaultWorkspace)).toBe(true);
    expect(hasSidebar(espDefinition)).toBe(false);
  });

  it("supports generic live-acquisition metadata and lazy chrome slots", () => {
    expect(espDefinition.capabilities.liveAcquisition).toBe(true);
    expect(espDefinition.toolbarAction).toBe(TestWorkspace);
    expect(espDefinition.statusBarContent).toBe(TestWorkspace);
    expectTypeOf(espDefinition.toolbarAction).toMatchTypeOf<
      LazyExoticComponent<ComponentType>
    >();
    expectTypeOf(espDefinition.statusBarContent).toMatchTypeOf<
      LazyExoticComponent<ComponentType>
    >();
  });
});

describe("registry-driven shell chrome", () => {
  it("shows sidebars by default and honors a generic disabled capability", () => {
    expect(shouldRenderWorkspaceSidebar(logWorkspace)).toBe(true);
    expect(eventLogWorkspace.capabilities?.sidebar).toBe(false);
    expect(shouldRenderWorkspaceSidebar(eventLogWorkspace)).toBe(false);
  });

  it("renders lazy toolbar and status slots while preserving legacy fallback chrome", async () => {
    const workspaceWithSlots: WorkspaceDefinition = {
      ...logWorkspace,
      toolbarAction: TestToolbarAction,
      statusBarContent: TestStatusContent,
    };

    render(
      createElement(
        "div",
        null,
        createElement(WorkspaceToolbarAction, {
          workspace: workspaceWithSlots,
        }),
        createElement(WorkspaceStatusBarContent, {
          workspace: workspaceWithSlots,
          children: createElement("span", null, "Legacy status fallback"),
        }),
      ),
    );

    expect(
      await screen.findByRole("button", { name: "Workspace live action" }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("Workspace status content"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Legacy status fallback"),
    ).not.toBeInTheDocument();

    cleanup();
    render(
      createElement(WorkspaceStatusBarContent, {
        workspace: logWorkspace,
        children: createElement("span", null, "Legacy status fallback"),
      }),
    );

    expect(screen.getByText("Legacy status fallback")).toBeInTheDocument();
    expect(logWorkspace.label).toBe("Log Explorer");
    expect(logWorkspace.actionLabels).toEqual({
      file: "Open file...",
      folder: "Open folder...",
      placeholder: "Open...",
    });
  });

  it("keeps legacy status content visible while a workspace status slot is loading", async () => {
    let resolveStatusContent:
      ((module: { default: ComponentType }) => void) | undefined;
    const DelayedStatusContent = lazy(
      () =>
        new Promise<{ default: ComponentType }>((resolve) => {
          resolveStatusContent = resolve;
        }),
    );
    const workspaceWithDelayedStatus: WorkspaceDefinition = {
      ...logWorkspace,
      statusBarContent: DelayedStatusContent,
    };

    render(
      createElement(WorkspaceStatusBarContent, {
        workspace: workspaceWithDelayedStatus,
        children: createElement("span", null, "Legacy status while loading"),
      }),
    );

    expect(screen.getByText("Legacy status while loading")).toBeInTheDocument();

    await act(async () => {
      resolveStatusContent?.({
        default: () => createElement("span", null, "Loaded workspace status"),
      });
    });

    expect(
      await screen.findByText("Loaded workspace status"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Legacy status while loading"),
    ).not.toBeInTheDocument();
  });
});

describe("ESP workspace registration", () => {
  it("registers cross-platform offline analysis with Windows-only live capability", () => {
    expect(getWorkspace("esp-diagnostics")).toBe(espDiagnosticsWorkspace);
    expect(espDiagnosticsWorkspace.label).toBe("ESP Diagnostics");
    expect(espDiagnosticsWorkspace.platforms).toBe("all");
    expect(espDiagnosticsWorkspace.capabilities).toMatchObject({
      sidebar: false,
      liveAcquisition: true,
      tabStrip: false,
    });
    expect(
      getAvailableWorkspaces("windows").map((workspace) => workspace.id),
    ).toContain("esp-diagnostics");
    expect(
      getAvailableWorkspaces("macos").map((workspace) => workspace.id),
    ).toContain("esp-diagnostics");
    expect(
      getAvailableWorkspaces("linux").map((workspace) => workspace.id),
    ).toContain("esp-diagnostics");
    expect(supportsEspLiveAcquisition("windows")).toBe(true);
    expect(supportsEspLiveAcquisition("macos")).toBe(false);
    expect(supportsEspLiveAcquisition("linux")).toBe(false);
  });

  it("routes evidence folders, manifests, CABs, and ZIPs only", () => {
    expect(
      resolveEspEvidenceSource({
        kind: "folder",
        path: "/captures/cmtrace-bundle",
      }),
    ).toBe("/captures/cmtrace-bundle");
    expect(
      resolveEspEvidenceSource({
        kind: "known",
        sourceId: "cmtrace-evidence",
        defaultPath: "/captures/known-bundle",
        pathKind: "folder",
      }),
    ).toBe("/captures/known-bundle");
    expect(
      resolveEspEvidenceSource({
        kind: "file",
        path: "/captures/manifest.json",
      }),
    ).toBe("/captures/manifest.json");
    expect(
      resolveEspEvidenceSource({
        kind: "file",
        path: "/captures/MDMDiagReport.CAB",
      }),
    ).toBe("/captures/MDMDiagReport.CAB");
    expect(
      resolveEspEvidenceSource({
        kind: "file",
        path: "/captures/evidence.zip",
      }),
    ).toBe("/captures/evidence.zip");
    expect(
      resolveEspEvidenceSource({ kind: "file", path: "/captures/random.json" }),
    ).toBeNull();
    expect(
      resolveEspEvidenceSource({ kind: "file", path: "/captures/ime.log" }),
    ).toBeNull();
  });

  it("uses locale-independent case folding for evidence extensions", () => {
    const localeLower = vi
      .spyOn(String.prototype, "toLocaleLowerCase")
      .mockReturnValue("evidence.zıp");

    try {
      expect(
        resolveEspEvidenceSource({
          kind: "file",
          path: "/captures/EVIDENCE.ZIP",
        }),
      ).toBe("/captures/EVIDENCE.ZIP");
      expect(localeLower).not.toHaveBeenCalled();
    } finally {
      localeLower.mockRestore();
    }
  });

  it("rejects an unsupported file selected from the workspace import action", async () => {
    const currentSnapshot = makeChromeSnapshot();
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: currentSnapshot,
      error: null,
    });
    vi.mocked(open).mockResolvedValueOnce("/captures/random.json");
    render(createElement(EspDiagnosticsWorkspace));

    fireEvent.click(
      screen.getByRole("button", { name: "Import captured evidence" }),
    );

    expect(
      await screen.findByText(
        "ESP Diagnostics accepts CMTrace evidence folders, manifest.json, CAB, or ZIP sources.",
      ),
    ).toBeInTheDocument();
    expect(vi.mocked(invoke)).not.toHaveBeenCalledWith(
      "analyze_esp_evidence",
      expect.anything(),
    );
    expect(useEspDiagnosticsStore.getState()).toMatchObject({
      phase: "ready",
      snapshot: currentSnapshot,
      error:
        "ESP Diagnostics accepts CMTrace evidence folders, manifest.json, CAB, or ZIP sources.",
    });
  });

  it("renders a production idle workspace with explicit local actions", () => {
    render(createElement(EspDiagnosticsWorkspace));

    expect(
      screen.getByRole("heading", { name: "ESP Diagnostics" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Import captured evidence" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Start live diagnostics" }),
    ).toBeEnabled();
    expect(screen.getByText("Waiting for evidence")).toBeInTheDocument();
  });

  it("renders analyzing and error states without discarding the action surface", () => {
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    const view = render(createElement(EspDiagnosticsWorkspace));
    expect(screen.getByText("Analyzing captured evidence")).toBeInTheDocument();

    act(() => {
      useEspDiagnosticsStore
        .getState()
        .fail("analysis-a", "Bundle is unreadable");
    });
    expect(screen.getByText("Bundle is unreadable")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Import captured evidence" }),
    ).toBeEnabled();
    view.unmount();
  });

  it("keeps an active live session under explicit stop control", async () => {
    useEspDiagnosticsStore.setState({
      phase: "live",
      requestId: "live-a",
      sessionId: "session-a",
      sequence: 1,
      snapshot: null,
    });

    render(createElement(EspDiagnosticsWorkspace));

    expect(
      screen.getByRole("button", { name: "Import evidence folder" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Import captured evidence" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Stop live diagnostics" }),
    ).toBeEnabled();

    await expect(
      espDiagnosticsWorkspace.onOpenSource!(
        { kind: "file", path: "/captures/manifest.json" },
        "toolbar.open-file",
      ),
    ).rejects.toThrow("Stop live diagnostics before importing");
    expect(useEspDiagnosticsStore.getState().sessionId).toBe("session-a");
    expect(vi.mocked(invoke)).not.toHaveBeenCalledWith(
      "analyze_esp_evidence",
      expect.anything(),
    );
  });
});

describe("ESP workspace app chrome", () => {
  it("mounts one global session listener and never stops collection on navigation", async () => {
    useEspDiagnosticsStore.setState({
      phase: "live",
      requestId: "live-a",
      sessionId: "session-a",
      sequence: 1,
      snapshot: makeChromeSnapshot(),
    });

    await act(async () => {
      await useUiStore.persist.rehydrate();
    });

    const view = render(createElement(GlobalWorkspaceListeners));
    await waitFor(() => expect(eventMocks.listen).toHaveBeenCalledTimes(1));

    act(() => {
      useUiStore.setState({ activeView: "log", activeWorkspace: "log" });
    });
    view.rerender(createElement(GlobalWorkspaceListeners));

    expect(eventMocks.listen).toHaveBeenCalledTimes(1);
    expect(eventMocks.listen).toHaveBeenCalledWith(
      "esp-diagnostics-session-update",
      expect.any(Function),
    );
    expect(useEspDiagnosticsStore.getState().sessionId).toBe("session-a");

    view.unmount();
    await waitFor(() => expect(eventMocks.unlisten).toHaveBeenCalledTimes(1));
    expect(useEspDiagnosticsStore.getState().sessionId).toBe("session-a");
    expect(vi.mocked(invoke)).not.toHaveBeenCalledWith(
      "stop_esp_diagnostics_session",
      expect.anything(),
    );
  });

  it("exposes a prominent ESP-only live-log action with state and counts", async () => {
    useEspDiagnosticsStore.setState({
      phase: "live",
      requestId: "live-a",
      sessionId: "session-a",
      sequence: 1,
      snapshot: makeChromeSnapshot(),
      unreadEvidenceCount: 2,
      evidenceViewMode: "collapsed",
    });

    render(
      createElement(WorkspaceToolbarAction, {
        workspace: espDiagnosticsWorkspace,
      }),
    );

    const action = await screen.findByRole("button", {
      name: "Open live logs, Live diagnostics active, 3 evidence records, 2 unread",
    });
    expect(action).toHaveAttribute("data-appearance", "primary");
    expect(screen.getByTestId("esp-live-status-dot")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();

    fireEvent.click(action);
    expect(useEspDiagnosticsStore.getState().evidenceViewMode).toBe("docked");
    expect(
      screen.getByRole("button", {
        name: "Hide live logs, Live diagnostics active, 3 evidence records, 0 unread",
      }),
    ).toHaveAttribute("aria-pressed", "true");

    cleanup();
    render(createElement(WorkspaceToolbarAction, { workspace: logWorkspace }));
    expect(
      screen.queryByRole("button", { name: /live logs/i }),
    ).not.toBeInTheDocument();
  });

  it("summarizes start-stop state, sources, elevation, and Graph status", () => {
    useEspDiagnosticsStore.setState({
      phase: "live",
      requestId: "live-a",
      sessionId: "session-a",
      sequence: 1,
      snapshot: makeChromeSnapshot(),
      graphPhase: "partial",
    });

    render(createElement(EspStatusBarContent));
    expect(screen.getByText("Live session")).toBeInTheDocument();
    expect(screen.getByText("2 sources")).toBeInTheDocument();
    expect(screen.getByText("3 evidence")).toBeInTheDocument();
    expect(screen.getByText("Not elevated")).toBeInTheDocument();
    expect(screen.getByText("Graph partial")).toBeInTheDocument();

    act(() => {
      useEspDiagnosticsStore.setState({ phase: "stopping" });
    });
    expect(screen.getByText("Stopping live session")).toBeInTheDocument();

    act(() => {
      useEspDiagnosticsStore.setState({
        phase: "starting",
        sessionId: null,
        snapshot: null,
      });
    });
    expect(screen.getByText("Starting live session")).toBeInTheDocument();
  });

  it("reports elevated state even when administrator relaunch is unavailable", () => {
    const snapshot = makeChromeSnapshot();
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: {
        ...snapshot,
        elevation: {
          ...snapshot.elevation,
          isElevated: true,
          restartSupported: false,
        },
      },
    });

    render(createElement(EspStatusBarContent));

    expect(screen.getByText("Elevated")).toBeInTheDocument();
    expect(screen.queryByText("Elevation unavailable")).not.toBeInTheDocument();
  });

  it("registers lazy ESP toolbar and status slots", () => {
    expect(espDiagnosticsWorkspace.toolbarAction).toBeDefined();
    expect(espDiagnosticsWorkspace.statusBarContent).toBeDefined();
    expect(espDiagnosticsWorkspace.toolbarAction).not.toBe(EspToolbarAction);
    expect(espDiagnosticsWorkspace.statusBarContent).not.toBe(
      EspStatusBarContent,
    );
  });
});
