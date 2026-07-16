import {
  createElement,
  lazy,
  type ComponentType,
  type LazyExoticComponent,
} from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
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
import { shouldRenderWorkspaceSidebar } from "../components/layout/AppShell";
import { WorkspaceToolbarAction } from "../components/layout/Toolbar";
import { WorkspaceStatusBarContent } from "../components/layout/StatusBar";
import type { WorkspaceId } from "../types/log";
import { useUiStore } from "../stores/ui-store";
import { useEspDiagnosticsStore } from "./esp-diagnostics/esp-diagnostics-store";
import { EspDiagnosticsWorkspace } from "./esp-diagnostics/EspDiagnosticsWorkspace";
import {
  espDiagnosticsWorkspace,
  resolveEspEvidenceSource,
  supportsEspLiveAcquisition,
} from "./esp-diagnostics";
import { eventLogWorkspace } from "./event-log";
import { logWorkspace } from "./log";
import { getAvailableWorkspaces, getWorkspace } from "./registry";
import type { WorkspaceDefinition } from "./types";

vi.mock("./event-log/evtx-store", () => ({
  useEvtxStore: vi.fn(),
}));

const TestWorkspace = lazy(async () => ({ default: () => null }));
const TestToolbarAction = lazy(async () => ({
  default: () => createElement("button", { type: "button" }, "Workspace live action"),
}));
const TestStatusContent = lazy(async () => ({
  default: () => createElement("span", null, "Workspace status content"),
}));

afterEach(cleanup);
beforeEach(() => {
  useEspDiagnosticsStore.setState(useEspDiagnosticsStore.getInitialState(), true);
  useUiStore.setState({ currentPlatform: "windows", enabledWorkspaces: null });
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
        createElement(WorkspaceToolbarAction, { workspace: workspaceWithSlots }),
        createElement(
          WorkspaceStatusBarContent,
          {
            workspace: workspaceWithSlots,
            children: createElement("span", null, "Legacy status fallback"),
          },
        ),
      ),
    );

    expect(
      await screen.findByRole("button", { name: "Workspace live action" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Workspace status content")).toBeInTheDocument();
    expect(screen.queryByText("Legacy status fallback")).not.toBeInTheDocument();

    cleanup();
    render(
      createElement(
        WorkspaceStatusBarContent,
        {
          workspace: logWorkspace,
          children: createElement("span", null, "Legacy status fallback"),
        },
      ),
    );

    expect(screen.getByText("Legacy status fallback")).toBeInTheDocument();
    expect(logWorkspace.label).toBe("Log Explorer");
    expect(logWorkspace.actionLabels).toEqual({
      file: "Open file...",
      folder: "Open folder...",
      placeholder: "Open...",
    });
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
    expect(getAvailableWorkspaces("windows").map((workspace) => workspace.id)).toContain(
      "esp-diagnostics",
    );
    expect(getAvailableWorkspaces("macos").map((workspace) => workspace.id)).toContain(
      "esp-diagnostics",
    );
    expect(getAvailableWorkspaces("linux").map((workspace) => workspace.id)).toContain(
      "esp-diagnostics",
    );
    expect(supportsEspLiveAcquisition("windows")).toBe(true);
    expect(supportsEspLiveAcquisition("macos")).toBe(false);
    expect(supportsEspLiveAcquisition("linux")).toBe(false);
  });

  it("routes evidence folders, manifests, CABs, and ZIPs only", () => {
    expect(
      resolveEspEvidenceSource({ kind: "folder", path: "/captures/cmtrace-bundle" }),
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
      resolveEspEvidenceSource({ kind: "file", path: "/captures/manifest.json" }),
    ).toBe("/captures/manifest.json");
    expect(
      resolveEspEvidenceSource({ kind: "file", path: "/captures/MDMDiagReport.CAB" }),
    ).toBe("/captures/MDMDiagReport.CAB");
    expect(
      resolveEspEvidenceSource({ kind: "file", path: "/captures/evidence.zip" }),
    ).toBe("/captures/evidence.zip");
    expect(
      resolveEspEvidenceSource({ kind: "file", path: "/captures/random.json" }),
    ).toBeNull();
    expect(
      resolveEspEvidenceSource({ kind: "file", path: "/captures/ime.log" }),
    ).toBeNull();
  });

  it("rejects an unsupported file selected from the workspace import action", async () => {
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
      useEspDiagnosticsStore.getState().fail("analysis-a", "Bundle is unreadable");
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
