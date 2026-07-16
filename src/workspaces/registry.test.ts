import {
  createElement,
  lazy,
  type ComponentType,
  type LazyExoticComponent,
} from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import { shouldRenderWorkspaceSidebar } from "../components/layout/AppShell";
import { WorkspaceToolbarAction } from "../components/layout/Toolbar";
import { WorkspaceStatusBarContent } from "../components/layout/StatusBar";
import type { WorkspaceId } from "../types/log";
import { eventLogWorkspace } from "./event-log";
import { logWorkspace } from "./log";
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
