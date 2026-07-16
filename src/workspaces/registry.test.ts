import { lazy, type ComponentType, type LazyExoticComponent } from "react";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { WorkspaceId } from "../types/log";
import type { WorkspaceDefinition } from "./types";

const TestWorkspace = lazy(async () => ({ default: () => null }));

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
