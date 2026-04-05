// src/workspaces/registry.ts
import type { PlatformKind, WorkspaceId } from "../types/log";
import type { WorkspaceDefinition } from "./types";

const ALL_WORKSPACES: WorkspaceDefinition[] = [];

export const workspaceRegistry = new Map<WorkspaceId, WorkspaceDefinition>(
  ALL_WORKSPACES.map((ws) => [ws.id, ws]),
);

export function getWorkspace(id: WorkspaceId): WorkspaceDefinition {
  const ws = workspaceRegistry.get(id);
  if (!ws) throw new Error(`Unknown workspace: ${id}`);
  return ws;
}

export function getAvailableWorkspaces(
  platform: PlatformKind,
  enabledWorkspaces?: readonly WorkspaceId[] | null,
): WorkspaceDefinition[] {
  const enabled = enabledWorkspaces ? new Set(enabledWorkspaces) : null;
  return ALL_WORKSPACES.filter((ws) => {
    if (enabled && !enabled.has(ws.id)) return false;
    return ws.platforms === "all" || ws.platforms.includes(platform);
  });
}
