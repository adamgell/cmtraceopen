import { invoke } from "@tauri-apps/api/core";
import { inspectPathKind } from "./commands";
import type { LogSource, WorkspaceId } from "../types/log";

export type RecentEntryKind = "file" | "folder";

/**
 * Recording must never break opening a log, so every failure here is a warning
 * and the promise always resolves.
 */
async function pushRecentEntry(
  path: string,
  kind: RecentEntryKind,
  workspace: WorkspaceId,
): Promise<void> {
  try {
    await invoke("push_recent_entry", { path, kind, workspace });
  } catch (error) {
    console.warn("[recent] failed to record entry", { path, workspace, error });
  }
}

export async function recordRecentSource(
  source: LogSource,
  workspace: WorkspaceId,
): Promise<void> {
  if (source.kind !== "file" && source.kind !== "folder") {
    return;
  }

  await pushRecentEntry(source.path, source.kind, workspace);
}

export async function recordRecentPath(
  path: string,
  workspace: WorkspaceId,
): Promise<void> {
  let kind: "file" | "folder" | "unknown";

  try {
    kind = await inspectPathKind(path);
  } catch (error) {
    console.warn("[recent] failed to inspect path kind", { path, error });
    return;
  }

  if (kind === "unknown") {
    console.warn("[recent] skipped path with unresolvable kind", { path });
    return;
  }

  await pushRecentEntry(path, kind, workspace);
}

export async function clearRecentEntries(): Promise<void> {
  try {
    await invoke("clear_recent_entries");
  } catch (error) {
    console.warn("[recent] failed to clear entries", { error });
  }
}
