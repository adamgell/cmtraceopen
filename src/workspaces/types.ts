// src/workspaces/types.ts
import type { LazyExoticComponent, ComponentType } from "react";
import type { LogSource, PlatformKind, WorkspaceId } from "../types/log";

export interface DialogFilter {
  name: string;
  extensions: string[];
}

export interface WorkspaceActionLabels {
  file?: string;
  folder?: string;
  placeholder?: string;
}

export interface WorkspaceCapabilities {
  tabStrip?: boolean;
  findBar?: boolean;
  detailsPane?: boolean;
  infoPane?: boolean;
  footerBar?: boolean;
  multiFileDrop?: boolean;
  fontSizing?: boolean;
}

export interface WorkspaceDefinition {
  /** Unique workspace identifier. */
  id: WorkspaceId;
  /** Human-readable label shown in toolbar dropdown. */
  label: string;
  /** Platforms this workspace is available on. "all" means no restriction. */
  platforms: PlatformKind[] | "all";
  /** Lazy-loaded main workspace component. */
  component: LazyExoticComponent<ComponentType>;
  /** Lazy-loaded sidebar component. Omit for no sidebar. */
  sidebar?: LazyExoticComponent<ComponentType>;
  /** Boolean capability flags. All default to false if omitted. */
  capabilities?: WorkspaceCapabilities;
  /** File dialog filters for the "Open File" action. */
  fileFilters?: DialogFilter[];
  /** Labels for toolbar open-file/folder buttons. */
  actionLabels?: WorkspaceActionLabels;
  /** Handler for opening a source in this workspace. */
  onOpenSource?: (source: LogSource, trigger: string) => Promise<void>;
  /** Handler for opening a path directly (drag-and-drop, file association). */
  onOpenPath?: (path: string) => Promise<void>;
}
