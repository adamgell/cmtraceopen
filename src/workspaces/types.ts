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
  /** Whether the application sidebar is visible. Defaults to true if omitted. */
  sidebar?: boolean;
  tabStrip?: boolean;
  findBar?: boolean;
  detailsPane?: boolean;
  infoPane?: boolean;
  footerBar?: boolean;
  fontSizing?: boolean;
  /** Whether the toolbar's known-source presets menu is available. Defaults to true if omitted. */
  knownSources?: boolean;
  /** Whether pause/resume tailing is supported. Only the log workspace has this. */
  tailing?: boolean;
  /**
   * Whether loading a log keeps this workspace active instead of switching to
   * the Log workspace. Set on workspaces whose own screen is where the loaded
   * log belongs; explicit navigation (the workspace picker, or a call site that
   * switches views itself) still moves the user. Defaults to false.
   *
   * `true` keeps the view for every trigger. A list keeps it only for the
   * `ensureLogViewVisible` triggers it names, and every other trigger switches to
   * the Log workspace as it does for a workspace that sets nothing.
   */
  keepsViewOnLogLoad?: boolean | readonly string[];
  /**
   * Whether this workspace's own `onOpenSource` reopens a text-log FILE as a text log, by loading it
   * through the log store itself (a file source, or a known source that is one file). It does not
   * cover a folder: a handler that analyzes a folder never loads it as a text log. It matters to one
   * thing: a text-log load that fails Access Denied offers a restart as administrator, and the
   * restore ticket names the workspace that reopens the source after it. A workspace that does not
   * say so, or a target that is not a file, would be reopened as something else (Event Logs as
   * EVTX, Intune as an analysis), so the ticket names the Log workspace instead. Defaults to false.
   */
  reopensTextLogFiles?: boolean;
}

export interface WorkspaceDefinition {
  /** Unique workspace identifier. */
  id: WorkspaceId;
  /** Human-readable label shown in toolbar dropdown. */
  label: string;
  /** Override for the status bar view label. Defaults to `${label} workspace`. */
  statusLabel?: string;
  /** Platforms this workspace is available on. "all" means no restriction. */
  platforms: PlatformKind[] | "all";
  /** Lazy-loaded main workspace component. */
  component: LazyExoticComponent<ComponentType>;
  /**
   * Lazy-loaded sidebar component. Omit to use the default LogSidebar.
   * Set capabilities.sidebar to false to render no sidebar.
   */
  sidebar?: LazyExoticComponent<ComponentType>;
  /** Lazy-loaded workspace-specific toolbar action. */
  toolbarAction?: LazyExoticComponent<ComponentType>;
  /** Lazy-loaded workspace-specific status-bar content. */
  statusBarContent?: LazyExoticComponent<ComponentType>;
  /** Lazy-loaded dock rendered beneath (or over) the active workspace body. */
  dock?: LazyExoticComponent<ComponentType>;
  /** Boolean capability flags. Sidebar defaults to true; other flags default to false. */
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
