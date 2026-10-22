/**
 * Presentation state for the Event Logs workbench layout (spec sections 5, 8.2 and 9).
 *
 * Kept apart from `evtx-store`, which is load-bearing for queries and holds record data. Nothing
 * here carries record content: it is the active view, which regions are shown, the rail tab, two
 * pixel sizes and the correlation dock's window width. Whether the dock is collapsed is held here
 * too but is not persisted: a dock that reopens shows what is around the selected event.
 *
 * Persistence mirrors `ui-store` and `evtx-filter-store`: zustand `persist` over localStorage
 * under a dedicated key. Every persisted value is sanitized in `merge`, which runs on each
 * rehydration, so a hand-edited or stale envelope cannot reach the UI with an unknown view or an
 * out-of-range size (`migrate` only runs when the stored version differs).
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { DOCK_MIN_HEIGHT_PX } from "./evtx-main-column-layout";

export const EVTX_VIEW_IDS = [
  "table",
  "grouped",
  "timeline",
  "charts",
  "correlation",
] as const;
export type EvtxViewId = (typeof EVTX_VIEW_IDS)[number];

export const EVTX_VIEW_LABELS: Record<EvtxViewId, string> = {
  table: "Table",
  grouped: "Grouped",
  timeline: "Timeline",
  charts: "Charts",
  correlation: "Correlation",
};

/** Id of the tabpanel the Layout tablist controls. */
export const EVTX_VIEW_PANEL_ID = "evtx-view-panel";
export const evtxViewTabId = (view: EvtxViewId) => `evtx-view-tab-${view}`;

/** Id of a panel toggle in the view bar, so the dock can return focus to the one that opened it. */
export const evtxPanelToggleId = (panel: EvtxPanelId) => `evtx-panel-toggle-${panel}`;

/** Ids that link each rail tab to its panel. */
export const evtxRailTabId = (tab: "insights" | "chains" | "details") => `evtx-rail-tab-${tab}`;
export const evtxRailPanelId = (tab: "insights" | "chains" | "details") => `evtx-rail-panel-${tab}`;

/** Tab ids of the Insights rail (spec section 8.13: Insights, Chains, Details). */
export const EVTX_RAIL_TAB_IDS = ["insights", "chains", "details"] as const;
export type EvtxRailTabId = (typeof EVTX_RAIL_TAB_IDS)[number];

export type EvtxPanelId = "channels" | "insights" | "dock";
export type EvtxPanels = Record<EvtxPanelId, boolean>;

/** The correlation dock's window, as the half width around the selected event (spec 8.12). */
export const EVTX_DOCK_WINDOW_OPTIONS_MS = [30_000, 75_000, 120_000, 300_000] as const;
type EvtxDockWindowMs = (typeof EVTX_DOCK_WINDOW_OPTIONS_MS)[number];
const DEFAULT_DOCK_WINDOW_MS: EvtxDockWindowMs = 75_000;

export const EVTX_LAYOUT_STORAGE_KEY = "cmtraceopen-evtx-layout";

export const DEFAULT_RAIL_WIDTH = 340;
export const MIN_RAIL_WIDTH = 280;
export const MAX_RAIL_WIDTH = 480;
export const DEFAULT_DOCK_HEIGHT = 210;
/**
 * The least the dock is stored or drawn at: its header plus one lane (evtx-main-column-layout.ts).
 * The same number bounds the resize handle, so a window too short for the chosen height can render
 * the dock at it and the handle can still move it.
 */
export const MIN_DOCK_HEIGHT = DOCK_MIN_HEIGHT_PX;
/** The dock may take at most half the viewport height; applied in pixels at use time. */
export const MAX_DOCK_HEIGHT_RATIO = 0.5;

/**
 * Which panels have content to show. A panel that has none (a phase that has not built it yet) has
 * its toggle disabled, and a persisted `true` is forced back to `false` on rehydration. The phase
 * that enables a panel that defaults ON must flip it here AND in `DEFAULT_PANELS`, and must bump the
 * persist `version`. It adds NO `migrate` function (AGENTS.md rules out compatibility migrations):
 * an envelope written under an older version is discarded, so the stored layout resets to the
 * defaults and nobody stays on a persisted `false` for the new panel. Phase 4 did this for Insights
 * (version 2).
 *
 * The correlation dock (Phase 11) is available but defaults OFF (R4: it takes 210 px of the main
 * column, and the Table grid keeps its floor of five rows whether it is open or not, so the dock
 * is the panel that gives way; see evtx-main-column-layout.ts), so its default is the `false`
 * every stored layout already holds, and shipping it needed no version bump.
 */
export const EVTX_PANELS_AVAILABLE: EvtxPanels = {
  channels: true,
  insights: true,
  dock: true,
};

const DEFAULT_PANELS: EvtxPanels = { channels: true, insights: true, dock: false };

/** Persist version of the layout envelope. 2: the Insights rail shipped and defaults on. */
export const EVTX_LAYOUT_VERSION = 2;

function clampNumber(value: unknown, fallback: number, min: number, max: number): number {
  const number = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  return Math.min(max, Math.max(min, Math.round(number)));
}

export function clampRailWidth(value: unknown): number {
  return clampNumber(value, DEFAULT_RAIL_WIDTH, MIN_RAIL_WIDTH, MAX_RAIL_WIDTH);
}

/** The pixel ceiling for the dock at the current viewport height. Never below the minimum. */
export function maxDockHeightFor(viewportHeight: number): number {
  return Math.max(MIN_DOCK_HEIGHT, Math.floor(viewportHeight * MAX_DOCK_HEIGHT_RATIO));
}

/**
 * Clamps the dock height. The ceiling depends on the viewport, so callers pass the height at use
 * time; the store itself only enforces the minimum plus a sane absolute bound.
 */
export function clampDockHeight(value: unknown, viewportHeight?: number): number {
  const max =
    viewportHeight === undefined || !Number.isFinite(viewportHeight)
      ? Number.MAX_SAFE_INTEGER
      : maxDockHeightFor(viewportHeight);
  return clampNumber(value, DEFAULT_DOCK_HEIGHT, MIN_DOCK_HEIGHT, max);
}

/**
 * The Chains tab is on show: the Insights rail is visible and on that tab. A hidden rail shows no
 * tab, whatever tab it was left on.
 */
export function chainsTabShown(layout: Pick<EvtxPersistedLayout, "panels" | "railTab">): boolean {
  return layout.panels.insights && layout.railTab === "chains";
}

/**
 * Whether the correlation entries (titles, spans and positions) must be read: the two surfaces that
 * list entries are the Correlation view and the Chains tab. The counts-only consumers (the Insights
 * card, the tab's number) never cause a scan. The one rule: the workspace asks the hook with it.
 */
export function correlationItemsNeeded(
  layout: Pick<EvtxPersistedLayout, "activeView" | "panels" | "railTab">,
): boolean {
  return layout.activeView === "correlation" || chainsTabShown(layout);
}

function isOneOf<T extends string>(list: readonly T[], value: unknown): value is T {
  return typeof value === "string" && (list as readonly string[]).includes(value);
}

function isDockWindowMs(value: unknown): value is EvtxDockWindowMs {
  return (EVTX_DOCK_WINDOW_OPTIONS_MS as readonly unknown[]).includes(value);
}

export interface EvtxPersistedLayout {
  activeView: EvtxViewId;
  panels: EvtxPanels;
  railTab: EvtxRailTabId;
  railWidth: number;
  dockHeight: number;
  /** Half the correlation dock's window: one of `EVTX_DOCK_WINDOW_OPTIONS_MS`. */
  dockWindowMs: EvtxDockWindowMs;
}

/** Builds a valid layout from anything read back from storage. Unknown keys are dropped. */
export function sanitizeLayout(raw: unknown): EvtxPersistedLayout {
  const source = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const rawPanels = (
    source.panels && typeof source.panels === "object" ? source.panels : {}
  ) as Record<string, unknown>;
  const panel = (id: EvtxPanelId): boolean =>
    EVTX_PANELS_AVAILABLE[id] &&
    (typeof rawPanels[id] === "boolean" ? (rawPanels[id] as boolean) : DEFAULT_PANELS[id]);
  return {
    activeView: isOneOf(EVTX_VIEW_IDS, source.activeView) ? source.activeView : "table",
    panels: { channels: panel("channels"), insights: panel("insights"), dock: panel("dock") },
    railTab: isOneOf(EVTX_RAIL_TAB_IDS, source.railTab) ? source.railTab : "insights",
    railWidth: clampRailWidth(source.railWidth),
    dockHeight: clampDockHeight(source.dockHeight),
    dockWindowMs: isDockWindowMs(source.dockWindowMs) ? source.dockWindowMs : DEFAULT_DOCK_WINDOW_MS,
  };
}

interface EvtxLayoutState extends EvtxPersistedLayout {
  /** The dock shows only its header row. Not persisted. */
  dockCollapsed: boolean;
  setActiveView: (view: EvtxViewId) => void;
  setPanel: (panel: EvtxPanelId, visible: boolean) => void;
  togglePanel: (panel: EvtxPanelId) => void;
  setRailTab: (tab: EvtxRailTabId) => void;
  setRailWidth: (width: number) => void;
  /** Pass the viewport height to apply the 50vh ceiling in pixels. */
  setDockHeight: (height: number, viewportHeight?: number) => void;
  /** Ignores a width that is not one of the four options. */
  setDockWindowMs: (windowMs: number) => void;
  setDockCollapsed: (collapsed: boolean) => void;
}

export const useEvtxLayoutStore = create<EvtxLayoutState>()(
  persist(
    (set) => ({
      ...sanitizeLayout(undefined),
      dockCollapsed: false,
      setActiveView: (view) => {
        if (isOneOf(EVTX_VIEW_IDS, view)) set({ activeView: view });
      },
      setPanel: (panel, visible) => {
        if (!EVTX_PANELS_AVAILABLE[panel]) return;
        // A dock that is shown again is shown expanded: its toggle asks for the dock, not for a header.
        set((state) => ({
          panels: { ...state.panels, [panel]: visible },
          ...(panel === "dock" && visible ? { dockCollapsed: false } : {}),
        }));
      },
      togglePanel: (panel) => {
        if (!EVTX_PANELS_AVAILABLE[panel]) return;
        set((state) => ({
          panels: { ...state.panels, [panel]: !state.panels[panel] },
          ...(panel === "dock" && !state.panels.dock ? { dockCollapsed: false } : {}),
        }));
      },
      setRailTab: (tab) => {
        if (isOneOf(EVTX_RAIL_TAB_IDS, tab)) set({ railTab: tab });
      },
      setRailWidth: (width) => set({ railWidth: clampRailWidth(width) }),
      setDockHeight: (height, viewportHeight) =>
        set({ dockHeight: clampDockHeight(height, viewportHeight) }),
      setDockWindowMs: (windowMs) => {
        if (isDockWindowMs(windowMs)) set({ dockWindowMs: windowMs });
      },
      setDockCollapsed: (collapsed) => set({ dockCollapsed: collapsed === true }),
    }),
    {
      name: EVTX_LAYOUT_STORAGE_KEY,
      version: EVTX_LAYOUT_VERSION,
      partialize: (state): EvtxPersistedLayout => ({
        activeView: state.activeView,
        panels: state.panels,
        railTab: state.railTab,
        railWidth: state.railWidth,
        dockHeight: state.dockHeight,
        dockWindowMs: state.dockWindowMs,
      }),
      merge: (persisted, current) => ({ ...current, ...sanitizeLayout(persisted) }),
    },
  ),
);
