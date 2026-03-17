import { create } from "zustand";
import type {
  Cluster,
  ClusterableEntry,
  ClusterResult,
  ClusteringProgress,
  MultiSourceClusterResult,
} from "../types/clustering";
import { analyzeClusters, analyzeAllSources } from "../lib/commands";
import { useLogStore } from "./log-store";
import { useIntuneStore } from "./intune-store";
import { useDsregcmdStore } from "./dsregcmd-store";

export type ClusteringPhase = "idle" | "analyzing" | "ready" | "error";

interface ClusteringState {
  /** Current analysis phase */
  phase: ClusteringPhase;
  /** Progress message during analysis */
  progressMessage: string;
  /** Progress percentage (0-100) */
  progressPercent: number | null;
  /** Single-file clustering results */
  result: ClusterResult | null;
  /** Multi-source clustering results */
  multiSourceResult: MultiSourceClusterResult | null;
  /** Set of anomaly entry IDs for quick lookup */
  anomalyIds: Set<number> | null;
  /** Currently active/highlighted cluster ID */
  activeClusterId: number | null;
  /** Set of entry IDs in the active cluster (for filtering) */
  activeClusterEntryIds: Set<number> | null;
  /** Error message if analysis failed */
  errorMessage: string | null;

  /** Trigger clustering analysis for a single file */
  analyzeClusters: (path: string) => Promise<void>;
  /** Trigger multi-source clustering across all workspaces */
  analyzeAllSources: () => Promise<void>;
  /** Set the active cluster for highlighting/filtering */
  setActiveCluster: (clusterId: number | null) => void;
  /** Clear all clustering state */
  clearClustering: () => void;
  /** Update progress from backend events */
  updateProgress: (progress: ClusteringProgress) => void;
  /** Add new anomaly IDs (from incremental tail updates) */
  addAnomalyIds: (ids: number[]) => void;
  /** Update clusters from incremental results */
  updateClusters: (clusters: Cluster[]) => void;
}

/**
 * Collects text data from all workspace stores into ClusterableEntry items.
 * Each entry gets a unique ID within the clustering scope.
 */
function collectAllEntries(): ClusterableEntry[] {
  const entries: ClusterableEntry[] = [];
  let nextId = 1;

  // --- Log workspace ---
  const logState = useLogStore.getState();
  for (const entry of logState.entries) {
    if (!entry.message.trim()) continue;
    entries.push({
      id: nextId++,
      message: entry.message,
      source: "Log",
      severity: entry.severity ?? null,
      timestamp: entry.timestampDisplay ?? null,
    });
  }

  // --- Intune workspace ---
  const intuneState = useIntuneStore.getState();

  // Intune events
  for (const event of intuneState.events) {
    if (!event.detail.trim()) continue;
    entries.push({
      id: nextId++,
      message: `[${event.eventType}] ${event.name}: ${event.detail}`,
      source: "Intune Events",
      severity: event.status === "Failed" ? "Error" : event.status === "Success" ? "Info" : "Warning",
      timestamp: event.startTime ?? null,
    });
  }

  // Intune diagnostics
  for (const diag of intuneState.diagnostics) {
    const parts = [diag.title, diag.summary];
    if (diag.likelyCause) parts.push(diag.likelyCause);
    for (const ev of diag.evidence) {
      parts.push(ev);
    }
    entries.push({
      id: nextId++,
      message: parts.join(" — "),
      source: "Intune Diagnostics",
      severity: diag.severity ?? null,
      timestamp: null,
    });
  }

  // Intune event log entries
  if (intuneState.eventLogAnalysis) {
    for (const logEntry of intuneState.eventLogAnalysis.entries) {
      if (!logEntry.message.trim()) continue;
      entries.push({
        id: nextId++,
        message: `[${logEntry.provider}:${logEntry.eventId}] ${logEntry.message}`,
        source: "Intune Event Logs",
        severity: logEntry.severity ?? null,
        timestamp: logEntry.timestamp ?? null,
      });
    }
  }

  // --- DSRegCmd workspace ---
  const dsregState = useDsregcmdStore.getState();

  if (dsregState.result) {
    // DSRegCmd diagnostics
    for (const diag of dsregState.result.diagnostics) {
      const parts = [diag.title, diag.summary];
      for (const ev of diag.evidence) {
        parts.push(ev);
      }
      entries.push({
        id: nextId++,
        message: parts.join(" — "),
        source: "DSRegCmd Diagnostics",
        severity: diag.severity ?? null,
        timestamp: null,
      });
    }

    // DSRegCmd event log entries
    if (dsregState.result.eventLogAnalysis) {
      for (const logEntry of dsregState.result.eventLogAnalysis.entries) {
        if (!logEntry.message.trim()) continue;
        entries.push({
          id: nextId++,
          message: `[${logEntry.provider}:${logEntry.eventId}] ${logEntry.message}`,
          source: "DSRegCmd Event Logs",
          severity: logEntry.severity ?? null,
          timestamp: logEntry.timestamp ?? null,
        });
      }
    }
  }

  return entries;
}

export const useClusteringStore = create<ClusteringState>((set, get) => ({
  phase: "idle",
  progressMessage: "",
  progressPercent: null,
  result: null,
  multiSourceResult: null,
  anomalyIds: null,
  activeClusterId: null,
  activeClusterEntryIds: null,
  errorMessage: null,

  analyzeClusters: async (path: string) => {
    set({
      phase: "analyzing",
      progressMessage: "Starting analysis...",
      progressPercent: 0,
      errorMessage: null,
      result: null,
      multiSourceResult: null,
      anomalyIds: null,
      activeClusterId: null,
      activeClusterEntryIds: null,
    });

    try {
      const result = await analyzeClusters(path);
      set({
        phase: "ready",
        progressMessage: "",
        progressPercent: null,
        result,
        anomalyIds: new Set(result.anomalyEntryIds),
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      set({
        phase: "error",
        progressMessage: "",
        progressPercent: null,
        errorMessage: message,
      });
    }
  },

  analyzeAllSources: async () => {
    set({
      phase: "analyzing",
      progressMessage: "Collecting entries from all workspaces...",
      progressPercent: 0,
      errorMessage: null,
      result: null,
      multiSourceResult: null,
      anomalyIds: null,
      activeClusterId: null,
      activeClusterEntryIds: null,
    });

    try {
      const entries = collectAllEntries();
      if (entries.length === 0) {
        set({
          phase: "error",
          progressMessage: "",
          progressPercent: null,
          errorMessage:
            "No data available. Open log files or run Intune/DSRegCmd analysis first.",
        });
        return;
      }

      set({
        progressMessage: `Sending ${entries.length} entries for analysis...`,
        progressPercent: 2,
      });

      const result = await analyzeAllSources(entries);
      set({
        phase: "ready",
        progressMessage: "",
        progressPercent: null,
        multiSourceResult: result,
        anomalyIds: new Set(result.anomalyEntryIds),
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      set({
        phase: "error",
        progressMessage: "",
        progressPercent: null,
        errorMessage: message,
      });
    }
  },

  setActiveCluster: (clusterId: number | null) => {
    const { result, multiSourceResult } = get();
    if (clusterId === null) {
      set({
        activeClusterId: null,
        activeClusterEntryIds: null,
      });
      return;
    }

    const clusters =
      multiSourceResult?.clusters ?? result?.clusters ?? [];
    const cluster = clusters.find((c) => c.id === clusterId);
    set({
      activeClusterId: clusterId,
      activeClusterEntryIds: cluster
        ? new Set(cluster.entryIds)
        : null,
    });
  },

  clearClustering: () =>
    set({
      phase: "idle",
      progressMessage: "",
      progressPercent: null,
      result: null,
      multiSourceResult: null,
      anomalyIds: null,
      activeClusterId: null,
      activeClusterEntryIds: null,
      errorMessage: null,
    }),

  updateProgress: (progress: ClusteringProgress) => {
    set({
      progressMessage: progress.message,
      progressPercent: progress.percent,
    });
  },

  addAnomalyIds: (ids: number[]) => {
    const current = get().anomalyIds;
    const updated = current ? new Set(current) : new Set<number>();
    for (const id of ids) {
      updated.add(id);
    }
    set({ anomalyIds: updated });
  },

  updateClusters: (clusters: Cluster[]) => {
    const { result } = get();
    if (!result) return;

    const updatedClusters = result.clusters.map((existing) => {
      const updated = clusters.find((c) => c.id === existing.id);
      return updated ?? existing;
    });

    set({
      result: { ...result, clusters: updatedClusters },
    });
  },
}));
