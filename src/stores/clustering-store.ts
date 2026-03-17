import { create } from "zustand";
import type {
  Cluster,
  ClusterResult,
  ClusteringProgress,
} from "../types/clustering";
import { analyzeClusters } from "../lib/commands";

export type ClusteringPhase = "idle" | "analyzing" | "ready" | "error";

interface ClusteringState {
  /** Current analysis phase */
  phase: ClusteringPhase;
  /** Progress message during analysis */
  progressMessage: string;
  /** Progress percentage (0-100) */
  progressPercent: number | null;
  /** Clustering results */
  result: ClusterResult | null;
  /** Set of anomaly entry IDs for quick lookup */
  anomalyIds: Set<number> | null;
  /** Currently active/highlighted cluster ID */
  activeClusterId: number | null;
  /** Set of entry IDs in the active cluster (for filtering) */
  activeClusterEntryIds: Set<number> | null;
  /** Error message if analysis failed */
  errorMessage: string | null;

  /** Trigger clustering analysis for a file */
  analyzeClusters: (path: string) => Promise<void>;
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

export const useClusteringStore = create<ClusteringState>((set, get) => ({
  phase: "idle",
  progressMessage: "",
  progressPercent: null,
  result: null,
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

  setActiveCluster: (clusterId: number | null) => {
    const { result } = get();
    if (clusterId === null || !result) {
      set({
        activeClusterId: null,
        activeClusterEntryIds: null,
      });
      return;
    }

    const cluster = result.clusters.find((c) => c.id === clusterId);
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
