import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useClusteringStore } from "../stores/clustering-store";
import type { ClusteringProgress } from "../types/clustering";

const CLUSTERING_PROGRESS_EVENT = "clustering-progress";

export function useClusteringProgress() {
  const updateProgress = useClusteringStore((s) => s.updateProgress);

  useEffect(() => {
    const unlisten = listen<ClusteringProgress>(
      CLUSTERING_PROGRESS_EVENT,
      (event) => {
        updateProgress(event.payload);
      }
    );

    return () => {
      unlisten.then((dispose) => dispose());
    };
  }, [updateProgress]);
}
