import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useUiStore, type CollectionProgressState } from "../stores/ui-store";
import { isTauri } from "../lib/runtime";

const COLLECTION_PROGRESS_EVENT = "collection-progress";

interface CollectionProgressPayload {
  requestId: string;
  message: string;
  currentItem: string | null;
  completedItems: number;
  totalItems: number;
}

export function useCollectionProgressListener() {
  const setCollectionProgress = useUiStore((s) => s.setCollectionProgress);

  useEffect(() => {
    if (!isTauri) return;
    const unlisten = listen<CollectionProgressPayload>(
      COLLECTION_PROGRESS_EVENT,
      (event) => {
        const p = event.payload;
        const currentProgress = useUiStore.getState().collectionProgress;

        // Only update if this event matches the active collection request.
        if (currentProgress && currentProgress.requestId === p.requestId) {
          const update: CollectionProgressState = {
            requestId: p.requestId,
            message: p.message,
            currentItem: p.currentItem,
            completedItems: p.completedItems,
            totalItems: p.totalItems,
          };
          setCollectionProgress(update);
        }
      }
    );

    return () => {
      unlisten.then((dispose) => dispose());
    };
  }, [setCollectionProgress]);
}
