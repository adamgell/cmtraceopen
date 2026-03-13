import { useEffect } from "react";
import { getFileAssociationPromptStatus } from "../lib/commands";
import { useUiStore } from "../stores/ui-store";

/**
 * Shows the classic startup prompt for standalone Windows use when the app is
 * not already associated with .log/.lo_ files.
 */
export function useFileAssociationPrompt() {
  const setShowFileAssociationPrompt = useUiStore(
    (state) => state.setShowFileAssociationPrompt
  );

  useEffect(() => {
    let isDisposed = false;

    getFileAssociationPromptStatus()
      .then((status) => {
        if (isDisposed || !status.supported || !status.shouldPrompt) {
          return;
        }

        setShowFileAssociationPrompt(true);
      })
      .catch((error) => {
        console.error("[file-association-prompt] failed to load prompt status", {
          error,
        });
      });

    return () => {
      isDisposed = true;
    };
  }, [setShowFileAssociationPrompt]);
}
