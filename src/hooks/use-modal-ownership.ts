import { useLayoutEffect } from "react";
import { type ModalOwner, useUiStore } from "../stores/ui-store";

/**
 * Connects component-local confirmation state to the application-wide modal
 * queue. The local state remains the source of truth for whether the request
 * still matters; the coordinator decides when that request may render.
 */
export function useModalOwnership(
  owner: ModalOwner,
  requested: boolean,
): boolean {
  const modalOwner = useUiStore((state) => state.modalOwner);
  const requestModal = useUiStore((state) => state.requestModal);
  const releaseModal = useUiStore((state) => state.releaseModal);

  useLayoutEffect(() => {
    if (requested) {
      requestModal(owner);
    } else {
      releaseModal(owner);
    }

    return () => releaseModal(owner);
  }, [owner, releaseModal, requestModal, requested]);

  return requested && modalOwner === owner;
}
