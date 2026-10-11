/**
 * The one entry point for selecting a record from a view (spec section 9, "Row click (any view)"):
 * select it, switch the rail to Details and show the rail if it is hidden.
 *
 * It is an action rather than an effect on `selectedRecordId` on purpose. The store reassigns the
 * selection when it reconciles or restores records, and those changes must not reopen a rail the
 * user closed; and clicking the row that is already selected changes no id, yet must still bring
 * the Details tab back. Every view calls this from its click and keyboard handlers.
 */
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";

/** `null` clears the selection and leaves the rail as it is. */
export function selectRecordAndShowDetails(id: number | null): void {
  useEvtxStore.getState().setSelectedRecordId(id);
  if (id === null) return;
  const layout = useEvtxLayoutStore.getState();
  layout.setRailTab("details");
  layout.setPanel("insights", true);
}
