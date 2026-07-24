export const ESP_LIVE_EVIDENCE_TRIGGER_ID = "esp-live-evidence-trigger";

export function focusEspLiveEvidenceTrigger(): void {
  if (typeof document === "undefined") return;

  document
    .getElementById(ESP_LIVE_EVIDENCE_TRIGGER_ID)
    ?.focus({ preventScroll: true });
}
