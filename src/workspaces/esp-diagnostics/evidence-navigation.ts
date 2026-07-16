export const ESP_EVIDENCE_NAVIGATION_EVENT = "esp-evidence-navigation";

export type EspEvidenceNavigationTarget =
  | { kind: "evidence"; id: string }
  | { kind: "coverage"; id: string };

export function requestEspEvidenceNavigation(
  target: EspEvidenceNavigationTarget,
): void {
  window.dispatchEvent(
    new CustomEvent<EspEvidenceNavigationTarget>(
      ESP_EVIDENCE_NAVIGATION_EVENT,
      { detail: target },
    ),
  );
}
