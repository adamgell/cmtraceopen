import { Button, tokens } from "@fluentui/react-components";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";

function liveStateLabel(phase: string): string {
  switch (phase) {
    case "live":
      return "Live diagnostics active";
    case "starting":
      return "Live diagnostics starting";
    case "stopping":
      return "Live diagnostics stopping";
    default:
      return "Live diagnostics inactive";
  }
}

export function EspToolbarAction() {
  const phase = useEspDiagnosticsStore((state) => state.phase);
  const evidenceCount = useEspDiagnosticsStore(
    (state) => state.snapshot?.rawEvidence.length ?? 0,
  );
  const unreadEvidenceCount = useEspDiagnosticsStore(
    (state) => state.unreadEvidenceCount,
  );
  const evidenceViewMode = useEspDiagnosticsStore(
    (state) => state.evidenceViewMode,
  );
  const setEvidenceViewMode = useEspDiagnosticsStore(
    (state) => state.setEvidenceViewMode,
  );
  const markEvidenceRead = useEspDiagnosticsStore(
    (state) => state.markEvidenceRead,
  );

  const isOpen = evidenceViewMode !== "collapsed";
  const actionLabel = isOpen ? "Hide live logs" : "Open live logs";
  const accessibleLabel = `${actionLabel}, ${liveStateLabel(phase)}, ${evidenceCount} evidence ${
    evidenceCount === 1 ? "record" : "records"
  }, ${unreadEvidenceCount} unread`;
  const isLive = phase === "live";

  const toggleEvidence = () => {
    if (isOpen) {
      setEvidenceViewMode("collapsed");
      return;
    }

    setEvidenceViewMode("docked");
    markEvidenceRead();
  };

  return (
    <Button
      appearance="primary"
      size="small"
      aria-label={accessibleLabel}
      aria-pressed={isOpen}
      data-appearance="primary"
      onClick={toggleEvidence}
      style={{
        minWidth: 154,
        fontFamily: tokens.fontFamilyBase,
        fontWeight: 650,
      }}
    >
      <span
        aria-hidden="true"
        data-testid="esp-live-status-dot"
        style={{
          width: 8,
          height: 8,
          flexShrink: 0,
          borderRadius: "50%",
          backgroundColor: isLive
            ? tokens.colorPaletteGreenBackground3
            : phase === "starting" || phase === "stopping"
              ? tokens.colorPaletteYellowBackground3
              : tokens.colorNeutralForegroundDisabled,
          boxShadow: isLive
            ? `0 0 0 2px ${tokens.colorPaletteGreenBackground2}`
            : "none",
        }}
      />
      <span>{actionLabel}</span>
      <span
        aria-hidden="true"
        style={{
          minWidth: 20,
          padding: "0 5px",
          borderRadius: 9,
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorBrandForeground1,
          fontFamily: tokens.fontFamilyMonospace,
          fontSize: 10,
          lineHeight: "18px",
          textAlign: "center",
        }}
      >
        {evidenceCount}
      </span>
      {unreadEvidenceCount > 0 ? (
        <span
          aria-hidden="true"
          style={{
            fontFamily: tokens.fontFamilyMonospace,
            fontSize: 10,
          }}
        >
          +{unreadEvidenceCount}
        </span>
      ) : null}
    </Button>
  );
}
