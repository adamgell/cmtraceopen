import { Badge, tokens } from "@fluentui/react-components";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";

const phaseLabels = {
  idle: "Waiting for evidence",
  analyzing: "Analyzing captured evidence",
  starting: "Starting live session",
  live: "Live session",
  stopping: "Stopping live session",
  ready: "Analysis ready",
  error: "Diagnostics error",
} as const;

const graphLabels = {
  disabled: "Graph off",
  unavailable: "Graph unavailable",
  idle: "Graph local only",
  loading: "Graph loading",
  ready: "Graph ready",
  partial: "Graph partial",
  error: "Graph error",
  cancelled: "Graph cancelled",
} as const;

export function EspStatusBarContent() {
  const phase = useEspDiagnosticsStore((state) => state.phase);
  const snapshot = useEspDiagnosticsStore((state) => state.snapshot);
  const graphPhase = useEspDiagnosticsStore((state) => state.graphPhase);

  const evidenceCount = snapshot?.rawEvidence.length ?? 0;
  const sourceCount = snapshot
    ? new Set(
        snapshot.rawEvidence.map(
          (record) => record.provenance.sourceArtifactId,
        ),
      ).size
    : 0;
  const elevationLabel = !snapshot
    ? "Elevation unknown"
    : snapshot.elevation.isElevated
      ? "Elevated"
      : "Not elevated";
  const isLive = phase === "live";

  return (
    <div
      style={{
        width: "100%",
        minWidth: 0,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
        fontFamily: tokens.fontFamilyMonospace,
        fontSize: 11,
      }}
    >
      <div
        style={{
          minWidth: 0,
          display: "flex",
          alignItems: "center",
          gap: 8,
          overflow: "hidden",
        }}
      >
        <Badge appearance="outline" color={isLive ? "success" : "brand"}>
          ESP
        </Badge>
        <span
          aria-hidden="true"
          style={{
            width: 7,
            height: 7,
            flexShrink: 0,
            borderRadius: "50%",
            backgroundColor: isLive
              ? tokens.colorPaletteGreenBackground3
              : tokens.colorNeutralForegroundDisabled,
          }}
        />
        <strong style={{ whiteSpace: "nowrap" }}>{phaseLabels[phase]}</strong>
        <span style={{ color: tokens.colorNeutralForeground3 }}>•</span>
        <span style={{ whiteSpace: "nowrap" }}>
          {sourceCount} {sourceCount === 1 ? "source" : "sources"}
        </span>
        <span style={{ color: tokens.colorNeutralForeground3 }}>•</span>
        <span style={{ whiteSpace: "nowrap" }}>{evidenceCount} evidence</span>
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          flexShrink: 0,
          whiteSpace: "nowrap",
        }}
      >
        <span
          style={{
            color:
              snapshot && !snapshot.elevation.isElevated
                ? tokens.colorPaletteYellowForeground2
                : tokens.colorNeutralForeground2,
          }}
        >
          {elevationLabel}
        </span>
        <span style={{ color: tokens.colorNeutralForeground3 }}>•</span>
        <span
          style={{
            color:
              graphPhase === "error"
                ? tokens.colorPaletteRedForeground1
                : graphPhase === "partial" || graphPhase === "loading"
                  ? tokens.colorPaletteYellowForeground2
                  : graphPhase === "ready"
                    ? tokens.colorPaletteGreenForeground1
                    : tokens.colorNeutralForeground3,
          }}
        >
          {graphLabels[graphPhase]}
        </span>
      </div>
    </div>
  );
}
