import { Badge, tokens } from "@fluentui/react-components";
import {
  ArrowSync12Regular,
  ErrorCircle12Regular,
  Warning12Regular,
} from "@fluentui/react-icons";
import { useStatusBarForeground } from "../../components/layout/status-bar-foreground";
import {
  useEspDiagnosticsStore,
  type EspGraphPhase,
} from "./esp-diagnostics-store";

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

/**
 * The bar sits on the brand background, where colored text fails contrast, so
 * Graph state carries its tone as an icon beside the label.
 */
function GraphToneIcon({ phase }: { phase: EspGraphPhase }) {
  if (phase === "error") {
    return <ErrorCircle12Regular role="img" aria-label="Error" />;
  }
  if (phase === "partial") {
    return <Warning12Regular role="img" aria-label="Warning" />;
  }
  if (phase === "loading") {
    return <ArrowSync12Regular role="img" aria-label="In progress" />;
  }
  // "ready" deliberately has no icon: the store counts skipped and notFound
  // sections as complete, so a check could hide a Graph coverage gap.
  return null;
}

export function EspStatusBarContent() {
  const foreground = useStatusBarForeground();
  const phase = useEspDiagnosticsStore((state) => state.phase);
  const snapshot = useEspDiagnosticsStore((state) => state.snapshot);
  const elevationProbe = useEspDiagnosticsStore((state) => state.elevationProbe);
  const graphPhase = useEspDiagnosticsStore((state) => state.graphPhase);

  const evidenceCount = snapshot?.rawEvidence.length ?? 0;
  const sourceCount = snapshot
    ? new Set(
        snapshot.rawEvidence.map(
          (record) => record.provenance.sourceArtifactId,
        ),
      ).size
    : 0;
  // Treat the process as elevated if either the authoritative standalone probe
  // or the collected snapshot confirms it (the snapshot stays "not elevated"
  // until evidence collection reduces the elevation fact).
  const hasElevationInfo = elevationProbe != null || snapshot != null;
  const isElevated =
    (elevationProbe?.isElevated ?? false) ||
    (snapshot?.elevation.isElevated ?? false);
  const elevationLabel = !hasElevationInfo
    ? "Elevation unknown"
    : isElevated
      ? "Elevated"
      : "Not elevated";
  const isLive = phase === "live";

  return (
    <div
      data-status-content="esp-diagnostics"
      style={{
        width: "100%",
        minWidth: 0,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
        fontFamily: tokens.fontFamilyMonospace,
        color: foreground,
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
        <Badge
          appearance="outline"
          color="brand"
          style={{ color: foreground, borderColor: foreground }}
        >
          ESP
        </Badge>
        <span
          aria-hidden="true"
          style={{
            width: 7,
            height: 7,
            flexShrink: 0,
            borderRadius: "50%",
            // Live is shape (filled vs hollow), not palette color, so the
            // in-app high-contrast theme is covered. Under OS forced-colors
            // mode the background is forced and the box-shadow dropped, so
            // both states vanish and the phase label carries the state.
            backgroundColor: isLive ? foreground : "transparent",
            boxShadow: `0 0 0 1px ${foreground}`,
          }}
        />
        <strong style={{ whiteSpace: "nowrap" }}>{phaseLabels[phase]}</strong>
        <span aria-hidden="true">•</span>
        <span style={{ whiteSpace: "nowrap" }}>
          {sourceCount} {sourceCount === 1 ? "source" : "sources"}
        </span>
        <span aria-hidden="true">•</span>
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
        <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
          {hasElevationInfo && !isElevated && (
            <Warning12Regular role="img" aria-label="Warning" />
          )}
          {elevationLabel}
        </span>
        <span aria-hidden="true">•</span>
        <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <GraphToneIcon phase={graphPhase} />
          <span>{graphLabels[graphPhase]}</span>
        </span>
      </div>
    </div>
  );
}
