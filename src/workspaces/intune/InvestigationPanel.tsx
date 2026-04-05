import {
  Badge,
  Caption1,
  Card,
  Title3,
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { DownloadSurface } from "./DownloadSurface";
import { EventTimeline } from "./EventTimeline";
import type { DownloadStat, IntuneEvent, IntuneEventType, IntuneStatus } from "./types";

/** Inline style that forces Fluent typography components to inherit font size. */
const inheritFontSize: React.CSSProperties = { fontSize: "inherit" };

const useInvestigationStyles = makeStyles({
  investigationShell: {
    display: "grid",
    gap: "12px",
    height: "100%",
    minHeight: 0,
  },
  investigationFrame: {
    minHeight: "520px",
    display: "flex",
    flexDirection: "column",
    overflow: "hidden",
    backgroundColor: tokens.colorNeutralCardBackground,
  },
  investigationHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    alignItems: "center",
    flexWrap: "wrap",
    ...shorthands.padding("12px", "14px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  investigationBody: {
    flex: 1,
    minHeight: 0,
  },
  scopeRow: {
    display: "flex",
    gap: "6px",
    flexWrap: "wrap",
    alignItems: "center",
  },
  textStack: {
    display: "grid",
    gap: "4px",
  },
});

export type InvestigationSurface = "timeline" | "downloads";

export interface InvestigationPanelProps {
  surface: InvestigationSurface;
  events: IntuneEvent[];
  downloads: DownloadStat[];
  timelineScopeFilePath: string | null;
  filterEventType: IntuneEventType | "All";
  filterStatus: IntuneStatus | "All";
}

export function InvestigationPanel(props: InvestigationPanelProps) {
  const styles = useInvestigationStyles();
  const {
    surface,
    events,
    downloads,
    timelineScopeFilePath,
    filterEventType,
    filterStatus,
  } = props;

  return (
    <div className={styles.investigationShell}>
      <Card className={styles.investigationFrame}>
        <div className={styles.investigationHeader}>
          <div className={styles.textStack}>
            <Title3 style={inheritFontSize}>
              {surface === "timeline"
                ? "Event evidence"
                : "Download evidence"}
            </Title3>
            <Caption1 style={inheritFontSize}>
              {surface === "timeline"
                ? "Timeline filters and file scope are driven by the triage actions you choose above."
                : "Download rows remain available as the supporting evidence surface for content retrieval failures."}
            </Caption1>
          </div>
          <div className={styles.scopeRow}>
            {surface === "timeline" && timelineScopeFilePath && (
              <Badge appearance="filled" color="informative">
                {getFileName(timelineScopeFilePath)}
              </Badge>
            )}
            {surface === "timeline" && filterEventType !== "All" && (
              <Badge appearance="outline" color="brand">
                {formatEventTypeLabel(filterEventType)}
              </Badge>
            )}
            {surface === "timeline" && filterStatus !== "All" && (
              <Badge appearance="outline" color="warning">
                {filterStatus}
              </Badge>
            )}
          </div>
        </div>

        <div className={styles.investigationBody}>
          {surface === "timeline" ? (
            <EventTimeline events={events} />
          ) : (
            <DownloadSurface downloads={downloads} />
          )}
        </div>
      </Card>
    </div>
  );
}

/* ─── Pure utility functions ─── */

function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  return normalized.split("/").pop() ?? path;
}

function formatEventTypeLabel(eventType: IntuneEventType): string {
  switch (eventType) {
    case "Win32App":
      return "Win32 app";
    case "WinGetApp":
      return "WinGet app";
    case "PowerShellScript":
      return "PowerShell script";
    case "Remediation":
      return "Remediation";
    case "Esp":
      return "ESP";
    case "SyncSession":
      return "Sync session";
    case "PolicyEvaluation":
      return "Policy evaluation";
    case "ContentDownload":
      return "Content download";
    case "Other":
    default:
      return "Other";
  }
}
