import { tokens } from "@fluentui/react-components";
import { LinkRegular, PulseRegular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import type { EspTimelineEntry } from "./types";

function timestampValue(entry: EspTimelineEntry): number {
  const parsed = Date.parse(
    entry.timestamp.normalizedUtc ?? entry.timestamp.rawText,
  );
  return Number.isFinite(parsed) ? parsed : 0;
}

function timeLabel(entry: EspTimelineEntry): string {
  const value = entry.timestamp.normalizedUtc ?? entry.timestamp.rawText;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return entry.timestamp.rawText;
  return parsed.toISOString().slice(11, 19);
}

function kindLabel(kind: EspTimelineEntry["kind"]): string {
  switch (kind) {
    case "profileDownload":
      return "Profile";
    case "offlineDomainJoin":
      return "ODJ";
    case "registration":
      return "Registration";
    case "workload":
      return "Workload";
    case "deliveryOptimization":
      return "Delivery Optimization";
    case "coverage":
      return "Coverage";
    case "process":
      return "Process";
    case "other":
      return "Other";
  }
}

interface LiveActivityProps {
  entries: EspTimelineEntry[];
}

export function LiveActivity({ entries }: LiveActivityProps) {
  const orderedEntries = [...entries].sort(
    (left, right) =>
      timestampValue(right) - timestampValue(left) ||
      left.entryId.localeCompare(right.entryId),
  );

  return (
    <section
      role="region"
      aria-labelledby="esp-live-activity-heading"
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          minHeight: 36,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
          padding: "0 10px",
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div>
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.09em",
              lineHeight: "11px",
              textTransform: "uppercase",
            }}
          >
            Independent evidence timeline
          </div>
          <h2
            id="esp-live-activity-heading"
            style={{
              margin: 0,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 13,
              fontWeight: 650,
              lineHeight: "17px",
            }}
          >
            Live activity
          </h2>
        </div>
        <strong style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: 10 }}>
          {entries.length} {entries.length === 1 ? "occurrence" : "occurrences"}
        </strong>
      </div>

      {orderedEntries.length === 0 ? (
        <div
          role="status"
          style={{
            minHeight: 52,
            display: "flex",
            alignItems: "center",
            gap: 7,
            padding: "0 10px",
            color: tokens.colorNeutralForeground2,
            fontSize: 11,
          }}
        >
          <PulseRegular aria-hidden="true" /> No timeline occurrences observed
          yet.
        </div>
      ) : (
        <ol style={{ margin: 0, padding: 0, listStyle: "none" }}>
          {orderedEntries.map((entry) => (
            <li
              key={entry.entryId}
              style={{
                display: "grid",
                gridTemplateColumns: "58px 86px minmax(0, 1fr) auto",
                alignItems: "start",
                gap: 8,
                padding: "7px 9px",
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
              }}
            >
              <time
                dateTime={entry.timestamp.normalizedUtc ?? undefined}
                style={{
                  color: tokens.colorNeutralForeground3,
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  fontSize: 10,
                  lineHeight: "14px",
                }}
              >
                {timeLabel(entry)}
              </time>
              <span
                style={{
                  color: tokens.colorBrandForeground1,
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  fontSize: 9,
                  fontWeight: 700,
                  lineHeight: "14px",
                  textTransform: "uppercase",
                }}
              >
                {kindLabel(entry.kind)}
              </span>
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 6,
                    fontFamily: LOG_UI_FONT_FAMILY,
                    fontSize: 11,
                    fontWeight: 650,
                    lineHeight: "14px",
                  }}
                >
                  <span>{entry.title}</span>
                  {entry.status ? (
                    <span
                      style={{
                        color: tokens.colorNeutralForeground3,
                        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                        fontSize: 9,
                      }}
                    >
                      {entry.status.display}
                    </span>
                  ) : null}
                </div>
                {entry.detail ? (
                  <div
                    style={{
                      marginTop: 1,
                      overflow: "hidden",
                      color: tokens.colorNeutralForeground3,
                      fontSize: 9,
                      lineHeight: "13px",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={entry.detail}
                  >
                    {entry.detail}
                  </div>
                ) : null}
              </div>
              <div style={{ display: "flex", gap: 5 }}>
                {entry.evidence.map((reference) => (
                  <a
                    key={reference.evidenceId}
                    href={`#evidence-${reference.evidenceId}`}
                    aria-label={`Open evidence ${reference.evidenceId}`}
                    title={`${reference.sourceArtifactId} · ${reference.evidenceId}`}
                    style={{ color: tokens.colorBrandForegroundLink }}
                  >
                    <LinkRegular aria-hidden="true" />
                  </a>
                ))}
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
