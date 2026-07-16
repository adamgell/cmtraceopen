import { useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { LinkRegular, PulseRegular } from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import { requestEspEvidenceNavigation } from "./evidence-navigation";
import type { EspTimelineEntry } from "./types";

function timestampValue(entry: EspTimelineEntry): number | null {
  if (!entry.timestamp.normalizedUtc) return null;
  const parsed = Date.parse(entry.timestamp.normalizedUtc);
  return Number.isFinite(parsed) ? parsed : null;
}

function compareEntries(
  left: EspTimelineEntry,
  right: EspTimelineEntry,
): number {
  const leftTimestamp = timestampValue(left);
  const rightTimestamp = timestampValue(right);
  if (leftTimestamp !== null && rightTimestamp !== null) {
    return (
      rightTimestamp - leftTimestamp ||
      left.entryId.localeCompare(right.entryId)
    );
  }
  if (leftTimestamp !== null) return -1;
  if (rightTimestamp !== null) return 1;
  return left.entryId.localeCompare(right.entryId);
}

function timeLabel(entry: EspTimelineEntry): string {
  if (!entry.timestamp.normalizedUtc) return entry.timestamp.rawText;
  const parsed = new Date(entry.timestamp.normalizedUtc);
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

export const ESP_ACTIVITY_WINDOW_SIZE = 80;

export function LiveActivity({ entries }: LiveActivityProps) {
  const [windowStart, setWindowStart] = useState(0);
  const orderedEntries = useMemo(
    () => [...entries].sort(compareEntries),
    [entries],
  );
  const maximumStart = Math.max(
    0,
    orderedEntries.length - ESP_ACTIVITY_WINDOW_SIZE,
  );
  const safeStart = Math.min(windowStart, maximumStart);
  const visibleEntries = orderedEntries.slice(
    safeStart,
    safeStart + ESP_ACTIVITY_WINDOW_SIZE,
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
              fontSize: 10,
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
        <>
          {orderedEntries.length > ESP_ACTIVITY_WINDOW_SIZE ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
                padding: "5px 9px",
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                color: tokens.colorNeutralForeground2,
                fontSize: 10,
              }}
            >
              <span>
                Showing {safeStart + 1}–
                {Math.min(
                  safeStart + ESP_ACTIVITY_WINDOW_SIZE,
                  orderedEntries.length,
                )}{" "}
                of {orderedEntries.length} occurrences
              </span>
              <span style={{ display: "inline-flex", gap: 5 }}>
                <Button
                  size="small"
                  disabled={safeStart === 0}
                  onClick={() =>
                    setWindowStart(
                      Math.max(0, safeStart - ESP_ACTIVITY_WINDOW_SIZE),
                    )
                  }
                >
                  Newer
                </Button>
                <Button
                  size="small"
                  disabled={safeStart >= maximumStart}
                  onClick={() =>
                    setWindowStart(
                      Math.min(
                        maximumStart,
                        safeStart + ESP_ACTIVITY_WINDOW_SIZE,
                      ),
                    )
                  }
                >
                  Older
                </Button>
              </span>
            </div>
          ) : null}
          <ol style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {visibleEntries.map((entry) => (
              <li
                key={entry.entryId}
                data-testid="esp-activity-entry"
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
                    fontSize: 10,
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
                          fontSize: 10,
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
                        fontSize: 10,
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
                      onClick={() =>
                        requestEspEvidenceNavigation({
                          kind: "evidence",
                          id: reference.evidenceId,
                        })
                      }
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
        </>
      )}
    </section>
  );
}
