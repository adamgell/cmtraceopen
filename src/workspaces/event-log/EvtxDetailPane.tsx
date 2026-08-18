import { useEffect, useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
  clampLogDetailsFontSize,
  getLogDetailsLineHeight,
} from "../../lib/log-accessibility";
import { useMarkerStore } from "../../stores/marker-store";
import { useUiStore } from "../../stores/ui-store";
import {
  getEvtxMarker,
  loadEvtxMarkers,
  toggleEvtxBookmark,
  toggleEvtxTag,
} from "./evtx-marker-adapter";
import { useEvtxStore } from "./evtx-store";

export function EvtxDetailPane() {
  const markersByFile = useMarkerStore((s) => s.markersByFile);
  const records = useEvtxStore((s) => s.records);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const [showRawXml, setShowRawXml] = useState(false);

  const logDetailsFontSize = useUiStore((s) => s.logDetailsFontSize);
  const fontSize = clampLogDetailsFontSize(logDetailsFontSize);
  const detailLineHeight = getLogDetailsLineHeight(logDetailsFontSize);
  const monoFontSize = Math.max(10, fontSize - 1);
  const labelFontSize = Math.max(10, fontSize - 2);

  const record = useMemo(() => {
    if (selectedRecordId == null) return null;
    return records.find((r) => r.id === selectedRecordId) ?? null;
  }, [records, selectedRecordId]);
  const marker = useMemo(
    () => (record ? getEvtxMarker(record, markersByFile) : null),
    [record, markersByFile]
  );

  useEffect(() => {
    if (record) loadEvtxMarkers([record.sourceLabel]);
  }, [record?.sourceLabel]);

  if (!record) {
    return (
      <div
        style={{
          padding: "16px",
          color: tokens.colorNeutralForeground4,
          fontSize: `${fontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
          textAlign: "center",
        }}
      >
        Select a record to view details.
      </div>
    );
  }


  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        overflow: "auto",
        padding: "12px",
        fontFamily: LOG_UI_FONT_FAMILY,
        fontSize: `${fontSize}px`,
        lineHeight: `${detailLineHeight}px`,
        gap: "12px",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          flexWrap: "wrap",
        }}
      >
        <span
          style={{
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
          }}
        >
          Event {record.eventId}
        </span>
        <span
          style={{
            fontSize: `${monoFontSize}px`,
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          }}
        >
          {record.timestamp}
        </span>
        <span
          style={{
            fontSize: `${monoFontSize}px`,
            color: tokens.colorNeutralForeground4,
          }}
        >
          {record.level}
        </span>
        <div role="group" aria-label="Selected event markers" style={{ display: "flex", gap: "6px" }}>
          <button
            type="button"
            aria-label={marker?.category === "bookmark" ? "Tag event" : marker ? "Remove event tag" : "Tag event"}
            aria-pressed={Boolean(marker && marker.category !== "bookmark")}
            onClick={() => toggleEvtxTag(record)}
            style={{
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "4px",
              padding: "3px 7px",
              cursor: "pointer",
              background: "transparent",
              color: tokens.colorNeutralForeground1,
            }}
          >
            {marker && marker.category !== "bookmark" ? `Tagged: ${marker.category}` : "Tag"}
          </button>
          <button
            type="button"
            aria-label={marker?.category === "bookmark" ? "Remove bookmark" : "Bookmark event"}
            aria-pressed={marker?.category === "bookmark"}
            onClick={() => toggleEvtxBookmark(record)}
            style={{
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "4px",
              padding: "3px 7px",
              cursor: "pointer",
              background: "transparent",
              color: marker?.category === "bookmark" ? "#8b5cf6" : tokens.colorNeutralForeground1,
            }}
          >
            {marker?.category === "bookmark" ? "Bookmarked" : "Bookmark"}
          </button>
        </div>
      </div>

      {/* Message */}
      {record.message && (
        <div
          style={{
            fontSize: `${monoFontSize}px`,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            backgroundColor: tokens.colorNeutralBackground1,
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            padding: "8px",
            borderRadius: "4px",
            color: tokens.colorNeutralForeground1,
            minHeight: "60px",
            maxHeight: "200px",
            overflow: "auto",
            flexShrink: 0,
          }}
        >
          {record.message}
        </div>
      )}

      {/* Event Data key-value table */}
      {record.eventData.length > 0 && (
        <div>
          <div
            style={{
              fontSize: `${labelFontSize}px`,
              fontWeight: 600,
              color: tokens.colorNeutralForeground3,
              textTransform: "uppercase",
              marginBottom: "4px",
            }}
          >
            Event Data
          </div>
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              fontSize: `${monoFontSize}px`,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            }}
          >
            <tbody>
              {record.eventData.map((field, i) => (
                <tr
                  key={`${field.name}-${i}`}
                  style={{
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                  }}
                >
                  <td
                    style={{
                      padding: "4px 8px 4px 0",
                      fontWeight: 600,
                      color: tokens.colorNeutralForeground3,
                      verticalAlign: "top",
                      whiteSpace: "nowrap",
                      width: "1%",
                    }}
                  >
                    {field.name}
                  </td>
                  <td
                    style={{
                      padding: "4px 0",
                      color: tokens.colorNeutralForeground1,
                      wordBreak: "break-all",
                    }}
                  >
                    {field.value}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Metadata */}
      <div
        style={{
          display: "flex",
          gap: "16px",
          flexWrap: "wrap",
          fontSize: `${monoFontSize}px`,
          color: tokens.colorNeutralForeground3,
        }}
      >
        <span>
          <strong>Provider:</strong> {record.provider}
        </span>
        <span>
          <strong>Channel:</strong> {record.channel}
        </span>
        <span>
          <strong>Computer:</strong> {record.computer}
        </span>
        <span>
          <strong>Record ID:</strong> {record.eventRecordIdText ?? record.eventRecordId}
        </span>
        <span>
          <strong>Source:</strong> {record.sourceLabel}
        </span>
        {/* System-block fields. Rendered only when the provider actually wrote them, so an absent
            value reads as absent rather than as a zero the provider never claimed. */}
        {record.task != null && (
          <span>
            <strong>Task:</strong> {record.task}
          </span>
        )}
        {record.opcode != null && (
          <span>
            <strong>Opcode:</strong> {record.opcode}
          </span>
        )}
        {record.processId != null && (
          <span>
            <strong>PID:</strong> {record.processId}
          </span>
        )}
        {record.threadId != null && (
          <span>
            <strong>TID:</strong> {record.threadId}
          </span>
        )}
        {record.keywords && (
          <span>
            <strong>Keywords:</strong> {record.keywords}
          </span>
        )}
        {record.userSid && (
          <span title="Raw security identifier; not resolved to an account name">
            <strong>User SID:</strong> {record.userSid}
          </span>
        )}
      </div>

      {/* Map-derived columns. Only present where a map covers this event type, so the section is
          hidden entirely rather than showing an empty heading. */}
      {record.mapped && record.mapped.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div
            style={{
              fontSize: `${monoFontSize}px`,
              fontWeight: 600,
              marginBottom: "4px",
              color: tokens.colorNeutralForeground2,
            }}
          >
            Mapped fields
          </div>
          {record.mapped.map((column) => (
            <div
              key={column.property}
              style={{
                display: "flex",
                gap: "8px",
                fontSize: `${monoFontSize}px`,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              }}
            >
              <span
                style={{
                  minWidth: "110px",
                  color: tokens.colorNeutralForeground3,
                }}
              >
                {column.property}
              </span>
              <span
                title={
                  column.complete
                    ? undefined
                    : "The map references a field this event did not carry; the unresolved placeholder is shown as-is"
                }
                style={{
                  color: column.complete
                    ? tokens.colorNeutralForeground1
                    : tokens.colorPaletteMarigoldForeground1,
                }}
              >
                {column.text}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Raw XML */}
      <div>
        <Button
          size="small"
          appearance="subtle"
          onClick={() => setShowRawXml(!showRawXml)}
          style={{ fontSize: `${fontSize}px` }}
        >
          {showRawXml ? "Hide Raw XML" : "Show Raw XML"}
        </Button>
        {showRawXml && (
          <pre
            style={{
              marginTop: "6px",
              fontSize: `${Math.max(10, monoFontSize - 1)}px`,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              backgroundColor: tokens.colorNeutralBackground3,
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              padding: "8px",
              borderRadius: "4px",
              maxHeight: "300px",
              overflow: "auto",
              color: tokens.colorNeutralForeground1,
            }}
          >
            {record.rawXml}
          </pre>
        )}
      </div>
    </div>
  );
}
