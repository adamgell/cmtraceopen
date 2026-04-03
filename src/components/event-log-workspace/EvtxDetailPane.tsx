import { useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useEvtxStore } from "../../stores/evtx-store";

export function EvtxDetailPane() {
  const records = useEvtxStore((s) => s.records);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const [showRawXml, setShowRawXml] = useState(false);

  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );

  const record = useMemo(() => {
    if (selectedRecordId == null) return null;
    return records.find((r) => r.id === selectedRecordId) ?? null;
  }, [records, selectedRecordId]);

  if (!record) {
    return (
      <div
        style={{
          padding: "16px",
          color: tokens.colorNeutralForeground4,
          fontSize: `${metrics.fontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
          textAlign: "center",
        }}
      >
        Select a record to view details.
      </div>
    );
  }

  const fontSize = metrics.fontSize;
  const monoFontSize = Math.max(10, fontSize - 1);

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
              fontSize: "11px",
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
                      padding: "3px 8px 3px 0",
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
                      padding: "3px 0",
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
          <strong>Record ID:</strong> {record.eventRecordId}
        </span>
        <span>
          <strong>Source:</strong> {record.sourceLabel}
        </span>
      </div>

      {/* Raw XML */}
      <div>
        <Button
          size="small"
          appearance="subtle"
          onClick={() => setShowRawXml(!showRawXml)}
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
