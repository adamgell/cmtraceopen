import { useEffect, useMemo, useRef, useState } from "react";
import { Button, Input, tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { EspEvidenceBoundaryMarker } from "./esp-diagnostics-store";
import type {
  EspDiagnosticsSnapshot,
  EspObservationValue,
  EspRawEvidenceRecord,
  EspTimelineEntry,
} from "./types";

type LiveEvidenceSeverity = "error" | "warning" | "info";

interface LiveEvidenceRowBase {
  rowId: string;
  timestamp: string;
  source: string;
  severity: LiveEvidenceSeverity;
  component: string;
  message: string;
}

interface LiveEvidenceRecordRow extends LiveEvidenceRowBase {
  kind: "evidence";
  record: EspRawEvidenceRecord;
}

interface LiveEvidenceBoundaryRow extends LiveEvidenceRowBase {
  kind: "sourceReset";
  marker: EspEvidenceBoundaryMarker;
}

type LiveEvidenceRow = LiveEvidenceRecordRow | LiveEvidenceBoundaryRow;

export interface LiveEvidenceTableProps {
  snapshot: EspDiagnosticsSnapshot | null;
  boundaryMarkers?: EspEvidenceBoundaryMarker[];
}

function observationValueText(value: EspObservationValue): string {
  if ("text" in value) return value.text;
  if ("integer" in value) return String(value.integer);
  if ("unsigned" in value) return String(value.unsigned);
  if ("boolean" in value) return String(value.boolean);
  return value.stringList.join(", ");
}

function timelineForRecord(
  record: EspRawEvidenceRecord,
  activity: EspTimelineEntry[],
): EspTimelineEntry | undefined {
  const evidenceIds = new Set([
    record.recordId,
    ...record.evidence.map((reference) => reference.evidenceId),
  ]);
  return activity.find((entry) =>
    entry.evidence.some(
      (reference) =>
        evidenceIds.has(reference.evidenceId) &&
        reference.sourceArtifactId === record.provenance.sourceArtifactId,
    ),
  );
}

function severityForRecord(
  record: EspRawEvidenceRecord,
  message: string,
  timeline: EspTimelineEntry | undefined,
): LiveEvidenceSeverity {
  const normalized = timeline?.status?.normalized.toLowerCase() ?? "";
  if (
    record.accessState === "permissionDenied" ||
    record.parseState === "malformed" ||
    /^(failed|error|cancelled)$/.test(normalized) ||
    /\b(error|failed|failure|fatal|denied)\b/i.test(message)
  ) {
    return "error";
  }
  if (
    /^(pending|inprogress|rebootrequired)$/.test(normalized) ||
    /\b(warn(?:ing)?|retry|timeout|timed out|reboot required)\b/i.test(message)
  ) {
    return "warning";
  }
  return "info";
}

function rowForRecord(
  record: EspRawEvidenceRecord,
  activity: EspTimelineEntry[],
): LiveEvidenceRecordRow {
  const timeline = timelineForRecord(record, activity);
  const rawMessage = observationValueText(record.rawValue);
  const normalizedContext = timeline
    ? `${timeline.title} ${timeline.detail ?? ""}`
    : "";
  return {
    kind: "evidence",
    rowId: record.recordId,
    record,
    timestamp:
      record.sourceTimestamp?.rawText ||
      record.sourceTimestamp?.normalizedUtc ||
      record.observedAtUtc,
    source: record.provenance.sourceArtifactId,
    severity: severityForRecord(
      record,
      `${normalizedContext} ${rawMessage}`,
      timeline,
    ),
    component: timeline?.kind ?? record.provenance.sourceKind,
    message: rawMessage,
  };
}

function rowForBoundary(
  marker: EspEvidenceBoundaryMarker,
): LiveEvidenceBoundaryRow {
  const source = [
    ...new Set(marker.sources.map((entry) => entry.sourceArtifactId)),
  ].join(", ");
  return {
    kind: "sourceReset",
    rowId: marker.markerId,
    marker,
    timestamp: marker.emittedAtUtc,
    source: source || "Unknown source",
    severity: "info",
    component: "Source reset",
    message: "Source reset after rotation or truncation",
  };
}

function severityColor(severity: LiveEvidenceSeverity): string {
  switch (severity) {
    case "error":
      return tokens.colorPaletteRedForeground1;
    case "warning":
      return tokens.colorPaletteYellowForeground2;
    case "info":
      return tokens.colorNeutralForeground2;
  }
}

function ProvenanceDetails({ row }: { row: LiveEvidenceRow }) {
  if (row.kind === "sourceReset") {
    return (
      <aside
        aria-label="Reset boundary provenance"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
          gap: "6px 16px",
          padding: "8px 10px",
          borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
          color: tokens.colorNeutralForeground2,
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: 10,
          lineHeight: "15px",
        }}
      >
        <span>Boundary {row.marker.markerId}</span>
        <span>Emitted {row.marker.emittedAtUtc}</span>
        {row.marker.sources.length > 0 ? (
          row.marker.sources.map((source) => (
            <span
              key={`${source.sourceArtifactId}\u0000${source.filePath ?? ""}`}
            >
              {source.sourceArtifactId} · {source.filePath ?? "No file path"}
            </span>
          ))
        ) : (
          <span>Source provenance unavailable</span>
        )}
      </aside>
    );
  }
  const { record } = row;
  const { provenance } = record;
  return (
    <aside
      aria-label="Raw evidence provenance"
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
        gap: "6px 16px",
        padding: "8px 10px",
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground3,
        color: tokens.colorNeutralForeground2,
        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
        fontSize: 10,
        lineHeight: "15px",
      }}
    >
      <span>Record {record.recordId}</span>
      <span>Source {provenance.sourceKind}</span>
      <span>{provenance.filePath ?? "No file path"}</span>
      {provenance.lineNumber !== null ? (
        <span>Line {provenance.lineNumber}</span>
      ) : null}
      {provenance.recordNumber !== null ? (
        <span>Record number {provenance.recordNumber}</span>
      ) : null}
      {provenance.registry ? (
        <span>
          {provenance.registry.hive}\{provenance.registry.key}
          {provenance.registry.valueName
            ? ` · ${provenance.registry.valueName}`
            : ""}
        </span>
      ) : null}
      {provenance.event ? (
        <span>
          {provenance.event.channel} · Event {provenance.event.eventId} · Record{" "}
          {provenance.event.recordId ?? "unknown"}
        </span>
      ) : null}
      <span>Parse {record.parseState}</span>
      <span>Access {record.accessState}</span>
      <span>Sensitivity {record.sensitivity}</span>
    </aside>
  );
}

export function LiveEvidenceTable({
  snapshot,
  boundaryMarkers = [],
}: LiveEvidenceTableProps) {
  const records = snapshot?.rawEvidence ?? [];
  const activity = snapshot?.activity ?? [];
  const rows = useMemo(
    () => [
      ...records.map((record) => rowForRecord(record, activity)),
      ...boundaryMarkers.map(rowForBoundary),
    ],
    [activity, boundaryMarkers, records],
  );
  const sources = useMemo(
    () => [...new Set(rows.map((row) => row.source))].sort(),
    [rows],
  );
  const [sourceFilter, setSourceFilter] = useState("all");
  const [textFilter, setTextFilter] = useState("");
  const [problemsOnly, setProblemsOnly] = useState(false);
  const [following, setFollowing] = useState(true);
  const [manualPause, setManualPause] = useState(false);
  const [selectedRowId, setSelectedRowId] = useState<string | null>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);

  const filteredRows = useMemo(() => {
    const query = textFilter.trim().toLocaleLowerCase("en-US");
    return rows.filter((row) => {
      if (sourceFilter !== "all" && row.source !== sourceFilter) return false;
      if (problemsOnly && row.severity === "info") return false;
      if (!query) return true;
      return [row.timestamp, row.source, row.component, row.message]
        .join(" ")
        .toLocaleLowerCase("en-US")
        .includes(query);
    });
  }, [problemsOnly, rows, sourceFilter, textFilter]);

  const virtualizer = useVirtualizer({
    count: filteredRows.length,
    getScrollElement: () => scrollerRef.current,
    estimateSize: () => 32,
    overscan: 10,
    getItemKey: (index) => filteredRows[index]?.rowId ?? index,
  });

  useEffect(() => {
    if (following && filteredRows.length > 0) {
      virtualizer.scrollToIndex(filteredRows.length - 1, { align: "end" });
    }
  }, [filteredRows.length, following, virtualizer]);

  useEffect(() => {
    if (selectedRowId && !rows.some((row) => row.rowId === selectedRowId)) {
      setSelectedRowId(null);
    }
  }, [rows, selectedRowId]);

  const selectedRow = rows.find((row) => row.rowId === selectedRowId);

  const handleScroll = () => {
    const element = scrollerRef.current;
    if (!element || manualPause) return;
    const nearBottom =
      element.scrollHeight - element.scrollTop - element.clientHeight <= 48;
    setFollowing(nearBottom);
  };

  const resumeFollow = () => {
    setManualPause(false);
    setFollowing(true);
    if (filteredRows.length > 0) {
      virtualizer.scrollToIndex(filteredRows.length - 1, { align: "end" });
    }
  };

  return (
    <div
      style={{
        display: "grid",
        gridTemplateRows: "auto minmax(0, 1fr) auto",
        minHeight: 0,
        height: "100%",
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 7,
          minWidth: 0,
          padding: "5px 8px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        <Input
          size="small"
          aria-label="Search live evidence"
          placeholder="Filter messages"
          value={textFilter}
          onChange={(_event, data) => setTextFilter(data.value)}
          style={{ minWidth: 180, maxWidth: 320 }}
        />
        <label
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 5,
            color: tokens.colorNeutralForeground2,
            fontSize: 11,
          }}
        >
          Source
          <select
            aria-label="Filter live evidence by source"
            value={sourceFilter}
            onChange={(event) => setSourceFilter(event.target.value)}
            style={{
              minWidth: 150,
              height: 24,
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: 3,
              backgroundColor: tokens.colorNeutralBackground1,
              color: tokens.colorNeutralForeground1,
              fontSize: 11,
            }}
          >
            <option value="all">All sources</option>
            {sources.map((source) => (
              <option key={source} value={source}>
                {source}
              </option>
            ))}
          </select>
        </label>
        <Button
          size="small"
          appearance={problemsOnly ? "primary" : "subtle"}
          aria-pressed={problemsOnly}
          onClick={() => setProblemsOnly((value) => !value)}
        >
          Errors and warnings
        </Button>
        <span
          aria-live="polite"
          style={{
            marginLeft: "auto",
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
          }}
        >
          {filteredRows.length.toLocaleString()} /{" "}
          {rows.length.toLocaleString()}
        </span>
        <Button
          size="small"
          appearance={following ? "subtle" : "primary"}
          onClick={
            following
              ? () => {
                  setManualPause(true);
                  setFollowing(false);
                }
              : resumeFollow
          }
        >
          {following ? "Pause follow" : "Resume follow"}
        </Button>
      </div>

      <div
        ref={scrollerRef}
        data-testid="live-evidence-scroller"
        onScroll={handleScroll}
        style={{ minHeight: 0, overflow: "auto", backgroundColor: "#101315" }}
      >
        <div
          role="table"
          aria-label="Live evidence records"
          aria-rowcount={filteredRows.length}
          style={{
            minWidth: 900,
            color: "#e8ecef",
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
          }}
        >
          <div
            role="row"
            style={{
              position: "sticky",
              zIndex: 2,
              top: 0,
              display: "grid",
              gridTemplateColumns:
                "190px minmax(150px, 0.8fr) 78px 120px minmax(360px, 2fr)",
              minHeight: 27,
              alignItems: "center",
              borderBottom: "1px solid #394148",
              backgroundColor: "#1b2024",
              color: "#b9c2c9",
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.04em",
              textTransform: "uppercase",
            }}
          >
            {["Timestamp", "Source", "Severity", "Component", "Message"].map(
              (label) => (
                <span
                  key={label}
                  role="columnheader"
                  style={{ padding: "0 8px" }}
                >
                  {label}
                </span>
              ),
            )}
          </div>
          <div
            role="rowgroup"
            style={{
              position: "relative",
              height: virtualizer.getTotalSize(),
            }}
          >
            {virtualizer.getVirtualItems().map((virtualRow) => {
              const row = filteredRows[virtualRow.index];
              if (!row) return null;
              const selected = selectedRowId === row.rowId;
              return (
                <div
                  key={row.rowId}
                  ref={virtualizer.measureElement}
                  role="row"
                  data-index={virtualRow.index}
                  data-testid={
                    row.kind === "sourceReset"
                      ? "live-evidence-reset-row"
                      : "live-evidence-row"
                  }
                  data-record-id={row.rowId}
                  aria-selected={selected}
                  tabIndex={0}
                  onClick={() => setSelectedRowId(row.rowId)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setSelectedRowId(row.rowId);
                    }
                  }}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    minHeight: virtualRow.size,
                    transform: `translateY(${virtualRow.start}px)`,
                    display: "grid",
                    gridTemplateColumns:
                      "190px minmax(150px, 0.8fr) 78px 120px minmax(360px, 2fr)",
                    alignItems: "center",
                    borderBottom: "1px solid #252b30",
                    borderLeft: selected
                      ? `3px solid ${tokens.colorBrandStroke1}`
                      : row.kind === "sourceReset"
                        ? "3px solid #5b9bd5"
                        : "3px solid transparent",
                    backgroundColor: selected
                      ? "#26323a"
                      : row.kind === "sourceReset"
                        ? "#17242b"
                        : "transparent",
                    cursor: "default",
                  }}
                >
                  <span
                    role="cell"
                    style={{ padding: "0 8px", color: "#9fb1bd" }}
                  >
                    {row.timestamp}
                  </span>
                  <span
                    role="cell"
                    style={{ padding: "0 8px", color: "#8fc8ef" }}
                  >
                    {row.source}
                  </span>
                  <span
                    role="cell"
                    style={{
                      padding: "0 8px",
                      color: severityColor(row.severity),
                      fontWeight: 700,
                      textTransform: "uppercase",
                    }}
                  >
                    {row.severity}
                  </span>
                  <span
                    role="cell"
                    style={{ padding: "0 8px", color: "#c1a7e8" }}
                  >
                    {row.component}
                  </span>
                  <span
                    role="cell"
                    title={row.message}
                    style={{
                      minWidth: 0,
                      overflow: "hidden",
                      padding: "0 8px",
                      textOverflow: "ellipsis",
                      whiteSpace: "pre",
                    }}
                  >
                    {row.message}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {selectedRow ? <ProvenanceDetails row={selectedRow} /> : null}
    </div>
  );
}
