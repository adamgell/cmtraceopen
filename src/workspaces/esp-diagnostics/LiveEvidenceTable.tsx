import { useEffect, useMemo, useRef, useState } from "react";
import { Button, Input, tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import type {
  EspEvidenceBoundaryMarker,
  EspEvidenceBoundarySource,
  EspEvidenceRecordRow,
} from "./esp-diagnostics-store";
import type {
  EspDiagnosticsSnapshot,
  EspObservationValue,
  EspRawEvidenceRecord,
  EspTimelineEntry,
} from "./types";
import { displayEvidenceValue } from "./esp-view-model";

type LiveEvidenceSeverity = "error" | "warning" | "info";

interface LiveEvidenceRowBase {
  rowId: string;
  timestamp: string;
  source: string;
  severity: LiveEvidenceSeverity;
  component: string;
  message: string;
  order: number;
  sourceIds: string[];
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

interface IndexedTimelineEntry {
  activityIndex: number;
  entry: EspTimelineEntry;
}

type TimelineEvidenceIndex = Map<string, Map<string, IndexedTimelineEntry>>;

export interface LiveEvidenceTableProps {
  snapshot: EspDiagnosticsSnapshot | null;
  boundaryMarkers?: EspEvidenceBoundaryMarker[];
  recordRows?: ReadonlyMap<string, EspEvidenceRecordRow>;
}

function observationValueText(value: EspObservationValue): string {
  if ("text" in value) return value.text;
  if ("integer" in value) return String(value.integer);
  if ("unsigned" in value) return String(value.unsigned);
  if ("boolean" in value) return String(value.boolean);
  return value.stringList.join(", ");
}

function indexTimelineEvidence(
  activity: EspTimelineEntry[],
): TimelineEvidenceIndex {
  const index: TimelineEvidenceIndex = new Map();
  activity.forEach((entry, activityIndex) => {
    for (const reference of entry.evidence) {
      let sourceIndex = index.get(reference.sourceArtifactId);
      if (!sourceIndex) {
        sourceIndex = new Map();
        index.set(reference.sourceArtifactId, sourceIndex);
      }
      if (!sourceIndex.has(reference.evidenceId)) {
        sourceIndex.set(reference.evidenceId, { activityIndex, entry });
      }
    }
  });
  return index;
}

function timelineForRecord(
  record: EspRawEvidenceRecord,
  timelineIndex: TimelineEvidenceIndex,
): EspTimelineEntry | undefined {
  const references = [
    {
      sourceArtifactId: record.provenance.sourceArtifactId,
      evidenceId: record.recordId,
    },
    ...record.evidence,
  ];
  let earliest: IndexedTimelineEntry | undefined;
  for (const reference of references) {
    const candidate = timelineIndex
      .get(reference.sourceArtifactId)
      ?.get(reference.evidenceId);
    if (
      candidate &&
      (!earliest || candidate.activityIndex < earliest.activityIndex)
    ) {
      earliest = candidate;
    }
  }
  return earliest?.entry;
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
  timelineIndex: TimelineEvidenceIndex,
  recordRow: EspEvidenceRecordRow | undefined,
  fallbackOrder: number,
): LiveEvidenceRecordRow {
  const timeline = timelineForRecord(record, timelineIndex);
  const rawMessage = observationValueText(record.rawValue);
  const displayMessage = displayEvidenceValue(
    rawMessage,
    record.sensitivity,
    false,
  );
  const normalizedContext = timeline
    ? `${timeline.title} ${timeline.detail ?? ""}`
    : "";
  return {
    kind: "evidence",
    rowId: recordRow?.rowId ?? record.recordId,
    record,
    timestamp:
      record.sourceTimestamp?.normalizedUtc ||
      record.sourceTimestamp?.rawText ||
      record.observedAtUtc,
    source: record.provenance.sourceArtifactId,
    severity: severityForRecord(
      record,
      `${normalizedContext} ${rawMessage}`,
      timeline,
    ),
    component: timeline?.kind ?? record.provenance.sourceKind,
    message: displayMessage,
    order: recordRow?.order ?? fallbackOrder,
    sourceIds: [record.provenance.sourceArtifactId],
  };
}

function rowForBoundary(
  marker: EspEvidenceBoundaryMarker,
): LiveEvidenceBoundaryRow {
  const sourceIds = [
    ...new Set(
      marker.observedDeltas.flatMap((delta) =>
        [delta.previous, delta.incoming]
          .filter((source) => source !== null)
          .map((source) => source.sourceArtifactId),
      ),
    ),
  ].sort();
  return {
    kind: "sourceReset",
    rowId: marker.markerId,
    marker,
    timestamp: marker.emittedAtUtc,
    source: "Exact source unknown",
    severity: "info",
    component: "Source reset",
    message: "Source reset boundary observed; exact source unavailable",
    order: marker.order,
    sourceIds,
  };
}

function boundarySourceText(source: EspEvidenceBoundarySource | null): string {
  if (!source) return "none";
  return `${source.sourceArtifactId} · ${source.filePath ?? "No file path"}`;
}

function boundaryDeltaLabel(kind: "removed" | "added" | "changed"): string {
  switch (kind) {
    case "removed":
      return "Removed";
    case "added":
      return "Added";
    case "changed":
      return "Changed";
  }
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

function ProvenanceDetails({
  row,
  fontSize,
  lineHeight,
}: {
  row: LiveEvidenceRow;
  fontSize: number;
  lineHeight: number;
}) {
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
          fontSize,
          lineHeight: `${lineHeight}px`,
        }}
      >
        <span>Boundary {row.marker.markerId}</span>
        <span>Emitted {row.marker.emittedAtUtc}</span>
        <span>Exact reset source unavailable</span>
        <span>Observed raw-record deltas do not identify the reset source</span>
        {row.marker.observedDeltas.length > 0 ? (
          row.marker.observedDeltas.map((delta) => (
            <span key={`${delta.kind}\u0000${delta.recordId}`}>
              {boundaryDeltaLabel(delta.kind)} {delta.recordId} · Previous:{" "}
              {boundarySourceText(delta.previous)} · Incoming:{" "}
              {boundarySourceText(delta.incoming)}
            </span>
          ))
        ) : (
          <span>No raw-record changes were observed in this reset update</span>
        )}
        {row.marker.omittedDeltaCount > 0 ? (
          <span>
            {row.marker.omittedDeltaCount.toLocaleString()} additional observed
            deltas omitted
          </span>
        ) : null}
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
        fontSize,
        lineHeight: `${lineHeight}px`,
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
  recordRows,
}: LiveEvidenceTableProps) {
  const records = snapshot?.rawEvidence ?? [];
  const activity = snapshot?.activity ?? [];
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize],
  );
  // The dense evidence grid sits one tier below the standard log row so the
  // compact CMTrace layout is preserved, while still tracking the accessibility
  // font-size control. Per-row chrome (borders + vertical padding) is fixed, so
  // only the line height scales with the font.
  const bodyFontSize = Math.max(9, metrics.fontSize - 3);
  const rowLineHeight = Math.max(15, Math.round(bodyFontSize * 1.5));
  const rowHeight = rowLineHeight + 17;
  const headerMinHeight = rowLineHeight + 12;
  const rows = useMemo(() => {
    const timelineIndex = indexTimelineEvidence(activity);
    return [
      ...records.map((record, index) =>
        rowForRecord(
          record,
          timelineIndex,
          recordRows?.get(record.recordId),
          index,
        ),
      ),
      ...boundaryMarkers.map(rowForBoundary),
    ].sort((left, right) =>
      left.order === right.order
        ? left.rowId.localeCompare(right.rowId)
        : left.order - right.order,
    );
  }, [activity, boundaryMarkers, recordRows, records]);
  const sources = useMemo(
    () => [...new Set(rows.flatMap((row) => row.sourceIds))].sort(),
    [rows],
  );
  const [sourceFilter, setSourceFilter] = useState("all");
  const [textFilter, setTextFilter] = useState("");
  const [problemsOnly, setProblemsOnly] = useState(false);
  const [following, setFollowing] = useState(true);
  const [manualPause, setManualPause] = useState(false);
  const [selectedRowId, setSelectedRowId] = useState<string | null>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);
  const activeSourceFilter =
    sourceFilter === "all" || sources.includes(sourceFilter)
      ? sourceFilter
      : "all";

  useEffect(() => {
    if (sourceFilter !== activeSourceFilter) {
      setSourceFilter(activeSourceFilter);
    }
  }, [activeSourceFilter, sourceFilter]);

  const filteredRows = useMemo(() => {
    const query = textFilter.trim().toLocaleLowerCase("en-US");
    return rows.filter((row) => {
      if (
        activeSourceFilter !== "all" &&
        !row.sourceIds.includes(activeSourceFilter)
      ) {
        return false;
      }
      if (problemsOnly && row.severity === "info") return false;
      if (!query) return true;
      return [
        row.timestamp,
        row.source,
        ...row.sourceIds,
        row.component,
        row.message,
      ]
        .join(" ")
        .toLocaleLowerCase("en-US")
        .includes(query);
    });
  }, [activeSourceFilter, problemsOnly, rows, textFilter]);

  const virtualizer = useVirtualizer({
    count: filteredRows.length,
    getScrollElement: () => scrollerRef.current,
    estimateSize: () => rowHeight,
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
            value={activeSourceFilter}
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
          aria-rowcount={filteredRows.length + 1}
          style={{
            minWidth: 900,
            color: "#e8ecef",
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: bodyFontSize,
            lineHeight: `${rowLineHeight}px`,
          }}
        >
          <div
            role="row"
            aria-rowindex={1}
            style={{
              position: "sticky",
              zIndex: 2,
              top: 0,
              display: "grid",
              gridTemplateColumns:
                "190px minmax(150px, 0.8fr) 78px 120px minmax(360px, 2fr)",
              minHeight: headerMinHeight,
              alignItems: "center",
              borderBottom: "1px solid #394148",
              backgroundColor: "#1b2024",
              color: "#b9c2c9",
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: bodyFontSize,
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
                  aria-rowindex={virtualRow.index + 2}
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
                      // Preserve the message's own line breaks, but wrap long
                      // lines and break unbreakable tokens (e.g. base64/JWT
                      // hashes in Win32App workload logs) so they cannot overrun
                      // the column. The virtualizer measures element height, so
                      // rows resize to fit the wrapped content.
                      whiteSpace: "pre-wrap",
                      overflowWrap: "anywhere",
                      wordBreak: "break-word",
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

      {selectedRow ? (
        <ProvenanceDetails
          row={selectedRow}
          fontSize={bodyFontSize}
          lineHeight={rowLineHeight}
        />
      ) : null}
    </div>
  );
}
