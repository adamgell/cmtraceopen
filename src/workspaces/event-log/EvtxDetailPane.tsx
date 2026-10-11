import { useEffect, useMemo, useState } from "react";
import { Button, Tab, TabList, tokens } from "@fluentui/react-components";
import {
  ArrowDown16Regular,
  ArrowRight12Regular,
  ArrowUp16Regular,
  Dismiss12Regular,
} from "@fluentui/react-icons";
import { invoke } from "@tauri-apps/api/core";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
  clampLogDetailsFontSize,
  getLogDetailsLineHeight,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useMarkerStore } from "../../stores/marker-store";
import { useUiStore } from "../../stores/ui-store";
import type { ErrorCodeOutcome } from "../../types/log";
import {
  evtxMarkerKey,
  getEvtxMarker,
  isEvtxMarkerAddressable,
  loadEvtxMarkers,
  toggleEvtxBookmark,
  toggleEvtxTag,
} from "./evtx-marker-adapter";
import { useEvtxStore } from "./evtx-store";
import { EvtxMarkerControls } from "./EvtxTimelineRow";
import {
  evtxRailTabId,
  useEvtxLayoutStore,
} from "./evtx-layout-store";
import { renderedRecords, sortForGrid } from "./evtx-row-order";
import { useRailTextColors } from "./evtx-rail-text";
import {
  buildSameIdSeries,
  findRecordById,
  findingForRecord,
  formatCount,
  neighborRecordId,
} from "./evtx-insights-data";
import { formatEventTime } from "./evtx-time";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import { EVTX_TIME_WINDOW_LABELS, type DiagnosisFinding, type EvtxRecord } from "./types";

/** How many EventData fields the Details tab shows before "Show all". */
const EVENT_DATA_PREVIEW_COUNT = 6;

type DetailSubTab = "details" | "xml";
const detailSubTabId = (tab: DetailSubTab) => `evtx-detail-tab-${tab}`;
const detailSubPanelId = (tab: DetailSubTab) => `evtx-detail-panel-${tab}`;

/** 24 bars, 22 px tall. Decorative: the counts beside it carry the numbers. */
function Sparkline({ bins, color }: { bins: number[]; color: string }) {
  const max = Math.max(...bins, 1);
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox={`0 0 ${bins.length} 22`}
      preserveAspectRatio="none"
      style={{ width: "100%", height: "22px", display: "block" }}
    >
      {bins.map((count, index) =>
        count > 0 ? (
          <rect
            key={index}
            x={index + 0.1}
            width={0.8}
            y={22 - Math.max(1.5, (count / max) * 22)}
            height={Math.max(1.5, (count / max) * 22)}
            fill={color}
          />
        ) : null,
      )}
    </svg>
  );
}

interface EvtxDetailPaneProps {
  /** The visible records, for Previous and Next and the Same ID card. */
  visibleRecords?: readonly EvtxRecord[];
  /** Actionable findings in display order, for the finding callout. */
  findings?: readonly DiagnosisFinding[];
}

const NO_RECORDS: readonly EvtxRecord[] = [];
const NO_FINDINGS: readonly DiagnosisFinding[] = [];

/** One error code found in an event's text, as the parser crate reports it. */
interface ErrorCodeMention {
  start: number;
  end: number;
  codeHex: string;
  codeDecimal: string;
  /** Empty when `known` is false. */
  description: string;
  /** Empty when `known` is false. */
  category: string;
  outcome: ErrorCodeOutcome | null;
  known: boolean;
}

export function EvtxDetailPane({
  visibleRecords = NO_RECORDS,
  findings = NO_FINDINGS,
}: EvtxDetailPaneProps) {
  const markersByFile = useMarkerStore((s) => s.markersByFile);
  const records = useEvtxStore((s) => s.records);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const [subTab, setSubTab] = useState<DetailSubTab>("details");
  const [showAllEventData, setShowAllEventData] = useState(false);
  const setSelectedRecordId = useEvtxStore((s) => s.setSelectedRecordId);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const sortField = useEvtxStore((s) => s.sortField);
  const sortDirection = useEvtxStore((s) => s.sortDirection);
  const groupBy = useEvtxStore((s) => s.groupBy);
  const collapsedGroups = useEvtxStore((s) => s.collapsedGroups);
  const railText = useRailTextColors();
  const setRailTab = useEvtxLayoutStore((s) => s.setRailTab);
  const visuals = useEvtxVisualTokens();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  // The summary header follows the log list size; the sections below keep the details size.
  const listFontSize = getLogListMetrics(logListFontSize).fontSize;
  const [resolvedCodes, setResolvedCodes] = useState<{
    text: string;
    mentions: ErrorCodeMention[];
  } | null>(null);

  const logDetailsFontSize = useUiStore((s) => s.logDetailsFontSize);
  const fontSize = clampLogDetailsFontSize(logDetailsFontSize);
  const detailLineHeight = getLogDetailsLineHeight(logDetailsFontSize);
  const monoFontSize = Math.max(10, fontSize - 1);
  const labelFontSize = Math.max(10, fontSize - 2);

  const record = useMemo(
    () => findRecordById(records, selectedRecordId),
    [records, selectedRecordId],
  );
  // The grid's rendered row order (sorted, grouped, collapsed groups skipped), so Previous and Next
  // walk the rows the way they read. Memoized: `visibleRecords` is the rail's debounced set.
  const ordered = useMemo(
    () =>
      visibleRecords.length > 0
        ? renderedRecords(
            sortForGrid(visibleRecords, sortField, sortDirection),
            groupBy,
            collapsedGroups,
            timeZoneMode,
          )
        : NO_RECORDS,
    [visibleRecords, sortField, sortDirection, groupBy, collapsedGroups, timeZoneMode],
  );
  const { previousId, nextId } = useMemo(
    () => ({
      previousId: neighborRecordId(ordered, selectedRecordId, -1),
      nextId: neighborRecordId(ordered, selectedRecordId, 1),
    }),
    [ordered, selectedRecordId],
  );
  const sameId = useMemo(
    () => (record && visibleRecords.length > 0 ? buildSameIdSeries(visibleRecords, record) : null),
    [record, visibleRecords],
  );
  const finding = useMemo(
    () => (record ? findingForRecord(findings, record, records) : null),
    [record, findings, records],
  );
  /**
   * The text an operator is reading here: the message and the event data, which
   * is where MDM, AppX and Windows Update codes tend to sit. `rawXml` repeats
   * both, so it is left out rather than scanned twice.
   */
  const codeSourceText = useMemo(() => {
    if (!record) return "";
    return [record.message, ...record.eventData.map((field) => field.value)]
      .filter((value) => value.length > 0)
      .join("\n");
  }, [record]);
  const errorCodes = resolvedCodes?.text === codeSourceText ? resolvedCodes.mentions : [];

  // Detection lives in the parser crate, so this asks rather than decides what a
  // code looks like. A code the database does not hold comes back marked unknown.
  useEffect(() => {
    if (codeSourceText.length === 0) {
      setResolvedCodes(null);
      return;
    }
    let cancelled = false;
    invoke<ErrorCodeMention[]>("resolve_error_codes_in_text", {
      text: codeSourceText,
    })
      .then((mentions) => {
        if (cancelled) return;
        // One line per distinct code: an event that repeats a code in its event
        // data should not repeat it in the list.
        const seen = new Set<string>();
        setResolvedCodes({
          text: codeSourceText,
          mentions: (Array.isArray(mentions) ? mentions : []).filter((mention) => {
            if (seen.has(mention.codeHex)) return false;
            seen.add(mention.codeHex);
            return true;
          }),
        });
      })
      .catch(() => {
        if (!cancelled) setResolvedCodes(null);
      });
    return () => {
      cancelled = true;
    };
  }, [codeSourceText]);

  const marker = useMemo(
    () => (record ? getEvtxMarker(record, markersByFile) : null),
    [record, markersByFile]
  );

  useEffect(() => {
    if (record) loadEvtxMarkers([record.sourceLabel]);
  }, [record?.sourceLabel]);

  // A different record starts on Details with its EventData collapsed.
  const recordId = record?.id;
  useEffect(() => {
    setSubTab("details");
    setShowAllEventData(false);
  }, [recordId]);

  if (!record) {
    return (
      <div
        role="region"
        aria-label="Event log details"
        style={{
          padding: "16px",
          color: railText.secondary,
          fontSize: `${fontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
          textAlign: "center",
        }}
      >
        Select a record to view details.
      </div>
    );
  }

  const markerAddressable = isEvtxMarkerAddressable(record);
  const level = visuals.levels[record.level];
  const LevelIcon = level.RailIcon;
  const eventDataShown = showAllEventData
    ? record.eventData
    : record.eventData.slice(0, EVENT_DATA_PREVIEW_COUNT);
  const processText = [
    record.processId != null ? `PID ${record.processId}` : null,
    record.threadId != null ? `TID ${record.threadId}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
  const definitions: Array<{
    term: string;
    value: string;
    mono?: boolean;
    numeric?: boolean;
    title?: string;
  }> = [
    { term: "Channel", value: record.channel },
    { term: "Provider", value: record.provider },
    {
      term: "Record ID",
      value: String(record.eventRecordIdText ?? record.eventRecordId),
      numeric: true,
    },
    ...(processText ? [{ term: "Process", value: processText, numeric: true }] : []),
    ...(record.userSid
      ? [
          {
            term: "User SID",
            value: record.userSid,
            mono: true,
            title: "Raw security identifier; not resolved to an account name",
          },
        ]
      : []),
  ];

  const sectionHeading = {
    fontSize: `${labelFontSize}px`,
    fontWeight: 600,
    color: railText.secondary,
    textTransform: "uppercase" as const,
    marginBottom: "4px",
  };

  return (
    <div
      role="region"
      aria-label="Event log details"
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        fontFamily: LOG_UI_FONT_FAMILY,
        fontSize: `${fontSize}px`,
        lineHeight: `${detailLineHeight}px`,
      }}
    >
      {/* Summary header: level, id, level word, previous, next and close on the first row; the
          marker actions take the row below, so the close button cannot be pushed off the rail. */}
      <div
        data-evtx-marker-key={evtxMarkerKey(record)}
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          gap: "4px 8px",
          padding: "10px 12px 4px",
          flexShrink: 0,
        }}
      >
        <LevelIcon aria-hidden="true" style={{ color: level.railIconColor, flexShrink: 0 }} />
        <span
          style={{
            fontSize: `${listFontSize + 1}px`,
            fontWeight: 600,
            whiteSpace: "nowrap",
            color: railText.primary,
          }}
        >
          Event {record.eventId}
        </span>
        <span
          style={{
            fontSize: `${Math.max(10, listFontSize - 2)}px`,
            fontWeight: 600,
            color: level.textColor,
          }}
        >
          {record.level}
        </span>
        <span style={{ flex: 1 }} />
        <Button
          size="small"
          appearance="subtle"
          icon={<ArrowUp16Regular />}
          aria-label="Previous event"
          disabledFocusable={previousId === null}
          onClick={() => previousId !== null && setSelectedRecordId(previousId)}
          style={{ minWidth: "24px", width: "24px", height: "24px", padding: 0 }}
        />
        <Button
          size="small"
          appearance="subtle"
          icon={<ArrowDown16Regular />}
          aria-label="Next event"
          disabledFocusable={nextId === null}
          onClick={() => nextId !== null && setSelectedRecordId(nextId)}
          style={{ minWidth: "24px", width: "24px", height: "24px", padding: 0 }}
        />
        <Button
          size="small"
          appearance="subtle"
          icon={<Dismiss12Regular />}
          aria-label="Close details"
          onClick={() => {
            setSelectedRecordId(null);
            setRailTab("insights");
            // This button is about to unmount; hand focus to the Insights tab, which is always
            // rendered, so a keyboard user keeps their place (spec section 10).
            document.getElementById(evtxRailTabId("insights"))?.focus();
          }}
          style={{ minWidth: "24px", width: "24px", height: "24px", padding: 0 }}
        />
        <div style={{ flexBasis: "100%" }}>
          <EvtxMarkerControls
            record={record}
            marker={marker}
            markerAddressable={markerAddressable}
            fontSize={fontSize}
            variant="detail"
            onTag={toggleEvtxTag}
            onBookmark={toggleEvtxBookmark}
          />
        </div>
      </div>

      <TabList
        size="small"
        aria-label="Event detail view"
        selectedValue={subTab}
        onTabSelect={(_, data) => setSubTab(data.value as DetailSubTab)}
        style={{
          paddingLeft: "6px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          flexShrink: 0,
        }}
      >
        {(["details", "xml"] as const).map((tab) => (
          <Tab
            key={tab}
            id={detailSubTabId(tab)}
            value={tab}
            aria-controls={detailSubPanelId(tab)}
            style={subTab === tab ? { color: railText.primary } : undefined}
          >
            {tab === "details" ? "Details" : "XML"}
          </Tab>
        ))}
      </TabList>

      <div
        role="tabpanel"
        id={detailSubPanelId(subTab)}
        aria-labelledby={detailSubTabId(subTab)}
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "auto",
          padding: "12px",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
        }}
      >
        {subTab === "xml" ? (
          <pre
            aria-label="Raw event XML"
            style={{
              margin: 0,
              fontSize: `${Math.max(10, monoFontSize - 1)}px`,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              backgroundColor: tokens.colorNeutralBackground3,
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              padding: "8px",
              borderRadius: "4px",
              color: railText.primary,
            }}
          >
            {record.rawXml}
          </pre>
        ) : (
          <>
            {record.message && (
              <div
                style={{
                  fontSize: `${listFontSize}px`,
                  fontWeight: 600,
                  lineHeight: 1.4,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  color: railText.primary,
                  flexShrink: 0,
                }}
              >
                {record.message}
              </div>
            )}

            <div
              style={{
                fontSize: `${Math.max(10, listFontSize - 2)}px`,
                color: railText.secondary,
              }}
            >
              <span style={{ fontFamily: tokens.fontFamilyNumeric }}>
                {formatEventTime(record.timestampEpoch, timeZoneMode, record.timestamp)}
              </span>
              {` · ${record.computer}`}
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "84px 1fr",
                gap: "4px 10px",
                fontSize: `${Math.max(10, listFontSize - 2)}px`,
                lineHeight: 1.4,
                flexShrink: 0,
              }}
            >
              {definitions.map((definition) => (
                <div key={definition.term} style={{ display: "contents" }}>
                  <span style={{ color: tokens.colorNeutralForeground2 }}>{definition.term}</span>
                  <span
                    title={definition.title}
                    style={{
                      color: railText.primary,
                      wordBreak: "break-all",
                      fontFamily: definition.mono
                        ? LOG_MONOSPACE_FONT_FAMILY
                        : definition.numeric
                          ? tokens.fontFamilyNumeric
                          : undefined,
                    }}
                  >
                    {definition.value}
                  </span>
                </div>
              ))}
            </div>

            {errorCodes.length > 0 && (
              <div
                style={{
                  border: `1px solid ${tokens.colorNeutralStroke1}`,
                  borderRadius: "4px",
                  padding: "8px",
                  flexShrink: 0,
                }}
              >
                <div style={sectionHeading}>Error codes in this event</div>
                <ul
                  style={{
                    margin: 0,
                    paddingLeft: "18px",
                    fontSize: `${monoFontSize}px`,
                    lineHeight: `${detailLineHeight}px`,
                  }}
                >
                  {errorCodes.map((mention) => (
                    <li key={mention.codeHex}>
                      <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
                        {mention.codeHex}
                      </span>
                      {": "}
                      {mention.known ? (
                        <span>
                          {mention.description}
                          {mention.category ? ` (${mention.category})` : ""}
                        </span>
                      ) : (
                        // Not silence: the code is real, the database just cannot
                        // explain it, and the operator needs to see that difference.
                        <span style={{ color: railText.secondary }}>
                          Not in the error database
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {(record.activityId ||
              record.relatedActivityId ||
              record.sessionId ||
              record.deviceId ||
              record.userId ||
              record.processStartTime) && (
              <div
                style={{
                  border: `1px solid ${tokens.colorNeutralStroke2}`,
                  padding: "8px",
                  borderRadius: "4px",
                  backgroundColor: tokens.colorNeutralBackground1,
                  flexShrink: 0,
                }}
              >
                <div style={sectionHeading}>Correlation identity</div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "max-content 1fr",
                    gap: "2px 12px",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                    fontSize: `${monoFontSize}px`,
                  }}
                >
                  {[
                    ["Activity ID", record.activityId],
                    ["Related activity ID", record.relatedActivityId],
                    ["Session ID", record.sessionId],
                    ["Device ID", record.deviceId],
                    ["User ID", record.userId],
                    ["Process start", record.processStartTime],
                  ]
                    .filter(([, value]) => value)
                    .map(([label, value]) => (
                      <div key={label} style={{ display: "contents" }}>
                        <span style={{ color: railText.secondary }}>{label}</span>
                        <span
                          style={{ color: railText.primary, wordBreak: "break-all" }}
                        >
                          {value}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* EventData: a preview of the first fields, "Show all" reveals the rest. */}
            {record.eventData.length > 0 && (
              <div style={{ flexShrink: 0 }}>
                <div style={sectionHeading}>Event Data</div>
                <table
                  style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    fontSize: `${monoFontSize}px`,
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  <tbody>
                    {eventDataShown.map((field, i) => (
                      <tr
                        key={`${field.name}-${i}`}
                        style={{ borderBottom: `1px solid ${tokens.colorNeutralStroke2}` }}
                      >
                        <td
                          style={{
                            padding: "4px 8px 4px 0",
                            fontWeight: 600,
                            color: railText.secondary,
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
                            color: railText.primary,
                            wordBreak: "break-all",
                          }}
                        >
                          {field.value}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {record.eventData.length > EVENT_DATA_PREVIEW_COUNT && (
                  <Button
                    size="small"
                    appearance="subtle"
                    aria-expanded={showAllEventData}
                    onClick={() => setShowAllEventData((value) => !value)}
                    style={{ fontSize: `${labelFontSize}px` }}
                  >
                    {showAllEventData ? "Show fewer" : `Show all ${record.eventData.length}`}
                  </Button>
                )}
              </div>
            )}

            {sameId && (
              <div
                aria-label="Same ID"
                role="group"
                style={{
                  display: "grid",
                  gap: "6px",
                  padding: "8px 10px",
                  borderRadius: "6px",
                  backgroundColor: tokens.colorNeutralBackground1,
                  border: `1px solid ${tokens.colorNeutralStroke2}`,
                  flexShrink: 0,
                }}
              >
                <div style={sectionHeading}>
                  {/* The series counts the visible events (every filter), so the heading says so. */}
                  Same ID in visible events
                  {timeWindow === "all"
                    ? ""
                    : `, ${EVTX_TIME_WINDOW_LABELS[timeWindow].toLowerCase()}`}
                </div>
                {sameId.bins.length > 0 && (
                  <Sparkline bins={sameId.bins} color={visuals.singleSeries} />
                )}
                <div
                  style={{
                    fontSize: `${Math.max(10, listFontSize - 2)}px`,
                    color: tokens.colorNeutralForeground2,
                  }}
                >
                  <span style={{ fontFamily: tokens.fontFamilyNumeric }}>
                    {formatCount(sameId.occurrences)}
                  </span>{" "}
                  {sameId.occurrences === 1 ? "occurrence" : "occurrences"}
                  {sameId.firstEpoch !== null && (
                    <>
                      {" \u00b7 first "}
                      <span style={{ fontFamily: tokens.fontFamilyNumeric }}>
                        {formatEventTime(sameId.firstEpoch, timeZoneMode)}
                      </span>
                    </>
                  )}
                </div>
              </div>
            )}

            {finding && (
              <button
                type="button"
                onClick={() => {
                  setRailTab("insights");
                  // The Insights panel stays mounted, so its card exists; focus it once the tab is
                  // visible.
                  requestAnimationFrame(() => {
                    const card = Array.from(
                      document.querySelectorAll<HTMLElement>("[data-finding-id]"),
                    ).find((element) => element.dataset.findingId === finding.findingId);
                    card?.scrollIntoView?.({ block: "nearest" });
                    card?.focus();
                  });
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "8px",
                  padding: "8px 10px",
                  borderRadius: "6px",
                  textAlign: "left",
                  cursor: "pointer",
                  font: "inherit",
                  fontSize: `${Math.max(10, listFontSize - 2)}px`,
                  fontWeight: 600,
                  flexShrink: 0,
                  backgroundColor: visuals.findingCallout.background,
                  border: `1px solid ${visuals.findingCallout.border}`,
                  color: visuals.findingCallout.foreground,
                }}
              >
                <span>Part of finding: {finding.title}</span>
                <ArrowRight12Regular aria-hidden="true" />
              </button>
            )}

            {/* Metadata the definition grid does not carry. System-block fields render only when
                the provider wrote them, so an absent value reads as absent rather than as a zero
                the provider never claimed. */}
            <div
              style={{
                display: "flex",
                gap: "16px",
                flexWrap: "wrap",
                fontSize: `${monoFontSize}px`,
                color: railText.secondary,
                flexShrink: 0,
              }}
            >
              <span>
                <strong>Source:</strong> {record.sourceLabel}
              </span>
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
              {record.keywords && (
                <span>
                  <strong>Keywords:</strong> {record.keywords}
                </span>
              )}
            </div>

            {/* Map-derived columns. Only present where a map covers this event type, so the
                section is hidden entirely rather than showing an empty heading. */}
            {record.mapped && record.mapped.length > 0 && (
              <div style={{ flexShrink: 0 }}>
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
                    <span style={{ minWidth: "110px", color: railText.secondary }}>
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
                          ? railText.primary
                          : visuals.levels.Warning.textColor,
                      }}
                    >
                      {column.text}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
