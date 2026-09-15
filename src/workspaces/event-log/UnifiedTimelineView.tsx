import { useEffect, useMemo, useRef, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";

import type {
  EventLogAnalysisSessionStatus,
  EventLogAnalysisTimelinePage,
} from "../../lib/commands";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { formatEventTime } from "./evtx-time";
import { useEvtxStore } from "./evtx-store";
import {
  isEventOrigin,
  originContext,
  originDetail,
  originLabel,
  type TimelineCorrelationEdge,
  type TimelineItem,
  type TimelineSeverity,
  type UnifiedTimeline,
} from "./unified-timeline";

const UNPLACED_PREVIEW_LIMIT = 100;
export const EVENT_LOG_TIMELINE_PAGE_SIZE = 1_000;
export const EVENT_LOG_TIMELINE_CACHE_RADIUS = 1;
export const EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT = 24 * 1024 * 1024;
export const EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT = 2;

export interface TimelinePageCacheSegment {
  items: TimelineItem[];
  serializedBytes: number;
}

export type TimelinePageCache = Map<number, TimelinePageCacheSegment>;

export interface TimelineRetentionWindow {
  start: number;
  endExclusive: number;
}

export function timelineRetentionWindowForRange(
  firstIndex: number,
  lastIndex: number,
  totalItems: number,
  radius: number,
): TimelineRetentionWindow {
  if (totalItems <= 0) return { start: 0, endExclusive: 0 };
  const pageSize = EVENT_LOG_TIMELINE_PAGE_SIZE;
  const firstOffset = Math.floor(Math.max(firstIndex, 0) / pageSize) * pageSize;
  const lastOffset =
    Math.floor(Math.max(lastIndex, firstIndex, 0) / pageSize) * pageSize;
  return {
    start: Math.max(firstOffset - radius * pageSize, 0),
    endExclusive: Math.min(
      lastOffset + (radius + 1) * pageSize,
      totalItems,
    ),
  };
}

export function retainTimelinePageCache(
  cache: TimelinePageCache,
  window: TimelineRetentionWindow,
  visibleRange: { first: number; last: number },
): TimelinePageCache {
  const candidates: Array<{
    offset: number;
    segment: TimelinePageCacheSegment;
    visible: boolean;
    distance: number;
  }> = [];
  for (const [offset, segment] of cache) {
    const start = offset;
    const end = offset + segment.items.length;
    if (start >= window.endExclusive || end <= window.start) continue;
    const visible =
      start <= visibleRange.last && end > visibleRange.first;
    const distance = visible
      ? 0
      : end <= visibleRange.first
        ? visibleRange.first - end
        : start - visibleRange.last;
    candidates.push({
      offset,
      segment,
      visible,
      distance,
    });
  }
  candidates.sort(
    (left, right) =>
      Number(right.visible) - Number(left.visible) ||
      left.distance - right.distance ||
      left.offset - right.offset,
  );

  const retained: TimelinePageCache = new Map();
  let retainedBytes = 0;
  for (const candidate of candidates) {
    if (
      !candidate.visible &&
      retainedBytes + candidate.segment.serializedBytes >
        EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT
    ) {
      continue;
    }
    retained.set(candidate.offset, candidate.segment);
    retainedBytes += candidate.segment.serializedBytes;
  }
  return retained;
}

export function timelinePageCacheRowCount(cache: TimelinePageCache): number {
  let count = 0;
  for (const segment of cache.values()) count += segment.items.length;
  return count;
}

export function timelinePageCacheByteCount(cache: TimelinePageCache): number {
  let count = 0;
  for (const segment of cache.values()) count += segment.serializedBytes;
  return count;
}

export function timelinePageCacheSegment(
  items: TimelineItem[],
  serializedBytes: number,
): TimelinePageCacheSegment {
  return { items, serializedBytes };
}

export function timelinePageCacheItem(
  cache: TimelinePageCache,
  index: number,
): TimelineItem | undefined {
  for (const [offset, segment] of cache) {
    if (index >= offset && index < offset + segment.items.length) {
      return segment.items[index - offset];
    }
  }
  return undefined;
}

function firstMissingTimelineIndex(
  cache: TimelinePageCache,
  firstIndex: number,
  lastIndex: number,
): number | null {
  for (let index = firstIndex; index <= lastIndex; index += 1) {
    if (timelinePageCacheItem(cache, index) === undefined) return index;
  }
  return null;
}

const SEVERITY_COLORS: Record<TimelineSeverity, string> = {
  critical: tokens.colorPaletteRedForeground1,
  error: tokens.colorPaletteRedForeground1,
  warning: tokens.colorPaletteMarigoldForeground1,
  info: tokens.colorBrandForeground1,
  verbose: tokens.colorNeutralForeground4,
};

function correlationEdgeLabel(edge: TimelineCorrelationEdge): string {
  return `${edge.strength} · ${edge.confidence} · ${edge.key.kind}: ${edge.key.value}`;
}

export interface UnifiedTimelineViewProps {
  status?: EventLogAnalysisSessionStatus | null;
  initialPage?: EventLogAnalysisTimelinePage | null;
  loadPage?: (
    offset: number,
    limit: number,
  ) => Promise<EventLogAnalysisTimelinePage>;
  pending?: boolean;
}

/**
 * The merged view of events and text logs.
 *
 * Rows carry a source badge because the whole value of the view is knowing, at a glance, which
 * side of the merge a line came from. Without it the two blur together and the reader loses the
 * distinction that makes the correlation meaningful.
 */
export function UnifiedTimelineView({
  status = null,
  initialPage = null,
  loadPage,
  pending = false,
}: UnifiedTimelineViewProps) {
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  const [loadedPages, setLoadedPages] = useState<TimelinePageCache>(
    () => new Map(),
  );
  const loadedPagesRef = useRef<TimelinePageCache>(loadedPages);
  const visibleRangeRef = useRef({ first: 0, last: 0 });
  const retentionWindowRef = useRef<TimelineRetentionWindow>({
    start: 0,
    endExclusive: 0,
  });
  const continuationOffsetRef = useRef<number | null>(null);
  const pendingPageRequestRef = useRef<{
    offset: number;
    token: symbol;
    generation: number;
  } | null>(null);
  const pageSessionGenerationRef = useRef(0);
  const retryAttemptsRef = useRef(new Map<string, number>());
  const automaticRetryRef = useRef<{
    offset: number;
    generation: number;
    timer: number;
  } | null>(null);
  const [failedPage, setFailedPage] = useState<{
    offset: number;
    message: string;
  } | null>(null);
  const [requestRevision, setRequestRevision] = useState(0);
  const sessionId = status?.sessionId ?? null;
  const sessionRevision = status?.revision ?? null;

  useEffect(() => {
    pageSessionGenerationRef.current += 1;
    continuationOffsetRef.current = null;
    retryAttemptsRef.current.clear();
    if (automaticRetryRef.current !== null) {
      window.clearTimeout(automaticRetryRef.current.timer);
      automaticRetryRef.current = null;
    }
    const next: TimelinePageCache = new Map();
    if (
      sessionId !== null &&
      sessionRevision !== null &&
      initialPage !== null &&
      initialPage.sessionId === sessionId &&
      initialPage.revision === sessionRevision
    ) {
      next.set(
        initialPage.offset,
        timelinePageCacheSegment(
          initialPage.items,
          initialPage.serializedBytes,
        ),
      );
      continuationOffsetRef.current = initialPage.nextOffset;
    }
    loadedPagesRef.current = next;
    setLoadedPages(next);
    setFailedPage(null);
  }, [initialPage, sessionId, sessionRevision]);

  useEffect(
    () => () => {
      if (automaticRetryRef.current !== null) {
        window.clearTimeout(automaticRetryRef.current.timer);
        automaticRetryRef.current = null;
      }
    },
    [],
  );

  const totalItems = status?.totalItems ?? 0;

  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: totalItems,
    getScrollElement: () => parentRef.current,
    estimateSize: () => metrics.rowHeight + 2,
    overscan: 12,
  });

  const virtualRows = virtualizer.getVirtualItems();
  const firstVirtualIndex = virtualRows[0]?.index ?? 0;
  const lastVirtualIndex =
    virtualRows[virtualRows.length - 1]?.index ?? firstVirtualIndex;

  const retentionWindow = useMemo(
    () =>
      timelineRetentionWindowForRange(
        firstVirtualIndex,
        lastVirtualIndex,
        totalItems,
        EVENT_LOG_TIMELINE_CACHE_RADIUS,
      ),
    [firstVirtualIndex, lastVirtualIndex, totalItems],
  );

  useEffect(() => {
    visibleRangeRef.current = {
      first: firstVirtualIndex,
      last: lastVirtualIndex,
    };
    retentionWindowRef.current = retentionWindow;
    const continuationOffset = continuationOffsetRef.current;
    if (
      continuationOffset !== null &&
      (continuationOffset < firstVirtualIndex ||
        continuationOffset > lastVirtualIndex)
    ) {
      continuationOffsetRef.current = null;
    }
    const automaticRetry = automaticRetryRef.current;
    if (
      automaticRetry !== null &&
      (automaticRetry.offset < firstVirtualIndex ||
        automaticRetry.offset > lastVirtualIndex)
    ) {
      window.clearTimeout(automaticRetry.timer);
      automaticRetryRef.current = null;
    }
    const retained = retainTimelinePageCache(
      loadedPagesRef.current,
      retentionWindow,
      { first: firstVirtualIndex, last: lastVirtualIndex },
    );
    if (retained !== loadedPagesRef.current) {
      loadedPagesRef.current = retained;
      setLoadedPages(retained);
    }
    setFailedPage((existing) =>
      existing !== null &&
      (existing.offset < firstVirtualIndex || existing.offset > lastVirtualIndex)
        ? null
        : existing,
    );
  }, [
    firstVirtualIndex,
    lastVirtualIndex,
    retentionWindow,
  ]);

  useEffect(() => {
    if (
      status === null ||
      loadPage === undefined ||
      totalItems === 0
    ) {
      return;
    }
    if (
      pendingPageRequestRef.current !== null ||
      automaticRetryRef.current !== null
    ) {
      return;
    }
    const continuationOffset = continuationOffsetRef.current;
    const offset =
      continuationOffset !== null &&
      continuationOffset >= firstVirtualIndex &&
      continuationOffset <= lastVirtualIndex &&
      timelinePageCacheItem(loadedPagesRef.current, continuationOffset) ===
        undefined
        ? continuationOffset
        : firstMissingTimelineIndex(
            loadedPagesRef.current,
            firstVirtualIndex,
            lastVirtualIndex,
          );
    if (offset === null || failedPage?.offset === offset) return;
    continuationOffsetRef.current = null;

    const token = Symbol("timeline-page-request");
    const generation = pageSessionGenerationRef.current;
    pendingPageRequestRef.current = { offset, token, generation };
    void loadPage(offset, EVENT_LOG_TIMELINE_PAGE_SIZE)
      .then((page) => {
        if (
          pendingPageRequestRef.current?.token !== token ||
          pageSessionGenerationRef.current !== generation
        ) {
          return;
        }
        if (
          page.sessionId !== status.sessionId ||
          page.revision !== status.revision
        ) {
          throw new Error("The event-log analysis session changed while paging.");
        }
        if (page.offset !== offset) {
          throw new Error("The event-log analysis returned the wrong timeline page.");
        }
        const currentWindow = retentionWindowRef.current;
        if (
          page.offset + page.items.length <= currentWindow.start ||
          page.offset >= currentWindow.endExclusive
        ) {
          return;
        }
        const next = new Map(loadedPagesRef.current);
        next.set(
          page.offset,
          timelinePageCacheSegment(page.items, page.serializedBytes),
        );
        const retained = retainTimelinePageCache(
          next,
          currentWindow,
          visibleRangeRef.current,
        );
        loadedPagesRef.current = retained;
        setLoadedPages(retained);
        setFailedPage(null);
        retryAttemptsRef.current.delete(`${generation}:${offset}`);
        const visibleRange = visibleRangeRef.current;
        if (
          page.nextOffset !== null &&
          page.nextOffset >= visibleRange.first &&
          page.nextOffset <= visibleRange.last &&
          timelinePageCacheItem(retained, page.nextOffset) === undefined
        ) {
          continuationOffsetRef.current = page.nextOffset;
        }
      })
      .catch((error: unknown) => {
        if (
          pendingPageRequestRef.current?.token === token &&
          pageSessionGenerationRef.current === generation &&
          offset >= visibleRangeRef.current.first &&
          offset <= visibleRangeRef.current.last
        ) {
          const retryKey = `${generation}:${offset}`;
          const attempt = (retryAttemptsRef.current.get(retryKey) ?? 0) + 1;
          retryAttemptsRef.current.set(retryKey, attempt);
          if (attempt <= EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT) {
            const timer = window.setTimeout(
              () => {
                const retry = automaticRetryRef.current;
                if (
                  retry?.generation !== generation ||
                  retry.offset !== offset
                ) {
                  return;
                }
                automaticRetryRef.current = null;
                if (
                  pageSessionGenerationRef.current === generation &&
                  offset >= visibleRangeRef.current.first &&
                  offset <= visibleRangeRef.current.last
                ) {
                  setRequestRevision((revision) => revision + 1);
                }
              },
              100 * 2 ** (attempt - 1),
            );
            automaticRetryRef.current = { offset, generation, timer };
          } else {
            setFailedPage({
              offset,
              message: error instanceof Error ? error.message : String(error),
            });
          }
        }
      })
      .finally(() => {
        if (pendingPageRequestRef.current?.token === token) {
          pendingPageRequestRef.current = null;
          setRequestRevision((revision) => revision + 1);
        }
      });
  }, [
    failedPage,
    loadPage,
    loadedPages,
    requestRevision,
    status,
    totalItems,
    firstVirtualIndex,
    lastVirtualIndex,
  ]);

  const previewTimeline = useMemo<UnifiedTimeline>(
    () =>
      ({
        items: initialPage?.items ?? [],
        unplaced: initialPage?.unplacedPreview ?? [],
        edges: initialPage?.edgesPreview ?? [],
        coverageGaps: initialPage?.coverageGapsPreview ?? [],
      }),
    [initialPage],
  );

  const counts = {
    logs: status?.logItems ?? 0,
    events: status?.eventItems ?? 0,
    unplaced: status?.totalUnplaced ?? 0,
  };
  const correlationEdges = previewTimeline.edges;
  const coverageGaps = previewTimeline.coverageGaps;
  const correlationCounts = useMemo(() => {
    const result = { exact: 0, candidate: 0, ambiguous: 0 };
    for (const edge of correlationEdges) result[edge.strength] += 1;
    return result;
  }, [correlationEdges]);
  const totalCorrelationEdges = status?.totalEdges ?? 0;
  const coverageGapCount = status?.totalCoverageGaps ?? 0;
  const unplacedCount = status?.totalUnplaced ?? 0;
  const dropped =
    unplacedCount === 0
      ? null
      : `${unplacedCount.toLocaleString()} timeline ${unplacedCount === 1 ? "item" : "items"} could not be placed: no timestamp`;
  const unplacedPreview = previewTimeline.unplaced.slice(
    0,
    UNPLACED_PREVIEW_LIMIT,
  );
  const unplacedOmittedCount = unplacedCount - unplacedPreview.length;
  const correlationPreview = correlationEdges.slice(0, UNPLACED_PREVIEW_LIMIT);
  const correlationOmittedCount =
    totalCorrelationEdges - correlationPreview.length;
  const coverageGapPreview = coverageGaps.slice(0, UNPLACED_PREVIEW_LIMIT);
  const coverageGapOmittedCount = coverageGapCount - coverageGapPreview.length;

  const fontSize = metrics.fontSize;
  const smallFontSize = Math.max(9, fontSize - 3);
  const monoFontSize = Math.max(10, fontSize - 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          padding: "4px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground2,
          fontSize: `${smallFontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
          color: tokens.colorNeutralForeground3,
          flexShrink: 0,
        }}
      >
        <span>{counts.logs.toLocaleString()} log lines</span>
        <span>{counts.events.toLocaleString()} events</span>
        {/* Only shown when something was actually dropped; a "0 unplaced" badge would read as
            reassurance and invite no attention. */}
        {dropped && (
          <span
            style={{ color: tokens.colorPaletteMarigoldForeground1 }}
            title="These carried no timestamp, so placing them would invent a sequence the evidence does not support"
          >
            {dropped}
          </span>
        )}
        {totalCorrelationEdges > correlationEdges.length ? (
          <span title="Correlation details are paged and bounded">
            correlations {totalCorrelationEdges.toLocaleString()}
          </span>
        ) : null}
        {totalCorrelationEdges === correlationEdges.length &&
          correlationCounts.exact > 0 && (
          <span title="Unique explicit identity matches within one normalized machine">
            exact {correlationCounts.exact}
          </span>
        )}
        {totalCorrelationEdges === correlationEdges.length &&
          correlationCounts.candidate > 0 && (
          <span
            style={{ color: tokens.colorNeutralForeground4 }}
            title="Secondary identity only; not a causal relationship"
          >
            candidate {correlationCounts.candidate}
          </span>
        )}
        {totalCorrelationEdges === correlationEdges.length &&
          correlationCounts.ambiguous > 0 && (
          <span
            style={{ color: tokens.colorPaletteMarigoldForeground1 }}
            title="Contradictory or duplicate exact candidates remain unresolved"
          >
            ambiguous {correlationCounts.ambiguous}
          </span>
        )}
        {coverageGapCount > 0 && (
          <span
            style={{ color: tokens.colorPaletteMarigoldForeground1 }}
            title="Missing or unsupported identity coverage prevents a stronger conclusion"
          >
            coverage gaps {coverageGapCount}
          </span>
        )}
      </div>
      {failedPage && (
        <div
          role="alert"
          style={{
            color: tokens.colorPaletteRedForeground1,
            padding: "4px 12px",
            flexShrink: 0,
          }}
        >
          A timeline page could not be loaded: {failedPage.message}{" "}
          <Button
            appearance="subtle"
            size="small"
            onClick={() => {
              retryAttemptsRef.current.delete(
                `${pageSessionGenerationRef.current}:${failedPage.offset}`,
              );
              setFailedPage(null);
              setRequestRevision((revision) => revision + 1);
            }}
          >
            Retry timeline page
          </Button>
        </div>
      )}
      {(totalCorrelationEdges > 0 || coverageGapCount > 0) && (
        <details
          style={{
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground2,
            fontSize: `${smallFontSize}px`,
            fontFamily: LOG_UI_FONT_FAMILY,
            flexShrink: 0,
          }}
        >
          <summary style={{ cursor: "pointer", padding: "6px 12px" }}>
            Show correlation details
          </summary>
          <div
            role="region"
            aria-label="Correlation details"
            tabIndex={0}
            style={{
              display: "grid",
              gap: "4px",
              padding: "0 12px 6px",
              maxHeight: "min(320px, 40vh)",
              overflowY: "auto",
              overflowWrap: "anywhere",
            }}
          >
            {correlationPreview.map((edge) => (
              <div
                key={edge.id}
                data-testid="correlation-edge"
                style={{
                  display: "grid",
                  gap: "2px",
                  padding: "4px 6px",
                  borderLeft: `3px solid ${
                    edge.strength === "ambiguous"
                      ? tokens.colorPaletteMarigoldForeground1
                      : tokens.colorNeutralStroke2
                  }`,
                }}
              >
                <span>{correlationEdgeLabel(edge)}</span>
                <span>
                  from: {edge.fromId} → {edge.toId ?? "unresolved"}
                </span>
                {edge.candidateIds.length > 0 && (
                  <span>candidate IDs: {edge.candidateIds.join(", ")}</span>
                )}
                {edge.evidence.slice(0, UNPLACED_PREVIEW_LIMIT).map((evidence) => (
                  <span key={`${edge.id}-${evidence.originId}-${evidence.field}`}>
                    {evidence.field}: {evidence.value} ({evidence.originId})
                  </span>
                ))}
                {edge.evidence.length > UNPLACED_PREVIEW_LIMIT && (
                  <span>
                    Showing the first {UNPLACED_PREVIEW_LIMIT.toLocaleString()} of{" "}
                    {edge.evidence.length.toLocaleString()} evidence items;{" "}
                    {(edge.evidence.length - UNPLACED_PREVIEW_LIMIT).toLocaleString()} omitted.
                  </span>
                )}
                {edge.coverage.gap && (
                  <span>
                    coverage reason: {edge.coverage.gap.reason} ({edge.coverage.gap.source})
                  </span>
                )}
              </div>
            ))}
            {coverageGapPreview.map((gap, index) => (
              <div key={`coverage-gap-${index}`} data-testid="correlation-gap">
                coverage: {gap.reason} ({gap.source})
              </div>
            ))}
            {coverageGapOmittedCount > 0 && (
              <div>
                Showing the first {coverageGapPreview.length.toLocaleString()} of{" "}
                {coverageGapCount.toLocaleString()} coverage gaps;{" "}
                {coverageGapOmittedCount.toLocaleString()} omitted.
              </div>
            )}
            {correlationOmittedCount > 0 && (
              <div>
                Showing the first {correlationPreview.length.toLocaleString()} of{" "}
                {totalCorrelationEdges.toLocaleString()} correlations;{" "}
                {correlationOmittedCount.toLocaleString()} omitted.
              </div>
            )}
          </div>
        </details>
      )}

      {totalItems === 0 ? (
        <div
          style={{
            padding: "24px",
            textAlign: "center",
            color: tokens.colorNeutralForeground3,
            fontSize: `${fontSize}px`,
            fontFamily: LOG_UI_FONT_FAMILY,
            overflowY: "auto",
          }}
        >
          {pending ? (
            "Building the unified timeline..."
          ) : unplacedCount === 0 ? (
            "Nothing to place on the timeline yet. Load a log file and an event source to correlate them."
          ) : (
            <>
              <div style={{ marginBottom: "16px", fontWeight: 600 }}>{dropped}</div>
              <div
                role="list"
                aria-label="Unplaced timeline entries"
                style={{
                  display: "grid",
                  gap: "4px",
                  margin: "0 auto",
                  maxWidth: "1100px",
                  textAlign: "left",
                }}
              >
                {unplacedPreview.map((entry, index) => (
                  <div
                    key={`${originDetail(entry.origin)}-${index}`}
                    role="listitem"
                    title={originDetail(entry.origin)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      padding: "6px 8px",
                      border: `1px solid ${tokens.colorNeutralStroke2}`,
                      backgroundColor: tokens.colorNeutralBackground2,
                      fontSize: `${smallFontSize}px`,
                      textAlign: "left",
                    }}
                  >
                    <span
                      style={{
                        width: "70px",
                        flexShrink: 0,
                        fontWeight: 700,
                        color: tokens.colorPaletteMarigoldForeground1,
                      }}
                    >
                      {isEventOrigin(entry.origin) ? "UNPLACED EVT" : "UNPLACED LOG"}
                    </span>
                    <span
                      style={{
                        width: "220px",
                        flexShrink: 0,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {originLabel(entry.origin)}
                    </span>
                    <span
                      style={{
                        width: "220px",
                        flexShrink: 0,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: tokens.colorNeutralForeground4,
                      }}
                    >
                      {originContext(entry.origin)}
                    </span>
                    <span style={{ color: tokens.colorNeutralForeground3 }}>No timestamp</span>
                  </div>
                ))}
              </div>
              {unplacedOmittedCount > 0 && (
                <div style={{ marginTop: "12px", fontSize: `${smallFontSize}px` }}>
                  Showing the first {unplacedPreview.length.toLocaleString()} of{" "}
                  {unplacedCount.toLocaleString()} unplaced entries;{" "}
                  {unplacedOmittedCount.toLocaleString()} omitted. Use the source details above to
                  investigate the missing timestamps.
                </div>
              )}
            </>
          )}
        </div>
      ) : (
        <div
          ref={parentRef}
          style={{
            overflowY: "auto",
            flex: 1,
            minHeight: 0,
            backgroundColor: tokens.colorNeutralBackground1,
            fontFamily: LOG_UI_FONT_FAMILY,
          }}
        >
          <div style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative" }}>
            {virtualRows.map((virtualRow) => {
              const item = timelinePageCacheItem(
                loadedPages,
                virtualRow.index,
              );
              if (!item) {
                return (
                  <div
                    key={virtualRow.key}
                    data-index={virtualRow.index}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: `${virtualRow.size}px`,
                      transform: `translateY(${virtualRow.start}px)`,
                      padding: "2px 12px",
                      boxSizing: "border-box",
                      color: tokens.colorNeutralForeground4,
                      fontSize: `${smallFontSize}px`,
                    }}
                  >
                    Loading timeline row…
                  </div>
                );
              }
              const color = SEVERITY_COLORS[item.severity];
              const fromEvent = isEventOrigin(item.origin);

              return (
                <div
                  key={virtualRow.key}
                  data-index={virtualRow.index}
                  ref={virtualizer.measureElement}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    transform: `translateY(${virtualRow.start}px)`,
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "2px 12px",
                    boxSizing: "border-box",
                    borderLeft: `4px solid ${color}`,
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    backgroundColor:
                      virtualRow.index % 2 === 0
                        ? tokens.colorNeutralBackground1
                        : tokens.colorNeutralBackground2,
                    fontSize: `${fontSize}px`,
                    lineHeight: `${metrics.rowLineHeight}px`,
                  }}
                >
                  <span
                    style={{
                      width: "40px",
                      flexShrink: 0,
                      textAlign: "center",
                      fontSize: `${smallFontSize}px`,
                      fontWeight: 700,
                      borderRadius: "4px",
                      backgroundColor: fromEvent
                        ? tokens.colorBrandBackground2
                        : tokens.colorNeutralBackground4,
                      color: tokens.colorNeutralForeground2,
                    }}
                    title={fromEvent ? "Windows event" : "Text log line"}
                  >
                    {fromEvent ? "EVT" : "LOG"}
                  </span>

                  <span
                    style={{
                      width: "175px",
                      flexShrink: 0,
                      fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                      fontSize: `${monoFontSize}px`,
                      color: tokens.colorNeutralForeground3,
                    }}
                  >
                    {formatEventTime(item.timestampMs, timeZoneMode)}
                  </span>
                  <span
                    style={{
                      width: "220px",
                      flexShrink: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontSize: `${smallFontSize}px`,
                      color: tokens.colorNeutralForeground3,
                    }}
                    title={originDetail(item.origin)}
                  >
                    {originLabel(item.origin)}
                  </span>

                  <span
                    style={{
                      width: "180px",
                      flexShrink: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontSize: `${smallFontSize}px`,
                      color: tokens.colorNeutralForeground4,
                    }}
                    title={originDetail(item.origin)}
                  >
                    {originContext(item.origin)}
                  </span>

                  <span
                    style={{
                      flex: 1,
                      minWidth: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      color: tokens.colorNeutralForeground1,
                    }}
                    title={item.message}
                  >
                    {item.message}
                  </span>
                </div>
              );
            })}
          </div>
          {unplacedCount > 0 && (
            <div
              style={{
                padding: "10px 12px",
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                color: tokens.colorPaletteMarigoldForeground1,
                fontSize: `${smallFontSize}px`,
              }}
            >
              {unplacedPreview.map((unplaced, index) => (
                <div
                  key={`${originDetail(unplaced.origin)}-${index}`}
                  style={{ padding: "4px 0" }}
                >
                  {isEventOrigin(unplaced.origin) ? "Unplaced event" : "Unplaced log"}: no timestamp ·{" "}
                  {originContext(unplaced.origin)}
                </div>
              ))}
              {unplacedOmittedCount > 0 && (
                <div style={{ padding: "4px 0" }}>
                  Showing the first {unplacedPreview.length.toLocaleString()} of{" "}
                  {unplacedCount.toLocaleString()} unplaced entries;{" "}
                  {unplacedOmittedCount.toLocaleString()} omitted.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
