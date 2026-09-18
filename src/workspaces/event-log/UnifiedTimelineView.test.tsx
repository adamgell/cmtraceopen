import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { deferred } from "../../test-utils/deferred";
import {
  EVENT_LOG_TIMELINE_CACHE_RADIUS,
  EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT,
  EVENT_LOG_TIMELINE_PAGE_SIZE,
  retainTimelinePageCache,
  timelinePageCacheByteCount,
  timelinePageCacheRowCount,
  timelinePageCacheSegment,
  timelinePageCacheItem,
  timelineRetentionWindowForRange,
  UnifiedTimelineView,
} from "./UnifiedTimelineView";
import type { UnifiedTimeline } from "./unified-timeline";

const virtualWindow = vi.hoisted(() => ({ start: 0, size: 20 }));
const TEST_PAGE_SERIALIZED_BYTES = 64 * 1024;

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () =>
      Array.from(
        { length: Math.min(Math.max(count - virtualWindow.start, 0), virtualWindow.size) },
        (_, relativeIndex) => ({
        index: virtualWindow.start + relativeIndex,
        key: virtualWindow.start + relativeIndex,
        size: estimateSize(),
        start: (virtualWindow.start + relativeIndex) * estimateSize(),
      })),
    measureElement: vi.fn(),
  }),
}));

vi.mock("./evtx-store", () => ({
  useEvtxStore: (selector: (state: { timeZoneMode: "utc" }) => unknown) =>
    selector({ timeZoneMode: "utc" }),
}));

const timeline: UnifiedTimeline = {
  items: [
    {
      timestampMs: 1,
      severity: "error",
      message: "Enrollment failed",
      origin: {
        kind: "event",
        stableId: "source12:capture.evtx|channel72:Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin|record1234",
        source: "capture.evtx",
        machine: "HOST-A",
        bundle: "bundle-1",
        channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
        provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
        processId: 4321,
        activityId: "{activity}",
        eventId: 76,
        recordId: 1234,
      },
    },
  ],
  unplaced: [
    {
      origin: {
        kind: "event",
        stableId: "source12:capture.evtx|channel8:Security|record1234",
        source: "capture.evtx",
        machine: null,
        bundle: null,
        channel: "Security",
        provider: "Provider",
        processId: null,
        activityId: null,
        eventId: 4624,
        recordId: 1234,
      },
      reason: "missingTimestamp",
    },
  ],
  edges: [],
  coverageGaps: [],
};

function timelineSessionProps(
  value: UnifiedTimeline,
  totalItems = value.items.length,
) {
  const status = {
    sessionId: "timeline-session",
    revision: 1,
    totalItems,
    eventItems: totalItems,
    logItems: 0,
    totalUnplaced: value.unplaced.length,
    totalEdges: value.edges.length,
    totalCoverageGaps: value.coverageGaps.length,
    finalized: true,
  };
  return {
    status,
    initialPage: {
      ...status,
      offset: 0,
      nextOffset: value.items.length < totalItems ? value.items.length : null,
      serializedBytes: TEST_PAGE_SERIALIZED_BYTES,
      items: value.items,
      unplacedPreview: value.unplaced,
      edgesPreview: value.edges,
      coverageGapsPreview: value.coverageGaps,
    },
    loadPage: vi.fn(),
  };
}

function timelinePage(
  status: ReturnType<typeof timelineSessionProps>["status"],
  offset: number,
) {
  const count = Math.min(
    EVENT_LOG_TIMELINE_PAGE_SIZE,
    status.totalItems - offset,
  );
  return {
    ...status,
    offset,
    nextOffset: offset + count < status.totalItems ? offset + count : null,
    serializedBytes: TEST_PAGE_SERIALIZED_BYTES,
    items: Array.from({ length: count }, (_, index) => ({
      ...timeline.items[0],
      timestampMs: offset + index + 1,
      message: `Paged event ${offset + index + 1}`,
    })),
    unplacedPreview: [],
    edgesPreview: [],
    coverageGapsPreview: [],
  };
}

describe("UnifiedTimelineView", () => {
  beforeEach(() => {
    virtualWindow.start = 0;
    virtualWindow.size = 20;
  });
  it("renders source and machine provenance while exposing unplaced coverage", () => {
    render(<UnifiedTimelineView {...timelineSessionProps(timeline)} />);
    expect(screen.getByText(/HOST-A · capture\.evtx/)).toBeInTheDocument();
    expect(screen.getAllByTitle(/stable source12:capture\.evtx/)).toHaveLength(2);
    expect(
      screen.getByText("1 timeline item could not be placed: no timestamp"),
    ).toBeInTheDocument();
    expect(screen.getByText("Enrollment failed")).toBeInTheDocument();
  });
  it("renders actionable details when every entry is unplaced", () => {
    render(
      <UnifiedTimelineView
        {...timelineSessionProps({ ...timeline, items: [] })}
      />,
    );
    expect(screen.getByRole("list", { name: "Unplaced timeline entries" })).toBeInTheDocument();
    expect(screen.getByText("Security (4624)")).toBeInTheDocument();
    expect(screen.getByText("machine unknown · capture.evtx")).toBeInTheDocument();
    expect(screen.getByText("No timestamp")).toBeInTheDocument();
  });

  it("shows exact, candidate, ambiguous, and coverage states", () => {
    const correlatedTimeline: UnifiedTimeline = {
      ...timeline,
      edges: [
        {
          id: "exact-edge",
          fromId:
            timeline.items[0].origin.kind === "event"
              ? timeline.items[0].origin.stableId
              : "",
          toId:
            timeline.unplaced[0].origin.kind === "event"
              ? timeline.unplaced[0].origin.stableId
              : null,
          key: { kind: "activityId", value: "{activity}" },
          strength: "exact",
          confidence: "high",
          candidateIds: [],
          evidence: [
            {
              originId:
                "source12:capture.evtx|channel72:Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin|record1234",
              field: "activityId",
              value: "{activity}",
            },
          ],
          coverage: { state: "covered" },
        },
        {
          id: "candidate-edge",
          fromId: "candidate",
          toId: "candidate-target",
          key: { kind: "secondary", value: "process:1" },
          strength: "candidate",
          confidence: "low",
          candidateIds: [],
          evidence: [],
          coverage: { state: "covered" },
        },
        {
          id: "ambiguous-edge",
          fromId: "ambiguous",
          toId: "ambiguous-target",
          key: { kind: "sessionId", value: "session" },
          strength: "ambiguous",
          confidence: "unknown",
          candidateIds: ["ambiguous-target", "other-target"],
          evidence: [],
          coverage: {
            state: "gap",
            gap: { source: "ambiguous", reason: "duplicate" },
          },
        },
      ],
      coverageGaps: [
        {
          source: "correlation",
          reason: "coverage gap limit reached; 2 additional gaps omitted",
        },
      ],
    };
    render(
      <UnifiedTimelineView {...timelineSessionProps(correlatedTimeline)} />,
    );
    expect(screen.getByText("exact 1")).toBeInTheDocument();
    expect(screen.getByText("candidate 1")).toBeInTheDocument();
    expect(screen.getByText("ambiguous 1")).toBeInTheDocument();
    expect(screen.getByText("coverage gaps 1")).toBeInTheDocument();
    const details = document.querySelector("details");
    expect(details).not.toHaveAttribute("open");
    fireEvent.click(screen.getByText("Show correlation details"));
    expect(details).toHaveProperty("open", true);
    const detailViewport = screen.getByRole("region", { name: "Correlation details" });
    expect(detailViewport).toHaveStyle({ overflowY: "auto" });
    expect(detailViewport.style.maxHeight).not.toBe("");
    expect(screen.getByText(/exact · high · activityId: \{activity\}/)).toBeInTheDocument();
    expect(screen.getByText("candidate IDs: ambiguous-target, other-target")).toBeInTheDocument();
    expect(screen.getByText(/coverage reason: duplicate/)).toBeInTheDocument();
    expect(
      screen.getByText(/coverage: coverage gap limit reached; 2 additional gaps omitted/),
    ).toBeInTheDocument();
  });

  it("bounds coverage-gap details and gives duplicate gaps collision-free keys", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      render(
        <UnifiedTimelineView
          {...timelineSessionProps({
            ...timeline,
            coverageGaps: Array.from({ length: 105 }, () => ({
              source: "event-record-identity",
              reason: "duplicate gap",
            })),
          })}
        />,
      );

      fireEvent.click(screen.getByText("Show correlation details"));
      expect(screen.getAllByTestId("correlation-gap")).toHaveLength(100);
      expect(
        screen.getByText("Showing the first 100 of 105 coverage gaps; 5 omitted."),
      ).toBeInTheDocument();
      expect(consoleError.mock.calls.flat().join(" ")).not.toMatch(/same key/i);
    } finally {
      consoleError.mockRestore();
    }
  });

  it("virtualizes a 100,000-item backend timeline from a bounded first page", () => {
    const items = Array.from({ length: 20 }, (_, index) => ({
      ...timeline.items[0],
      timestampMs: index + 1,
      message: `Paged event ${index + 1}`,
    }));
    const status = {
      sessionId: "large-session",
      revision: 7,
      totalItems: 100_000,
      eventItems: 100_000,
      logItems: 0,
      totalUnplaced: 0,
      totalEdges: 0,
      totalCoverageGaps: 0,
      finalized: true,
    };

    render(
      <UnifiedTimelineView
        status={status}
        initialPage={{
          sessionId: status.sessionId,
          revision: status.revision,
          offset: 0,
          nextOffset: items.length,
          serializedBytes: TEST_PAGE_SERIALIZED_BYTES,
          totalItems: status.totalItems,
          eventItems: status.eventItems,
          logItems: status.logItems,
          totalUnplaced: status.totalUnplaced,
          totalEdges: status.totalEdges,
          totalCoverageGaps: status.totalCoverageGaps,
          items,
          unplacedPreview: [],
          edgesPreview: [],
          coverageGapsPreview: [],
        }}
        loadPage={vi.fn()}
      />,
    );

    expect(screen.getByText("100,000 events")).toBeInTheDocument();
    expect(screen.getByText("Paged event 1")).toBeInTheDocument();
    expect(document.querySelectorAll("[data-index]")).toHaveLength(20);
  });

  it("evicts distant pages while scanning and reloads an evicted page", async () => {
    const totalItems = 30_000;
    const base = timelineSessionProps(timeline, totalItems);
    const initialPage = timelinePage(base.status, 0);
    const loadPage = vi.fn((offset: number) =>
      Promise.resolve(timelinePage(base.status, offset)),
    );
    const props = { status: base.status, initialPage, loadPage };
    const { rerender } = render(<UnifiedTimelineView {...props} />);

    let simulatedCache = new Map(
      initialPage.items.length > 0
        ? [
            [
              0,
              timelinePageCacheSegment(
                initialPage.items,
                initialPage.serializedBytes,
              ),
            ],
          ]
        : [],
    );
    for (let page = 1; page <= 12; page += 1) {
      const offset = page * EVENT_LOG_TIMELINE_PAGE_SIZE;
      const next = new Map(simulatedCache);
      next.set(
        offset,
        timelinePageCacheSegment(
          timelinePage(base.status, offset).items,
          TEST_PAGE_SERIALIZED_BYTES,
        ),
      );
      simulatedCache = retainTimelinePageCache(
        next,
        timelineRetentionWindowForRange(
          offset,
          offset + virtualWindow.size - 1,
          totalItems,
          EVENT_LOG_TIMELINE_CACHE_RADIUS,
        ),
        { first: offset, last: offset + virtualWindow.size - 1 },
      );
      expect(timelinePageCacheRowCount(simulatedCache)).toBeLessThanOrEqual(
        EVENT_LOG_TIMELINE_PAGE_SIZE * 3,
      );

      virtualWindow.start = offset;
      rerender(<UnifiedTimelineView {...props} />);
      await waitFor(() =>
        expect(loadPage).toHaveBeenCalledWith(
          offset,
          EVENT_LOG_TIMELINE_PAGE_SIZE,
        ),
      );
      expect(await screen.findByText(`Paged event ${offset + 1}`)).toBeInTheDocument();
      expect(document.querySelectorAll("[data-index]")).toHaveLength(20);
    }

    expect(loadPage).toHaveBeenCalledTimes(12);
    virtualWindow.start = 0;
    rerender(<UnifiedTimelineView {...props} />);
    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(13));
    expect(loadPage).toHaveBeenLastCalledWith(
      0,
      EVENT_LOG_TIMELINE_PAGE_SIZE,
    );
    expect(await screen.findByText("Paged event 1")).toBeInTheDocument();
    expect(document.querySelectorAll("[data-index]")).toHaveLength(20);
  });

  it("bounds cumulative cache bytes while retaining the visible segment", () => {
    const heavyCache = new Map<
      number,
      ReturnType<typeof timelinePageCacheSegment>
    >(
      Array.from(
        { length: 100 },
        (_, index): [
          number,
          ReturnType<typeof timelinePageCacheSegment>,
        ] => [
          index,
          {
            items: [
              {
                ...timeline.items[0],
                timestampMs: index,
                message: `Heavy event ${index}`,
              },
            ],
            serializedBytes: 8 * 1024 * 1024,
          },
        ],
      ),
    );

    const retained = retainTimelinePageCache(
      heavyCache,
      { start: 0, endExclusive: 100 },
      { first: 50, last: 50 },
    );

    expect(timelinePageCacheByteCount(retained)).toBeLessThanOrEqual(
      EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT,
    );
    expect(timelinePageCacheItem(retained, 50)?.message).toBe("Heavy event 50");
  });

  it("retains whole segments and trusts authoritative backend page bytes", () => {
    const items = timelinePage(
      timelineSessionProps(timeline, 2_000).status,
      0,
    ).items;
    const segment = timelinePageCacheSegment(items, 7_654_321);
    const retained = retainTimelinePageCache(
      new Map([[0, segment]]),
      { start: 500, endExclusive: 1_500 },
      { first: 500, last: 519 },
    );

    expect(retained.get(0)).toBe(segment);
    expect(retained.get(0)?.items).toBe(items);
    expect(timelinePageCacheByteCount(retained)).toBe(7_654_321);
  });

  it("keeps one page request active and skips superseded viewport requests", async () => {
    const totalItems = 20_000;
    const base = timelineSessionProps(timeline, totalItems);
    const initialPage = timelinePage(base.status, 0);
    const firstRequest = deferred<ReturnType<typeof timelinePage>>();
    const loadPage = vi.fn((offset: number) =>
      offset === EVENT_LOG_TIMELINE_PAGE_SIZE
        ? firstRequest.promise
        : Promise.resolve(timelinePage(base.status, offset)),
    );
    const props = { status: base.status, initialPage, loadPage };
    const { rerender } = render(<UnifiedTimelineView {...props} />);

    virtualWindow.start = EVENT_LOG_TIMELINE_PAGE_SIZE;
    rerender(<UnifiedTimelineView {...props} />);
    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(1));

    for (let page = 2; page <= 10; page += 1) {
      virtualWindow.start = page * EVENT_LOG_TIMELINE_PAGE_SIZE;
      rerender(<UnifiedTimelineView {...props} />);
    }
    expect(loadPage).toHaveBeenCalledTimes(1);

    await act(async () => {
      firstRequest.resolve(
        timelinePage(base.status, EVENT_LOG_TIMELINE_PAGE_SIZE),
      );
      await firstRequest.promise;
    });
    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(2));
    expect(loadPage).toHaveBeenLastCalledWith(
      10 * EVENT_LOG_TIMELINE_PAGE_SIZE,
      EVENT_LOG_TIMELINE_PAGE_SIZE,
    );
  });

  it("continues a byte-bounded short page from the backend next offset", async () => {
    const totalItems = 2_000;
    const base = timelineSessionProps(timeline, totalItems);
    const initialPage = timelinePage(base.status, 0);
    const firstPage = timelinePage(
      base.status,
      EVENT_LOG_TIMELINE_PAGE_SIZE,
    );
    firstPage.items = firstPage.items.slice(0, 5);
    firstPage.nextOffset = EVENT_LOG_TIMELINE_PAGE_SIZE + 5;
    const loadPage = vi.fn((offset: number) =>
      Promise.resolve(
        offset === EVENT_LOG_TIMELINE_PAGE_SIZE
          ? firstPage
          : timelinePage(base.status, offset),
      ),
    );
    virtualWindow.start = EVENT_LOG_TIMELINE_PAGE_SIZE;
    render(
      <UnifiedTimelineView
        status={base.status}
        initialPage={initialPage}
        loadPage={loadPage}
      />,
    );

    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(2));
    expect(loadPage.mock.calls.map(([offset]) => offset)).toEqual([
      EVENT_LOG_TIMELINE_PAGE_SIZE,
      EVENT_LOG_TIMELINE_PAGE_SIZE + 5,
    ]);
    expect(
      await screen.findByText(
        `Paged event ${EVENT_LOG_TIMELINE_PAGE_SIZE + virtualWindow.size}`,
      ),
    ).toBeInTheDocument();
  });

  it("never inserts an old-session page after the session changes", async () => {
    const oldBase = timelineSessionProps(timeline, 2_000);
    const newBase = timelineSessionProps(timeline, 2_000);
    newBase.status = { ...newBase.status, sessionId: "new-session" };
    const oldPageRequest = deferred<ReturnType<typeof timelinePage>>();
    const newPage = timelinePage(
      newBase.status,
      EVENT_LOG_TIMELINE_PAGE_SIZE,
    );
    newPage.items[0] = { ...newPage.items[0], message: "New session row" };
    const loadPage = vi
      .fn()
      .mockReturnValueOnce(oldPageRequest.promise)
      .mockResolvedValueOnce(newPage);
    virtualWindow.start = EVENT_LOG_TIMELINE_PAGE_SIZE;
    const { rerender } = render(
      <UnifiedTimelineView
        status={oldBase.status}
        initialPage={timelinePage(oldBase.status, 0)}
        loadPage={loadPage}
      />,
    );
    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(1));

    rerender(
      <UnifiedTimelineView
        status={newBase.status}
        initialPage={timelinePage(newBase.status, 0)}
        loadPage={loadPage}
      />,
    );
    const oldPage = timelinePage(
      oldBase.status,
      EVENT_LOG_TIMELINE_PAGE_SIZE,
    );
    oldPage.items[0] = { ...oldPage.items[0], message: "Old session row" };
    await act(async () => {
      oldPageRequest.resolve(oldPage);
      await oldPageRequest.promise;
    });

    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("New session row")).toBeInTheDocument();
    expect(screen.queryByText("Old session row")).toBeNull();
  });

  it("automatically retries a transient timeline page failure", async () => {
    const totalItems = 2_000;
    const base = timelineSessionProps(timeline, totalItems);
    const initialPage = timelinePage(base.status, 0);
    const loadPage = vi
      .fn()
      .mockRejectedValueOnce(new Error("temporary paging failure"))
      .mockResolvedValueOnce(
        timelinePage(base.status, EVENT_LOG_TIMELINE_PAGE_SIZE),
      );
    virtualWindow.start = EVENT_LOG_TIMELINE_PAGE_SIZE;
    render(
      <UnifiedTimelineView
        status={base.status}
        initialPage={initialPage}
        loadPage={loadPage}
      />,
    );

    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByText(
        `Paged event ${EVENT_LOG_TIMELINE_PAGE_SIZE + 1}`,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry timeline page" })).toBeNull();
  });

  it("stops bounded automatic retries and offers a manual retry", async () => {
    const totalItems = 2_000;
    const base = timelineSessionProps(timeline, totalItems);
    const initialPage = timelinePage(base.status, 0);
    const loadPage = vi
      .fn()
      .mockRejectedValueOnce(new Error("persistent paging failure"))
      .mockRejectedValueOnce(new Error("persistent paging failure"))
      .mockRejectedValueOnce(new Error("persistent paging failure"))
      .mockResolvedValueOnce(
        timelinePage(base.status, EVENT_LOG_TIMELINE_PAGE_SIZE),
      );
    virtualWindow.start = EVENT_LOG_TIMELINE_PAGE_SIZE;
    render(
      <UnifiedTimelineView
        status={base.status}
        initialPage={initialPage}
        loadPage={loadPage}
      />,
    );

    expect(
      await screen.findByText(/persistent paging failure/),
    ).toBeInTheDocument();
    expect(loadPage).toHaveBeenCalledTimes(3);
    fireEvent.click(
      screen.getByRole("button", { name: "Retry timeline page" }),
    );

    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(4));
    expect(
      await screen.findByText(
        `Paged event ${EVENT_LOG_TIMELINE_PAGE_SIZE + 1}`,
      ),
    ).toBeInTheDocument();
  });
});
