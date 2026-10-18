import { tokens } from "@fluentui/react-components";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_LOG_LIST_FONT_SIZE,
  MAX_LOG_LIST_FONT_SIZE,
  MIN_LOG_LIST_FONT_SIZE,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { deferred } from "../../test-utils/deferred";
import {
  EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT,
  EVENT_LOG_TIMELINE_PAGE_SIZE,
} from "./evtx-timeline-paging";
import {
  EVENT_LOG_TIMELINE_CACHE_RADIUS,
  retainTimelinePageCache,
  timelinePageCacheByteCount,
  timelinePageCacheRowCount,
  timelinePageCacheSegment,
  timelinePageCacheItem,
  timelineRetentionWindowForRange,
  UnifiedTimelineView,
} from "./UnifiedTimelineView";
import {
  UNIFIED_TIMELINE_FLOOR_ROWS,
  UNIFIED_TIMELINE_STRIP_HEIGHT_PX,
  timelineStripLayout,
} from "./evtx-timeline-strip";
import source from "./UnifiedTimelineView.tsx?raw";
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
  it("marks each row with the shared EVT / LOG chip, LOG on bg3 where the older chip was on bg4", () => {
    const withLog: UnifiedTimeline = {
      ...timeline,
      items: [
        ...timeline.items,
        {
          timestampMs: 2,
          severity: "info",
          message: "Starting Powershell Execution",
          origin: {
            kind: "log",
            file: "C:\\Logs\\AgentExecutor.log",
            component: "AgentExecutor",
            line: 7,
            source: "C:\\Logs\\AgentExecutor.log",
            machine: null,
            bundle: null,
            recordId: 7,
          },
        },
      ],
    };
    render(<UnifiedTimelineView {...timelineSessionProps(withLog)} />);
    const evt = screen.getByRole("img", { name: "Windows event" });
    const log = screen.getByRole("img", { name: "Text log line" });
    expect(evt).toHaveAttribute("data-chip", "EVT");
    expect(evt).toHaveTextContent("EVT");
    expect(evt.style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    expect(log).toHaveAttribute("data-chip", "LOG");
    expect(log).toHaveTextContent("LOG");
    expect(log.style.backgroundColor).toBe(tokens.colorNeutralBackground3);
    // Each chip is in its own row, in the column the rows reserve for it.
    expect(within(evt.closest("div[data-index]") as HTMLElement).queryByRole("img", { name: "Text log line" })).toBeNull();
  });

  it("centers the chip in the 40 px column the rows reserve, at every font size, with the chip's own size", () => {
    const before = useUiStore.getState().logListFontSize;
    try {
      for (const fontSize of [MIN_LOG_LIST_FONT_SIZE, DEFAULT_LOG_LIST_FONT_SIZE, MAX_LOG_LIST_FONT_SIZE]) {
        useUiStore.setState({ logListFontSize: fontSize });
        const view = render(<UnifiedTimelineView {...timelineSessionProps(timeline)} />);
        const chip = screen.getByRole("img", { name: "Windows event" });
        // The chip is a child of its column, which is a centering flex box of fixed width that never
        // shrinks: its own width (at most 41 px at the largest font, measured in Chromium) is split
        // evenly on both sides.
        const column = chip.parentElement as HTMLElement;
        expect(column.style.width, `column at ${fontSize}`).toBe("40px");
        expect(column.style.display).toBe("flex");
        expect(column.style.justifyContent).toBe("center");
        expect(column.style.flexShrink).toBe("0");
        // The chip sizes itself: max(10, f - 4), whatever size the row's own text is.
        expect(chip.style.fontSize, `chip at ${fontSize}`).toBe(`${Math.max(10, fontSize - 4)}px`);
        view.unmount();
      }
    } finally {
      useUiStore.setState({ logListFontSize: before });
    }
  });

  it("draws no chip of its own: the kind chip is the shared component", () => {
    expect(source).toContain("EvtxKindChip");
    expect(source).not.toMatch(/colorNeutralBackground4|colorBrandBackground2/);
    expect(source).not.toMatch(/title=\{fromEvent/);
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

/**
 * #839, first comment: a preview is paired with the SAME page's own total, and a total that is
 * missing or not a count is unknown. It is never 0, and it never lets "Showing the first N" or the
 * exact/candidate/ambiguous breakdown claim completeness.
 */
describe("the header when a count is not known", () => {
  const edge = (n: number, strength: "exact" | "candidate" | "ambiguous" = "exact") => ({
    id: `edge-${n}`,
    fromId: `from-${n}`,
    toId: `to-${n}`,
    key: { kind: "activityId", value: `{key-${n}}` },
    strength,
    confidence: "high" as const,
    candidateIds: [],
    evidence: [],
    coverage: { state: "covered" as const },
  });
  const gap = (n: number) => ({ source: "correlation", reason: `gap ${n}` });
  const base = () => timelineSessionProps(timeline);

  /** The session, with the first page changed: the status keeps the totals the session reported. */
  function sessionWith(
    page: Record<string, unknown>,
    status: Record<string, unknown> = {},
  ) {
    const props = base();
    return {
      ...props,
      status: { ...props.status, ...status },
      initialPage: { ...props.initialPage, ...page },
    };
  }
  const header = () => document.body.textContent ?? "";
  const open = () => fireEvent.click(screen.getByText("Show correlation details"));
  const detail = () => screen.getByRole("region", { name: "Correlation details" }).textContent ?? "";

  describe("with no session at all", () => {
    it("says the counts are unknown, never 0", () => {
      render(<UnifiedTimelineView status={null} initialPage={null} loadPage={vi.fn()} pending={false} />);
      expect(screen.getByText("counts unknown")).toBeInTheDocument();
      expect(header()).not.toMatch(/\b0\b/);
      expect(header()).not.toMatch(/log lines|events|correlations|coverage gaps|exact|ambiguous/);
    });

    it("does not say there is nothing to place", () => {
      render(<UnifiedTimelineView status={null} initialPage={null} loadPage={vi.fn()} pending={false} />);
      expect(screen.getByText("The unified timeline is not available: its size is not known.")).toBeInTheDocument();
      expect(header()).not.toMatch(/Nothing to place/);
    });

    it("says the counts are unknown while the session is being built too, beside the building message", () => {
      render(<UnifiedTimelineView status={null} initialPage={null} loadPage={vi.fn()} pending />);
      expect(screen.getByText("counts unknown")).toBeInTheDocument();
      expect(screen.getByText("Building the unified timeline...")).toBeInTheDocument();
    });
  });

  describe("correlation edges", () => {
    it.each([
      ["not a number", Number.NaN],
      ["missing", undefined],
      ["negative", -3],
      ["fractional", 1.5],
      ["infinite", Number.POSITIVE_INFINITY],
    ])("reads a page total that is %s as unknown, with no breakdown and no 'of M' line", (_why, total) => {
      render(
        <UnifiedTimelineView
          {...sessionWith({ edgesPreview: [edge(1)], totalEdges: total }, { totalEdges: 1 })}
        />,
      );
      // The session total says 1, but the preview belongs to the page, and the page's total is bad.
      expect(screen.getByText("correlations unknown")).toBeInTheDocument();
      expect(screen.queryByText(/^exact \d/)).toBeNull();
      expect(screen.queryByText(/^correlations \d/)).toBeNull();
      open();
      expect(detail()).toContain("Showing the first 1 correlations; the number in this session is not known.");
      expect(detail()).not.toMatch(/ of \d|NaN|omitted/);
    });

    it("reads a page total below what its preview holds as unknown: a contradiction is not proof", () => {
      render(<UnifiedTimelineView {...sessionWith({ edgesPreview: [edge(1), edge(2)], totalEdges: 1 })} />);
      expect(screen.getByText("correlations unknown")).toBeInTheDocument();
      expect(screen.queryByText("exact 2")).toBeNull();
    });

    it("shows 'the first N of M' with M from the PAGE when the preview is shorter than its total", () => {
      render(
        <UnifiedTimelineView
          {...sessionWith(
            { edgesPreview: [edge(1), edge(2), edge(3)], totalEdges: 7 },
            // A different session total must not be the one paired with this preview.
            { totalEdges: 99 },
          )}
        />,
      );
      expect(screen.getByText("correlations 7")).toBeInTheDocument();
      expect(screen.queryByText(/correlations 99/)).toBeNull();
      expect(screen.queryByText(/^exact \d/)).toBeNull();
      open();
      expect(detail()).toContain("Showing the first 3 of 7 correlations; 4 omitted.");
      expect(detail()).not.toContain("99");
    });

    it("still gives the breakdown when the page's total equals its preview", () => {
      render(
        <UnifiedTimelineView
          {...sessionWith({ edgesPreview: [edge(1), edge(2, "candidate")], totalEdges: 2 })}
        />,
      );
      expect(screen.getByText("exact 1")).toBeInTheDocument();
      expect(screen.getByText("candidate 1")).toBeInTheDocument();
      expect(screen.queryByText(/correlations (unknown|\d)/)).toBeNull();
    });

    it("shows no correlation chip at all when the page counts none", () => {
      render(<UnifiedTimelineView {...sessionWith({ edgesPreview: [], totalEdges: 0 })} />);
      expect(screen.queryByText(/correlations/)).toBeNull();
      expect(screen.queryByText("Show correlation details")).toBeNull();
    });
  });

  describe("coverage gaps", () => {
    it("reads a page total that is not a count as unknown, and says how many are listed", () => {
      render(
        <UnifiedTimelineView
          {...sessionWith({ coverageGapsPreview: [gap(1)], totalCoverageGaps: Number.NaN }, { totalCoverageGaps: 1 })}
        />,
      );
      expect(screen.getByText("coverage gaps unknown")).toBeInTheDocument();
      open();
      expect(detail()).toContain("Showing the first 1 coverage gaps; the number in this session is not known.");
      expect(detail()).not.toMatch(/ of \d|NaN/);
    });

    it("takes M from the page, not the session, when the preview is shorter", () => {
      render(
        <UnifiedTimelineView
          {...sessionWith(
            { coverageGapsPreview: [gap(1), gap(2)], totalCoverageGaps: 5 },
            { totalCoverageGaps: 99 },
          )}
        />,
      );
      expect(screen.getByText("coverage gaps 5")).toBeInTheDocument();
      open();
      expect(detail()).toContain("Showing the first 2 of 5 coverage gaps; 3 omitted.");
    });
  });

  describe("unplaced entries", () => {
    it("says the number is unknown in the header and under the list when the page's total is not a count", () => {
      render(<UnifiedTimelineView {...sessionWith({ totalUnplaced: Number.NaN }, { totalUnplaced: 1 })} />);
      expect(screen.getByText("The number of timeline items that could not be placed is not known")).toBeInTheDocument();
      expect(screen.getByText(/Showing the first 1 unplaced entries; the number in this session is not known\./)).toBeInTheDocument();
      expect(screen.queryByText(/1 timeline item could not be placed/)).toBeNull();
    });

    it("does not say there is nothing to place when the total is unknown and nothing is listed", () => {
      const props = timelineSessionProps({ ...timeline, items: [], unplaced: [] });
      render(<UnifiedTimelineView {...props} initialPage={{ ...props.initialPage, totalUnplaced: Number.NaN }} />);
      expect(screen.queryByText(/Nothing to place/)).toBeNull();
      // Said in the header and again as the empty state's heading.
      expect(
        screen.getAllByText("The number of timeline items that could not be placed is not known").length,
      ).toBeGreaterThanOrEqual(1);
    });

    it("says nothing is to be placed only when the page counts none", () => {
      render(<UnifiedTimelineView {...timelineSessionProps({ ...timeline, items: [], unplaced: [] })} />);
      expect(screen.getByText(/Nothing to place on the timeline yet/)).toBeInTheDocument();
    });
  });

  describe("the session's own counts", () => {
    it("says log lines and events are unknown when the status does not report a count", () => {
      render(<UnifiedTimelineView {...sessionWith({}, { logItems: Number.NaN, eventItems: undefined })} />);
      expect(screen.getByText("log lines unknown")).toBeInTheDocument();
      expect(screen.getByText("events unknown")).toBeInTheDocument();
      expect(header()).not.toMatch(/NaN|\b0 log lines|\b0 events/);
    });

    it("says them as numbers when it does", () => {
      render(<UnifiedTimelineView {...sessionWith({}, { logItems: 12, eventItems: 1_234 })} />);
      expect(screen.getByText("12 log lines")).toBeInTheDocument();
      expect(screen.getByText("1,234 events")).toBeInTheDocument();
    });
  });
});

/**
 * Z2. The Table view's strip is a fixed-height flex column (header, correlation details, list). A
 * scroll container's automatic minimum size is 0, so a list that is only `flex: 1` collapses to
 * nothing once the details fill the strip. jsdom does no layout, so these pin the styles that
 * prevent it; e2e/screenshots/event-logs.spec.ts ("event-logs table") measures the list in a browser.
 */
describe("the strip keeps its list when the correlation details are open (Z2)", () => {
  const correlated: UnifiedTimeline = {
    ...timeline,
    edges: [
      {
        id: "exact-edge",
        fromId: "a",
        toId: "b",
        key: { kind: "activityId", value: "{activity}" },
        strength: "exact",
        confidence: "high",
        candidateIds: [],
        evidence: [],
        coverage: { state: "covered" },
      },
    ],
  };
  // The default list font is 13: a row is 20 + 2 + 1 + 2 = 25 px as the virtualizer estimates it.
  const ROW_PX = 25;

  it("derives the floor and the details cap from one row, three rows and what is left of the strip", () => {
    expect(timelineStripLayout(ROW_PX)).toEqual({
      floorPx: 3 * ROW_PX,
      detailsMaxPx: UNIFIED_TIMELINE_STRIP_HEIGHT_PX - 6 * ROW_PX,
    });
    expect(UNIFIED_TIMELINE_FLOOR_ROWS).toBe(3);
    // At the default font the header (29 px), the summary (33), the capped region and the floor fit.
    const { floorPx, detailsMaxPx } = timelineStripLayout(ROW_PX);
    expect(29 + 33 + detailsMaxPx + floorPx).toBeLessThanOrEqual(UNIFIED_TIMELINE_STRIP_HEIGHT_PX);
    // It scales with the font, and the region is never given less than two rows.
    expect(timelineStripLayout(41)).toEqual({ floorPx: 123, detailsMaxPx: 82 });
    expect(timelineStripLayout(60).detailsMaxPx).toBe(120);
  });

  it("gives the list a floor of three rows, or all it has, and the details region a cap below the strip", () => {
    render(<UnifiedTimelineView {...timelineSessionProps(correlated, 500)} />);
    const list = screen.getByTestId("unified-timeline-list");
    expect(list.style.overflowY).toBe("auto");
    expect(list.style.minHeight).toBe(`${3 * ROW_PX}px`);
    expect(screen.getByRole("region", { name: "Correlation details", hidden: true }).style.maxHeight).toBe(
      `min(${UNIFIED_TIMELINE_STRIP_HEIGHT_PX - 6 * ROW_PX}px, 40vh)`,
    );
  });

  it("floors a list that holds fewer than three rows at its whole content", () => {
    render(<UnifiedTimelineView {...timelineSessionProps({ ...correlated, items: timeline.items.slice(0, 1) })} />);
    expect(screen.getByTestId("unified-timeline-list").style.minHeight).toBe(`${ROW_PX}px`);
  });

  it("gives the unplaced container, which is the strip's only content when nothing is placed, the same floor", () => {
    render(<UnifiedTimelineView {...timelineSessionProps({ ...correlated, items: [] })} />);
    const container = screen.getByTestId("unified-timeline-empty");
    expect(container.style.overflowY).toBe("auto");
    expect(container.style.minHeight).toBe(`${3 * ROW_PX}px`);
    expect(container.style.boxSizing).toBe("border-box");
    expect(container).toContainElement(screen.getByRole("list", { name: "Unplaced timeline entries" }));
  });

  it("gives every scroll container that is a direct child of the strip a floor above zero", () => {
    for (const items of [timeline.items, []]) {
      const { unmount } = render(<UnifiedTimelineView {...timelineSessionProps({ ...correlated, items })} />);
      const strip = screen.getByTestId("unified-timeline");
      const scrollers = Array.from(strip.children).filter(
        (child) => !["", "visible"].includes((child as HTMLElement).style.overflowY),
      ) as HTMLElement[];
      expect(scrollers.length).toBeGreaterThan(0);
      for (const scroller of scrollers) {
        expect(parseFloat(scroller.style.minHeight), scroller.getAttribute("data-testid") ?? "").toBeGreaterThan(0);
      }
      unmount();
    }
  });
});
