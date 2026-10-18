/**
 * The Details context section as the pane mounts it (#843): the component of EvtxDetailContext fed
 * from the workspace's own sources, with nothing of its own. The session is the workspace's
 * (`useEvtxAnalysisSession`, mapped with `analysisSessionState`), the unread sources are the store's
 * (`useUnreadSources`), the window is the shared reader's (`useEvtxCorrelationWindow`) at a fixed
 * ±5 min. This file protects that wiring: when it reads, what it reads, and what it shows when the
 * session is not there. The list itself is EvtxDetailContext's and the model's.
 */
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import type { ThemeId } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { EvtxAnalysisSessionProvider, type EvtxAnalysisSession } from "./evtx-analysis-session";
import {
  ANALYSIS_BUILDING_TEXT,
  NO_SESSION_TEXT,
  READING_WINDOW_TEXT,
  UNREAD_SOURCES_NOTE,
  UPDATING_CORRELATION_TEXT,
} from "./evtx-correlation-copy";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import { eventItem, makeData, recordFor, rid, synthetic } from "./evtx-correlation-test-fixtures";
import type { CorrelationWindowDeps } from "./evtx-correlation-window";
import { DETAIL_CONTEXT_HALF_WIDTH_MS, DETAIL_CONTEXT_TITLE } from "./evtx-detail-context-model";
import { SESSION_KEY, countsFor, logItem, windowReplyFor } from "./evtx-detail-context-test-helpers";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import EvtxDetailContextSection from "./EvtxDetailContextSection";
import sectionSource from "./EvtxDetailContextSection.tsx?raw";
import { EvtxCorrelationProvider, type EvtxCorrelationData } from "./useEvtxCorrelation";

const record = recordFor(20);
const t = record.timestampEpoch;
const [SESSION_ID, REVISION] = SESSION_KEY.split(":") as [string, string];
const STATUS: EvtxAnalysisSession = { sessionId: SESSION_ID, revision: Number(REVISION) };

const around = () => [
  eventItem(19, t - 1_000),
  eventItem(20, t),
  eventItem(21, t + 3_300),
  logItem(7, t + 4_000),
];

/** Injected IO: no wait, and a window call that answers with the entries around the record. */
function makeDeps() {
  const queryWindow = vi.fn<CorrelationWindowDeps["queryWindow"]>(async (sessionId, startMs, endMs) =>
    windowReplyFor(sessionId, STATUS.revision, startMs, endMs, around()),
  );
  const queryTimelinePage = vi.fn<CorrelationWindowDeps["queryTimelinePage"]>();
  const deps: Partial<CorrelationWindowDeps> = { queryWindow, queryTimelinePage, sleep: () => Promise.resolve() };
  return { deps, queryWindow, queryTimelinePage };
}

interface MountOptions {
  status?: EvtxAnalysisSession | null;
  data?: Partial<EvtxCorrelationData>;
  deps?: Partial<CorrelationWindowDeps>;
}

function tree({ status = STATUS, data = {}, deps }: MountOptions) {
  const base = makeData({ items: [], edges: [synthetic("e", rid(20), rid(21))], builtFor: SESSION_KEY, hasItems: false });
  return (
    <div style={{ backgroundColor: "var(--colorNeutralBackground2)" }}>
      <EvtxAnalysisSessionProvider value={status}>
        <EvtxCorrelationProvider value={{ ...base, ...data }}>
          <EvtxDetailContextSection
            record={record}
            timeZoneMode="utc"
            windowDeps={deps}
            selectionSettleMs={0}
            sessionSettleMs={0}
          />
        </EvtxCorrelationProvider>
      </EvtxAnalysisSessionProvider>
    </div>
  );
}

const section = () => screen.getByRole("group", { name: DETAIL_CONTEXT_TITLE });
/** Lets the hook's (immediate) wait and the mocked reply settle. */
const settle = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });

beforeEach(() => {
  useUiStore.setState({ themeId: "light" as ThemeId, logListFontSize: 14 });
  useEvtxStore.getState().reset();
  useEvtxLayoutStore.setState({
    panels: { channels: true, insights: true, dock: false },
    railTab: "details",
    activeView: "table",
  });
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false });
});

afterEach(() => {
  cleanup();
});

describe("when the section reads its window", () => {
  it("reads ±5 min around the record's instant, once, and lists what came back", async () => {
    const { deps, queryWindow } = makeDeps();
    render(tree({ deps }));
    await waitFor(() => expect(within(section()).getAllByRole("listitem")).toHaveLength(4));
    expect(queryWindow).toHaveBeenCalledTimes(1);
    expect(queryWindow).toHaveBeenCalledWith(STATUS.sessionId, t - DETAIL_CONTEXT_HALF_WIDTH_MS, t + DETAIL_CONTEXT_HALF_WIDTH_MS, 1_000);
    expect(DETAIL_CONTEXT_HALF_WIDTH_MS).toBe(300_000);
    expect(within(section()).getByRole("img", { name: /^Exact link to this event/ })).toBeInTheDocument();
  });

  it("reads nothing while the Insights panel is hidden, and reads when it is shown", async () => {
    const { deps, queryWindow } = makeDeps();
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: false, dock: false } });
    render(tree({ deps }));
    await settle();
    expect(queryWindow).not.toHaveBeenCalled();
    act(() => useEvtxLayoutStore.setState({ panels: { channels: true, insights: true, dock: false } }));
    await waitFor(() => expect(queryWindow).toHaveBeenCalledTimes(1));
  });

  it("reads nothing while the rail is on another tab, and reads when it is on Details", async () => {
    const { deps, queryWindow } = makeDeps();
    useEvtxLayoutStore.setState({ railTab: "insights" });
    render(tree({ deps }));
    await settle();
    expect(queryWindow).not.toHaveBeenCalled();
    act(() => useEvtxLayoutStore.setState({ railTab: "details" }));
    await waitFor(() => expect(queryWindow).toHaveBeenCalledTimes(1));
  });

  it("does not read the same request twice when only the counts object changes", async () => {
    const { deps, queryWindow } = makeDeps();
    const view = render(tree({ deps }));
    await waitFor(() => expect(queryWindow).toHaveBeenCalledTimes(1));
    view.rerender(tree({ deps, data: { counts: countsFor([synthetic("e", rid(20), rid(21))]) } }));
    await settle();
    expect(queryWindow).toHaveBeenCalledTimes(1);
  });

  it("reads nothing for a record that has no usable instant", async () => {
    const { deps, queryWindow } = makeDeps();
    const untimed = { ...record, timestampEpoch: 0 };
    render(
      <EvtxAnalysisSessionProvider value={STATUS}>
        <EvtxCorrelationProvider value={makeData({ items: [], edges: [], builtFor: SESSION_KEY })}>
          <EvtxDetailContextSection record={untimed} timeZoneMode="utc" windowDeps={deps} selectionSettleMs={0} sessionSettleMs={0} />
        </EvtxCorrelationProvider>
      </EvtxAnalysisSessionProvider>,
    );
    await settle();
    expect(queryWindow).not.toHaveBeenCalled();
    expect(section()).toHaveTextContent("This event has no timestamp; it cannot be placed.");
  });
});

describe("what the section takes from the workspace", () => {
  it("shows the store's unread sources", async () => {
    const { deps } = makeDeps();
    act(() =>
      useEvtxStore.setState({
        coverageDetails: [{ source: "Security", kind: "accessDenied", reason: "needs elevation" }],
      }),
    );
    render(tree({ deps }));
    await waitFor(() => expect(section()).toHaveTextContent(UNREAD_SOURCES_NOTE));
  });

  it("pairs the window with the counts of its own session, and shows an icon only for them", async () => {
    const { deps } = makeDeps();
    const other = countsFor([synthetic("e", rid(20), rid(21))], { builtFor: "another:9" });
    render(tree({ deps, data: { counts: other } }));
    await waitFor(() => expect(within(section()).getAllByRole("listitem")).toHaveLength(4));
    expect(within(section()).queryAllByRole("img", { name: /link to this event/ })).toEqual([]);
  });

  it("says the pair is an earlier session's when the counts are", async () => {
    const { deps } = makeDeps();
    const earlier = countsFor([synthetic("e", rid(20), rid(21))], { updating: true });
    render(tree({ deps, data: { counts: earlier } }));
    await waitFor(() => expect(section()).toHaveTextContent(UPDATING_CORRELATION_TEXT));
  });

  it("is a window of the workspace's session, however it is provided: no session in the tree is no session", async () => {
    const { deps, queryWindow } = makeDeps();
    render(tree({ status: null, deps, data: { stage: "unavailable" } }));
    await settle();
    expect(queryWindow).not.toHaveBeenCalled();
    expect(section()).toHaveTextContent(NO_SESSION_TEXT);
  });
});

describe("the three states of the session", () => {
  it("says the analysis is being built while the stage is pending, and waits", async () => {
    const { deps, queryWindow } = makeDeps();
    render(tree({ status: null, deps, data: { stage: "pending" } }));
    await settle();
    expect(queryWindow).not.toHaveBeenCalled();
    expect(section()).toHaveTextContent(ANALYSIS_BUILDING_TEXT);
  });

  it("says there is no analysis when there is none and none is coming", async () => {
    const { deps } = makeDeps();
    render(tree({ status: null, deps, data: { stage: "ready" } }));
    await settle();
    expect(section()).toHaveTextContent(NO_SESSION_TEXT);
    expect(section()).not.toHaveTextContent(ANALYSIS_BUILDING_TEXT);
  });

  it("says it is reading while the session is there and the window is on its way", async () => {
    const pending = new Promise<never>(() => undefined);
    const { deps } = makeDeps();
    render(tree({ deps: { ...deps, queryWindow: () => pending } }));
    await settle();
    expect(section()).toHaveTextContent(READING_WINDOW_TEXT);
    expect(section()).toHaveAttribute("aria-busy", "true");
  });

  it("keeps listing the window it read while the session is rebuilt, and drops it when none is coming", async () => {
    const { deps } = makeDeps();
    const view = render(tree({ deps }));
    await waitFor(() => expect(within(section()).getAllByRole("listitem")).toHaveLength(4));

    // The workspace holds the status at null for the whole rebuild; the stage says one is on the way.
    view.rerender(tree({ status: null, deps, data: { stage: "pending" } }));
    await settle();
    expect(within(section()).getAllByRole("listitem")).toHaveLength(4);

    // The same null status with nothing coming: the kept window is never listed under none.
    view.rerender(tree({ status: null, deps, data: { stage: "unavailable" } }));
    await settle();
    expect(within(section()).queryAllByRole("listitem")).toEqual([]);
    expect(section()).toHaveTextContent(NO_SESSION_TEXT);
  });
});

describe("what the section is made of", () => {
  it("reads every source from the workspace's own, and defines none of them", () => {
    for (const used of [
      "useEvtxAnalysisSession",
      "useUnreadSources",
      "useEvtxCorrelationWindow",
      "useEvtxCorrelationData",
      "analysisSessionState",
      "dockCenterMs",
      "DETAIL_CONTEXT_HALF_WIDTH_MS",
    ]) {
      expect(sectionSource, used).toContain(used);
    }
    // No parallel reader, producer or session rule.
    expect(sectionSource).not.toMatch(/loadCorrelationWindow|unreadSourcesFrom|coverageDetails|stage\s*===|useEffect\(/);
    expect(sectionSource).not.toMatch(/from "\.\/EvtxCorrelationLanes"|from "\.\/EvtxCorrelationView"/);
  });
});
