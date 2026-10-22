/**
 * The hook is the store's coverage state through `unreadSourcesFrom`: the rule is evtx-coverage.test.ts's,
 * this shows that it reads the store's four inputs and follows them.
 */
import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useEvtxStore } from "./evtx-store";
import { useUnreadSources } from "./useUnreadSources";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

beforeEach(() => {
  useEvtxStore.getState().reset();
});
afterEach(cleanup);

describe("useUnreadSources", () => {
  it("is false with nothing missing", () => {
    expect(renderHook(() => useUnreadSources()).result.current).toBe(false);
  });

  it("follows the structured coverage gaps", () => {
    const view = renderHook(() => useUnreadSources());
    act(() =>
      useEvtxStore.setState({
        coverageDetails: [{ source: "Security", kind: "accessDenied", reason: "needs elevation" }],
      }),
    );
    expect(view.result.current).toBe(true);
    act(() => useEvtxStore.setState({ coverageDetails: [] }));
    expect(view.result.current).toBe(false);
  });

  it("follows the legacy and the live-tail gaps", () => {
    const view = renderHook(() => useUnreadSources());
    act(() => useEvtxStore.setState({ coverageGaps: ["System: stopped at 100000 events"] }));
    expect(view.result.current).toBe(true);
    act(() => useEvtxStore.setState({ coverageGaps: [], tailCoverageGaps: ["Application: not delivered"] }));
    expect(view.result.current).toBe(true);
    act(() => useEvtxStore.setState({ tailCoverageGaps: [] }));
    expect(view.result.current).toBe(false);
  });

  it("follows the source manifest's coverage", () => {
    const view = renderHook(() => useUnreadSources());
    act(() =>
      useEvtxStore.setState({
        sourceManifest: {
          coverage: [{ path: "C:\\Evidence\\System.evtx", kind: "missing", reason: "the file is not in the bundle" }],
        } as never,
      }),
    );
    expect(view.result.current).toBe(true);
    act(() => useEvtxStore.setState({ sourceManifest: null }));
    expect(view.result.current).toBe(false);
  });

  it("does not render again for state it does not read", () => {
    let renders = 0;
    renderHook(() => {
      renders += 1;
      return useUnreadSources();
    });
    const before = renders;
    act(() => useEvtxStore.setState({ selectedRecordId: 5 }));
    act(() => useEvtxStore.setState({ records: [] }));
    act(() => useEvtxStore.setState({ timeZoneMode: "utc" }));
    expect(renders).toBe(before);
  });
});
