import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { useTimelineStore } from "../../stores/timeline-store";
import { useLogStore } from "../../stores/log-store";
import { deferred } from "../../test-utils/deferred";
import { syntheticTimeline, firewallTimelineError } from "../../test-utils/timeline";
import { firewallEntry } from "../../test-utils/firewall";
import type { TimelineEntry, TimelineBundle, IncidentDetail } from "../../types/timeline";
import { useTimelineEntries } from "./hooks/useTimelineEntries";
import { useIncidentDetail } from "./hooks/useIncidentDetail";
import { buildTimelineFromSources } from "./hooks/buildTimelineFromSources";
import { openTimelineSource, openTimelineFiles, replaceTimelineSource } from "../../workspaces/timeline/open-timeline-source";
import { TimelineWorkspace } from "./TimelineWorkspace";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("./SwimLaneCanvas", () => ({ SwimLaneCanvas: () => null }));
vi.mock("./TimelineRuler", () => ({ TimelineRuler: () => null }));
vi.mock("./BrushOverlay", () => ({ BrushOverlay: () => null }));
vi.mock("../log-view/LogListView", () => ({ LogListView: () => null }));
const rows: TimelineEntry[] = [{ kind: "log", sourceIdx: 0, entry: firewallEntry() }];
const reasons = ["sourceChanged", "generationUnverifiable", "readDecodeFailure", "invalidIndexContext"] as const;
beforeEach(() => {
  vi.resetAllMocks(); useTimelineStore.getState().reset();
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  vi.mocked(invoke).mockResolvedValue([]);
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
describe("firewall timeline query failures", () => {
  it.each(reasons)("shows page %s without success-caching empty results", async reason => {
    useTimelineStore.getState().setBundle(syntheticTimeline());
    vi.mocked(invoke).mockRejectedValueOnce(firewallTimelineError(reason));
    const hook = renderHook(() => useTimelineEntries(0));
    await waitFor(() => expect(useTimelineStore.getState().queryError).toContain("/synthetic/firewall.log"));
    expect(useTimelineStore.getState().entryCache.size).toBe(0);
    if (reason === "sourceChanged") {
      hook.rerender(); expect(invoke).toHaveBeenCalledTimes(1);
      render(<TimelineWorkspace />);
      expect(screen.getByText("Source changed. Rebuild the timeline to continue.")).toBeVisible();
      expect(screen.getByText(/Counts and lanes are stale/)).toBeVisible();
    }
  });
  it.each(reasons)("shows detail %s without hiding the failure as an empty result", async reason => {
    useTimelineStore.getState().setBundle(syntheticTimeline());
    vi.mocked(invoke).mockRejectedValueOnce(firewallTimelineError(reason));
    renderHook(() => useIncidentDetail(1));
    await waitFor(() => expect(useTimelineStore.getState().queryError).toContain("/synthetic/firewall.log"));
    expect(useTimelineStore.getState().detailCache.size).toBe(0);
  });
  it("late_timeline_completions_cannot_mutate_rebuilt_bundle", async () => {
    useTimelineStore.getState().setBundle(syntheticTimeline("old"));
    const page = deferred<TimelineEntry[]>(), detail = deferred<IncidentDetail>();
    vi.mocked(invoke).mockImplementation((command, args) => (args as { id: string }).id === "old" ? (command === "query_timeline_entries_cmd" ? page.promise : detail.promise) : new Promise(() => {}));
    renderHook(() => useTimelineEntries(0)); renderHook(() => useIncidentDetail(1));
    const origin = useTimelineStore.getState().requestOrigin();
    act(() => useTimelineStore.getState().reportQueryError(firewallTimelineError(), origin));
    expect(useTimelineStore.getState().timelineGeneration).toBeGreaterThan(origin.generation);
    // Revoked success cannot repopulate even before rebuild.
    await act(async () => { page.resolve(rows); await page.promise; });
    expect(useTimelineStore.getState().entryCache.size).toBe(0);
    act(() => useTimelineStore.getState().setBundle(syntheticTimeline("new")));
    await act(async () => { detail.reject(firewallTimelineError()); await Promise.resolve(); });
    expect(useTimelineStore.getState().staleSource).toBeNull();
    expect(useTimelineStore.getState().detailCache.size).toBe(0);
  });
});
describe("real invoke build and UI paths", () => {
  it.each(["open", "append", "replace", "rebuild"] as const)("retains source-specific %s failures and previous stale evidence", async action => {
    useTimelineStore.getState().setBundle(syntheticTimeline());
    useTimelineStore.getState().reportQueryError(firewallTimelineError(), useTimelineStore.getState().requestOrigin());
    vi.mocked(invoke).mockRejectedValueOnce(firewallTimelineError("readDecodeFailure"));
    const request = action === "open" ? openTimelineSource({ kind: "file", path: "/synthetic/new.log" }) : action === "append" ? openTimelineFiles(["/synthetic/new.log"]) : action === "replace" ? replaceTimelineSource({ kind: "file", path: "/synthetic/new.log" }) : buildTimelineFromSources([{ path: "/synthetic/firewall.log" }]);
    await expect(request).rejects.toMatchObject({ kind: "firewallSource", reason: "readDecodeFailure" });
    expect(useTimelineStore.getState().bundle?.id).toBe("synthetic-timeline");
    expect(useTimelineStore.getState().staleSource).not.toBeNull();
    expect(useTimelineStore.getState().loadError).toContain("/synthetic/firewall.log");
  });
  it("late build success and error cannot overwrite a rebuilt bundle", async () => {
    const success = deferred<TimelineBundle>(), failure = deferred<TimelineBundle>();
    vi.mocked(invoke).mockReturnValueOnce(success.promise).mockReturnValueOnce(failure.promise);
    const a = buildTimelineFromSources([{ path: "/synthetic/a.log" }]);
    const b = buildTimelineFromSources([{ path: "/synthetic/b.log" }]);
    useTimelineStore.getState().setBundle(syntheticTimeline("new"));
    success.resolve(syntheticTimeline("old")); await a;
    failure.reject(firewallTimelineError()); await expect(b).rejects.toMatchObject({ reason: "sourceChanged" });
    expect(useTimelineStore.getState().bundle?.id).toBe("new");
    expect(useTimelineStore.getState().loadError).toBeNull();
    expect(useTimelineStore.getState().staleSource).toBeNull();
  });
  it("shows a typed drag/drop build rejection", async () => {
    vi.mocked(invoke).mockRejectedValue(firewallTimelineError("generationUnverifiable"));
    render(<TimelineWorkspace />);
    const file = new File(["synthetic"], "firewall.log"); Object.defineProperty(file, "path", { value: "/synthetic/firewall.log" });
    fireEvent.drop(screen.getByText("Drop log files here").parentElement!, { dataTransfer: { files: [file] } });
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("/synthetic/firewall.log"));
    expect(screen.getByRole("alert")).toHaveTextContent("cannot be verified");
  });
  it.each([0, 2])("shows excluded firewall records for %s indexed rows without dropping Explorer data", total => {
    const bundle = syntheticTimeline(); bundle.totalEntries = total; bundle.sources[0].entryCount = total;
    useTimelineStore.getState().setBundle(bundle); useLogStore.getState().setEntries([firewallEntry()]);
    render(<TimelineWorkspace />);
    expect(screen.getByText(/3 firewall records.*excluded/)).toBeVisible();
    expect(useLogStore.getState().entries).toHaveLength(1);
  });
  it("successful rebuild clears stale state and installs the new snapshot", async () => {
    useTimelineStore.getState().setBundle(syntheticTimeline());
    useTimelineStore.getState().reportQueryError(firewallTimelineError(), useTimelineStore.getState().requestOrigin());
    vi.mocked(invoke).mockResolvedValueOnce(syntheticTimeline("rebuilt"));
    await buildTimelineFromSources([{ path: "/synthetic/firewall.log" }]);
    expect(useTimelineStore.getState().bundle?.id).toBe("rebuilt"); expect(useTimelineStore.getState().staleSource).toBeNull();
  });
});

describe("folder discovery ownership", () => {
  it.each(["append", "replace"] as const)("revokes late %s discovery before a native build can start", async mode => {
    useTimelineStore.getState().setBundle(syntheticTimeline("old"));
    const listing = deferred<unknown>(); vi.mocked(invoke).mockReturnValueOnce(listing.promise);
    const operation = (mode === "append" ? openTimelineSource : replaceTimelineSource)({ kind: "folder", path: "/synthetic/old-folder" });
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("list_log_folder", { path: "/synthetic/old-folder" }));
    useTimelineStore.getState().setBundle(syntheticTimeline("new"));
    listing.resolve({ sourceKind: "folder", source: { kind: "folder", path: "/synthetic/old-folder" }, entries: [{ name: "old.log", path: "/synthetic/old-folder/old.log", isDir: false, sizeBytes: 1, modifiedUnixMs: null }] });
    await operation;
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(useTimelineStore.getState().bundle?.id).toBe("new");
  });
  it("ignores a discovery rejection after same-bundle invalidation", async () => {
    useTimelineStore.getState().setBundle(syntheticTimeline());
    const listing = deferred<unknown>(); vi.mocked(invoke).mockReturnValueOnce(listing.promise);
    const operation = openTimelineSource({ kind: "folder", path: "/synthetic/old-folder" });
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    useTimelineStore.getState().invalidateCaches();
    listing.reject(new Error("old listing failure")); await expect(operation).rejects.toThrow();
    expect(useTimelineStore.getState().loadError).toBeNull();
  });
});
