/**
 * Coverage-gap handling through the store's real load paths.
 *
 * `evtx-coverage.test.ts` covers the merge rule in isolation. That is not enough: the rule can be
 * right while a call site drops the gaps entirely, which is exactly what `queryChannels` did. These
 * drive the store itself so a regression in a load path fails here.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn().mockResolvedValue(() => {}) }));

const { useEvtxStore } = await import("./evtx-store");

function result(channel: string, gaps: string[]) {
  return {
    records: [],
    channels: [{ name: channel, eventCount: 0, sourceType: "live" }],
    totalRecords: 0,
    parseErrors: gaps.length,
    errorMessages: gaps,
  };
}

describe("coverage gaps through the store", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
    });
  });

  it("keeps the gaps a channel query reported", async () => {
    // queryChannels previously discarded these, so a partly unreadable channel looked complete.
    invoke.mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]));

    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([
      "Application: 3 records unreadable",
    ]);
  });

  it("accumulates gaps as channels load one at a time", async () => {
    invoke
      .mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]))
      .mockResolvedValueOnce(result("System", ["System: stopped at 100000 events"]));

    await useEvtxStore.getState().queryChannels(["Application"]);
    await useEvtxStore.getState().queryChannels(["System"]);

    expect(useEvtxStore.getState().coverageGaps).toHaveLength(2);
  });

  it("does not repeat a gap when the same channel is queried again", async () => {
    invoke
      .mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]))
      .mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]));

    await useEvtxStore.getState().queryChannels(["Application"]);
    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toHaveLength(1);
  });

  it("reports nothing when a channel loads cleanly", async () => {
    invoke.mockResolvedValueOnce(result("Application", []));

    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("a refresh drops gaps from the records it replaced", async () => {
    // The refresh clears the records, so gaps describing them must go too, or the banner reports a
    // gap in a set that is no longer on screen.
    invoke.mockResolvedValueOnce(result("Application", ["Application: stale gap"]));
    await useEvtxStore.getState().queryChannels(["Application"]);
    expect(useEvtxStore.getState().coverageGaps).toHaveLength(1);

    invoke.mockResolvedValueOnce(result("Application", ["Application: fresh gap"]));
    await useEvtxStore.getState().refreshLoadedChannels();

    expect(useEvtxStore.getState().coverageGaps).toEqual(["Application: fresh gap"]);
  });
});
