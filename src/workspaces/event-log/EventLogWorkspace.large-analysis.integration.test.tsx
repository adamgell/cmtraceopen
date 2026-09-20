import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

vi.mock("./SourcePicker", () => ({ SourcePicker: () => null }));
vi.mock("./ChannelPicker", () => ({ ChannelPicker: () => null }));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxTimeline", () => ({
  EvtxTimeline: () => <div role="grid" aria-label="Loaded event grid" />,
}));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./EventDiagnosisPanel", () => ({ EventDiagnosisPanel: () => null }));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));

import { useLogStore } from "../../stores/log-store";
import { useEvtxStore } from "./evtx-store";
import { EventLogWorkspace } from "./EventLogWorkspace";
import type { EvtxRecord } from "./types";

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: 1,
  provider: "Example Provider",
  channel: "Application",
  eventId: 42,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event message",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
};

const EMPTY_TIMELINE_PAGE = {
  sessionId: "test-session",
  revision: 1,
  offset: 0,
  nextOffset: null,
  serializedBytes: 1_024,
  totalItems: 0,
  eventItems: 0,
  logItems: 0,
  items: [],
  totalUnplaced: 0,
  totalEdges: 0,
  totalCoverageGaps: 0,
  unplacedPreview: [],
  edgesPreview: [],
  coverageGapsPreview: [],
};

const NEUTRAL_DIAGNOSIS = {
  findings: [],
  evidence: [],
  coverageGaps: [],
  correlations: [],
  events: [],
  overview: {
    outcome: "noFindings",
    headline: "No issues detected.",
    findingCount: 0,
    actionableFindingCount: 0,
    coverageGapCount: 0,
    evidenceCount: 0,
    correlationCount: 0,
    errorTokenEventCount: 0,
  },
};

const MAX_APPEND_RECORDS = 1_000;
const MAX_APPEND_RECORD_BYTES = 8 * 1024 * 1024;
const MAX_APPEND_ENVELOPE_BYTES = 9 * 1024 * 1024;

function isRecordLike(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    "eventRecordId" in value &&
    "channel" in value &&
    "rawXml" in value
  );
}

function payloadContainsCompleteRecordArray(
  payload: unknown,
  expectedCount: number,
): boolean {
  if (Array.isArray(payload)) {
    if (
      payload.length === expectedCount &&
      isRecordLike(payload[0]) &&
      isRecordLike(payload[payload.length - 1])
    ) {
      return true;
    }
    return payload.some((value) => payloadContainsCompleteRecordArray(value, expectedCount));
  }
  if (payload === null || typeof payload !== "object") return false;
  return Object.values(payload).some((value) =>
    payloadContainsCompleteRecordArray(value, expectedCount),
  );
}

function jsonByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function commandNames(): string[] {
  return mocks.invoke.mock.calls.map(([command]) => String(command));
}

function payloadsFor(commandName: string): Array<Record<string, unknown>> {
  return mocks.invoke.mock.calls
    .filter(([command]) => command === commandName)
    .map(([, payload]) => payload as Record<string, unknown>);
}

describe("EventLogWorkspace large-analysis transport", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
    useLogStore.setState({
      entries: [],
      activeSource: null,
      sourceOpenMode: "merged",
    });
    mocks.invoke.mockReset();

    let receivedRecords = 0;
    let revision = 0;
    mocks.invoke.mockImplementation(
      async (command: string, payload?: Record<string, unknown>) => {
        if (command === "evtx_create_analysis_session") {
          return {
            sessionId: "test-session",
            revision,
            totalItems: receivedRecords,
            eventItems: receivedRecords,
            logItems: 0,
            totalUnplaced: 0,
            totalEdges: 0,
            totalCoverageGaps: 0,
            finalized: false,
          };
        }
        if (command === "evtx_append_analysis_chunk") {
          receivedRecords += Array.isArray(payload?.records)
            ? payload.records.length
            : 0;
          revision += 1;
          return {
            sessionId: "test-session",
            revision,
            totalItems: receivedRecords,
            eventItems: receivedRecords,
            logItems: 0,
            totalUnplaced: 0,
            totalEdges: 0,
            totalCoverageGaps: 0,
            finalized: false,
          };
        }
        if (command === "evtx_finalize_analysis_session") {
          revision += 1;
          return {
            sessionId: "test-session",
            revision,
            totalItems: receivedRecords,
            eventItems: receivedRecords,
            logItems: 0,
            totalUnplaced: 0,
            totalEdges: 0,
            totalCoverageGaps: 0,
            finalized: true,
          };
        }
        if (command === "evtx_query_analysis_timeline") {
          return { ...EMPTY_TIMELINE_PAGE, revision };
        }
        if (command === "evtx_diagnose_analysis_session") {
          return NEUTRAL_DIAGNOSIS;
        }
        if (command === "evtx_close_analysis_session") return undefined;

        return undefined;
      },
    );
  });

  afterEach(() => {
    cleanup();
  });

  it(
    "streams oversized analysis input in bounded session chunks while keeping the event grid visible",
    async () => {
      const largeMessage = RECORD.message.repeat(1_024);
      const largeRawXml = RECORD.rawXml.repeat(2_048);
      const records = Array.from({ length: 2_048 }, (_, index) => ({
        ...RECORD,
        id: index + 1,
        eventRecordId: index + 1,
        timestampEpoch: index + 1,
        message: largeMessage,
        rawXml: largeRawXml,
      }));
      const minimumSerializedTextBytes =
        records.length * (largeMessage.length + largeRawXml.length);
      expect(minimumSerializedTextBytes).toBeGreaterThan(64 * 1024 * 1024);

      useEvtxStore.setState({
        records,
        channels: [
          {
            name: "Application",
            eventCount: records.length,
            sourceType: { file: { path: "sample.evtx" } },
          },
        ],
        selectedChannels: new Set(["Application"]),
        loadedChannels: new Set(["Application"]),
        sourceMode: "files",
        timeWindow: "all",
      });

      const workspace = render(<EventLogWorkspace />);
      expect(
        screen.getByRole("grid", { name: "Loaded event grid" }),
      ).toBeVisible();

      await waitFor(
        () => {
          const commands = commandNames();
          expect(commands).toContain("evtx_diagnose_analysis_session");
        },
        { timeout: 15_000 },
      );

      const commands = commandNames();
      const appendPayloads = payloadsFor("evtx_append_analysis_chunk");
      const appendRecords = appendPayloads.flatMap((payload) =>
        Array.isArray(payload.records) ? payload.records : [],
      );

      expect.soft(commands).toContain("evtx_create_analysis_session");
      expect.soft(appendPayloads.length).toBeGreaterThan(1);
      expect.soft(commands).toContain("evtx_finalize_analysis_session");
      expect.soft(commands).toContain("evtx_query_analysis_timeline");
      expect.soft(commands).toContain("evtx_diagnose_analysis_session");
      expect.soft(appendRecords).toHaveLength(records.length);
      expect.soft(appendRecords[0]).toMatchObject({
        record: { id: 1 },
        originalSerializedBytes: null,
      });
      expect.soft(appendRecords[appendRecords.length - 1]).toMatchObject({
        record: { id: records.length },
        originalSerializedBytes: null,
      });

      for (const payload of appendPayloads) {
        const chunkRecords = Array.isArray(payload.records)
          ? payload.records
          : [];
        expect.soft(chunkRecords.length).toBeGreaterThan(0);
        expect.soft(chunkRecords.length).toBeLessThanOrEqual(MAX_APPEND_RECORDS);
        expect
          .soft(jsonByteLength(chunkRecords))
          .toBeLessThanOrEqual(MAX_APPEND_RECORD_BYTES);
        expect
          .soft(jsonByteLength(payload))
          .toBeLessThan(MAX_APPEND_ENVELOPE_BYTES);
      }

      expect
        .soft(
          mocks.invoke.mock.calls.some(([, payload]) =>
            payloadContainsCompleteRecordArray(payload, records.length),
          ),
        )
        .toBe(false);

      await act(async () => workspace.unmount());
      expect.soft(commandNames()).toContain("evtx_close_analysis_session");
    },
    30_000,
  );
});
