import { describe, expect, it, vi } from "vitest";
import {
  streamEventLogExport,
  type EventLogExportTransport,
} from "./event-export-session";
import { MAX_EXPORT_CHUNK_RECORDS } from "./evtx-export";
import type { EvtxRecord } from "./types";

const record = (id: number): EvtxRecord => ({
  id,
  eventRecordId: id,
  timestamp: "2026-08-09T12:00:00Z",
  timestampEpoch: id,
  provider: "Provider",
  channel: "Application",
  eventId: 326,
  level: "Information",
  computer: "HOST",
  message: `event-${id}`,
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "events.evtx",
});

function transport(overrides: Partial<EventLogExportTransport> = {}): EventLogExportTransport {
  let records = 0;
  let bytes = 0;
  let expected = 0;
  return {
    create: vi.fn(
      async (
        _format: string,
        _destination: string,
        _sourcePaths: string[],
        expectedRecords: number,
      ) => {
        expected = expectedRecords;
        return {
          sessionId: "export-1",
          nextSequence: 0,
          receivedRecords: 0,
          receivedBytes: 0,
          expectedRecords,
        };
      },
    ),
    append: vi.fn(async (_sessionId: string, sequence: number, payloadBase64: string) => {
      const payload = atob(payloadBase64);
      records += payload.split("\n").length - 1;
      bytes += payload.length;
      return {
        sessionId: "export-1",
        nextSequence: sequence + 1,
        receivedRecords: records,
        receivedBytes: bytes,
        expectedRecords: expected,
      };
    }),
    finalize: vi.fn(async () => ({ sessionId: "export-1", records, bytes: 4096 })),
    close: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe("event export session", () => {
  it("creates, appends, and finalizes a backend-owned session", async () => {
    const backend = transport();
    const records = Array.from(
      { length: MAX_EXPORT_CHUNK_RECORDS + 1 },
      (_, index) => record(index + 1)
    );

    await expect(
      streamEventLogExport(
        {
          records,
          format: "json",
          destination: "C:/exports/events.json",
          sourcePaths: ["C:/logs/source.evtx"],
        },
        backend
      )
    ).resolves.toEqual({
      sessionId: "export-1",
      records: MAX_EXPORT_CHUNK_RECORDS + 1,
      bytes: 4096,
    });

    expect(backend.create).toHaveBeenCalledOnce();
    expect(backend.append).toHaveBeenCalledTimes(2);
    expect(backend.finalize).toHaveBeenCalledWith("export-1");
    expect(backend.close).not.toHaveBeenCalled();
  });

  it.each(["append", "finalize"] as const)("closes backend staging when %s fails", async (step) => {
    const backend = transport({
      [step]: vi.fn().mockRejectedValue(new Error(`${step} failed`)),
    });

    await expect(
      streamEventLogExport(
        {
          records: [record(1)],
          format: "json",
          destination: "C:/exports/events.json",
          sourcePaths: [],
        },
        backend
      )
    ).rejects.toThrow(`${step} failed`);

    expect(backend.close).toHaveBeenCalledWith("export-1");
  });

  it("rejects a backend record-count mismatch and cleans up", async () => {
    const backend = transport({
      finalize: vi.fn().mockResolvedValue({
        sessionId: "export-1",
        records: 0,
        bytes: 4096,
      }),
    });

    await expect(
      streamEventLogExport(
        {
          records: [record(1)],
          format: "json",
          destination: "C:/exports/events.json",
          sourcePaths: [],
        },
        backend
      )
    ).rejects.toThrow("exported 0 of 1 events");
    expect(backend.close).toHaveBeenCalledWith("export-1");
  });

  it("does not finalize when an append status disagrees with the sent stream", async () => {
    const backend = transport({
      append: vi.fn().mockResolvedValue({
        sessionId: "export-1",
        nextSequence: 1,
        receivedRecords: 0,
        receivedBytes: 0,
        expectedRecords: 1,
      }),
    });

    await expect(
      streamEventLogExport(
        {
          records: [record(1)],
          format: "json",
          destination: "C:/exports/events.json",
          sourcePaths: [],
        },
        backend
      )
    ).rejects.toThrow("did not acknowledge the complete export stream");
    expect(backend.finalize).not.toHaveBeenCalled();
    expect(backend.close).toHaveBeenCalledWith("export-1");
  });

  it("closes an in-flight session when the operator cancels", async () => {
    const controller = new AbortController();
    let rejectAppend!: (error: Error) => void;
    const appendResult = new Promise<never>((_resolve, reject) => {
      rejectAppend = reject;
    });
    const backend = transport({ append: vi.fn(() => appendResult) });
    const pending = streamEventLogExport(
      {
        records: [record(1)],
        format: "json",
        destination: "C:/exports/events.json",
        sourcePaths: [],
        signal: controller.signal,
      },
      backend,
    );
    await vi.waitFor(() => expect(backend.append).toHaveBeenCalledOnce());

    controller.abort();
    await vi.waitFor(() => expect(backend.close).toHaveBeenCalledWith("export-1"));
    rejectAppend(new Error("backend cancellation interrupted append"));

    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(backend.finalize).not.toHaveBeenCalled();
  });

  it("treats a successful finalize as authoritative when cancellation loses the race", async () => {
    const controller = new AbortController();
    let resolveFinalize!: (result: {
      sessionId: string;
      records: number;
      bytes: number;
    }) => void;
    const finalizeResult = new Promise<Parameters<typeof resolveFinalize>[0]>((resolve) => {
      resolveFinalize = resolve;
    });
    const backend = transport({ finalize: vi.fn(() => finalizeResult) });
    const pending = streamEventLogExport(
      {
        records: [record(1)],
        format: "json",
        destination: "C:/exports/events.json",
        sourcePaths: [],
        signal: controller.signal,
      },
      backend,
    );
    await vi.waitFor(() => expect(backend.finalize).toHaveBeenCalledOnce());

    controller.abort();
    await vi.waitFor(() => expect(backend.close).toHaveBeenCalledWith("export-1"));
    resolveFinalize({ sessionId: "export-1", records: 1, bytes: 4096 });

    await expect(pending).resolves.toEqual({
      sessionId: "export-1",
      records: 1,
      bytes: 4096,
    });
  });
});
