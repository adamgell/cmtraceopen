import {
  appendEventLogExportChunk,
  closeEventLogExportSession,
  createEventLogExportSession,
  finalizeEventLogExportSession,
  type EventLogExportResult,
  type EventLogExportSessionStatus,
} from "../../lib/commands";
import {
  exportPayloadChunks,
  type EvtxExportFormatValue,
} from "./evtx-export";
import type { EvtxRecord } from "./types";

export interface EventLogExportTransport {
  create(
    format: EvtxExportFormatValue,
    destination: string,
    sourcePaths: string[],
    expectedRecords: number,
  ): Promise<EventLogExportSessionStatus>;
  append(
    sessionId: string,
    sequence: number,
    payloadBase64: string,
  ): Promise<EventLogExportSessionStatus>;
  finalize(sessionId: string): Promise<EventLogExportResult>;
  close(sessionId: string): Promise<void>;
}

const defaultTransport: EventLogExportTransport = {
  create: createEventLogExportSession,
  append: appendEventLogExportChunk,
  finalize: finalizeEventLogExportSession,
  close: closeEventLogExportSession,
};

export interface EventLogExportRequest {
  records: readonly EvtxRecord[];
  format: EvtxExportFormatValue;
  destination: string;
  sourcePaths: string[];
  signal?: AbortSignal;
  onProgress?: (receivedRecords: number, expectedRecords: number) => void;
}

function cancellationError(): Error {
  const error = new Error("Export cancelled");
  error.name = "AbortError";
  return error;
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw cancellationError();
}

function assertStatus(
  status: EventLogExportSessionStatus,
  sessionId: string,
  nextSequence: number,
  receivedRecords: number,
  receivedBytes: number,
  expectedRecords: number,
): void {
  if (
    status.sessionId !== sessionId ||
    status.nextSequence !== nextSequence ||
    status.receivedRecords !== receivedRecords ||
    status.receivedBytes !== receivedBytes ||
    status.expectedRecords !== expectedRecords
  ) {
    throw new Error("The export writer did not acknowledge the complete export stream.");
  }
}

/** Sends one bounded fragment at a time and always closes unfinished backend staging. */
export async function streamEventLogExport(
  request: EventLogExportRequest,
  transport: EventLogExportTransport = defaultTransport,
): Promise<EventLogExportResult> {
  throwIfCancelled(request.signal);
  const expectedRecords = request.records.length;
  let sessionId: string | null = null;
  let completed = false;
  let abortClose: Promise<void> | null = null;

  const closeForAbort = () => {
    if (sessionId !== null && abortClose === null) {
      abortClose = transport.close(sessionId).catch(() => undefined);
    }
  };
  request.signal?.addEventListener("abort", closeForAbort, { once: true });

  try {
    const created = await transport.create(
      request.format,
      request.destination,
      request.sourcePaths,
      expectedRecords,
    );
    sessionId = created.sessionId;
    assertStatus(created, sessionId, 0, 0, 0, expectedRecords);
    throwIfCancelled(request.signal);

    let nextSequence = 0;
    let receivedRecords = 0;
    let receivedBytes = 0;
    for (const chunk of exportPayloadChunks(request.format, request.records)) {
      throwIfCancelled(request.signal);
      const status = await transport.append(
        sessionId,
        nextSequence,
        chunk.payloadBase64,
      );
      nextSequence += 1;
      receivedRecords += chunk.completedRecords;
      receivedBytes += chunk.decodedBytes;
      assertStatus(
        status,
        sessionId,
        nextSequence,
        receivedRecords,
        receivedBytes,
        expectedRecords,
      );
      request.onProgress?.(receivedRecords, expectedRecords);
    }
    throwIfCancelled(request.signal);

    const result = await transport.finalize(sessionId);
    if (result.sessionId !== sessionId) {
      throw new Error("The export writer returned statistics for another export session.");
    }
    if (result.records !== expectedRecords) {
      throw new Error(
        `The export writer exported ${result.records} of ${expectedRecords} events.`,
      );
    }
    completed = true;
    sessionId = null;
    return result;
  } catch (error) {
    // Closing an in-flight backend call commonly rejects with a transport/backend error. The
    // operator still asked to cancel, so keep that outcome stable for the UI regardless of which
    // side of the race reports first.
    if (request.signal?.aborted) throw cancellationError();
    throw error;
  } finally {
    request.signal?.removeEventListener("abort", closeForAbort);
    if (abortClose !== null) await abortClose;
    if (!completed && sessionId !== null) {
      await transport.close(sessionId).catch(() => undefined);
    }
  }
}
