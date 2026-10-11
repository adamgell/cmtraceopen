/**
 * Which of the events on screen an EVTX subset can be cut from (spec 8.17).
 *
 * `EvtExportLog` copies events out of a live channel or out of an `.evtx` file, so only those
 * records can go into a subset. Everything else the list can hold (lines from a text log, events
 * read from inside an archive, events from a remote machine) is counted and named rather than
 * dropped: an export that quietly holds fewer events than the list shows would read as a complete
 * one, and the operator would have no way to know what is missing.
 *
 * Pure, so the grouping is testable without the dialog.
 */
import type { EvtxSubsetResult, EvtxSubsetSourceRequest } from "../../lib/commands";
import type { EvtxRecord } from "./types";

/** `source_label` the live path stamps on every record read from a local channel. */
const LIVE_SOURCE_LABEL = "Live";
const REMOTE_SOURCE_PREFIX = "Remote:";
/** Joins an archive path to the member inside it, as in `bundle.zip::logs/System.evtx`. */
const ARCHIVE_MEMBER_SEPARATOR = "::";

export type EvtxSubsetSkipReason =
  | "remote"
  | "archive"
  | "textLog"
  | "notEvtx"
  | "noRecordId";

const plural = (count: number, one: string, many = `${one}s`) => (count === 1 ? one : many);

/** One line saying how many records were left out and why, for the dialog's "Not included" list. */
export function describeSkippedRecords({ reason, records }: EvtxSubsetSkipped): string {
  const n = records.toLocaleString();
  switch (reason) {
    case "remote":
      return `${n} ${plural(records, "event")} from a remote machine (remote export is not supported)`;
    case "archive":
      return `${n} ${plural(records, "event")} read from inside an archive (an archive member has no .evtx file of its own)`;
    case "textLog":
      return `${n} text log ${plural(records, "line")} (not Windows events)`;
    case "notEvtx":
      return `${n} ${plural(records, "event")} not read from an .evtx file`;
    case "noRecordId":
      return `${n} ${plural(records, "event")} without an EventRecordID (they cannot be selected by ID)`;
  }
}

/** The order skipped groups are listed in. */
const SKIP_REASON_ORDER: readonly EvtxSubsetSkipReason[] = [
  "remote",
  "archive",
  "textLog",
  "notEvtx",
  "noRecordId",
];

export interface EvtxSubsetSourcePlan extends EvtxSubsetSourceRequest {
  /** Distinct events that will be requested from this source. */
  recordCount: number;
}

export interface EvtxSubsetSkipped {
  reason: EvtxSubsetSkipReason;
  records: number;
}

export interface EvtxSubsetPlan {
  sources: EvtxSubsetSourcePlan[];
  skipped: EvtxSubsetSkipped[];
  /** Records the plan will request, summed over sources. */
  exportableRecords: number;
  skippedRecords: number;
}

/**
 * The decimal `EventRecordID` of a record. The lossless text field wins over the number, because
 * the number is a JavaScript double and cannot hold every u64. Zero with no text is the live
 * path's "the XML had no EventRecordID" default, not an identity.
 */
export function eventRecordIdText(record: EvtxRecord): string | null {
  const text = record.eventRecordIdText;
  if (typeof text === "string" && /^\d+$/.test(text)) return text;
  if (Number.isSafeInteger(record.eventRecordId) && record.eventRecordId > 0) {
    return String(record.eventRecordId);
  }
  return null;
}

type Classification =
  | { kind: "export"; source: EvtxSubsetSourceRequest["kind"]; path: string; id: string }
  | { kind: "skip"; reason: EvtxSubsetSkipReason };

function classify(record: EvtxRecord): Classification {
  if (record.originKind === "log") return { kind: "skip", reason: "textLog" };
  const label = record.sourceLabel;
  if (label.startsWith(REMOTE_SOURCE_PREFIX)) return { kind: "skip", reason: "remote" };
  const id = eventRecordIdText(record);
  if (label === LIVE_SOURCE_LABEL) {
    // The label says "Live", not which channel, so the record's own channel names the source.
    // The live path stamps the channel that was queried, which is the one to export from.
    if (record.channel.length === 0) return { kind: "skip", reason: "notEvtx" };
    return id === null
      ? { kind: "skip", reason: "noRecordId" }
      : { kind: "export", source: "channel", path: record.channel, id };
  }
  if (label.includes(ARCHIVE_MEMBER_SEPARATOR)) return { kind: "skip", reason: "archive" };
  if (!label.toLowerCase().endsWith(".evtx")) return { kind: "skip", reason: "notEvtx" };
  return id === null
    ? { kind: "skip", reason: "noRecordId" }
    : { kind: "export", source: "file", path: label, id };
}

export function planEvtxSubsetSources(records: readonly EvtxRecord[]): EvtxSubsetPlan {
  // Keyed case-insensitively: Windows treats channel names and paths that way, and the backend
  // refuses a request that lists one source twice.
  const groups = new Map<string, { source: EvtxSubsetSourceRequest; ids: Set<string> }>();
  const skippedByReason = new Map<EvtxSubsetSkipReason, number>();

  for (const record of records) {
    const outcome = classify(record);
    if (outcome.kind === "skip") {
      skippedByReason.set(outcome.reason, (skippedByReason.get(outcome.reason) ?? 0) + 1);
      continue;
    }
    const key = `${outcome.source}\u0000${outcome.path.toLowerCase()}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        source: { kind: outcome.source, path: outcome.path, recordIds: [] },
        ids: new Set(),
      };
      groups.set(key, group);
    }
    group.ids.add(outcome.id);
  }

  const sources: EvtxSubsetSourcePlan[] = [...groups.values()]
    .map(({ source, ids }) => {
      const recordIds = [...ids];
      return { ...source, recordIds, recordCount: recordIds.length };
    })
    .sort(
      (a, b) =>
        a.kind.localeCompare(b.kind) || a.path.localeCompare(b.path, undefined, { sensitivity: "base" }),
    );
  const skipped = SKIP_REASON_ORDER
    .filter((reason) => skippedByReason.has(reason))
    .map((reason) => ({ reason, records: skippedByReason.get(reason) ?? 0 }));

  return {
    sources,
    skipped,
    exportableRecords: sources.reduce((sum, source) => sum + source.recordCount, 0),
    skippedRecords: skipped.reduce((sum, entry) => sum + entry.records, 0),
  };
}

/** The one-line outcome for the view bar's status line and the top of the result list. */
export function summarizeEvtxSubsetResult(result: EvtxSubsetResult): string {
  const total = result.files.length;
  const exported = result.files.filter((file) => file.status === "exported");
  const failed = total - exported.length;
  if (exported.length === 0) {
    return `Nothing was exported: ${total} EVTX subset ${plural(total, "file")} failed.`;
  }
  const verified = exported.every((file) => file.exportedRecords !== null);
  const events = exported.reduce(
    (sum, file) => sum + (file.exportedRecords ?? file.requestedRecords),
    0,
  );
  const eventText = `${events.toLocaleString()} ${plural(events, "event")}${
    verified ? "" : ", counts not verified"
  }`;
  if (failed === 0) {
    return `Exported ${exported.length} EVTX subset ${plural(exported.length, "file")} (${eventText}).`;
  }
  return `Exported ${exported.length} of ${total} EVTX subset files (${eventText}); ${failed} failed.`;
}
