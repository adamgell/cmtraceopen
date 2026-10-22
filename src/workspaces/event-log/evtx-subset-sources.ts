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
import type {
  EvtxSubsetFileResult,
  EvtxSubsetResult,
  EvtxSubsetSourceRequest,
} from "../../lib/commands";
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
  | "noRecordId"
  | "idTooLarge";

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
    case "idTooLarge":
      return `${n} ${plural(records, "event")} with an EventRecordID above ${MAX_EXACT_RECORD_ID} (too large for the query to match exactly)`;
  }
}

/** The order skipped groups are listed in. */
const SKIP_REASON_ORDER: readonly EvtxSubsetSkipReason[] = [
  "remote",
  "archive",
  "textLog",
  "notEvtx",
  "noRecordId",
  "idTooLarge",
];

export interface EvtxSubsetSourcePlan extends EvtxSubsetSourceRequest {
  /** Distinct events (machine, source channel and EventRecordID) requested from this source. */
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
 * The decimal `EventRecordID` of a record, by the same rule the store sorts and identifies records
 * with: lossless text when it is a non-zero decimal (leading zeros stripped), else the number when
 * the record carries no text. All-zero text, and zero with no text, are the live path's "the XML
 * had no EventRecordID" default, not an identity.
 */
export function eventRecordIdText(record: EvtxRecord): string | null {
  const rawText = record.eventRecordIdText?.trim() ?? "";
  if (/^\d+$/.test(rawText) && !/^0+$/.test(rawText)) {
    return rawText.replace(/^0+(?=\d)/, "");
  }
  if (!rawText && Number.isSafeInteger(record.eventRecordId) && record.eventRecordId > 0) {
    return String(record.eventRecordId);
  }
  return null;
}

/**
 * The largest EventRecordID the Event Log query language can match exactly: XPath numbers are
 * IEEE doubles. The backend refuses a source that asks for a larger one, so such an event is set
 * aside here and listed, instead of failing every other event of its source.
 */
const MAX_EXACT_RECORD_ID = "9007199254740991";

function exceedsExactRange(id: string): boolean {
  return BigInt(id) > BigInt(MAX_EXACT_RECORD_ID);
}

/** What the file parser writes when an event's System block names no computer. */
const UNKNOWN_COMPUTER = "Unknown";

/**
 * The machine an event was logged on, or null when it names none. The machine is part of an
 * event's identity: a log that collects events can hold the same EventRecordID from two machines.
 */
function computerOf(record: EvtxRecord): string | null {
  const name = record.computer.trim();
  return name === "" || name === UNKNOWN_COMPUTER ? null : record.computer;
}

/**
 * The log an event was written to, by its own `System/Channel`, or null when it names none. This is
 * not `record.channel`: a live read stamps the log that was queried there, which for a collector
 * such as ForwardedEvents is the collector, not where the event came from. The source log is the
 * third part of an event's identity, because one machine can forward two logs whose
 * EventRecordIDs coincide.
 */
function sourceChannelOf(record: EvtxRecord): string | null {
  const name = record.eventChannel;
  return name == null || name.trim() === "" ? null : name;
}

/**
 * What identifies an event beside its EventRecordID. The backend's `EventOrigin` is the same
 * definition: it names these two parts in the query and compares them when it reads the file back.
 */
function originKey(computer: string | null, channel: string | null): string {
  return JSON.stringify([computer, channel]);
}

type Classification =
  | {
      kind: "export";
      source: EvtxSubsetSourceRequest["kind"];
      path: string;
      computer: string | null;
      channel: string | null;
      id: string;
    }
  | { kind: "skip"; reason: EvtxSubsetSkipReason };

function classify(record: EvtxRecord): Classification {
  if (record.originKind === "log") return { kind: "skip", reason: "textLog" };
  const label = record.sourceLabel;
  if (label.startsWith(REMOTE_SOURCE_PREFIX)) return { kind: "skip", reason: "remote" };
  const id = eventRecordIdText(record);
  const computer = computerOf(record);
  const channel = sourceChannelOf(record);
  if (label === LIVE_SOURCE_LABEL) {
    // The label says "Live", not which channel, so the record's own channel names the source.
    // The live path stamps the channel that was queried, which is the one to export from.
    if (record.channel.length === 0) return { kind: "skip", reason: "notEvtx" };
    if (id === null) return { kind: "skip", reason: "noRecordId" };
    if (exceedsExactRange(id)) return { kind: "skip", reason: "idTooLarge" };
    return { kind: "export", source: "channel", path: record.channel, computer, channel, id };
  }
  if (label.includes(ARCHIVE_MEMBER_SEPARATOR)) return { kind: "skip", reason: "archive" };
  if (!label.toLowerCase().endsWith(".evtx")) return { kind: "skip", reason: "notEvtx" };
  if (id === null) return { kind: "skip", reason: "noRecordId" };
  if (exceedsExactRange(id)) return { kind: "skip", reason: "idTooLarge" };
  return { kind: "export", source: "file", path: label, computer, channel, id };
}

export function planEvtxSubsetSources(records: readonly EvtxRecord[]): EvtxSubsetPlan {
  // Sources are keyed case-insensitively: Windows treats channel names and paths that way, and the
  // backend refuses a request that lists one source twice. Machines and source channels are kept
  // exactly as logged, because the query compares them exactly.
  const groups = new Map<
    string,
    {
      kind: EvtxSubsetSourceRequest["kind"];
      path: string;
      byOrigin: Map<
        string,
        { computer: string | null; channel: string | null; ids: Set<string> }
      >;
    }
  >();
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
      group = { kind: outcome.source, path: outcome.path, byOrigin: new Map() };
      groups.set(key, group);
    }
    const origin = originKey(outcome.computer, outcome.channel);
    let events = group.byOrigin.get(origin);
    if (!events) {
      events = { computer: outcome.computer, channel: outcome.channel, ids: new Set() };
      group.byOrigin.set(origin, events);
    }
    events.ids.add(outcome.id);
  }

  const sources: EvtxSubsetSourcePlan[] = [...groups.values()]
    .map(({ kind, path, byOrigin }) => {
      const recordGroups = [...byOrigin.values()].map(({ computer, channel, ids }) => ({
        computer,
        channel,
        recordIds: [...ids],
      }));
      return {
        kind,
        path,
        recordGroups,
        recordCount: recordGroups.reduce((sum, group) => sum + group.recordIds.length, 0),
      };
    })
    .sort(
      (a, b) =>
        a.kind.localeCompare(b.kind) ||
        a.path.localeCompare(b.path, undefined, { sensitivity: "base" }),
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

/**
 * Whether a written file was checked against the request and found to differ from it: an event
 * that was asked for is missing, or one that was not asked for is there. A file that could not be
 * read back is unverified, which is a different state and is stated as such.
 */
export function fileDiffersFromRequest(file: EvtxSubsetFileResult): boolean {
  return (
    file.status === "exported" &&
    ((file.missing?.count ?? 0) > 0 || (file.unrequested?.count ?? 0) > 0)
  );
}

/**
 * The one-line outcome, for the done heading, the polite announcement and the view bar's status
 * line (the last stays on screen after the dialog is gone). It must not read as a complete export
 * of the view when it is not, so it says how many events were left out of the plan, and how many
 * files were found to differ from the request.
 */
export function summarizeEvtxSubsetResult(result: EvtxSubsetResult, notIncluded = 0): string {
  const total = result.files.length;
  const exported = result.files.filter((file) => file.status === "exported");
  const failed = total - exported.length;
  const differing = result.files.filter(fileDiffersFromRequest).length;
  const notes: string[] = [];
  if (exported.length > 0 && failed > 0) notes.push(`${failed} failed`);
  if (notIncluded > 0) notes.push(`${notIncluded.toLocaleString()} not included`);
  if (differing > 0) {
    notes.push(`${differing} ${plural(differing, "file differs", "files differ")} from the request`);
  }
  const suffix = notes.map((note) => `; ${note}`).join("");

  if (exported.length === 0) {
    return `Nothing was exported: ${total} EVTX subset ${plural(total, "file")} failed${suffix}.`;
  }
  const verified = exported.every((file) => file.exportedRecords !== null);
  const events = exported.reduce(
    (sum, file) => sum + (file.exportedRecords ?? file.requestedRecords),
    0,
  );
  const eventText = `${events.toLocaleString()} ${plural(events, "event")}${
    verified ? "" : ", counts not verified"
  }`;
  const files =
    failed === 0
      ? `${exported.length} EVTX subset ${plural(exported.length, "file")}`
      : `${exported.length} of ${total} EVTX subset files`;
  return `Exported ${files} (${eventText})${suffix}.`;
}
