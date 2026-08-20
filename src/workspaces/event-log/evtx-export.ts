import type { EvtxRecord } from "./types";

export const EVTX_EXPORT_FORMATS = [
  { value: "csv", label: "CSV", extension: "csv" },
  { value: "tsv", label: "TSV", extension: "tsv" },
  { value: "json", label: "JSON", extension: "json" },
  { value: "xml", label: "Event XML", extension: "xml" },
  { value: "html", label: "HTML", extension: "html" },
  { value: "rawXml", label: "Raw Event XML", extension: "xml" },
] as const;

export type EvtxExportFormat = (typeof EVTX_EXPORT_FORMATS)[number];

/**
 * Raw XML and event data dominate the IPC payload but are not read by delimited
 * or HTML writers. Keep the full normalized record only for lossless formats.
 */

type EvtxReducedRecord = Omit<EvtxRecord, "rawXml" | "eventData">;

const REDUCED_EXPORT_FORMATS = ["csv", "tsv", "html"] as const;
type EvtxReducedFormat = (typeof REDUCED_EXPORT_FORMATS)[number];

type EvtxLosslessFormat = Exclude<EvtxExportFormat["value"], EvtxReducedFormat>;

export function exportPayload(
  format: EvtxReducedFormat,
  records: readonly EvtxRecord[]
): EvtxReducedRecord[];

export function exportPayload(
  format: EvtxLosslessFormat,
  records: readonly EvtxRecord[]
): EvtxRecord[];

export function exportPayload(
  format: EvtxExportFormat["value"],
  records: readonly EvtxRecord[]
): EvtxRecord[] | EvtxReducedRecord[];

export function exportPayload(
  format: EvtxExportFormat["value"],
  records: readonly EvtxRecord[]
): EvtxRecord[] | EvtxReducedRecord[] {
  if (!REDUCED_EXPORT_FORMATS.includes(format as EvtxReducedFormat)) return [...records];
  return records.map(({ rawXml: _rawXml, eventData: _eventData, ...rest }) => rest);
}

export function isValidExportByteCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
