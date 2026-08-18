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
export function exportPayload(
  format: EvtxExportFormat["value"],
  records: readonly EvtxRecord[]
): EvtxRecord[] {
  if (format !== "csv" && format !== "tsv" && format !== "html") return [...records];
  return records.map(({ rawXml: _rawXml, eventData: _eventData, ...rest }) => rest as EvtxRecord);
}

export function isValidExportByteCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
