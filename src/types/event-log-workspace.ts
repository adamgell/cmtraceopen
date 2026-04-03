export interface EvtxRecord {
  id: number;
  eventRecordId: number;
  timestamp: string;
  timestampEpoch: number;
  provider: string;
  channel: string;
  eventId: number;
  level: EvtxLevel;
  computer: string;
  message: string;
  eventData: EvtxField[];
  rawXml: string;
  sourceLabel: string;
}

export interface EvtxField {
  name: string;
  value: string;
}

export type EvtxLevel = "Critical" | "Error" | "Warning" | "Information" | "Verbose";

export interface EvtxChannelInfo {
  name: string;
  eventCount: number;
  sourceType: "live" | { file: { path: string } };
}

export interface EvtxParseResult {
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  totalRecords: number;
  parseErrors: number;
  errorMessages: string[];
}
