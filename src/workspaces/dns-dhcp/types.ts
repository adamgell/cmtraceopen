import type { LogEntry, LogFormat } from "../../types/log";

export interface SourceFile {
  path: string;
  fileName: string;
  format: LogFormat;
  entryCount: number;
  enabled: boolean;
}

export interface Device {
  ip: string;
  hostname: string | null;
  mac: string | null;
  isEnriched: boolean;

  totalQueries: number;
  nxdomainCount: number;
  servfailCount: number;
  firstSeen: number;
  lastSeen: number;

  dhcpEntries: LogEntry[];
  dnsEntries: LogEntry[];
  /** All entries for this device (dns + dhcp + audit), sorted by timestamp. */
  allEntries: LogEntry[];
}
