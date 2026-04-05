import { useMemo } from "react";
import { parseDisplayDateTimeValue } from "../../lib/date-time-format";
import { useIntuneStore } from "./intune-store";
import type {
  DownloadStat,
  IntuneEvent,
  IntuneEventType,
  IntuneSummary,
  IntuneTimeWindowPreset,
} from "./types";

export function useTimeWindowFilter() {
  const events = useIntuneStore((s) => s.events);
  const downloads = useIntuneStore((s) => s.downloads);
  const timeWindow = useIntuneStore((s) => s.timeWindow);

  const timeWindowAnchor = useMemo(
    () => getLatestActivityTimestamp(events, downloads),
    [downloads, events]
  );
  const filteredEventsByTime = useMemo(
    () => filterEventsByTimeWindow(events, timeWindow, timeWindowAnchor),
    [events, timeWindow, timeWindowAnchor]
  );
  const filteredDownloadsByTime = useMemo(
    () => filterDownloadsByTimeWindow(downloads, timeWindow, timeWindowAnchor),
    [downloads, timeWindow, timeWindowAnchor]
  );
  const filteredSummary = useMemo(
    () => buildWindowedSummary(filteredEventsByTime, filteredDownloadsByTime),
    [filteredDownloadsByTime, filteredEventsByTime]
  );
  const timeWindowLabel = getTimeWindowLabel(timeWindow);
  const isWindowFiltered = timeWindow !== "all";

  return {
    filteredEventsByTime,
    filteredDownloadsByTime,
    filteredSummary,
    timeWindowLabel,
    isWindowFiltered,
  };
}

export function getTimeWindowLabel(preset: IntuneTimeWindowPreset): string {
  switch (preset) {
    case "last-hour":
      return "Last Hour";
    case "last-6-hours":
      return "Last 6 Hours";
    case "last-day":
      return "Last Day";
    case "last-7-days":
      return "Last 7 Days";
    case "all":
    default:
      return "All Activity";
  }
}

function getLatestActivityTimestamp(
  events: IntuneEvent[],
  downloads: DownloadStat[]
): number | null {
  let latest: number | null = null;

  for (const event of events) {
    const candidate = parseIntuneTimestamp(event.startTime) ?? parseIntuneTimestamp(event.endTime);
    if (candidate != null && (latest == null || candidate > latest)) {
      latest = candidate;
    }
  }

  for (const download of downloads) {
    const candidate = parseIntuneTimestamp(download.timestamp);
    if (candidate != null && (latest == null || candidate > latest)) {
      latest = candidate;
    }
  }

  return latest;
}

function filterEventsByTimeWindow(
  events: IntuneEvent[],
  preset: IntuneTimeWindowPreset,
  anchorTimestamp: number | null
): IntuneEvent[] {
  const windowMs = getTimeWindowDurationMs(preset);
  if (windowMs == null || anchorTimestamp == null) {
    return events;
  }

  const threshold = anchorTimestamp - windowMs;
  return events.filter((event) => {
    const timestamp = parseIntuneTimestamp(event.startTime) ?? parseIntuneTimestamp(event.endTime);
    return timestamp != null && timestamp >= threshold;
  });
}

function filterDownloadsByTimeWindow(
  downloads: DownloadStat[],
  preset: IntuneTimeWindowPreset,
  anchorTimestamp: number | null
): DownloadStat[] {
  const windowMs = getTimeWindowDurationMs(preset);
  if (windowMs == null || anchorTimestamp == null) {
    return downloads;
  }

  const threshold = anchorTimestamp - windowMs;
  return downloads.filter((download) => {
    const timestamp = parseIntuneTimestamp(download.timestamp);
    return timestamp != null && timestamp >= threshold;
  });
}

export function buildWindowedSummary(
  events: IntuneEvent[],
  downloads: DownloadStat[]
): IntuneSummary {
  const summaryEvents = events.filter((event) => isSummarySignalEvent(event));
  let win32Apps = 0;
  let wingetApps = 0;
  let scripts = 0;
  let remediations = 0;
  let succeeded = 0;
  let failed = 0;
  let inProgress = 0;
  let pending = 0;
  let timedOut = 0;
  let failedScripts = 0;

  for (const event of summaryEvents) {
    switch (event.eventType) {
      case "Win32App":
        win32Apps += 1;
        break;
      case "WinGetApp":
        wingetApps += 1;
        break;
      case "PowerShellScript":
        scripts += 1;
        break;
      case "Remediation":
        remediations += 1;
        break;
      default:
        break;
    }

    switch (event.status) {
      case "Success":
        succeeded += 1;
        break;
      case "Failed":
        failed += 1;
        if (event.eventType === "PowerShellScript") {
          failedScripts += 1;
        }
        break;
      case "InProgress":
        inProgress += 1;
        break;
      case "Pending":
        pending += 1;
        break;
      case "Timeout":
        timedOut += 1;
        failed += 1;
        if (event.eventType === "PowerShellScript") {
          failedScripts += 1;
        }
        break;
      default:
        break;
    }
  }

  const successfulDownloads = downloads.filter((download) => download.success).length;
  const failedDownloads = downloads.length - successfulDownloads;

  return {
    totalEvents: summaryEvents.length,
    win32Apps,
    wingetApps,
    scripts,
    remediations,
    succeeded,
    failed,
    inProgress,
    pending,
    timedOut,
    totalDownloads: downloads.length,
    successfulDownloads,
    failedDownloads,
    failedScripts,
    logTimeSpan: calculateEventTimeSpan(events),
  };
}

function isSummarySignalEvent(event: IntuneEvent): boolean {
  switch (event.eventType) {
    case "Win32App":
    case "WinGetApp":
    case "PowerShellScript":
    case "Remediation":
    case "PolicyEvaluation":
    case "ContentDownload":
    case "Esp":
    case "SyncSession":
      return true;
    case "Other":
      return event.status === "Failed"
        || event.status === "Timeout"
        || event.status === "Pending"
        || event.status === "InProgress";
    default:
      return false;
  }
}

function calculateEventTimeSpan(events: IntuneEvent[]): string | null {
  let earliest: number | null = null;
  let latest: number | null = null;

  for (const event of events) {
    for (const rawTimestamp of [event.startTime, event.endTime]) {
      const timestamp = parseIntuneTimestamp(rawTimestamp);
      if (timestamp == null) {
        continue;
      }

      if (earliest == null || timestamp < earliest) {
        earliest = timestamp;
      }
      if (latest == null || timestamp > latest) {
        latest = timestamp;
      }
    }
  }

  if (earliest == null || latest == null) {
    return null;
  }

  const totalSeconds = Math.max(0, Math.round((latest - earliest) / 1000));
  if (totalSeconds < 60) {
    return `${totalSeconds}s`;
  }

  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }

  return `${minutes}m ${seconds}s`;
}

function getTimeWindowDurationMs(preset: IntuneTimeWindowPreset): number | null {
  switch (preset) {
    case "last-hour":
      return 60 * 60 * 1000;
    case "last-6-hours":
      return 6 * 60 * 60 * 1000;
    case "last-day":
      return 24 * 60 * 60 * 1000;
    case "last-7-days":
      return 7 * 24 * 60 * 60 * 1000;
    case "all":
    default:
      return null;
  }
}

function parseIntuneTimestamp(value: string | null | undefined): number | null {
  return parseDisplayDateTimeValue(value);
}

export function formatEventTypeLabel(eventType: IntuneEventType): string {
  switch (eventType) {
    case "Win32App":
      return "Win32 app";
    case "WinGetApp":
      return "WinGet app";
    case "PowerShellScript":
      return "PowerShell script";
    case "PolicyEvaluation":
      return "Policy evaluation";
    case "ContentDownload":
      return "Content download";
    default:
      return eventType;
  }
}
