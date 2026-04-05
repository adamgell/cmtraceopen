import type { IntuneEvent, DownloadStat } from "../workspaces/intune/types";
import { STATUS_RANK } from "../workspaces/intune/types";
import type { IntuneSortField, DownloadSortField } from "../workspaces/intune/intune-store";

export type SortDirection = "asc" | "desc";

/**
 * Compare two IntuneEvent records by the given sort field and direction.
 * Null values sort last regardless of direction.
 */
export function compareEvents(
  a: IntuneEvent,
  b: IntuneEvent,
  field: IntuneSortField,
  direction: SortDirection,
): number {
  switch (field) {
    case "time": {
      const aTime = a.startTimeEpoch;
      const bTime = b.startTimeEpoch;
      if (aTime == null && bTime != null) return 1;
      if (aTime != null && bTime == null) return -1;
      if (aTime == null && bTime == null) return 0;
      return direction === "asc" ? aTime! - bTime! : bTime! - aTime!;
    }
    case "name": {
      const cmp = a.name.localeCompare(b.name);
      return direction === "asc" ? cmp : -cmp;
    }
    case "type": {
      const cmp = a.eventType.localeCompare(b.eventType);
      return direction === "asc" ? cmp : -cmp;
    }
    case "status": {
      const cmp = (STATUS_RANK[a.status] ?? 5) - (STATUS_RANK[b.status] ?? 5);
      return direction === "asc" ? cmp : -cmp;
    }
    case "duration": {
      const aDur = a.durationSecs;
      const bDur = b.durationSecs;
      if (aDur == null && bDur != null) return 1;
      if (aDur != null && bDur == null) return -1;
      if (aDur == null && bDur == null) return 0;
      return direction === "asc" ? aDur! - bDur! : bDur! - aDur!;
    }
    default:
      return 0;
  }
}

/**
 * Compare two DownloadStat records by the given sort field and direction.
 * Null values sort last regardless of direction.
 */
export function compareDownloads(
  a: DownloadStat,
  b: DownloadStat,
  field: DownloadSortField,
  direction: SortDirection,
): number {
  switch (field) {
    case "name": {
      const cmp = a.name.localeCompare(b.name);
      return direction === "asc" ? cmp : -cmp;
    }
    case "size": {
      const cmp = a.sizeBytes - b.sizeBytes;
      return direction === "asc" ? cmp : -cmp;
    }
    case "speed": {
      const cmp = a.speedBps - b.speedBps;
      return direction === "asc" ? cmp : -cmp;
    }
    case "doPercentage": {
      const cmp = a.doPercentage - b.doPercentage;
      return direction === "asc" ? cmp : -cmp;
    }
    case "duration": {
      const cmp = a.durationSecs - b.durationSecs;
      return direction === "asc" ? cmp : -cmp;
    }
    case "timestamp": {
      const aTime = a.timestampEpoch;
      const bTime = b.timestampEpoch;
      if (aTime == null && bTime != null) return 1;
      if (aTime != null && bTime == null) return -1;
      if (aTime == null && bTime == null) return 0;
      return direction === "asc" ? aTime! - bTime! : bTime! - aTime!;
    }
    default:
      return 0;
  }
}
