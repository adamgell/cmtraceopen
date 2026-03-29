import { getSystemDateTimePreferences, type SystemDateTimePreferences } from "./commands";
import type { LogEntry } from "../types/log";

type DateLikeValue = Date | number | string | null | undefined;

const DEFAULT_AM_DESIGNATOR = "AM";
const DEFAULT_PM_DESIGNATOR = "PM";

const fallbackDateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "short",
  timeStyle: "medium",
});

const fallbackTimeFormatter = new Intl.DateTimeFormat(undefined, {
  timeStyle: "medium",
});

let cachedPreferences: SystemDateTimePreferences | null = null;

export async function initializeDateTimeFormatting(): Promise<void> {
  try {
    cachedPreferences = await getSystemDateTimePreferences();
  } catch (error) {
    console.warn("[date-time-format] failed to load system date/time preferences", {
      error,
    });
    cachedPreferences = null;
  }
}

export async function refreshDateTimeFormatting(): Promise<void> {
  try {
    cachedPreferences = await getSystemDateTimePreferences();
  } catch {
    // Keep existing cached preferences on refresh failure
  }
}

export function formatDisplayDateTime(value: DateLikeValue): string | null {
  const parsed = parseDisplayDateTime(value);
  if (!parsed) {
    return null;
  }

  if (!cachedPreferences) {
    return fallbackDateTimeFormatter.format(parsed);
  }

  return formatWithWindowsPattern(
    parsed,
    `${cachedPreferences.datePattern} ${cachedPreferences.timePattern}`.trim(),
    cachedPreferences
  );
}

export function formatDisplayTime(value: DateLikeValue): string | null {
  const parsed = parseDisplayDateTime(value);
  if (!parsed) {
    return null;
  }

  if (!cachedPreferences) {
    return fallbackTimeFormatter.format(parsed);
  }

  return formatWithWindowsPattern(parsed, cachedPreferences.timePattern, cachedPreferences);
}

export function formatLogEntryTimestamp(entry: Pick<LogEntry, "timestamp" | "timestampDisplay">): string | null {
  return formatDisplayDateTime(entry.timestampDisplay ?? entry.timestamp);
}

export function parseDisplayDateTime(value: DateLikeValue): Date | null {
  if (value == null) {
    return null;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === "number") {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  const utcNormalized = /^\d{4}-\d{2}-\d{2} /.test(trimmed) && trimmed.endsWith(" UTC")
    ? `${trimmed.slice(0, -4).replace(" ", "T")}Z`
    : trimmed;

  const nativeParsed = new Date(utcNormalized);
  if (!Number.isNaN(nativeParsed.getTime())) {
    return nativeParsed;
  }

  return parseWindowsLikeTimestamp(trimmed);
}

export function parseDisplayDateTimeValue(value: DateLikeValue): number | null {
  return parseDisplayDateTime(value)?.getTime() ?? null;
}

function parseWindowsLikeTimestamp(value: string): Date | null {
  const monthFirst = value.match(/^(\d{1,2})-(\d{1,2})-(\d{4})[ T](\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?$/);
  if (monthFirst) {
    return buildLocalDate(
      Number.parseInt(monthFirst[3], 10),
      Number.parseInt(monthFirst[1], 10),
      Number.parseInt(monthFirst[2], 10),
      Number.parseInt(monthFirst[4], 10),
      Number.parseInt(monthFirst[5], 10),
      Number.parseInt(monthFirst[6], 10),
      monthFirst[7]
    );
  }

  const yearFirst = value.match(/^(\d{4})[-\/](\d{1,2})[-\/](\d{1,2})[ T](\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?$/);
  if (!yearFirst) {
    return null;
  }

  return buildLocalDate(
    Number.parseInt(yearFirst[1], 10),
    Number.parseInt(yearFirst[2], 10),
    Number.parseInt(yearFirst[3], 10),
    Number.parseInt(yearFirst[4], 10),
    Number.parseInt(yearFirst[5], 10),
    Number.parseInt(yearFirst[6], 10),
    yearFirst[7]
  );
}

function buildLocalDate(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  fraction: string | undefined
): Date | null {
  const millis = Number.parseInt((fraction ?? "0").slice(0, 3).padEnd(3, "0"), 10);
  const parsed = new Date(year, month - 1, day, hour, minute, second, millis);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatWithWindowsPattern(
  date: Date,
  pattern: string,
  preferences: SystemDateTimePreferences
): string {
  let result = "";

  for (let index = 0; index < pattern.length;) {
    const character = pattern[index];

    if (character === "'") {
      const closingIndex = pattern.indexOf("'", index + 1);
      if (closingIndex === -1) {
        result += pattern.slice(index + 1);
        break;
      }
      result += pattern.slice(index + 1, closingIndex);
      index = closingIndex + 1;
      continue;
    }

    if (!/[A-Za-z]/.test(character)) {
      result += character;
      index += 1;
      continue;
    }

    let tokenEnd = index + 1;
    while (tokenEnd < pattern.length && pattern[tokenEnd] === character) {
      tokenEnd += 1;
    }

    const token = pattern.slice(index, tokenEnd);
    result += formatToken(date, token, preferences);
    index = tokenEnd;
  }

  return result.replace(/\s+/g, " ").trim();
}

function formatToken(
  date: Date,
  token: string,
  preferences: SystemDateTimePreferences
): string {
  switch (token) {
    case "d":
      return String(date.getDate());
    case "dd":
      return String(date.getDate()).padStart(2, "0");
    case "ddd":
      return new Intl.DateTimeFormat(undefined, { weekday: "short" }).format(date);
    case "dddd":
      return new Intl.DateTimeFormat(undefined, { weekday: "long" }).format(date);
    case "M":
      return String(date.getMonth() + 1);
    case "MM":
      return String(date.getMonth() + 1).padStart(2, "0");
    case "MMM":
      return new Intl.DateTimeFormat(undefined, { month: "short" }).format(date);
    case "MMMM":
      return new Intl.DateTimeFormat(undefined, { month: "long" }).format(date);
    case "y":
      return String(date.getFullYear());
    case "yy":
      return String(date.getFullYear()).slice(-2).padStart(2, "0");
    case "yyy":
    case "yyyy":
      return String(date.getFullYear()).padStart(token.length, "0");
    case "H":
      return String(date.getHours());
    case "HH":
      return String(date.getHours()).padStart(2, "0");
    case "h": {
      const hour = date.getHours() % 12 || 12;
      return String(hour);
    }
    case "hh": {
      const hour = date.getHours() % 12 || 12;
      return String(hour).padStart(2, "0");
    }
    case "m":
      return String(date.getMinutes());
    case "mm":
      return String(date.getMinutes()).padStart(2, "0");
    case "s":
      return String(date.getSeconds());
    case "ss":
      return String(date.getSeconds()).padStart(2, "0");
    case "t":
      return getDayPeriodDesignator(date, preferences).slice(0, 1);
    case "tt":
      return getDayPeriodDesignator(date, preferences);
    default:
      return token;
  }
}

function getDayPeriodDesignator(
  date: Date,
  preferences: SystemDateTimePreferences
): string {
  return date.getHours() < 12
    ? preferences.amDesignator || DEFAULT_AM_DESIGNATOR
    : preferences.pmDesignator || DEFAULT_PM_DESIGNATOR;
}