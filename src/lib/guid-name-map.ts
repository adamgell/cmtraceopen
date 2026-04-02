import type { LogEntry } from "../types/log";

const GET_POLICIES_PREFIX = "Get policies = ";

const GUID_RE =
  /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g;

/**
 * Sanitize JSON with invalid escape sequences (e.g. Windows paths like `\Package`).
 * Doubles backslashes that aren't followed by valid JSON escape characters.
 */
function sanitizeJson(input: string): string {
  const validEscapes = new Set(['"', "\\", "/", "b", "f", "n", "r", "t", "u"]);
  const out: string[] = [];
  for (let i = 0; i < input.length; i++) {
    if (input[i] === "\\" && i + 1 < input.length) {
      if (validEscapes.has(input[i + 1])) {
        out.push("\\", input[i + 1]);
        i++;
      } else {
        out.push("\\\\");
      }
    } else {
      out.push(input[i]);
    }
  }
  return out.join("");
}

function tryParseArray(jsonStr: string): unknown[] | null {
  try {
    const parsed = JSON.parse(jsonStr);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    try {
      const parsed = JSON.parse(sanitizeJson(jsonStr));
      return Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
}

/**
 * Scan log entries for "Get policies" messages and extract GUID→Name mappings.
 * Returns a map keyed by lowercase GUID for case-insensitive lookup.
 */
export function buildGuidNameMap(
  entries: LogEntry[]
): Record<string, string> {
  const map: Record<string, string> = {};

  for (const entry of entries) {
    if (!entry.message.startsWith(GET_POLICIES_PREFIX)) continue;

    const jsonStr = entry.message.slice(GET_POLICIES_PREFIX.length);
    const arr = tryParseArray(jsonStr);
    if (!arr) continue;

    for (const item of arr) {
      const obj = item as Record<string, unknown>;
      if (typeof obj.Id === "string" && typeof obj.Name === "string" && obj.Name) {
        map[obj.Id.toLowerCase()] = obj.Name;
      }
    }
  }

  return map;
}

/**
 * Merge new GUID→Name entries into an existing map (does not overwrite existing names).
 */
export function mergeGuidNameMap(
  existing: Record<string, string>,
  newEntries: LogEntry[]
): Record<string, string> {
  const additions = buildGuidNameMap(newEntries);
  if (Object.keys(additions).length === 0) return existing;

  return { ...existing, ...additions };
}

/**
 * Find all GUIDs in a message and return their resolved names.
 */
export function resolveGuidsInMessage(
  message: string,
  guidMap: Record<string, string>
): { guid: string; name: string }[] {
  if (Object.keys(guidMap).length === 0) return [];

  const results: { guid: string; name: string }[] = [];
  const seen = new Set<string>();

  for (const match of message.matchAll(GUID_RE)) {
    const guidLower = match[0].toLowerCase();
    if (seen.has(guidLower)) continue;
    seen.add(guidLower);
    const name = guidMap[guidLower];
    if (name) {
      results.push({ guid: match[0], name });
    }
  }

  return results;
}
