import type { GraphAppInfo } from "./commands";
import type { GuidCategory, GuidRegistryEntry } from "../types/intune";

function categorizeOdataType(odataType: string | null): GuidCategory {
  if (!odataType) return "unknown";
  const t = odataType.toLowerCase();
  if (t.includes("healthscript")) return "remediation";
  if (t.includes("managementscript") || t.includes("shellscript")) return "script";
  return "app";
}

export function buildGraphRegistryEntries(
  apps: GraphAppInfo[]
): Record<string, GuidRegistryEntry> {
  const entries: Record<string, GuidRegistryEntry> = {};
  for (const app of apps) {
    entries[app.id] = {
      name: app.displayName,
      source: "GraphApi",
      category: categorizeOdataType(app.odataType),
      publisher: app.publisher ?? undefined,
    };
  }
  return entries;
}
