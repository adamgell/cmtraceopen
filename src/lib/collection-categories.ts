/**
 * Maps top-level UI categories to profile_data.json family strings.
 * The backend filters on families; the frontend owns the grouping.
 */

export interface CategoryDefinition {
  id: string;
  label: string;
  families: string[];
}

export const COLLECTION_CATEGORIES: CategoryDefinition[] = [
  {
    id: "intune-mdm",
    label: "Intune & MDM",
    families: ["intune", "intune-ime", "mdm", "mdm-enrollment", "mdm-diagnostics", "omadm", "sidecar"],
  },
  {
    id: "autopilot",
    label: "Autopilot & Provisioning",
    families: ["autopilot", "provisioning"],
  },
  {
    id: "networking",
    label: "Networking",
    families: ["networking", "firewall"],
  },
  {
    id: "security",
    label: "Security & Certificates",
    families: ["security", "certificates", "bitlocker", "antimalware", "secureboot"],
  },
  {
    id: "windows-update",
    label: "Windows Update",
    families: ["windows-update", "delivery-optimization"],
  },
  {
    id: "event-logs",
    label: "Event Logs",
    families: ["curated-evtx-copy"],
  },
  {
    id: "configmgr-epm",
    label: "ConfigMgr & EPM",
    families: ["configmgr", "epm", "device-inventory"],
  },
  {
    id: "general",
    label: "General & System",
    families: [
      "general", "system", "telemetry", "kiosk", "policymanager",
      "device-join", "panther", "cbs", "dism", "msi", "setup",
      "wmi", "wpm", "ndes", "company-portal", "teams",
    ],
  },
];

export interface PresetDefinition {
  id: string;
  label: string;
  categoryIds: string[];
}

export const COLLECTION_PRESETS: PresetDefinition[] = [
  {
    id: "full",
    label: "Full Collection",
    categoryIds: COLLECTION_CATEGORIES.map((c) => c.id),
  },
  {
    id: "intune-autopilot",
    label: "Intune + Autopilot",
    categoryIds: ["intune-mdm", "autopilot", "event-logs"],
  },
  {
    id: "networking",
    label: "Networking",
    categoryIds: ["networking", "general"],
  },
  {
    id: "security",
    label: "Security",
    categoryIds: ["security", "event-logs"],
  },
  {
    id: "quick",
    label: "Quick System Info",
    categoryIds: ["general"],
  },
];

/** Given a set of enabled category IDs, return the flat list of family strings for the backend. */
export function getEnabledFamilies(enabledCategoryIds: Set<string>): string[] {
  return COLLECTION_CATEGORIES
    .filter((cat) => enabledCategoryIds.has(cat.id))
    .flatMap((cat) => cat.families);
}

/** Given a set of enabled category IDs, check if all categories are enabled (i.e. full collection). */
export function isFullCollection(enabledCategoryIds: Set<string>): boolean {
  return COLLECTION_CATEGORIES.every((cat) => enabledCategoryIds.has(cat.id));
}
