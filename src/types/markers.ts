export interface MarkerCategory {
  id: string;
  label: string;
  color: string;
}

export interface Marker {
  lineId: number;
  category: string;
  color: string;
  added: string; // ISO 8601
}

export interface MarkerFile {
  version: number;
  sourcePath: string;
  sourceSize: number;
  created: string;
  modified: string;
  markers: Marker[];
  categories: MarkerCategory[];
}

export const DEFAULT_CATEGORIES: MarkerCategory[] = [
  { id: "bug", label: "Bug", color: "#ef4444" },
  { id: "investigate", label: "Investigate", color: "#60a5fa" },
  { id: "confirmed", label: "Confirmed", color: "#4ade80" },
];
