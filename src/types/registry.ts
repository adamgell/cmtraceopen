export type RegistryValueKind =
  | "string"
  | "dword"
  | "qword"
  | "binary"
  | "expandString"
  | "multiString"
  | "none"
  | "deleteMarker";

export interface RegistryValue {
  name: string;
  kind: RegistryValueKind;
  data: string;
  lineNumber: number;
}

export interface RegistryKey {
  path: string;
  values: RegistryValue[];
  lineNumber: number;
  isDelete: boolean;
}

export interface RegistryParseResult {
  keys: RegistryKey[];
  filePath: string;
  fileSize: number;
  totalKeys: number;
  totalValues: number;
  parseErrors: number;
}

export interface RegistryTreeNode {
  name: string;
  fullPath: string;
  children: RegistryTreeNode[];
  /** Index into the flat keys array, or null for synthetic intermediate nodes. */
  keyIndex: number | null;
}
