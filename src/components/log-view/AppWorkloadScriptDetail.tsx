import { useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { ScriptCodeViewer } from "../../workspaces/intune/ScriptCodeViewer";

interface PolicyEntry {
  id: string;
  name: string;
  intent?: number;
  targetType?: number;
  installCommandLine?: string;
  uninstallCommandLine?: string;
  installBehavior?: number;
  detectionType?: number;
  scriptBody?: string;
  enforceSignatureCheck?: boolean;
  runAs32Bit?: boolean;
  returnCodes?: { returnCode: number; type: number }[];
}

interface SideCarDetail {
  kind: "start" | "complete" | "exitCode" | "detected" | "processId" | "other";
  exitCode?: number;
  detected?: boolean;
  processId?: number;
  raw: string;
}

type ParsedDetail =
  | { type: "policies"; policies: PolicyEntry[] }
  | { type: "sidecar"; detail: SideCarDetail }
  | null;

function decodeBase64(encoded: string): string | null {
  try {
    const binaryStr = atob(encoded);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return null;
  }
}

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

function parseGetPolicies(message: string): PolicyEntry[] | null {
  if (!message.startsWith("Get policies = ")) return null;

  const jsonStr = message.slice("Get policies = ".length);
  let arr: unknown[];
  try {
    arr = JSON.parse(jsonStr);
  } catch {
    try {
      arr = JSON.parse(sanitizeJson(jsonStr));
    } catch {
      return null;
    }
  }

  if (!Array.isArray(arr)) return null;

  return arr.map((item: unknown) => {
    const obj = item as Record<string, unknown>;
    const rawId = obj.Id;
    if (typeof rawId !== "string" || rawId.length === 0) return null;
    const entry: PolicyEntry = {
      id: String(rawId),
      name: String(obj.Name ?? "Unknown"),
      intent: typeof obj.Intent === "number" ? obj.Intent : undefined,
      targetType: typeof obj.TargetType === "number" ? obj.TargetType : undefined,
      installCommandLine: typeof obj.InstallCommandLine === "string" ? obj.InstallCommandLine : undefined,
      uninstallCommandLine: typeof obj.UninstallCommandLine === "string" ? obj.UninstallCommandLine : undefined,
      installBehavior: typeof obj.InstallBehavior === "number" ? obj.InstallBehavior : undefined,
    };

    // Parse DetectionRule
    if (typeof obj.DetectionRule === "string") {
      try {
        const rules = JSON.parse(obj.DetectionRule) as Record<string, unknown>[];
        if (rules.length > 0) {
          const rule = rules[0];
          entry.detectionType = typeof rule.DetectionType === "number" ? rule.DetectionType : undefined;
          if (entry.detectionType === 3 && typeof rule.DetectionText === "string") {
            try {
              const dt = JSON.parse(rule.DetectionText) as Record<string, unknown>;
              if (typeof dt.ScriptBody === "string" && dt.ScriptBody) {
                entry.scriptBody = decodeBase64(dt.ScriptBody) ?? undefined;
              }
              entry.enforceSignatureCheck = dt.EnforceSignatureCheck === 1;
              entry.runAs32Bit = dt.RunAs32Bit === 1;
            } catch { /* ignore nested parse failure */ }
          }
        }
      } catch { /* ignore detection rule parse failure */ }
    }

    // Parse ReturnCodes
    if (typeof obj.ReturnCodes === "string") {
      try {
        const codes = JSON.parse(obj.ReturnCodes) as { ReturnCode: number; Type: number }[];
        entry.returnCodes = codes.map((c) => ({ returnCode: c.ReturnCode, type: c.Type }));
      } catch { /* ignore */ }
    }

    return entry;
  }).filter((entry): entry is PolicyEntry => entry !== null);
}

function parseSideCarDetail(message: string): SideCarDetail | null {
  const lower = message.toLowerCase();
  if (!lower.includes("sidecarscriptdetectionmanager")) return null;

  if (lower.includes("start detectionmanager sidecarscriptdetectionmanager")) {
    return { kind: "start", raw: message };
  }
  if (lower.includes("completed detectionmanager sidecarscriptdetectionmanager")) {
    const detected = /applicationdetectedbycurrentrule:\s*(true|false)/i.exec(message);
    return {
      kind: "complete",
      detected: detected ? detected[1].toLowerCase() === "true" : undefined,
      raw: message,
    };
  }
  const exitMatch = /powershell\s+exitcode:\s*(\d+)/i.exec(message);
  if (exitMatch) {
    return { kind: "exitCode", exitCode: parseInt(exitMatch[1], 10), raw: message };
  }
  const pidMatch = /process\s+id\s*=\s*(\d+)/i.exec(message);
  if (pidMatch) {
    return { kind: "processId", processId: parseInt(pidMatch[1], 10), raw: message };
  }
  const detectedMatch = /applicationdetectedbycurrentrule:\s*(true|false)/i.exec(message);
  if (detectedMatch) {
    return { kind: "detected", detected: detectedMatch[1].toLowerCase() === "true", raw: message };
  }
  return { kind: "other", raw: message };
}

function parseMessage(message: string): ParsedDetail {
  const policies = parseGetPolicies(message);
  if (policies) return { type: "policies", policies };

  const sidecar = parseSideCarDetail(message);
  if (sidecar) return { type: "sidecar", detail: sidecar };

  return null;
}

const INTENT_LABELS: Record<number, string> = {
  0: "Available",
  1: "Available (no enrollment)",
  3: "Required",
  4: "Uninstall",
};

const TARGET_TYPE_LABELS: Record<number, string> = {
  1: "User",
  2: "Device",
  3: "Both",
};

const DETECTION_TYPE_LABELS: Record<number, string> = {
  0: "Registry",
  1: "MSI Product Code",
  2: "File/Folder",
  3: "PowerShell Script",
};

const RETURN_CODE_TYPE_LABELS: Record<number, string> = {
  0: "Failed",
  1: "Success",
  2: "Soft Reboot",
  3: "Hard Reboot",
  4: "Retry",
};

const labelStyle: React.CSSProperties = {
  color: tokens.colorNeutralForeground3,
  marginRight: "4px",
};

const valueStyle: React.CSSProperties = {
  color: tokens.colorNeutralForeground1,
  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
};

function PolicyCard({ policy }: { policy: PolicyEntry }) {
  return (
    <div
      style={{
        marginBottom: "12px",
        padding: "8px",
        backgroundColor: tokens.colorNeutralBackground3,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "4px",
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: "6px", color: tokens.colorNeutralForeground1 }}>
        {policy.name}
      </div>
      <div style={{ fontSize: "12px", display: "flex", flexDirection: "column", gap: "3px" }}>
        <div>
          <span style={labelStyle}>ID:</span>
          <span style={valueStyle}>{policy.id}</span>
        </div>
        {policy.intent != null && (
          <div>
            <span style={labelStyle}>Intent:</span>
            <span style={valueStyle}>{INTENT_LABELS[policy.intent] ?? policy.intent}</span>
          </div>
        )}
        {policy.targetType != null && (
          <div>
            <span style={labelStyle}>Target:</span>
            <span style={valueStyle}>{TARGET_TYPE_LABELS[policy.targetType] ?? policy.targetType}</span>
          </div>
        )}
        {policy.installCommandLine && (
          <div>
            <span style={labelStyle}>Install:</span>
            <span style={valueStyle}>{policy.installCommandLine}</span>
          </div>
        )}
        {policy.uninstallCommandLine && (
          <div>
            <span style={labelStyle}>Uninstall:</span>
            <span style={valueStyle}>{policy.uninstallCommandLine}</span>
          </div>
        )}
        {policy.detectionType != null && (
          <div>
            <span style={labelStyle}>Detection:</span>
            <span style={valueStyle}>{DETECTION_TYPE_LABELS[policy.detectionType] ?? `Type ${policy.detectionType}`}</span>
          </div>
        )}
        {policy.returnCodes && policy.returnCodes.length > 0 && (
          <div>
            <span style={labelStyle}>Return Codes:</span>
            <span style={valueStyle}>
              {policy.returnCodes
                .map((rc) => `${rc.returnCode}=${RETURN_CODE_TYPE_LABELS[rc.type] ?? rc.type}`)
                .join(", ")}
            </span>
          </div>
        )}
      </div>
      {policy.scriptBody && (
        <ScriptCodeViewer script={policy.scriptBody} maxHeight={300} />
      )}
    </div>
  );
}

function SideCarBanner({ detail }: { detail: SideCarDetail }) {
  const labelMap: Record<SideCarDetail["kind"], { label: string; color: string }> = {
    start: { label: "Script Detection Started", color: tokens.colorBrandForeground1 },
    complete: { label: "Script Detection Complete", color: tokens.colorPaletteGreenForeground1 },
    exitCode: { label: "PowerShell Exit Code", color: detail.exitCode === 0 ? tokens.colorPaletteGreenForeground1 : tokens.colorPaletteRedForeground1 },
    detected: { label: "Detection Result", color: detail.detected ? tokens.colorPaletteGreenForeground1 : tokens.colorPaletteMarigoldForeground1 },
    processId: { label: "Script Process", color: tokens.colorNeutralForeground2 },
    other: { label: "Script Detection", color: tokens.colorNeutralForeground2 },
  };

  const { label, color } = labelMap[detail.kind];

  return (
    <div
      style={{
        padding: "6px 8px",
        marginBottom: "8px",
        backgroundColor: tokens.colorNeutralBackground3,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "4px",
        borderLeft: `3px solid ${color}`,
        fontSize: "12px",
      }}
    >
      <span style={{ fontWeight: 600, color }}>{label}</span>
      {detail.exitCode != null && (
        <span style={{ ...valueStyle, marginLeft: "8px" }}>
          Exit Code: {detail.exitCode}
        </span>
      )}
      {detail.detected != null && (
        <span style={{ ...valueStyle, marginLeft: "8px" }}>
          App {detail.detected ? "Detected" : "Not Detected"}
        </span>
      )}
      {detail.processId != null && (
        <span style={{ ...valueStyle, marginLeft: "8px" }}>
          PID: {detail.processId}
        </span>
      )}
    </div>
  );
}

interface AppWorkloadScriptDetailProps {
  message: string;
}

export function AppWorkloadScriptDetail({ message }: AppWorkloadScriptDetailProps) {
  const parsed = useMemo(() => parseMessage(message), [message]);

  if (!parsed) return null;

  if (parsed.type === "sidecar") {
    return <SideCarBanner detail={parsed.detail} />;
  }

  return (
    <div style={{ marginTop: "8px" }}>
      <div
        style={{
          fontWeight: 600,
          marginBottom: "6px",
          color: tokens.colorNeutralForeground2,
          fontSize: "12px",
        }}
      >
        {parsed.policies.length} App {parsed.policies.length === 1 ? "Policy" : "Policies"}
      </div>
      {parsed.policies.map((policy) => (
        <PolicyCard key={policy.id} policy={policy} />
      ))}
    </div>
  );
}
