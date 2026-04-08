import { tokens } from "@fluentui/react-components";
import type { SecureBootScanState, DataSource } from "./types";

type RowStatus = "ok" | "warn" | "error" | "muted";

interface FactRow {
  label: string;
  value: string;
  status: RowStatus;
}

interface FactGroup {
  title: string;
  rows: FactRow[];
}

function rowColors(status: RowStatus) {
  switch (status) {
    case "ok":
      return {
        value: tokens.colorPaletteGreenForeground1,
        background: tokens.colorPaletteGreenBackground1,
      };
    case "warn":
      return {
        value: tokens.colorPaletteMarigoldForeground2,
        background: tokens.colorPaletteYellowBackground1,
      };
    case "error":
      return {
        value: tokens.colorPaletteRedForeground1,
        background: tokens.colorPaletteRedBackground1,
      };
    case "muted":
    default:
      return {
        value: tokens.colorNeutralForeground3,
        background: tokens.colorNeutralBackground3,
      };
  }
}

function FactGroupCard({ group }: { group: FactGroup }) {
  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralCardBackground,
        borderRadius: "10px",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: "10px 12px",
          backgroundColor: tokens.colorNeutralBackground3,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        }}
      >
        <div
          style={{
            fontSize: "13px",
            fontWeight: 700,
            color: tokens.colorNeutralForeground1,
          }}
        >
          {group.title}
        </div>
      </div>
      <div>
        {group.rows.map((row) => {
          const colors = rowColors(row.status);
          return (
            <div
              key={row.label}
              style={{
                display: "grid",
                gridTemplateColumns: "140px minmax(0, 1fr)",
                gap: "8px",
                padding: "8px 12px",
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                alignItems: "start",
              }}
            >
              <div
                style={{
                  fontSize: "12px",
                  fontWeight: 600,
                  color: tokens.colorNeutralForeground3,
                }}
              >
                {row.label}
              </div>
              <div
                style={{
                  fontSize: "12px",
                  color: colors.value,
                  backgroundColor: colors.background,
                  padding: "2px 6px",
                  borderRadius: "2px",
                  wordBreak: "break-word",
                  whiteSpace: "pre-wrap",
                }}
              >
                {row.value}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function fmtBool(value: boolean | null, trueLabel = "Yes", falseLabel = "No"): { text: string; status: RowStatus } {
  if (value === null) return { text: "Unknown", status: "muted" };
  return { text: value ? trueLabel : falseLabel, status: value ? "ok" : "warn" };
}

function fmtBoolRequired(value: boolean | null, trueLabel = "Yes", falseLabel = "No"): { text: string; status: RowStatus } {
  if (value === null) return { text: "Unknown", status: "muted" };
  return { text: value ? trueLabel : falseLabel, status: value ? "ok" : "error" };
}

function fmtNum(value: number | null): { text: string; status: RowStatus } {
  if (value === null) return { text: "Unknown", status: "muted" };
  return { text: String(value), status: "muted" };
}

function fmtStr(value: string | null): { text: string; status: RowStatus } {
  if (value === null || value === "") return { text: "Unknown", status: "muted" };
  return { text: value, status: "muted" };
}

const LOG_IMPORT_ONLY = { text: "Log import only", status: "muted" as RowStatus };

function buildGroups(scanState: SecureBootScanState, dataSource: DataSource): FactGroup[] {
  const isLogImportOnly = dataSource === "logImport";

  function liveOrImport<T>(
    liveValue: T,
    liveToFact: (v: T) => { text: string; status: RowStatus },
  ): { text: string; status: RowStatus } {
    if (isLogImportOnly) return LOG_IMPORT_ONLY;
    return liveToFact(liveValue);
  }

  // --- Certificates group ---
  const ca2023Status = liveOrImport(scanState.uefiCa2023Status, (v) => {
    if (v === null) return { text: "Unknown", status: "muted" };
    return { text: String(v), status: v === 0 ? "ok" : "warn" };
  });
  const ca2023Capable = liveOrImport(scanState.uefiCa2023Capable, (v) => {
    if (v === null) return { text: "Unknown", status: "muted" };
    return { text: v === 1 ? "Capable" : "Not capable", status: v === 1 ? "ok" : "warn" };
  });
  const bootManager = liveOrImport(scanState.secureBootEnabled, (v) =>
    fmtBoolRequired(v, "Enabled", "Disabled"),
  );
  const optInKey = liveOrImport(scanState.managedOptIn, (v) => {
    if (v === null) return { text: "Unknown", status: "muted" };
    return { text: String(v), status: v === 1 ? "ok" : "warn" };
  });

  const certificatesGroup: FactGroup = {
    title: "Certificates",
    rows: [
      { label: "CA 2023 Status", value: ca2023Status.text, status: ca2023Status.status },
      { label: "Boot Manager", value: bootManager.text, status: bootManager.status },
      { label: "Capable Flag", value: ca2023Capable.text, status: ca2023Capable.status },
      { label: "Opt-in Key", value: optInKey.text, status: optInKey.status },
    ],
  };

  // --- System Health group ---
  const secureBootRow = liveOrImport(scanState.secureBootEnabled, (v) =>
    fmtBoolRequired(v, "Enabled", "Disabled"),
  );
  const tpmRow = liveOrImport(
    { present: scanState.tpmPresent, enabled: scanState.tpmEnabled },
    ({ present, enabled }) => {
      if (present === null) return { text: "Unknown", status: "muted" };
      if (!present) return { text: "Not present", status: "warn" };
      if (enabled === false) return { text: "Present but disabled", status: "warn" };
      return { text: "Present & enabled", status: "ok" };
    },
  );
  const bitlockerRow = liveOrImport(scanState.bitlockerProtectionOn, (v) =>
    fmtBool(v, "Protection on", "Protection off"),
  );
  const diskRow = liveOrImport(scanState.diskPartitionStyle, (v) =>
    fmtStr(v),
  );

  const systemHealthGroup: FactGroup = {
    title: "System Health",
    rows: [
      { label: "Secure Boot", value: secureBootRow.text, status: secureBootRow.status },
      { label: "TPM", value: tpmRow.text, status: tpmRow.status },
      { label: "BitLocker", value: bitlockerRow.text, status: bitlockerRow.status },
      { label: "Disk", value: diskRow.text, status: diskRow.status },
    ],
  };

  // --- Configuration group ---
  const telemetryRow = liveOrImport(scanState.telemetryLevel, (v) =>
    fmtNum(v),
  );
  const diagtrackRow = liveOrImport(scanState.diagtrackRunning, (v) =>
    fmtBoolRequired(v, "Running", "Stopped"),
  );
  const schedTaskRow = liveOrImport(scanState.scheduledTaskExists, (v) =>
    fmtBool(v, "Exists", "Missing"),
  );
  const payloadsRow = liveOrImport(scanState.payloadBinCount, (v) => {
    if (v === null) return { text: "Unknown", status: "muted" };
    return { text: `${v} file${v === 1 ? "" : "s"}`, status: v > 0 ? "ok" : "warn" };
  });

  const configurationGroup: FactGroup = {
    title: "Configuration",
    rows: [
      { label: "Telemetry", value: telemetryRow.text, status: telemetryRow.status },
      { label: "DiagTrack", value: diagtrackRow.text, status: diagtrackRow.status },
      { label: "Sched Task", value: schedTaskRow.text, status: schedTaskRow.status },
      { label: "Payloads", value: payloadsRow.text, status: payloadsRow.status },
    ],
  };

  return [certificatesGroup, systemHealthGroup, configurationGroup];
}

export interface FactGroupCardsProps {
  scanState: SecureBootScanState;
  dataSource: DataSource;
}

export function FactGroupCards({ scanState, dataSource }: FactGroupCardsProps) {
  const groups = buildGroups(scanState, dataSource);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
        gap: "12px",
      }}
    >
      {groups.map((group) => (
        <FactGroupCard key={group.title} group={group} />
      ))}
    </div>
  );
}
