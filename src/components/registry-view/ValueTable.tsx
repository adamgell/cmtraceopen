import { useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import { useRegistryStore } from "../../stores/registry-store";
import { getValueTypeLabel } from "../../lib/registry-utils";

export function ValueTable() {
  const registryData = useRegistryStore((s) => s.registryData);
  const selectedKeyPath = useRegistryStore((s) => s.selectedKeyPath);

  const selectedKey = useMemo(() => {
    if (!registryData || !selectedKeyPath) return null;
    return registryData.keys.find((k) => k.path === selectedKeyPath) ?? null;
  }, [registryData, selectedKeyPath]);

  if (!selectedKeyPath) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: tokens.colorNeutralForeground3,
          fontSize: "13px",
        }}
      >
        Select a key to view its values
      </div>
    );
  }

  if (!selectedKey || selectedKey.values.length === 0) {
    return (
      <div style={{ padding: "12px", fontSize: "12px" }}>
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            marginBottom: "8px",
            fontFamily: tokens.fontFamilyMonospace,
            fontSize: "11px",
            wordBreak: "break-all",
          }}
        >
          {selectedKeyPath}
        </div>
        <div style={{ color: tokens.colorNeutralForeground3 }}>
          {selectedKey?.isDelete
            ? "This key is marked for deletion."
            : "This key has no values."}
        </div>
      </div>
    );
  }

  return (
    <div style={{ height: "100%", overflow: "auto", fontSize: "12px" }}>
      {/* Key path header */}
      <div
        style={{
          padding: "8px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          fontFamily: tokens.fontFamilyMonospace,
          fontSize: "11px",
          color: tokens.colorNeutralForeground3,
          wordBreak: "break-all",
        }}
      >
        {selectedKeyPath}
      </div>

      {/* Table header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(160px, 1fr) 120px minmax(200px, 3fr)",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
          position: "sticky",
          top: 0,
          zIndex: 1,
        }}
      >
        <div style={headerCellStyle}>Name</div>
        <div style={headerCellStyle}>Type</div>
        <div style={headerCellStyle}>Data</div>
      </div>

      {/* Value rows */}
      {selectedKey.values.map((value, idx) => (
        <div
          key={`${value.name}-${idx}`}
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(160px, 1fr) 120px minmax(200px, 3fr)",
            borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
          }}
        >
          <div style={cellStyle} title={value.name}>
            <span
              style={{
                fontWeight:
                  value.name === "(Default)" ? 600 : 400,
              }}
            >
              {value.name}
            </span>
          </div>
          <div style={cellStyle}>
            <span style={{ color: tokens.colorNeutralForeground3 }}>
              {getValueTypeLabel(value.kind)}
            </span>
          </div>
          <div
            style={{
              ...cellStyle,
              fontFamily: tokens.fontFamilyMonospace,
              wordBreak: "break-all",
            }}
            title={value.data}
          >
            {value.kind === "deleteMarker" ? (
              <span style={{ color: tokens.colorPaletteRedForeground1, fontStyle: "italic" }}>
                {value.data}
              </span>
            ) : (
              truncateData(value.data, 500)
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

const headerCellStyle: React.CSSProperties = {
  padding: "6px 12px",
  fontWeight: 600,
  fontSize: "11px",
  color: tokens.colorNeutralForeground2,
};

const cellStyle: React.CSSProperties = {
  padding: "4px 12px",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  lineHeight: "22px",
};

function truncateData(data: string, maxLen: number): string {
  if (data.length <= maxLen) return data;
  return data.slice(0, maxLen) + "...";
}
