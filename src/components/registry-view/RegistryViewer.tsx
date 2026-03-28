import { useCallback, useEffect, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { KeyTree } from "./KeyTree";
import { ValueTable } from "./ValueTable";
import { useRegistryStore, getCachedRegistry, setCachedRegistry } from "../../stores/registry-store";
import { useLogStore } from "../../stores/log-store";
import { parseRegistryFile } from "../../lib/commands";

const MIN_TREE_WIDTH = 180;
const DEFAULT_TREE_WIDTH = 320;

export function RegistryViewer() {
  const [treeWidth, setTreeWidth] = useState(DEFAULT_TREE_WIDTH);
  const resizing = useRef(false);
  const registryData = useRegistryStore((s) => s.registryData);
  const openFilePath = useLogStore((s) => s.openFilePath);

  // Load registry data when the file path changes
  useEffect(() => {
    if (!openFilePath) return;

    const cached = getCachedRegistry(openFilePath);
    if (cached) {
      useRegistryStore.getState().setRegistryData(cached);
      return;
    }

    // Load from backend
    parseRegistryFile(openFilePath)
      .then((data) => {
        setCachedRegistry(openFilePath, data);
        useRegistryStore.getState().setRegistryData(data);
      })
      .catch((err) => {
        console.error("[registry-viewer] failed to parse registry file", err);
      });
  }, [openFilePath]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    resizing.current = true;
    const startX = e.clientX;
    const startWidth = treeWidth;

    const handleMouseMove = (ev: MouseEvent) => {
      if (!resizing.current) return;
      const newWidth = Math.max(MIN_TREE_WIDTH, startWidth + ev.clientX - startX);
      setTreeWidth(newWidth);
    };

    const handleMouseUp = () => {
      resizing.current = false;
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
  }, [treeWidth]);

  if (!registryData) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: tokens.colorNeutralForeground3,
        }}
      >
        Loading registry data...
      </div>
    );
  }

  return (
    <div
      style={{
        display: "flex",
        height: "100%",
        overflow: "hidden",
      }}
    >
      {/* Key tree panel */}
      <div
        style={{
          width: `${treeWidth}px`,
          flexShrink: 0,
          borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Tree header */}
        <div
          style={{
            padding: "6px 12px",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground3,
            fontSize: "11px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground2,
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <span>Registry Keys</span>
          <span style={{ color: tokens.colorNeutralForeground3, fontWeight: 400 }}>
            {registryData.totalKeys} keys, {registryData.totalValues} values
          </span>
        </div>
        <div style={{ flex: 1, overflow: "hidden" }}>
          <KeyTree />
        </div>
      </div>

      {/* Resize handle */}
      <div
        onMouseDown={handleMouseDown}
        style={{
          width: "4px",
          cursor: "col-resize",
          backgroundColor: "transparent",
          flexShrink: 0,
        }}
      />

      {/* Value table panel */}
      <div style={{ flex: 1, overflow: "hidden" }}>
        <ValueTable />
      </div>
    </div>
  );
}
