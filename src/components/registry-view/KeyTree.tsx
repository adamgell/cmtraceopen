import { useCallback, useEffect, useMemo, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useRegistryStore } from "../../stores/registry-store";
import { flattenVisibleTree } from "../../lib/registry-utils";

const ROW_HEIGHT = 26;
const INDENT_PX = 18;

export function KeyTree() {
  const tree = useRegistryStore((s) => s.tree);
  const expandedPaths = useRegistryStore((s) => s.expandedPaths);
  const selectedKeyPath = useRegistryStore((s) => s.selectedKeyPath);
  const toggleExpanded = useRegistryStore((s) => s.toggleExpanded);
  const setSelectedKeyPath = useRegistryStore((s) => s.setSelectedKeyPath);

  const flatRows = useMemo(
    () => flattenVisibleTree(tree, expandedPaths),
    [tree, expandedPaths]
  );

  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: flatRows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  // Scroll selected row into view when search navigates
  const selectedIndex = useMemo(
    () =>
      selectedKeyPath
        ? flatRows.findIndex((r) => r.node.fullPath === selectedKeyPath)
        : -1,
    [flatRows, selectedKeyPath]
  );

  useEffect(() => {
    if (selectedIndex >= 0) {
      virtualizer.scrollToIndex(selectedIndex, { align: "auto" });
    }
  }, [selectedIndex, virtualizer]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (selectedIndex < 0) return;
      const row = flatRows[selectedIndex];
      if (!row) return;

      if (e.key === "ArrowDown" && selectedIndex < flatRows.length - 1) {
        e.preventDefault();
        setSelectedKeyPath(flatRows[selectedIndex + 1].node.fullPath);
      } else if (e.key === "ArrowUp" && selectedIndex > 0) {
        e.preventDefault();
        setSelectedKeyPath(flatRows[selectedIndex - 1].node.fullPath);
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        if (
          row.node.children.length > 0 &&
          !expandedPaths.has(row.node.fullPath)
        ) {
          toggleExpanded(row.node.fullPath);
        }
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        if (expandedPaths.has(row.node.fullPath)) {
          toggleExpanded(row.node.fullPath);
        }
      }
    },
    [
      selectedIndex,
      flatRows,
      expandedPaths,
      toggleExpanded,
      setSelectedKeyPath,
    ]
  );

  return (
    <div
      ref={parentRef}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      style={{
        height: "100%",
        overflow: "auto",
        outline: "none",
      }}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const row = flatRows[virtualRow.index];
          const isSelected = row.node.fullPath === selectedKeyPath;
          const hasChildren = row.node.children.length > 0;
          const isExpanded = expandedPaths.has(row.node.fullPath);

          return (
            <div
              key={row.node.fullPath}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                height: `${virtualRow.size}px`,
                transform: `translateY(${virtualRow.start}px)`,
                display: "flex",
                alignItems: "center",
                paddingLeft: `${row.depth * INDENT_PX + 4}px`,
                cursor: "pointer",
                backgroundColor: isSelected
                  ? tokens.colorNeutralBackground1Selected
                  : "transparent",
                borderLeft: isSelected
                  ? `2px solid ${tokens.colorBrandForeground1}`
                  : "2px solid transparent",
                userSelect: "none",
                fontSize: "12px",
                fontFamily: tokens.fontFamilyMonospace,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
              onClick={() => setSelectedKeyPath(row.node.fullPath)}
              onDoubleClick={() => {
                if (hasChildren) toggleExpanded(row.node.fullPath);
              }}
            >
              {/* Expand/collapse chevron */}
              <span
                style={{
                  width: "16px",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                  color: tokens.colorNeutralForeground3,
                  fontSize: "10px",
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  if (hasChildren) toggleExpanded(row.node.fullPath);
                }}
              >
                {hasChildren ? (isExpanded ? "▼" : "▶") : ""}
              </span>
              {/* Folder icon */}
              <span
                style={{
                  width: "16px",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                  fontSize: "12px",
                  marginRight: "4px",
                }}
              >
                {isExpanded && hasChildren ? "📂" : "📁"}
              </span>
              {/* Node name */}
              <span
                style={{
                  color: isSelected
                    ? tokens.colorNeutralForeground1
                    : tokens.colorNeutralForeground2,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
                title={row.node.fullPath}
              >
                {row.node.name}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
