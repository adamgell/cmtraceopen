import { useCallback, useEffect, useMemo, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import {
  ChevronDownRegular,
  ChevronRightRegular,
  FolderOpenRegular,
  FolderRegular,
} from "@fluentui/react-icons";
import {
  defaultRangeExtractor,
  useVirtualizer,
} from "@tanstack/react-virtual";
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
  const disclosurePointerRef = useRef(false);

  // Scroll selected row into view when search navigates.
  const selectedIndex = useMemo(
    () =>
      selectedKeyPath
        ? flatRows.findIndex((r) => r.node.fullPath === selectedKeyPath)
        : -1,
    [flatRows, selectedKeyPath]
  );

  const rangeExtractor = useCallback(
    (range: Parameters<typeof defaultRangeExtractor>[0]) => {
      const indexes = defaultRangeExtractor(range);
      if (
        selectedIndex < 0 ||
        selectedIndex >= flatRows.length ||
        indexes.includes(selectedIndex)
      ) {
        return indexes;
      }
      return [...indexes, selectedIndex].sort((a, b) => a - b);
    },
    [flatRows.length, selectedIndex]
  );

  const virtualizer = useVirtualizer({
    count: flatRows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
    rangeExtractor,
  });

  useEffect(() => {
    if (selectedIndex >= 0) {
      virtualizer.scrollToIndex(selectedIndex, { align: "auto" });
    }
  }, [selectedIndex, virtualizer]);
  const virtualItems = virtualizer.getVirtualItems();
  const selectedItemMounted = virtualItems.some(
    (virtualRow) => virtualRow.index === selectedIndex,
  );

  const handleFocus = useCallback(() => {
    if (disclosurePointerRef.current) {
      disclosurePointerRef.current = false;
      return;
    }
    if (selectedIndex < 0 && flatRows.length > 0) {
      setSelectedKeyPath(flatRows[0].node.fullPath);
    }
  }, [flatRows, selectedIndex, setSelectedKeyPath]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if ((e.key === "Home" || e.key === "End") && flatRows.length > 0) {
        e.preventDefault();
        const targetIndex = e.key === "Home" ? 0 : flatRows.length - 1;
        setSelectedKeyPath(flatRows[targetIndex].node.fullPath);
        return;
      }

      if (selectedIndex < 0) {
        if (flatRows.length === 0) return;
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const initialIndex = e.key === "ArrowUp" ? flatRows.length - 1 : 0;
          setSelectedKeyPath(flatRows[initialIndex].node.fullPath);
        }
        return;
      }
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
        if (row.node.children.length > 0) {
          if (!expandedPaths.has(row.node.fullPath)) {
            toggleExpanded(row.node.fullPath);
          } else {
            const child = flatRows[selectedIndex + 1];
            if (child && child.depth > row.depth) {
              setSelectedKeyPath(child.node.fullPath);
            }
          }
        }
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        if (
          row.node.children.length > 0 &&
          expandedPaths.has(row.node.fullPath)
        ) {
          toggleExpanded(row.node.fullPath);
        } else if (row.depth > 0) {
          for (let index = selectedIndex - 1; index >= 0; index--) {
            if (flatRows[index].depth < row.depth) {
              setSelectedKeyPath(flatRows[index].node.fullPath);
              break;
            }
          }
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
      role="tree"
      aria-label="Registry keys"
      aria-activedescendant={
        selectedItemMounted && selectedIndex >= 0
          ? `registry-tree-item-${selectedIndex}`
          : undefined
      }
      tabIndex={0}
      onFocus={handleFocus}
      onKeyDown={handleKeyDown}
      style={{
        height: "100%",
        overflow: "auto",
      }}
    >

      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualItems.map((virtualRow) => {
          const row = flatRows[virtualRow.index];
          const isSelected = row.node.fullPath === selectedKeyPath;
          const hasChildren = row.node.children.length > 0;
          const isExpanded = expandedPaths.has(row.node.fullPath);

          return (
            <div
              key={row.node.fullPath}
              id={`registry-tree-item-${virtualRow.index}`}
              role="treeitem"
              aria-level={row.depth + 1}
              aria-posinset={row.posInSet}
              aria-setsize={row.setSize}
              aria-selected={isSelected}
              aria-expanded={hasChildren ? isExpanded : undefined}
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
              onPointerDown={(e) => {
                if (e.button === 0) {
                  setSelectedKeyPath(row.node.fullPath);
                }
              }}
              onClick={() => setSelectedKeyPath(row.node.fullPath)}
              onDoubleClick={() => {
                if (hasChildren) toggleExpanded(row.node.fullPath);
              }}
            >
              {/* Expand/collapse chevron */}
              <span
                data-registry-disclosure
                role="presentation"
                aria-hidden="true"
                style={{
                  width: "16px",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                  color: tokens.colorNeutralForeground3,
                  fontSize: "10px",
                }}
                onPointerDown={(e) => {
                  e.stopPropagation();
                  if (e.button === 0) disclosurePointerRef.current = true;
                }}
                onPointerCancel={() => {
                  disclosurePointerRef.current = false;
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  if (!hasChildren) return;
                  toggleExpanded(row.node.fullPath);
                  disclosurePointerRef.current = true;
                  parentRef.current?.focus({ preventScroll: true });
                  disclosurePointerRef.current = false;
                }}
              >
                {hasChildren ? (isExpanded ? <ChevronDownRegular /> : <ChevronRightRegular />) : ""}
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
                {isExpanded && hasChildren ? <FolderOpenRegular /> : <FolderRegular />}
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
