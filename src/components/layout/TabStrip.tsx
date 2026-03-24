import { useCallback, useEffect, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../stores/ui-store";

const MAX_VISIBLE_TABS = 6;

export function TabStrip() {
  const openTabs = useUiStore((s) => s.openTabs);
  const activeTabIndex = useUiStore((s) => s.activeTabIndex);
  const switchTab = useUiStore((s) => s.switchTab);
  const closeTab = useUiStore((s) => s.closeTab);

  const [hoveredTabIndex, setHoveredTabIndex] = useState<number | null>(null);
  const [overflowOpen, setOverflowOpen] = useState(false);
  const overflowRef = useRef<HTMLDivElement>(null);

  // Close overflow dropdown when clicking outside
  useEffect(() => {
    if (!overflowOpen) return;
    const handleDocumentClick = (e: MouseEvent) => {
      if (
        overflowRef.current &&
        !overflowRef.current.contains(e.target as Node)
      ) {
        setOverflowOpen(false);
      }
    };
    document.addEventListener("click", handleDocumentClick);
    return () => document.removeEventListener("click", handleDocumentClick);
  }, [overflowOpen]);

  const handleSwitchTab = useCallback(
    (index: number) => {
      switchTab(index);
    },
    [switchTab]
  );

  const handleCloseTab = useCallback(
    (e: React.MouseEvent, index: number) => {
      e.stopPropagation();
      closeTab(index);
    },
    [closeTab]
  );

  const handleToggleOverflow = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      setOverflowOpen((prev) => !prev);
    },
    []
  );

  const handleOverflowSelect = useCallback(
    (index: number) => {
      switchTab(index);
      setOverflowOpen(false);
    },
    [switchTab]
  );

  if (openTabs.length === 0) {
    return null;
  }

  const visibleTabs = openTabs.slice(0, MAX_VISIBLE_TABS);
  const overflowTabs = openTabs.slice(MAX_VISIBLE_TABS);
  const hasOverflow = overflowTabs.length > 0;

  return (
    <div style={stripStyle}>
      {visibleTabs.map((tab, index) => {
        const isActive = index === activeTabIndex;
        const isHovered = index === hoveredTabIndex;

        return (
          <div
            key={tab.id}
            style={{
              ...tabStyle,
              ...(isActive ? activeTabStyle : inactiveTabStyle),
            }}
            onClick={() => handleSwitchTab(index)}
            onMouseEnter={() => setHoveredTabIndex(index)}
            onMouseLeave={() => setHoveredTabIndex(null)}
          >
            <span style={tabLabelStyle}>{tab.fileName}</span>
            <span
              style={{
                ...closeButtonStyle,
                visibility: isHovered || isActive ? "visible" : "hidden",
              }}
              onClick={(e) => handleCloseTab(e, index)}
            >
              x
            </span>
          </div>
        );
      })}
      {hasOverflow && (
        <div ref={overflowRef} style={overflowContainerStyle}>
          <div
            style={overflowButtonStyle}
            onClick={handleToggleOverflow}
          >
            {overflowTabs.length} more...
          </div>
          {overflowOpen && (
            <div style={overflowDropdownStyle}>
              {overflowTabs.map((tab, i) => {
                const realIndex = MAX_VISIBLE_TABS + i;
                const isActive = realIndex === activeTabIndex;
                return (
                  <div
                    key={tab.id}
                    style={{
                      ...overflowItemStyle,
                      backgroundColor: isActive
                        ? tokens.colorNeutralBackground1
                        : "transparent",
                      color: isActive
                        ? tokens.colorNeutralForeground1
                        : tokens.colorNeutralForeground3,
                    }}
                    onClick={() => handleOverflowSelect(realIndex)}
                  >
                    {tab.fileName}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// --- Styles ---

const stripStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  height: 34,
  backgroundColor: tokens.colorNeutralBackground3,
  borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  overflow: "hidden",
  flexShrink: 0,
};

const tabStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 4,
  height: "100%",
  maxWidth: 200,
  minWidth: 80,
  padding: "0 8px",
  cursor: "pointer",
  boxSizing: "border-box",
  userSelect: "none",
  fontSize: 12,
};

const activeTabStyle: React.CSSProperties = {
  backgroundColor: tokens.colorNeutralBackground1,
  color: tokens.colorNeutralForeground1,
  borderBottom: `2px solid ${tokens.colorBrandBackground}`,
};

const inactiveTabStyle: React.CSSProperties = {
  backgroundColor: "transparent",
  color: tokens.colorNeutralForeground3,
};

const tabLabelStyle: React.CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  flex: 1,
};

const closeButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: 16,
  height: 16,
  fontSize: 11,
  lineHeight: 1,
  borderRadius: 2,
  flexShrink: 0,
  cursor: "pointer",
};

const overflowContainerStyle: React.CSSProperties = {
  position: "relative",
  height: "100%",
  display: "flex",
  alignItems: "center",
};

const overflowButtonStyle: React.CSSProperties = {
  padding: "0 10px",
  fontSize: 12,
  color: tokens.colorNeutralForeground3,
  cursor: "pointer",
  whiteSpace: "nowrap",
  userSelect: "none",
};

const overflowDropdownStyle: React.CSSProperties = {
  position: "absolute",
  top: "100%",
  right: 0,
  minWidth: 180,
  maxWidth: 280,
  backgroundColor: tokens.colorNeutralBackground1,
  border: `1px solid ${tokens.colorNeutralStroke1}`,
  borderRadius: 4,
  boxShadow: tokens.shadow8,
  zIndex: 1000,
  padding: "4px 0",
};

const overflowItemStyle: React.CSSProperties = {
  padding: "6px 12px",
  fontSize: 12,
  cursor: "pointer",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};
