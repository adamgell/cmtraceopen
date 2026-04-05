import { type CSSProperties, type KeyboardEvent, type MouseEvent as ReactMouseEvent, useCallback, useEffect, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";

/** Minimum width a tab can shrink to before being pushed to overflow */
const MIN_TAB_WIDTH = 100;
/** Width reserved for the overflow chevron button */
const OVERFLOW_BUTTON_WIDTH = 36;

export function TabStrip() {
  const openTabs = useUiStore((s) => s.openTabs);
  const activeTabIndex = useUiStore((s) => s.activeTabIndex);
  const switchTab = useUiStore((s) => s.switchTab);
  const closeTab = useUiStore((s) => s.closeTab);

  const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  const mergedTabState = useLogStore((s) => s.mergedTabState);
  const closeMergedTab = useLogStore((s) => s.closeMergedTab);
  const closeDiff = useLogStore((s) => s.closeDiff);

  const [hoveredTabIndex, setHoveredTabIndex] = useState<number | null>(null);
  const [overflowOpen, setOverflowOpen] = useState(false);
  const [visibleCount, setVisibleCount] = useState(openTabs.length);

  const stripRef = useRef<HTMLDivElement>(null);
  const overflowRef = useRef<HTMLDivElement>(null);
  const tabRefs = useRef<(HTMLDivElement | null)[]>([]);

  // Measure available width and compute how many tabs fit
  useEffect(() => {
    const el = stripRef.current;
    if (!el) return;

    const computeVisible = () => {
      const containerWidth = el.clientWidth;
      if (openTabs.length === 0) {
        setVisibleCount(0);
        return;
      }

      // Try fitting all tabs first
      const widthPerTab = containerWidth / openTabs.length;
      if (widthPerTab >= MIN_TAB_WIDTH) {
        setVisibleCount(openTabs.length);
        return;
      }

      // Reserve space for the overflow button, then fit as many as possible
      const availableWidth = containerWidth - OVERFLOW_BUTTON_WIDTH;
      const count = Math.max(1, Math.floor(availableWidth / MIN_TAB_WIDTH));
      setVisibleCount(Math.min(count, openTabs.length));
    };

    computeVisible();

    const observer = new ResizeObserver(computeVisible);
    observer.observe(el);
    return () => observer.disconnect();
  }, [openTabs.length]);

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
    (e: ReactMouseEvent, index: number) => {
      e.stopPropagation();
      if (sourceOpenMode === "merged" && index === activeTabIndex) {
        closeMergedTab();
        return;
      }
      closeTab(index);
    },
    [closeTab, sourceOpenMode, activeTabIndex, closeMergedTab]
  );

  const handleToggleOverflow = useCallback(
    (e: ReactMouseEvent) => {
      e.stopPropagation();
      setOverflowOpen((prev) => !prev);
    },
    []
  );

  const handleTabKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>, index: number) => {
      const vc = Math.min(openTabs.length, visibleCount);
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        switchTab(index);
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        const next = (index + 1) % vc;
        switchTab(next);
        tabRefs.current[next]?.focus();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        const prev = (index - 1 + vc) % vc;
        switchTab(prev);
        tabRefs.current[prev]?.focus();
      } else if (e.key === "Home") {
        e.preventDefault();
        switchTab(0);
        tabRefs.current[0]?.focus();
      } else if (e.key === "End") {
        e.preventDefault();
        const last = vc - 1;
        switchTab(last);
        tabRefs.current[last]?.focus();
      }
    },
    [openTabs.length, visibleCount, switchTab]
  );

  const handleOverflowSelect = useCallback(
    (index: number) => {
      switchTab(index);
      setOverflowOpen(false);
    },
    [switchTab]
  );

  const handleOverflowClose = useCallback(
    (e: ReactMouseEvent, index: number) => {
      e.stopPropagation();
      if (sourceOpenMode === "merged" && index === activeTabIndex) {
        closeMergedTab();
        return;
      }
      if (sourceOpenMode === "diff" && index === activeTabIndex) {
        closeDiff();
        return;
      }
      closeTab(index);
    },
    [closeTab, sourceOpenMode, activeTabIndex, closeMergedTab, closeDiff]
  );

  if (openTabs.length === 0) {
    return null;
  }

  const visibleTabs = openTabs.slice(0, visibleCount);
  const overflowTabs = openTabs.slice(visibleCount);
  const hasOverflow = overflowTabs.length > 0;
  const focusableIndex = activeTabIndex < visibleCount ? activeTabIndex : 0;

  tabRefs.current.length = visibleTabs.length;

  return (
    <div style={outerStripStyle}>
      {/* Tabs area: clipped so extra tabs don't spill */}
      <div ref={stripRef} role="tablist" aria-label="Open log files" style={tabsAreaStyle}>
        {visibleTabs.map((tab, index) => {
          const isActive = index === activeTabIndex;
          const isHovered = index === hoveredTabIndex;

          return (
            <div
              key={tab.id}
              ref={(el) => { tabRefs.current[index] = el; }}
              role="tab"
              aria-selected={isActive}
              tabIndex={index === focusableIndex ? 0 : -1}
              style={{
                ...tabStyle,
                ...(isActive ? activeTabStyle : inactiveTabStyle),
                flex: hasOverflow ? `0 0 ${MIN_TAB_WIDTH}px` : "1 1 0",
                maxWidth: hasOverflow ? undefined : 200,
              }}
              onClick={() => handleSwitchTab(index)}
              onKeyDown={(e) => handleTabKeyDown(e, index)}
              onMouseEnter={() => setHoveredTabIndex(index)}
              onMouseLeave={() => setHoveredTabIndex(null)}
            >
              <span style={tabLabelStyle}>
                {sourceOpenMode === "merged" && index === activeTabIndex && mergedTabState ? (
                  <span title={mergedTabState.sourceFilePaths.join("\n")}>
                    Merged ({mergedTabState.sourceFilePaths.length} files)
                  </span>
                ) : (
                  tab.fileName
                )}
              </span>
              <button
                aria-label={`Close ${tab.fileName}`}
                style={{
                  ...closeButtonBaseStyle,
                  visibility: isHovered || isActive ? "visible" : "hidden",
                }}
                onClick={(e) => handleCloseTab(e, index)}
              >
                ×
              </button>
            </div>
          );
        })}
      </div>
      {/* Overflow chevron: sits outside the clipped area so dropdown isn't clipped */}
      {hasOverflow && (
        <div ref={overflowRef} style={overflowContainerStyle}>
          <button
            style={overflowChevronStyle}
            aria-haspopup="listbox"
            aria-expanded={overflowOpen}
            aria-label={`${overflowTabs.length} more tabs`}
            title={`${overflowTabs.length} more tabs`}
            onClick={handleToggleOverflow}
          >
            <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
              <path d="M2.5 4.5L6 8L9.5 4.5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
          {overflowOpen && (
            <div role="listbox" style={overflowDropdownStyle}>
              {overflowTabs.map((tab, i) => {
                const realIndex = visibleCount + i;
                const isActive = realIndex === activeTabIndex;
                return (
                  <div
                    key={tab.id}
                    role="option"
                    aria-selected={isActive}
                    style={{
                      ...overflowItemStyle,
                      backgroundColor: isActive
                        ? tokens.colorNeutralBackground1Selected
                        : "transparent",
                      fontWeight: isActive ? 600 : 400,
                    }}
                    onClick={() => handleOverflowSelect(realIndex)}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLDivElement).style.backgroundColor =
                        tokens.colorNeutralBackground1Hover;
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLDivElement).style.backgroundColor =
                        isActive ? tokens.colorNeutralBackground1Selected : "transparent";
                    }}
                  >
                    <span style={overflowItemLabelStyle}>{tab.fileName}</span>
                    <button
                      aria-label={`Close ${tab.fileName}`}
                      style={overflowItemCloseStyle}
                      onClick={(e) => handleOverflowClose(e, realIndex)}
                    >
                      ×
                    </button>
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

/** Outer wrapper: flex row, no clipping so the overflow dropdown can escape */
const outerStripStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  height: 34,
  backgroundColor: tokens.colorNeutralBackground3,
  borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  flexShrink: 0,
};

/** Inner tab area: clips so tabs don't spill past the measured width */
const tabsAreaStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  height: "100%",
  flex: 1,
  minWidth: 0,
  overflow: "hidden",
};

const tabStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 4,
  height: "100%",
  minWidth: 0,
  padding: "0 8px",
  cursor: "pointer",
  boxSizing: "border-box",
  userSelect: "none",
  fontSize: 12,
  fontFamily: "inherit",
};

const activeTabStyle: CSSProperties = {
  backgroundColor: tokens.colorNeutralBackground1,
  color: tokens.colorNeutralForeground1,
  borderBottom: `2px solid ${tokens.colorBrandBackground}`,
};

const inactiveTabStyle: CSSProperties = {
  backgroundColor: "transparent",
  color: tokens.colorNeutralForeground3,
};

const tabLabelStyle: CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  flex: 1,
  minWidth: 0,
};

const closeButtonBaseStyle: CSSProperties = {
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
  border: "none",
  background: "none",
  padding: 0,
  color: "inherit",
  fontFamily: "inherit",
};

const overflowContainerStyle: CSSProperties = {
  position: "relative",
  height: "100%",
  display: "flex",
  alignItems: "center",
  flexShrink: 0,
};

const overflowChevronStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  width: OVERFLOW_BUTTON_WIDTH,
  height: "100%",
  cursor: "pointer",
  border: "none",
  background: "none",
  color: tokens.colorNeutralForeground3,
  padding: 0,
};

const overflowDropdownStyle: CSSProperties = {
  position: "absolute",
  top: "100%",
  right: 0,
  minWidth: 200,
  maxWidth: 300,
  backgroundColor: tokens.colorNeutralBackground1,
  border: `1px solid ${tokens.colorNeutralStroke1}`,
  borderRadius: 4,
  boxShadow: tokens.shadow8,
  zIndex: 1000,
  padding: "4px 0",
};

const overflowItemStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  padding: "6px 12px",
  fontSize: 12,
  cursor: "pointer",
  color: tokens.colorNeutralForeground1,
  gap: 8,
};

const overflowItemLabelStyle: CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  flex: 1,
  minWidth: 0,
};

const overflowItemCloseStyle: CSSProperties = {
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
  border: "none",
  background: "none",
  padding: 0,
  color: tokens.colorNeutralForeground3,
};
