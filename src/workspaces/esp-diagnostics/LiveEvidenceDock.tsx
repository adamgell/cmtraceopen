import {
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent,
} from "react";
import { Button, tokens } from "@fluentui/react-components";
import {
  DismissRegular,
  FullScreenMaximizeRegular,
  FullScreenMinimizeRegular,
} from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import {
  ESP_EVIDENCE_DOCK_MIN_HEIGHT,
  getEspEvidenceDockMaxHeight,
  useEspDiagnosticsStore,
} from "./esp-diagnostics-store";
import { LiveEvidenceTable } from "./LiveEvidenceTable";
import type { EspDiagnosticsSnapshot } from "./types";

export interface LiveEvidenceDockProps {
  snapshot: EspDiagnosticsSnapshot | null;
}

/** Registry slot that binds the shared dock to the app-lifetime ESP store. */
export function EspLiveEvidenceDock() {
  const snapshot = useEspDiagnosticsStore((state) => state.snapshot);
  return <LiveEvidenceDock snapshot={snapshot} />;
}

const KEYBOARD_RESIZE_STEP = 24;

function workspaceHeight(element: HTMLElement | null): number {
  const measured = element?.parentElement?.getBoundingClientRect().height ?? 0;
  return measured > 0 ? measured : window.innerHeight;
}

export function LiveEvidenceDock({ snapshot }: LiveEvidenceDockProps) {
  const phase = useEspDiagnosticsStore((state) => state.phase);
  const viewMode = useEspDiagnosticsStore((state) => state.evidenceViewMode);
  const dockHeight = useEspDiagnosticsStore(
    (state) => state.evidenceDockHeight,
  );
  const unreadCount = useEspDiagnosticsStore(
    (state) => state.unreadEvidenceCount,
  );
  const boundaryMarkers = useEspDiagnosticsStore(
    (state) => state.evidenceBoundaryMarkers,
  );
  const recordRows = useEspDiagnosticsStore(
    (state) => state.evidenceRecordRows,
  );
  const setViewMode = useEspDiagnosticsStore(
    (state) => state.setEvidenceViewMode,
  );
  const setDockHeight = useEspDiagnosticsStore(
    (state) => state.setEvidenceDockHeight,
  );
  const markEvidenceRead = useEspDiagnosticsStore(
    (state) => state.markEvidenceRead,
  );
  const dockRef = useRef<HTMLElement>(null);
  const stopPointerResizeRef = useRef<(() => void) | null>(null);
  const [measuredWorkspaceHeight, setMeasuredWorkspaceHeight] = useState(() =>
    typeof window === "undefined" ? 0 : window.innerHeight,
  );

  useEffect(
    () => () => {
      stopPointerResizeRef.current?.();
    },
    [],
  );

  useEffect(() => {
    if (viewMode !== "collapsed") markEvidenceRead();
  }, [markEvidenceRead, viewMode]);

  useEffect(() => {
    if (viewMode !== "docked") stopPointerResizeRef.current?.();
  }, [viewMode]);

  useEffect(() => {
    if (viewMode !== "docked") return;

    const clampToWorkspace = () => {
      const availableHeight = workspaceHeight(dockRef.current);
      setMeasuredWorkspaceHeight(availableHeight);
      const state = useEspDiagnosticsStore.getState();
      setDockHeight(state.evidenceDockHeight, availableHeight);
    };
    clampToWorkspace();
    window.addEventListener("resize", clampToWorkspace);
    const parent = dockRef.current?.parentElement;
    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined" && parent) {
      observer = new ResizeObserver(clampToWorkspace);
      observer.observe(parent);
    }
    return () => {
      window.removeEventListener("resize", clampToWorkspace);
      observer?.disconnect();
    };
  }, [setDockHeight, viewMode]);

  if (viewMode === "collapsed") return null;

  const evidenceCount = snapshot?.rawEvidence.length ?? 0;
  const isLive =
    phase === "live" || phase === "starting" || phase === "stopping";
  const isFull = viewMode === "full";

  const resizeFromKeyboard = (event: KeyboardEvent<HTMLDivElement>) => {
    let nextHeight: number | null = null;
    const availableHeight = workspaceHeight(dockRef.current);
    switch (event.key) {
      case "ArrowUp":
        nextHeight = dockHeight + KEYBOARD_RESIZE_STEP;
        break;
      case "ArrowDown":
        nextHeight = dockHeight - KEYBOARD_RESIZE_STEP;
        break;
      case "Home":
        nextHeight = ESP_EVIDENCE_DOCK_MIN_HEIGHT;
        break;
      case "End":
        nextHeight = getEspEvidenceDockMaxHeight(availableHeight);
        break;
      default:
        return;
    }
    event.preventDefault();
    setDockHeight(nextHeight, availableHeight);
  };

  const startPointerResize = (event: PointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    stopPointerResizeRef.current?.();
    const startY = event.clientY;
    const startHeight = dockHeight;
    const pointerId = event.pointerId;

    const move = (moveEvent: globalThis.PointerEvent) => {
      if (pointerId && moveEvent.pointerId && moveEvent.pointerId !== pointerId)
        return;
      setDockHeight(
        startHeight + startY - moveEvent.clientY,
        workspaceHeight(dockRef.current),
      );
    };
    const cleanup = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", stop);
      window.removeEventListener("pointercancel", stop);
      if (stopPointerResizeRef.current === cleanup) {
        stopPointerResizeRef.current = null;
      }
    };
    const stop = (upEvent: globalThis.PointerEvent) => {
      if (pointerId && upEvent.pointerId && upEvent.pointerId !== pointerId)
        return;
      cleanup();
    };

    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop);
    window.addEventListener("pointercancel", stop);
    stopPointerResizeRef.current = cleanup;
  };

  return (
    <section
      ref={dockRef}
      role="region"
      aria-label="Live evidence and logs"
      data-view-mode={viewMode}
      style={{
        position: isFull ? "absolute" : "relative",
        inset: isFull ? 0 : undefined,
        zIndex: isFull ? 10 : 4,
        display: "grid",
        gridTemplateRows: "auto minmax(0, 1fr)",
        width: "100%",
        minWidth: 0,
        height: isFull ? "100%" : `${dockHeight}px`,
        minHeight: isFull ? 0 : ESP_EVIDENCE_DOCK_MIN_HEIGHT,
        flex: isFull ? "1 1 auto" : "0 0 auto",
        overflow: "hidden",
        borderTop: `1px solid ${tokens.colorNeutralStrokeAccessible}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: isFull ? "none" : `0 -6px 18px rgba(0, 0, 0, 0.2)`,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      {!isFull ? (
        <div
          role="separator"
          aria-label="Resize live evidence and logs"
          aria-orientation="horizontal"
          aria-valuemin={ESP_EVIDENCE_DOCK_MIN_HEIGHT}
          aria-valuemax={getEspEvidenceDockMaxHeight(measuredWorkspaceHeight)}
          aria-valuenow={dockHeight}
          tabIndex={0}
          onKeyDown={resizeFromKeyboard}
          onPointerDown={startPointerResize}
          title="Drag or use arrow keys to resize live logs"
          style={{
            position: "absolute",
            zIndex: 6,
            top: 0,
            left: 0,
            width: "100%",
            height: 7,
            cursor: "ns-resize",
            touchAction: "none",
          }}
        >
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              top: 2,
              left: "50%",
              width: 44,
              height: 2,
              borderRadius: 2,
              backgroundColor: tokens.colorNeutralStrokeAccessible,
              transform: "translateX(-50%)",
            }}
          />
        </div>
      ) : null}

      <header
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          minWidth: 0,
          minHeight: 40,
          padding: "6px 8px 6px 10px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
          background: `linear-gradient(90deg, ${tokens.colorNeutralBackground3}, ${tokens.colorNeutralBackground1})`,
        }}
      >
        <span
          aria-hidden="true"
          style={{
            width: 9,
            height: 9,
            flex: "0 0 auto",
            borderRadius: "50%",
            backgroundColor: isLive
              ? tokens.colorPaletteGreenBackground3
              : tokens.colorNeutralForegroundDisabled,
            boxShadow: isLive
              ? `0 0 0 3px ${tokens.colorPaletteGreenBackground2}`
              : "none",
          }}
        />
        <div style={{ minWidth: 0 }}>
          <strong
            style={{ display: "block", fontSize: 12, lineHeight: "15px" }}
          >
            Live Evidence &amp; Logs
          </strong>
          <span
            style={{
              display: "block",
              overflow: "hidden",
              color: tokens.colorNeutralForeground3,
              fontSize: 10,
              lineHeight: "13px",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {isLive ? "Live collection active" : "Evidence viewer"} · collection
            continues when hidden
          </span>
        </div>
        <span
          aria-label={`${evidenceCount} evidence records${unreadCount ? `, ${unreadCount} unread` : ""}`}
          style={{
            marginLeft: 4,
            padding: "2px 7px",
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: 10,
            backgroundColor: tokens.colorNeutralBackground3,
            color: tokens.colorNeutralForeground2,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
          }}
        >
          {evidenceCount.toLocaleString()}
        </span>
        <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
          {isFull ? (
            <Button
              size="small"
              appearance="subtle"
              icon={<FullScreenMinimizeRegular />}
              onClick={() => setViewMode("docked")}
            >
              Restore docked live logs
            </Button>
          ) : (
            <Button
              size="small"
              appearance="subtle"
              icon={<FullScreenMaximizeRegular />}
              onClick={() => setViewMode("full")}
            >
              Expand live logs
            </Button>
          )}
          <Button
            size="small"
            appearance="subtle"
            icon={<DismissRegular />}
            aria-label="Close live logs"
            onClick={() => setViewMode("collapsed")}
          />
        </div>
      </header>

      <LiveEvidenceTable
        snapshot={snapshot}
        boundaryMarkers={boundaryMarkers}
        recordRows={recordRows}
      />
    </section>
  );
}
