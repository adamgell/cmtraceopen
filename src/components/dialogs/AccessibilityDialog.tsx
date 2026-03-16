import { useEffect, useRef } from "react";
import {
  DEFAULT_LOG_DETAILS_FONT_SIZE,
  DEFAULT_LOG_LIST_FONT_SIZE,
  MAX_LOG_DETAILS_FONT_SIZE,
  MAX_LOG_LIST_FONT_SIZE,
  MIN_LOG_DETAILS_FONT_SIZE,
  MIN_LOG_LIST_FONT_SIZE,
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";
import {
  type LogSeverityPaletteMode,
  getLogSeverityPalette,
} from "../../lib/constants";
import { useUiStore } from "../../stores/ui-store";

interface AccessibilityDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

const paletteOptions: Array<{
  value: LogSeverityPaletteMode;
  label: string;
  description: string;
}> = [
  {
    value: "classic",
    label: "Classic CMTrace",
    description: "Preserve CMTrace's original severity colors.",
  },
  {
    value: "accessible",
    label: "Accessible",
    description: "Use softer backgrounds and higher-contrast text.",
  },
];

export function AccessibilityDialog({ isOpen, onClose }: AccessibilityDialogProps) {
  const logListFontSize = useUiStore((state) => state.logListFontSize);
  const logDetailsFontSize = useUiStore((state) => state.logDetailsFontSize);
  const logSeverityPaletteMode = useUiStore(
    (state) => state.logSeverityPaletteMode
  );
  const setLogListFontSize = useUiStore((state) => state.setLogListFontSize);
  const setLogDetailsFontSize = useUiStore(
    (state) => state.setLogDetailsFontSize
  );
  const setLogSeverityPaletteMode = useUiStore(
    (state) => state.setLogSeverityPaletteMode
  );
  const resetLogAccessibilityPreferences = useUiStore(
    (state) => state.resetLogAccessibilityPreferences
  );
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (isOpen) {
      if (document.activeElement instanceof HTMLElement) {
        previouslyFocusedElementRef.current = document.activeElement;
      } else {
        previouslyFocusedElementRef.current = null;
      }
      const dialogNode = dialogRef.current;
      if (dialogNode) {
        dialogNode.focus();
      }
    } else {
      if (previouslyFocusedElementRef.current) {
        previouslyFocusedElementRef.current.focus();
      }
    }
  }, [isOpen]);

  if (!isOpen) {
    return null;
  }

  const palette = getLogSeverityPalette(logSeverityPaletteMode);

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(0,0,0,0.3)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Accessibility settings"
        tabIndex={-1}
        onKeyDown={(event) => {
          if (event.key !== "Tab") {
            return;
          }
          const dialogNode = dialogRef.current;
          if (!dialogNode) {
            return;
          }
          const focusableSelectors = [
            'a[href]',
            'button:not([disabled])',
            'textarea:not([disabled])',
            'input:not([disabled])',
            'select:not([disabled])',
            '[tabindex]:not([tabindex="-1"])',
          ];
          const focusableElements = Array.from(
            dialogNode.querySelectorAll<HTMLElement>(focusableSelectors.join(","))
          ).filter(
            (el) =>
              !el.hasAttribute("disabled") &&
              el.getAttribute("aria-hidden") !== "true"
          );
          if (focusableElements.length === 0) {
            event.preventDefault();
            dialogNode.focus();
            return;
          }
          const firstElement = focusableElements[0];
          const lastElement =
            focusableElements[focusableElements.length - 1];
          const activeElement = document.activeElement as HTMLElement | null;

          if (!event.shiftKey && activeElement === lastElement) {
            event.preventDefault();
            firstElement.focus();
          } else if (event.shiftKey && activeElement === firstElement) {
            event.preventDefault();
            lastElement.focus();
          }
        }}
        style={{
          backgroundColor: "#f0f0f0",
          border: "1px solid #999",
          borderRadius: "4px",
          padding: "16px",
          minWidth: "520px",
          maxWidth: "640px",
          boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
        }}
      >
        <div style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "4px" }}>
          Accessibility Settings
        </div>
        <div style={{ fontSize: "12px", color: "#555", marginBottom: "14px", lineHeight: 1.5 }}>
          Adjust log-reading text sizes independently and choose whether severity rows use classic CMTrace colors or a more accessible palette.
        </div>

        <section style={{ marginBottom: "14px" }}>
          <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "6px" }}>
            Application text size
          </div>
          <div style={{ fontSize: "11px", color: "#666", marginBottom: "6px" }}>
            Controls text size across log lists, Intune workspace, timelines, and evidence surfaces.
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <input
              type="range"
              min={MIN_LOG_LIST_FONT_SIZE}
              max={MAX_LOG_LIST_FONT_SIZE}
              value={logListFontSize}
              onChange={(event) => setLogListFontSize(Number(event.target.value))}
              style={{ flex: 1 }}
              aria-label={`Application text size: ${logListFontSize} pixels`}
            />
            <div style={{ width: "68px", textAlign: "right", fontSize: "12px" }}>
              {logListFontSize}px
            </div>
          </div>
          <div style={{ fontSize: "11px", color: "#666", marginTop: "4px" }}>
            Quick actions: Ctrl/Cmd + =, Ctrl/Cmd + -, Ctrl/Cmd + 0
          </div>
        </section>

        <section style={{ marginBottom: "14px" }}>
          <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "6px" }}>
            Details pane text size
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <input
              type="range"
              min={MIN_LOG_DETAILS_FONT_SIZE}
              max={MAX_LOG_DETAILS_FONT_SIZE}
              value={logDetailsFontSize}
              onChange={(event) => setLogDetailsFontSize(Number(event.target.value))}
              style={{ flex: 1 }}
            />
            <div style={{ width: "68px", textAlign: "right", fontSize: "12px" }}>
              {logDetailsFontSize}px
            </div>
          </div>
        </section>

        <section style={{ marginBottom: "14px" }}>
          <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "8px" }}>
            Severity colors
          </div>
          <div style={{ display: "grid", gap: "8px" }}>
            {paletteOptions.map((option) => (
              <label
                key={option.value}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "8px",
                  fontSize: "12px",
                  padding: "8px",
                  border: "1px solid #d1d5db",
                  borderRadius: "4px",
                  backgroundColor:
                    option.value === logSeverityPaletteMode ? "#eff6ff" : "#ffffff",
                }}
              >
                <input
                  type="radio"
                  name="log-severity-palette"
                  checked={logSeverityPaletteMode === option.value}
                  onChange={() => setLogSeverityPaletteMode(option.value)}
                />
                <span>
                  <strong>{option.label}</strong>
                  <span style={{ display: "block", color: "#555", marginTop: "2px" }}>
                    {option.description}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </section>

        <section
          style={{
            backgroundColor: "#ffffff",
            border: "1px solid #d1d5db",
            borderRadius: "4px",
            padding: "10px",
            marginBottom: "14px",
          }}
        >
          <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px" }}>Preview</div>
          <div
            style={{
              fontSize: `${logListFontSize}px`,
              lineHeight: 1.5,
              padding: "4px 6px",
              backgroundColor: palette.info.background,
              color: palette.info.text,
              border: "1px solid #e5e7eb",
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            }}
          >
            {`<![LOG[Preview message row]LOG]!><time="09:32:10.125+000" date="03-14-2026" component="Accessibility" thread="4412" type="1">`}
          </div>
          <div
            style={{
              fontSize: `${logDetailsFontSize}px`,
              lineHeight: 1.6,
              padding: "8px 6px 0 6px",
              color: "#111827",
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            }}
          >
            The details pane preview uses its own independent reading size.
          </div>
        </section>

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: "11px", color: "#666" }}>
            Defaults: list {DEFAULT_LOG_LIST_FONT_SIZE}px, details {DEFAULT_LOG_DETAILS_FONT_SIZE}px
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button onClick={resetLogAccessibilityPreferences}>Reset Defaults</button>
            <button onClick={onClose}>Close</button>
          </div>
        </div>
      </div>
    </div>
  );
}