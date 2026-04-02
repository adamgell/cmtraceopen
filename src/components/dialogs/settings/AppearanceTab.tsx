import { useEffect, useState, useMemo } from "react";
import { tokens, Spinner } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import {
  DEFAULT_LOG_DETAILS_FONT_SIZE,
  DEFAULT_LOG_LIST_FONT_SIZE,
  MAX_LOG_DETAILS_FONT_SIZE,
  MAX_LOG_LIST_FONT_SIZE,
  MIN_LOG_DETAILS_FONT_SIZE,
  MIN_LOG_LIST_FONT_SIZE,
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../../lib/log-accessibility";
import { useUiStore } from "../../../stores/ui-store";
import { getThemeById, getAllThemes, type ThemeId } from "../../../lib/themes";

interface SystemFontList {
  families: string[];
}

export function AppearanceTab() {
  const logListFontSize = useUiStore((state) => state.logListFontSize);
  const logDetailsFontSize = useUiStore((state) => state.logDetailsFontSize);
  const fontFamily = useUiStore((state) => state.fontFamily);
  const themeId = useUiStore((state) => state.themeId);
  const setLogListFontSize = useUiStore((state) => state.setLogListFontSize);
  const setLogDetailsFontSize = useUiStore(
    (state) => state.setLogDetailsFontSize
  );
  const setFontFamily = useUiStore((state) => state.setFontFamily);
  const setThemeId = useUiStore((state) => state.setThemeId);
  const resetLogAccessibilityPreferences = useUiStore(
    (state) => state.resetLogAccessibilityPreferences
  );

  const [systemFonts, setSystemFonts] = useState<string[]>([]);
  const [fontsLoading, setFontsLoading] = useState(false);
  const [fontFilter, setFontFilter] = useState("");

  useEffect(() => {
    setFontsLoading(true);
    invoke<SystemFontList>("list_system_fonts")
      .then((result) => {
        setSystemFonts(result.families);
      })
      .catch((err) => {
        console.error("[appearance] failed to load system fonts", err);
        setSystemFonts([]);
      })
      .finally(() => {
        setFontsLoading(false);
      });
  }, []);

  const filteredFonts = useMemo(() => {
    if (!fontFilter.trim()) return systemFonts;
    const lower = fontFilter.toLowerCase();
    return systemFonts.filter((f) => f.toLowerCase().includes(lower));
  }, [systemFonts, fontFilter]);

  const allThemes = useMemo(() => getAllThemes(), []);
  const palette = getThemeById(themeId).severityPalette;

  return (
    <div>
      <section style={{ marginBottom: "14px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "6px" }}>
          Theme
        </div>
        <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginBottom: "6px" }}>
          Select the application color theme. Changes apply immediately.
        </div>
        <select
          value={themeId}
          onChange={(e) => setThemeId(e.target.value as ThemeId)}
          style={{
            width: "100%",
            padding: "4px 8px",
            fontSize: "12px",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "4px",
            background: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
          aria-label="Select application theme"
        >
          {allThemes.map((theme) => (
            <option key={theme.id} value={theme.id}>
              {theme.label}
            </option>
          ))}
        </select>
      </section>

      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "14px", lineHeight: 1.5 }}>
        Adjust log-reading text sizes independently and choose whether severity rows use classic CMTrace colors or a more accessible palette.
      </div>

      <section style={{ marginBottom: "14px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "6px" }}>
          Application text size
        </div>
        <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginBottom: "6px" }}>
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
        <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginTop: "4px" }}>
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
        <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "6px" }}>
          Font family
        </div>
        <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginBottom: "6px" }}>
          Choose a font for the entire application. Each font name is previewed in its own typeface.
        </div>
        <input
          type="text"
          placeholder="Filter fonts..."
          value={fontFilter}
          onChange={(e) => setFontFilter(e.target.value)}
          style={{
            width: "100%",
            padding: "4px 8px",
            fontSize: "12px",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "4px",
            background: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            marginBottom: "6px",
            outline: "none",
          }}
          aria-label="Filter font families"
        />
        <div
          style={{
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: "4px",
            maxHeight: "160px",
            overflowY: "auto",
            backgroundColor: tokens.colorNeutralBackground2,
          }}
        >
          {fontsLoading ? (
            <div
              style={{
                padding: "12px",
                textAlign: "center",
                fontSize: "12px",
                color: tokens.colorNeutralForeground3,
              }}
            >
              <Spinner size="tiny" label="Loading system fonts..." />
            </div>
          ) : (
            <>
              {/* Default (System) option */}
              <button
                type="button"
                onClick={() => setFontFamily(null)}
                style={{
                  display: "block",
                  width: "100%",
                  textAlign: "left",
                  padding: "4px 8px",
                  fontSize: "12px",
                  border: "none",
                  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                  background:
                    fontFamily === null
                      ? tokens.colorBrandBackground2
                      : "transparent",
                  color:
                    fontFamily === null
                      ? tokens.colorBrandForeground1
                      : tokens.colorNeutralForeground1,
                  fontWeight: fontFamily === null ? 600 : 400,
                  cursor: "pointer",
                }}
              >
                Default (System)
              </button>
              {filteredFonts.map((name) => (
                <button
                  type="button"
                  key={name}
                  onClick={() => setFontFamily(name)}
                  style={{
                    display: "block",
                    width: "100%",
                    textAlign: "left",
                    padding: "4px 8px",
                    fontSize: "12px",
                    border: "none",
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    background:
                      fontFamily === name
                        ? tokens.colorBrandBackground2
                        : "transparent",
                    color:
                      fontFamily === name
                        ? tokens.colorBrandForeground1
                        : tokens.colorNeutralForeground1,
                    fontWeight: fontFamily === name ? 600 : 400,
                    fontFamily: `'${name}', sans-serif`,
                    cursor: "pointer",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {name}
                </button>
              ))}
              {filteredFonts.length === 0 && !fontsLoading && (
                <div
                  style={{
                    padding: "8px",
                    textAlign: "center",
                    fontSize: "12px",
                    color: tokens.colorNeutralForeground3,
                  }}
                >
                  No fonts match the filter.
                </div>
              )}
            </>
          )}
        </div>
        {fontFamily && (
          <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginTop: "4px" }}>
            Selected: {fontFamily}
          </div>
        )}
      </section>

      <section style={{ marginBottom: "14px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "8px" }}>
          Severity colors
        </div>
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
          Severity colors are now controlled by the active theme. Use the theme picker in the toolbar to switch themes.
        </div>
      </section>

      <section
        style={{
          backgroundColor: tokens.colorNeutralBackground2,
          border: `1px solid ${tokens.colorNeutralStroke2}`,
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
            border: `1px solid ${tokens.colorNeutralStroke2}`,
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
            color: tokens.colorNeutralForeground1,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          }}
        >
          The details pane preview uses its own independent reading size.
        </div>
      </section>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
          Defaults: list {DEFAULT_LOG_LIST_FONT_SIZE}px, details {DEFAULT_LOG_DETAILS_FONT_SIZE}px
        </div>
        <button
          type="button"
          onClick={resetLogAccessibilityPreferences}
          style={{
            padding: "4px 12px",
            fontSize: "12px",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "4px",
            background: tokens.colorNeutralBackground3,
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          Reset Defaults
        </button>
      </div>
    </div>
  );
}
