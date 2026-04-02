import { useEffect, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { getVersion } from "@tauri-apps/api/app";
import { useUiStore } from "../../../stores/ui-store";

const SKIPPED_VERSION_KEY = "cmtraceopen-skipped-update-version";

function getSkippedVersion(): string | null {
  try {
    return localStorage.getItem(SKIPPED_VERSION_KEY);
  } catch {
    return null;
  }
}

function clearSkippedVersion(): void {
  try {
    localStorage.removeItem(SKIPPED_VERSION_KEY);
  } catch {
    // localStorage unavailable
  }
}

export function UpdatesTab() {
  const autoUpdateEnabled = useUiStore((state) => state.autoUpdateEnabled);
  const setAutoUpdateEnabled = useUiStore((state) => state.setAutoUpdateEnabled);

  const [appVersion, setAppVersion] = useState<string>("...");
  const [skippedVersion, setSkippedVersion] = useState<string | null>(null);

  useEffect(() => {
    getVersion()
      .then(setAppVersion)
      .catch(() => setAppVersion("unknown"));

    setSkippedVersion(getSkippedVersion());
  }, []);

  const handleClearSkipped = () => {
    clearSkippedVersion();
    setSkippedVersion(null);
  };

  return (
    <div>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "14px", lineHeight: 1.5 }}>
        Control automatic update checking and view version information.
      </div>

      <section style={{ marginBottom: "16px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "8px" }}>
          Version
        </div>
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground1 }}>
          CMTrace Open v{appVersion}
        </div>
      </section>

      <section style={{ marginBottom: "16px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "8px" }}>
          Automatic updates
        </div>
        <label
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: "8px",
            fontSize: "12px",
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={autoUpdateEnabled}
            onChange={(e) => setAutoUpdateEnabled(e.target.checked)}
            style={{ marginTop: "2px", cursor: "pointer" }}
          />
          <div>
            <div style={{ fontWeight: 600 }}>Check for updates on startup</div>
            <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginTop: "2px" }}>
              When enabled, CMTrace Open checks for new versions a few seconds after launch.
            </div>
          </div>
        </label>
      </section>

      {skippedVersion && (
        <section style={{ marginBottom: "16px" }}>
          <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "8px" }}>
            Skipped version
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              fontSize: "12px",
              color: tokens.colorNeutralForeground1,
            }}
          >
            <span>v{skippedVersion} is being skipped</span>
            <button
              type="button"
              onClick={handleClearSkipped}
              style={{
                padding: "3px 10px",
                fontSize: "11px",
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                borderRadius: "4px",
                background: tokens.colorNeutralBackground3,
                color: tokens.colorNeutralForeground1,
                cursor: "pointer",
              }}
            >
              Clear
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
