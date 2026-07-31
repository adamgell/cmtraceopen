import { Suspense, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

import { useJamfStore } from "./jamf-store";
import { MacosJamfTabStrip } from "./MacosJamfTabStrip";
import { MacosJamfEnvironmentBanner } from "./MacosJamfEnvironmentBanner";
import { MacosJamfOverviewTab } from "./MacosJamfOverviewTab";
import { MacosJamfLogsTab } from "./MacosJamfLogsTab";
import { MacosJamfPoliciesTab } from "./MacosJamfPoliciesTab";
import { MacosJamfProfilesTab } from "./MacosJamfProfilesTab";
import { MacosJamfSelfServiceTab } from "./MacosJamfSelfServiceTab";
import { MacosJamfConnectTab } from "./MacosJamfConnectTab";
import type { JamfEnvironment } from "./types";

export function MacosJamfWorkspace() {
  const activeTab = useJamfStore((s) => s.activeTab);
  const setActiveTab = useJamfStore((s) => s.setActiveTab);
  const envSlice = useJamfStore((s) => s.environment);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);

  const loadEnvironment = useCallback(async () => {
    begin("environment");
    try {
      const env = await invoke<JamfEnvironment>("jamf_collect_environment");
      finish("environment", env);
    } catch (e) {
      fail("environment", e instanceof Error ? e.message : String(e));
    }
  }, [begin, finish, fail]);

  useEffect(() => {
    if (envSlice.status !== "idle") return;
    void loadEnvironment();
  }, [envSlice.status, loadEnvironment]);

  const tabBody = (() => {
    switch (activeTab) {
      case "overview":
        return <MacosJamfOverviewTab />;
      case "logs":
        return <MacosJamfLogsTab />;
      case "policies":
        return <MacosJamfPoliciesTab />;
      case "profiles":
        return <MacosJamfProfilesTab />;
      case "self-service":
        return <MacosJamfSelfServiceTab />;
      case "connect":
        return <MacosJamfConnectTab />;
    }
  })();

  return (
    // The banner and tab strip stay put; only the tab body scrolls. Matches the
    // macOS Diagnostics shell, and is what keeps long tables usable.
    <div
      style={{
        padding: 16,
        display: "flex",
        flexDirection: "column",
        gap: 12,
        height: "100%",
        overflow: "hidden",
        boxSizing: "border-box",
      }}
    >
      <MacosJamfEnvironmentBanner
        environment={envSlice.data ?? null}
        loading={envSlice.status === "loading"}
        error={envSlice.status === "error" ? envSlice.error : null}
        onRetry={() => void loadEnvironment()}
      />
      <MacosJamfTabStrip active={activeTab} onChange={setActiveTab} />
      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        <Suspense fallback={<div>Loading...</div>}>{tabBody}</Suspense>
      </div>
    </div>
  );
}
