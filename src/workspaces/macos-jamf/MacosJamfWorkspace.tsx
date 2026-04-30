import { Suspense, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

import { useJamfStore } from "./jamf-store";
import { MacosJamfTabStrip } from "./MacosJamfTabStrip";
import { MacosJamfEnvironmentBanner } from "./MacosJamfEnvironmentBanner";
import { MacosJamfOverviewTab } from "./MacosJamfOverviewTab";
import { MacosJamfLogsTab } from "./MacosJamfLogsTab";
import type { JamfEnvironment } from "./types";

const Placeholder = ({ label }: { label: string }) => (
  <div style={{ padding: 24, color: "var(--colorNeutralForeground3)" }}>
    {label} tab - implemented in a later phase.
  </div>
);

export function MacosJamfWorkspace() {
  const activeTab = useJamfStore((s) => s.activeTab);
  const setActiveTab = useJamfStore((s) => s.setActiveTab);
  const envSlice = useJamfStore((s) => s.environment);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);

  useEffect(() => {
    if (envSlice.status !== "idle") return;
    void (async () => {
      begin("environment");
      try {
        const env = await invoke<JamfEnvironment>("jamf_collect_environment");
        finish("environment", env);
      } catch (e) {
        fail("environment", e instanceof Error ? e.message : String(e));
      }
    })();
  }, [envSlice.status, begin, finish, fail]);

  const tabBody = (() => {
    switch (activeTab) {
      case "overview":
        return <MacosJamfOverviewTab />;
      case "logs":
        return <MacosJamfLogsTab />;
      case "policies":
        return <Placeholder label="Policies" />;
      case "profiles":
        return <Placeholder label="Profiles" />;
      case "self-service":
        return <Placeholder label="Self Service" />;
      case "connect":
        return <Placeholder label="JAMF Connect" />;
    }
  })();

  return (
    <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>
      <MacosJamfEnvironmentBanner
        environment={envSlice.data ?? null}
        loading={envSlice.status === "loading"}
      />
      <MacosJamfTabStrip active={activeTab} onChange={setActiveTab} />
      <Suspense fallback={<div>Loading...</div>}>{tabBody}</Suspense>
    </div>
  );
}
