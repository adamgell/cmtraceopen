import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button, Caption1, Subtitle2 } from "@fluentui/react-components";

import { ProfileDrilldown } from "../macos-diag";
import type { MacosMdmProfile } from "../macos-diag/types";
import { useJamfStore } from "./jamf-store";
import type { JamfProfilesResult } from "./types";

export function MacosJamfProfilesTab() {
  const slice = useJamfStore((s) => s.profiles);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);
  const orgFromEnv = useJamfStore((s) => s.environment.data?.mdmOrganization ?? null);
  const [selected, setSelected] = useState<MacosMdmProfile | null>(null);

  const reload = async () => {
    begin("profiles");
    try {
      const result = await invoke<JamfProfilesResult>("jamf_filter_profiles", {
        expectedOrganization: orgFromEnv,
      });
      finish("profiles", result);
    } catch (e) {
      fail("profiles", e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    if (slice.status === "idle") void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (slice.status === "loading") return <div>Listing profiles...</div>;
  if (slice.status === "error")
    return (
      <div>
        <div>Failed to list profiles: {slice.error}</div>
        <Button onClick={reload}>Retry</Button>
      </div>
    );

  const profiles = slice.data?.profiles ?? [];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 16 }}>
      <div>
        <Subtitle2>JAMF-deployed profiles</Subtitle2>
        <Caption1>{profiles.length} profile(s)</Caption1>
        <ul style={{ marginTop: 8, listStyle: "none", padding: 0 }}>
          {profiles.map((p) => (
            <li
              key={p.profileIdentifier}
              style={{
                cursor: "pointer",
                padding: "4px 8px",
                fontWeight: selected?.profileIdentifier === p.profileIdentifier ? 600 : 400,
              }}
              onClick={() => setSelected(p)}
            >
              {p.profileDisplayName}
            </li>
          ))}
        </ul>
      </div>
      <div>
        {selected ? (
          <ProfileDrilldown profile={selected} />
        ) : (
          <Caption1>Select a profile to view payloads.</Caption1>
        )}
      </div>
    </div>
  );
}
