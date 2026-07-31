import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button, Caption1, Subtitle2 } from "@fluentui/react-components";

// Imported from the module, not the ../macos-diag barrel: the barrel also
// constructs macosDiagWorkspace, so going through it makes this workspace
// re-enter macos-diag/index.ts mid-initialization and throws
// "Cannot access 'macosDiagWorkspace' before initialization" at runtime.
import { ProfileDrilldown } from "../macos-diag/ProfileDrilldown";
import type { MacosMdmProfile } from "../macos-diag/types";
import { useJamfStore } from "./jamf-store";
import type { JamfProfilesResult } from "./types";

export function MacosJamfProfilesTab() {
  const slice = useJamfStore((s) => s.profiles);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);
  const mdmOrg = useJamfStore((s) => s.environment.data?.mdmOrganization ?? null);
  const jamfInstalled = useJamfStore((s) => s.environment.data?.jamfInstalled ?? false);
  const envStatus = useJamfStore((s) => s.environment.status);
  const [selected, setSelected] = useState<MacosMdmProfile | null>(null);

  // The MDM organization matches every profile that MDM deployed, which is the
  // right answer only when the MDM in question is JAMF. On a Mac managed by
  // something else it would relabel that vendor's profiles as JAMF-deployed, so
  // fall back to JAMF-specific payload matching alone.
  const orgFromEnv = jamfInstalled ? mdmOrg : null;

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

  // Wait for the environment before the first fetch: `expectedOrganization`
  // comes from it, and firing on mount pinned the request to a null org.
  useEffect(() => {
    if (envStatus !== "loading" && slice.status === "idle") void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [envStatus]);

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
