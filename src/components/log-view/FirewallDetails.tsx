import { useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import type { FirewallRecord } from "../../types/log";

export function FirewallDetails({ record }: { record: FirewallRecord }) {
  const [copyError, setCopyError] = useState(false);
  const copyRaw = async () => {
    try { await writeText(record.rawLine); setCopyError(false); }
    catch { setCopyError(true); }
  };
  return <section aria-label="Windows Firewall fields" style={{ marginBottom: 8 }}>
    <div>Time basis: {record.timeBasis === "utc" ? "UTC" : record.timeBasis === "local" ? "Local (source timezone unknown)" : "Unknown"}</div>
    <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", columnGap: 12, marginBlock: 8 }}>
      {record.fields.map((field, index) => <div key={index} style={{ display: "contents" }}>
        <dt>{field.name}</dt><dd style={{ margin: 0, overflowWrap: "anywhere" }}>{field.value ?? "Not present"}</dd>
      </div>)}
    </dl>
    {record.recordKind === "malformed" && <div>Fields could not be mapped. Declared fields: {record.declaredFields.join(" ") || "unavailable"}</div>}
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <strong>Raw line{record.truncated ? " (truncated at 65,536 decoded bytes)" : ""}</strong>
      <Button size="small" onClick={copyRaw}>{record.truncated ? "Copy raw line (truncated)" : "Copy raw line"}</Button>
    </div>
    {copyError && <div role="alert">Could not copy the raw line.</div>}
    <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", color: tokens.colorNeutralForeground1 }}>{record.rawLine}</pre>
  </section>;
}
