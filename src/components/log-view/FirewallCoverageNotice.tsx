import { tokens } from "@fluentui/react-components";
import { useLogStore } from "../../stores/log-store";
import type { FirewallSourceState } from "../../stores/firewall-state";

function coverageText(source: FirewallSourceState): string {
  const c = source.coverage, parts: string[] = [];
  const add = (count: string, label: string) => { if (count !== "0") parts.push(`${count} ${label}`); };
  add(c.padding.count, "NUL padding characters skipped");
  add(c.malformed.count, "malformed rows");
  add(c.oversized.count, "oversized rows (raw text truncated)");
  add(c.lossEvents.count, "loss events");
  add(c.lostEvents.count, "known lost events");
  add(c.unknownLossCount.count, "loss event with unknown count");
  add(c.unplacedTimestamps.count, "without absolute time (excluded from timeline)");
  if (source.decoding.kind === "pending") parts.push(`${source.decoding.pendingBytes} undecoded bytes awaiting append`);
  if (source.decoding.kind === "gap") {
    const reason = source.decoding.reason === "invalidEncoding" ? "invalid encoding"
      : source.decoding.reason === "readFailed" ? "source could not be read"
      : source.decoding.reason === "generationUnverifiable" ? "source generation could not be verified"
      : "reason unavailable";
    parts.push(`Decoding gap: ${reason}. Reopen the source when resolved.`);
  }
  return parts.join("; ");
}

export function FirewallCoverageNotice() {
  const sources = useLogStore(s => s.firewallSources);
  const path = useLogStore(s => s.openFilePath);
  const files = useLogStore(s => s.aggregateFiles);
  const mode = useLogStore(s => s.sourceOpenMode);
  const paths = mode === "aggregate-folder" ? files.map(file => file.filePath) : path ? [path] : [];
  const notices = paths.flatMap(filePath => {
    const source = sources[filePath];
    const text = source && coverageText(source);
    return text ? [{ filePath, text }] : [];
  });
  if (notices.length === 0) return null;
  return <div role="status" aria-label="Windows Firewall coverage" style={{ padding: "4px 8px", fontSize: 12, backgroundColor: tokens.colorNeutralBackground3, flexShrink: 0 }}>
    {notices.map(({ filePath, text }) => <div key={filePath}>{paths.length > 1 ? `${filePath}: ` : "Windows Firewall: "}{text}</div>)}
  </div>;
}
