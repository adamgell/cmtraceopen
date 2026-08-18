import { useCallback } from "react";
import { tokens, Button } from "@fluentui/react-components";
import { DismissRegular } from "@fluentui/react-icons";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { useDnsDhcpStore } from "../../workspaces/dns-dhcp/dns-dhcp-store";
import type { ParserKind } from "../../types/log";

const PARSER_LABELS: Partial<Record<ParserKind, string>> = {
  dnsDebug: "DNS debug log",
  dnsAudit: "DNS audit log",
  dhcp: "DHCP server log",
};

const DNS_PARSER_KINDS = new Set<ParserKind>(["dnsDebug", "dnsAudit", "dhcp"]);

export function DnsWorkspaceBanner() {
  const parserSelection = useLogStore((s) => s.parserSelection);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const activeWorkspace = useUiStore((s) => s.activeWorkspace);
  const dismissedDnsBannerPath = useUiStore((s) => s.dismissedDnsBannerPath);
  const setDismissedDnsBannerPath = useUiStore((s) => s.setDismissedDnsBannerPath);

  const parser = parserSelection?.parser;
  const label = parser ? PARSER_LABELS[parser] : undefined;
  const dismissed = openFilePath !== null && dismissedDnsBannerPath === openFilePath;

  const handleOpenInWorkspace = useCallback(() => {
    const logState = useLogStore.getState();
    const { openFilePath, entries, formatDetected } = logState;

    if (!openFilePath || !formatDetected) return;

    const fileName = openFilePath.split(/[\\/]/).pop() ?? openFilePath;
    useDnsDhcpStore.getState().addSource(openFilePath, fileName, formatDetected, entries);
    useUiStore.getState().ensureWorkspaceVisible("dns-dhcp", "banner");
  }, []);

  if (!label || dismissed || activeWorkspace !== "log" || !parser || !DNS_PARSER_KINDS.has(parser)) {
    return null;
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "6px 12px",
        background: tokens.colorNeutralBackground4,
        borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
        fontSize: 13,
        color: tokens.colorNeutralForeground2,
        flexShrink: 0,
      }}
    >
      <span>
        This looks like a {label}. Open in the DNS/DHCP workspace for device correlation and query analysis?
      </span>
      <Button size="small" appearance="primary" onClick={handleOpenInWorkspace}>
        Open in workspace
      </Button>
      <Button
        size="small"
        appearance="subtle"
        icon={<DismissRegular />}
        onClick={() => {
          if (openFilePath) setDismissedDnsBannerPath(openFilePath);
        }}
        aria-label="Dismiss"
      />
    </div>
  );
}
