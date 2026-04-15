// src/workspaces/dns-dhcp/index.ts
import { startTransition, lazy } from "react";
import type { WorkspaceDefinition } from "../types";
import { useUiStore } from "../../stores/ui-store";
import { getLogSourcePath } from "../../lib/log-source";
import { openLogFile } from "../../lib/commands";

export const dnsDhcpWorkspace: WorkspaceDefinition = {
  id: "dns-dhcp",
  label: "DNS / DHCP",
  platforms: "all",
  component: lazy(() =>
    import("./DnsDhcpWorkspace").then((m) => ({
      default: m.DnsDhcpWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("./DnsDhcpSidebar").then((m) => ({
      default: m.DnsDhcpSidebar,
    }))
  ),
  capabilities: { fontSizing: true },
  fileFilters: [
    { name: "DNS/DHCP Logs", extensions: ["log", "evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open DNS/DHCP File",
    folder: "Open Log Folder",
    placeholder: "Open DNS or DHCP logs...",
  },
  onOpenSource: async (source, trigger) => {
    const { useDnsDhcpStore } = await import("./dns-dhcp-store");

    useUiStore.getState().ensureWorkspaceVisible("dns-dhcp", trigger);

    const sourcePath = getLogSourcePath(source);
    const fileName = sourcePath.split(/[\\/]/).pop() ?? sourcePath;

    useDnsDhcpStore.getState().setLoading(true);
    useDnsDhcpStore.getState().setLoadError(null);

    try {
      const result = await openLogFile(sourcePath);
      const format = result.formatDetected;

      // Accept DnsDebug, DnsAudit, or entries that have ipAddress (DHCP)
      const isDns = format === "DnsDebug" || format === "DnsAudit";
      const hasDhcp = result.entries.some((e) => e.ipAddress != null);

      if (!isDns && !hasDhcp) {
        useDnsDhcpStore.getState().setLoadError(
          `Unsupported format "${format}". Expected DNS debug/audit logs or DHCP logs.`
        );
        useDnsDhcpStore.getState().setLoading(false);
        return;
      }

      startTransition(() => {
        useDnsDhcpStore.getState().addSource(sourcePath, fileName, format, result.entries);
        useDnsDhcpStore.getState().setLoading(false);
      });
    } catch (error) {
      console.error("[dns-dhcp] failed to open source", { source, trigger, error });
      useDnsDhcpStore.getState().setLoadError(
        error instanceof Error ? error.message : String(error)
      );
      useDnsDhcpStore.getState().setLoading(false);
    }
  },
  onOpenPath: async (path) => {
    const { useDnsDhcpStore } = await import("./dns-dhcp-store");

    const fileName = path.split(/[\\/]/).pop() ?? path;

    useDnsDhcpStore.getState().setLoading(true);
    useDnsDhcpStore.getState().setLoadError(null);

    try {
      const result = await openLogFile(path);
      const format = result.formatDetected;

      const isDns = format === "DnsDebug" || format === "DnsAudit";
      const hasDhcp = result.entries.some((e) => e.ipAddress != null);

      if (!isDns && !hasDhcp) {
        useDnsDhcpStore.getState().setLoadError(
          `Unsupported format "${format}". Expected DNS debug/audit logs or DHCP logs.`
        );
        useDnsDhcpStore.getState().setLoading(false);
        return;
      }

      startTransition(() => {
        useDnsDhcpStore.getState().addSource(path, fileName, format, result.entries);
        useDnsDhcpStore.getState().setLoading(false);
      });
    } catch (error) {
      console.error("[dns-dhcp] failed to open path", { path, error });
      useDnsDhcpStore.getState().setLoadError(
        error instanceof Error ? error.message : String(error)
      );
      useDnsDhcpStore.getState().setLoading(false);
    }
  },
};
