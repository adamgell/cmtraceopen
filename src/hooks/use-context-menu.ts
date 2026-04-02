import { useCallback } from "react";
import {
  Menu,
  MenuItem,
  PredefinedMenuItem,
} from "@tauri-apps/api/menu";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { invoke } from "@tauri-apps/api/core";
import { useFilterStore } from "../stores/filter-store";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import type { LogEntry } from "../types/log";

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) + "\u2026" : text;
}

function findErrorCode(entry: LogEntry): string | null {
  if (entry.errorCodeSpans && entry.errorCodeSpans.length > 0) {
    const span = entry.errorCodeSpans[0];
    return entry.message.slice(span.start, span.end);
  }
  return null;
}

function formatLine(entry: LogEntry): string {
  const parts: string[] = [];
  if (entry.timestampDisplay) parts.push(entry.timestampDisplay);
  if (entry.component) parts.push(entry.component);
  if (entry.threadDisplay) parts.push(entry.threadDisplay);
  parts.push(entry.message);
  return parts.join("\t");
}

export function useContextMenu() {
  const addQuickFilter = useFilterStore((s) => s.addQuickFilter);

  const showContextMenu = useCallback(
    async (entry: LogEntry, event: React.MouseEvent) => {
      event.preventDefault();

      const errorCode = findErrorCode(entry);
      const messagePreview = truncate(entry.message, 40);

      const items: (MenuItem | PredefinedMenuItem)[] = [
        await MenuItem.new({
          id: "copy-line",
          text: "Copy Line",
          action: () => {
            writeText(formatLine(entry));
          },
        }),
        await MenuItem.new({
          id: "copy-message",
          text: "Copy Message",
          action: () => {
            writeText(entry.message);
          },
        }),
      ];

      if (entry.timestampDisplay) {
        items.push(
          await MenuItem.new({
            id: "copy-timestamp",
            text: "Copy Timestamp",
            action: () => {
              writeText(entry.timestampDisplay!);
            },
          })
        );
      }

      items.push(await PredefinedMenuItem.new({ item: "Separator" }));

      items.push(
        await MenuItem.new({
          id: "include-filter",
          text: `Include: "${messagePreview}"`,
          action: () => {
            addQuickFilter("Message", entry.message, "Contains");
          },
        }),
        await MenuItem.new({
          id: "exclude-filter",
          text: `Exclude: "${messagePreview}"`,
          action: () => {
            addQuickFilter("Message", entry.message, "NotContains");
          },
        })
      );

      items.push(
        await MenuItem.new({
          id: "jump-to-line",
          text: "Jump to Line\u2026",
          action: () => {
            setTimeout(() => {
              const input = window.prompt("Jump to line:");
              if (!input) return;
              const targetLine = parseInt(input, 10);
              if (isNaN(targetLine)) return;
              const logState = useLogStore.getState();
              const entries = logState.entries;
              const target = entries.find((e) => e.lineNumber >= targetLine)
                ?? entries[entries.length - 1];
              if (target) {
                logState.selectEntry(target.id);
              }
            }, 0);
          },
        })
      );

      items.push(await PredefinedMenuItem.new({ item: "Separator" }));

      if (errorCode) {
        items.push(
          await MenuItem.new({
            id: "error-lookup",
            text: `Error Lookup: ${errorCode}`,
            action: () => {
              const uiState = useUiStore.getState();
              uiState.setLookupErrorCode(errorCode);
              uiState.setShowErrorLookupDialog(true);
            },
          })
        );
      }

      if (entry.sourceFile) {
        items.push(
          await MenuItem.new({
            id: "open-source-file",
            text: `Open Source File`,
            action: () => {
              invoke("reveal_in_file_manager", { path: entry.sourceFile! }).catch(console.error);
            },
          })
        );
      }

      const menu = await Menu.new({ items });
      await menu.popup();
    },
    [addQuickFilter]
  );

  return { showContextMenu };
}
