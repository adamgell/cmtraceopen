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
import { useMarkerStore } from "../stores/marker-store";
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

      // Marker state — use entry.filePath as the canonical key
      const markerState = useMarkerStore.getState();
      const entryFilePath = entry.filePath;
      const fileMarkers = markerState.markersByFile.get(entryFilePath);
      const existingMarker = fileMarkers?.get(entry.id);

      const items: (MenuItem | PredefinedMenuItem)[] = [
        await MenuItem.new({
          id: "copy-line",
          text: "Copy Line",
          action: () => {
            writeText(formatLine(entry)).catch(console.error);
          },
        }),
        await MenuItem.new({
          id: "copy-message",
          text: "Copy Message",
          action: () => {
            writeText(entry.message).catch(console.error);
          },
        }),
      ];

      if (entry.timestampDisplay) {
        items.push(
          await MenuItem.new({
            id: "copy-timestamp",
            text: "Copy Timestamp",
            action: () => {
              writeText(entry.timestampDisplay!).catch(console.error);
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

      // ── Marker actions ──
      // Always show marker items — actions use entry.filePath directly.
      {
        const categories = markerState.categories;
        if (existingMarker) {
          // Show current category and option to remove
          const currentCat = categories.find((c) => c.id === existingMarker.category);
          items.push(
            await MenuItem.new({
              id: "marker-remove",
              text: `Remove Marker (${currentCat?.label ?? existingMarker.category})`,
              action: () => {
                const fp = entry.filePath;
                if (!fp) return;
                useMarkerStore.getState().toggleMarker(fp, entry.id);
                useMarkerStore.getState().saveMarkers(fp);
              },
            })
          );
          // Show category options to change
          for (const cat of categories) {
            if (cat.id === existingMarker.category) continue;
            const catId = cat.id;
            items.push(
              await MenuItem.new({
                id: `marker-set-${catId}`,
                text: `Change to ${cat.label}`,
                action: () => {
                  const fp = entry.filePath;
                  if (!fp) return;
                  useMarkerStore.getState().setMarkerCategory(fp, entry.id, catId);
                  useMarkerStore.getState().saveMarkers(fp);
                },
              })
            );
          }
        } else {
          // Show options to mark with each category
          for (const cat of categories) {
            // Capture cat.id in a local const so the closure gets the right value
            const catId = cat.id;
            items.push(
              await MenuItem.new({
                id: `marker-add-${catId}`,
                text: `Mark as ${cat.label}`,
                action: () => {
                  const fp = entry.filePath;
                  if (!fp) return;
                  const store = useMarkerStore.getState();
                  store.setActiveCategory(catId);
                  store.toggleMarker(fp, entry.id);
                  store.saveMarkers(fp);
                },
              })
            );
          }
        }

        items.push(await PredefinedMenuItem.new({ item: "Separator" }));
      }

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
