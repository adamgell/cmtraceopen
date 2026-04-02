import { useEffect, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../stores/ui-store";
import { AppearanceTab } from "./settings/AppearanceTab";
import { ColumnsTab } from "./settings/ColumnsTab";
import { BehaviorTab } from "./settings/BehaviorTab";
import { UpdatesTab } from "./settings/UpdatesTab";
import { FileAssociationsTab } from "./settings/FileAssociationsTab";

type SettingsTabId = "appearance" | "columns" | "behavior" | "updates" | "file-associations";

interface TabDef {
  id: SettingsTabId;
  label: string;
  windowsOnly?: boolean;
}

const TABS: TabDef[] = [
  { id: "appearance", label: "Appearance" },
  { id: "columns", label: "Columns" },
  { id: "behavior", label: "Behavior" },
  { id: "updates", label: "Updates" },
  { id: "file-associations", label: "File Associations", windowsOnly: true },
];

interface SettingsDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function SettingsDialog({ isOpen, onClose }: SettingsDialogProps) {
  const currentPlatform = useUiStore((state) => state.currentPlatform);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);
  const [activeTab, setActiveTab] = useState<SettingsTabId>("appearance");

  const visibleTabs = TABS.filter(
    (tab) => !tab.windowsOnly || currentPlatform === "windows"
  );

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (isOpen) {
      if (document.activeElement instanceof HTMLElement) {
        previouslyFocusedElementRef.current = document.activeElement;
      } else {
        previouslyFocusedElementRef.current = null;
      }
      const dialogNode = dialogRef.current;
      if (dialogNode) {
        dialogNode.focus();
      }
    } else {
      if (previouslyFocusedElementRef.current) {
        previouslyFocusedElementRef.current.focus();
      }
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const renderTabContent = () => {
    switch (activeTab) {
      case "appearance":
        return <AppearanceTab />;
      case "columns":
        return <ColumnsTab />;
      case "behavior":
        return <BehaviorTab />;
      case "updates":
        return <UpdatesTab />;
      case "file-associations":
        return <FileAssociationsTab />;
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(0,0,0,0.3)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Settings"
        tabIndex={-1}
        onKeyDown={(event) => {
          if (event.key !== "Tab") return;
          const dialogNode = dialogRef.current;
          if (!dialogNode) return;
          const focusableSelectors = [
            "a[href]",
            "button:not([disabled])",
            "textarea:not([disabled])",
            "input:not([disabled])",
            "select:not([disabled])",
            '[tabindex]:not([tabindex="-1"])',
          ];
          const focusableElements = Array.from(
            dialogNode.querySelectorAll<HTMLElement>(focusableSelectors.join(","))
          ).filter(
            (el) =>
              !el.hasAttribute("disabled") &&
              el.getAttribute("aria-hidden") !== "true"
          );
          if (focusableElements.length === 0) {
            event.preventDefault();
            dialogNode.focus();
            return;
          }
          const firstElement = focusableElements[0];
          const lastElement = focusableElements[focusableElements.length - 1];
          const activeElement = document.activeElement as HTMLElement | null;
          if (!event.shiftKey && activeElement === lastElement) {
            event.preventDefault();
            firstElement.focus();
          } else if (event.shiftKey && activeElement === firstElement) {
            event.preventDefault();
            lastElement.focus();
          }
        }}
        style={{
          backgroundColor: tokens.colorNeutralBackground1,
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          padding: "16px",
          minWidth: "580px",
          maxWidth: "700px",
          maxHeight: "90vh",
          overflowY: "auto",
          boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
          color: tokens.colorNeutralForeground1,
        }}
      >
        {/* Title bar */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "12px",
          }}
        >
          <div style={{ fontSize: "16px", fontWeight: "bold" }}>Settings</div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close settings"
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              padding: "4px",
              fontSize: "16px",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1,
            }}
          >
            x
          </button>
        </div>

        {/* Tab bar */}
        <div
          role="tablist"
          style={{
            display: "flex",
            gap: "0",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            marginBottom: "14px",
          }}
        >
          {visibleTabs.map((tab) => (
            <button
              type="button"
              key={tab.id}
              role="tab"
              aria-selected={activeTab === tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: "6px 14px",
                fontSize: "12px",
                border: "none",
                borderBottom:
                  activeTab === tab.id
                    ? `2px solid ${tokens.colorBrandForeground1}`
                    : "2px solid transparent",
                background: "transparent",
                color:
                  activeTab === tab.id
                    ? tokens.colorBrandForeground1
                    : tokens.colorNeutralForeground2,
                fontWeight: activeTab === tab.id ? 600 : 400,
                cursor: "pointer",
                whiteSpace: "nowrap",
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div role="tabpanel">{renderTabContent()}</div>
      </div>
    </div>
  );
}
