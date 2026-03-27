import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import {
  COLLECTION_CATEGORIES,
  COLLECTION_PRESETS,
  isFullCollection,
  type CategoryDefinition,
} from "../../lib/collection-categories";
import { collectDiagnostics } from "../../lib/commands";
import { useUiStore } from "../../stores/ui-store";

interface CollectDiagnosticsDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function CollectDiagnosticsDialog({ isOpen, onClose }: CollectDiagnosticsDialogProps) {
  const setCollectionProgress = useUiStore((s) => s.setCollectionProgress);
  const setCollectionResult = useUiStore((s) => s.setCollectionResult);
  const collectingRef = useRef(false);

  // Category-level enabled state (all enabled by default)
  const [enabledCategories, setEnabledCategories] = useState<Set<string>>(
    () => new Set(COLLECTION_CATEGORIES.map((c) => c.id))
  );

  // Family-level overrides: families explicitly disabled within an enabled category
  const [disabledFamilies, setDisabledFamilies] = useState<Set<string>>(new Set());

  // Expanded categories in the tree
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

  // Reset state when dialog opens
  useEffect(() => {
    if (isOpen) {
      setEnabledCategories(new Set(COLLECTION_CATEGORIES.map((c) => c.id)));
      setDisabledFamilies(new Set());
      setExpandedCategories(new Set());
    }
  }, [isOpen]);

  // Compute the effective enabled families
  const effectiveFamilies = useMemo(() => {
    const families: string[] = [];
    for (const cat of COLLECTION_CATEGORIES) {
      if (!enabledCategories.has(cat.id)) continue;
      for (const fam of cat.families) {
        if (!disabledFamilies.has(fam)) {
          families.push(fam);
        }
      }
    }
    return families;
  }, [enabledCategories, disabledFamilies]);

  const totalFamilyCount = COLLECTION_CATEGORIES.reduce((sum, c) => sum + c.families.length, 0);

  const handlePresetClick = useCallback((categoryIds: string[]) => {
    setEnabledCategories(new Set(categoryIds));
    setDisabledFamilies(new Set());
  }, []);

  const handleCategoryToggle = useCallback((categoryId: string) => {
    setEnabledCategories((prev) => {
      const next = new Set(prev);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
    // Clear family-level overrides for this category
    const cat = COLLECTION_CATEGORIES.find((c) => c.id === categoryId);
    if (cat) {
      setDisabledFamilies((prev) => {
        const next = new Set(prev);
        for (const fam of cat.families) {
          next.delete(fam);
        }
        return next;
      });
    }
  }, []);

  const handleFamilyToggle = useCallback((categoryId: string, family: string) => {
    const cat = COLLECTION_CATEGORIES.find((c) => c.id === categoryId);
    if (!cat) return;

    setDisabledFamilies((prev) => {
      const next = new Set(prev);
      if (next.has(family)) {
        next.delete(family);
      } else {
        next.add(family);
        // If all families in this category are now disabled, disable the category
        const allDisabled = cat.families.every((f) => f === family || next.has(f));
        if (allDisabled) {
          setEnabledCategories((catPrev) => {
            const catNext = new Set(catPrev);
            catNext.delete(categoryId);
            return catNext;
          });
          // Remove family-level overrides since category is now off
          for (const f of cat.families) {
            next.delete(f);
          }
        }
      }
      return next;
    });

    // If category was off and we're enabling a family, turn the category on
    setEnabledCategories((prev) => {
      if (!prev.has(categoryId)) {
        const next = new Set(prev);
        next.add(categoryId);
        return next;
      }
      return prev;
    });
  }, []);

  const handleExpandToggle = useCallback((categoryId: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
  }, []);

  const isCategoryIndeterminate = useCallback((cat: CategoryDefinition): boolean => {
    if (!enabledCategories.has(cat.id)) return false;
    return cat.families.some((f) => disabledFamilies.has(f));
  }, [enabledCategories, disabledFamilies]);

  const isFamilyEnabled = useCallback((categoryId: string, family: string): boolean => {
    return enabledCategories.has(categoryId) && !disabledFamilies.has(family);
  }, [enabledCategories, disabledFamilies]);

  const handleCollect = useCallback(async () => {
    if (collectingRef.current || effectiveFamilies.length === 0) return;
    collectingRef.current = true;

    const requestId = `collect-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const families = isFullCollection(enabledCategories) && disabledFamilies.size === 0
      ? null  // null means "collect everything" — skip filtering
      : effectiveFamilies;

    setCollectionProgress({
      requestId,
      message: "Starting collection...",
      completedItems: 0,
      totalItems: 0,
      currentItem: null,
    });
    onClose();

    try {
      const result = await collectDiagnostics(requestId, null, families);
      setCollectionProgress(null);
      setCollectionResult(result);
    } catch (error) {
      setCollectionProgress(null);
      setCollectionResult({
        bundlePath: "",
        bundleId: "",
        artifactCounts: { collected: 0, missing: 0, failed: 0, total: 0 },
        durationMs: 0,
        gaps: [{ artifactId: "error", category: "system", reason: String(error) }],
      });
    } finally {
      collectingRef.current = false;
    }
  }, [effectiveFamilies, enabledCategories, disabledFamilies, onClose, setCollectionProgress, setCollectionResult]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    }
  }, [onClose]);

  if (!isOpen) return null;

  return (
    <div
      onKeyDown={handleKeyDown}
      style={{
        position: "fixed",
        inset: 0,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: "rgba(0, 0, 0, 0.3)",
        zIndex: 1000,
      }}
    >
      <div
        style={{
          width: "520px",
          maxHeight: "80vh",
          display: "flex",
          flexDirection: "column",
          backgroundColor: tokens.colorNeutralBackground1,
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "8px",
          boxShadow: tokens.shadow16,
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div style={{ padding: "16px 20px 0", fontSize: "16px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
          Collect Diagnostics
        </div>

        {/* Presets */}
        <div style={{ padding: "12px 20px" }}>
          <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "1px", color: tokens.colorNeutralForeground3, marginBottom: "8px" }}>
            Quick Presets
          </div>
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            {COLLECTION_PRESETS.map((preset) => (
              <button
                key={preset.id}
                onClick={() => handlePresetClick(preset.categoryIds)}
                style={{
                  padding: "4px 12px",
                  borderRadius: "4px",
                  border: `1px solid ${tokens.colorNeutralStroke1}`,
                  background: "transparent",
                  color: tokens.colorNeutralForeground1,
                  fontSize: "12px",
                  cursor: "pointer",
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <div style={{ borderTop: `1px solid ${tokens.colorNeutralStroke2}`, margin: "0 20px" }} />

        {/* Category Tree */}
        <div style={{ padding: "12px 20px", flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "1px", color: tokens.colorNeutralForeground3, marginBottom: "8px" }}>
            Categories
          </div>
          <div style={{ flex: 1, overflowY: "auto", border: `1px solid ${tokens.colorNeutralStroke2}`, borderRadius: "4px", padding: "4px" }}>
            {COLLECTION_CATEGORIES.map((cat) => {
              const isExpanded = expandedCategories.has(cat.id);
              const isEnabled = enabledCategories.has(cat.id);
              const isIndeterminate = isCategoryIndeterminate(cat);

              return (
                <div key={cat.id} style={{ marginBottom: "2px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", padding: "4px", cursor: "pointer" }}>
                    <span
                      onClick={() => handleExpandToggle(cat.id)}
                      style={{ color: tokens.colorNeutralForeground3, fontSize: "11px", width: "12px", textAlign: "center", userSelect: "none" }}
                    >
                      {isExpanded ? "\u25BC" : "\u25B6"}
                    </span>
                    <input
                      type="checkbox"
                      checked={isEnabled}
                      ref={(el) => { if (el) el.indeterminate = isIndeterminate; }}
                      onChange={() => handleCategoryToggle(cat.id)}
                      style={{ accentColor: tokens.colorBrandBackground }}
                    />
                    <span
                      onClick={() => handleExpandToggle(cat.id)}
                      style={{ fontSize: "13px", fontWeight: 600, color: tokens.colorNeutralForeground1, flex: 1, userSelect: "none" }}
                    >
                      {cat.label}
                    </span>
                    <span style={{ fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
                      {cat.families.length} {cat.families.length === 1 ? "family" : "families"}
                    </span>
                  </div>
                  {isExpanded && (
                    <div style={{ marginLeft: "30px", paddingBottom: "4px" }}>
                      {cat.families.map((fam) => (
                        <div key={fam} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "2px 0" }}>
                          <input
                            type="checkbox"
                            checked={isFamilyEnabled(cat.id, fam)}
                            onChange={() => handleFamilyToggle(cat.id, fam)}
                            style={{ accentColor: tokens.colorBrandBackground }}
                          />
                          <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground2 }}>{fam}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${tokens.colorNeutralStroke2}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
            {effectiveFamilies.length} of {totalFamilyCount} families selected
          </span>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              onClick={onClose}
              style={{
                padding: "6px 16px",
                borderRadius: "4px",
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                background: "transparent",
                color: tokens.colorNeutralForeground1,
                fontSize: "13px",
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
            <button
              onClick={handleCollect}
              disabled={effectiveFamilies.length === 0}
              style={{
                padding: "6px 20px",
                borderRadius: "4px",
                border: "none",
                background: effectiveFamilies.length === 0 ? tokens.colorNeutralBackgroundDisabled : tokens.colorBrandBackground,
                color: effectiveFamilies.length === 0 ? tokens.colorNeutralForegroundDisabled : tokens.colorNeutralForegroundOnBrand,
                fontSize: "13px",
                fontWeight: 600,
                cursor: effectiveFamilies.length === 0 ? "not-allowed" : "pointer",
              }}
            >
              Collect
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
