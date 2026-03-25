import { useState, useEffect, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import { useFilterStore } from "../../stores/filter-store";

export type FilterOp =
  | "Equals"
  | "NotEquals"
  | "Contains"
  | "NotContains"
  | "Before"
  | "After";

export type FilterField = "Message" | "Component" | "Thread" | "Timestamp";

export interface FilterClause {
  field: FilterField;
  op: FilterOp;
  value: string;
}

interface FilterDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onApply: (clauses: FilterClause[]) => Promise<void>;
  currentClauses: FilterClause[];
}

const FIELDS: { label: string; value: FilterField }[] = [
  { label: "Log Text", value: "Message" },
  { label: "Component", value: "Component" },
  { label: "Thread", value: "Thread" },
  { label: "Date/Time", value: "Timestamp" },
];

const OPS: { label: string; value: FilterOp }[] = [
  { label: "equals", value: "Equals" },
  { label: "does not equal", value: "NotEquals" },
  { label: "contains", value: "Contains" },
  { label: "does not contain", value: "NotContains" },
  { label: "is before", value: "Before" },
  { label: "is after", value: "After" },
];

function emptyClause(): FilterClause {
  return { field: "Message", op: "Contains", value: "" };
}

export function FilterDialog({
  isOpen,
  onClose,
  onApply,
  currentClauses,
}: FilterDialogProps) {
  const [clauses, setClauses] = useState<FilterClause[]>([emptyClause()]);
  const inputRef = useRef<HTMLInputElement>(null);

  const isFiltering = useFilterStore((s) => s.isFiltering);
  const filterError = useFilterStore((s) => s.filterError);

  useEffect(() => {
    if (isOpen) {
      setClauses(
        currentClauses.length > 0
          ? [...currentClauses]
          : [emptyClause()]
      );
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen, currentClauses]);

  useEffect(() => {
    if (!isOpen) return;

    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !isFiltering) onClose();
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isFiltering, isOpen, onClose]);

  const updateClause = (index: number, updates: Partial<FilterClause>) => {
    if (isFiltering) {
      return;
    }

    setClauses((prev) =>
      prev.map((c, i) => (i === index ? { ...c, ...updates } : c))
    );
  };

  const addClause = () => {
    if (isFiltering) {
      return;
    }

    setClauses((prev) => [...prev, emptyClause()]);
  };

  const removeClause = (index: number) => {
    if (isFiltering) {
      return;
    }

    setClauses((prev) => prev.filter((_, i) => i !== index));
  };

  const handleApply = async () => {
    if (isFiltering) {
      return;
    }

    const validClauses = clauses.filter((c) => c.value.trim() !== "");

    try {
      await onApply(validClauses);
      onClose();
    } catch {
      // Error state is handled by filter store and shown in the dialog/status UI.
    }
  };

  const handleClear = async () => {
    if (isFiltering) {
      return;
    }

    try {
      await onApply([]);
      onClose();
    } catch {
      // Error state is handled by filter store and shown in the dialog/status UI.
    }
  };

  if (!isOpen) return null;

  const appliedClauseCount = currentClauses.length;
  const validDraftClauseCount = clauses.filter((c) => c.value.trim() !== "").length;

  const statusText = isFiltering
    ? "Applying filter..."
    : filterError
      ? `Filter failed: ${filterError}`
      : appliedClauseCount > 0
        ? `${appliedClauseCount} clause(s) currently active`
        : "No filter currently active";

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "rgba(0,0,0,0.3)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "60px",
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !isFiltering) onClose();
      }}
    >
      <div
        style={{
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          padding: "12px",
          minWidth: "520px",
          boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
        }}
      >
        <div
          style={{
            fontSize: "13px",
            fontWeight: "bold",
            marginBottom: "10px",
          }}
        >
          Filter
        </div>

        {clauses.map((clause, index) => (
          <div
            key={index}
            style={{
              display: "flex",
              gap: "4px",
              marginBottom: "6px",
              alignItems: "center",
            }}
          >
            {index > 0 && (
              <span
                style={{
                  fontSize: "11px",
                  color: tokens.colorNeutralForeground3,
                  width: "30px",
                  textAlign: "center",
                }}
              >
                AND
              </span>
            )}
            {index === 0 && <span style={{ width: "30px" }} />}

            <select
              value={clause.field}
              disabled={isFiltering}
              onChange={(e) =>
                updateClause(index, { field: e.target.value as FilterField })
              }
              style={{ fontSize: "12px", padding: "2px" }}
            >
              {FIELDS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>

            <select
              value={clause.op}
              disabled={isFiltering}
              onChange={(e) =>
                updateClause(index, { op: e.target.value as FilterOp })
              }
              style={{ fontSize: "12px", padding: "2px" }}
            >
              {OPS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>

            <input
              ref={index === 0 ? inputRef : undefined}
              type="text"
              value={clause.value}
              disabled={isFiltering}
              onChange={(e) => updateClause(index, { value: e.target.value })}
              placeholder="Value..."
              style={{
                flex: 1,
                fontSize: "12px",
                padding: "2px 4px",
              }}
            />

            {clauses.length > 1 && (
              <button
                onClick={() => removeClause(index)}
                disabled={isFiltering}
                style={{
                  fontSize: "11px",
                  padding: "1px 4px",
                  border: `1px solid ${tokens.colorNeutralStroke1}`,
                  borderRadius: "4px",
                  background: tokens.colorNeutralBackground3,
                  color: tokens.colorNeutralForeground1,
                  cursor: "pointer",
                }}
                title="Remove clause"
              >
                ✕
              </button>
            )}
          </div>
        ))}

        <div
          style={{
            marginTop: "6px",
            fontSize: "11px",
            color: filterError ? tokens.colorPaletteRedForeground1 : isFiltering ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground3,
          }}
        >
          {statusText}
          {!isFiltering && !filterError && (
            <span>{` • Draft clauses ready: ${validDraftClauseCount}`}</span>
          )}
        </div>

        <div
          style={{
            display: "flex",
            gap: "6px",
            justifyContent: "space-between",
            marginTop: "10px",
          }}
        >
          <button onClick={addClause} disabled={isFiltering} style={{
            padding: "4px 12px",
            fontSize: "11px",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "4px",
            background: tokens.colorNeutralBackground3,
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}>
            + Add Clause
          </button>
          <div style={{ display: "flex", gap: "6px" }}>
            <button
              onClick={() => {
                handleClear().catch((error) => {
                  console.error("[filter-dialog] clear failed", { error });
                });
              }}
              disabled={isFiltering}
              style={{
                padding: "4px 12px",
                fontSize: "12px",
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                borderRadius: "4px",
                background: tokens.colorNeutralBackground3,
                color: tokens.colorNeutralForeground1,
                cursor: "pointer",
              }}
            >
              Clear Filter
            </button>
            <button
              onClick={() => {
                handleApply().catch((error) => {
                  console.error("[filter-dialog] apply failed", { error });
                });
              }}
              disabled={isFiltering}
              style={{
                padding: "4px 12px",
                fontSize: "12px",
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                borderRadius: "4px",
                background: tokens.colorNeutralBackground3,
                color: tokens.colorNeutralForeground1,
                cursor: "pointer",
              }}
            >
              {isFiltering ? "Applying..." : "Apply"}
            </button>
            <button onClick={onClose} disabled={isFiltering} style={{
              padding: "4px 12px",
              fontSize: "12px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "4px",
              background: tokens.colorNeutralBackground3,
              color: tokens.colorNeutralForeground1,
              cursor: "pointer",
            }}>
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}