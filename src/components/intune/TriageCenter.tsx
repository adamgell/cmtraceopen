import { useState, useMemo } from "react";
import type {
  IntuneDiagnosticCategory,
  IntuneDiagnosticInsight,
  IntuneRemediationPriority,
} from "../../types/intune";

interface TriageCenterProps {
  diagnostics: IntuneDiagnosticInsight[];
  onNavigateToAnomaly?: (anomalyId: string) => void;
}

type SourceFilter = "All" | "Diagnostic" | "Anomaly";

const PRIORITY_ORDER: Record<IntuneRemediationPriority, number> = {
  Immediate: 0,
  High: 1,
  Medium: 2,
  Monitor: 3,
};

const PRIORITY_COLORS: Record<
  IntuneRemediationPriority,
  { bg: string; text: string; border: string }
> = {
  Immediate: { bg: "#ef4444", text: "#ffffff", border: "#dc2626" },
  High: { bg: "#f59e0b", text: "#1f2937", border: "#d97706" },
  Medium: { bg: "#3b82f6", text: "#ffffff", border: "#2563eb" },
  Monitor: { bg: "#9ca3af", text: "#ffffff", border: "#6b7280" },
};

const CATEGORY_TONES: Record<IntuneDiagnosticCategory, string> = {
  Download: "#c2410c",
  Install: "#7c3aed",
  Timeout: "#b45309",
  Script: "#0f766e",
  Policy: "#2563eb",
  State: "#0f766e",
  General: "#475569",
};

const ALL_PRIORITIES: IntuneRemediationPriority[] = [
  "Immediate",
  "High",
  "Medium",
  "Monitor",
];

const ALL_CATEGORIES: IntuneDiagnosticCategory[] = [
  "Download",
  "Install",
  "Timeout",
  "Script",
  "Policy",
  "State",
  "General",
];

const selStyle: React.CSSProperties = {
  fontSize: 12,
  padding: "3px 6px",
  borderRadius: 4,
  border: "1px solid #d1d1d1",
  background: "#fff",
};

function isAnomalyDerived(id: string): boolean {
  return id.startsWith("anomaly-");
}

function getAnomalyIdFromDiagnosticId(id: string): string | null {
  if (!isAnomalyDerived(id)) return null;
  return id;
}

function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return segments[segments.length - 1] || path;
}

export function TriageCenter({ diagnostics, onNavigateToAnomaly }: TriageCenterProps) {
  const [priorityFilter, setPriorityFilter] = useState<IntuneRemediationPriority | "All">("All");
  const [categoryFilter, setCategoryFilter] = useState<IntuneDiagnosticCategory | "All">("All");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("All");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const priorityCounts = useMemo(() => {
    const counts: Record<IntuneRemediationPriority, number> = {
      Immediate: 0,
      High: 0,
      Medium: 0,
      Monitor: 0,
    };
    for (const d of diagnostics) {
      counts[d.remediationPriority]++;
    }
    return counts;
  }, [diagnostics]);

  const filtered = useMemo(() => {
    return diagnostics
      .filter((d) => {
        if (priorityFilter !== "All" && d.remediationPriority !== priorityFilter) return false;
        if (categoryFilter !== "All" && d.category !== categoryFilter) return false;
        if (sourceFilter === "Anomaly" && !isAnomalyDerived(d.id)) return false;
        if (sourceFilter === "Diagnostic" && isAnomalyDerived(d.id)) return false;
        return true;
      })
      .sort((a, b) => {
        const pa = PRIORITY_ORDER[a.remediationPriority];
        const pb = PRIORITY_ORDER[b.remediationPriority];
        return pa - pb;
      });
  }, [diagnostics, priorityFilter, categoryFilter, sourceFilter]);

  if (diagnostics.length === 0) {
    return (
      <div
        style={{
          padding: 48,
          textAlign: "center",
          color: "#6b7280",
          fontSize: 14,
        }}
      >
        No issues detected — the analysis found no actionable items.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
      {/* Priority Summary Header */}
      <div
        style={{
          display: "flex",
          gap: 8,
          padding: "10px 12px",
          borderBottom: "1px solid #e5e7eb",
          flexShrink: 0,
          flexWrap: "wrap",
        }}
      >
        {ALL_PRIORITIES.map((priority) => {
          const colors = PRIORITY_COLORS[priority];
          const count = priorityCounts[priority];
          const isActive = priorityFilter === priority;
          return (
            <button
              key={priority}
              onClick={() =>
                setPriorityFilter(isActive ? "All" : priority)
              }
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "6px 12px",
                borderRadius: 6,
                border: isActive
                  ? `2px solid ${colors.border}`
                  : "1px solid #e5e7eb",
                backgroundColor: isActive ? colors.bg : "#ffffff",
                color: isActive ? colors.text : "#374151",
                cursor: "pointer",
                fontSize: 12,
                fontWeight: 600,
                outline: isActive ? `2px solid ${colors.bg}40` : "none",
                outlineOffset: 1,
              }}
            >
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 20,
                  height: 20,
                  borderRadius: "50%",
                  backgroundColor: isActive ? "rgba(255,255,255,0.25)" : colors.bg,
                  color: isActive ? colors.text : "#ffffff",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                {count}
              </span>
              {priority}
            </button>
          );
        })}
      </div>

      {/* Filter Bar */}
      <div
        style={{
          display: "flex",
          gap: 8,
          padding: "6px 12px",
          borderBottom: "1px solid #e5e7eb",
          alignItems: "center",
          flexShrink: 0,
        }}
      >
        <select
          value={priorityFilter}
          onChange={(e) =>
            setPriorityFilter(e.target.value as IntuneRemediationPriority | "All")
          }
          style={selStyle}
        >
          <option value="All">All priorities</option>
          {ALL_PRIORITIES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select
          value={categoryFilter}
          onChange={(e) =>
            setCategoryFilter(e.target.value as IntuneDiagnosticCategory | "All")
          }
          style={selStyle}
        >
          <option value="All">All categories</option>
          {ALL_CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value as SourceFilter)}
          style={selStyle}
        >
          <option value="All">All sources</option>
          <option value="Diagnostic">Diagnostic</option>
          <option value="Anomaly">Anomaly</option>
        </select>
        <span
          style={{ fontSize: 11, color: "#6b7280", marginLeft: "auto" }}
        >
          {filtered.length} of {diagnostics.length} actions
        </span>
      </div>

      {/* Unified Action List */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "auto",
          padding: "8px 12px",
        }}
      >
        {filtered.length === 0 ? (
          <div
            style={{
              padding: 32,
              textAlign: "center",
              color: "#9ca3af",
              fontSize: 13,
            }}
          >
            No actions match the current filters.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {filtered.map((d) => (
              <TriageActionCard
                key={d.id}
                diagnostic={d}
                expanded={expandedId === d.id}
                onToggle={() =>
                  setExpandedId(expandedId === d.id ? null : d.id)
                }
                onNavigateToAnomaly={onNavigateToAnomaly}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function TriageActionCard({
  diagnostic,
  expanded,
  onToggle,
  onNavigateToAnomaly,
}: {
  diagnostic: IntuneDiagnosticInsight;
  expanded: boolean;
  onToggle: () => void;
  onNavigateToAnomaly?: (anomalyId: string) => void;
}) {
  const priorityColors = PRIORITY_COLORS[diagnostic.remediationPriority];
  const categoryTone = CATEGORY_TONES[diagnostic.category];
  const anomalySource = isAnomalyDerived(diagnostic.id);
  const anomalyId = getAnomalyIdFromDiagnosticId(diagnostic.id);

  return (
    <div
      style={{
        border: "1px solid #e5e7eb",
        borderLeft: `4px solid ${priorityColors.bg}`,
        borderRadius: 6,
        backgroundColor: expanded ? "#f9fafb" : "#ffffff",
        cursor: "pointer",
      }}
    >
      {/* Collapsed header */}
      <div
        onClick={onToggle}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 12px",
        }}
      >
        {/* Priority badge */}
        <span
          style={{
            fontSize: 9,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: priorityColors.text,
            backgroundColor: priorityColors.bg,
            borderRadius: "999px",
            padding: "2px 8px",
            flexShrink: 0,
          }}
        >
          {diagnostic.remediationPriority}
        </span>

        {/* Source indicator */}
        <span
          style={{
            fontSize: 9,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
            color: anomalySource ? "#7c3aed" : "#0f766e",
            backgroundColor: anomalySource ? "#f5f3ff" : "#ecfdf5",
            border: `1px solid ${anomalySource ? "#c4b5fd" : "#a7f3d0"}`,
            borderRadius: "999px",
            padding: "2px 6px",
            flexShrink: 0,
          }}
        >
          {anomalySource ? "Anomaly" : "Diagnostic"}
        </span>

        {/* Category badge */}
        <span
          style={{
            fontSize: 9,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
            color: categoryTone,
            border: `1px solid ${categoryTone}33`,
            backgroundColor: `${categoryTone}12`,
            borderRadius: "999px",
            padding: "2px 6px",
            flexShrink: 0,
          }}
        >
          {diagnostic.category}
        </span>

        {/* Title */}
        <span
          style={{
            fontSize: 13,
            fontWeight: 600,
            color: "#111827",
            flex: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {diagnostic.title}
        </span>

        {/* Summary (truncated) */}
        {!expanded && (
          <span
            style={{
              fontSize: 11,
              color: "#6b7280",
              maxWidth: 280,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              flexShrink: 1,
            }}
          >
            {diagnostic.summary}
          </span>
        )}

        {/* Expand/collapse indicator */}
        <span
          style={{
            fontSize: 11,
            color: "#9ca3af",
            flexShrink: 0,
            transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
            transition: "transform 0.15s ease",
          }}
        >
          &#9660;
        </span>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div
          style={{
            padding: "0 12px 12px",
            borderTop: "1px solid #e5e7eb",
          }}
        >
          {/* Summary */}
          <div
            style={{
              fontSize: 12,
              color: "#374151",
              marginTop: 10,
              marginBottom: 10,
              lineHeight: 1.5,
            }}
          >
            {diagnostic.summary}
          </div>

          {/* Likely Cause */}
          {diagnostic.likelyCause && (
            <div
              style={{
                marginBottom: 10,
                padding: "8px 10px",
                borderRadius: 6,
                backgroundColor: "#fffbeb",
                border: "1px solid #fde68a",
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "#92400e",
                  marginBottom: 4,
                  fontWeight: 600,
                }}
              >
                Likely Cause
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: "#1f2937",
                  lineHeight: 1.45,
                }}
              >
                {diagnostic.likelyCause}
              </div>
            </div>
          )}

          {/* Evidence */}
          {diagnostic.evidence.length > 0 && (
            <TriageDetailSection label="Evidence">
              <ul style={listStyle}>
                {diagnostic.evidence.map((item, i) => (
                  <li key={i} style={{ marginBottom: 2 }}>
                    {item}
                  </li>
                ))}
              </ul>
            </TriageDetailSection>
          )}

          {/* Next Checks */}
          {diagnostic.nextChecks.length > 0 && (
            <TriageDetailSection label="Next Checks">
              <ul style={listStyle}>
                {diagnostic.nextChecks.map((item, i) => (
                  <li key={i} style={{ marginBottom: 2 }}>
                    {item}
                  </li>
                ))}
              </ul>
            </TriageDetailSection>
          )}

          {/* Suggested Fixes */}
          {diagnostic.suggestedFixes.length > 0 && (
            <TriageDetailSection label="Suggested Fixes">
              <ul style={{ ...listStyle, listStyleType: "none", paddingLeft: 4 }}>
                {diagnostic.suggestedFixes.map((item, i) => (
                  <li
                    key={i}
                    style={{
                      marginBottom: 2,
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 6,
                    }}
                  >
                    <span style={{ color: "#16a34a", flexShrink: 0, fontSize: 13 }}>
                      &#10003;
                    </span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </TriageDetailSection>
          )}

          {/* Focus Areas */}
          {diagnostic.focusAreas.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={sectionLabelStyle}>Focus Areas</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {diagnostic.focusAreas.map((area) => (
                  <span
                    key={area}
                    style={{
                      fontSize: 10,
                      borderRadius: "999px",
                      padding: "3px 8px",
                      color: "#0f766e",
                      backgroundColor: "#ecfeff",
                      border: "1px solid #99f6e4",
                      fontWeight: 600,
                    }}
                  >
                    {area}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Error Codes */}
          {diagnostic.relatedErrorCodes.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={sectionLabelStyle}>Error Codes</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {diagnostic.relatedErrorCodes.map((code) => (
                  <span
                    key={code}
                    style={{
                      fontSize: 10,
                      borderRadius: "999px",
                      padding: "3px 8px",
                      color: "#b45309",
                      backgroundColor: "#fffbeb",
                      border: "1px solid #fde68a",
                      fontWeight: 600,
                      fontFamily: "monospace",
                    }}
                  >
                    {code}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Affected Source Files */}
          {diagnostic.affectedSourceFiles.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={sectionLabelStyle}>Affected Sources</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {diagnostic.affectedSourceFiles.map((file) => (
                  <span
                    key={file}
                    style={{
                      fontSize: 10,
                      borderRadius: "999px",
                      padding: "3px 8px",
                      color: "#1d4ed8",
                      backgroundColor: "#eff6ff",
                      border: "1px solid #bfdbfe",
                      fontWeight: 600,
                    }}
                    title={file}
                  >
                    {getFileName(file)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Knowledge Base Links */}
          {diagnostic.knowledgeBaseLinks &&
            diagnostic.knowledgeBaseLinks.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <div style={sectionLabelStyle}>Learn More</div>
                {diagnostic.knowledgeBaseLinks.map((link, i) => (
                  <div
                    key={i}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      marginBottom: 2,
                    }}
                  >
                    <a
                      href={link.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        fontSize: 12,
                        color: "#2563eb",
                        cursor: "pointer",
                        textDecoration: "underline",
                      }}
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        window.open(link.url, "_blank");
                      }}
                    >
                      {link.title}
                    </a>
                    <span style={{ fontSize: 11, color: "#9ca3af" }}>
                      &mdash; {link.relevance}
                    </span>
                  </div>
                ))}
              </div>
            )}

          {/* Navigate to anomaly link */}
          {anomalySource && anomalyId && onNavigateToAnomaly && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onNavigateToAnomaly(anomalyId);
              }}
              style={{
                marginTop: 4,
                fontSize: 12,
                color: "#7c3aed",
                backgroundColor: "transparent",
                border: "1px solid #c4b5fd",
                borderRadius: 4,
                padding: "4px 10px",
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              View Anomaly &rarr;
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function TriageDetailSection({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={sectionLabelStyle}>{label}</div>
      {children}
    </div>
  );
}

const sectionLabelStyle: React.CSSProperties = {
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  color: "#6b7280",
  marginBottom: 4,
  fontWeight: 600,
};

const listStyle: React.CSSProperties = {
  margin: 0,
  paddingLeft: 18,
  color: "#1f2937",
  fontSize: 12,
};
