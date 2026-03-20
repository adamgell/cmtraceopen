import { useState, useMemo } from "react";
import type {
  Anomaly, AnomalyAnalysis, AnomalyKind, AnomalySeverity,
  CausalChain, DetectionLayer,
} from "../../types/anomaly";

interface AnomalySurfaceProps {
  analysis: AnomalyAnalysis;
  onSelectEventId?: (id: number) => void;
}

const KIND_LABELS: Record<AnomalyKind, string> = {
  MissingStep: "Missing Step", OutOfOrderStep: "Out of Order",
  OrphanedStart: "Orphaned Start", UnexpectedLoop: "Unexpected Loop",
  DurationOutlier: "Duration Outlier", FrequencySpike: "Frequency Spike",
  FrequencyGap: "Frequency Gap", DownloadPerformance: "Download Issue",
  ErrorRateTrend: "Error Rate Trend", SeverityEscalation: "Severity Escalation",
  CrossSourceCorrelation: "Cross-Source", RootCauseCandidate: "Root Cause",
};

const LAYER_LABELS: Record<DetectionLayer, string> = {
  FlowModel: "Flow Model", Statistical: "Statistical",
  Escalation: "Escalation", CrossSource: "Cross-Source",
};

const SEV_COLORS: Record<AnomalySeverity, string> = {
  Critical: "#dc2626", Warning: "#d97706", Info: "#2563eb",
};

const ALL_KINDS = Object.keys(KIND_LABELS) as AnomalyKind[];
const ALL_SEVS: AnomalySeverity[] = ["Critical", "Warning", "Info"];
const ALL_LAYERS = Object.keys(LAYER_LABELS) as DetectionLayer[];

const selStyle: React.CSSProperties = {
  fontSize: 12, padding: "3px 6px", borderRadius: 4,
  border: "1px solid #d1d1d1", background: "#fff",
};
const sectionHead: React.CSSProperties = {
  fontSize: 11, fontWeight: 600, color: "#1f2937", marginBottom: 4,
};
const metaRow: React.CSSProperties = {
  display: "flex", gap: 16, flexWrap: "wrap", fontSize: 11, color: "#374151",
};
const chipBtn = (border: string, bg: string): React.CSSProperties => ({
  fontSize: 10, padding: "2px 6px", borderRadius: 10,
  border: `1px solid ${border}`, background: bg, color: "#1f2937", cursor: "pointer",
});

export function AnomalySurface({ analysis, onSelectEventId }: AnomalySurfaceProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [kindF, setKindF] = useState<AnomalyKind | "All">("All");
  const [sevF, setSevF] = useState<AnomalySeverity | "All">("All");
  const [layerF, setLayerF] = useState<DetectionLayer | "All">("All");
  const [chainsOpen, setChainsOpen] = useState(true);
  const { summary, causalChains } = analysis;

  const filtered = useMemo(() => {
    return analysis.anomalies
      .filter((a) => kindF === "All" || a.kind === kindF)
      .filter((a) => sevF === "All" || a.severity === sevF)
      .filter((a) => layerF === "All" || a.detectionLayer === layerF)
      .sort((a, b) => b.score - a.score);
  }, [analysis.anomalies, kindF, sevF, layerF]);

  if (analysis.anomalies.length === 0) {
    return (
      <div style={{ padding: 48, textAlign: "center", color: "#6b7280", fontSize: 14 }}>
        No anomalies detected. The deployment appears healthy.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
      {/* Summary cards */}
      <div style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid #e5e7eb", flexShrink: 0, flexWrap: "wrap" }}>
        <Card label="Total" value={summary.totalAnomalies} />
        <Card label="Critical" value={summary.criticalCount} color="#dc2626" />
        <Card label="Warning" value={summary.warningCount} color="#d97706" />
        <Card label="Info" value={summary.infoCount} color="#2563eb" />
        <Card label="Causal Chains" value={summary.causalChainCount} />
      </div>
      {/* Filter bar */}
      <div style={{ display: "flex", gap: 8, padding: "6px 12px", borderBottom: "1px solid #e5e7eb", alignItems: "center", flexShrink: 0 }}>
        <select value={kindF} onChange={(e) => setKindF(e.target.value as AnomalyKind | "All")} style={selStyle}>
          <option value="All">All kinds</option>
          {ALL_KINDS.map((k) => <option key={k} value={k}>{KIND_LABELS[k]}</option>)}
        </select>
        <select value={sevF} onChange={(e) => setSevF(e.target.value as AnomalySeverity | "All")} style={selStyle}>
          <option value="All">All severities</option>
          {ALL_SEVS.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={layerF} onChange={(e) => setLayerF(e.target.value as DetectionLayer | "All")} style={selStyle}>
          <option value="All">All layers</option>
          {ALL_LAYERS.map((l) => <option key={l} value={l}>{LAYER_LABELS[l]}</option>)}
        </select>
        <span style={{ fontSize: 11, color: "#6b7280", marginLeft: "auto" }}>
          {filtered.length} of {analysis.anomalies.length} anomalies
        </span>
      </div>
      {/* Anomaly list */}
      <div style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
        {filtered.map((a) => {
          const sel = a.id === selectedId;
          return (
            <div key={a.id}>
              <Row anomaly={a} selected={sel} onClick={() => setSelectedId(sel ? null : a.id)} />
              {sel && <Detail anomaly={a} onSelectEventId={onSelectEventId} />}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div style={{ padding: 24, textAlign: "center", color: "#6b7280", fontSize: 13 }}>
            No anomalies match the current filters.
          </div>
        )}
      </div>
      {/* Causal chains */}
      {causalChains.length > 0 && (
        <div style={{ borderTop: "1px solid #e5e7eb", flexShrink: 0 }}>
          <button
            onClick={() => setChainsOpen(!chainsOpen)}
            style={{
              width: "100%", display: "flex", alignItems: "center", gap: 6,
              padding: "8px 12px", background: "#f9fafb", border: "none",
              borderBottom: chainsOpen ? "1px solid #e5e7eb" : "none",
              cursor: "pointer", fontSize: 12, fontWeight: 600, color: "#1f2937", textAlign: "left",
            }}
          >
            <span style={{ fontSize: 10 }}>{chainsOpen ? "\u25BC" : "\u25B6"}</span>
            Causal Chains ({causalChains.length})
          </button>
          {chainsOpen && (
            <div style={{ maxHeight: 240, overflowY: "auto" }}>
              {causalChains.map((c) => <Chain key={c.id} chain={c} onSelectEventId={onSelectEventId} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------- sub-components ---------- */

function Card({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div style={{ padding: "8px 12px", border: "1px solid #e5e7eb", borderRadius: 6, background: "#fff", minWidth: 90, display: "grid", gap: 2 }}>
      <span style={{ fontSize: 11, color: "#6b7280" }}>{label}</span>
      <span style={{ fontSize: 20, fontWeight: 700, color: color ?? "#1f2937", lineHeight: 1.2 }}>{value}</span>
    </div>
  );
}

function Row({ anomaly, selected, onClick }: { anomaly: Anomaly; selected: boolean; onClick: () => void }) {
  const sc = SEV_COLORS[anomaly.severity];
  return (
    <div
      onClick={onClick}
      style={{
        display: "flex", alignItems: "center", gap: 8, padding: "6px 12px",
        cursor: "pointer", borderBottom: selected ? "none" : "1px solid #f0f0f0",
        backgroundColor: selected ? "#f0f9ff" : "transparent", fontSize: 12,
      }}
    >
      <span style={{ display: "flex", alignItems: "center", gap: 4, flexShrink: 0, minWidth: 70 }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: sc, flexShrink: 0 }} />
        <span style={{ fontSize: 11, color: sc, fontWeight: 600 }}>{anomaly.severity}</span>
      </span>
      <span style={{ fontSize: 10, padding: "1px 5px", borderRadius: 3, background: "#f3f4f6", color: "#6b7280", whiteSpace: "nowrap", flexShrink: 0 }}>
        {KIND_LABELS[anomaly.kind]}
      </span>
      <span style={{ flex: 1, fontWeight: 600, color: "#1f2937", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {anomaly.title}
      </span>
      <span style={{ display: "flex", alignItems: "center", gap: 4, flexShrink: 0, width: 100 }}>
        <span style={{ flex: 1, height: 6, backgroundColor: "#f3f4f6", borderRadius: 3, overflow: "hidden" }}>
          <span style={{ display: "block", width: `${Math.min(anomaly.score, 100)}%`, height: "100%", backgroundColor: sc, borderRadius: 3 }} />
        </span>
        <span style={{ fontSize: 10, color: "#6b7280", width: 26, textAlign: "right" }}>{Math.round(anomaly.score)}</span>
      </span>
      <span style={{ fontSize: 11, color: "#6b7280", flexShrink: 0, minWidth: 50, textAlign: "right" }}>
        {anomaly.affectedEventIds.length} evt{anomaly.affectedEventIds.length !== 1 ? "s" : ""}
      </span>
    </div>
  );
}

function Detail({ anomaly, onSelectEventId }: { anomaly: Anomaly; onSelectEventId?: (id: number) => void }) {
  const fc = anomaly.flowContext;
  const sc = anomaly.statisticalContext;
  return (
    <div style={{ padding: "10px 12px 14px 30px", background: "#f9fafb", borderBottom: "1px solid #e5e7eb", fontSize: 12 }}>
      <div style={{ color: "#1f2937", marginBottom: 10, lineHeight: 1.5 }}>{anomaly.description}</div>
      <div style={{ fontSize: 11, color: "#6b7280", marginBottom: 10 }}>
        Detection: {LAYER_LABELS[anomaly.detectionLayer]}
      </div>
      {anomaly.scoreFactors.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={sectionHead}>Score Factors</div>
          {anomaly.scoreFactors.map((f, i) => (
            <div key={i} style={{ display: "flex", gap: 8, alignItems: "baseline", fontSize: 11, color: "#374151", padding: "2px 0" }}>
              <span style={{ fontWeight: 600, minWidth: 100 }}>{f.factor}</span>
              <span style={{ color: "#6b7280", minWidth: 80 }}>w={f.weight.toFixed(2)} v={f.value.toFixed(2)}</span>
              <span style={{ color: "#6b7280" }}>{f.explanation}</span>
            </div>
          ))}
        </div>
      )}
      {fc && (
        <div style={{ marginBottom: 10 }}>
          <div style={sectionHead}>Flow Context</div>
          <div style={metaRow}>
            <span><strong>Expected:</strong> {fc.expectedStep}</span>
            <span><strong>Actual:</strong> {fc.actualStep ?? "none"}</span>
            <span><strong>Lifecycle:</strong> {fc.lifecycle}</span>
            {fc.subjectGuid && <span><strong>GUID:</strong> {fc.subjectGuid}</span>}
          </div>
        </div>
      )}
      {sc && (
        <div style={{ marginBottom: 10 }}>
          <div style={sectionHead}>Statistical Context</div>
          <div style={metaRow}>
            <span><strong>Metric:</strong> {sc.metricName}</span>
            <span><strong>Observed:</strong> {sc.observedValue.toFixed(2)}</span>
            <span><strong>Mean:</strong> {sc.populationMean.toFixed(2)}</span>
            <span><strong>Stddev:</strong> {sc.populationStddev.toFixed(2)}</span>
            <span><strong>Z-score:</strong> {sc.zScore.toFixed(2)}</span>
          </div>
        </div>
      )}
      {anomaly.enrichedErrorCodes && anomaly.enrichedErrorCodes.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={sectionHead}>Error Codes</div>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
            {anomaly.enrichedErrorCodes.map((code, i) => (
              <span key={i} style={{ fontSize: 10, padding: "2px 8px", borderRadius: 3, background: "#fef3c7", color: "#92400e", border: "1px solid #fcd34d", fontFamily: "monospace" }}>
                {code}
              </span>
            ))}
          </div>
        </div>
      )}
      {anomaly.affectedEventIds.length > 0 && (
        <div>
          <div style={sectionHead}>Affected Events</div>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
            {anomaly.affectedEventIds.map((id) => (
              <button key={id} onClick={(e) => { e.stopPropagation(); onSelectEventId?.(id); }}
                style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, border: "1px solid #d1d5db", background: "#fff", color: "#2563eb", cursor: "pointer" }}>
                #{id}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Chain({ chain, onSelectEventId }: { chain: CausalChain; onSelectEventId?: (id: number) => void }) {
  return (
    <div style={{ padding: "8px 12px", borderBottom: "1px solid #f0f0f0", fontSize: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ color: "#1f2937", fontWeight: 500 }}>{chain.description}</span>
        <span style={{ fontSize: 11, color: "#6b7280" }}>{Math.round(chain.confidence * 100)}% confidence</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
        {chain.chainEventIds.map((id, i) => {
          const isRoot = id === chain.rootEventId;
          const isTerm = id === chain.terminalEventId;
          return (
            <span key={id} style={{ display: "flex", alignItems: "center", gap: 2 }}>
              <button onClick={() => onSelectEventId?.(id)}
                style={chipBtn(isRoot ? "#dc2626" : isTerm ? "#d97706" : "#d1d5db", isRoot ? "#fef2f2" : isTerm ? "#fffbeb" : "#fff")}>
                #{id}
              </button>
              {i < chain.chainEventIds.length - 1 && <span style={{ color: "#d1d5db", fontSize: 10 }}>{"\u2192"}</span>}
            </span>
          );
        })}
      </div>
    </div>
  );
}
