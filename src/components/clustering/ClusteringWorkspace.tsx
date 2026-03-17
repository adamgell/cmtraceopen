import { useCallback, useMemo } from "react";
import {
  Badge,
  Button,
  Caption1,
  ProgressBar,
  Spinner,
  Subtitle2,
  Title3,
} from "@fluentui/react-components";
import { useClusteringStore } from "../../stores/clustering-store";
import { useLogStore } from "../../stores/log-store";
import type { Cluster } from "../../types/clustering";

function ClusterCard({
  cluster,
  isActive,
  onSelect,
}: {
  cluster: Cluster;
  isActive: boolean;
  onSelect: (id: number | null) => void;
}) {
  return (
    <div
      onClick={() => onSelect(isActive ? null : cluster.id)}
      style={{
        padding: "10px 14px",
        marginBottom: "6px",
        borderRadius: "6px",
        border: isActive
          ? "2px solid #0078D7"
          : "1px solid #e0e0e0",
        backgroundColor: isActive ? "#e6f2ff" : "#fff",
        cursor: "pointer",
        transition: "all 120ms ease",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "4px",
        }}
      >
        <Subtitle2>{cluster.label}</Subtitle2>
        <Badge appearance="filled" color="informative" size="small">
          {cluster.size} entries
        </Badge>
      </div>
      <Caption1
        style={{
          color: "#666",
          display: "block",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {cluster.representativeMessage}
      </Caption1>
    </div>
  );
}

function AnalyzingView() {
  const progressMessage = useClusteringStore((s) => s.progressMessage);
  const progressPercent = useClusteringStore((s) => s.progressPercent);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: "16px",
        padding: "40px",
      }}
    >
      <Spinner size="large" />
      <Subtitle2>Analyzing Log Patterns</Subtitle2>
      <Caption1 style={{ color: "#666", textAlign: "center" }}>
        {progressMessage}
      </Caption1>
      {progressPercent !== null && (
        <ProgressBar
          value={progressPercent / 100}
          style={{ width: "300px" }}
        />
      )}
    </div>
  );
}

function IdleView({ onAnalyze }: { onAnalyze: () => void }) {
  const hasSource = useLogStore((s) => s.openFilePath !== null);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: "16px",
        padding: "40px",
      }}
    >
      <Title3>Log Pattern Analysis</Title3>
      <Caption1
        style={{
          color: "#666",
          textAlign: "center",
          maxWidth: "480px",
          lineHeight: "1.5",
        }}
      >
        Use semantic embeddings to discover patterns in your log file. Entries
        are grouped by meaning, and outliers are flagged as anomalies. This
        requires the embedding model (~80 MB) which will be downloaded on first
        use.
      </Caption1>
      <Button
        appearance="primary"
        size="large"
        disabled={!hasSource}
        onClick={onAnalyze}
      >
        Analyze Patterns
      </Button>
      {!hasSource && (
        <Caption1 style={{ color: "#999" }}>
          Open a log file first to analyze patterns.
        </Caption1>
      )}
    </div>
  );
}

function ErrorView({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: "16px",
        padding: "40px",
      }}
    >
      <Subtitle2 style={{ color: "#c00" }}>Analysis Failed</Subtitle2>
      <Caption1
        style={{
          color: "#666",
          textAlign: "center",
          maxWidth: "480px",
        }}
      >
        {message}
      </Caption1>
      <Button appearance="primary" onClick={onRetry}>
        Retry
      </Button>
    </div>
  );
}

export function ClusteringWorkspace() {
  const phase = useClusteringStore((s) => s.phase);
  const result = useClusteringStore((s) => s.result);
  const activeClusterId = useClusteringStore((s) => s.activeClusterId);
  const errorMessage = useClusteringStore((s) => s.errorMessage);
  const setActiveCluster = useClusteringStore((s) => s.setActiveCluster);
  const analyze = useClusteringStore((s) => s.analyzeClusters);
  const openFilePath = useLogStore((s) => s.openFilePath);

  const handleAnalyze = useCallback(() => {
    if (openFilePath) {
      analyze(openFilePath);
    }
  }, [analyze, openFilePath]);

  const sortedClusters = useMemo(() => {
    if (!result) return [];
    return [...result.clusters].sort((a, b) => b.size - a.size);
  }, [result]);

  if (phase === "analyzing") {
    return <AnalyzingView />;
  }

  if (phase === "error") {
    return (
      <ErrorView
        message={errorMessage ?? "Unknown error"}
        onRetry={handleAnalyze}
      />
    );
  }

  if (phase === "idle" || !result) {
    return <IdleView onAnalyze={handleAnalyze} />;
  }

  // Ready state — show results
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        overflow: "hidden",
      }}
    >
      {/* Summary bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "16px",
          padding: "12px 16px",
          borderBottom: "1px solid #e0e0e0",
          backgroundColor: "#f8f9fa",
          flexShrink: 0,
        }}
      >
        <Subtitle2>Pattern Analysis</Subtitle2>
        <Badge appearance="tint" color="brand">
          {result.clusters.length} clusters
        </Badge>
        <Badge
          appearance="tint"
          color={result.anomalyEntryIds.length > 0 ? "warning" : "success"}
        >
          {result.anomalyEntryIds.length} anomalies
        </Badge>
        <Caption1 style={{ color: "#999", marginLeft: "auto" }}>
          {result.totalEntries} entries analyzed in{" "}
          {(result.processingTimeMs / 1000).toFixed(1)}s
        </Caption1>
        <Button
          appearance="secondary"
          size="small"
          onClick={handleAnalyze}
        >
          Re-analyze
        </Button>
        {activeClusterId !== null && (
          <Button
            appearance="subtle"
            size="small"
            onClick={() => setActiveCluster(null)}
          >
            Clear Selection
          </Button>
        )}
      </div>

      {/* Cluster list */}
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "16px",
        }}
      >
        {result.anomalyEntryIds.length > 0 && (
          <div style={{ marginBottom: "16px" }}>
            <Caption1
              style={{
                fontWeight: 600,
                color: "#c47a00",
                display: "block",
                marginBottom: "8px",
              }}
            >
              Anomalies — {result.anomalyEntryIds.length} entries that don't
              fit any pattern
            </Caption1>
          </div>
        )}

        <Caption1
          style={{
            fontWeight: 600,
            display: "block",
            marginBottom: "8px",
          }}
        >
          Discovered Clusters
        </Caption1>

        {sortedClusters.map((cluster) => (
          <ClusterCard
            key={cluster.id}
            cluster={cluster}
            isActive={activeClusterId === cluster.id}
            onSelect={setActiveCluster}
          />
        ))}
      </div>
    </div>
  );
}
