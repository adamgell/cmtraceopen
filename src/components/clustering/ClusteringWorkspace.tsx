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
import { useIntuneStore } from "../../stores/intune-store";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import type {
  MultiSourceCluster,
  ClusteringSourceSummary,
} from "../../types/clustering";

function SourceBadges({
  breakdown,
}: {
  breakdown: ClusteringSourceSummary[];
}) {
  if (breakdown.length === 0) return null;
  return (
    <div style={{ display: "flex", gap: "4px", flexWrap: "wrap", marginTop: "4px" }}>
      {breakdown.map((s) => (
        <Badge
          key={s.source}
          appearance="outline"
          size="small"
          color="subtle"
        >
          {s.source}: {s.count}
        </Badge>
      ))}
    </div>
  );
}

function MultiSourceClusterCard({
  cluster,
  isActive,
  onSelect,
}: {
  cluster: MultiSourceCluster;
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
      <SourceBadges breakdown={cluster.sourceBreakdown} />
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
      <Subtitle2>Analyzing Patterns</Subtitle2>
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

function IdleView({
  onAnalyzeFile,
  onAnalyzeAll,
  hasFile,
  hasAnyData,
}: {
  onAnalyzeFile: () => void;
  onAnalyzeAll: () => void;
  hasFile: boolean;
  hasAnyData: boolean;
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
      <Title3>Pattern Analysis</Title3>
      <Caption1
        style={{
          color: "#666",
          textAlign: "center",
          maxWidth: "480px",
          lineHeight: "1.5",
        }}
      >
        Use semantic embeddings to discover patterns across all your
        workspace data. Entries from log files, Intune events and
        diagnostics, and DSRegCmd analysis are grouped by meaning, and
        outliers are flagged as anomalies. The embedding model (~80 MB)
        will be downloaded on first use.
      </Caption1>
      <div style={{ display: "flex", gap: "12px" }}>
        <Button
          appearance="primary"
          size="large"
          disabled={!hasAnyData}
          onClick={onAnalyzeAll}
        >
          Analyze All Sources
        </Button>
        {hasFile && (
          <Button
            appearance="secondary"
            size="large"
            onClick={onAnalyzeFile}
          >
            Analyze Log File Only
          </Button>
        )}
      </div>
      {!hasAnyData && (
        <Caption1 style={{ color: "#999" }}>
          Open a log file or run workspace analysis first.
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
  const multiSourceResult = useClusteringStore((s) => s.multiSourceResult);
  const activeClusterId = useClusteringStore((s) => s.activeClusterId);
  const errorMessage = useClusteringStore((s) => s.errorMessage);
  const setActiveCluster = useClusteringStore((s) => s.setActiveCluster);
  const analyzeSingleFile = useClusteringStore((s) => s.analyzeClusters);
  const analyzeAll = useClusteringStore((s) => s.analyzeAllSources);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const hasIntuneData = useIntuneStore((s) => s.events.length > 0);
  const hasDsregData = useDsregcmdStore((s) => s.result !== null);
  const hasLogData = useLogStore((s) => s.entries.length > 0);

  const hasFile = openFilePath !== null;
  const hasAnyData = hasLogData || hasIntuneData || hasDsregData;

  const handleAnalyzeFile = useCallback(() => {
    if (openFilePath) {
      analyzeSingleFile(openFilePath);
    }
  }, [analyzeSingleFile, openFilePath]);

  const handleAnalyzeAll = useCallback(() => {
    analyzeAll();
  }, [analyzeAll]);

  // Use multi-source result if available, fall back to single-file result
  const activeResult = multiSourceResult ?? result;

  const sortedClusters = useMemo(() => {
    if (!activeResult) return [];
    return [...activeResult.clusters].sort((a, b) => b.size - a.size);
  }, [activeResult]);

  if (phase === "analyzing") {
    return <AnalyzingView />;
  }

  if (phase === "error") {
    return (
      <ErrorView
        message={errorMessage ?? "Unknown error"}
        onRetry={handleAnalyzeAll}
      />
    );
  }

  if (phase === "idle" || !activeResult) {
    return (
      <IdleView
        onAnalyzeFile={handleAnalyzeFile}
        onAnalyzeAll={handleAnalyzeAll}
        hasFile={hasFile}
        hasAnyData={hasAnyData}
      />
    );
  }

  // Ready state — show results
  const isMultiSource = multiSourceResult !== null;
  const sources = isMultiSource ? multiSourceResult.sources : [];
  const anomalyEntries = isMultiSource
    ? multiSourceResult.anomalyEntries
    : [];

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
          flexWrap: "wrap",
        }}
      >
        <Subtitle2>Pattern Analysis</Subtitle2>
        <Badge appearance="tint" color="brand">
          {activeResult.clusters.length} clusters
        </Badge>
        <Badge
          appearance="tint"
          color={activeResult.anomalyEntryIds.length > 0 ? "warning" : "success"}
        >
          {activeResult.anomalyEntryIds.length} anomalies
        </Badge>
        <Caption1 style={{ color: "#999", marginLeft: "auto" }}>
          {activeResult.totalEntries} entries analyzed in{" "}
          {(activeResult.processingTimeMs / 1000).toFixed(1)}s
        </Caption1>
        <Button
          appearance="secondary"
          size="small"
          onClick={handleAnalyzeAll}
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

      {/* Source summary (multi-source only) */}
      {isMultiSource && sources.length > 0 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            padding: "8px 16px",
            borderBottom: "1px solid #eee",
            backgroundColor: "#fafbfc",
            flexWrap: "wrap",
          }}
        >
          <Caption1 style={{ fontWeight: 600, color: "#555" }}>
            Sources:
          </Caption1>
          {sources.map((s) => (
            <Badge key={s.source} appearance="outline" size="small">
              {s.source} ({s.count})
            </Badge>
          ))}
        </div>
      )}

      {/* Cluster list */}
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "16px",
        }}
      >
        {activeResult.anomalyEntryIds.length > 0 && (
          <div style={{ marginBottom: "16px" }}>
            <Caption1
              style={{
                fontWeight: 600,
                color: "#c47a00",
                display: "block",
                marginBottom: "8px",
              }}
            >
              Anomalies — {activeResult.anomalyEntryIds.length} entries
              that don&apos;t fit any pattern
            </Caption1>
            {isMultiSource && anomalyEntries.length > 0 && (
              <div
                style={{
                  maxHeight: "200px",
                  overflow: "auto",
                  marginBottom: "8px",
                  borderRadius: "4px",
                  border: "1px solid #f0d9a0",
                  backgroundColor: "#fffcf5",
                }}
              >
                {anomalyEntries.slice(0, 20).map((entry) => (
                  <div
                    key={entry.id}
                    style={{
                      padding: "6px 12px",
                      borderBottom: "1px solid #f5ecd5",
                      fontSize: "12px",
                      display: "flex",
                      gap: "8px",
                    }}
                  >
                    <Badge
                      appearance="outline"
                      size="small"
                      color="subtle"
                      style={{ flexShrink: 0 }}
                    >
                      {entry.source}
                    </Badge>
                    <span
                      style={{
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: "#555",
                      }}
                    >
                      {entry.message}
                    </span>
                  </div>
                ))}
                {anomalyEntries.length > 20 && (
                  <div
                    style={{
                      padding: "6px 12px",
                      fontSize: "12px",
                      color: "#999",
                    }}
                  >
                    ...and {anomalyEntries.length - 20} more
                  </div>
                )}
              </div>
            )}
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

        {sortedClusters.map((cluster) => {
          if (isMultiSource && "sourceBreakdown" in cluster) {
            return (
              <MultiSourceClusterCard
                key={cluster.id}
                cluster={cluster as MultiSourceCluster}
                isActive={activeClusterId === cluster.id}
                onSelect={setActiveCluster}
              />
            );
          }
          // Single-file cluster fallback
          return (
            <MultiSourceClusterCard
              key={cluster.id}
              cluster={{
                ...cluster,
                sourceBreakdown: [],
              }}
              isActive={activeClusterId === cluster.id}
              onSelect={setActiveCluster}
            />
          );
        })}
      </div>
    </div>
  );
}
