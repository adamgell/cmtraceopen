export interface Cluster {
  id: number;
  label: string;
  entryIds: number[];
  representativeMessage: string;
  size: number;
}

export interface ClusterResult {
  clusters: Cluster[];
  anomalyEntryIds: number[];
  totalEntries: number;
  clusteredEntries: number;
  processingTimeMs: number;
}

export interface IncrementalClusterResult {
  assignments: Record<number, number>; // entryId -> clusterId
  newAnomalyIds: number[];
  updatedClusters: Cluster[];
}

export interface ClusteringProgress {
  stage: string;
  message: string;
  percent: number | null;
}

/** A generic entry from any workspace that can be clustered. */
export interface ClusterableEntry {
  id: number;
  message: string;
  source: string;
  severity: string | null;
  timestamp: string | null;
}

export interface ClusteringSourceSummary {
  source: string;
  count: number;
}

export interface MultiSourceCluster {
  id: number;
  label: string;
  entryIds: number[];
  representativeMessage: string;
  size: number;
  sourceBreakdown: ClusteringSourceSummary[];
}

export interface MultiSourceClusterResult {
  clusters: MultiSourceCluster[];
  anomalyEntryIds: number[];
  anomalyEntries: ClusterableEntry[];
  totalEntries: number;
  clusteredEntries: number;
  processingTimeMs: number;
  sources: ClusteringSourceSummary[];
}
