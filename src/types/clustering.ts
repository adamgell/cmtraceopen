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
