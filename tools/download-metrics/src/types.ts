export const CLASSIFICATION_CONTRACT = "2026-07-13.1" as const;

export type Platform = "windows" | "macos" | "linux" | "cross-platform" | "unknown";
export type Architecture = "x64" | "arm64" | "unknown";
export type Edition = "full" | "lite" | "not-applicable" | "unknown";
export type PackageType =
  | "portable-exe"
  | "msi"
  | "nsis-setup"
  | "dmg"
  | "deb"
  | "rpm"
  | "appimage"
  | "updater-manifest"
  | "updater-archive"
  | "signature"
  | "sbom"
  | "unknown";
export type DeliveryRole =
  | "manual-only"
  | "mixed-manual-update"
  | "updater-only"
  | "supporting-file"
  | "unknown";
export type Channel = "stable" | "nightly";
export type SourceLabel =
  | "download-home"
  | "github-readme"
  | "github-release"
  | "cmtraceopen-product"
  | "nightly-builds-page"
  | "project-docs"
  | "unknown";

export type AssetClassification = {
  platform: Platform;
  architecture: Architecture;
  edition: Edition;
  packageType: PackageType;
  deliveryRole: DeliveryRole;
};

export type ClassifiedReleaseAsset = AssetClassification & {
  id: number;
  name: string;
  size: number;
  contentType: string;
  browserDownloadUrl: string;
  releaseTag: string;
  channel: Channel;
  publishedAt: string;
};

export type NormalizedRelease = {
  tag: string;
  name: string;
  publishedAt: string;
  htmlUrl: string;
  assets: ClassifiedReleaseAsset[];
};

export type AssetStatus = "current" | "replaced" | "deleted";

export type SnapshotAsset = {
  snapshotAt: string;
  releaseId: number;
  releaseTag: string;
  channel: "stable" | "nightly";
  publishedAt: string;
  prerelease: boolean;
  assetId: number;
  name: string;
  createdAt: string;
  updatedAt: string;
  size: number;
  contentType: string;
  downloadCount: number;
  platform: Platform;
  architecture: Architecture;
  edition: Edition;
  packageType: PackageType;
  deliveryRole: DeliveryRole;
  status: AssetStatus;
  delta: number | null;
};

export type Snapshot = {
  schemaVersion: 1;
  repository: "adamgell/cmtraceopen";
  capturedAt: string;
  assets: SnapshotAsset[];
};

export type GitHubAsset = {
  id: number;
  name: string;
  created_at: string;
  updated_at: string;
  size: number;
  content_type: string;
  download_count: number;
  browser_download_url: string;
};

export type GitHubRelease = {
  id: number;
  tag_name: string;
  name: string | null;
  published_at: string;
  prerelease: boolean;
  draft: boolean;
  assets: GitHubAsset[];
};

export type RoleSummary = Record<DeliveryRole, { cumulative: number; delta: number }>;
