import { classifyAsset } from "./classify";
import type {
  GitHubRelease,
  Snapshot,
  SnapshotAsset,
} from "./types";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function compareSnapshotAssets(
  left: SnapshotAsset,
  right: SnapshotAsset,
): number {
  return (
    compareText(left.releaseTag, right.releaseTag) ||
    compareText(left.platform, right.platform) ||
    compareText(left.architecture, right.architecture) ||
    compareText(left.packageType, right.packageType) ||
    left.assetId - right.assetId
  );
}

function logicalKey(asset: SnapshotAsset): string {
  return JSON.stringify([
    asset.releaseTag,
    asset.platform,
    asset.architecture,
    asset.edition,
    asset.packageType,
    asset.deliveryRole,
  ]);
}

function validateCount(assetId: number, count: number): void {
  if (!Number.isFinite(count) || !Number.isInteger(count) || count < 0) {
    throw new Error(`Invalid download count for asset ${assetId}`);
  }
}

function flattenCurrent(
  releases: GitHubRelease[],
  capturedAt: string,
): SnapshotAsset[] {
  const seenIds = new Set<number>();

  return releases.flatMap((release) =>
    release.assets.map((asset) => {
      if (!Number.isSafeInteger(asset.id) || asset.id <= 0) {
        throw new Error(`Invalid asset ID ${asset.id}`);
      }
      if (seenIds.has(asset.id)) {
        throw new Error(`Duplicate asset ID ${asset.id}`);
      }
      seenIds.add(asset.id);
      validateCount(asset.id, asset.download_count);

      const classification = classifyAsset(asset.name);
      return {
        snapshotAt: capturedAt,
        releaseId: release.id,
        releaseTag: release.tag_name,
        channel: release.tag_name.toLowerCase() === "nightly" ? "nightly" : "stable",
        publishedAt: release.published_at,
        prerelease: release.prerelease,
        assetId: asset.id,
        name: asset.name,
        createdAt: asset.created_at,
        updatedAt: asset.updated_at,
        size: asset.size,
        contentType: asset.content_type,
        downloadCount: asset.download_count,
        ...classification,
        status: "current" as const,
        delta: null,
      };
    }),
  );
}

export function reconcileSnapshots(
  previous: Snapshot | null,
  currentAssets: GitHubRelease[],
  capturedAt: string,
): Snapshot {
  const current = flattenCurrent(currentAssets, capturedAt);
  const previousById = new Map<number, SnapshotAsset>();

  for (const asset of previous?.assets ?? []) {
    validateCount(asset.assetId, asset.downloadCount);
    if (previousById.has(asset.assetId)) {
      throw new Error(`Duplicate asset ID ${asset.assetId} in previous snapshot`);
    }
    previousById.set(asset.assetId, asset);
  }

  const reconciledCurrent = current.map((asset): SnapshotAsset => {
    const prior = previousById.get(asset.assetId);
    if (!prior) {
      return asset;
    }

    const delta = asset.downloadCount - prior.downloadCount;
    if (delta < 0) {
      throw new Error(`Negative download delta for asset ${asset.assetId}`);
    }

    return { ...asset, delta };
  });

  const currentIds = new Set(current.map(({ assetId }) => assetId));
  const currentLogicalKeys = new Set(current.map(logicalKey));
  const tombstones = [...previousById.values()]
    .filter(({ assetId }) => !currentIds.has(assetId))
    .map((asset): SnapshotAsset => ({
      ...asset,
      snapshotAt: capturedAt,
      delta: 0,
      status:
        asset.status === "current"
          ? currentLogicalKeys.has(logicalKey(asset))
            ? "replaced"
            : "deleted"
          : asset.status,
    }));

  return {
    schemaVersion: 1,
    repository: "adamgell/cmtraceopen",
    capturedAt,
    assets: [...reconciledCurrent, ...tombstones].sort(compareSnapshotAssets),
  };
}
