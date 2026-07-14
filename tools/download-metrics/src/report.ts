import { compareSnapshotAssets } from "./reconcile";
import type { DeliveryRole, RoleSummary, Snapshot } from "./types";

const ROLES: DeliveryRole[] = [
  "manual-only",
  "mixed-manual-update",
  "updater-only",
  "supporting-file",
  "unknown",
];

const CSV_HEADER = [
  "snapshot_at",
  "release_id",
  "release_tag",
  "channel",
  "published_at",
  "prerelease",
  "asset_id",
  "name",
  "created_at",
  "updated_at",
  "size",
  "content_type",
  "download_count",
  "delta",
  "platform",
  "architecture",
  "edition",
  "package_type",
  "delivery_role",
  "status",
].join(",");

export function buildSummary(snapshot: Snapshot): RoleSummary {
  const summary = Object.fromEntries(
    ROLES.map((role) => [role, { cumulative: 0, delta: 0 }]),
  ) as RoleSummary;

  for (const asset of snapshot.assets) {
    if (asset.status !== "current") {
      continue;
    }
    summary[asset.deliveryRole].cumulative += asset.downloadCount;
    summary[asset.deliveryRole].delta += asset.delta ?? 0;
  }

  return summary;
}

function quoteCsv(value: string | number | boolean | null): string {
  const rendered = value === null ? "" : String(value);
  return `"${rendered.replaceAll('"', '""')}"`;
}

export function toCsv(snapshot: Snapshot): string {
  const rows = [...snapshot.assets].sort(compareSnapshotAssets).map((asset) =>
    [
      asset.snapshotAt,
      asset.releaseId,
      asset.releaseTag,
      asset.channel,
      asset.publishedAt,
      asset.prerelease,
      asset.assetId,
      asset.name,
      asset.createdAt,
      asset.updatedAt,
      asset.size,
      asset.contentType,
      asset.downloadCount,
      asset.delta,
      asset.platform,
      asset.architecture,
      asset.edition,
      asset.packageType,
      asset.deliveryRole,
      asset.status,
    ]
      .map(quoteCsv)
      .join(","),
  );

  return `${[CSV_HEADER, ...rows].join("\n")}\n`;
}
