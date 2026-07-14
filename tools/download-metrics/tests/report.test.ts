import { describe, expect, it } from "vitest";

import { buildSummary, toCsv } from "../src/report";
import type { DeliveryRole, Snapshot, SnapshotAsset } from "../src/types";

const roles: DeliveryRole[] = [
  "manual-only",
  "mixed-manual-update",
  "updater-only",
  "supporting-file",
  "unknown",
];

function row(
  assetId: number,
  deliveryRole: DeliveryRole,
  downloadCount: number,
  delta: number | null,
  overrides: Partial<SnapshotAsset> = {},
): SnapshotAsset {
  return {
    snapshotAt: "2026-07-14T00:17:00.000Z",
    releaseId: 10,
    releaseTag: "v1.4.0",
    channel: "stable",
    publishedAt: "2026-04-01T12:30:00Z",
    prerelease: false,
    assetId,
    name: `asset-${assetId}.bin`,
    createdAt: "2026-04-01T12:31:00Z",
    updatedAt: "2026-04-01T12:32:00Z",
    size: 1_024,
    contentType: "application/octet-stream",
    downloadCount,
    delta,
    platform: "unknown",
    architecture: "unknown",
    edition: "unknown",
    packageType: "unknown",
    deliveryRole,
    status: "current",
    ...overrides,
  };
}

function snapshot(assets: SnapshotAsset[]): Snapshot {
  return {
    schemaVersion: 1,
    repository: "adamgell/cmtraceopen",
    capturedAt: "2026-07-14T00:17:00.000Z",
    assets,
  };
}

describe("role-separated summary", () => {
  it("reports cumulative asset deliveries and deltas independently for every role", () => {
    const summary = buildSummary(
      snapshot([
        row(1, "manual-only", 10, 2),
        row(2, "mixed-manual-update", 20, 3),
        row(3, "updater-only", 30, null),
        row(4, "supporting-file", 40, 4),
        row(5, "unknown", 50, 5),
      ]),
    );

    expect(Object.keys(summary)).toEqual(roles);
    expect(summary).toEqual({
      "manual-only": { cumulative: 10, delta: 2 },
      "mixed-manual-update": { cumulative: 20, delta: 3 },
      "updater-only": { cumulative: 30, delta: 0 },
      "supporting-file": { cumulative: 40, delta: 4 },
      unknown: { cumulative: 50, delta: 5 },
    });
    expect(summary["manual-only"]).toEqual({ cumulative: 10, delta: 2 });
  });

  it("keeps unknown diagnostics separate from every known headline role", () => {
    const summary = buildSummary(snapshot([row(5, "unknown", 99, 8)]));

    expect(summary.unknown).toEqual({ cumulative: 99, delta: 8 });
    for (const role of roles.filter((candidate) => candidate !== "unknown")) {
      expect(summary[role]).toEqual({ cumulative: 0, delta: 0 });
    }
  });

  it("excludes deleted and replaced tombstones from current totals", () => {
    const summary = buildSummary(
      snapshot([
        row(1, "manual-only", 10, 2),
        row(2, "manual-only", 20, 0, { status: "replaced" }),
        row(3, "manual-only", 30, 0, { status: "deleted" }),
      ]),
    );

    expect(summary["manual-only"]).toEqual({ cumulative: 10, delta: 2 });
  });

  it("never exposes user, installation, activity, uniqueness, or conversion semantics", () => {
    const summary = buildSummary(snapshot([]));
    const serialized = JSON.stringify(summary);

    for (const forbidden of [
      "users",
      "installs",
      "activeUsers",
      "conversion",
      "unique",
    ]) {
      expect(summary).not.toHaveProperty(forbidden);
      expect(serialized).not.toContain(forbidden);
    }
  });
});

describe("stable CSV report", () => {
  it("uses the exact header and deterministic row ordering", () => {
    const csv = toCsv(
      snapshot([
        row(30, "manual-only", 3, 1, {
          releaseTag: "z-nightly",
          platform: "windows",
          architecture: "arm64",
          packageType: "portable-exe",
        }),
        row(20, "manual-only", 2, null, {
          releaseTag: "v1.4.0",
          platform: "windows",
          architecture: "x64",
          packageType: "msi",
        }),
        row(10, "manual-only", 1, 0, {
          releaseTag: "v1.4.0",
          platform: "macos",
          architecture: "arm64",
          packageType: "dmg",
        }),
      ]),
    );
    const lines = csv.trimEnd().split("\n");

    expect(lines[0]).toBe(
      "snapshot_at,release_id,release_tag,channel,published_at,prerelease,asset_id,name,created_at,updated_at,size,content_type,download_count,delta,platform,architecture,edition,package_type,delivery_role,status",
    );
    expect(lines.slice(1).map((line) => line.split(",")[6])).toEqual([
      '"10"',
      '"20"',
      '"30"',
    ]);
    expect(csv.endsWith("\n")).toBe(true);
  });

  it("quotes every field and escapes filenames, timestamps, and content types safely", () => {
    const csv = toCsv(
      snapshot([
        row(7, "supporting-file", 12, null, {
          name: 'CMTrace, "verified"\nasset.sig',
          snapshotAt: '2026-07-14T00:17:00.000Z',
          createdAt: '2026-04-01T12:31:00Z',
          contentType: 'application/x-test; note="quoted"',
        }),
      ]),
    );

    expect(csv).toContain('"2026-07-14T00:17:00.000Z"');
    expect(csv).toContain('"CMTrace, ""verified""\nasset.sig"');
    expect(csv).toContain('"application/x-test; note=""quoted"""');
    expect(csv).toContain(',"12","","unknown",');
  });
});
