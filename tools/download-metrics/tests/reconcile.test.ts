import { describe, expect, it } from "vitest";

import { reconcileSnapshots } from "../src/reconcile";
import type {
  GitHubAsset,
  GitHubRelease,
  Snapshot,
  SnapshotAsset,
} from "../src/types";

const CAPTURED_AT = "2026-07-14T00:17:00.000Z";

function asset(
  id: number,
  name: string,
  downloadCount: number,
  overrides: Partial<GitHubAsset> = {},
): GitHubAsset {
  return {
    id,
    name,
    created_at: "2026-07-13T10:00:00Z",
    updated_at: "2026-07-13T11:00:00Z",
    size: 1_024,
    content_type: "application/octet-stream",
    download_count: downloadCount,
    browser_download_url: `https://github.com/adamgell/cmtraceopen/releases/download/nightly/${name}`,
    ...overrides,
  };
}

function release(
  assets: GitHubAsset[],
  overrides: Partial<GitHubRelease> = {},
): GitHubRelease {
  return {
    id: 99,
    tag_name: "nightly",
    name: "Nightly",
    published_at: "2026-07-13T09:00:00Z",
    prerelease: true,
    draft: false,
    assets,
    ...overrides,
  };
}

function previousAsset(overrides: Partial<SnapshotAsset> = {}): SnapshotAsset {
  return {
    snapshotAt: "2026-07-13T00:17:00.000Z",
    releaseId: 99,
    releaseTag: "nightly",
    channel: "nightly",
    publishedAt: "2026-07-13T09:00:00Z",
    prerelease: true,
    assetId: 101,
    name: "CMTrace-Open_Nightly_20260713_1_abc123_x64.exe",
    createdAt: "2026-07-13T10:00:00Z",
    updatedAt: "2026-07-13T11:00:00Z",
    size: 1_024,
    contentType: "application/octet-stream",
    downloadCount: 10,
    platform: "windows",
    architecture: "x64",
    edition: "full",
    packageType: "portable-exe",
    deliveryRole: "manual-only",
    status: "current",
    delta: null,
    ...overrides,
  };
}

function previous(assets: SnapshotAsset[]): Snapshot {
  return {
    schemaVersion: 1,
    repository: "adamgell/cmtraceopen",
    capturedAt: "2026-07-13T00:17:00.000Z",
    assets,
  };
}

describe("snapshot reconciliation", () => {
  it("uses null deltas for the first cumulative observation", () => {
    const snapshot = reconcileSnapshots(
      null,
      [release([asset(101, "CMTrace-Open_Nightly_20260713_1_abc123_x64.exe", 10)])],
      CAPTURED_AT,
    );

    expect(snapshot).toEqual({
      schemaVersion: 1,
      repository: "adamgell/cmtraceopen",
      capturedAt: CAPTURED_AT,
      assets: [
        expect.objectContaining({
          snapshotAt: CAPTURED_AT,
          assetId: 101,
          downloadCount: 10,
          delta: null,
          status: "current",
          platform: "windows",
          architecture: "x64",
          edition: "full",
          packageType: "portable-exe",
          deliveryRole: "manual-only",
        }),
      ],
    });
  });

  it("derives a delta by stable numeric asset ID", () => {
    const snapshot = reconcileSnapshots(
      previous([previousAsset()]),
      [release([asset(101, "CMTrace-Open_Nightly_20260713_1_abc123_x64.exe", 14)])],
      CAPTURED_AT,
    );

    expect(snapshot.assets).toHaveLength(1);
    expect(snapshot.assets[0]).toMatchObject({
      assetId: 101,
      downloadCount: 14,
      delta: 4,
      status: "current",
    });
  });

  it("rejects a negative delta instead of normalizing it away", () => {
    expect(() =>
      reconcileSnapshots(
        previous([previousAsset()]),
        [release([asset(101, "CMTrace-Open_Nightly_20260713_1_abc123_x64.exe", 9)])],
        CAPTURED_AT,
      ),
    ).toThrow("Negative download delta for asset 101");
  });

  it("marks a missing nightly asset replaced only when the exact logical key matches", () => {
    const old = previousAsset({
      assetId: 101,
      name: "old-name-that-does-not-drive-replacement.exe",
    });
    const snapshot = reconcileSnapshots(
      previous([old]),
      [release([asset(202, "CMTrace-Open_Nightly_20260714_2_def456_x64.exe", 0)])],
      CAPTURED_AT,
    );

    expect(snapshot.assets).toEqual([
      expect.objectContaining({
        assetId: 101,
        name: "old-name-that-does-not-drive-replacement.exe",
        downloadCount: 10,
        delta: 0,
        status: "replaced",
      }),
      expect.objectContaining({
        assetId: 202,
        downloadCount: 0,
        delta: null,
        status: "current",
      }),
    ]);
  });

  it.each([
    ["releaseTag", { tag_name: "v1.4.0", prerelease: false }, {}],
    ["platform", {}, { name: "CMTrace.Open_Nightly_20260714_2_def456_amd64.AppImage" }],
    ["architecture", {}, { name: "CMTrace-Open_Nightly_20260714_2_def456_arm64.exe" }],
    ["edition", {}, { name: "CMTrace-Open-Lite_Nightly_20260714_2_def456_x64.exe" }],
    ["packageType", {}, { name: "CMTrace-Open_Nightly_20260714_2_def456_x64.msi" }],
    ["deliveryRole", {}, { name: "CMTrace-Open_Nightly_20260714_2_def456_x64-setup.exe" }],
  ])(
    "does not replace an asset when only %s differs",
    (_field, releaseOverrides, assetOverrides) => {
      const snapshot = reconcileSnapshots(
        previous([previousAsset()]),
        [
          release(
            [
              asset(
                202,
                "CMTrace-Open_Nightly_20260714_2_def456_x64.exe",
                1,
                assetOverrides as Partial<GitHubAsset>,
              ),
            ],
            releaseOverrides as Partial<GitHubRelease>,
          ),
        ],
        CAPTURED_AT,
      );

      expect(snapshot.assets.find(({ assetId }) => assetId === 101)?.status).toBe(
        "deleted",
      );
    },
  );

  it("creates a deleted tombstone that retains the last observed count and metadata", () => {
    const old = previousAsset({
      assetId: 303,
      name: "removed.bin",
      downloadCount: 7,
      platform: "unknown",
      architecture: "unknown",
      edition: "unknown",
      packageType: "unknown",
      deliveryRole: "unknown",
    });

    const snapshot = reconcileSnapshots(previous([old]), [], CAPTURED_AT);

    expect(snapshot.assets).toEqual([
      {
        ...old,
        snapshotAt: CAPTURED_AT,
        status: "deleted",
        delta: 0,
      },
    ]);
  });

  it("keeps existing tombstones across later snapshots", () => {
    const old = previousAsset({ status: "replaced", delta: 0 });

    const snapshot = reconcileSnapshots(previous([old]), [], CAPTURED_AT);

    expect(snapshot.assets[0]).toMatchObject({
      assetId: 101,
      status: "replaced",
      delta: 0,
      snapshotAt: CAPTURED_AT,
    });
  });

  it("preserves zero-count current assets", () => {
    const snapshot = reconcileSnapshots(
      null,
      [release([asset(404, "mystery-download.bin", 0)])],
      CAPTURED_AT,
    );

    expect(snapshot.assets).toEqual([
      expect.objectContaining({
        assetId: 404,
        downloadCount: 0,
        deliveryRole: "unknown",
        status: "current",
      }),
    ]);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5])(
    "rejects invalid download count %s",
    (downloadCount) => {
      expect(() =>
        reconcileSnapshots(
          null,
          [release([asset(505, "mystery-download.bin", downloadCount)])],
          CAPTURED_AT,
        ),
      ).toThrow("Invalid download count for asset 505");
    },
  );

  it("sorts snapshot rows by release tag, platform, architecture, package type, and asset ID", () => {
    const snapshot = reconcileSnapshots(
      null,
      [
        release(
          [
            asset(30, "CMTrace-Open_Nightly_20260714_2_def456_arm64.exe", 0),
            asset(20, "CMTrace-Open_Nightly_20260714_2_def456_x64.msi", 0),
            asset(10, "CMTrace-Open_Nightly_20260714_2_def456_x64.exe", 0),
          ],
          { tag_name: "z-nightly" },
        ),
        release([asset(40, "CMTrace.Open_1.4.0_aarch64.dmg", 0)], {
          id: 50,
          tag_name: "v1.4.0",
          prerelease: false,
        }),
      ],
      CAPTURED_AT,
    );

    expect(snapshot.assets.map(({ assetId }) => assetId)).toEqual([40, 30, 20, 10]);
  });
});
