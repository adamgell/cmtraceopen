import { describe, expect, it } from "vitest";

import { classifyAsset, recommendationRank } from "../src/classify";
import { CLASSIFICATION_CONTRACT, type ClassifiedReleaseAsset } from "../src/types";
import fixture from "./fixtures/release-assets.json";

describe("download metrics classification parity", () => {
  it("pins the shared classification contract", () => {
    expect(CLASSIFICATION_CONTRACT).toBe("2026-07-13.1");
  });

  it.each(fixture.assets)("classifies $name exactly like the site", ({ name, expected }) => {
    expect(classifyAsset(name)).toEqual(expected);
  });

  it.each(fixture.assets)("ranks $name exactly like the site", (asset) => {
    const classified: ClassifiedReleaseAsset = {
      ...classifyAsset(asset.name),
      id: asset.id,
      name: asset.name,
      size: asset.size,
      contentType: asset.content_type,
      browserDownloadUrl: asset.browser_download_url,
      releaseTag: "fixture",
      channel: asset.browser_download_url.includes("/nightly/") ? "nightly" : "stable",
      publishedAt: "2026-07-13T00:00:00Z",
    };

    expect(recommendationRank(classified)).toBe(asset.expected_rank);
  });

  it("classifies a representative stable asset", () => {
    expect(classifyAsset("CMTrace-Open_1.4.0_x64.exe")).toEqual({
      platform: "windows",
      architecture: "x64",
      edition: "full",
      packageType: "portable-exe",
      deliveryRole: "manual-only",
    });
  });

  it("classifies a representative nightly asset", () => {
    expect(
      classifyAsset("CMTrace-Open_Nightly_20260713_75_efb9803c9f91_x64-setup.exe"),
    ).toEqual({
      platform: "windows",
      architecture: "x64",
      edition: "full",
      packageType: "nsis-setup",
      deliveryRole: "mixed-manual-update",
    });
  });

  it("preserves the recommended Windows portable rank", () => {
    const asset: ClassifiedReleaseAsset = {
      ...classifyAsset("CMTrace-Open_1.4.0_x64.exe"),
      id: 475711960,
      name: "CMTrace-Open_1.4.0_x64.exe",
      size: 23561984,
      contentType: "application/x-msdownload",
      browserDownloadUrl:
        "https://github.com/adamgell/cmtraceopen/releases/download/v1.4.0/CMTrace-Open_1.4.0_x64.exe",
      releaseTag: "v1.4.0",
      channel: "stable",
      publishedAt: "2026-07-13T00:00:00Z",
    };

    expect(recommendationRank(asset)).toBe(0);
  });

  it("keeps unknown assets out of every headline role", () => {
    const classification = classifyAsset("mystery-download.bin");
    const asset: ClassifiedReleaseAsset = {
      ...classification,
      id: 1,
      name: "mystery-download.bin",
      size: 1,
      contentType: "application/octet-stream",
      browserDownloadUrl:
        "https://github.com/adamgell/cmtraceopen/releases/download/fixture/mystery-download.bin",
      releaseTag: "fixture",
      channel: "stable",
      publishedAt: "2026-07-13T00:00:00Z",
    };

    expect(classification).toEqual({
      platform: "unknown",
      architecture: "unknown",
      edition: "unknown",
      packageType: "unknown",
      deliveryRole: "unknown",
    });
    expect(recommendationRank(asset)).toBeNull();
  });
});
