import { describe, expect, it } from "vitest";

import { classifyAsset, recommendationRank } from "../src/classify";
import { CLASSIFICATION_CONTRACT, type ClassifiedReleaseAsset } from "../src/types";

describe("download metrics classification parity", () => {
  it("pins the shared classification contract", () => {
    expect(CLASSIFICATION_CONTRACT).toBe("2026-07-13.1");
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
});
