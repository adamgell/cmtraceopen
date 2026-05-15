import { describe, expect, it } from "vitest";
import {
  getReleasePageUrl,
  getUpdateChannel,
  getUpdateChannelLabel,
} from "./update-channel";

describe("update channel metadata", () => {
  it("treats nightly prerelease versions as the nightly channel", () => {
    expect(getUpdateChannel("1.3.2-nightly.20260514.42.gabc123def456")).toBe("nightly");
  });

  it("treats regular versions as the stable channel", () => {
    expect(getUpdateChannel("1.3.2")).toBe("stable");
  });

  it("links nightly builds to the mutable nightly release", () => {
    expect(getReleasePageUrl("nightly")).toBe(
      "https://github.com/adamgell/cmtraceopen/releases/tag/nightly"
    );
  });

  it("uses human-readable channel labels", () => {
    expect(getUpdateChannelLabel("stable")).toBe("Stable channel");
    expect(getUpdateChannelLabel("nightly")).toBe("Nightly channel");
  });
});
