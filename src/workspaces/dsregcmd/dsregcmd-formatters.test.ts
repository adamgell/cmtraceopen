import { describe, expect, it } from "vitest";
import { toneForPrtState } from "./dsregcmd-formatters";

describe("toneForPrtState", () => {
  it("is neutral when PRT presence is unknown", () => {
    expect(toneForPrtState(null, null)).toBe("neutral");
  });

  it("is bad when no PRT is present", () => {
    expect(toneForPrtState(false, null)).toBe("bad");
  });

  it("is warn when the PRT is stale", () => {
    expect(toneForPrtState(true, true)).toBe("warn");
  });

  it("is good when the PRT is present and fresh", () => {
    expect(toneForPrtState(true, false)).toBe("good");
  });

  it("is neutral when freshness is unknown instead of claiming health", () => {
    expect(toneForPrtState(true, null)).toBe("neutral");
    expect(toneForPrtState(true, undefined)).toBe("neutral");
  });
});
