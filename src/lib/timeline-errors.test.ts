import { describe, expect, it } from "vitest";
import { formatTimelineError, isFirewallTimelineError } from "./timeline-errors";
import { firewallTimelineError } from "../test-utils/timeline";
describe("scoped firewall timeline errors", () => {
  it.each(["sourceChanged", "generationUnverifiable", "readDecodeFailure", "invalidIndexContext"] as const)("formats %s with its source", reason => {
    const error = firewallTimelineError(reason);
    expect(isFirewallTimelineError(error)).toBe(true);
    expect(formatTimelineError(error)).toContain(error.path);
    expect(formatTimelineError(error)).not.toContain("[object Object]");
  });
  it("keeps ordinary messages and rejects unknown structured kinds", () => {
    expect(formatTimelineError(new Error("ordinary"))).toBe("ordinary");
    expect(isFirewallTimelineError({ ...firewallTimelineError(), reason: "invented" })).toBe(false);
    expect(isFirewallTimelineError({ ...firewallTimelineError(), sourceIdx: -1 })).toBe(false);
  });
});
