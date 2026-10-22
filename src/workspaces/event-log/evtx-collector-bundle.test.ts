/** The bundle id of a collector layout, as the engine reads it (`bundle_from_source`). */
import { describe, expect, it } from "vitest";
import { bundleOfSource } from "./evtx-collector-bundle";

describe("bundleOfSource (a mirror of the engine's bundle_from_source)", () => {
  const ID = "CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdef";

  it("reads the bundle id from the collector's layout, on either separator", () => {
    expect(bundleOfSource(`/ProgramData/CmtraceOpen/Evidence/${ID}/evidence/dhcp.log`)).toBe(ID);
    expect(
      bundleOfSource("C:\\ProgramData\\CmtraceOpen\\Evidence\\CMTRACE-20260822-120000-HOST-abcdef0123456789abcdef0123456789\\evidence\\ccm.log"),
    ).toBe("CMTRACE-20260822-120000-HOST-abcdef0123456789abcdef0123456789");
  });

  it("ignores case in the prefix, the evidence segment and the hex nonce, and keeps the id as written", () => {
    const id = "cmtrace-20260822-120000-HOST-0123456789ABCDEF0123456789abcdef";
    expect(bundleOfSource(`/x/${id}/EVIDENCE/a.log`)).toBe(id);
  });

  it("accepts a host name with dashes and a leap day, and rejects a day that is not on the calendar", () => {
    expect(bundleOfSource("/c/CMTRACE-20240229-120000-MY-HOST-1-0123456789abcdef0123456789abcdef/evidence/a")).toBe(
      "CMTRACE-20240229-120000-MY-HOST-1-0123456789abcdef0123456789abcdef",
    );
    expect(bundleOfSource("/c/CMTRACE-20230229-120000-HOST-0123456789abcdef0123456789abcdef/evidence/a")).toBeNull();
    expect(bundleOfSource("/c/CMTRACE-19000229-120000-HOST-0123456789abcdef0123456789abcdef/evidence/a")).toBeNull();
    expect(bundleOfSource("/c/CMTRACE-20000229-120000-HOST-0123456789abcdef0123456789abcdef/evidence/a")).not.toBeNull();
  });

  it.each([
    ["a path that is not collector output", "/captures/arbitrary/bundle/evidence/event.evtx"],
    ["a nonce that is not 32 hex digits", "/captures/CMTRACE-20260822-120000-HOST-not-a-uuid/evidence/event.evtx"],
    ["a month of 13", "/captures/CMTRACE-20261340-120000-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"],
    ["an hour of 25", "/captures/CMTRACE-20260822-250061-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"],
    ["year 0", "/captures/CMTRACE-00000101-120000-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"],
    ["a second of 60", "/captures/CMTRACE-20260822-235960-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"],
    ["an empty host", "/captures/CMTRACE-20260822-120000--0123456789abcdef0123456789abcdef/evidence/event.evtx"],
    ["an hour of 24", "/captures/CMTRACE-20260822-240000-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"],
    ["a minute of 60", "/captures/CMTRACE-20260822-126000-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"],
    ["a nonce of 31 hex digits", "/captures/CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcde/evidence/event.evtx"],
    ["a nonce of 33 hex digits", "/captures/CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdef0/evidence/event.evtx"],
    ["a nonce of 32 characters that are not all hex", "/captures/CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdeg/evidence/event.evtx"],
    ["a segment that is not followed by evidence", `/captures/${"CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdef"}/logs/event.evtx`],
  ])("returns null for %s (the engine's own rejections)", (_why, source) => {
    expect(bundleOfSource(source)).toBeNull();
  });

  it("takes the first valid pair and skips an invalid one before it", () => {
    const first = "CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdef";
    const second = "CMTRACE-20260823-130000-HOST-fedcba9876543210fedcba9876543210";
    expect(bundleOfSource(`/c/CMTRACE-20260822-120000-HOST-short/evidence/${first}/evidence/${second}/evidence/a`)).toBe(first);
    expect(bundleOfSource(`/c/${first}/evidence/${second}/evidence/a`)).toBe(first);
  });

  it("is null for an empty source", () => {
    expect(bundleOfSource("")).toBeNull();
  });
});
