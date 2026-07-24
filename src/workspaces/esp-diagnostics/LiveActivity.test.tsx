import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { LiveActivity } from "./LiveActivity";
import type { EspTimelineEntry } from "./types";

function entry(title: string): EspTimelineEntry {
  return {
    entryId: "e1",
    timestamp: {
      rawText: "2026-07-23T20:00:00Z",
      originalOffset: "Z",
      normalizedUtc: "2026-07-23T20:00:00Z",
      kind: "utc",
    },
    kind: "workload",
    title,
    detail: null,
    status: null,
    evidence: [],
  };
}

describe("LiveActivity", () => {
  it("rewrites a known workload GUID in the timeline to its name", () => {
    const names = new Map([
      ["18c617f8-26d2-40d5-9e0f-fc1015e5da79", "Windows Autopatch Client Broker"],
    ]);
    const { container } = render(
      <LiveActivity
        entries={[entry("Win32App_18c617f8-26d2-40d5-9e0f-fc1015e5da79_1")]}
        graphNames={names}
      />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("Windows Autopatch Client Broker");
    expect(text).not.toContain("Win32App_18c617f8");
  });

  it("leaves an unknown setup GUID untouched", () => {
    const { container } = render(
      <LiveActivity
        entries={[entry("Reconstruct OS {04A446E2-4ADE-42DC-810B-EA70CE70CF11}")]}
        graphNames={new Map()}
      />,
    );
    expect(container.textContent).toContain(
      "{04A446E2-4ADE-42DC-810B-EA70CE70CF11}",
    );
  });
});
