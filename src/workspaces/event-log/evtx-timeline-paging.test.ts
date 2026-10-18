/**
 * The paging constants are defined once. The engine's preview limit is mirrored from Rust, so a test
 * reads the Rust source and pins it; and no consumer keeps a number of its own for it.
 */
import { describe, expect, it } from "vitest";
import analysisSessionSource from "../../../src-tauri/src/event_log/analysis_session.rs?raw";
import {
  EVENT_LOG_TIMELINE_PAGE_SIZE,
  EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT,
} from "./evtx-timeline-paging";
import unifiedTimelineViewSource from "./UnifiedTimelineView.tsx?raw";

const withoutComments = (text: string) =>
  text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

describe("the engine's preview limit", () => {
  it("equals MAX_ANALYSIS_TIMELINE_PREVIEW_ITEMS in analysis_session.rs, which caps the unplaced, edge and gap previews", () => {
    const engine = /const MAX_ANALYSIS_TIMELINE_PREVIEW_ITEMS: usize = (\d+);/.exec(analysisSessionSource);
    expect(engine).not.toBeNull();
    expect(EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT).toBe(Number(engine?.[1]));
    // bounded_preview applies it to all three previews, so one number is right for all three.
    const previews = [...analysisSessionSource.matchAll(/bounded_preview\(timeline\.(\w+)\.iter\(\)/g)].map(
      (match) => match[1],
    );
    expect(previews).toEqual(["unplaced", "edges", "coverage_gaps"]);
    expect(analysisSessionSource).toMatch(/\.take\(MAX_ANALYSIS_TIMELINE_PREVIEW_ITEMS\)/);
  });

  it("is imported by the unified timeline for its three previews, which keep no number of their own", () => {
    const code = withoutComments(unifiedTimelineViewSource);
    const importBlock = /import \{[^}]*\} from "\.\/evtx-timeline-paging";/.exec(code);
    expect(importBlock?.[0]).toContain("EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT");
    // The unplaced, edge and coverage-gap previews, and no more.
    const body = code.replace(importBlock?.[0] ?? "", "");
    expect(body.match(/\bEVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT\b/g)).toHaveLength(3);
    expect(code).not.toMatch(/\bUNPLACED_PREVIEW_LIMIT\b|\bUNPLACED_LIST_LIMIT\b/);
  });

  it("is not the evidence-row cap, which is a display cap of its own with its own name", () => {
    const code = withoutComments(unifiedTimelineViewSource);
    expect(code).toMatch(/const EDGE_EVIDENCE_ROWS_SHOWN = 100;/);
    expect(code).not.toMatch(/edge\.evidence\.slice\(0, EVENT_LOG_TIMELINE_PREVIEW_ITEM_LIMIT\)/);
  });

  it("sits beside the page size, which it is not", () => {
    expect(EVENT_LOG_TIMELINE_PAGE_SIZE).toBe(1_000);
  });
});
