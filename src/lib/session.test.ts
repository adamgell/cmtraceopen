import { describe, it, expect } from "vitest";
import { validateSession, createEmptySession } from "./session";

function sessionWith(clauses: unknown[]): Record<string, unknown> {
  return {
    version: 1,
    savedAt: "2026-01-01T00:00:00Z",
    workspace: "log",
    tabs: [],
    activeTabIndex: 0,
    mergedTabState: null,
    filters: {
      clauses,
      findQuery: "",
      findCaseSensitive: false,
      findUseRegex: false,
      highlightText: "",
    },
    workspaceState: { type: "log" },
  };
}

describe("validateSession filter clauses", () => {
  it("keeps well-formed clauses", () => {
    const session = validateSession(
      sessionWith([{ field: "Message", op: "Contains", value: "error" }])
    );
    expect(session).not.toBeNull();
    expect(session!.filters.clauses).toEqual([
      { field: "Message", op: "Contains", value: "error" },
    ]);
  });

  it("drops malformed clauses but keeps valid ones", () => {
    const session = validateSession(
      sessionWith([
        { field: "Message", op: "Contains", value: "error" }, // valid
        { field: "Bogus", op: "Contains", value: "x" }, // invalid field
        { field: "Message", op: "Nope", value: "x" }, // invalid op
        { field: "Message", op: "Contains", value: 42 }, // non-string value
        "not-an-object",
        null,
      ])
    );
    expect(session).not.toBeNull();
    expect(session!.filters.clauses).toEqual([
      { field: "Message", op: "Contains", value: "error" },
    ]);
  });

  it("yields an empty clause list when clauses is missing or not an array", () => {
    const empty = createEmptySession();
    expect(empty.filters.clauses).toEqual([]);

    const session = validateSession(sessionWith("nonsense" as unknown as unknown[]));
    expect(session).not.toBeNull();
    expect(session!.filters.clauses).toEqual([]);
  });
});
