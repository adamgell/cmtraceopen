import { describe, expect, it } from "vitest";
import { validateSession } from "./session";

function createSessionInput() {
  return {
    version: 1,
    savedAt: "2024-01-01T00:00:00.000Z",
    workspace: "log",
    tabs: [
      {
        filePath: "/logs/app.log",
        fileHash: "",
        fileSize: 0,
        selectedId: null,
        scrollPosition: null,
        activeColumns: [],
      },
    ],
    activeTabIndex: 0,
    mergedTabState: null,
    workspaceState: { type: "log" },
  };
}

describe("session validation", () => {
  it("preserves valid saved filter clauses", () => {
    const data = {
      ...createSessionInput(),
      filters: {
        clauses: [
          { field: "Message", op: "Contains", value: "error" },
          { field: "Severity", op: "Equals", value: "warning" },
        ],
        findQuery: "needle",
        findCaseSensitive: true,
        findUseRegex: false,
        highlightText: "match",
      },
    };

    const session = validateSession(data);

    expect(session).not.toBeNull();
    expect(session?.filters).toEqual(data.filters);
  });

  it("drops malformed clauses without rejecting the session", () => {
    const validClause = { field: "Component", op: "Equals", value: "SmsProvider" } as const;
    const data = {
      ...createSessionInput(),
      filters: {
        clauses: [
          validClause,
          { field: "Component", op: "Bogus", value: "bad" },
          { field: "Unknown", op: "Contains", value: "bad" },
          { field: "Thread", op: "Contains" },
          { field: "Message", op: "Contains", value: 42 },
          null,
          "raw-json",
        ],
        findQuery: "needle",
        findCaseSensitive: false,
        findUseRegex: true,
        highlightText: "focus",
      },
    };

    const session = validateSession(data);

    expect(session).not.toBeNull();
    expect(session?.filters.clauses).toEqual([validClause]);
    expect(session?.filters.findQuery).toBe("needle");
    expect(session?.filters.findUseRegex).toBe(true);
    expect(session?.tabs).toHaveLength(1);
  });

  it("keeps backward compatibility for missing or malformed filter state", () => {
    const sessionWithMissingFilters = validateSession(createSessionInput());
    const sessionWithNullFilters = validateSession({
      ...createSessionInput(),
      filters: null,
    });
    const sessionWithMalformedFilters = validateSession({
      ...createSessionInput(),
      filters: {
        clauses: { bad: true },
        findQuery: 123,
        findCaseSensitive: "yes",
        findUseRegex: "no",
        highlightText: ["oops"],
      },
    });

    expect(sessionWithMissingFilters?.filters).toEqual({
      clauses: [],
      findQuery: "",
      findCaseSensitive: false,
      findUseRegex: false,
      highlightText: "",
    });
    expect(sessionWithNullFilters?.filters).toEqual({
      clauses: [],
      findQuery: "",
      findCaseSensitive: false,
      findUseRegex: false,
      highlightText: "",
    });
    expect(sessionWithMalformedFilters?.filters).toEqual({
      clauses: [],
      findQuery: "",
      findCaseSensitive: false,
      findUseRegex: false,
      highlightText: "",
    });
  });
});
