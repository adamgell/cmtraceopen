import { describe, expect, it } from "vitest";
import {
  getMdmState,
  getTopIssueLine,
  getVerdictHeadline,
  getVerdictTone,
  sortDiagnostics,
} from "./dsregcmd-verdict";
import type {
  DsregcmdAnalysisResult,
  DsregcmdDiagnosticInsight,
  DsregcmdEnrollmentEntry,
  DsregcmdJoinType,
  DsregcmdSeverity,
} from "./types";

const JOIN_TYPES: DsregcmdJoinType[] = [
  "EntraIdJoined",
  "HybridEntraIdJoined",
  "NotJoined",
  "Unknown",
];

interface FixtureOptions {
  joinType?: DsregcmdJoinType;
  mdmUrl?: string | null;
  mdmComplianceUrl?: string | null;
  diagnostics?: Array<{ id: string; severity: DsregcmdSeverity; title?: string }>;
  enrollments?: Array<Partial<DsregcmdEnrollmentEntry>> | null;
  taskGuids?: string[] | null;
}

function makeResult(options: FixtureOptions = {}): DsregcmdAnalysisResult {
  const {
    joinType = "EntraIdJoined",
    mdmUrl = null,
    mdmComplianceUrl = null,
    diagnostics = [],
    enrollments = null,
    taskGuids = null,
  } = options;

  return {
    facts: { managementDetails: { mdmUrl, mdmComplianceUrl } },
    derived: { joinType },
    diagnostics: diagnostics.map(
      ({ id, severity, title }) =>
        ({ id, severity, title: title ?? `Title of ${id}` }) as DsregcmdDiagnosticInsight,
    ),
    enrollmentEvidence: enrollments
      ? {
          enrollmentCount: enrollments.length,
          enrollments: enrollments.map((entry) => ({
            guid: null,
            upn: null,
            providerId: null,
            enrollmentState: null,
            ...entry,
          })),
        }
      : null,
    scheduledTaskEvidence: taskGuids ? { enterpriseMgmtGuids: taskGuids } : null,
  } as unknown as DsregcmdAnalysisResult;
}

const GUID = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
const URL_A = "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc";
const URL_B = "https://portal.manage.microsoft.com/TermsofUse.aspx";

describe("getVerdictTone", () => {
  it("is error when any diagnostic is an Error, even beside warnings", () => {
    const result = makeResult({
      diagnostics: [
        { id: "a", severity: "Warning" },
        { id: "b", severity: "Error" },
      ],
    });
    expect(getVerdictTone(result)).toBe("error");
  });

  it("is warning when the worst diagnostic is a Warning", () => {
    const result = makeResult({
      diagnostics: [
        { id: "a", severity: "Info" },
        { id: "b", severity: "Warning" },
      ],
    });
    expect(getVerdictTone(result)).toBe("warning");
  });

  it.each(["EntraIdJoined", "HybridEntraIdJoined"] as const)(
    "is healthy for %s with no Error or Warning",
    (joinType) => {
      const result = makeResult({
        joinType,
        diagnostics: [{ id: "i", severity: "Info" }],
      });
      expect(getVerdictTone(result)).toBe("healthy");
    },
  );

  it.each(["NotJoined", "Unknown"] as const)(
    "is neutral for %s with no Error or Warning (never healthy)",
    (joinType) => {
      expect(getVerdictTone(makeResult({ joinType }))).toBe("neutral");
    },
  );

  it.each(JOIN_TYPES)("lets an Error override the join type %s", (joinType) => {
    const result = makeResult({
      joinType,
      diagnostics: [{ id: "e", severity: "Error" }],
    });
    expect(getVerdictTone(result)).toBe("error");
  });

  it.each(JOIN_TYPES)("lets a Warning override the join type %s", (joinType) => {
    const result = makeResult({
      joinType,
      diagnostics: [{ id: "w", severity: "Warning" }],
    });
    expect(getVerdictTone(result)).toBe("warning");
  });

  it("does not treat unknown MDM state as a reason for healthy or unhealthy", () => {
    expect(getVerdictTone(makeResult({ joinType: "EntraIdJoined" }))).toBe("healthy");
  });
});

describe("getMdmState", () => {
  it("reports Enrolled (registry) when mdm-confirmed-via-registry is present", () => {
    const result = makeResult({
      diagnostics: [{ id: "mdm-confirmed-via-registry", severity: "Info" }],
    });
    expect(getMdmState(result)).toEqual({
      kind: "enrolled-registry",
      label: "Enrolled (registry)",
      tone: "pass",
    });
  });

  it("reports Enrolled (registry) from the GUID cross-reference without the diagnostic", () => {
    const result = makeResult({
      enrollments: [{ guid: GUID, enrollmentState: 1 }],
      taskGuids: [GUID],
    });
    expect(getMdmState(result).kind).toBe("enrolled-registry");
  });

  it("matches GUIDs case-insensitively", () => {
    const result = makeResult({
      enrollments: [{ guid: GUID.toLowerCase(), enrollmentState: 1 }],
      taskGuids: [GUID],
    });
    expect(getMdmState(result).kind).toBe("enrolled-registry");
  });

  it("matches when any one of several enrollments qualifies", () => {
    const result = makeResult({
      enrollments: [
        { guid: "{11111111-1111-1111-1111-111111111111}", enrollmentState: 1 },
        { guid: GUID, enrollmentState: 1 },
      ],
      taskGuids: ["{22222222-2222-2222-2222-222222222222}", GUID],
    });
    expect(getMdmState(result).kind).toBe("enrolled-registry");
  });

  it.each([
    ["enrollment state is not 1", [{ guid: GUID, enrollmentState: 2 }], [GUID]],
    ["enrollment state is null", [{ guid: GUID, enrollmentState: null }], [GUID]],
    ["enrollment guid is null", [{ guid: null, enrollmentState: 1 }], [GUID]],
    ["guid is not among the task guids", [{ guid: GUID, enrollmentState: 1 }], ["{99999999-8888-7777-6666-555555555555}"]],
    ["there are no task guids", [{ guid: GUID, enrollmentState: 1 }], []],
  ])("does not cross-reference when %s", (_name, enrollments, taskGuids) => {
    const result = makeResult({ enrollments, taskGuids });
    expect(getMdmState(result).kind).toBe("no-urls");
  });

  it("does not cross-reference without scheduled task evidence", () => {
    const result = makeResult({
      enrollments: [{ guid: GUID, enrollmentState: 1 }],
      taskGuids: null,
    });
    expect(getMdmState(result).kind).toBe("no-urls");
  });

  it("does not cross-reference without enrollment evidence", () => {
    expect(getMdmState(makeResult({ taskGuids: [GUID] })).kind).toBe("no-urls");
  });

  it("reports No enrollment (registry) when enrollment-missing-on-joined is present", () => {
    const result = makeResult({
      diagnostics: [{ id: "enrollment-missing-on-joined", severity: "Warning" }],
    });
    expect(getMdmState(result)).toEqual({
      kind: "no-enrollment-registry",
      label: "No enrollment (registry)",
      tone: "warn",
    });
  });

  it("reports URLs present (neutral) when both URLs are reported", () => {
    const result = makeResult({ mdmUrl: URL_A, mdmComplianceUrl: URL_B });
    expect(getMdmState(result)).toEqual({
      kind: "urls-present",
      label: "URLs present",
      tone: "neutral",
    });
  });

  it.each([
    ["only mdmUrl", { mdmUrl: URL_A, mdmComplianceUrl: null }],
    ["only mdmComplianceUrl", { mdmUrl: null, mdmComplianceUrl: URL_B }],
  ])("reports URLs partial when %s is reported", (_name, urls) => {
    expect(getMdmState(makeResult(urls))).toEqual({
      kind: "urls-partial",
      label: "URLs partial",
      tone: "neutral",
    });
  });

  it("reports No URLs (neutral) when neither URL is reported", () => {
    expect(getMdmState(makeResult())).toEqual({
      kind: "no-urls",
      label: "No URLs",
      tone: "neutral",
    });
  });

  describe("first match wins", () => {
    it("Enrolled beats No enrollment when both diagnostics are present", () => {
      const result = makeResult({
        diagnostics: [
          { id: "enrollment-missing-on-joined", severity: "Warning" },
          { id: "mdm-confirmed-via-registry", severity: "Info" },
        ],
      });
      expect(getMdmState(result).kind).toBe("enrolled-registry");
    });

    it("Enrolled (cross-reference) beats No enrollment", () => {
      const result = makeResult({
        diagnostics: [{ id: "enrollment-missing-on-joined", severity: "Warning" }],
        enrollments: [{ guid: GUID, enrollmentState: 1 }],
        taskGuids: [GUID],
      });
      expect(getMdmState(result).kind).toBe("enrolled-registry");
    });

    it("Enrolled beats URLs present", () => {
      const result = makeResult({
        mdmUrl: URL_A,
        mdmComplianceUrl: URL_B,
        diagnostics: [{ id: "mdm-confirmed-via-registry", severity: "Info" }],
      });
      expect(getMdmState(result).kind).toBe("enrolled-registry");
    });

    it("No enrollment beats URLs present", () => {
      const result = makeResult({
        mdmUrl: URL_A,
        mdmComplianceUrl: URL_B,
        diagnostics: [{ id: "enrollment-missing-on-joined", severity: "Warning" }],
      });
      expect(getMdmState(result).kind).toBe("no-enrollment-registry");
    });

    it("No enrollment beats URLs partial", () => {
      const result = makeResult({
        mdmUrl: URL_A,
        diagnostics: [{ id: "enrollment-missing-on-joined", severity: "Warning" }],
      });
      expect(getMdmState(result).kind).toBe("no-enrollment-registry");
    });
  });
});

describe("getVerdictHeadline", () => {
  const JOIN_CLAUSES: Record<DsregcmdJoinType, string> = {
    EntraIdJoined: "Entra joined",
    HybridEntraIdJoined: "Hybrid Entra joined",
    NotJoined: "Not joined to Entra ID",
    Unknown: "Join state not reported",
  };

  const MDM_FIXTURES: Array<[string, FixtureOptions, string]> = [
    [
      "Enrolled (registry)",
      { diagnostics: [{ id: "mdm-confirmed-via-registry", severity: "Info" }] },
      "MDM enrollment confirmed in registry",
    ],
    [
      "No enrollment (registry)",
      { diagnostics: [{ id: "enrollment-missing-on-joined", severity: "Warning" }] },
      "No MDM enrollment in registry",
    ],
    ["URLs present", { mdmUrl: URL_A, mdmComplianceUrl: URL_B }, "MDM URLs present"],
    ["URLs partial", { mdmUrl: URL_A }, "MDM URLs partially reported"],
    ["No URLs", {}, "No MDM URLs reported"],
  ];

  describe.each(["EntraIdJoined", "HybridEntraIdJoined"] as const)("%s", (joinType) => {
    it.each(MDM_FIXTURES)("joins the clause with MDM state %s", (_name, options, clause) => {
      const result = makeResult({ ...options, joinType });
      expect(getVerdictHeadline(result)).toBe(`${JOIN_CLAUSES[joinType]} · ${clause}`);
    });
  });

  describe.each(["NotJoined", "Unknown"] as const)("%s", (joinType) => {
    it.each(MDM_FIXTURES)("omits the management clause with MDM state %s", (_name, options) => {
      const result = makeResult({ ...options, joinType });
      expect(getVerdictHeadline(result)).toBe(JOIN_CLAUSES[joinType]);
    });
  });

  it("matches the spec's DD1 example for empty MDM URLs and no registry evidence", () => {
    expect(getVerdictHeadline(makeResult())).toBe(
      "Entra joined · No MDM URLs reported",
    );
  });

  it("holds the headline and tone invariants across the full join x MDM x severity matrix", () => {
    const severities: Array<Array<{ id: string; severity: DsregcmdSeverity }>> = [
      [],
      [{ id: "i", severity: "Info" }],
      [{ id: "w", severity: "Warning" }],
      [{ id: "e", severity: "Error" }],
    ];
    // Independent of the module: spec rule for the tone.
    const expectedTone = (result: DsregcmdAnalysisResult) => {
      if (result.diagnostics.some((d) => d.severity === "Error")) return "error";
      if (result.diagnostics.some((d) => d.severity === "Warning")) return "warning";
      return result.derived.joinType === "EntraIdJoined" ||
        result.derived.joinType === "HybridEntraIdJoined"
        ? "healthy"
        : "neutral";
    };
    let checked = 0;
    for (const joinType of JOIN_TYPES) {
      for (const [, mdm, clause] of MDM_FIXTURES) {
        for (const extra of severities) {
          const result = makeResult({
            ...mdm,
            joinType,
            diagnostics: [...(mdm.diagnostics ?? []), ...extra],
          });
          const headline = getVerdictHeadline(result);
          const joined = joinType === "EntraIdJoined" || joinType === "HybridEntraIdJoined";
          expect(headline).toBe(
            joined ? `${JOIN_CLAUSES[joinType]} \u00b7 ${clause}` : JOIN_CLAUSES[joinType],
          );
          expect(headline).not.toMatch(/manag/i);
          expect(headline.toLowerCase()).not.toContain("not managed");
          expect(headline.toLowerCase()).not.toContain("managed by intune");
          expect(getVerdictTone(result)).toBe(expectedTone(result));
          checked += 1;
        }
      }
    }
    expect(checked).toBe(80);
  });

  it("does not put the top issue into the headline", () => {
    const result = makeResult({
      diagnostics: [{ id: "e", severity: "Error", title: "Device registration failed" }],
    });
    expect(getVerdictHeadline(result)).not.toContain("Device registration failed");
  });
});

describe("getTopIssueLine", () => {
  it("is null when there is no Error diagnostic", () => {
    const result = makeResult({
      diagnostics: [
        { id: "w", severity: "Warning" },
        { id: "i", severity: "Info" },
      ],
    });
    expect(getTopIssueLine(result)).toBeNull();
  });

  it("is null for no diagnostics", () => {
    expect(getTopIssueLine(makeResult())).toBeNull();
  });

  it("names the first Error diagnostic in engine order", () => {
    const result = makeResult({
      diagnostics: [
        { id: "w", severity: "Warning", title: "A warning" },
        { id: "e1", severity: "Error", title: "First error" },
        { id: "e2", severity: "Error", title: "Second error" },
      ],
    });
    expect(getTopIssueLine(result)).toBe("Top issue: First error");
  });
});

describe("sortDiagnostics", () => {
  const diagnostic = (id: string, severity: DsregcmdSeverity) =>
    ({ id, severity }) as DsregcmdDiagnosticInsight;

  it("orders Error, then Warning, then Info, stable within a severity", () => {
    const source = [
      diagnostic("info-a", "Info"),
      diagnostic("warning-a", "Warning"),
      diagnostic("error-a", "Error"),
      diagnostic("warning-b", "Warning"),
      diagnostic("error-b", "Error"),
      diagnostic("info-b", "Info"),
    ];
    expect(sortDiagnostics(source).map((item) => item.id)).toEqual([
      "error-a",
      "error-b",
      "warning-a",
      "warning-b",
      "info-a",
      "info-b",
    ]);
  });

  it("keeps every diagnostic (no limit) and does not mutate its input", () => {
    const source = Array.from({ length: 20 }, (_, index) =>
      diagnostic(`d${index}`, index % 2 === 0 ? "Info" : "Error"),
    );
    const snapshot = source.map((item) => item.id);
    expect(sortDiagnostics(source)).toHaveLength(20);
    expect(source.map((item) => item.id)).toEqual(snapshot);
  });

  it("returns an empty list for no diagnostics", () => {
    expect(sortDiagnostics([])).toEqual([]);
  });
});
