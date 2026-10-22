import { describe, expect, it } from "vitest";
import {
  getMdmState,
  getTopIssueLine,
  getVerdictHeadline,
  getVerdictTone,
  sortDiagnostics,
} from "./dsregcmd-verdict";
import {
  getMdmVisibilityLabel,
  toneForMdmVisibility,
} from "./dsregcmd-formatters";
import {
  buildAnalysisResult,
  buildDerived,
  buildDiagnostic,
  buildEnrollmentEntry,
  buildFacts,
} from "./dsregcmd-test-builders";
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
  /** Registry-confirmed enrollment; null (the default) is "unknown". */
  mdmEnrolled?: boolean | null;
  diagnostics?: Array<{ id: string; severity: DsregcmdSeverity; title?: string }>;
  enrollments?: Array<Partial<DsregcmdEnrollmentEntry>> | null;
  taskGuids?: string[] | null;
}

function makeResult(options: FixtureOptions = {}): DsregcmdAnalysisResult {
  const {
    joinType = "EntraIdJoined",
    mdmUrl = null,
    mdmComplianceUrl = null,
    mdmEnrolled = null,
    diagnostics = [],
    enrollments = null,
    taskGuids = null,
  } = options;

  return buildAnalysisResult({
    facts: buildFacts({ mdmUrl, mdmComplianceUrl }),
    derived: buildDerived({
      joinType,
      mdmEnrolled,
      mdmUrlsPresent: mdmUrl !== null || mdmComplianceUrl !== null ? true : null,
    }),
    diagnostics: diagnostics.map(({ id, severity, title }) =>
      buildDiagnostic({ id, severity, title: title ?? `Title of ${id}` }),
    ),
    enrollmentEvidence: enrollments
      ? {
          enrollmentCount: enrollments.length,
          enrollments: enrollments.map((entry) => buildEnrollmentEntry(entry)),
        }
      : null,
    scheduledTaskEvidence: taskGuids ? { enterpriseMgmtGuids: taskGuids } : null,
  });
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

  it("reports Enrolled (registry) from registry-confirmed mdmEnrolled without the diagnostic", () => {
    expect(getMdmState(makeResult({ mdmEnrolled: true })).kind).toBe("enrolled-registry");
  });

  it.each([
    ["both MDM URLs", URL_A, URL_B],
    ["only the MDM URL", URL_A, null],
    ["only the compliance URL", null, URL_B],
  ])(
    "still reports Enrolled (registry) when mdmEnrolled is true with %s present",
    (_name, mdmUrl, mdmComplianceUrl) => {
      const result = makeResult({ mdmUrl, mdmComplianceUrl, mdmEnrolled: true });
      expect(getMdmState(result)).toEqual({
        kind: "enrolled-registry",
        label: "Enrolled (registry)",
        tone: "pass",
      });
    },
  );

  // The parser owns the cross-reference (apply_enrollment_cross_reference), so
  // raw evidence beside an unknown mdmEnrolled is not re-derived here.
  it("does not re-derive enrollment from raw evidence when mdmEnrolled is null", () => {
    const result = makeResult({
      enrollments: [{ guid: GUID, enrollmentState: 1 }],
      taskGuids: [GUID],
    });
    expect(getMdmState(result).kind).toBe("no-urls");
  });

  it("does not report Enrolled (registry) when mdmEnrolled is false", () => {
    expect(getMdmState(makeResult({ mdmEnrolled: false })).kind).toBe("no-urls");
  });

  it("reports URLs present, never No enrollment, when URLs are shown and the registry is unknown (#883)", () => {
    const result = makeResult({ mdmUrl: URL_A, mdmComplianceUrl: URL_B, mdmEnrolled: null });
    expect(getMdmState(result).kind).toBe("urls-present");
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

    it("Enrolled (mdmEnrolled) beats No enrollment", () => {
      const result = makeResult({
        diagnostics: [{ id: "enrollment-missing-on-joined", severity: "Warning" }],
        mdmEnrolled: true,
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

/// Case (a) of the reducer-contract ruling on #924: an empty enrollments
/// registry beside an observed EnterpriseMgmt task GUID contradicts itself, so
/// the parser leaves `mdmEnrolled` null and raises no warning. The chip must
/// not turn that into a negative.
describe("MDM state for an empty registry beside a task GUID (#924 case a)", () => {
  const caseA = (urls: { mdmUrl?: string; mdmComplianceUrl?: string }) =>
    makeResult({
      ...urls,
      mdmEnrolled: null,
      enrollments: [],
      taskGuids: [GUID],
    });

  it("reports URLs present (neutral), never No enrollment (registry)", () => {
    const result = caseA({ mdmUrl: URL_A, mdmComplianceUrl: URL_B });
    expect(result.enrollmentEvidence?.enrollmentCount).toBe(0);
    expect(getMdmState(result)).toEqual({
      kind: "urls-present",
      label: "URLs present",
      tone: "neutral",
    });
    expect(getVerdictHeadline(result)).toBe("Entra joined · MDM URLs present");
    expect(toneForMdmVisibility(result)).toBe("good");
  });

  it("reports No URLs (neutral) without URLs, never No enrollment (registry)", () => {
    const result = caseA({});
    expect(getMdmState(result)).toEqual({
      kind: "no-urls",
      label: "No URLs",
      tone: "neutral",
    });
    expect(getMdmVisibilityLabel(result.derived)).toBe("Unknown");
    expect(toneForMdmVisibility(result)).toBe("neutral");
  });
});

/// The six MDM states (URLs shown or not x enrolled true, unknown or false) on
/// a joined and a not-joined device, built as the parser produces them (pinned
/// on the Rust side by `mdm_enrollment_rule_six_states_joined_and_not_joined`).
/// The visibility label warns exactly when the chip does.
describe("MDM surfaces for the six MDM states, joined and not joined", () => {
  type Enrolled = boolean | null;
  interface Row {
    joined: boolean;
    urls: boolean;
    enrolled: Enrolled;
    label: string;
    labelTone: string;
    chip: string;
    chipTone: string;
    headline: string;
  }

  const ENTRA = "Entra joined";
  const NOT_JOINED = "Not joined to Entra ID";
  const ROWS: Row[] = [
    { joined: true, urls: true, enrolled: true, label: "Present", labelTone: "good", chip: "Enrolled (registry)", chipTone: "pass", headline: `${ENTRA} · MDM enrollment confirmed in registry` },
    { joined: true, urls: true, enrolled: null, label: "Present", labelTone: "good", chip: "URLs present", chipTone: "neutral", headline: `${ENTRA} · MDM URLs present` },
    { joined: true, urls: true, enrolled: false, label: "Not enrolled", labelTone: "warn", chip: "No enrollment (registry)", chipTone: "warn", headline: `${ENTRA} · No MDM enrollment in registry` },
    { joined: true, urls: false, enrolled: true, label: "Registry only", labelTone: "good", chip: "Enrolled (registry)", chipTone: "pass", headline: `${ENTRA} · MDM enrollment confirmed in registry` },
    { joined: true, urls: false, enrolled: null, label: "Unknown", labelTone: "neutral", chip: "No URLs", chipTone: "neutral", headline: `${ENTRA} · No MDM URLs reported` },
    { joined: true, urls: false, enrolled: false, label: "Not enrolled", labelTone: "warn", chip: "No enrollment (registry)", chipTone: "warn", headline: `${ENTRA} · No MDM enrollment in registry` },
    { joined: false, urls: true, enrolled: true, label: "Present", labelTone: "good", chip: "Enrolled (registry)", chipTone: "pass", headline: NOT_JOINED },
    { joined: false, urls: true, enrolled: null, label: "Present", labelTone: "good", chip: "URLs present", chipTone: "neutral", headline: NOT_JOINED },
    { joined: false, urls: true, enrolled: false, label: "Not enrolled", labelTone: "neutral", chip: "URLs present", chipTone: "neutral", headline: NOT_JOINED },
    { joined: false, urls: false, enrolled: true, label: "Registry only", labelTone: "good", chip: "Enrolled (registry)", chipTone: "pass", headline: NOT_JOINED },
    { joined: false, urls: false, enrolled: null, label: "Unknown", labelTone: "neutral", chip: "No URLs", chipTone: "neutral", headline: NOT_JOINED },
    { joined: false, urls: false, enrolled: false, label: "Not enrolled", labelTone: "neutral", chip: "No URLs", chipTone: "neutral", headline: NOT_JOINED },
  ];

  /** The analysis the parser returns for one row. */
  function parserResult({ joined, urls, enrolled }: Row): DsregcmdAnalysisResult {
    const diagnostics: DsregcmdDiagnosticInsight[] = [];
    if (enrolled === true && !urls) {
      diagnostics.push(buildDiagnostic({ id: "mdm-confirmed-via-registry", severity: "Info" }));
    }
    if (enrolled === false && joined) {
      diagnostics.push(buildDiagnostic({ id: "enrollment-missing-on-joined", severity: "Warning" }));
    }
    const facts = buildFacts(urls ? { mdmUrl: URL_A, mdmComplianceUrl: URL_B } : {});
    facts.joinState.azureAdJoined = joined;
    facts.joinState.domainJoined = false;
    return buildAnalysisResult({
      facts,
      derived: buildDerived({
        joinType: joined ? "EntraIdJoined" : "NotJoined",
        mdmEnrolled: enrolled,
        mdmUrlsPresent: urls ? true : null,
        missingMdm: urls ? false : null,
        complianceUrlPresent: urls ? true : null,
        missingComplianceUrl: urls ? false : null,
      }),
      diagnostics,
      enrollmentEvidence:
        enrolled === null
          ? null
          : {
              enrollmentCount: enrolled ? 1 : 0,
              enrollments: enrolled
                ? [buildEnrollmentEntry({ guid: GUID, enrollmentState: 1 })]
                : [],
            },
      scheduledTaskEvidence: enrolled ? { enterpriseMgmtGuids: [GUID] } : null,
    });
  }

  it.each(ROWS)(
    "joined=$joined urls=$urls enrolled=$enrolled: $label ($labelTone), chip $chip ($chipTone)",
    (row) => {
      const result = parserResult(row);
      const chip = getMdmState(result);
      expect(getMdmVisibilityLabel(result.derived)).toBe(row.label);
      expect(toneForMdmVisibility(result)).toBe(row.labelTone);
      expect(chip.label).toBe(row.chip);
      expect(chip.tone).toBe(row.chipTone);
      expect(getVerdictHeadline(result)).toBe(row.headline);
      expect(toneForMdmVisibility(result) === "warn").toBe(chip.tone === "warn");
    },
  );
});

describe("getVerdictHeadline", () => {
  it.each([
    ["both MDM URLs", URL_A, URL_B],
    ["only the MDM URL", URL_A, null],
    ["only the compliance URL", null, URL_B],
  ])(
    "uses the registry-confirmed clause when mdmEnrolled is true with %s present",
    (_name, mdmUrl, mdmComplianceUrl) => {
      const result = makeResult({ mdmUrl, mdmComplianceUrl, mdmEnrolled: true });
      expect(getVerdictHeadline(result)).toBe(
        `${JOIN_CLAUSES.EntraIdJoined} \u00b7 MDM enrollment confirmed in registry`,
      );
    },
  );

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
  const diagnostic = (id: string, severity: DsregcmdSeverity): DsregcmdDiagnosticInsight =>
    buildDiagnostic({ id, severity });

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
