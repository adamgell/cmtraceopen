import { describe, expect, it } from "vitest";
import {
  buildEndpointConnectivityGroup,
  buildEnrollmentStatusGroup,
  buildEnterpriseMgmtTasksGroup,
  buildProxyConfigGroup,
} from "./fact-group-builders";
import { activeEnrollmentCount } from "./dsregcmd-formatters";
import {
  buildAnalysisResult,
  buildDerived,
  buildDiagnostic,
  buildEnrollmentEntry,
  buildFacts,
} from "./dsregcmd-test-builders";
import type { DsregcmdAnalysisResult, DsregcmdEnrollmentEntry } from "./types";

function resultWith(
  overrides: Partial<DsregcmdAnalysisResult>,
): DsregcmdAnalysisResult {
  return {
    facts: {} as unknown as DsregcmdAnalysisResult["facts"],
    derived: {} as unknown as DsregcmdAnalysisResult["derived"],
    diagnostics: [],
    policyEvidence: {} as unknown as DsregcmdAnalysisResult["policyEvidence"],
    osVersion: null,
    proxyEvidence: null,
    enrollmentEvidence: null,
    activeEvidence: null,
    scheduledTaskEvidence: null,
    eventLogAnalysis: null,
    ...overrides,
  };
}

describe("buildEndpointConnectivityGroup", () => {
  it("renders malformed endpoint strings without throwing", () => {
    const result = resultWith({
      activeEvidence: {
        connectivityTests: [
          {
            endpoint: "not a url",
            reachable: false,
            statusCode: null,
            latencyMs: null,
            errorMessage: "boom",
            timestamp: "2026-01-01T00:00:00.000Z",
          },
        ],
        scpQuery: null,
      },
    });

    const groups = buildEndpointConnectivityGroup(result);
    expect(groups).toHaveLength(1);
    expect(groups[0].rows[0].label).toBe("not a url");
  });
  it("falls back to the endpoint text when the parsed hostname is empty", () => {
    const result = resultWith({
      activeEvidence: {
        connectivityTests: [
          {
            endpoint: "file:///path",
            reachable: false,
            statusCode: null,
            latencyMs: null,
            errorMessage: "boom",
            timestamp: "2026-01-01T00:00:00.000Z",
          },
        ],
        scpQuery: null,
      },
    });

    const groups = buildEndpointConnectivityGroup(result);
    expect(groups[0].rows[0].label).toBe("file:///path");
  });
});

describe("buildProxyConfigGroup", () => {
  it("does not expose the binary WinHTTP row", () => {
    const result = resultWith({
      proxyEvidence: {
        proxyEnabled: true,
        proxyServer: "http://proxy.contoso.com:8080",
        proxyOverride: null,
        autoConfigUrl: null,
        wpadDetected: false,
      },
    });

    const groups = buildProxyConfigGroup(result);
    expect(groups).toHaveLength(1);
    expect(
      groups[0].rows.some((row) => row.label === "WinHTTP Proxy"),
    ).toBe(false);
  });
});

/// GUID identity ignores braces and case, as the parser compares it (ruling on
/// #924): Windows writes the Enrollments subkey unbraced, while a task GUID can
/// arrive braced. GUIDs are synthetic.
describe("enrollment and task GUID cross-reference", () => {
  const unbracedRegistryGuid = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb";
  const bracedTaskGuid = "{AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB}";
  const result = buildAnalysisResult({
    facts: buildFacts(),
    enrollmentEvidence: {
      enrollmentCount: 1,
      enrollments: [
        buildEnrollmentEntry({
          guid: unbracedRegistryGuid,
          upn: "user@contoso.test",
          enrollmentState: 1,
        }),
      ],
    },
    scheduledTaskEvidence: { enterpriseMgmtGuids: [bracedTaskGuid] },
  });

  it("marks an unbraced registry enrollment as matched by a braced task GUID", () => {
    const [group] = buildEnrollmentStatusGroup(result);
    const row = group.rows.find((candidate) => candidate.label === "Enrollment 1");
    expect(row?.value).toContain("task-matched");
    expect(row?.tone).toBe("good");
  });

  it("finds the registry match for a braced task GUID", () => {
    const [group] = buildEnterpriseMgmtTasksGroup(result);
    const row = group.rows.find((candidate) => candidate.label === bracedTaskGuid);
    expect(row?.value).toContain("Registry match");
    expect(row?.value).toContain("user@contoso.test");
    expect(row?.tone).toBe("good");
  });

  it("does not match a different GUID", () => {
    const other = buildAnalysisResult({
      ...result,
      scheduledTaskEvidence: {
        enterpriseMgmtGuids: ["{99999999-8888-7777-6666-555555555555}"],
      },
    });
    const [enrollmentGroup] = buildEnrollmentStatusGroup(other);
    expect(
      enrollmentGroup.rows.find((row) => row.label === "Enrollment 1")?.value,
    ).not.toContain("task-matched");
    const [taskGroup] = buildEnterpriseMgmtTasksGroup(other);
    expect(taskGroup.rows[1]?.value).toBe("No matching enrollment registry entry");
  });
});

const KEY_ROW = "Enrollment registry keys";
const ACTIVE_ROW = "Active enrollments (EnrollmentState 1)";
const MDM_GUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
const MDM_GUID_VARIANT = "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}";
const GUID_B = "BBBBBBBB-2222-3333-4444-CCCCCCCCCCCC";
const GUID_C = "CCCCCCCC-3333-4444-5555-DDDDDDDDDDDD";
const GUID_D = "DDDDDDDD-4444-5555-6666-EEEEEEEEEEEE";

const keyed = (
  guid: string | null,
  enrollmentState: number | null,
  providerId: string | null = "MS DM Server",
): DsregcmdEnrollmentEntry => buildEnrollmentEntry({ guid, enrollmentState, providerId });

/// The fixture matrix shared with `multiple_enrollments_active_count_matrix`
/// in crates/cmtraceopen-parser/src/dsregcmd/rules.rs: each case's entries and
/// its active count.
const ACTIVE_COUNT_MATRIX: Array<[string, DsregcmdEnrollmentEntry[], number]> = [
  ["no keys", [], 0],
  ["one active", [keyed(MDM_GUID, 1)], 1],
  ["active, no values, state 6", [keyed(MDM_GUID, 1), keyed(GUID_B, null, null), keyed(GUID_C, 6)], 1],
  ["two active, different providers", [keyed(MDM_GUID, 1), keyed(GUID_B, 1, "Contoso MDM")], 2],
  ["two active, no providers", [keyed(MDM_GUID, 1, null), keyed(GUID_B, 1, null)], 2],
  ["none active", [keyed(MDM_GUID, 0), keyed(GUID_B, 2), keyed(GUID_C, 6), keyed(GUID_D, null)], 0],
  ["one GUID braced and unbraced, both active", [keyed(MDM_GUID, 1), keyed(MDM_GUID_VARIANT, 1)], 1],
  ["one GUID braced and unbraced, disagreeing", [keyed(MDM_GUID, 1), keyed(MDM_GUID_VARIANT, 6)], 0],
  ["no GUID", [keyed(null, 1)], 0],
  ["not GUID-shaped", [keyed("Context", 1)], 0],
  ["three active", [keyed(MDM_GUID, 1), keyed(GUID_B, 1), keyed(GUID_C, 1, null)], 3],
];

function enrollmentRows(result: DsregcmdAnalysisResult) {
  const [group] = buildEnrollmentStatusGroup(result);
  const row = (label: string) => group.rows.find((candidate) => candidate.label === label);
  return { group, keyRow: row(KEY_ROW), activeRow: row(ACTIVE_ROW) };
}

/// Active enrollments (reducer-contract ruling 2 on #924): only distinct GUIDs
/// whose reconciled EnrollmentState is exactly 1 count.
describe("activeEnrollmentCount", () => {
  it.each(ACTIVE_COUNT_MATRIX)("%s", (_name, enrollments, expected) => {
    expect(activeEnrollmentCount({ enrollments })).toBe(expected);
  });

  it.each(ACTIVE_COUNT_MATRIX)(
    "%s: the active row shows the count and warns only above 1",
    (_name, enrollments, expected) => {
      const { activeRow } = enrollmentRows(
        buildAnalysisResult({
          facts: buildFacts(),
          enrollmentEvidence: { enrollmentCount: enrollments.length, enrollments },
        }),
      );
      expect(activeRow?.value).toBe(String(expected));
      expect(activeRow?.tone).toBe(expected > 1 ? "warn" : "neutral");
    },
  );
});

/// The registry-key row reads the parser's `enrollment-missing-on-joined`
/// diagnostic and never re-derives it: it warns exactly when the diagnostic is
/// raised.
describe("Enrollment Status rows", () => {
  const missingOnJoined = buildDiagnostic({
    id: "enrollment-missing-on-joined",
    severity: "Warning",
  });

  /** Analyses the parser produces, with registry evidence read. */
  function parserState(
    joined: boolean,
    state: "confirmed" | "unconfirmed" | "negative" | "case-a",
  ): DsregcmdAnalysisResult {
    const facts = buildFacts();
    facts.joinState.azureAdJoined = joined;
    facts.joinState.domainJoined = false;
    const enrollments =
      state === "confirmed"
        ? [keyed(MDM_GUID, 1)]
        : state === "unconfirmed"
          ? [keyed(MDM_GUID, 6)]
          : [];
    const mdmEnrolled =
      state === "confirmed" ? true : state === "negative" ? false : null;
    return buildAnalysisResult({
      facts,
      derived: buildDerived({
        joinType: joined ? "EntraIdJoined" : "NotJoined",
        mdmEnrolled,
      }),
      diagnostics: state === "negative" && joined ? [missingOnJoined] : [],
      enrollmentEvidence: { enrollmentCount: enrollments.length, enrollments },
      scheduledTaskEvidence:
        state === "confirmed" || state === "case-a"
          ? { enterpriseMgmtGuids: [MDM_GUID_VARIANT] }
          : null,
    });
  }

  const STATES = ["confirmed", "unconfirmed", "negative", "case-a"] as const;
  const CASES = [true, false].flatMap((joined) =>
    STATES.map((state) => ({ joined, state })),
  );

  it.each(CASES)(
    "joined=$joined $state: the key row warns exactly with the diagnostic",
    ({ joined, state }) => {
      const result = parserState(joined, state);
      const { keyRow } = enrollmentRows(result);
      const diagnosed = result.diagnostics.some(
        (item) => item.id === "enrollment-missing-on-joined",
      );
      expect(keyRow?.tone === "warn").toBe(diagnosed);
      expect(keyRow?.tone).toBe(
        joined && state === "negative" ? "warn" : "neutral",
      );
    },
  );

  /// Fixtures where the diagnostic and the raw fields disagree, which the
  /// parser never produces: the row follows the diagnostic, so rebuilding the
  /// predicate from `mdmEnrolled` and the join state fails here.
  it("follows the diagnostic, not the raw fields, when they disagree", () => {
    const rawNegativeWithoutDiagnostic = parserState(true, "negative");
    rawNegativeWithoutDiagnostic.diagnostics = [];
    expect(enrollmentRows(rawNegativeWithoutDiagnostic).keyRow?.tone).toBe("neutral");

    const diagnosticWithoutRawNegative = parserState(false, "case-a");
    diagnosticWithoutRawNegative.diagnostics = [missingOnJoined];
    expect(enrollmentRows(diagnosticWithoutRawNegative).keyRow?.tone).toBe("warn");
  });

  it("keeps the key row neutral for an empty registry beside a task GUID (case a)", () => {
    const { keyRow } = enrollmentRows(parserState(true, "case-a"));
    expect(keyRow?.value).toBe("0");
    expect(keyRow?.tone).toBe("neutral");
  });

  it("never marks a count row good", () => {
    const fixtures = [
      ...CASES.map(({ joined, state }) => parserState(joined, state)),
      ...ACTIVE_COUNT_MATRIX.map(([, enrollments]) =>
        buildAnalysisResult({
          facts: buildFacts(),
          enrollmentEvidence: { enrollmentCount: enrollments.length, enrollments },
        }),
      ),
    ];
    for (const result of fixtures) {
      const { keyRow, activeRow } = enrollmentRows(result);
      expect(keyRow?.tone).not.toBe("good");
      expect(activeRow?.tone).not.toBe("good");
    }
  });

  it("shows one registry key and no active enrollment for a key without values", () => {
    const { group, keyRow, activeRow } = enrollmentRows(
      buildAnalysisResult({
        facts: buildFacts(),
        enrollmentEvidence: {
          enrollmentCount: 1,
          enrollments: [buildEnrollmentEntry({ guid: MDM_GUID })],
        },
      }),
    );
    expect(keyRow?.value).toBe("1");
    expect(activeRow?.value).toBe("0");
    expect(group.caption).not.toMatch(/MDM enrollment entries/);
  });

  it("renders no rows when the export was not read", () => {
    expect(buildEnrollmentStatusGroup(buildAnalysisResult({ facts: buildFacts() }))).toEqual([]);
  });
});
