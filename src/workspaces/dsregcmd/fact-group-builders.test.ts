import { describe, expect, it } from "vitest";
import {
  buildEndpointConnectivityGroup,
  buildEnrollmentStatusGroup,
  buildEnterpriseMgmtTasksGroup,
  buildProxyConfigGroup,
} from "./fact-group-builders";
import {
  buildAnalysisResult,
  buildEnrollmentEntry,
  buildFacts,
} from "./dsregcmd-test-builders";
import type { DsregcmdAnalysisResult } from "./types";

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
