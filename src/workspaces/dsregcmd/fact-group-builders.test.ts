import { describe, expect, it } from "vitest";
import {
  buildEndpointConnectivityGroup,
  buildProxyConfigGroup,
} from "./fact-group-builders";
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
