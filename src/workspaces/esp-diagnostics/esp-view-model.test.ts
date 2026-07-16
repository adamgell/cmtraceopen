import { describe, expect, it } from "vitest";
import {
  ESP_EVIDENCE_DISCLOSURE_POLICY,
  buildEspEvidenceViewModel,
} from "./esp-view-model";
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspRawEvidenceRecord,
} from "./types";

function timestamp(rawText: string) {
  return {
    rawText,
    originalOffset: "+00:00",
    normalizedUtc: rawText,
    kind: "utc" as const,
  };
}

function graphOverlay(): EspGraphOverlay {
  const skipped = {
    status: "skipped" as const,
    requiredScope: null,
    apiVersion: "v1.0" as const,
    data: null,
    error: null,
  };
  return {
    requestId: "graph-evidence",
    requestedAtUtc: "2026-07-15T20:08:00Z",
    deviceMatch: skipped,
    autopilotIdentity: skipped,
    deploymentProfile: skipped,
    intendedDeploymentProfile: skipped,
    profileAssignments: skipped,
    autopilotEvents: skipped,
    enrollmentConfiguration: skipped,
    apps: {
      status: "available",
      requiredScope: "DeviceManagementApps.Read.All",
      apiVersion: "v1.0",
      data: [
        {
          appId: "app-raw-guid",
          displayName: "Graph VPN name",
          trackedOnEnrollmentStatus: true,
          status: null,
          assignments: [],
          evidence: [],
        },
      ],
      error: null,
    },
    policies: {
      status: "available",
      requiredScope: "DeviceManagementConfiguration.Read.All",
      apiVersion: "v1.0",
      data: [
        {
          policyId: "policy-raw-guid",
          displayName: "Graph compliance name",
          kind: "compliance",
          status: null,
          assignments: [],
          evidence: [],
        },
      ],
      error: null,
    },
    scripts: {
      status: "available",
      requiredScope: "DeviceManagementScripts.Read.All",
      apiVersion: "beta",
      data: [
        {
          scriptId: "script-raw-guid",
          displayName: "Graph bootstrap name",
          kind: "platformScript",
          status: null,
          assignments: [],
          evidence: [],
        },
      ],
      error: null,
    },
  };
}

function rawEvidence(): EspRawEvidenceRecord {
  return {
    recordId: "raw-record-17",
    provenance: {
      sourceKind: "registry",
      sourceArtifactId: "esp-registry",
      filePath: null,
      lineNumber: null,
      recordNumber: 17,
      registry: {
        hive: "HKLM",
        key: "SOFTWARE\\Microsoft\\Enrollments\\Status",
        valueName: "EntDMID",
      },
      event: null,
    },
    sourceTimestamp: timestamp("2026-07-15T20:07:00Z"),
    observedAtUtc: "2026-07-15T20:07:03Z",
    rawValue: { text: "raw-sensitive-value" },
    sensitivity: "sensitive",
    parseState: "parsed",
    accessState: "available",
    evidence: [
      { evidenceId: "evidence-raw-17", sourceArtifactId: "esp-registry" },
    ],
  };
}

function snapshot(
  overrides: Partial<EspDiagnosticsSnapshot> = {},
): EspDiagnosticsSnapshot {
  return {
    schemaVersion: 1,
    scenario: "autopilotV1",
    phase: "deviceSetup",
    generatedAtUtc: "2026-07-15T20:08:05Z",
    elevation: {
      isElevated: false,
      restartSupported: true,
      restrictedSources: ["ESP registry"],
    },
    identity: {
      deviceName: "ESP-LAB-042",
      managedDeviceId: "managed-raw-guid",
      entraDeviceId: "entra-raw-guid",
      entdmId: { value: "entdm-sensitive", sensitivity: "sensitive" },
      tenantId: { value: "tenant-sensitive", sensitivity: "sensitive" },
      tenantDomain: { value: "contoso.example", sensitivity: "public" },
      userPrincipalName: {
        value: "operator@contoso.example",
        sensitivity: "restricted",
      },
      serialNumber: { value: "SERIAL-042", sensitivity: "sensitive" },
      evidence: [],
    },
    profile: {
      profileName: "Windows Autopilot Standard",
      deploymentProfileId: "profile-raw-guid",
      correlationId: "correlation-raw-guid",
      tenantDomain: { value: "contoso.example", sensitivity: "public" },
      tenantId: { value: "tenant-sensitive", sensitivity: "sensitive" },
      oobeConfig: {
        rawMask: 255,
        skipKeyboard: true,
        enablePatchDownload: true,
        skipWindowsUpgradeUx: false,
        aadTpmRequired: true,
        aadDeviceAuthentication: true,
        tpmAttestation: true,
        skipEula: true,
        skipOemRegistration: true,
        skipExpressSettings: true,
        disallowAdmin: true,
      },
      profileDownloadTime: timestamp("2026-07-15T19:58:00Z"),
      joinMode: "entra",
      odjApplied: false,
      skipDomainConnectivityCheck: false,
      devicePreparation: {
        agentDownloadTimeoutSeconds: 900,
        pageTimeoutSeconds: 3600,
        allowSkipOnFailure: false,
        allowDiagnostics: true,
        scriptIds: ["script-raw-guid"],
        evidence: [],
      },
      evidence: [],
    },
    enrollments: [
      {
        enrollmentId: "enrollment-raw-guid",
        providerId: "provider-raw-guid",
        tenantId: { value: "tenant-sensitive", sensitivity: "sensitive" },
        userPrincipalName: {
          value: "operator@contoso.example",
          sensitivity: "restricted",
        },
        entdmId: { value: "entdm-sensitive", sensitivity: "sensitive" },
        settings: {
          deviceEspEnabled: true,
          userEspEnabled: true,
          timeoutSeconds: 3600,
          blocking: true,
          allowReset: false,
          allowRetry: true,
          continueAnyway: false,
        },
        evidence: [],
      },
    ],
    sessions: [
      {
        sessionId: "session-device-raw-guid",
        kind: "classic",
        scope: "device",
        userSid: null,
        startedAt: timestamp("2026-07-15T20:00:00Z"),
        endedAt: null,
        phase: "deviceSetup",
        isLatest: true,
        workloadIds: [
          "app-workload",
          "script-workload",
          "policy-workload",
          "cert-workload",
        ],
        evidence: [],
      },
      {
        sessionId: "session-user-raw-guid",
        kind: "classic",
        scope: "user",
        userSid: { value: "S-1-5-21-restricted", sensitivity: "restricted" },
        startedAt: timestamp("2026-07-15T20:04:00Z"),
        endedAt: null,
        phase: "accountSetup",
        isLatest: true,
        workloadIds: [],
        evidence: [],
      },
    ],
    workloads: [
      {
        workloadId: "app-workload",
        sessionId: "session-device-raw-guid",
        kind: "win32App",
        scope: "device",
        rawIdentifier: "app-raw-guid",
        displayName: "Local VPN name",
        status: {
          raw: 3,
          normalized: "installing",
          display: "Installing",
          detail: null,
        },
        timestamps: {
          firstObserved: timestamp("2026-07-15T20:01:00Z"),
          started: timestamp("2026-07-15T20:02:00Z"),
          ended: null,
          lastUpdated: timestamp("2026-07-15T20:08:00Z"),
        },
        exitCode: null,
        enforcementErrorCode: null,
        blocking: true,
        evidence: [],
      },
      {
        workloadId: "script-workload",
        sessionId: "session-device-raw-guid",
        kind: "platformScript",
        scope: "device",
        rawIdentifier: "script-raw-guid",
        displayName: null,
        status: {
          raw: "success",
          normalized: "succeeded",
          display: "Succeeded",
          detail: null,
        },
        timestamps: {
          firstObserved: timestamp("2026-07-15T20:01:00Z"),
          started: timestamp("2026-07-15T20:02:00Z"),
          ended: timestamp("2026-07-15T20:03:00Z"),
          lastUpdated: timestamp("2026-07-15T20:03:00Z"),
        },
        exitCode: null,
        enforcementErrorCode: null,
        blocking: false,
        evidence: [],
      },
      {
        workloadId: "policy-workload",
        sessionId: "session-device-raw-guid",
        kind: "policy",
        scope: "device",
        rawIdentifier: "policy-raw-guid",
        displayName: null,
        status: {
          raw: 2,
          normalized: "processed",
          display: "Processed",
          detail: null,
        },
        timestamps: {
          firstObserved: timestamp("2026-07-15T20:01:00Z"),
          started: null,
          ended: null,
          lastUpdated: null,
        },
        exitCode: null,
        enforcementErrorCode: null,
        blocking: null,
        evidence: [],
      },
      {
        workloadId: "cert-workload",
        sessionId: "session-device-raw-guid",
        kind: "scepCertificate",
        scope: "device",
        rawIdentifier: "certificate-raw-guid",
        displayName: "Wi-Fi SCEP",
        status: {
          raw: 1,
          normalized: "pending",
          display: "Pending",
          detail: null,
        },
        timestamps: {
          firstObserved: timestamp("2026-07-15T20:01:00Z"),
          started: null,
          ended: null,
          lastUpdated: null,
        },
        exitCode: null,
        enforcementErrorCode: null,
        blocking: true,
        evidence: [],
      },
    ],
    installerCorrelations: [],
    nodeCache: [
      {
        index: 7,
        nodeUri: "./Device/Vendor/MSFT/DMClient/Provider/ProviderID",
        expectedValue: "provider-raw-guid",
        sensitivity: "public",
        evidence: [],
      },
    ],
    registrationEvents: [
      {
        eventId: 75,
        recordId: 912,
        status: {
          raw: "0x0",
          normalized: "succeeded",
          display: "Registration succeeded",
          detail: null,
        },
        message: "Device registration completed.",
        timestamp: timestamp("2026-07-15T19:59:00Z"),
        namedData: [{ name: "JoinMode", value: "entra" }],
        evidence: [],
      },
    ],
    deliveryOptimization: {
      downloadHttpBytes: 1000,
      downloadLanBytes: 250,
      downloadCacheHostBytes: 500,
      peerSharePercent: 14.2,
      connectedCacheSharePercent: 28.5,
      transfers: [],
      evidence: [],
    },
    hardware: {
      osVersion: "10.0.26100",
      osBuild: "26100.4652",
      manufacturer: "Microsoft Corporation",
      model: "Virtual Machine",
      serialNumber: { value: "SERIAL-042", sensitivity: "sensitive" },
      tpmVersion: "2.0",
      evidence: [],
    },
    activity: [],
    findings: [],
    coverage: [
      {
        artifactId: "esp-registry",
        family: "ESP registry and NodeCache",
        status: "available",
        detail: null,
        observedAtUtc: "2026-07-15T20:08:00Z",
        evidence: [],
      },
    ],
    rawEvidence: [rawEvidence()],
    graph: graphOverlay(),
    ...overrides,
  };
}

describe("ESP evidence view model", () => {
  it("always returns every approved evidence family in the approved order", () => {
    const viewModel = buildEspEvidenceViewModel(snapshot());

    expect(viewModel.sections.map((section) => section.id)).toEqual([
      "identity-profile",
      "oobe-flags",
      "esp-configuration",
      "enrollment-sessions",
      "apps",
      "scripts",
      "policies",
      "certificates",
      "join-registration",
      "delivery-optimization",
      "hardware",
      "node-cache",
      "source-coverage",
      "raw-provenance",
    ]);
    expect(viewModel.sections.every((section) => section.items.length > 0)).toBe(
      true,
    );
  });

  it("preserves raw IDs while treating Graph names as additive labels", () => {
    const sections = buildEspEvidenceViewModel(snapshot()).sections;
    const apps = sections.find((section) => section.id === "apps");
    const scripts = sections.find((section) => section.id === "scripts");
    const policies = sections.find((section) => section.id === "policies");

    expect(apps?.items[0]).toMatchObject({
      title: "Local VPN name",
      graphName: "Graph VPN name",
      rawId: "app-raw-guid",
    });
    expect(scripts?.items[0]).toMatchObject({
      graphName: "Graph bootstrap name",
      rawId: "script-raw-guid",
    });
    expect(policies?.items[0]).toMatchObject({
      graphName: "Graph compliance name",
      rawId: "policy-raw-guid",
    });

    const withoutGraph = buildEspEvidenceViewModel(
      snapshot({ graph: null }),
    ).sections.find((section) => section.id === "apps");
    expect(withoutGraph?.items[0]).toMatchObject({
      title: "Local VPN name",
      graphName: null,
      rawId: "app-raw-guid",
    });
  });

  it("masks sensitive values by default, reveals only sensitive values, and never reveals restricted values", () => {
    const masked = buildEspEvidenceViewModel(snapshot());
    const revealed = buildEspEvidenceViewModel(snapshot(), {
      revealSensitive: true,
    });
    const maskedValues = masked.sections.flatMap((section) =>
      section.items.flatMap((item) => item.fields.map((field) => field.value)),
    );
    const revealedValues = revealed.sections.flatMap((section) =>
      section.items.flatMap((item) => item.fields.map((field) => field.value)),
    );

    expect(ESP_EVIDENCE_DISCLOSURE_POLICY).toContain(
      "Sensitive values are masked by default",
    );
    expect(maskedValues).not.toContain("tenant-sensitive");
    expect(maskedValues).not.toContain("raw-sensitive-value");
    expect(maskedValues).not.toContain("operator@contoso.example");
    expect(revealedValues).toContain("tenant-sensitive");
    expect(revealedValues).toContain("raw-sensitive-value");
    expect(revealedValues).not.toContain("operator@contoso.example");
    expect(revealedValues).toContain("Restricted value · reveal unavailable");
  });

  it("explains source-aware absence for empty, missing, and permission-denied sections", () => {
    const empty = snapshot({
      profile: null,
      enrollments: [],
      sessions: [],
      workloads: [],
      nodeCache: [],
      registrationEvents: [],
      deliveryOptimization: null,
      hardware: null,
      rawEvidence: [],
      graph: null,
      coverage: [
        {
          artifactId: "platform-scripts",
          family: "Platform scripts",
          status: "permissionDenied",
          detail: "Administrator rights required",
          observedAtUtc: "2026-07-15T20:08:00Z",
          evidence: [],
        },
        {
          artifactId: "delivery-optimization",
          family: "Delivery Optimization event log",
          status: "missing",
          detail: "No event log export was attached",
          observedAtUtc: "2026-07-15T20:08:00Z",
          evidence: [],
        },
      ],
    });
    const sections = buildEspEvidenceViewModel(empty).sections;
    const byId = (id: string) =>
      sections.find((section) => section.id === id);

    expect(byId("scripts")).toMatchObject({
      sourceState: "permissionDenied",
      sourceNote: expect.stringContaining("Administrator rights required"),
      items: [],
    });
    expect(byId("delivery-optimization")).toMatchObject({
      sourceState: "missing",
      sourceNote: expect.stringContaining("No event log export was attached"),
      items: [],
    });
    expect(byId("certificates")).toMatchObject({
      sourceState: "notObserved",
      sourceNote: expect.stringContaining("No certificate records were observed"),
      items: [],
    });
    expect(sections).toHaveLength(14);
  });

  it("retains raw provenance, source state, sensitivity, parse state, and evidence IDs", () => {
    const raw = buildEspEvidenceViewModel(snapshot()).sections.find(
      (section) => section.id === "raw-provenance",
    );

    expect(raw?.items[0]).toMatchObject({
      id: "raw-record-17",
      title: "registry · esp-registry",
      rawId: "raw-record-17",
      evidence: [
        { evidenceId: "evidence-raw-17", sourceArtifactId: "esp-registry" },
      ],
    });
    expect(raw?.items[0].fields).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: "Access", value: "available" }),
        expect.objectContaining({ label: "Parse", value: "parsed" }),
        expect.objectContaining({ label: "Sensitivity", value: "sensitive" }),
        expect.objectContaining({
          label: "Registry",
          value: expect.stringContaining("HKLM"),
        }),
      ]),
    );
  });
});
