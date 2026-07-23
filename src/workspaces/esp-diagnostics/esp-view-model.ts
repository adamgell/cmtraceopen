import type {
  EspArtifactCoverage,
  EspArtifactStatus,
  EspClassifiedString,
  EspDiagnosticsSnapshot,
  EspEvidenceRef,
  EspObservationValue,
  EspSensitivity,
  EspTimestamp,
  EspTrackedKind,
  EspWorkload,
} from "./types";

export const ESP_EVIDENCE_DISCLOSURE_POLICY =
  "Sensitive values are masked by default. Reveal applies only to this view and never reveals restricted values. Copy remains unavailable for restricted values.";

export type EspEvidenceSourceState =
  EspArtifactStatus | "partial" | "notObserved";

export interface EspEvidenceFieldViewModel {
  label: string;
  value: string;
  sensitivity: EspSensitivity;
}

export interface EspEvidenceItemViewModel {
  id: string;
  title: string;
  graphName: string | null;
  rawId: string | null;
  fields: EspEvidenceFieldViewModel[];
  evidence: EspEvidenceRef[];
}

export interface EspEvidenceSectionViewModel {
  id: string;
  title: string;
  description: string;
  sourceState: EspEvidenceSourceState;
  sourceNote: string;
  items: EspEvidenceItemViewModel[];
}

export interface EspEvidenceViewModel {
  disclosurePolicy: string;
  sections: EspEvidenceSectionViewModel[];
}

interface BuildOptions {
  revealSensitive?: boolean;
}

interface SectionDefinition {
  id: string;
  title: string;
  description: string;
  emptyNoun: string;
  coverageTerms: string[];
  items: EspEvidenceItemViewModel[];
  sourceOverride?: {
    state: EspEvidenceSourceState;
    note: string;
  };
}

const MASKED_SENSITIVE_VALUE = "Sensitive value · masked";
const MASKED_RESTRICTED_VALUE = "Restricted value · reveal unavailable";

function displayBoolean(value: boolean | null): string {
  return value === null ? "Unknown" : value ? "Enabled" : "Disabled";
}

function displayNullable(value: string | number | null): string {
  return value === null || value === "" ? "Unknown" : String(value);
}

function displayTimestamp(value: EspTimestamp | null): string {
  return value?.normalizedUtc ?? value?.rawText ?? "Unknown";
}

function hasDevicePreparationEvidence(
  value: NonNullable<EspDiagnosticsSnapshot["profile"]>["devicePreparation"],
): boolean {
  return Boolean(
    value &&
    (value.agentDownloadTimeoutSeconds !== null ||
      value.pageTimeoutSeconds !== null ||
      value.allowSkipOnFailure !== null ||
      value.allowDiagnostics !== null ||
      value.scriptIds.length > 0 ||
      value.evidence.length > 0),
  );
}

function hasProfileEvidence(
  profile: NonNullable<EspDiagnosticsSnapshot["profile"]>,
): boolean {
  return (
    profile.profileName !== null ||
    profile.deploymentProfileId !== null ||
    profile.correlationId !== null ||
    profile.tenantDomain !== null ||
    profile.tenantId !== null ||
    profile.oobeConfig !== null ||
    profile.profileDownloadTime !== null ||
    profile.joinMode !== null ||
    profile.odjApplied !== null ||
    profile.skipDomainConnectivityCheck !== null ||
    hasDevicePreparationEvidence(profile.devicePreparation) ||
    profile.evidence.length > 0
  );
}

function displayClassified(
  value: EspClassifiedString | null,
  revealSensitive: boolean,
): string {
  if (!value) return "Unknown";
  if (value.sensitivity === "restricted") return MASKED_RESTRICTED_VALUE;
  if (value.sensitivity === "sensitive" && !revealSensitive) {
    return MASKED_SENSITIVE_VALUE;
  }
  return value.value;
}

export function displayEvidenceValue(
  value: string,
  sensitivity: EspSensitivity,
  revealSensitive: boolean,
): string {
  if (sensitivity === "restricted") return MASKED_RESTRICTED_VALUE;
  if (sensitivity === "sensitive" && !revealSensitive) {
    return MASKED_SENSITIVE_VALUE;
  }
  return value;
}

function displayObservationValue(value: EspObservationValue): string {
  if ("text" in value) return value.text;
  if ("integer" in value) return String(value.integer);
  if ("unsigned" in value) return String(value.unsigned);
  if ("boolean" in value) return String(value.boolean);
  return value.stringList.join(", ");
}

function field(
  label: string,
  value: string,
  sensitivity: EspSensitivity = "public",
): EspEvidenceFieldViewModel {
  return { label, value, sensitivity };
}

function item(
  id: string,
  title: string,
  fields: EspEvidenceFieldViewModel[],
  options: {
    graphName?: string | null;
    rawId?: string | null;
    evidence?: EspEvidenceRef[];
  } = {},
): EspEvidenceItemViewModel {
  return {
    id,
    title,
    graphName: options.graphName ?? null,
    rawId: options.rawId ?? null,
    fields,
    evidence: options.evidence ?? [],
  };
}

const WORKLOAD_GUID_RE =
  /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/;

/**
 * Match a Graph record id to a workload's raw identifier. The classic workload
 * identifier is a decorated form (e.g. `Win32App_<guid>_1`) while the Graph app id
 * is the bare GUID, so an exact === never matches. Compare case-insensitively and,
 * failing that, by the embedded GUID -- mirroring the backend's identifiers_match.
 */
function graphIdentifierMatches(recordId: string, rawIdentifier: string): boolean {
  if (recordId.toLowerCase() === rawIdentifier.toLowerCase()) return true;
  const recordGuid = WORKLOAD_GUID_RE.exec(recordId)?.[0].toLowerCase();
  const workloadGuid = WORKLOAD_GUID_RE.exec(rawIdentifier)?.[0].toLowerCase();
  return recordGuid !== undefined && recordGuid === workloadGuid;
}

function graphNameForWorkload(
  snapshot: EspDiagnosticsSnapshot,
  workload: EspWorkload,
): string | null {
  if (!snapshot.graph) return null;
  if (["msi", "office", "modernApp", "win32App"].includes(workload.kind)) {
    return (
      snapshot.graph.apps.data?.find((record) =>
        graphIdentifierMatches(record.appId, workload.rawIdentifier),
      )?.displayName ?? null
    );
  }
  if (workload.kind === "platformScript") {
    return (
      snapshot.graph.scripts.data?.find((record) =>
        graphIdentifierMatches(record.scriptId, workload.rawIdentifier),
      )?.displayName ?? null
    );
  }
  if (["policy", "scepCertificate"].includes(workload.kind)) {
    return (
      snapshot.graph.policies.data?.find((record) =>
        graphIdentifierMatches(record.policyId, workload.rawIdentifier),
      )?.displayName ?? null
    );
  }
  return null;
}

function workloadItem(
  snapshot: EspDiagnosticsSnapshot,
  workload: EspWorkload,
): EspEvidenceItemViewModel {
  return item(
    workload.workloadId,
    workload.displayName ?? `${workload.kind} record`,
    [
      field("Status", workload.status.display),
      field("Raw status", String(workload.status.raw)),
      ...(workload.status.detail
        ? [
            field("Status detail", workload.status.detail.display),
            field("Detail raw status", String(workload.status.detail.raw)),
          ]
        : []),
      field("Scope", workload.scope),
      field("Session", workload.sessionId),
      field("Blocking", displayBoolean(workload.blocking)),
      field(
        "First observed",
        displayTimestamp(workload.timestamps.firstObserved),
      ),
    ],
    {
      graphName: graphNameForWorkload(snapshot, workload),
      rawId: workload.rawIdentifier,
      evidence: workload.evidence,
    },
  );
}

function workloadsOfKinds(
  snapshot: EspDiagnosticsSnapshot,
  kinds: EspTrackedKind[],
): EspEvidenceItemViewModel[] {
  return snapshot.workloads
    .filter((workload) => kinds.includes(workload.kind))
    .map((workload) => workloadItem(snapshot, workload));
}

function coverageMatch(
  coverage: EspArtifactCoverage[],
  terms: string[],
): EspArtifactCoverage | null {
  const candidates = coverage.filter((entry) => {
    const haystack = `${entry.artifactId} ${entry.family}`.toLowerCase();
    return terms.some((term) => haystack.includes(term));
  });
  const priority: EspArtifactStatus[] = [
    "permissionDenied",
    "parseFailed",
    "missing",
    "unsupported",
    "available",
  ];
  return (
    candidates.sort(
      (left, right) =>
        priority.indexOf(left.status) - priority.indexOf(right.status),
    )[0] ?? null
  );
}

function finishSection(
  definition: SectionDefinition,
  coverage: EspArtifactCoverage[],
): EspEvidenceSectionViewModel {
  const section = {
    id: definition.id,
    title: definition.title,
    description: definition.description,
    items: definition.items,
  };
  if (definition.sourceOverride) {
    return {
      ...section,
      sourceState: definition.sourceOverride.state,
      sourceNote: definition.sourceOverride.note,
    };
  }
  const match = coverageMatch(coverage, definition.coverageTerms);
  if (definition.items.length > 0) {
    if (match && match.status !== "available") {
      return {
        ...section,
        sourceState: "partial",
        sourceNote: `${definition.items.length} normalized records available; partial source coverage: ${match.family} · ${match.detail ?? match.status}`,
      };
    }
    return {
      ...section,
      sourceState: "available",
      sourceNote: `${definition.items.length} normalized ${
        definition.items.length === 1 ? "record" : "records"
      } available.`,
    };
  }
  if (match && match.status !== "available") {
    return {
      ...section,
      sourceState: match.status,
      sourceNote: `${match.family} · ${match.detail ?? match.status}`,
    };
  }
  return {
    ...section,
    sourceState: "notObserved",
    sourceNote: `No ${definition.emptyNoun} records were observed in the collected sources.`,
  };
}

export function buildEspEvidenceViewModel(
  snapshot: EspDiagnosticsSnapshot,
  options: BuildOptions = {},
): EspEvidenceViewModel {
  const revealSensitive = options.revealSensitive ?? false;
  const identity = snapshot.identity;
  const profile =
    snapshot.profile && hasProfileEvidence(snapshot.profile)
      ? snapshot.profile
      : null;

  const hasIdentityEvidence =
    identity.deviceName !== null ||
    identity.managedDeviceId !== null ||
    identity.entraDeviceId !== null ||
    identity.entdmId !== null ||
    identity.tenantId !== null ||
    identity.tenantDomain !== null ||
    identity.userPrincipalName !== null ||
    identity.serialNumber !== null ||
    identity.evidence.length > 0;
  const identityItems: EspEvidenceItemViewModel[] = hasIdentityEvidence
    ? [
        item(
          "local-identity",
          identity.deviceName ?? "Local device identity",
          [
            field(
              "Managed device ID",
              displayNullable(identity.managedDeviceId),
            ),
            field("Entra device ID", displayNullable(identity.entraDeviceId)),
            field(
              "EntDM ID",
              displayClassified(identity.entdmId, revealSensitive),
              identity.entdmId?.sensitivity ?? "public",
            ),
            field(
              "Tenant ID",
              displayClassified(identity.tenantId, revealSensitive),
              identity.tenantId?.sensitivity ?? "public",
            ),
            field(
              "Tenant domain",
              displayClassified(identity.tenantDomain, revealSensitive),
              identity.tenantDomain?.sensitivity ?? "public",
            ),
            field(
              "User principal name",
              displayClassified(identity.userPrincipalName, revealSensitive),
              identity.userPrincipalName?.sensitivity ?? "public",
            ),
            field(
              "Serial number",
              displayClassified(identity.serialNumber, revealSensitive),
              identity.serialNumber?.sensitivity ?? "public",
            ),
          ],
          { evidence: identity.evidence },
        ),
      ]
    : [];
  if (profile) {
    identityItems.push(
      item(
        "deployment-profile",
        profile.profileName ?? "Deployment profile",
        [
          field("Correlation ID", displayNullable(profile.correlationId)),
          field(
            "Tenant domain",
            displayClassified(profile.tenantDomain, revealSensitive),
            profile.tenantDomain?.sensitivity ?? "public",
          ),
          field(
            "Tenant ID",
            displayClassified(profile.tenantId, revealSensitive),
            profile.tenantId?.sensitivity ?? "public",
          ),
          field("Join mode", displayNullable(profile.joinMode)),
          field(
            "Profile downloaded",
            displayTimestamp(profile.profileDownloadTime),
          ),
        ],
        { rawId: profile.deploymentProfileId, evidence: profile.evidence },
      ),
    );
  }

  const oobe = profile?.oobeConfig;
  const oobeItems = oobe
    ? [
        item(
          "oobe-mask",
          `OOBE mask ${oobe.rawMask}`,
          [
            field("Skip keyboard", displayBoolean(oobe.skipKeyboard)),
            field("Patch download", displayBoolean(oobe.enablePatchDownload)),
            field(
              "Skip Windows upgrade UX",
              displayBoolean(oobe.skipWindowsUpgradeUx),
            ),
            field("Entra TPM required", displayBoolean(oobe.aadTpmRequired)),
            field(
              "Entra device authentication",
              displayBoolean(oobe.aadDeviceAuthentication),
            ),
            field("TPM attestation", displayBoolean(oobe.tpmAttestation)),
            field("Skip EULA", displayBoolean(oobe.skipEula)),
            field(
              "Skip OEM registration",
              displayBoolean(oobe.skipOemRegistration),
            ),
            field(
              "Skip express settings",
              displayBoolean(oobe.skipExpressSettings),
            ),
            field("Disallow local admin", displayBoolean(oobe.disallowAdmin)),
          ],
          { evidence: profile?.evidence ?? [] },
        ),
      ]
    : [];

  const configurationItems: EspEvidenceItemViewModel[] = [];
  if (
    profile?.devicePreparation &&
    hasDevicePreparationEvidence(profile.devicePreparation)
  ) {
    const configuration = profile.devicePreparation;
    configurationItems.push(
      item(
        "device-preparation-config",
        "Device Preparation configuration",
        [
          field(
            "Agent timeout (seconds)",
            displayNullable(configuration.agentDownloadTimeoutSeconds),
          ),
          field(
            "Page timeout (seconds)",
            displayNullable(configuration.pageTimeoutSeconds),
          ),
          field(
            "Allow skip on failure",
            displayBoolean(configuration.allowSkipOnFailure),
          ),
          field(
            "Allow diagnostics",
            displayBoolean(configuration.allowDiagnostics),
          ),
          field("Script IDs", configuration.scriptIds.join(", ") || "None"),
        ],
        { evidence: configuration.evidence },
      ),
    );
  }
  configurationItems.push(
    ...snapshot.enrollments.map((enrollment) =>
      item(
        `esp-settings-${enrollment.enrollmentId}`,
        "Enrollment Status Page settings",
        [
          field(
            "Device ESP",
            displayBoolean(enrollment.settings.deviceEspEnabled),
          ),
          field("User ESP", displayBoolean(enrollment.settings.userEspEnabled)),
          field(
            "Timeout (seconds)",
            displayNullable(enrollment.settings.timeoutSeconds),
          ),
          field("Blocking", displayBoolean(enrollment.settings.blocking)),
          field("Allow reset", displayBoolean(enrollment.settings.allowReset)),
          field("Allow retry", displayBoolean(enrollment.settings.allowRetry)),
          field(
            "Continue anyway",
            displayBoolean(enrollment.settings.continueAnyway),
          ),
        ],
        { rawId: enrollment.enrollmentId, evidence: enrollment.evidence },
      ),
    ),
    ...workloadsOfKinds(snapshot, ["devicePreparationWorkload"]),
  );

  const enrollmentItems = [
    ...snapshot.enrollments.map((enrollment) =>
      item(
        `enrollment-${enrollment.enrollmentId}`,
        "Enrollment provider",
        [
          field("Provider ID", displayNullable(enrollment.providerId)),
          field(
            "Tenant ID",
            displayClassified(enrollment.tenantId, revealSensitive),
            enrollment.tenantId?.sensitivity ?? "public",
          ),
          field(
            "User principal name",
            displayClassified(enrollment.userPrincipalName, revealSensitive),
            enrollment.userPrincipalName?.sensitivity ?? "public",
          ),
          field(
            "EntDM ID",
            displayClassified(enrollment.entdmId, revealSensitive),
            enrollment.entdmId?.sensitivity ?? "public",
          ),
        ],
        { rawId: enrollment.enrollmentId, evidence: enrollment.evidence },
      ),
    ),
    ...snapshot.sessions.map((session) =>
      item(
        session.sessionId,
        `${session.scope === "device" ? "Device" : "User"} session`,
        [
          field("Kind", session.kind),
          field("Phase", session.phase),
          field("Latest", session.isLatest ? "Yes" : "No"),
          field("Started", displayTimestamp(session.startedAt)),
          field("Ended", displayTimestamp(session.endedAt)),
          field(
            "User SID",
            displayClassified(session.userSid, revealSensitive),
            session.userSid?.sensitivity ?? "public",
          ),
        ],
        { rawId: session.sessionId, evidence: session.evidence },
      ),
    ),
  ];

  const joinItems: EspEvidenceItemViewModel[] = [];
  if (profile) {
    joinItems.push(
      item(
        "join-profile",
        "Profile join intent",
        [
          field("Join mode", displayNullable(profile.joinMode)),
          field(
            "Offline domain join applied",
            displayBoolean(profile.odjApplied),
          ),
          field(
            "Skip domain connectivity check",
            displayBoolean(profile.skipDomainConnectivityCheck),
          ),
        ],
        { rawId: profile.deploymentProfileId, evidence: profile.evidence },
      ),
    );
  }
  const registrationOccurrences = new Map<string, number>();
  joinItems.push(
    ...snapshot.registrationEvents.map((event) => {
      const primaryEvidence = [...event.evidence].sort(
        (left, right) =>
          left.sourceArtifactId.localeCompare(right.sourceArtifactId) ||
          left.evidenceId.localeCompare(right.evidenceId),
      )[0];
      const identity =
        event.recordId === null
          ? `${primaryEvidence?.sourceArtifactId ?? "unreferenced"}-${
              primaryEvidence?.evidenceId ?? "no-evidence"
            }`
          : `record-${event.recordId}`;
      const baseId = `registration-${event.eventId}-${encodeURIComponent(identity)}`;
      const occurrence = (registrationOccurrences.get(baseId) ?? 0) + 1;
      registrationOccurrences.set(baseId, occurrence);
      return item(
        `${baseId}-${occurrence}`,
        event.message,
        [
          field("Status", event.status.display),
          field("Raw status", String(event.status.raw)),
          field("Timestamp", displayTimestamp(event.timestamp)),
          ...event.namedData.map((value) => field(value.name, value.value)),
        ],
        {
          rawId: event.recordId === null ? null : String(event.recordId),
          evidence: event.evidence,
        },
      );
    }),
  );

  const deliveryItems = snapshot.deliveryOptimization
    ? [
        item(
          "delivery-optimization-summary",
          "Delivery Optimization summary",
          [
            field(
              "HTTP bytes",
              String(snapshot.deliveryOptimization.downloadHttpBytes),
            ),
            field(
              "LAN peer bytes",
              String(snapshot.deliveryOptimization.downloadLanBytes),
            ),
            field(
              "Connected Cache bytes",
              String(snapshot.deliveryOptimization.downloadCacheHostBytes),
            ),
            field(
              "Peer share",
              displayNullable(snapshot.deliveryOptimization.peerSharePercent),
            ),
            field(
              "Connected Cache share",
              displayNullable(
                snapshot.deliveryOptimization.connectedCacheSharePercent,
              ),
            ),
            field(
              "Transfers",
              String(snapshot.deliveryOptimization.transfers.length),
            ),
          ],
          { evidence: snapshot.deliveryOptimization.evidence },
        ),
        ...snapshot.deliveryOptimization.transfers.map((transfer) =>
          item(
            `delivery-transfer-${transfer.transferId}`,
            `Delivery Optimization transfer · ${transfer.kind}`,
            [
              field("Kind", transfer.kind),
              field("Content ID", displayNullable(transfer.contentId)),
              field("App ID", displayNullable(transfer.appId)),
              field("Timestamp", displayTimestamp(transfer.timestamp)),
            ],
            {
              rawId: transfer.transferId,
              evidence: transfer.evidence,
            },
          ),
        ),
      ]
    : [];

  const hardwareItems = snapshot.hardware
    ? [
        item(
          "hardware-summary",
          "Hardware and operating system",
          [
            field("OS version", displayNullable(snapshot.hardware.osVersion)),
            field("OS build", displayNullable(snapshot.hardware.osBuild)),
            field(
              "Manufacturer",
              displayNullable(snapshot.hardware.manufacturer),
            ),
            field("Model", displayNullable(snapshot.hardware.model)),
            field("TPM version", displayNullable(snapshot.hardware.tpmVersion)),
            field(
              "Serial number",
              displayClassified(
                snapshot.hardware.serialNumber,
                revealSensitive,
              ),
              snapshot.hardware.serialNumber?.sensitivity ?? "public",
            ),
          ],
          { evidence: snapshot.hardware.evidence },
        ),
      ]
    : [];

  const nodeCacheItems = snapshot.nodeCache.map((entry) =>
    item(
      `node-cache-${entry.index}`,
      entry.nodeUri,
      [
        field(
          "Expected value",
          displayEvidenceValue(
            entry.expectedValue ?? "Unknown",
            entry.sensitivity,
            revealSensitive,
          ),
          entry.sensitivity,
        ),
      ],
      { rawId: String(entry.index), evidence: entry.evidence },
    ),
  );

  const coverageItems = snapshot.coverage.map((entry) =>
    item(
      `coverage-${entry.artifactId}`,
      entry.family,
      [
        field("Status", entry.status),
        field("Detail", entry.detail ?? "No additional detail"),
        field("Observed", entry.observedAtUtc),
      ],
      { rawId: entry.artifactId, evidence: entry.evidence },
    ),
  );
  const representedCoverageIds = new Set(
    snapshot.coverage.map((entry) => entry.artifactId),
  );
  const missingCoverageGapIds = Array.from(
    new Set(snapshot.findings.flatMap((finding) => finding.coverageGapIds)),
  ).filter((coverageGapId) => !representedCoverageIds.has(coverageGapId));
  coverageItems.push(
    ...missingCoverageGapIds.map((coverageGapId) =>
      item(
        `coverage-${coverageGapId}`,
        "Referenced coverage gap",
        [
          field("Status", "Referenced gap"),
          field(
            "Detail",
            "A finding references this coverage gap, but no source coverage record was included in this snapshot.",
          ),
          field("Observed", "Unknown"),
        ],
        { rawId: coverageGapId },
      ),
    ),
  );

  const rawItems = snapshot.rawEvidence.map((record) => {
    const registry = record.provenance.registry;
    const event = record.provenance.event;
    return item(
      record.recordId,
      `${record.provenance.sourceKind} · ${record.provenance.sourceArtifactId}`,
      [
        field(
          "Raw value",
          displayEvidenceValue(
            displayObservationValue(record.rawValue),
            record.sensitivity,
            revealSensitive,
          ),
          record.sensitivity,
        ),
        field("Access", record.accessState),
        field("Parse", record.parseState),
        field("Sensitivity", record.sensitivity),
        field("Observed", record.observedAtUtc),
        field("Source timestamp", displayTimestamp(record.sourceTimestamp)),
        field(
          "Source timestamp kind",
          record.sourceTimestamp?.kind ?? "Unknown",
        ),
        field(
          "Source original offset",
          record.sourceTimestamp?.originalOffset ?? "Unknown",
        ),
        ...(record.provenance.lineNumber === null
          ? []
          : [field("Line number", String(record.provenance.lineNumber))]),
        ...(record.provenance.recordNumber === null
          ? []
          : [field("Record number", String(record.provenance.recordNumber))]),
        ...(record.provenance.filePath
          ? [field("File", record.provenance.filePath)]
          : []),
        ...(registry
          ? [
              field(
                "Registry",
                `${registry.hive}\\${registry.key}${
                  registry.valueName ? ` · ${registry.valueName}` : ""
                }`,
              ),
            ]
          : []),
        ...(event
          ? [
              field(
                "Event",
                `${event.channel} · Event ${event.eventId} · Record ${
                  event.recordId ?? "unknown"
                }`,
              ),
              ...event.namedData.map((value) =>
                field(
                  `Event data · ${value.name}`,
                  displayEvidenceValue(
                    value.value,
                    record.sensitivity,
                    revealSensitive,
                  ),
                  record.sensitivity,
                ),
              ),
            ]
          : []),
      ],
      { rawId: record.recordId, evidence: record.evidence },
    );
  });

  const definitions: SectionDefinition[] = [
    {
      id: "identity-profile",
      title: "Identity and profile",
      description:
        "Local identity, deployment profile, and immutable identifiers.",
      emptyNoun: "identity or profile",
      coverageTerms: ["identity", "profile", "autopilot"],
      items: identityItems,
    },
    {
      id: "oobe-flags",
      title: "OOBE flags",
      description: "Decoded OOBE mask values without hiding the raw mask.",
      emptyNoun: "OOBE flag",
      coverageTerms: ["oobe", "profile", "autopilot"],
      items: oobeItems,
    },
    {
      id: "esp-configuration",
      title: "ESP configuration",
      description: "Classic ESP and Device Preparation configuration evidence.",
      emptyNoun: "ESP configuration",
      coverageTerms: ["esp", "enrollment", "device preparation"],
      items: configurationItems,
    },
    {
      id: "enrollment-sessions",
      title: "Enrollment and sessions",
      description:
        "Enrollment providers plus device and user session attempts.",
      emptyNoun: "enrollment or session",
      coverageTerms: ["enrollment", "session", "esp"],
      items: enrollmentItems,
    },
    {
      id: "apps",
      title: "Apps",
      description: "MSI, Microsoft 365, modern, and Win32 app evidence.",
      emptyNoun: "app workload",
      coverageTerms: ["app", "ime"],
      items: workloadsOfKinds(snapshot, [
        "msi",
        "office",
        "modernApp",
        "win32App",
      ]),
    },
    {
      id: "scripts",
      title: "Scripts",
      description: "Platform scripts with raw IDs and additive Graph names.",
      emptyNoun: "script",
      coverageTerms: ["script"],
      items: workloadsOfKinds(snapshot, ["platformScript"]),
    },
    {
      id: "policies",
      title: "Policies",
      description: "Tracked policy records and their wire state.",
      emptyNoun: "policy",
      coverageTerms: ["policy"],
      items: workloadsOfKinds(snapshot, ["policy"]),
    },
    {
      id: "certificates",
      title: "Certificates",
      description: "SCEP certificate workload evidence.",
      emptyNoun: "certificate",
      coverageTerms: ["certificate", "scep"],
      items: workloadsOfKinds(snapshot, ["scepCertificate"]),
    },
    {
      id: "join-registration",
      title: "Join and registration",
      description:
        "Join intent, offline-domain-join state, and registration events.",
      emptyNoun: "join or registration",
      coverageTerms: ["join", "registration", "mdm event"],
      items: joinItems,
    },
    {
      id: "delivery-optimization",
      title: "Delivery Optimization",
      description: "Transfer bytes and peer or Connected Cache contribution.",
      emptyNoun: "Delivery Optimization",
      coverageTerms: ["delivery optimization"],
      items: deliveryItems,
    },
    {
      id: "hardware",
      title: "Hardware",
      description:
        "Safe hardware and operating-system facts; hardware hash is excluded.",
      emptyNoun: "hardware",
      coverageTerms: ["hardware", "system"],
      items: hardwareItems,
    },
    {
      id: "node-cache",
      title: "NodeCache",
      description:
        "Raw NodeCache indices, URIs, and classified expected values.",
      emptyNoun: "NodeCache",
      coverageTerms: ["nodecache", "registry"],
      items: nodeCacheItems,
    },
    {
      id: "source-coverage",
      title: "Source coverage",
      description:
        "Collected, missing, denied, failed, and unsupported source families.",
      emptyNoun: "source coverage",
      coverageTerms: ["coverage"],
      items: coverageItems,
    },
    {
      id: "raw-provenance",
      title: "Raw provenance",
      description:
        "Raw records with stable IDs, origin, access, parse state, and sensitivity.",
      emptyNoun: "raw provenance",
      coverageTerms: ["raw", "evidence"],
      items: rawItems,
    },
  ];

  const representedEvidenceIds = new Set(
    definitions.flatMap((definition) =>
      definition.items.flatMap((evidenceItem) =>
        evidenceItem.evidence.map((reference) => reference.evidenceId),
      ),
    ),
  );
  const linkedReferences = [
    ...snapshot.findings.flatMap((finding) => finding.evidence),
    ...snapshot.activity.flatMap((entry) => entry.evidence),
    ...snapshot.workloads.flatMap((workload) => workload.evidence),
    ...snapshot.installerCorrelations.flatMap((correlation) => [
      ...correlation.evidence,
      ...correlation.processObservations.map(
        (process) => process.context.evidenceRef,
      ),
    ]),
  ];
  const seenLinkedEvidence = new Set<string>();
  const referenceOnlyItems = linkedReferences
    .filter((reference) => {
      if (
        representedEvidenceIds.has(reference.evidenceId) ||
        seenLinkedEvidence.has(reference.evidenceId)
      ) {
        return false;
      }
      seenLinkedEvidence.add(reference.evidenceId);
      return true;
    })
    .map((reference) =>
      item(
        `reference-only-${reference.evidenceId}`,
        `Evidence reference · ${reference.sourceArtifactId}`,
        [
          field("Evidence ID", reference.evidenceId),
          field("Source artifact", reference.sourceArtifactId),
          field("Raw record", "Raw record not included in this snapshot"),
        ],
        { rawId: reference.evidenceId, evidence: [reference] },
      ),
    );

  if (referenceOnlyItems.length > 0 || missingCoverageGapIds.length > 0) {
    const coverageDefinition = definitions.find(
      (definition) => definition.id === "source-coverage",
    );
    if (coverageDefinition) {
      coverageDefinition.items.push(...referenceOnlyItems);
      const notes = [];
      if (missingCoverageGapIds.length > 0) {
        notes.push(
          `${missingCoverageGapIds.length} referenced coverage ${
            missingCoverageGapIds.length === 1 ? "gap has" : "gaps have"
          } no source coverage record in this snapshot`,
        );
      }
      if (referenceOnlyItems.length > 0) {
        notes.push(
          `${referenceOnlyItems.length} linked evidence ${
            referenceOnlyItems.length === 1
              ? "reference has"
              : "references have"
          } no raw or normalized record in this snapshot`,
        );
      }
      coverageDefinition.sourceOverride = {
        state: "partial",
        note: `${snapshot.coverage.length} source coverage ${
          snapshot.coverage.length === 1 ? "record" : "records"
        } available; ${notes.join("; ")}.`,
      };
    }
  }

  return {
    disclosurePolicy: ESP_EVIDENCE_DISCLOSURE_POLICY,
    sections: definitions.map((definition) =>
      finishSection(definition, snapshot.coverage),
    ),
  };
}
