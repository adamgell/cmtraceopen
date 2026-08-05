import { useEffect, useRef, type ReactNode } from "react";
import { Button, Spinner } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import {
  ArchiveRegular,
  CheckmarkCircleRegular,
  DatabaseSearchRegular,
  DismissCircleRegular,
  FolderOpenRegular,
  InfoRegular,
  WarningRegular,
} from "@fluentui/react-icons";
import {
  captureSccmDiagnostics,
  authorizeSccmAdvancedCapture,
  cancelSccmAdvancedCapture,
  captureSccmAdvancedDiagnostics,
  discoverSccmEnvironment,
  revealInFileManager,
} from "../../lib/commands";
import { useSccmStore } from "./sccm-store";
import type {
  SccmCoverageState,
  SccmAdvancedSourceOption,
  SccmDiscoveryBasis,
  SccmDiscoveryIssueCode,
  SccmRole,
  SccmRotationCategory,
  SccmSourceDetailCode,
  SccmSourceStatus,
} from "./types";
import "./sccm-workspace.css";

const ROLE_LABELS: Record<SccmRole, string> = {
  client: "Client",
  siteServer: "Site Server",
  managementPoint: "Management Point",
  distributionPoint: "Distribution Point",
  softwareUpdatePoint: "Software Update Point",
  wsUs: "WSUS",
  provider: "Provider",
  adminService: "Admin Service",
  distributionPointPxe: "PXE Distribution Point",
  certificateRegistrationPoint: "Certificate Registration Point",
  reportingServicesPoint: "Reporting Services Point",
  cloudManagementGatewayConnectionPoint: "CMG Connection Point",
  serviceConnectionPoint: "Service Connection Point",
  clientNotificationServer: "Client Notification Server",
  unclassified: "Unclassified candidate",
};

const ADVANCED_CARD_LABELS: Record<string, string> = {
  "osd-pxe": "OSD / PXE",
  "certificate-enrollment-pki": "Certificate enrollment / PKI",
  reporting: "Reporting services",
  "cloud-service-connection": "Cloud service connection",
  "client-notification-bgb": "Client notification / BGB",
};

const BASIS_LABELS: Record<SccmDiscoveryBasis, string> = {
  registry: "Registry",
  service: "Service",
  cim: "CIM",
};

const ROTATION_LABELS: Record<SccmRotationCategory, string> = {
  current: "Current",
  loUnderscore: "LO_",
  numbered: "Numbered",
  timestamped: "Timestamped",
  unknown: "Unknown",
};

const COVERAGE_LABELS: Record<SccmCoverageState, string> = {
  captured: "Captured",
  absent: "Absent",
  accessDenied: "Access denied",
  capped: "Capped",
  skipped: "Skipped",
  unsupported: "Unsupported",
  parseFailed: "Parse failed",
};

const DETAIL_LABELS: Record<SccmSourceDetailCode, string> = {
  accessDenied: "Access denied",
  byteLimitExceeded: "Byte limit exceeded",
  fileLimitExceeded: "File limit exceeded",
  malformedRotation: "Malformed rotation",
  readFailed: "Read failed",
  unsafePath: "Unsafe path rejected",
  unsupportedPlatform: "Unsupported platform",
};

const ISSUE_LABELS: Record<SccmDiscoveryIssueCode, string> = {
  unsupportedPlatform: "Unsupported platform",
  registryAccessDenied: "Registry access denied",
  cimAccessDenied: "CIM access denied",
  discoveryFailed: "Discovery failed",
};

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message.trim()
    ? error.message
    : fallback;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function formatCaptureTime(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime())
    ? value
    : timestamp.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      });
}

function coverageIcon(state: SccmCoverageState): ReactNode {
  switch (state) {
    case "captured":
      return <CheckmarkCircleRegular aria-hidden="true" />;
    case "accessDenied":
    case "parseFailed":
      return <DismissCircleRegular aria-hidden="true" />;
    case "capped":
    case "unsupported":
      return <WarningRegular aria-hidden="true" />;
    case "absent":
    case "skipped":
      return <span aria-hidden="true">—</span>;
  }
}

function SourceLedger({ sources }: { sources: SccmSourceStatus[] }) {
  if (sources.length === 0) {
    return (
      <div className="sccm-empty-ledger">
        No allow-listed SCCM sources were observed for the detected roles.
      </div>
    );
  }

  return (
    <div className="sccm-ledger-scroll">
      <table className="sccm-ledger">
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">Role</th>
            <th scope="col">Rotation</th>
            <th scope="col">State</th>
            <th scope="col" className="sccm-numeric-column">
              Retained
            </th>
          </tr>
        </thead>
        <tbody>
          {sources.map((source, index) => (
            <tr
              key={`${source.role}:${source.sourceId}:${source.rotation}:${index}`}
            >
              <td>
                <span className="sccm-source-id">{source.sourceId}</span>
              </td>
              <td>{ROLE_LABELS[source.role]}</td>
              <td>
                <span className="sccm-rotation">{ROTATION_LABELS[source.rotation]}</span>
              </td>
              <td>
                <span
                  className={`sccm-state sccm-state--${source.state}`}
                  data-state={source.state}
                >
                  {coverageIcon(source.state)}
                  <span>{COVERAGE_LABELS[source.state]}</span>
                </span>
                {source.detailCode &&
                DETAIL_LABELS[source.detailCode] !== COVERAGE_LABELS[source.state] ? (
                  <span className="sccm-detail-code">
                    {DETAIL_LABELS[source.detailCode]}
                  </span>
                ) : null}
              </td>
              <td className="sccm-numeric-column sccm-byte-count">
                {formatBytes(source.retainedBytes)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function SccmWorkspace() {
  const mountedRef = useRef(true);
  const advancedOperationRef = useRef(0);
  const phase = useSccmStore((state) => state.phase);
  const discovery = useSccmStore((state) => state.discovery);
  const capture = useSccmStore((state) => state.capture);
  const error = useSccmStore((state) => state.error);
  const beginDiscovery = useSccmStore((state) => state.beginDiscovery);
  const completeDiscovery = useSccmStore((state) => state.completeDiscovery);
  const beginCapture = useSccmStore((state) => state.beginCapture);
  const completeCapture = useSccmStore((state) => state.completeCapture);
  const fail = useSccmStore((state) => state.fail);
  const advancedCapability = useSccmStore(
    (state) => state.advancedCapability,
  );
  const beginAdvancedAuthorization = useSccmStore(
    (state) => state.beginAdvancedAuthorization,
  );
  const completeAdvancedAuthorization = useSccmStore(
    (state) => state.completeAdvancedAuthorization,
  );
  const beginAdvancedCapture = useSccmStore(
    (state) => state.beginAdvancedCapture,
  );
  const clearAdvancedCapability = useSccmStore(
    (state) => state.clearAdvancedCapability,
  );
  const isBusy = [
    "discovering",
    "capturing",
    "authorizing",
    "capturingAdvanced",
  ].includes(phase);
  const canCapture = Boolean(
    discovery?.supported && discovery.roles.length > 0,
  );
  const sources = capture?.sources ?? discovery?.sources ?? [];

  const discover = async () => {
    if (isBusy) return;
    beginDiscovery();
    try {
      completeDiscovery(await discoverSccmEnvironment());
    } catch (error) {
      fail(errorMessage(error, "SCCM environment discovery failed."));
    }
  };

  const captureBundle = async () => {
    if (isBusy || !canCapture) return;
    beginCapture();
    try {
      completeCapture(await captureSccmDiagnostics());
    } catch (error) {
      fail(errorMessage(error, "SCCM diagnostic capture failed."));
    }
  };

  const revealBundle = async () => {
    if (!capture) return;
    try {
      await revealInFileManager(capture.bundleRoot);
    } catch (error) {
      fail(errorMessage(error, "The captured bundle could not be revealed."));
    }
  };

  useEffect(
    () => {
      mountedRef.current = true;
      return () => {
        mountedRef.current = false;
        advancedOperationRef.current += 1;
        const state = useSccmStore.getState();
        if (state.advancedCapability) {
          void cancelSccmAdvancedCapture(
            state.advancedCapability.capabilityHandle,
          ).catch(() => undefined);
        }
        if (
          state.advancedCapability ||
          state.phase === "authorizing" ||
          state.phase === "capturingAdvanced"
        ) {
          state.clearAdvancedCapability();
        }
      };
    },
    [],
  );

  const captureAdvanced = async (option: SccmAdvancedSourceOption) => {
    if (isBusy || option.availability === "blocked") return;
    const operationId = advancedOperationRef.current + 1;
    advancedOperationRef.current = operationId;
    const isActive = () =>
      mountedRef.current && advancedOperationRef.current === operationId;
    const selected = await open({ directory: true, multiple: false });
    if (!isActive() || typeof selected !== "string") return;
    const roleScope =
      option.availability === "observed" &&
      option.roleScopes.includes("managementPoint")
        ? "managementPoint"
        : option.roleScopes[0];
    const pathClass = option.pathClasses[0];
    if (!roleScope || !pathClass) return;
    const provenanceLabel =
      option.availability === "observed"
        ? "Observed role/path — bounded capture"
        : "Operator-declared candidate root — role not observed; capture only";
    const consented = window.confirm(
      `${ADVANCED_CARD_LABELS[option.cardId] ?? option.cardId}\n${provenanceLabel}\n\nRetain at most ${formatBytes(option.maxBytes)} across ${option.maxFiles} exact current/LO_ files?`,
    );
    if (!consented) return;

    beginAdvancedAuthorization();
    let issuedCapabilityHandle: string | null = null;
    try {
      const capability = await authorizeSccmAdvancedCapture({
        cardId: option.cardId,
        cardVersion: option.cardVersion,
        sourceId: option.sourceId,
        roleScope,
        pathClass,
        expectedSourceVersion: option.sourceVersion,
        selectedRoot: selected,
      });
      issuedCapabilityHandle = capability.capabilityHandle;
      if (!isActive()) {
        await cancelSccmAdvancedCapture(capability.capabilityHandle).catch(
          () => undefined,
        );
        return;
      }
      completeAdvancedAuthorization(capability);
      if (!window.confirm("Authorization is ready. Capture this bounded source now?")) {
        clearAdvancedCapability();
        await cancelSccmAdvancedCapture(capability.capabilityHandle);
        return;
      }
      beginAdvancedCapture();
      const result = await captureSccmAdvancedDiagnostics(
        capability.capabilityHandle,
      );
      if (isActive()) completeCapture(result);
    } catch (error) {
      if (issuedCapabilityHandle) {
        await cancelSccmAdvancedCapture(issuedCapabilityHandle).catch(
          () => undefined,
        );
      }
      if (isActive()) {
        fail(errorMessage(error, "Advanced SCCM capture failed."));
      }
    }
  };

  return (
    <main className="sccm-workspace">
      <header className="sccm-command-header">
        <div className="sccm-heading-lockup">
          <div className="sccm-kicker">CONFIGURATION MANAGER / NATIVE EVIDENCE</div>
          <div className="sccm-title-row">
            <span
              className={`sccm-status-lamp ${discovery ? "is-ready" : ""}`}
              aria-hidden="true"
            />
            <div>
              <h1>SCCM diagnostics</h1>
              <p>
                Read-only role discovery and bounded evidence capture. Source
                paths and machine identity stay inside the native collector.
              </p>
            </div>
          </div>
        </div>

        <div className="sccm-command-actions">
          <Button
            appearance={discovery ? "secondary" : "primary"}
            icon={phase === "discovering" ? <Spinner size="tiny" /> : <DatabaseSearchRegular />}
            disabled={isBusy}
            onClick={() => void discover()}
            aria-label={
              phase === "discovering"
                ? "Discovering SCCM environment"
                : "Discover SCCM environment"
            }
          >
            {phase === "discovering" ? "Discovering environment" : discovery ? "Refresh discovery" : "Discover environment"}
          </Button>
          {discovery ? (
            <Button
              appearance="primary"
              icon={phase === "capturing" ? <Spinner size="tiny" /> : <ArchiveRegular />}
              disabled={isBusy || !canCapture}
              onClick={() => void captureBundle()}
              aria-label={
                phase === "capturing"
                  ? "Capturing diagnostic bundle"
                  : "Capture diagnostic bundle"
              }
            >
              {phase === "capturing" ? "Capturing bundle" : "Capture diagnostic bundle"}
            </Button>
          ) : null}
        </div>
      </header>

      {!discovery ? (
        <section className="sccm-idle-panel" aria-labelledby="sccm-idle-title">
          <div className="sccm-idle-index" aria-hidden="true">
            01
          </div>
          <div>
            <h2 id="sccm-idle-title">Read-only environment discovery</h2>
            <p>
              Detect installed client and site-system roles before any files are
              retained. Discovery reads allow-listed system facts and does not
              create a bundle.
            </p>
          </div>
          <div className="sccm-safety-note">
            <span>NO INPUT PATHS</span>
            <span>NO HOST IDENTIFIERS</span>
            <span>NO WRITES</span>
          </div>
        </section>
      ) : (
        <div className="sccm-console-body">
          <section className="sccm-environment-strip" aria-label="Discovered environment">
            <div className="sccm-environment-fact">
              <span className="sccm-fact-label">Collector</span>
              <strong>{discovery.supported ? "Supported" : "Unavailable"}</strong>
            </div>
            <div className="sccm-environment-fact">
              <span className="sccm-fact-label">ConfigMgr</span>
              <strong>{discovery.configmgrVersion ?? "Not reported"}</strong>
            </div>
            <div className="sccm-environment-fact sccm-role-fact">
              <span className="sccm-fact-label">Observed roles</span>
              <div className="sccm-role-list">
                {discovery.roles.length > 0 ? (
                  discovery.roles.map((role) => (
                    <span className="sccm-role-chip" key={`${role.role}:${role.basis}`}>
                      <strong>{ROLE_LABELS[role.role]}</strong>
                      <span>{BASIS_LABELS[role.basis]}</span>
                    </span>
                  ))
                ) : (
                  <span className="sccm-no-roles">No SCCM roles observed</span>
                )}
              </div>
            </div>
          </section>

          {discovery.supported && discovery.roles.length === 0 ? (
            <section
              className="sccm-no-roles-state"
              aria-labelledby="sccm-no-roles-title"
            >
              <InfoRegular aria-hidden="true" />
              <div>
                <strong id="sccm-no-roles-title">No SCCM roles detected</strong>
                <span>
                  This host is supported, but discovery found no Configuration
                  Manager roles to collect.
                </span>
              </div>
            </section>
          ) : null}

          {error ? (
            <div className="sccm-error-banner" role="alert">
              <DismissCircleRegular aria-hidden="true" />
              <div>
                <strong>Native operation failed</strong>
                <span>{error}</span>
              </div>
            </div>
          ) : null}

          {discovery.issues.length > 0 ? (
            <section className="sccm-issue-rail" aria-label="Discovery issues">
              {discovery.issues.map((issue, index) => (
                <div className="sccm-issue" key={`${issue.code}:${issue.role ?? "all"}:${index}`}>
                  <WarningRegular aria-hidden="true" />
                  <span>{ISSUE_LABELS[issue.code]}</span>
                  {issue.role ? <small>{ROLE_LABELS[issue.role]}</small> : null}
                </div>
              ))}
            </section>
          ) : null}

          {capture ? (
            <section className="sccm-capture-receipt" aria-label="Capture result">
              <div className="sccm-receipt-mark">
                <CheckmarkCircleRegular aria-hidden="true" />
              </div>
              <div>
                <span className="sccm-fact-label">Bundle retained</span>
                <strong>{capture.artifactCount} {capture.artifactCount === 1 ? "artifact" : "artifacts"}</strong>
              </div>
              <div>
                <span className="sccm-fact-label">Payload</span>
                <strong>{formatBytes(capture.retainedBytes)} retained</strong>
              </div>
              <div>
                <span className="sccm-fact-label">Captured</span>
                <strong>{formatCaptureTime(capture.capturedAtUtc)}</strong>
              </div>
              <Button
                appearance="secondary"
                icon={<FolderOpenRegular />}
                onClick={() => void revealBundle()}
                aria-label="Reveal bundle"
              >
                Reveal bundle
              </Button>
            </section>
          ) : null}

          {discovery.advancedSources.length > 0 ? (
            <section
              className="sccm-advanced-panel"
              aria-labelledby="sccm-advanced-title"
            >
              <div className="sccm-panel-heading">
                <div>
                  <span className="sccm-panel-index">02 / ADVANCED SOURCES</span>
                  <h2 id="sccm-advanced-title">Bounded role capture</h2>
                </div>
                <span className="sccm-ledger-count">
                  {discovery.advancedSources.length} allow-listed
                </span>
              </div>
              <p className="sccm-advanced-intro">
                Select one exact source contract. The chosen directory crosses
                the native boundary once and is never returned, logged, or
                stored in the workspace.
              </p>
              <div className="sccm-advanced-grid">
                {discovery.advancedSources.map((option) => {
                  const observed = option.availability === "observed";
                  return (
                    <article
                      className={`sccm-advanced-source sccm-advanced-source--${option.availability}`}
                      key={option.sourceId}
                    >
                      <div>
                        <span className="sccm-advanced-card-id">
                          {ADVANCED_CARD_LABELS[option.cardId] ?? option.cardId}
                        </span>
                        <strong>{option.sourceId}</strong>
                      </div>
                      <p className="sccm-advanced-provenance">
                        {observed
                          ? "Observed role/path — bounded capture"
                          : option.availability === "blocked"
                            ? "Unavailable on this host"
                            : "Operator-declared candidate root — role not observed; capture only"}
                      </p>
                      <div className="sccm-advanced-limit">
                        <span>{formatBytes(option.maxBytes)} total / source</span>
                        <span>{option.maxFiles} files</span>
                        <span>current + LO_</span>
                      </div>
                      <Button
                        appearance={observed ? "primary" : "secondary"}
                        disabled={isBusy || option.availability === "blocked"}
                        onClick={() => void captureAdvanced(option)}
                        aria-label={`Authorize ${ADVANCED_CARD_LABELS[option.cardId] ?? option.cardId} bounded capture`}
                      >
                        {phase === "authorizing"
                          ? "Authorizing"
                          : phase === "capturingAdvanced"
                            ? "Capturing"
                            : "Choose candidate root"}
                      </Button>
                    </article>
                  );
                })}
              </div>
              {advancedCapability ? (
                <span className="sccm-capability-pending" role="status">
                  Single-use authorization ready
                </span>
              ) : null}
            </section>
          ) : null}

          <section className="sccm-ledger-panel" aria-labelledby="sccm-ledger-title">
            <div className="sccm-panel-heading">
              <div>
                <span className="sccm-panel-index">03 / SOURCE COVERAGE</span>
                <h2 id="sccm-ledger-title">Evidence ledger</h2>
              </div>
              <span className="sccm-ledger-count">{sources.length} rows</span>
            </div>
            <SourceLedger sources={sources} />
          </section>
        </div>
      )}
    </main>
  );
}
