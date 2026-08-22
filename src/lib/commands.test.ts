import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import {
  captureSccmDiagnostics,
  authorizeSccmAdvancedCapture,
  cancelSccmAdvancedCapture,
  captureSccmAdvancedDiagnostics,
  analyzeIntuneLogs,
  discoverSccmEnvironment,
  getSafeErrorMessage,
  graphGetAuthStatus,
  graphAuthenticate,
  graphCancelAuthentication,
  graphReserveInteractiveOperation,
  graphRequestMissingPermissions,
  diagnoseEventRecords,
  openLogFile,
  parseEventLogManifest,
  expandEventLogSources,
  buildTimeline,
  listLogFolder,
  parseFilesBatch,
  revealInFileManager,
  inspectEvidenceArtifact,
  getFileAssociationPromptStatus,
  openWindowsDefaultApps,
  registerLogFileHandler,
} from "./commands";
import type { EvtxRecord } from "../workspaces/event-log/types";

import { readAccessDenied } from "./source-error";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

async function captureRejection<T>(promise: Promise<T>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("Expected command to reject.");
    },
    (error: unknown) => error,
  );
}

function expectFreshCommandFallback(
  error: unknown,
  rejectedValue: unknown,
  message: string,
): void {
  expect(error).toBeInstanceOf(Error);
  expect(Object.is(error, rejectedValue)).toBe(false);
  expect((error as Error).message).toBe(message);
  expect(Object.prototype.hasOwnProperty.call(error, "body")).toBe(false);
  expect(Object.prototype.hasOwnProperty.call(error, "token")).toBe(false);
  expect(Object.getOwnPropertySymbols(error as object)).toEqual([]);
}

function makeHostileErrorProxy(secretPrefix: string): {
  rejection: object;
  getPrototypeOfReads: () => number;
} {
  const secretSymbol = Symbol(`${secretPrefix}-symbol`);
  const target = new Error(`${secretPrefix}-message-secret`);
  Object.defineProperties(target, {
    body: {
      enumerable: true,
      value: `${secretPrefix}-body-secret`,
    },
    token: {
      enumerable: true,
      value: `${secretPrefix}-token-secret`,
    },
    [secretSymbol]: {
      enumerable: true,
      value: `${secretPrefix}-symbol-secret`,
    },
  });

  let prototypeReads = 0;
  return {
    rejection: new Proxy(target, {
      getPrototypeOf() {
        prototypeReads += 1;
        throw new Error(`${secretPrefix}-prototype-trap-secret`);
      },
    }),
    getPrototypeOfReads: () => prototypeReads,
  };
}

beforeEach(() => {
  vi.mocked(invoke).mockReset();
});

describe("parse and folder IPC response validation", () => {
  it("preserves valid parser and folder responses", async () => {
    const parseResult = {
      entries: [
        {
          id: 0,
          lineNumber: 1,
          message: "line",
          component: null,
          timestamp: null,
          timestampDisplay: null,
          severity: "Info",
          thread: null,
          threadDisplay: null,
          sourceFile: null,
          format: "Simple",
          filePath: "C:\\Logs\\App.log",
          timezoneOffset: null,
        },
      ],
      formatDetected: "Simple",
      parserSelection: {
        parser: "simple",
        implementation: "simple",
        provenance: "dedicated",
        parseQuality: "structured",
        recordFraming: "physicalLine",
        dateOrder: null,
        specialization: null,
      },
      totalLines: 0,
      parseErrors: 0,
      filePath: "C:\\Logs\\App.log",
      fileSize: 0,
      byteOffset: 0,
    };
    const folderListing = {
      sourceKind: "folder",
      source: { kind: "folder", path: "C:\\Logs" },
      entries: [],
      childErrors: [
        {
          path: "C:\\Logs\\protected.evtx",
          reason: "access denied",
        },
      ],
      bundleMetadata: null,
    };
    vi.mocked(invoke)
      .mockResolvedValueOnce([parseResult])
      .mockResolvedValueOnce(folderListing);

    await expect(parseFilesBatch(["C:\\Logs\\App.log"], 7, 0)).resolves.toEqual(
      [parseResult],
    );
    expect(invoke).toHaveBeenCalledWith("parse_files_batch", {
      paths: ["C:\\Logs\\App.log"],
      requestId: 7,
      completedOffset: 0,
    });
    await expect(listLogFolder("C:\\Logs")).resolves.toEqual(folderListing);
  });

  it("rejects malformed parser and folder responses", async () => {
    vi.mocked(invoke)
      .mockResolvedValueOnce({ filePath: "C:\\Logs\\App.log" })
      .mockResolvedValueOnce([{ filePath: "C:\\Logs\\App.log" }])
      .mockResolvedValueOnce({
        sourceKind: "folder",
        source: { kind: "folder", path: "C:\\Logs" },
        entries: [{ name: "App.log", path: "C:\\Logs\\App.log" }],
      });

    await expect(openLogFile("C:\\Logs\\App.log")).rejects.toThrow(
      "Command 'open_log_file' returned an invalid response.",
    );
    await expect(parseFilesBatch(["C:\\Logs\\App.log"], 7, 0)).rejects.toThrow(
      "Command 'parse_files_batch' returned an invalid response.",
    );
    await expect(listLogFolder("C:\\Logs")).rejects.toThrow(
      "Command 'list_log_folder' returned an invalid response.",
    );
  });

  it("accepts a folder listing when optional childErrors is absent", async () => {
    const folderListing = {
      sourceKind: "folder",
      source: { kind: "folder", path: "C:\\Logs" },
      entries: [],
      bundleMetadata: null,
    };
    vi.mocked(invoke).mockResolvedValueOnce(folderListing);

    await expect(listLogFolder("C:\\Logs")).resolves.toEqual(folderListing);
  });

  it.each([
    ["when it is not an array", { path: "C:\\Logs\\protected.evtx", reason: "access denied" }],
    ["when it has a non-record member", ["access denied"]],
    [
      "when a member has a non-string path",
      [{ path: 7, reason: "access denied" }],
    ],
    [
      "when a member has a non-string reason",
      [{ path: "C:\\Logs\\protected.evtx", reason: { message: "denied" } }],
    ],
  ])("rejects folder childErrors %s", async (_label, childErrors) => {
    vi.mocked(invoke).mockResolvedValueOnce({
      sourceKind: "folder",
      source: { kind: "folder", path: "C:\\Logs" },
      entries: [],
      childErrors,
      bundleMetadata: null,
    });

    await expect(listLogFolder("C:\\Logs")).rejects.toThrow(
      "Command 'list_log_folder' returned an invalid response.",
    );
  });
});

describe("Windows file handler IPC boundary", () => {
  it("registers a candidate separately from opening the user-owned default picker", async () => {
    const registration = {
      supported: true,
      shouldPrompt: false,
      isRegistered: true,
    };
    vi.mocked(invoke)
      .mockResolvedValueOnce(registration)
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined);

    await expect(getFileAssociationPromptStatus()).resolves.toEqual(registration);
    await expect(registerLogFileHandler()).resolves.toBeUndefined();
    await expect(openWindowsDefaultApps()).resolves.toBeUndefined();

    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "get_file_association_prompt_status",
      undefined,
    );
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "register_log_file_handler",
      undefined,
    );
    expect(invoke).toHaveBeenNthCalledWith(
      3,
      "open_windows_default_apps",
      undefined,
    );
  });

  it("rejects the obsolete default-association status shape", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      supported: true,
      shouldPrompt: false,
      isAssociated: true,
    });

    await expect(getFileAssociationPromptStatus()).rejects.toThrow(
      "Command 'get_file_association_prompt_status' returned an invalid response.",
    );
  });

  it("surfaces unavailable native association commands instead of decoding a false unit success", async () => {
    vi.mocked(invoke)
      .mockRejectedValueOnce(
        new Error("register_log_file_handler is unavailable in browser mode"),
      )
      .mockRejectedValueOnce(
        new Error("open_windows_default_apps is unavailable in browser mode"),
      );

    await expect(registerLogFileHandler()).rejects.toThrow(
      "Command 'register_log_file_handler' failed.",
    );
    await expect(openWindowsDefaultApps()).rejects.toThrow(
      "Command 'open_windows_default_apps' failed.",
    );
  });
});

function validIntuneAnalysis() {
  return {
    events: [],
    downloads: [],
    summary: {},
    diagnostics: [],
    sourceFile: "C:\\Logs\\IntuneManagementExtension.log",
    sourceFiles: [],
    diagnosticsCoverage: {},
    diagnosticsConfidence: {},
    repeatedFailures: [],
    guidRegistry: {},
  };
}

describe("Intune IPC response validation", () => {
  it("accepts structured diagnostics metadata", async () => {
    const result = validIntuneAnalysis();
    vi.mocked(invoke).mockResolvedValueOnce(result);

    await expect(
      analyzeIntuneLogs("C:\\Logs", "request-1"),
    ).resolves.toEqual(result);
  });

  it("rejects malformed diagnostics metadata", async () => {
    const result = {
      ...validIntuneAnalysis(),
      diagnosticsCoverage: "complete",
      diagnosticsConfidence: "high",
    };
    vi.mocked(invoke).mockResolvedValueOnce(result);

    await expect(
      analyzeIntuneLogs("C:\\Logs", "request-1"),
    ).rejects.toThrow("invalid response");
  });
});


function validTimelineBundle() {
  return {
    id: "timeline-1",
    sources: [
      {
        idx: 0,
        kind: "intuneEvents",
        path: "C:\\Logs",
        displayName: "Logs",
        color: "#2563eb",
        entryCount: 1,
      },
      {
        idx: 1,
        kind: { logFile: { parserKind: "ccm" } },
        path: "C:\\Logs\\App.log",
        displayName: "App.log",
        color: "#16a34a",
        entryCount: 1,
      },
    ],
    timeRangeMs: [100, 200],
    totalEntries: 2,
    incidents: [
      {
        id: 0,
        tsStartMs: 100,
        tsEndMs: 200,
        signalCount: 2,
        sourceCount: 2,
        confidence: 0.5,
        anchorEventRef: null,
        anchorGuid: null,
        summary: "Overlapping failures",
      },
    ],
    deniedGuids: [],
    errors: [],
    tunables: {
      overlapWindowMs: 5_000,
      minSourceCount: 2,
      maxIncidentSpanMs: 60_000,
      enabledSignalKinds: ["errorSeverity"],
    },
  };
}

describe("timeline IPC response validation", () => {
  it("preserves a valid timeline bundle", async () => {
    const bundle = validTimelineBundle();
    vi.mocked(invoke).mockResolvedValue(bundle);

    await expect(
      buildTimeline([{ path: "C:\\Logs", displayName: "Logs" }]),
    ).resolves.toEqual(bundle);
    expect(invoke).toHaveBeenCalledWith("build_timeline_cmd", {
      sources: [{ path: "C:\\Logs", displayName: "Logs" }],
    });
  });

  it("rejects a timeline bundle with malformed nested source data", async () => {
    const bundle = validTimelineBundle();
    const malformedBundle = {
      ...bundle,
      sources: [
        {
          ...bundle.sources[0],
          kind: { logFile: { parserKind: "not-a-parser" } },
        },
      ],
    };
    vi.mocked(invoke).mockResolvedValue(malformedBundle);

    await expect(buildTimeline([{ path: "C:\\Logs" }])).rejects.toThrow(
      "Command 'build_timeline_cmd' returned an invalid response.",
    );
  });
});

function validEvidenceArtifactPreview() {
  return {
    path: "C:\\Logs\\snapshot.reg",
    intakeKind: "registrySnapshot",
    summary: "Parsed registry snapshot.",
    registrySnapshot: {
      keyCount: 1,
      valueCount: 1,
      keys: [
        {
          path: "HKLM\\Software\\Contoso",
          valueCount: 1,
          values: [
            {
              name: "Enabled",
              valueType: "dword",
              value: "0x00000001 (1)",
            },
          ],
        },
      ],
    },
    eventLogExport: null,
  };
}

describe("evidence artifact IPC response validation", () => {
  it("preserves validated nested preview metadata", async () => {
    const preview = validEvidenceArtifactPreview();
    vi.mocked(invoke).mockResolvedValue(preview);

    await expect(
      inspectEvidenceArtifact("C:\\Logs\\snapshot.reg", "registrySnapshot"),
    ).resolves.toEqual(preview);
  });

  it("rejects malformed nested preview metadata", async () => {
    const preview = validEvidenceArtifactPreview();
    vi.mocked(invoke).mockResolvedValue({
      ...preview,
      registrySnapshot: {
        ...preview.registrySnapshot,
        keys: [{ path: "HKLM\\Software\\Contoso", valueCount: 1 }],
      },
    });

    await expect(
      inspectEvidenceArtifact("C:\\Logs\\snapshot.reg", "registrySnapshot"),
    ).rejects.toThrow(
      "Command 'inspect_evidence_artifact' returned an invalid response.",
    );
  });
});

function validGraphStatus() {
  return {
    isAuthenticated: true,
    userPrincipalName: "admin@contoso.com",
    objectId: "00000000-0000-0000-0000-0000000000a1",
    tenantId: "tenant-1",
    grantedScopes: ["DeviceManagementManagedDevices.Read.All"],
    missingScopes: [],
    expiresAt: 1_800_000_000,
    capabilities: {
      managedDevices: true,
      serviceConfig: false,
      apps: false,
      configuration: false,
      scripts: false,
    },
  };
}

describe("SCCM product-path IPC boundary", () => {
  it("invokes discovery and capture without accepting frontend inputs", async () => {
    const discovery = {
      supported: true,
      configmgrVersion: null,
      roles: [],
      sources: [],
      issues: [],
      advancedSources: [],
    };
    const capture = {
      bundleRoot: "C:\\capture",
      capturedAtUtc: "2026-08-04T14:30:00Z",
      roles: [],
      sources: [],
      artifactCount: 0,
      retainedBytes: 0,
    };
    vi.mocked(invoke)
      .mockResolvedValueOnce(discovery)
      .mockResolvedValueOnce(capture)
      .mockResolvedValueOnce(undefined);

    await expect(discoverSccmEnvironment()).resolves.toBe(discovery);
    await expect(captureSccmDiagnostics()).resolves.toBe(capture);
    await expect(
      revealInFileManager(capture.bundleRoot),
    ).resolves.toBeUndefined();

    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "discover_sccm_environment",
      undefined,
    );
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "capture_sccm_diagnostics",
      undefined,
    );
    expect(invoke).toHaveBeenNthCalledWith(3, "reveal_in_file_manager", {
      path: capture.bundleRoot,
    });
  });

  it("keeps advanced authorization closed and capability-only after authorize", async () => {
    const request = {
      cardId: "osd-pxe",
      cardVersion: "1.0.0",
      sourceId: "advanced-osd-pxe",
      roleScope: "distributionPointPxe",
      pathClass: "configuredRoleLogRoot",
      expectedSourceVersion: "5.00.9141.1000",
      selectedRoot: "C:\\private-root",
    };
    const capability = {
      capabilityHandle: `cmtraceopen.capture-capability.sha256.v1:${"a".repeat(64)}`,
      cardId: request.cardId,
      cardVersion: request.cardVersion,
      sourceId: request.sourceId,
      roleScope: request.roleScope,
      pathClass: request.pathClass,
      sourceVersion: request.expectedSourceVersion,
    };
    const result = {
      bundleRoot: "C:\\bundle",
      capturedAtUtc: "2026-08-04T14:30:00Z",
      roles: [],
      sources: [],
      artifactCount: 0,
      retainedBytes: 0,
    };
    vi.mocked(invoke)
      .mockResolvedValueOnce(capability)
      .mockResolvedValueOnce(result)
      .mockResolvedValueOnce(undefined);

    await expect(authorizeSccmAdvancedCapture(request)).resolves.toBe(
      capability,
    );
    await expect(
      captureSccmAdvancedDiagnostics(capability.capabilityHandle),
    ).resolves.toBe(result);
    await expect(
      cancelSccmAdvancedCapture(capability.capabilityHandle),
    ).resolves.toBeUndefined();

    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "authorize_sccm_advanced_capture",
      {
        request,
      },
    );
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "capture_sccm_advanced_diagnostics",
      { capabilityHandle: capability.capabilityHandle },
    );
    expect(invoke).toHaveBeenNthCalledWith(3, "cancel_sccm_advanced_capture", {
      capabilityHandle: capability.capabilityHandle,
    });
    expect(invoke).not.toHaveBeenCalledWith(
      "capture_sccm_advanced_diagnostics",
      expect.objectContaining({ selectedRoot: expect.anything() }),
    );
  });
});

describe("Graph permission upgrade IPC boundary", () => {
  it("invokes the zero-argument native permission upgrade command", async () => {
    const result = {
      outcome: "upgraded",
      status: validGraphStatus(),
      message: null,
    };
    vi.mocked(invoke).mockResolvedValueOnce(result);

    await expect(
      graphRequestMissingPermissions("permission-request-1"),
    ).resolves.toBe(result);

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "graph_request_missing_permissions",
      { attemptId: "permission-request-1" },
    );
  });
});

describe("Graph authentication IPC boundary", () => {
  it("accepts only native-issued UUID-shaped operation tickets", async () => {
    const ticket = {
      attemptId: "22d12752-4b6e-45e0-aac4-0bc351e91118",
    };
    vi.mocked(invoke).mockResolvedValueOnce(ticket).mockResolvedValueOnce({
      attemptId: "frontend-controlled",
    });

    await expect(
      graphReserveInteractiveOperation("authentication"),
    ).resolves.toBe(ticket);
    await expect(
      graphReserveInteractiveOperation("permissionConsent"),
    ).rejects.toThrow(
      "Command 'graph_reserve_interactive_operation' returned an invalid response.",
    );

    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "graph_reserve_interactive_operation",
      { kind: "authentication" },
    );
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "graph_reserve_interactive_operation",
      { kind: "permissionConsent" },
    );
  });

  it("passes request ownership through authenticate and cancellation", async () => {
    const result = {
      outcome: "cancelled",
      status: validGraphStatus(),
      capability: { kind: "available" },
      message: "Microsoft Graph sign-in was cancelled.",
    };
    vi.mocked(invoke).mockResolvedValueOnce(result).mockResolvedValueOnce(true);

    await expect(graphAuthenticate("auth-request-1")).resolves.toBe(result);
    await expect(graphCancelAuthentication("auth-request-1")).resolves.toBe(
      true,
    );

    expect(invoke).toHaveBeenNthCalledWith(1, "graph_authenticate", {
      attemptId: "auth-request-1",
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "graph_cancel_authentication", {
      attemptId: "auth-request-1",
    });
  });

  it.each([
    ["graph_authenticate", () => graphAuthenticate("auth-request-1"), null],
    [
      "graph_authenticate",
      () => graphAuthenticate("auth-request-1"),
      {
        outcome: "connected",
        status: { ...validGraphStatus(), capabilities: {} },
        capability: { kind: "available" },
        message: null,
      },
    ],
    [
      "graph_authenticate",
      () => graphAuthenticate("auth-request-1"),
      {
        outcome: "other",
        status: validGraphStatus(),
        capability: { kind: "available" },
        message: null,
      },
    ],
    [
      "graph_cancel_authentication",
      () => graphCancelAuthentication("auth-request-1"),
      "true",
    ],
    [
      "graph_request_missing_permissions",
      () => graphRequestMissingPermissions("permission-request-1"),
      {
        outcome: "other",
        status: validGraphStatus(),
        message: null,
      },
    ],
  ] as const)(
    "rejects malformed %s responses",
    async (commandName, call, malformedResponse) => {
      vi.mocked(invoke).mockResolvedValueOnce(malformedResponse);

      await expect(call()).rejects.toThrow(
        `Command '${commandName}' returned an invalid response.`,
      );
    },
  );
});

describe("command rejection sanitization", () => {
  it("contains a hostile Error Proxy rejected by a Graph command", async () => {
    const { rejection, getPrototypeOfReads } = makeHostileErrorProxy("graph");
    vi.mocked(invoke).mockRejectedValueOnce(rejection);

    const error = await captureRejection(graphGetAuthStatus());

    expectFreshCommandFallback(
      error,
      rejection,
      "Command 'graph_get_auth_status' failed.",
    );
    // A single prototype probe classifies the object; the throwing getPrototypeOf
    // trap is contained, no getter runs, and no secret escapes.
    expect(getPrototypeOfReads()).toBe(1);
    expect((error as Error).message).not.toContain("secret");
  });

  it("contains a hostile Error Proxy rejected by a non-Graph command", async () => {
    const { rejection, getPrototypeOfReads } =
      makeHostileErrorProxy("open-log");
    vi.mocked(invoke).mockRejectedValueOnce(rejection);

    const error = await captureRejection(openLogFile("C:\\Logs\\ime.log"));

    expectFreshCommandFallback(
      error,
      rejection,
      "Command 'open_log_file' failed.",
    );
    expect(getPrototypeOfReads()).toBe(1);
    expect((error as Error).message).not.toContain("secret");
  });

  it("does not surface a Proxy-forged descriptor value", async () => {
    let descriptorTrapReads = 0;
    let descriptorValueReads = 0;
    const maliciousDescriptor = {
      configurable: true,
      enumerable: true,
      writable: true,
    } as PropertyDescriptor;
    Object.defineProperty(maliciousDescriptor, "value", {
      enumerable: true,
      get() {
        descriptorValueReads += 1;
        return "descriptor-value-secret";
      },
    });
    const rejection = new Proxy(
      {},
      {
        getOwnPropertyDescriptor(_target, property) {
          descriptorTrapReads += 1;
          return property === "message" ? maliciousDescriptor : undefined;
        },
      },
    );
    vi.mocked(invoke).mockRejectedValueOnce(rejection);

    const error = await captureRejection(openLogFile("C:\\Logs\\ime.log"));

    expectFreshCommandFallback(
      error,
      rejection,
      "Command 'open_log_file' failed.",
    );
    // The plain-prototype Proxy is inspected, but the fabricated data descriptor
    // is rejected because a direct read of the same property disagrees — the
    // forged secret is never surfaced.
    expect((error as Error).message).not.toContain("secret");
    expect(descriptorTrapReads).toBeGreaterThan(0);
    expect(descriptorValueReads).toBeLessThanOrEqual(1);
  });

  it("contains a throwing getOwnPropertyDescriptor trap", () => {
    let descriptorTrapReads = 0;
    const rejection = new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          descriptorTrapReads += 1;
          throw new Error("descriptor-trap-secret");
        },
      },
    );

    expect(() => getSafeErrorMessage(rejection, "safe fallback")).not.toThrow();
    expect(getSafeErrorMessage(rejection, "safe fallback")).toBe(
      "safe fallback",
    );
    // The throwing descriptor trap is contained and the safe fallback wins.
    expect(descriptorTrapReads).toBeGreaterThan(0);
  });
});

describe("getSafeErrorMessage", () => {
  it("preserves a trusted normalized message across repeated reads and message mutation", async () => {
    vi.mocked(invoke).mockRejectedValueOnce("  safe transport failure  ");

    const error = await captureRejection(graphGetAuthStatus());

    expect(error).toBeInstanceOf(Error);
    expect(getSafeErrorMessage(error, "safe fallback")).toBe(
      "safe transport failure",
    );
    expect(getSafeErrorMessage(error, "safe fallback")).toBe(
      "safe transport failure",
    );

    (error as Error).message = "mutated-message-secret";

    expect(getSafeErrorMessage(error, "safe fallback")).toBe(
      "safe transport failure",
    );
    expect(getSafeErrorMessage(error, "safe fallback")).not.toContain(
      "mutated-message-secret",
    );
  });

  it.each([
    ["ordinary Error", new Error("ordinary-error-secret")],
    ["non-string message", { message: { secret: "nested-secret" } }],
    ["function", function rejectedFunction() {}],
  ])("falls back without consuming a %s rejection", (_label, rejection) => {
    expect(getSafeErrorMessage(rejection, "safe fallback")).toBe(
      "safe fallback",
    );
  });

  it("does not invoke an object message accessor", () => {
    let messageReads = 0;
    const rejection = {};
    Object.defineProperty(rejection, "message", {
      get() {
        messageReads += 1;
        return "accessor-secret";
      },
    });

    expect(getSafeErrorMessage(rejection, "safe fallback")).toBe(
      "safe fallback",
    );
    expect(messageReads).toBe(0);
  });

  it("falls back for an arbitrary hostile Proxy, containing its prototype trap", () => {
    let trapReads = 0;
    const rejection = new Proxy(new Error("proxy-message-secret"), {
      get() {
        trapReads += 1;
        throw new Error("get-trap-secret");
      },
      getOwnPropertyDescriptor() {
        trapReads += 1;
        throw new Error("descriptor-trap-secret");
      },
      getPrototypeOf() {
        trapReads += 1;
        throw new Error("prototype-trap-secret");
      },
      ownKeys() {
        trapReads += 1;
        throw new Error("own-keys-trap-secret");
      },
    });

    expect(getSafeErrorMessage(rejection, "safe fallback")).toBe(
      "safe fallback",
    );
    // Only the prototype probe runs, and its throw is contained: the value,
    // descriptor, and own-keys traps are never reached.
    expect(trapReads).toBe(1);
  });

  it("does not trust a hostile Proxy that wraps a trusted normalized Error", async () => {
    vi.mocked(invoke).mockRejectedValueOnce("trusted transport failure");
    const trustedError = await captureRejection(graphGetAuthStatus());
    expect(trustedError).toBeInstanceOf(Error);

    let trapReads = 0;
    const wrapped = new Proxy(trustedError as Error, {
      get() {
        trapReads += 1;
        throw new Error("get-trap-secret");
      },
      getOwnPropertyDescriptor() {
        trapReads += 1;
        throw new Error("descriptor-trap-secret");
      },
      getPrototypeOf() {
        trapReads += 1;
        throw new Error("prototype-trap-secret");
      },
      ownKeys() {
        trapReads += 1;
        throw new Error("own-keys-trap-secret");
      },
    });

    expect(getSafeErrorMessage(wrapped, "safe fallback")).toBe("safe fallback");
    // The wrapped trusted Error is not reachable by identity through the Proxy,
    // so its message is not trusted; only the contained prototype probe runs.
    expect(trapReads).toBe(1);
  });

  it("preserves trimmed primitive strings only", () => {
    expect(getSafeErrorMessage("  safe transport failure  ")).toBe(
      "safe transport failure",
    );
    expect(getSafeErrorMessage("   ", "safe fallback")).toBe("safe fallback");

    for (const rejection of [
      42,
      true,
      1n,
      Symbol("symbol-secret"),
      null,
      undefined,
    ]) {
      expect(getSafeErrorMessage(rejection, "safe fallback")).toBe(
        "safe fallback",
      );
    }
  });

  it("surfaces the message from a plain-data-object rejection", () => {
    expect(
      getSafeErrorMessage(
        {
          kind: "sourceNotFound",
          path: "C:\\bundle",
          message: "manifest missing",
        },
        "safe fallback",
      ),
    ).toBe("manifest missing");
  });

  it("derives a readable message from `kind` when no message is present", () => {
    expect(
      getSafeErrorMessage({ kind: "sourceNotFound" }, "safe fallback"),
    ).toBe("Source not found");
  });

  it("falls back when a plain object's message is a throwing getter", () => {
    let messageReads = 0;
    const rejection = {} as Record<string, unknown>;
    Object.defineProperty(rejection, "message", {
      enumerable: true,
      get() {
        messageReads += 1;
        throw new Error("message-getter-secret");
      },
    });

    // The accessor `message` is ignored — never invoked — so the safe fallback
    // wins and no getter runs.
    expect(getSafeErrorMessage(rejection, "safe fallback")).toBe(
      "safe fallback",
    );
    expect(messageReads).toBe(0);
  });

  it("falls back for a class instance even when it carries a message", () => {
    class BackendFailure {
      message = "class-instance-secret";
    }

    expect(getSafeErrorMessage(new BackendFailure(), "safe fallback")).toBe(
      "safe fallback",
    );
  });
});

describe("Access Denied classification", () => {
  const invokeMock = vi.mocked(invoke);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  /** The wire shape produced by `AppError::AccessDenied` in src-tauri/src/error.rs. */
  function accessDeniedPayload(overrides: Record<string, unknown> = {}) {
    return {
      kind: "accessDenied",
      operation: "readFile",
      path: "C:\\Windows\\Logs\\CBS.log",
      message: "Access to this file was denied by Windows.",
      ...overrides,
    };
  }

  it("records a well-formed verdict on the normalized error", async () => {
    invokeMock.mockRejectedValue(accessDeniedPayload());

    const error = await captureRejection(
      openLogFile("C:\\Windows\\Logs\\CBS.log"),
    );

    expect(readAccessDenied(error)).toEqual({
      kind: "accessDenied",
      operation: "readFile",
      path: "C:\\Windows\\Logs\\CBS.log",
      message: "Access to this file was denied by Windows.",
    });
  });

  it("keeps the displayed message identical to the payload message", async () => {
    // Existing consumers do `error.message`; the structured payload must not
    // change what they render.
    invokeMock.mockRejectedValue(accessDeniedPayload());

    const error = await captureRejection(openLogFile("x.log"));

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe(
      "Access to this file was denied by Windows.",
    );
  });

  it("records nothing for any other structured error", async () => {
    invokeMock.mockRejectedValue({
      kind: "sourceNotFound",
      message: "captured evidence source was not found",
    });

    const error = await captureRejection(openLogFile("gone.log"));

    expect(readAccessDenied(error)).toBeNull();
  });

  it("records nothing for a plain string rejection", async () => {
    invokeMock.mockRejectedValue("Access is denied. (os error 5)");

    const error = await captureRejection(openLogFile("x.log"));

    // Text that merely says "access is denied" is not a verdict.
    expect(readAccessDenied(error)).toBeNull();
  });

  it("rejects a payload whose operation is not in the allowlist", async () => {
    invokeMock.mockRejectedValue(
      accessDeniedPayload({ operation: "deleteEverything" }),
    );

    const error = await captureRejection(openLogFile("x.log"));

    expect(readAccessDenied(error)).toBeNull();
  });

  it("rejects a partially-formed payload rather than half-trusting it", async () => {
    invokeMock.mockRejectedValue(accessDeniedPayload({ message: undefined }));

    const error = await captureRejection(openLogFile("x.log"));

    expect(readAccessDenied(error)).toBeNull();
  });

  it("accepts a verdict with no path context", async () => {
    invokeMock.mockRejectedValue(accessDeniedPayload({ path: null }));

    const error = await captureRejection(openLogFile("x.log"));

    expect(readAccessDenied(error)?.path).toBeNull();
  });

  it("cannot be forged by a hostile Proxy", async () => {
    let getterCalls = 0;
    const rejection = new Proxy(
      {},
      {
        getPrototypeOf: () => Object.prototype,
        getOwnPropertyDescriptor: (_target, key) => {
          getterCalls += 1;
          const forged = accessDeniedPayload() as Record<string, unknown>;
          return {
            configurable: true,
            enumerable: true,
            writable: true,
            value: forged[key as string],
          };
        },
        get: () => undefined,
      },
    );
    invokeMock.mockRejectedValue(rejection);

    const error = await captureRejection(openLogFile("x.log"));

    // The descriptor value and the direct read disagree, so the forged fields
    // are discarded and no elevation offer can be manufactured.
    expect(readAccessDenied(error)).toBeNull();
    expect(getterCalls).toBeGreaterThan(0);
  });
});

describe("event-log manifest commands", () => {
  const invokeMock = vi.mocked(invoke);
  it("keeps expansion and parse commands on the event-log wire contract", async () => {
    const manifest = {
      entries: [
        {
          sourceId: "/logs/application.evtx",
          path: "/logs/Application.evtx",
          kind: "file" as const,
        },
      ],
      coverage: [],
    };
    const result = {
      records: [],
      channels: [],
      totalRecords: 0,
      parseErrors: 0,
      errorMessages: [],
    };
    invokeMock.mockResolvedValueOnce(manifest).mockResolvedValueOnce(result);

    const sources = [{ path: "/logs", kind: "file" as const }];
    await expect(expandEventLogSources(sources)).resolves.toEqual(manifest);
    await expect(parseEventLogManifest(manifest)).resolves.toEqual(result);
    expect(invokeMock).toHaveBeenNthCalledWith(1, "evtx_expand_sources", {
      sources,
    });
    expect(invokeMock).toHaveBeenNthCalledWith(2, "evtx_parse_manifest", {
      manifest,
    });
  });

  const validEventRecord = {
    id: 1,
    eventRecordId: 42,
    timestamp: "2026-08-18T12:00:00Z",
    timestampEpoch: 1_755_523_200_000,
    provider: "Provider",
    channel: "Application",
    eventId: 75,
    level: "Information",
    computer: "WIN-TEST",
    message: "Enrollment failed",
    eventData: [],
    rawXml: "",
    sourceLabel: "Application.evtx",
  };

  it.each([
    ["absent", {}],
    ["null", { eventRecordIdText: null }],
    ["string", { eventRecordIdText: "42" }],
  ] as const)("accepts %s eventRecordIdText values", async (_label, identity) => {
    const result = {
      records: [{ ...validEventRecord, ...identity }],
      channels: [
        { name: "Application", eventCount: 1, sourceType: "live" },
      ],
      totalRecords: 1,
      parseErrors: 0,
      errorMessages: [],
    };
    vi.mocked(invoke).mockResolvedValueOnce(result);

    await expect(parseEventLogManifest({ entries: [], coverage: [] })).resolves.toEqual(
      result,
    );
  });

  it.each([[42], [true], [[]], [{ value: "42" }]])(
    "rejects malformed eventRecordIdText type %s",
    async (eventRecordIdText) => {
      vi.mocked(invoke).mockResolvedValueOnce({
        records: [{ ...validEventRecord, eventRecordIdText }],
        channels: [
          { name: "Application", eventCount: 1, sourceType: "live" },
        ],
        totalRecords: 1,
        parseErrors: 0,
        errorMessages: [],
      });

      await expect(
        parseEventLogManifest({ entries: [], coverage: [] }),
      ).rejects.toThrow(
        "Command 'evtx_parse_manifest' returned an invalid response.",
      );
    },
  );

  it.each([
    [null, "the event log reader returned an invalid source manifest"],
    [
      {
        entries: [
          { sourceId: "source", path: "Application.evtx", kind: "unknown" },
        ],
        coverage: [],
      },
      "the event log reader returned an invalid source manifest entry at index 0",
    ],
    [
      {
        entries: [],
        coverage: [
          { kind: "unknown", path: "Application.evtx", reason: "bad coverage" },
        ],
      },
      "the event log reader returned an invalid source manifest coverage at index 0",
    ],
  ] as const)(
    "rejects malformed expansion manifests at the command boundary (%s)",
    async (reply, message) => {
      vi.mocked(invoke).mockResolvedValueOnce(reply);

      await expect(
        expandEventLogSources([{ path: "/logs", kind: "file" }]),
      ).rejects.toThrow(message);
    },
  );
});

type DiagnosisSummaryFixture = {
  findings: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  coverageGaps: Array<Record<string, unknown>>;
  correlations: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
  overview: Record<string, unknown>;
};

function makeValidDiagnosisSummary(): DiagnosisSummaryFixture {
  const coverageGap = {
    id: "gap-1",
    source: "Application.evtx",
    state: "unknown",
    detail: "The source was not available.",
    evidence: [{ kind: "dsregcmdRaw", value: "gap evidence" }],
  };
  return {
    findings: [
      {
        findingId: "finding-1",
        class: "confirmedFailure",
        severity: "error",
        confidence: "high",
        title: "Enrollment failed",
        summary: "The event reports a failed enrollment.",
        evidence: [{ kind: "dsregcmdRaw", value: "provider evidence" }],
        coverageGaps: [coverageGap],
        recommendedChecks: ["Check the source file."],
      },
    ],
    evidence: [
      { kind: "dsregcmdRaw", value: "summary evidence" },
      { kind: "dsregcmdRaw", value: "provider evidence" },
    ],
    coverageGaps: [coverageGap],
    correlations: [
      {
        left: "event-1",
        right: "event-2",
        basis: "candidateIdentifier",
        status: "candidate",
        candidateIds: ["event-2"],
        evidence: [
          { originId: "event-1", field: "provider", value: "Provider" },
        ],
      },
    ],
    events: [
      {
        evidence: [{ kind: "dsregcmdRaw", value: "event evidence" }],
        family: "mdmEnrollment",
        findings: [],
        errorTokens: [
          {
            raw: "0x80070005",
            decimal: null,
            hex: "0x80070005",
            malformed: false,
            found: true,
            description: "Access denied",
            category: "hresult",
          },
        ],
      },
    ],
    overview: {
      outcome: "confirmedFailure",
      headline: "Evidence contains confirmed operational failure(s).",
      findingCount: 1,
      coverageGapCount: 1,
      evidenceCount: 2,
      correlationCount: 1,
    },
  };
}

function withDiagnosisRecordChange(
  summary: DiagnosisSummaryFixture,
  key: "coverageGaps" | "correlations",
  change: Record<string, unknown>,
): DiagnosisSummaryFixture {
  if (key === "coverageGaps") {
    return {
      ...summary,
      coverageGaps: [{ ...summary.coverageGaps[0], ...change }],
    };
  }
  return {
    ...summary,
    correlations: [{ ...summary.correlations[0], ...change }],
  };
}

function withDiagnosisFindingChange(
  summary: DiagnosisSummaryFixture,
  change: Record<string, unknown>,
): DiagnosisSummaryFixture {
  return { ...summary, findings: [{ ...summary.findings[0], ...change }] };
}

function withDiagnosisTokenChange(
  summary: DiagnosisSummaryFixture,
  change: Record<string, unknown>,
): DiagnosisSummaryFixture {
  const event = summary.events[0];
  const token = (event.errorTokens as Array<Record<string, unknown>>)[0];
  return {
    ...summary,
    events: [{ ...event, errorTokens: [{ ...token, ...change }] }],
  };
}
const malformedDiagnosisCases: Array<
  [string, (summary: DiagnosisSummaryFixture) => DiagnosisSummaryFixture]
> = [
  [
    "coverage gap state",
    (summary) =>
      withDiagnosisRecordChange(summary, "coverageGaps", { state: "invalid" }),
  ],
  [
    "coverage gap evidence",
    (summary) =>
      withDiagnosisRecordChange(summary, "coverageGaps", { evidence: [{}] }),
  ],
  [
    "correlation basis",
    (summary) =>
      withDiagnosisRecordChange(summary, "correlations", { basis: "invalid" }),
  ],
  [
    "correlation status",
    (summary) =>
      withDiagnosisRecordChange(summary, "correlations", { status: "invalid" }),
  ],
  [
    "correlation candidate",
    (summary) =>
      withDiagnosisRecordChange(summary, "correlations", {
        candidateIds: [42],
      }),
  ],
  [
    "correlation evidence",
    (summary) =>
      withDiagnosisRecordChange(summary, "correlations", { evidence: [{}] }),
  ],
  [
    "error token raw",
    (summary) => withDiagnosisTokenChange(summary, { raw: "" }),
  ],
  [
    "error token decimal fraction",
    (summary) => withDiagnosisTokenChange(summary, { decimal: 1.5 }),
  ],
  [
    "error token decimal unsafe integer",
    (summary) =>
      withDiagnosisTokenChange(summary, {
        decimal: Number.MAX_SAFE_INTEGER + 2,
      }),
  ],
  [
    "error token malformed",
    (summary) => withDiagnosisTokenChange(summary, { malformed: "false" }),
  ],
  [
    "error token found",
    (summary) => withDiagnosisTokenChange(summary, { found: "true" }),
  ],
  [
    "finding coverage gaps",
    (summary) => withDiagnosisFindingChange(summary, { coverageGaps: [{}] }),
  ],
  [
    "finding recommended checks",
    (summary) =>
      withDiagnosisFindingChange(summary, { recommendedChecks: [42] }),
  ],
];

describe("event-log diagnosis IPC boundary", () => {
  it.each(malformedDiagnosisCases)(
    "rejects malformed diagnosis summary %s",
    async (_caseName, mutateSummary) => {
      vi.mocked(invoke).mockResolvedValueOnce(
        mutateSummary(makeValidDiagnosisSummary()),
      );

      await expect(diagnoseEventRecords([])).rejects.toThrow(
        "Command 'evtx_diagnose_records' returned an invalid response.",
      );
      expect(invoke).toHaveBeenCalledWith("evtx_diagnose_records", {
        records: [],
        coverageGaps: [],
        timeline: null,
        textEntries: [],
      });
    },
  );
  it("rejects unsafe numeric event identity that conflicts with recordIdText", async () => {
    const summary = makeValidDiagnosisSummary();
    summary.evidence = [
      ...summary.evidence,
      {
        kind: "event",
        value: {
          source: "Application.evtx",
          provider: "Provider",
          eventId: 75,
          recordId: Number("9007199254740992"),
          recordIdText: "0",
          fallbackIdentity: "fallback",
        },
      },
    ];
    summary.overview.evidenceCount = summary.evidence.length;
    vi.mocked(invoke).mockResolvedValueOnce(summary);

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });
  it("rejects unsafe numeric event identity paired with a safe-range text id", async () => {
    const summary = makeValidDiagnosisSummary();
    summary.evidence = [
      ...summary.evidence,
      {
        kind: "event",
        value: {
          source: "Application.evtx",
          provider: "Provider",
          eventId: 75,
          recordId: Number("9007199254740992"),
          recordIdText: "42",
          fallbackIdentity: "fallback",
        },
      },
    ];
    summary.overview.evidenceCount = summary.evidence.length;
    vi.mocked(invoke).mockResolvedValueOnce(summary);

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });

  it("accepts unsafe numeric event identity when lossless text is present", async () => {
    const summary = makeValidDiagnosisSummary();
    summary.evidence = [
      ...summary.evidence,
      {
        kind: "event",
        value: {
          source: "Application.evtx",
          provider: "Provider",
          eventId: 75,
          recordId: Number("9007199254740992"),
          recordIdText: "9007199254740993",
          fallbackIdentity: null,
        },
      },
    ];
    summary.overview.evidenceCount = summary.evidence.length;
    vi.mocked(invoke).mockResolvedValueOnce(summary);

    await expect(diagnoseEventRecords([])).resolves.toBe(summary);
  });
  it("rejects an unsafe numeric event identity with mismatched lossless text", async () => {
    const summary = makeValidDiagnosisSummary();
    summary.evidence = [
      ...summary.evidence,
      {
        kind: "event",
        value: {
          source: "Application.evtx",
          provider: "Provider",
          eventId: 75,
          recordId: Number("9007199254740994"),
          recordIdText: "9007199254740993",
          fallbackIdentity: null,
        },
      },
    ];
    summary.overview.evidenceCount = summary.evidence.length;
    vi.mocked(invoke).mockResolvedValueOnce(summary);

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });


  it("rejects diagnosis overview counts that disagree with the summary arrays", async () => {
    const summary = makeValidDiagnosisSummary();
    summary.overview.findingCount = 99;
    vi.mocked(invoke).mockResolvedValueOnce(summary);

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });
  it("rejects a malformed backend response instead of exposing it as a diagnosis", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      findings: [],
      evidence: [],
      coverageGaps: [],
      correlations: [],
    });

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });

  it("rejects event diagnostics without source evidence", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      findings: [],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [
        {
          evidence: [],
          family: "mdmEnrollment",
          findings: [],
          errorTokens: [],
        },
      ],
    });

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });
  it("rejects nested evidence references that omit required event identity", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      findings: [
        {
          findingId: "finding-1",
          class: "confirmedFailure",
          severity: "error",
          confidence: "high",
          title: "Enrollment failed",
          summary: "The event reports a failed enrollment.",
          evidence: [
            {
              kind: "event",
              value: {
                source: "Application.evtx",
                provider: "Provider",
                eventId: 75,
              },
            },
          ],
          coverageGaps: [],
          recommendedChecks: [],
        },
      ],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [],
    });

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });

  it("accepts valid findings whose source message is empty", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      findings: [
        {
          findingId: "finding-empty-summary",
          class: "confirmedFailure",
          severity: "error",
          confidence: "medium",
          title: "Event reports a failure",
          summary: "",
          evidence: [{ kind: "dsregcmdRaw", value: "provider evidence" }],
          coverageGaps: [],
          recommendedChecks: [],
        },
      ],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [],
      overview: {
        outcome: "confirmedFailure",
        headline: "Failure evidence is available.",
        findingCount: 1,
        coverageGapCount: 0,
        evidenceCount: 0,
        correlationCount: 0,
      },
    });

    await expect(diagnoseEventRecords([])).resolves.toMatchObject({
      findings: [{ findingId: "finding-empty-summary", summary: "" }],
    });
  });

  it("rejects actionable findings without evidence or coverage", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      findings: [
        {
          findingId: "uncited-finding",
          class: "confirmedFailure",
          severity: "error",
          confidence: "high",
          title: "Uncited failure",
          summary: "No source was supplied.",
          evidence: [],
          coverageGaps: [],
          recommendedChecks: [],
        },
      ],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [],
    });

    await expect(diagnoseEventRecords([])).rejects.toThrow(
      "Command 'evtx_diagnose_records' returned an invalid response.",
    );
  });

  it("transports unsafe EventRecordID values through their lossless decimal text", async () => {
    const exactId = "9007199254740993";
    const record: EvtxRecord = {
      id: 1,
      eventRecordId: Number(exactId),
      eventRecordIdText: exactId,
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Provider",
      channel: "Application",
      eventId: 75,
      level: "Information",
      computer: "WIN-TEST",
      message: "Enrollment failed",
      eventData: [],
      rawXml: "",
      sourceLabel: "Application.evtx",
      originKind: "event",
    };
    vi.mocked(invoke).mockResolvedValueOnce({
      findings: [],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [],
      overview: {
        outcome: "noFindings",
        headline: "No operational findings were identified.",
        findingCount: 0,
        coverageGapCount: 0,
        evidenceCount: 0,
        correlationCount: 0,
      },
    });

    await expect(diagnoseEventRecords([record])).resolves.toEqual({
      findings: [],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [],
      overview: {
        outcome: "noFindings",
        headline: "No operational findings were identified.",
        findingCount: 0,
        coverageGapCount: 0,
        evidenceCount: 0,
        correlationCount: 0,
      },
    });
    expect(invoke).toHaveBeenCalledWith("evtx_diagnose_records", {
      records: [
        {
          ...record,
          eventRecordId: Number.MAX_SAFE_INTEGER + 1,
        },
      ],
      coverageGaps: [],
      timeline: null,
      textEntries: [],
    });
  });
  it("uses bounded numeric transport when decimal text exceeds u64", async () => {
    const record: EvtxRecord = {
      id: 1,
      eventRecordId: Number("18446744073709551616"),
      eventRecordIdText: "18446744073709551616",
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Provider",
      channel: "Application",
      eventId: 75,
      level: "Information",
      computer: "WIN-TEST",
      message: "Enrollment failed",
      eventData: [],
      rawXml: "",
      sourceLabel: "Application.evtx",
      originKind: "event",
    };
    vi.mocked(invoke).mockResolvedValueOnce({
      findings: [],
      evidence: [],
      coverageGaps: [],
      correlations: [],
      events: [],
      overview: {
        outcome: "noFindings",
        headline: "No operational findings were identified.",
        findingCount: 0,
        coverageGapCount: 0,
        evidenceCount: 0,
        correlationCount: 0,
      },
    });

    await expect(diagnoseEventRecords([record])).resolves.toMatchObject({
      findings: [],
    });
    expect(invoke).toHaveBeenCalledWith("evtx_diagnose_records", {
      records: [
        {
          ...record,
          eventRecordId: Number.MAX_SAFE_INTEGER + 1,
        },
      ],
      coverageGaps: [],
      timeline: null,
      textEntries: [],
    });
  });

  it("rejects an unsafe EventRecordID paired with a safe-range transport text id", async () => {
    const record: EvtxRecord = {
      id: 1,
      eventRecordId: Number("9007199254740992"),
      eventRecordIdText: "42",
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Provider",
      channel: "Application",
      eventId: 75,
      level: "Information",
      computer: "WIN-TEST",
      message: "Enrollment failed",
      eventData: [],
      rawXml: "",
      sourceLabel: "Application.evtx",
      originKind: "event",
    };

    await expect(diagnoseEventRecords([record])).rejects.toThrow(
      "EventRecordID text must preserve an unsafe numeric identity.",
    );
    expect(invoke).not.toHaveBeenCalled();
  });
  it("keeps malformed record identities in the diagnosis batch for backend coverage", async () => {
    const record: EvtxRecord = {
      id: 1,
      eventRecordId: 42,
      eventRecordIdText: "not-decimal",
      timestamp: "2026-08-18T12:00:00Z",
      timestampEpoch: 1_755_523_200_000,
      provider: "Provider",
      channel: "Application",
      eventId: 75,
      level: "Information",
      computer: "WIN-TEST",
      message: "Enrollment failed",
      eventData: [],
      rawXml: "",
      sourceLabel: "Application.evtx",
      originKind: "event",
    };
    const summary = makeValidDiagnosisSummary();
    vi.mocked(invoke).mockResolvedValueOnce(summary);

    await expect(diagnoseEventRecords([record])).resolves.toBe(summary);
    expect(invoke).toHaveBeenCalledWith("evtx_diagnose_records", {
      records: [{ ...record, eventRecordId: 42 }],
      coverageGaps: [],
      timeline: null,
      textEntries: [],
    });
  });
});
