import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import {
  captureSccmDiagnostics,
  authorizeSccmAdvancedCapture,
  cancelSccmAdvancedCapture,
  captureSccmAdvancedDiagnostics,
  discoverSccmEnvironment,
  getSafeErrorMessage,
  graphGetAuthStatus,
  graphAuthenticate,
  graphCancelAuthentication,
  graphReserveInteractiveOperation,
  graphRequestMissingPermissions,
  listLogFolder,
  openLogFile,
  parseFilesBatch,
  revealInFileManager,
} from "./commands";
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
      bundleMetadata: null,
    };
    vi.mocked(invoke)
      .mockResolvedValueOnce([parseResult])
      .mockResolvedValueOnce(folderListing);

    await expect(parseFilesBatch(["C:\\Logs\\App.log"], 7)).resolves.toEqual([
      parseResult,
    ]);
    await expect(listLogFolder("C:\\Logs")).resolves.toEqual(folderListing);
  });

  it("rejects malformed parser and folder responses", async () => {
    vi.mocked(invoke)
      .mockResolvedValueOnce([{ filePath: "C:\\Logs\\App.log" }])
      .mockResolvedValueOnce({
        sourceKind: "folder",
        source: { kind: "folder", path: "C:\\Logs" },
        entries: [{ name: "App.log", path: "C:\\Logs\\App.log" }],
      });

    await expect(parseFilesBatch(["C:\\Logs\\App.log"], 7)).rejects.toThrow(
      "invalid response",
    );
    await expect(listLogFolder("C:\\Logs")).rejects.toThrow("invalid response");
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
    const discovery = { supported: true, roles: [], sources: [], issues: [] };
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
    const result = { bundleRoot: "C:\\bundle", sources: [] };
    vi.mocked(invoke)
      .mockResolvedValueOnce(capability)
      .mockResolvedValueOnce(result)
      .mockResolvedValueOnce(undefined);

    await expect(authorizeSccmAdvancedCapture(request)).resolves.toBe(capability);
    await expect(
      captureSccmAdvancedDiagnostics(capability.capabilityHandle),
    ).resolves.toBe(result);
    await expect(
      cancelSccmAdvancedCapture(capability.capabilityHandle),
    ).resolves.toBeUndefined();

    expect(invoke).toHaveBeenNthCalledWith(1, "authorize_sccm_advanced_capture", {
      request,
    });
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
