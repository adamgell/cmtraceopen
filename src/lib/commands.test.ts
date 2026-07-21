import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import {
  getSafeErrorMessage,
  graphGetAuthStatus,
  graphRequestMissingPermissions,
  openLogFile,
} from "./commands";

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

describe("Graph permission upgrade IPC boundary", () => {
  it("invokes the zero-argument native permission upgrade command", async () => {
    const result = {
      outcome: "upgraded",
      status: {
        isAuthenticated: true,
        userPrincipalName: "admin@contoso.com",
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
        error: null,
      },
      message: null,
    };
    vi.mocked(invoke).mockResolvedValueOnce(result);

    await expect(graphRequestMissingPermissions()).resolves.toBe(result);

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "graph_request_missing_permissions",
      undefined,
    );
  });
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
        { kind: "sourceNotFound", path: "C:\\bundle", message: "manifest missing" },
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
