import { afterEach, describe, expect, it, vi } from "vitest";
import { createUuidRequestId } from "./uuid-request-id";

const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("createUuidRequestId", () => {
  it("uses the platform UUID generator when available", () => {
    const requestId = "11111111-2222-4333-8444-555555555555";
    const randomUUID = vi.fn(() => requestId);
    vi.stubGlobal("crypto", { randomUUID });

    expect(createUuidRequestId()).toBe(requestId);
    expect(randomUUID).toHaveBeenCalledOnce();
  });

  it("formats getRandomValues bytes as an RFC 4122 version 4 UUID", () => {
    const getRandomValues = vi.fn((bytes: Uint8Array) => {
      bytes.set(Array.from({ length: 16 }, (_, index) => index));
      return bytes;
    });
    vi.stubGlobal("crypto", { getRandomValues });

    expect(createUuidRequestId()).toBe("00010203-0405-4607-8809-0a0b0c0d0e0f");
    expect(getRandomValues).toHaveBeenCalledOnce();
  });

  it("retains a native-valid UUID shape without Web Crypto", () => {
    vi.stubGlobal("crypto", undefined);
    vi.spyOn(Math, "random").mockReturnValue(0);

    expect(createUuidRequestId()).toMatch(UUID_V4);
  });
});
