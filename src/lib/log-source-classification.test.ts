import { describe, expect, it } from "vitest";
import { classifySourceError } from "./log-source";
import { recordAccessDenied } from "./source-error";

describe("classifySourceError", () => {
  it("reports a structured Access Denied verdict as an error, not a missing source", () => {
    const error = new Error("Access to this file was denied by Windows.");
    recordAccessDenied(error, {
      kind: "accessDenied",
      operation: "readFile",
      path: "C:\\Windows\\Logs\\CBS.log",
      message: "Access to this file was denied by Windows.",
    });

    const verdict = classifySourceError(error);

    expect(verdict.kind).toBe("error");
    expect(verdict.accessDenied).not.toBeNull();
  });

  it.each([
    "The system cannot find the file specified.",
    "no such file or directory",
    "failed to open log: os error 2",
    "os error 3",
  ])("still reports genuine not-found wording as missing: %s", (message) => {
    expect(classifySourceError(new Error(message)).kind).toBe("missing");
  });

  it.each([
    "Access is denied. (os error 5)",
    "permission denied",
    "failed to read directory: os error 5",
  ])(
    "never reports unclassified permission wording as missing: %s",
    (message) => {
      // Without a backend verdict these used to fall into the "missing" bucket,
      // so a protected log the user could see in Explorer was reported as
      // "Source path is missing or inaccessible" and sent them hunting for a
      // file that had not moved.
      const verdict = classifySourceError(new Error(message));

      expect(verdict.kind).toBe("error");
      // No OS verdict, so no elevation offer: the classifier must never infer
      // one from localized message text.
      expect(verdict.accessDenied).toBeNull();
    },
  );

  it("treats an unrecognized failure as a generic error", () => {
    const verdict = classifySourceError(new Error("disk quota exceeded"));

    expect(verdict.kind).toBe("error");
    expect(verdict.accessDenied).toBeNull();
  });
});
