/**
 * Structured classification of source-operation failures.
 *
 * The elevation offer must never be driven by message text. Windows returns
 * localized strings for "Access is denied", so matching on them would silently
 * stop working on a non-English install and would also fire on unrelated errors
 * that merely mention permissions. The backend classifies from the OS error
 * kind/code and sends a typed payload; this module carries that verdict to the
 * UI without letting anything else in.
 *
 * The classification travels in a WeakMap keyed by the normalized `Error`
 * identity rather than as a property on it. That is the same trusted-channel
 * pattern `commands.ts` already uses for error messages: lookup by object
 * identity cannot invoke a Proxy trap, so a hostile rejection value cannot
 * fabricate an Access Denied verdict and talk the app into offering elevation.
 */

/** Mirrors `SourceOperation` in `src-tauri/src/error.rs`. */
export type SourceOperation =
  | "readFile"
  | "listFolder"
  | "openKnownSource"
  | "workspaceAction";

const SOURCE_OPERATIONS: readonly SourceOperation[] = [
  "readFile",
  "listFolder",
  "openKnownSource",
  "workspaceAction",
];

export interface AccessDeniedClassification {
  kind: "accessDenied";
  operation: SourceOperation;
  /** Bounded context from the backend, or null when none was supplied. */
  path: string | null;
  message: string;
}

const accessDeniedByError = new WeakMap<object, AccessDeniedClassification>();

export function isSourceOperation(value: unknown): value is SourceOperation {
  return (
    typeof value === "string" &&
    SOURCE_OPERATIONS.includes(value as SourceOperation)
  );
}

/**
 * Associates a verdict with a normalized command error.
 *
 * Called only by the command layer, which has already parsed the wire payload
 * with getter-safe reads.
 */
export function recordAccessDenied(
  error: object,
  classification: AccessDeniedClassification,
): void {
  accessDeniedByError.set(error, classification);
}

/**
 * The Access Denied verdict for a rejection, or null.
 *
 * Null for every unclassified failure, which is the safe default: no
 * classification means no elevation offer.
 */
export function readAccessDenied(
  error: unknown,
): AccessDeniedClassification | null {
  if (error === null || typeof error !== "object") return null;
  return accessDeniedByError.get(error) ?? null;
}

/** Whether a rejection was a confirmed operating-system permission refusal. */
export function isAccessDenied(error: unknown): boolean {
  return readAccessDenied(error) !== null;
}
