/**
 * Typed error representation for backend errors.
 *
 * The Rust backend returns `AppError` which is serialized to a string by Tauri.
 * This module provides utilities to parse those error strings into structured
 * objects for programmatic handling in the frontend.
 */

export type AppErrorKind =
  | "io"
  | "parse"
  | "input"
  | "state"
  | "platform"
  | "analysis"
  | "internal"
  | "unknown";

export interface AppError {
  kind: AppErrorKind;
  message: string;
}

const ERROR_PREFIXES: [AppErrorKind, string][] = [
  ["io", "I/O error: "],
  ["parse", "Parse error in "],
  ["input", "Invalid input: "],
  ["state", "State error: "],
  ["platform", "Platform not supported: "],
  ["analysis", "Analysis failed: "],
];

/**
 * Parse a backend error string into a structured AppError.
 *
 * The Rust `AppError` enum uses `thiserror` display strings like:
 * - "I/O error: ..."
 * - "Parse error in {file}: {reason}"
 * - "Invalid input: ..."
 * - "State error: ..."
 * - "Platform not supported: ..."
 * - "Analysis failed: ..."
 */
export function parseBackendError(error: unknown): AppError {
  const message =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : String(error);

  for (const [kind, prefix] of ERROR_PREFIXES) {
    if (message.startsWith(prefix)) {
      return { kind, message: message.slice(prefix.length) };
    }
  }

  return { kind: "unknown", message };
}

/**
 * Get a user-friendly error message from a backend error.
 */
export function getUserFriendlyError(error: unknown): string {
  const parsed = parseBackendError(error);

  switch (parsed.kind) {
    case "io":
      return `File operation failed: ${parsed.message}`;
    case "parse":
      return `Could not parse file: ${parsed.message}`;
    case "input":
      return parsed.message;
    case "platform":
      return `This feature is not available on your platform.`;
    case "analysis":
      return `Analysis failed: ${parsed.message}`;
    case "state":
      return `Internal state error. Please restart the application.`;
    default:
      return parsed.message;
  }
}
