import type { FirewallTimelineError } from "../types/timeline";
const messages = {
  sourceChanged: "Source changed. Rebuild the timeline to continue.",
  generationUnverifiable: "Source generation cannot be verified. Reopen the source on a supported filesystem.",
  readDecodeFailure: "Source could not be read or decoded. Check the file and rebuild the timeline.",
  invalidIndexContext: "The firewall index or field context is invalid. Rebuild the timeline.",
} as const;
export function isFirewallTimelineError(error: unknown): error is FirewallTimelineError {
  if (!error || typeof error !== "object") return false;
  const value = error as Record<string, unknown>;
  return value.kind === "firewallSource" && typeof value.path === "string" &&
    typeof value.sourceIdx === "number" && Number.isInteger(value.sourceIdx) && value.sourceIdx >= 0 && value.sourceIdx <= 65535 &&
    typeof value.reason === "string" && Object.prototype.hasOwnProperty.call(messages, value.reason);
}
export function formatTimelineError(error: unknown): string {
  if (isFirewallTimelineError(error)) return `${error.path}: ${messages[error.reason]}`;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object" && "message" in error && typeof error.message === "string") return error.message;
  return String(error);
}
