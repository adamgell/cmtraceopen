import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Page } from "@playwright/test";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");

/**
 * Host-identifying strings that must never appear in a committed screenshot:
 * home directory, OS user name, host name (full and first DNS label), working
 * directory and repo root.
 */
export function hostIdentifiers(): string[] {
  const found = [os.homedir(), process.cwd(), REPO_ROOT];
  const user = os.userInfo().username;
  if (user.length > 2) found.push(user);
  const host = os.hostname();
  if (host.length > 2) found.push(host);
  const shortHost = host.split(".")[0] ?? "";
  if (shortHost.length > 2) found.push(shortHost);
  return [...new Set(found.filter((value) => value.length > 0))];
}

/** Returns the host identifiers present in `text`, case-insensitively. */
export function findHostLeaks(
  text: string,
  identifiers: string[] = hostIdentifiers(),
): string[] {
  const haystack = text.toLowerCase();
  return identifiers.filter((id) => haystack.includes(id.toLowerCase()));
}

/**
 * Builds the failure message for a leak, or returns null when `text` is clean.
 * The offending line is shown with every identifier replaced by `<host>`, so
 * the message itself never repeats the user name or host name.
 */
export function describeHostLeak(
  text: string,
  what: string,
  identifiers: string[] = hostIdentifiers(),
): string | null {
  const leaks = findHostLeaks(text, identifiers);
  if (leaks.length === 0) return null;
  const pattern = new RegExp(
    leaks.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"),
    "gi",
  );
  const line = text.split("\n").find((l) => findHostLeaks(l, identifiers).length > 0) ?? "";
  return `Refusing to capture ${what}: page text contains a host path, user name or host name (${leaks.length} identifier(s)). Offending line: ${line.replace(pattern, "<host>").trim().slice(0, 200)}`;
}

/**
 * Throws when the page's visible text or any input/textarea value contains a
 * host identifier. Call before every committed screenshot: a capture that shows
 * a host path leaks the local user name to a public repo.
 */
export async function assertNoHostPaths(
  page: Page,
  what = "screenshot",
): Promise<void> {
  const text = await page.evaluate(() => {
    const values = Array.from(
      document.querySelectorAll("input, textarea"),
    ).map((el) => (el as HTMLInputElement | HTMLTextAreaElement).value);
    return [document.body.innerText, ...values].join("\n");
  });
  const message = describeHostLeak(text, what);
  if (message) throw new Error(message);
}
