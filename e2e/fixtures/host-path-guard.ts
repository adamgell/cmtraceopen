import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Page } from "@playwright/test";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");

/** Host-identifying strings that must never appear in a committed screenshot. */
export function hostIdentifiers(): string[] {
  const found = [os.homedir(), process.cwd(), REPO_ROOT];
  const user = os.userInfo().username;
  if (user.length > 2) found.push(user);
  return [...new Set(found.filter((value) => value.length > 0))];
}

/** Returns the host identifiers present in `text`, case-insensitively. */
export function findHostLeaks(text: string, identifiers = hostIdentifiers()) {
  const haystack = text.toLowerCase();
  return identifiers.filter((id) => haystack.includes(id.toLowerCase()));
}

/**
 * Throws when the page's visible text contains the home directory, OS user
 * name, working directory or repo root. Call before every committed screenshot:
 * a capture that shows a host path leaks the local user name to a public repo.
 */
export async function assertNoHostPaths(
  page: Page,
  what = "screenshot",
): Promise<void> {
  const text = await page.evaluate(() => document.body.innerText);
  const leaks = findHostLeaks(text);
  if (leaks.length > 0) {
    const line =
      text.split("\n").find((l) => findHostLeaks(l).length > 0) ?? "";
    const redacted = line.replaceAll(
      new RegExp(
        leaks.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"),
        "gi",
      ),
      "<host>",
    );
    throw new Error(
      `Refusing to capture ${what}: page text contains a host path or user name (${leaks.length} identifier(s)). Offending line: ${redacted.trim().slice(0, 200)}`,
    );
  }
}
