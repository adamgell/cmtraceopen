import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const IDENTITY_DIR = path.join(HERE, ".server-identity");

/**
 * Playwright `globalSetup`: fail fast when the server on :1420 belongs to another checkout.
 *
 * Both Playwright configs set `reuseExistingServer: true`, so a Vite server left running by a
 * different checkout is silently reused and the run tests THAT checkout's code. Identity is proven
 * by content: this run writes a random nonce file inside THIS checkout, then fetches it by a
 * root-relative URL. Every Vite server resolves that URL against its own root, so only this
 * checkout's server can return the nonce. (A `/@fs/<this checkout>/...` probe would not work: the
 * root checkout's server also serves files under its `.worktrees/` directory.) Playwright starts
 * the web server before `globalSetup`, so a free port is already this checkout's fresh server.
 */
export default async function assertOwnDevServer(): Promise<void> {
  const nonce = randomUUID();
  const file = path.join(IDENTITY_DIR, `${nonce}.txt`);
  mkdirSync(IDENTITY_DIR, { recursive: true });
  writeFileSync(file, nonce);
  try {
    const probe = `http://localhost:1420/e2e/.server-identity/${nonce}.txt`;
    let status = "no response";
    let body = "";
    try {
      const response = await fetch(probe);
      status = String(response.status);
      body = await response.text();
    } catch (error) {
      status = `fetch failed: ${(error as Error).message}`;
    }
    if (body !== nonce) {
      throw new Error(
        `The dev server on :1420 is not serving ${path.resolve(HERE, "..")} (GET ${probe} -> ${status}). ` +
          "Another checkout's `npm run frontend:dev` / `app:dev` is running; stop it, then re-run.",
      );
    }
  } finally {
    rmSync(file, { force: true });
  }
}
