import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Playwright `globalSetup`: fail fast when the server on :1420 belongs to another checkout.
 *
 * Both Playwright configs set `reuseExistingServer: true`, so a Vite server left running by a
 * different worktree is silently reused and the run tests THAT checkout's code. Vite only serves
 * `/@fs/` files inside its own workspace root, so asking for this checkout's package.json succeeds
 * only on this checkout's server (a foreign one answers 403).
 */
export default async function assertOwnDevServer(): Promise<void> {
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const probe = `http://localhost:1420/@fs${repo.startsWith("/") ? "" : "/"}${repo.replaceAll("\\", "/")}/package.json?raw`;
  const response = await fetch(probe);
  if (!response.ok) {
    throw new Error(
      `The dev server on :1420 is not serving ${repo} (GET ${probe} -> ${response.status}). ` +
        "Another checkout's `npm run frontend:dev` / `app:dev` is running; stop it, then re-run.",
    );
  }
}
