import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

/**
 * Every path the QA tracker cites.
 *
 * `\.tsx?` rather than `\.(?:ts|tsx)`: alternation is ordered, so the second
 * form matches the `ts` of a `.tsx` path and reads it as a truncated `.ts` one
 * that does not exist. That mistake produced thirty phantom missing files once
 * already, which is why this file exists.
 */
const CITED_PATH = /(?:src|e2e)\/[\w./-]+\.tsx?/g;

test("every file the QA tracker cites exists", () => {
  const root = process.cwd();
  const tracker = readFileSync(join(root, "docs/qa/user-stories.csv"), "utf8");
  const cited = new Set(tracker.match(CITED_PATH) ?? []);

  assert.ok(
    cited.size > 0,
    "docs/qa/user-stories.csv cites no files, which means the tracker moved or emptied",
  );

  const missing = [...cited].sort().filter((path) => !existsSync(join(root, path)));

  assert.deepEqual(
    missing,
    [],
    `docs/qa/user-stories.csv cites files that do not exist:\n${missing.join("\n")}`,
  );
});
