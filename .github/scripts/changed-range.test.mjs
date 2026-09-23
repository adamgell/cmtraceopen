/**
 * Contract tests for `.github/scripts/changed-range.sh` (#589).
 *
 * The selection rule is executed against a real temporary repository rather than
 * grepped out of the workflow, because the rule is about which base is *usable*.
 * A textual test cannot tell whether a valid root-commit base is being
 * reclassified as missing — and that misclassification is exactly the defect this
 * rule was fixed for: it sent a root-commit base down the empty-tree path, which
 * diffs the empty tree against HEAD and so reports whitespace in every file the
 * repository has ever contained.
 *
 * Each case asserts the **resulting path set**, not only the printed range.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptPath = fileURLToPath(new URL("./changed-range.sh", import.meta.url));

/**
 * The shell to run the rule under. On Windows the `bash` on PATH is often the WSL
 * shim, which cannot see a `D:\` or `E:\` working directory, so Git Bash is named
 * explicitly. Missing bash is a hard failure rather than a skip: this file is run
 * by the CI workflow on ubuntu-latest, where bash is always present, and a silently
 * skipped contract test is worse than no test.
 */
function bashPath() {
  if (process.platform !== "win32") {
    return "bash";
  }
  const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
  assert.ok(
    existsSync(gitBash),
    `Git Bash is required to execute the range contract on Windows; not found at ${gitBash}`,
  );
  return gitBash;
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(" ")} failed: ${result.stderr || result.stdout}`,
  );
  return result.stdout;
}

/** A repository whose root commit already carries whitespace drift. */
function makeRepo() {
  const dir = mkdtempSync(join(tmpdir(), "cmtrace-range-"));
  run("git", ["init", "-q", "-b", "main"], dir);
  run("git", ["config", "user.email", "test@example.invalid"], dir);
  run("git", ["config", "user.name", "Range Test"], dir);

  // The root commit carries trailing whitespace: pre-existing drift that the
  // changed-range check must not report when the range excludes it.
  writeFileSync(join(dir, "root.txt"), "root line has trailing space   \n");
  run("git", ["add", "."], dir);
  run("git", ["commit", "-qm", "root"], dir);
  const root = run("git", ["rev-parse", "HEAD"], dir).trim();

  // A later, clean commit.
  writeFileSync(join(dir, "changed.txt"), "changed line\n");
  run("git", ["add", "."], dir);
  run("git", ["commit", "-qm", "second"], dir);

  return { dir, root, head: run("git", ["rev-parse", "HEAD"], dir).trim() };
}

/** The range the rule prints for one event/base combination. */
function selectedRange(dir, event, before, prBase) {
  return run(bashPath(), [scriptPath, event, before, prBase], dir).trim();
}

/** The paths `git diff --check` reports for a selected range. */
function flaggedPaths(dir, range) {
  const args =
    range === "--empty-tree"
      ? [
          "diff",
          "--check",
          run("git", ["hash-object", "-t", "tree", "/dev/null"], dir).trim(),
          "HEAD",
        ]
      : ["diff", "--check", range];

  // `git diff --check` exits 2 when it finds whitespace problems — the outcome
  // this helper exists to observe — so its output is read for both 0 and 2.
  const result = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  assert.ok(
    result.status === 0 || result.status === 2,
    `git ${args.join(" ")} failed unexpectedly: ${result.stderr || result.stdout}`,
  );

  // `git diff --check` prints `path:line: message` and then, for trailing
  // whitespace, the offending content on the following line. Only the first shape
  // names a path, so the content lines are excluded rather than parsed as paths.
  return result.stdout
    .split("\n")
    .map((line) => /^(.*?):\d+: /.exec(line))
    .filter((match) => match !== null)
    .map((match) => match[1]);
}

test("a push with an ordinary base diffs only what that base changed", () => {
  const { dir, root, head } = makeRepo();
  const range = selectedRange(dir, "push", head, "");

  assert.equal(range, `${head}..HEAD`, "a push uses the two-dot range");
  assert.deepEqual(
    flaggedPaths(dir, range),
    [],
    "the clean commit is the only change, so nothing is flagged",
  );

  // The base the event supplied is the ordinary commit before HEAD.
  const fromRoot = selectedRange(dir, "push", root, "");
  assert.equal(fromRoot, `${root}..HEAD`, "a valid base is used as given");
  assert.deepEqual(
    flaggedPaths(dir, fromRoot),
    [],
    "the root commit's own whitespace is not in range, so it is not reported",
  );
});

test("a push with a root-commit base keeps that base rather than widening", () => {
  const { dir, root } = makeRepo();

  // The regression: requiring `base^` reclassified this valid base as missing and
  // fell through to the empty-tree diff.
  const range = selectedRange(dir, "push", root, "");
  assert.equal(
    range,
    `${root}..HEAD`,
    "a root commit is a valid base and must not be treated as unavailable",
  );
  assert.deepEqual(
    flaggedPaths(dir, range),
    [],
    "root..HEAD excludes the root commit's own drift, unlike the empty-tree form",
  );
});

test("a pull request uses the merge-base range for both ordinary and root bases", () => {
  const { dir, root, head } = makeRepo();

  assert.equal(
    selectedRange(dir, "pull_request", "", head),
    `${head}...HEAD`,
    "a pull request uses the three-dot range",
  );
  assert.equal(
    selectedRange(dir, "pull_request", "", root),
    `${root}...HEAD`,
    "a root-commit base is still valid for a pull request",
  );
});

test("an all-zero base falls back to the empty tree", () => {
  const { dir } = makeRepo();
  const zero = "0".repeat(40);

  assert.equal(
    selectedRange(dir, "push", zero, ""),
    "--empty-tree",
    "an all-zero base means there is nothing to compare against",
  );

  // The consequence is observable in the path set: with no base, the root
  // commit's own whitespace is genuinely part of the change.
  assert.deepEqual(
    flaggedPaths(dir, "--empty-tree"),
    ["root.txt"],
    "the empty-tree form reports the pre-existing drift, which is why it is not " +
      "used when a real base exists",
  );
});

test("a missing or unresolvable base falls back to the empty tree", () => {
  const { dir } = makeRepo();

  for (const missing of ["", "not-a-sha", "abcdef"]) {
    assert.equal(
      selectedRange(dir, "push", missing, ""),
      "--empty-tree",
      `base ${JSON.stringify(missing)} is not usable`,
    );
  }

  assert.equal(
    selectedRange(dir, "push", "1".repeat(40), ""),
    "--empty-tree",
    "a well-formed sha that is not in this repository is not usable either",
  );
});
