import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));

/**
 * Everything Claude Code and OMP load as agent context for this repository. A
 * fresh clone on a new machine must be able to run both runtimes, so none of it
 * may route into a home directory, one workstation, or Hermes.
 */
const AGENT_CONTEXT = [
  ".claude/skills",
  ".claude/agents",
  ".omp",
  ".Clairvoyance",
  "soul.md",
  "memory.md",
  "library.md",
  "AGENTS.md",
  "CLAUDE.md",
];

/**
 * A Windows path such as `C:/Users/<user>/AppData` is lab guidance, not a
 * workstation dependency, so the home-directory rule skips a drive-letter prefix.
 */
/**
 * `~/.omp/...` is OMP's documented per-machine runtime state (the model-probe
 * report the coordinator reads and rewrites on each host) and is a declared
 * non-goal to make portable, so the home-directory rule carves out exactly
 * that prefix and forbids every other `~/` route.
 */
const FORBIDDEN = [
  [/hermes/i, "depends on Hermes"],
  [/(?<![A-Za-z]:)\/Users\//, "names a macOS home directory"],
  [/\/private\//, "names a macOS private path"],
  [/~\/(?!\.omp\/)/, "routes into a home directory outside ~/.omp/"],
];

/**
 * A line carrying this exact marker is skipped by every rule above. `/hermes/i`
 * in particular can match a line that only mentions the pattern as data (a
 * variable name, a string check, a comment), not a live dependency on Hermes
 * or a workstation path, so a single marked line lets that case through
 * without weakening the rule for everything else. Kept as a plain substring
 * check, not a pattern of its own, so marking a line can never itself be
 * mistaken for a violation.
 */
const ALLOW_MARKER = "agent-context: allow";

function trackedFiles(paths) {
  const output = execFileSync("git", ["ls-files", "-z", "--", ...paths], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return output.split("\0").filter(Boolean);
}

function read(path) {
  return readFileSync(join(repoRoot, path), "utf8").replace(/\r\n/g, "\n");
}

function frontmatter(path) {
  const match = /^---\n([\s\S]*?)\n---\n/.exec(read(path));
  assert.ok(match, `${path} has no frontmatter`);
  return match[1];
}

/** A top-level `key: value` from frontmatter, unquoted, or null when absent. */
function scalar(fields, key) {
  const match = new RegExp(`^${key}:[ \\t]*(.+)$`, "m").exec(fields);
  return match ? match[1].trim().replace(/^"(.*)"$/, "$1") : null;
}

/**
 * A top-level one-line flow list such as `skills: [a, b]`, or null when the
 * key is absent. A key that is present but not written as a one-line flow
 * list (for example a YAML block list) fails loudly instead of silently
 * resolving to an empty list, so it cannot skip the checks below.
 */
function flowList(fields, key, path) {
  const match = new RegExp(`^${key}:[ \\t]*\\[([^\\]]*)\\][ \\t]*$`, "m").exec(fields);
  if (match) {
    return match[1]
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean);
  }
  const present = new RegExp(`^${key}:`, "m").test(fields);
  assert.ok(!present, `${path}: ${key} must be a one-line flow list`);
  return null;
}

function markdownIn(directory) {
  return trackedFiles([directory]).filter((path) => path.endsWith(".md"));
}

test("agent context names no workstation path and no Hermes dependency", () => {
  const violations = [];
  for (const path of trackedFiles(AGENT_CONTEXT)) {
    // LICENSE files record where vendored text came from.
    if (basename(path).startsWith("LICENSE")) {
      continue;
    }
    read(path)
      .split("\n")
      .forEach((line, index) => {
        if (line.includes(ALLOW_MARKER)) {
          return;
        }
        for (const [pattern, reason] of FORBIDDEN) {
          if (pattern.test(line)) {
            violations.push(`${path}:${index + 1}: ${reason}`);
          }
        }
      });
  }
  assert.deepEqual(violations, []);
});

test("the retired .agents directory stays empty", () => {
  assert.deepEqual(trackedFiles([".agents"]), []);
});

test("every skill an agent loads is checked in under .claude/skills", () => {
  const loadedBy = new Map();
  const want = (skill, from) => {
    if (!loadedBy.has(skill)) {
      loadedBy.set(skill, from);
    }
  };
  for (const path of markdownIn(".omp/agents")) {
    for (const skill of flowList(frontmatter(path), "autoloadSkills", path) ?? []) {
      want(skill, path);
    }
  }
  for (const path of markdownIn(".claude/agents")) {
    for (const skill of flowList(frontmatter(path), "skills", path) ?? []) {
      want(skill, path);
    }
  }
  const orchestrator = ".omp/skills/cmtraceopen-dev/SKILL.md";
  for (const [, skill] of read(orchestrator).matchAll(/skill:\/\/([a-z0-9-]+)/g)) {
    want(skill, orchestrator);
  }

  const checkedIn = new Set(trackedFiles([".claude/skills"]));
  const missing = [...loadedBy]
    .filter(([skill]) => !checkedIn.has(`.claude/skills/${skill}/SKILL.md`))
    .map(([skill, from]) => `${skill} (loaded by ${from})`);
  assert.deepEqual(missing, []);
});

/**
 * OMP model tiers mapped to Claude subagent settings. Sonnet at low effort
 * replaces a separate cheap model for the scaffold tier.
 */
const CLAUDE_TIER = {
  "@reasoning": { model: "opus", effort: null },
  "@mid": { model: "sonnet", effort: null },
  "@scaffold": { model: "sonnet", effort: "low" },
};

function body(path) {
  return read(path).replace(/^---\n[\s\S]*?\n---\n/, "");
}

test("every OMP staff role has a matching read-only Claude subagent", () => {
  const ompRoles = markdownIn(".omp/agents");
  assert.ok(ompRoles.length > 0, "no OMP staff roles found");
  const unmatched = new Set(markdownIn(".claude/agents").filter((path) => /\/cmtrace-[^/]+\.md$/.test(path)));

  for (const ompPath of ompRoles) {
    const role = basename(ompPath, ".md");
    const claudePath = `.claude/agents/cmtrace-${role}.md`;
    assert.ok(unmatched.delete(claudePath), `${ompPath} has no ${claudePath}`);

    const omp = frontmatter(ompPath);
    const claude = frontmatter(claudePath);
    const tier = CLAUDE_TIER[scalar(omp, "model")];
    assert.ok(tier, `${ompPath} has an unmapped model tier`);
    assert.equal(scalar(claude, "name"), `cmtrace-${role}`, claudePath);
    assert.equal(scalar(claude, "tools"), "Read, Grep, Glob", claudePath);
    assert.equal(scalar(claude, "model"), tier.model, claudePath);
    assert.equal(scalar(claude, "effort"), tier.effort, claudePath);
    assert.equal(scalar(claude, "omitClaudeMd"), "true", claudePath);
    assert.deepEqual(flowList(claude, "skills", claudePath), flowList(omp, "autoloadSkills", ompPath), claudePath);
    assert.ok(body(claudePath).includes(`\`${ompPath}\``), `${claudePath} must route to ${ompPath}`);
  }
  assert.deepEqual([...unmatched], [], "Claude subagents with no OMP staff role");
});
