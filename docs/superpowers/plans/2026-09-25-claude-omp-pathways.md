# Claude and OMP Shared Pathway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put every skill Claude Code and OMP load for this repo into `.claude/skills/`, remove Hermes as a dependency and as a review gate, and give Claude Code the seven OMP staff roles as subagents.

**Architecture:** `.claude/skills/` becomes the only skill home, read natively by both runtimes. OMP's external-skill installer is deleted. Claude subagents in `.claude/agents/cmtrace-<role>.md` are thin wrappers that route to `.omp/agents/<role>.md`, which stays the single source of role instructions and output schemas. A Node test in CI guards both rules.

**Tech Stack:** Markdown skills and agent definitions, Python 3.11+ `unittest` (OMP scripts), Node 22 `node:test` (CI guard), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-25-claude-omp-pathways-design.md`

---

## Ground rules for the executor

- Work only in `/Users/Adam.Gell/repo/cmtraceopen/.worktrees/agent-skill-in-repo` on branch `chore/agent-skill-in-repo`. Every command below runs from that directory.
- `CLAUDE.md` rule 2: each task is one phase. Verify it, then stop and get approval before the next task. Every task touches at most five files except Task 7 (seven files, all verbatim copies except three edits); get explicit approval for that exception.
- `CLAUDE.md` rule 9: re-read a file before editing it and after editing it.
- Never run `cargo fmt --all`. This plan changes no Rust.
- No em dashes or en dashes in anything you write (commit messages included).
- Do not push. Pushing and opening a PR are separate decisions for the owner.
- The vendoring sources exist only on this machine (`~/.hermes/profiles/default-old/`, `~/.hermes/hermes-agent`). That is expected: the point of this plan is that nothing reads them after it lands.

## One-time setup

- [ ] **Install frontend dependencies in the worktree** (needed for `npx tsc --noEmit`)

Run: `npm ci`
Expected: completes without errors.

- [ ] **Record the baseline**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests 2>&1 | tail -1`
Expected: `OK`

Run: `python3 .omp/skills/cmtraceopen-dev/scripts/write_project_config.py --check --report ~/.omp/agent/cmtraceopen/model-probe-report.json --repo-root "$PWD" --output .omp/config.yml`
Expected: `{"ok":true,"status":"unchanged"}`

## File map

| Path | Change | Responsibility |
|---|---|---|
| `scripts/agent-context.test.mjs` | Create | CI guard: no Hermes or workstation paths in agent context; `.agents/` empty; every loaded skill checked in; OMP and Claude staff in parity |
| `.github/workflows/cmtrace-ci.yml` | Modify | Run the guard |
| `.claude/skills/cmtraceopen/**` | Move from `.agents/skills/cmtraceopen/**` | The project agent skill |
| `.claude/skills/cmtraceopen-agent/SKILL.md` | Delete | Superseded loader |
| `.agents/skills/frontend-design/**` | Delete | Duplicate of `.claude/skills/frontend-design` |
| `.claude/skills/{contract-scoped-review,semantic-reducer-framework,semantic-reducer-development,branch-lane-verification,test-driven-development,systematic-debugging,windows-lab-workers,windows-remote-validation}/**` | Create (vendored) | Skills the staff roles load |
| `.claude/skills/cmtraceopen-code-review/SKILL.md` | Modify | Drop Hermes runbook; add Claude dispatch |
| `.Clairvoyance/staff/code-review-charter.md` | Modify | Charter review is the code-review agent's clean report |
| `.omp/skills/cmtraceopen-dev/scripts/lane_state.py` | Modify | Drop `charter_review` gate |
| `.omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py` | Modify | Enforce each role's closed top-level output keys |
| `.omp/skills/cmtraceopen-dev/scripts/write_project_config.py` | Modify | Config template without external skill directory |
| `.omp/skills/cmtraceopen-dev/scripts/setup_skillset.py` | Delete | External skill installer |
| `.omp/skills/cmtraceopen-dev/tests/{test_lane_state,test_validate_agent_output,test_write_project_config}.py` | Modify | Tests for the above |
| `.omp/skills/cmtraceopen-dev/tests/test_setup_skillset.py` | Delete | Tests for the deleted installer |
| `.omp/config.yml` | Modify | Generated config, kept byte-identical to the template |
| `.omp/skills/cmtraceopen-dev/SKILL.md` | Modify | In-repo skill resolution, charter route, gate set |
| `.omp/AGENTS.md`, `.Clairvoyance/staff/ceo-charter.md`, `.Clairvoyance/kickoff-prompt.md` | Modify | In-repo charter route |
| `.omp/agents/code-review.md`, `.omp/agents/coder.md`, `.omp/agents/tech-writer.md` | Modify | Gate schema; autoload lists |
| `.claude/agents/cmtrace-*.md` (7 files) | Create | Claude staff subagents |
| `soul.md`, `memory.md` | Modify | Paths and frontmatter |

---

## Piece 1: skills in the repo

### Task 1: Guard test (RED)

**Files:**
- Create: `scripts/agent-context.test.mjs`

- [ ] **Step 1: Write the guard**

Create `scripts/agent-context.test.mjs`:

```js
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
];

/**
 * A Windows path such as `C:/Users/<user>/AppData` is lab guidance, not a
 * workstation dependency, so the home-directory rule skips a drive-letter prefix.
 */
const FORBIDDEN = [
  [/hermes/i, "depends on Hermes"],
  [/(?<![A-Za-z]:)\/Users\//, "names a macOS home directory"],
  [/\/private\//, "names a macOS private path"],
];

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

/** A top-level one-line flow list such as `skills: [a, b]`, or null when absent. */
function flowList(fields, key) {
  const match = new RegExp(`^${key}:[ \\t]*\\[([^\\]]*)\\][ \\t]*$`, "m").exec(fields);
  if (!match) {
    return null;
  }
  return match[1]
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
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
    for (const skill of flowList(frontmatter(path), "autoloadSkills") ?? []) {
      want(skill, path);
    }
  }
  for (const path of markdownIn(".claude/agents")) {
    for (const skill of flowList(frontmatter(path), "skills") ?? []) {
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
```

- [ ] **Step 2: Run it and confirm RED**

Run: `git add scripts/agent-context.test.mjs && node --test scripts/agent-context.test.mjs 2>&1 | tail -8`
Expected: `ℹ pass 0` and `ℹ fail 3`. The first test lists about 60 `depends on Hermes` violations (`.Clairvoyance/*`, `.claude/skills/cmtraceopen-code-review/SKILL.md`, `.omp/**`, `soul.md`, `memory.md`) plus one `names a macOS home directory`. The second lists five `.agents/` files. The third lists nine missing skills, including `cmtrace-scaffold-pipeline` and `mdbook-docs`.

- [ ] **Step 3: Commit**

```bash
git commit -q -F - <<'EOF'
test(agents): guard agent context against Hermes and workstation paths

Red until the in-repo skills land. Not wired into CI yet.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 2: Move the cmtraceopen skill into .claude/skills

**Files:**
- Move: `.agents/skills/cmtraceopen/` to `.claude/skills/cmtraceopen/` (3 files; only `SKILL.md` changes)
- Modify: `soul.md`, `memory.md`

- [ ] **Step 1: Move the skill**

Run: `git mv .agents/skills/cmtraceopen .claude/skills/cmtraceopen`

- [ ] **Step 2: Rewrite every path that names the old location**

Run: `perl -pi -e 's#\.agents/skills/cmtraceopen#.claude/skills/cmtraceopen#g' .claude/skills/cmtraceopen/SKILL.md soul.md memory.md`

Run: `git grep -n '\.agents/' -- .claude soul.md memory.md`
Expected: no output.

- [ ] **Step 3: Drop the Hermes metadata from `.claude/skills/cmtraceopen/SKILL.md`**

Replace:

```yaml
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [cmtraceopen, tauri, rust, react, typescript, intune, sccm, esp, log-parser, project-specialist]
    related_skills: [cmtraceopen-code-review, requesting-code-review, test-driven-development, systematic-debugging]
---
```

with:

```yaml
platforms: [linux, macos, windows]
---
```

- [ ] **Step 4: Fix the frontmatter of `soul.md`**

Replace:

```yaml
author: Adam Gell / Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [cmtraceopen, soul, identity, agent-rules, tauri, rust, intune, sccm]
    related_skills: [cmtraceopen, cmtraceopen-code-review, requesting-code-review, test-driven-development, systematic-debugging]
---
```

with:

```yaml
author: Adam Gell
license: MIT
platforms: [linux, macos, windows]
---
```

- [ ] **Step 5: Fix the frontmatter of `memory.md`**

Replace:

```yaml
author: Adam Gell / Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [cmtraceopen, memory, durable-facts, architecture, checkpoints, workflow]
---
```

with:

```yaml
author: Adam Gell
license: MIT
platforms: [linux, macos, windows]
---
```

- [ ] **Step 6: Verify**

Run: `grep -niE 'hermes|\.agents/' .claude/skills/cmtraceopen/SKILL.md soul.md memory.md`
Expected: no output.

Run: `node --test scripts/agent-context.test.mjs 2>&1 | grep -E "soul.md|memory.md|cmtraceopen/SKILL"`
Expected: no output (those files no longer violate; other failures remain).

- [ ] **Step 7: Commit**

```bash
git add -A .agents .claude/skills/cmtraceopen soul.md memory.md
git commit -q -F - <<'EOF'
refactor(agents): move the cmtraceopen skill into .claude/skills

Claude Code and OMP both read .claude/skills; .agents is retired.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 3: Retire .agents and the old loader

**Files:**
- Delete: `.agents/skills/frontend-design/SKILL.md`, `.agents/skills/frontend-design/LICENSE.txt`, `.claude/skills/cmtraceopen-agent/SKILL.md`

- [ ] **Step 1: Confirm the frontend-design copies are identical before deleting one**

Run: `diff -r .agents/skills/frontend-design .claude/skills/frontend-design && echo identical`
Expected: `identical`

- [ ] **Step 2: Confirm nothing references the old loader**

Run: `git grep -n 'cmtraceopen-agent' -- ':!docs'`
Expected: only `.claude/skills/cmtraceopen-agent/SKILL.md` itself.

- [ ] **Step 3: Delete**

Run: `git rm -q -r .agents .claude/skills/cmtraceopen-agent`

- [ ] **Step 4: Verify**

Run: `node --test --test-name-pattern='retired' scripts/agent-context.test.mjs 2>&1 | grep -E 'pass|fail'`
Expected: `ℹ pass 1` and `ℹ fail 0`.

- [ ] **Step 5: Commit**

```bash
git commit -q -F - <<'EOF'
chore(agents): delete the .agents mirror and the cmtraceopen-agent loader

.agents/skills/frontend-design was an unchecked duplicate of the
.claude/skills copy, and cmtraceopen now covers what the loader did.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 4: Vendoring helpers (scratch, not committed)

**Files:** none in the repo. Everything goes under `/tmp/cmtraceopen-vendor/`.

- [ ] **Step 1: Create the vendoring helper**

Create `/tmp/cmtraceopen-vendor/vendor_skill.py`:

```python
#!/usr/bin/env python3
"""Vendor one OMP-approved skill into .claude/skills/<name>.

Usage (from the repository root): vendor_skill.py NAME SOURCE_DIR

1. Recompute the source tree digest the way setup_skillset.py did and require it
   to equal the digest pinned on origin/main, so the copy is exactly the content
   OMP last approved.
2. Copy the tree (regular files only) to .claude/skills/NAME.
3. In the SKILL.md frontmatter, drop any `author:` line naming Hermes and the
   whole `metadata:` block.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PINNED_SOURCE = ".omp/skills/cmtraceopen-dev/scripts/setup_skillset.py"


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()

    def add(kind: bytes, relative: Path, content_sha256: str = "") -> None:
        encoded = os.fsencode(relative.as_posix())
        digest.update(kind)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        if content_sha256:
            digest.update(bytes.fromhex(content_sha256))

    def visit(directory: Path, relative: Path) -> None:
        entries = sorted(os.scandir(directory), key=lambda e: os.fsencode(e.name))
        for entry in entries:
            path, child = directory / entry.name, relative / entry.name
            if path.is_symlink():
                sys.exit(f"source contains a symlink: {path}")
            if path.is_dir():
                add(b"D", child)
                visit(path, child)
            else:
                add(b"F", child, hashlib.sha256(path.read_bytes()).hexdigest())

    visit(root, Path())
    return digest.hexdigest()


def strip_frontmatter(skill: Path) -> None:
    lines = skill.read_text(encoding="utf-8").split("\n")
    if lines[0] != "---" or "---" not in lines[1:]:
        sys.exit(f"no frontmatter: {skill}")
    end = lines.index("---", 1)
    kept, in_metadata = [], False
    for line in lines[1:end]:
        if in_metadata and line.startswith(" "):
            continue
        in_metadata = False
        if line == "metadata:":
            in_metadata = True
            continue
        if line.startswith("author:") and "hermes" in line.lower():
            continue
        kept.append(line)
    skill.write_text("\n".join([lines[0], *kept, *lines[end:]]), encoding="utf-8")


def main() -> None:
    name, source = sys.argv[1], Path(sys.argv[2]).expanduser()
    repo = Path(
        subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    )
    pinned = subprocess.check_output(
        ["git", "show", f"origin/main:{PINNED_SOURCE}"], cwd=repo, text=True
    )
    pins = dict(re.findall(r'"([a-z0-9-]+)": \(\s*"([0-9a-f]{64})"', pinned))
    if name not in pins:
        sys.exit(f"{name} has no pinned digest")
    if tree_digest(source) != pins[name]:
        sys.exit(f"{name}: {source} does not match the pinned digest")
    dest = repo / ".claude" / "skills" / name
    if dest.exists():
        sys.exit(f"{dest} already exists")
    shutil.copytree(source, dest, symlinks=False)
    strip_frontmatter(dest / "SKILL.md")
    files = sorted(p.relative_to(repo).as_posix() for p in dest.rglob("*") if p.is_file())
    print(f"vendored {name} ({len(files)} files)")
    for path in files:
        print(f"  {path}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Create the edit helper**

Create `/tmp/cmtraceopen-vendor/edit_helpers.py`:

```python
"""Exact-text edits that fail loudly instead of silently missing."""
import sys
from pathlib import Path


def replace_once(path, old: str, new: str) -> None:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        sys.exit(f"{path}: expected 1 occurrence, found {count}: {old[:60]!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def replace_between(path, start: str, end, new: str) -> None:
    """Replace from `start` up to (not including) `end`; `end=None` means EOF."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if text.count(start) != 1:
        sys.exit(f"{path}: start marker not unique: {start!r}")
    head, rest = text.split(start)
    if end is None:
        tail = ""
    else:
        if rest.count(end) != 1:
            sys.exit(f"{path}: end marker not unique: {end!r}")
        tail = end + rest.split(end)[1]
    path.write_text(head + new + tail, encoding="utf-8")
```

- [ ] **Step 3: Extract the pinned hermes-agent sources**

Run:

```bash
mkdir -p /tmp/cmtraceopen-vendor/pinned
git -C ~/.hermes/hermes-agent archive 4a2198bf5124f0c4d915cb958f141116ae8607f0 \
  skills/software-development/test-driven-development \
  skills/software-development/systematic-debugging \
  | tar -x -C /tmp/cmtraceopen-vendor/pinned
ls /tmp/cmtraceopen-vendor/pinned/skills/software-development
```

Expected: `systematic-debugging` and `test-driven-development`.

### Task 5: Vendor contract-scoped-review and semantic-reducer-development

**Files:**
- Create: `.claude/skills/contract-scoped-review/{SKILL.md,references/bootstrap-correction-review.md,references/exact-artifact-review-gates.md}`
- Create: `.claude/skills/semantic-reducer-development/{SKILL.md,references/store-pilot.md}`

- [ ] **Step 1: Vendor**

```bash
python3 /tmp/cmtraceopen-vendor/vendor_skill.py contract-scoped-review ~/.hermes/profiles/default-old/skills/software-development/contract-scoped-review
python3 /tmp/cmtraceopen-vendor/vendor_skill.py semantic-reducer-development ~/.hermes/profiles/default-old/skills/.archive/semantic-reducer-development
```

Expected: `vendored contract-scoped-review (3 files)` and `vendored semantic-reducer-development (2 files)`.

- [ ] **Step 2: Verify**

Run: `grep -rniE 'hermes|/Users/|/private/' .claude/skills/contract-scoped-review .claude/skills/semantic-reducer-development`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/contract-scoped-review .claude/skills/semantic-reducer-development
git commit -q -F - <<'EOF'
feat(agents): vendor contract-scoped-review and semantic-reducer-development

Copied from the content OMP pinned in setup_skillset.py (tree digests
verified), with the Hermes frontmatter metadata removed.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 6: Vendor semantic-reducer-framework

**Files:**
- Create: `.claude/skills/semantic-reducer-framework/{SKILL.md,references/governance-acceptance-slice.md,references/semantic-reducer-reconciliation.md,references/phase-1-governance-example.md,references/reasoning-tier-adversarial-review.md}`

- [ ] **Step 1: Vendor**

Run: `python3 /tmp/cmtraceopen-vendor/vendor_skill.py semantic-reducer-framework ~/.hermes/profiles/default-old/skills/.archive/semantic-reducer-framework`
Expected: `vendored semantic-reducer-framework (5 files)`.

- [ ] **Step 2: Reword the two Hermes passages**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_once

replace_once(
    ".claude/skills/semantic-reducer-framework/SKILL.md",
    "3. Identify existing Hermes mechanisms for orchestration,",
    "3. Identify the repository's existing mechanisms (`.Clairvoyance/staff/` charters, `.claude/skills/`, `.omp/`) for orchestration,",
)
replace_once(
    ".claude/skills/semantic-reducer-framework/references/semantic-reducer-reconciliation.md",
    "inspect project rules, Hermes/Clairvoyance staff and skills,",
    "inspect project rules, Clairvoyance staff charters and repository skills,",
)
print("ok")
EOF
```

Expected: `ok`.

- [ ] **Step 3: Verify**

Run: `grep -rniE 'hermes|/Users/|/private/' .claude/skills/semantic-reducer-framework`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/semantic-reducer-framework
git commit -q -F - <<'EOF'
feat(agents): vendor semantic-reducer-framework

Copied from the OMP-pinned content; the two passages that pointed at
Hermes mechanisms now name the repository's own charters and skills.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 7: Vendor branch-lane-verification (seven files; needs approval for the file-count exception)

**Files:**
- Create: `.claude/skills/branch-lane-verification/SKILL.md` and `references/{recovery-branch-extraction,live-state-exact-plan-review,exact-plan-source-binding,superseded-branch-reconciliation,coderabbit-gates,ci-artifact-delivery}.md`

- [ ] **Step 1: Vendor**

Run: `python3 /tmp/cmtraceopen-vendor/vendor_skill.py branch-lane-verification ~/.hermes/profiles/default-old/skills/software-development/branch-lane-verification`
Expected: `vendored branch-lane-verification (7 files)`.

- [ ] **Step 2: Replace the Hermes delegation passages**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_between, replace_once

base = ".claude/skills/branch-lane-verification"
replace_once(
    f"{base}/SKILL.md",
    "When delegating the independent review via `delegate_task`:",
    "When dispatching the independent review to a subagent:",
)
replace_once(
    f"{base}/references/recovery-branch-extraction.md",
    "- `max_concurrent_children` caps the batch size; raise it via\n"
    "  `hermes config set delegation.max_concurrent_children 5` (with user approval)\n"
    "  rather than serializing a 5-lane program into 3+2.",
    "- The runtime's concurrent-subagent limit caps the batch size; raise it (with user\n"
    "  approval) rather than serializing a 5-lane program into 3+2.",
)
replace_between(
    f"{base}/references/coderabbit-gates.md",
    "## Delegation backend health (for the SKILL's Step 5 independent review)\n",
    None,
    "## Reviewer dispatch health (for the SKILL's Step 5 independent review)\n"
    "\n"
    "A misconfigured subagent backend makes every reviewer die on an API error while\n"
    "the dispatch still \"completes\", which is exactly the silent failure Step 5 warns\n"
    "about. Verify the backend once before relying on it for a gate: dispatch a trivial\n"
    "read-only task and check both the returned content and the model the runtime\n"
    "reports it used. Healthy means accurate content and a normal completion. Anything\n"
    "else means the gate cannot pass until the backend is fixed.\n",
)
print("ok")
EOF
```

Expected: `ok`.

- [ ] **Step 3: Verify**

Run: `grep -rniE 'hermes|delegate_task|/Users/|/private/' .claude/skills/branch-lane-verification`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/branch-lane-verification
git commit -q -F - <<'EOF'
feat(agents): vendor branch-lane-verification

Copied from the OMP-pinned content. The Hermes delegation and
`hermes config` troubleshooting passages are now runtime-neutral.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 8: Vendor test-driven-development and systematic-debugging

**Files:**
- Create: `.claude/skills/test-driven-development/SKILL.md`, `.claude/skills/test-driven-development/LICENSE`
- Create: `.claude/skills/systematic-debugging/SKILL.md`, `.claude/skills/systematic-debugging/LICENSE`

- [ ] **Step 1: Vendor**

```bash
python3 /tmp/cmtraceopen-vendor/vendor_skill.py test-driven-development /tmp/cmtraceopen-vendor/pinned/skills/software-development/test-driven-development
python3 /tmp/cmtraceopen-vendor/vendor_skill.py systematic-debugging /tmp/cmtraceopen-vendor/pinned/skills/software-development/systematic-debugging
```

Expected: `vendored test-driven-development (1 files)` and `vendored systematic-debugging (1 files)`.

- [ ] **Step 2: Replace the Hermes tool sections**

````bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_between, replace_once

TDD = ".claude/skills/test-driven-development/SKILL.md"
replace_between(
    TDD,
    "## Hermes Agent Integration\n",
    "### With systematic-debugging\n",
    "## Running the Cycle\n"
    "\n"
    "Run the focused test at every step and read its output:\n"
    "\n"
    "- RED: run the one new test and confirm it fails for the expected reason (missing\n"
    "  behavior, not a typo or an import error).\n"
    "- GREEN: run the same test and confirm it passes.\n"
    "- Full suite: run the project's whole test command and confirm nothing else broke.\n"
    "\n"
    "### With subagents\n"
    "\n"
    "When dispatching an implementation subagent, put the cycle in its brief: write the\n"
    "failing test first, run it and confirm the failure, write the minimal code, run it\n"
    "and confirm the pass, refactor, then commit. Give it the project's exact test\n"
    "command and the files in scope.\n"
    "\n",
)

SD = ".claude/skills/systematic-debugging/SKILL.md"
replace_once(
    SD,
    "**Action:** Use `read_file` on the relevant source files. Use `search_files` to find the error string in the codebase.",
    "**Action:** Read the relevant source files. Search the codebase for the error string (for example `git grep -n \"<error text>\"`).",
)
replace_once(
    SD,
    "**Action:** Use the `terminal` tool to run the tight loop:",
    "**Action:** Run the tight loop from a shell:",
)
replace_once(
    SD,
    "**Action:** Use `search_files` to trace references:\n"
    "\n"
    "```python\n"
    "# Find where the function is called\n"
    "search_files(\"function_name(\", path=\"src/\", file_glob=\"*.py\")\n"
    "\n"
    "# Find where the variable is set\n"
    "search_files(\"variable_name\\\\s*=\", path=\"src/\", file_glob=\"*.py\")\n"
    "```",
    "**Action:** Search for references to trace the data flow:\n"
    "\n"
    "```bash\n"
    "# Find where the function is called\n"
    "git grep -n \"function_name(\" -- src/\n"
    "\n"
    "# Find where the variable is set\n"
    "git grep -nE \"variable_name\\s*=\" -- src/\n"
    "```",
)
replace_once(
    SD,
    "**Action:** Use `search_files` to find comparable patterns:\n"
    "\n"
    "```python\n"
    "search_files(\"similar_pattern\", path=\"src/\", file_glob=\"*.py\")\n"
    "```",
    "**Action:** Search for comparable patterns:\n"
    "\n"
    "```bash\n"
    "git grep -n \"similar_pattern\" -- src/\n"
    "```",
)
replace_between(
    SD,
    "## Hermes Agent Integration\n",
    "### With test-driven-development\n",
    "## Investigation Tools\n"
    "\n"
    "During Phase 1, use whatever the runtime provides to:\n"
    "\n"
    "- search for error strings, callers, and comparable patterns;\n"
    "- read source with line numbers;\n"
    "- run tests, check git history, and reproduce the bug;\n"
    "- look up error messages and library documentation.\n"
    "\n"
    "### With subagents\n"
    "\n"
    "For complex multi-component debugging, dispatch an investigation subagent whose\n"
    "brief says: read the error carefully, reproduce it, trace the data flow to the root\n"
    "cause, and report findings without fixing anything yet. Include the full error, the\n"
    "failing file, and the exact test command.\n"
    "\n",
)
print("ok")
EOF
````

Expected: `ok`.

- [ ] **Step 3: Write the license notices**

```bash
for skill in test-driven-development systematic-debugging; do
  {
    printf 'This skill is vendored from NousResearch/hermes-agent at commit\n'
    printf '4a2198bf5124f0c4d915cb958f141116ae8607f0 (skills/software-development/%s),\n' "$skill"
    printf 'which adapted it from obra/superpowers. It was modified here: the runtime tool\n'
    printf 'integration section was replaced with runtime-neutral guidance and the\n'
    printf 'frontmatter metadata was removed.\n\n'
    printf -- '---- NousResearch/hermes-agent ----\n\n'
    git -C ~/.hermes/hermes-agent show 4a2198bf5124f0c4d915cb958f141116ae8607f0:LICENSE
    printf -- '\n---- obra/superpowers ----\n\n'
    cat ~/.claude/plugins/cache/claude-plugins-official/superpowers/6.2.0/LICENSE
  } > ".claude/skills/$skill/LICENSE"
done
head -12 .claude/skills/test-driven-development/LICENSE
```

Expected: the notice paragraph, then `MIT License` and `Copyright (c) 2025 Nous Research`.

- [ ] **Step 4: Verify**

Run: `grep -niE 'hermes|delegate_task|search_files|read_file|terminal\(|toolsets' .claude/skills/test-driven-development/SKILL.md .claude/skills/systematic-debugging/SKILL.md`
Expected: no output.

Run: `node --test scripts/agent-context.test.mjs 2>&1 | grep -E 'test-driven|systematic-debugging'`
Expected: no output (LICENSE files are exempt; the SKILL.md files are clean).

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/test-driven-development .claude/skills/systematic-debugging
git commit -q -F - <<'EOF'
feat(agents): vendor test-driven-development and systematic-debugging

Copied from hermes-agent at the commit OMP pinned (tree digests
verified). The Hermes tool sections (terminal, delegate_task,
search_files) are replaced with runtime-neutral guidance; each skill
carries the MIT notices of both upstreams and records the modification.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 9: Vendor the Windows lab skills with the lab inventory removed

The host names, addresses, and account originally quoted below have been redacted from this document with placeholder tokens; the real values live only in the pre-vendoring source.

**Files:**
- Create: `.claude/skills/windows-lab-workers/{SKILL.md,references/powershell-worker-session.md}`
- Create: `.claude/skills/windows-remote-validation/{SKILL.md,references/lab-access-template.md,references/two-layer-ai-lab-worker.md}`

- [ ] **Step 1: Vendor**

```bash
python3 /tmp/cmtraceopen-vendor/vendor_skill.py windows-lab-workers ~/.hermes/profiles/default-old/skills/.archive/windows-lab-workers
python3 /tmp/cmtraceopen-vendor/vendor_skill.py windows-remote-validation ~/.hermes/profiles/default-old/skills/.archive/windows-remote-validation
```

Expected: `vendored windows-lab-workers (2 files)` and `vendored windows-remote-validation (3 files)`.

- [ ] **Step 2: Replace the lab-specific reference with a template**

Run: `mv .claude/skills/windows-remote-validation/references/<old-lab-reference>.md .claude/skills/windows-remote-validation/references/lab-access-template.md`

Overwrite `.claude/skills/windows-remote-validation/references/lab-access-template.md` with:

````markdown
# Lab Access Template

Record these for each lab host in your local SSH config and lab notes. Real values
stay out of the repository.

## Access contract

- SSH alias: `<alias>`
- Address: `<lab-address>`
- Remote account: `<lab-account>`
- Local identity file: `<ssh-identity-file>`
- Hostname observed over SSH: `<host>`
- Windows shell: `powershell.exe` (Windows PowerShell 5.1)

## Client configuration

```sshconfig
Host <alias>
  HostName <lab-address>
  User <lab-account>
  IdentityFile <ssh-identity-file>
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
```

## ConfigMgr site server evidence surface

- Site-server log root: `C:\Program Files\Microsoft Configuration Manager\Logs`
- ConfigMgr version and product ID: `HKLM:\SOFTWARE\Microsoft\SMS\Setup`
- `C:\Windows\CCM\Logs` is absent when the server is not also a ConfigMgr client.
- Expected running services include `SMS_EXECUTIVE`, `SMS_NOTIFICATION_SERVER`,
  `SMS_SITE_COMPONENT_MANAGER`, `SMS_SITE_SQL_BACKUP`, and `SMS_SITE_VSS_WRITER`.
- `SMS_SITE_BACKUP` may be stopped between backup runs; check the site-backup
  configuration before classifying it as a fault or changing it.

## Known quoting lesson

Complex inline commands fail when passed through multiple shells, especially around
PowerShell strings containing parentheses, `$`, backticks, and nested quotes. The
working pattern: write a `.ps1` locally, `scp` it to
`C:/Users/<lab-account>/AppData/Local/Temp/`, then invoke it with
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`.
````

- [ ] **Step 3: Point SKILL.md at the template and anonymize the topology**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_once

W = ".claude/skills/windows-remote-validation"
replace_once(
    f"{W}/SKILL.md",
    "- `references/<old-lab-reference>.md` contains the proven <cm-server-host> access and probe details from the initial setup session.",
    "- `references/lab-access-template.md` lists what to record about a lab host and what a ConfigMgr site server's evidence surface looks like. Keep real host names, addresses, accounts, and key paths in your local SSH config, never in the repository.",
)
replace_once(
    f"{W}/references/two-layer-ai-lab-worker.md",
    "## Proven topology\n\n"
    "- Windows client: `<client-host>` at `<client-address>`, interactive console session `1`, account `<lab-account>`.\n"
    "- ConfigMgr server: `<cm-server-host>` at `<cm-server-address>`, account `<lab-account>`.",
    "## Topology\n\n"
    "- Windows client: `<client-host>` at `<client-address>`, interactive console session `1`, account `<lab-account>`.\n"
    "- ConfigMgr server: `<cm-server-host>` at `<cm-server-address>`, account `<lab-account>`.",
)
print("ok")
EOF
```

Expected: `ok`.

- [ ] **Step 4: Verify no lab inventory remains**

Run: `grep -rnE '([0-9]{1,3}\.){3}[0-9]{1,3}|<cm-server-host>|<client-host>|<lab-account>|/Users/Adam|id_ed25519|hermes' .claude/skills/windows-lab-workers .claude/skills/windows-remote-validation`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/windows-lab-workers .claude/skills/windows-remote-validation
git commit -q -F - <<'EOF'
feat(agents): vendor the Windows lab skills without the lab inventory

windows-lab-workers is copied as pinned. windows-remote-validation keeps
its workflow; host names, private addresses, the lab account, and the
SSH key path become placeholders because the repository is public.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 10: Remove Hermes from the review contract (docs)

**Files:**
- Modify: `.claude/skills/cmtraceopen-code-review/SKILL.md`
- Modify: `.Clairvoyance/staff/code-review-charter.md`

- [ ] **Step 1: Delete the Hermes runbook**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_between

replace_between(
    ".claude/skills/cmtraceopen-code-review/SKILL.md",
    "\n## Delegating a review to Hermes\n",
    None,
    "",
)
print("ok")
EOF
```

Run: `tail -3 .claude/skills/cmtraceopen-code-review/SKILL.md; grep -ci hermes .claude/skills/cmtraceopen-code-review/SKILL.md`
Expected: the last line is `at the report.`, and the count is `0`.

- [ ] **Step 2: Rewrite the charter's gate text**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_once

C = ".Clairvoyance/staff/code-review-charter.md"
replace_once(
    C,
    "review state (`approved_at_head`), a posted Hermes charter review with no open blocking\n"
    "findings, and contract-layer conformance; explicitly rejected review feedback with\n",
    "review state (`approved_at_head`), and contract-layer conformance; explicitly rejected\n"
    "review feedback with\n",
)
replace_once(
    C,
    "Hermes and CodeRabbit are both merge gates for ALL fixes (Adam, 2026-08-08): no\n"
    "fix PR of any size is merge-ready until CodeRabbit is APPROVED at head AND a\n"
    "Hermes charter review has been posted with its blocking findings resolved. Charter\n"
    "reviews run as Hermes sessions by default (see the operator skill's delegation\n"
    "runbook); the operator's own layer agents are the fallback when Hermes is\n"
    "unavailable, and a fallback review must say so in its report.\n",
    "A clean report from this charter's reviewer (the `code-review` staff agent in OMP,\n"
    "`cmtrace-code-review` in Claude Code) is the charter review; Main posts it on the\n"
    "pull request. No fix PR of any size is merge-ready until CodeRabbit is APPROVED at\n"
    "head and that clean charter review has been posted.\n",
)
print("ok")
EOF
```

Expected: `ok`.

- [ ] **Step 3: Verify**

Run: `grep -ni hermes .Clairvoyance/staff/code-review-charter.md .claude/skills/cmtraceopen-code-review/SKILL.md`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/cmtraceopen-code-review/SKILL.md .Clairvoyance/staff/code-review-charter.md
git commit -q -F - <<'EOF'
docs(review): make the code-review agent's clean report the charter review

Hermes no longer runs or gates reviews. The delegation runbook is gone,
and the charter now names the repository's own reviewer as the source
of the posted charter review.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 11: Drop the charter_review gate key (code)

**Files:**
- Modify: `.omp/skills/cmtraceopen-dev/tests/test_validate_agent_output.py`
- Modify: `.omp/skills/cmtraceopen-dev/tests/test_lane_state.py`
- Modify: `.omp/skills/cmtraceopen-dev/scripts/lane_state.py`
- Modify: `.omp/agents/code-review.md`
- Modify: `.omp/skills/cmtraceopen-dev/SKILL.md`

- [ ] **Step 1: Update the tests first**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_once

V = ".omp/skills/cmtraceopen-dev/tests/test_validate_agent_output.py"
replace_once(
    V,
    '        "coderabbit": "passed",\n        "charter_review": "passed",\n        "contract_conformance": "passed",\n',
    '        "coderabbit": "passed",\n        "contract_conformance": "passed",\n',
)
replace_once(V, '        missing.pop("charter_review")\n', '        missing.pop("contract_conformance")\n')
replace_once(
    V,
    '            {**clean_review_gate_states(), "focused": "passed"},\n',
    '            {**clean_review_gate_states(), "focused": "passed"},\n'
    '            {**clean_review_gate_states(), "charter_review": "passed"},\n',
)

L = ".omp/skills/cmtraceopen-dev/tests/test_lane_state.py"
replace_once(
    L,
    '            "coderabbit": "passed",\n            "charter_review": "passed",\n            "contract_conformance": "passed",\n',
    '            "coderabbit": "passed",\n            "contract_conformance": "passed",\n',
)
replace_once(L, 'raw["gate_states"].pop("charter_review")', 'raw["gate_states"].pop("contract_conformance")')
print("ok")
EOF
```

Expected: `ok`.

- [ ] **Step 2: Run the tests and confirm RED**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests -p 'test_validate_agent_output.py' 2>&1 | tail -3`
Expected: `FAILED` with failures or errors including `test_code_review_requires_closed_mandatory_gate_set` and the `code-review` subtest of `test_accepts_role_specific_productive_payloads` (the validator still requires `charter_review`).

- [ ] **Step 3: Remove the key from the gate set**

In `.omp/skills/cmtraceopen-dev/scripts/lane_state.py`, replace:

```python
    "coderabbit": "passed",
    "charter_review": "passed",
    "contract_conformance": "passed",
```

with:

```python
    "coderabbit": "passed",
    "contract_conformance": "passed",
```

- [ ] **Step 4: Update the code-review schema and instructions**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_once

R = ".omp/agents/code-review.md"
replace_once(R, "        charter_review: { type: string, const: passed }\n", "")
replace_once(
    R,
    "required: [ci, coderabbit, charter_review, contract_conformance]",
    "required: [ci, coderabbit, contract_conformance]",
)
replace_once(
    R,
    '{"ci":"passed","coderabbit":"passed","charter_review":"passed","contract_conformance":"passed"}',
    '{"ci":"passed","coderabbit":"passed","contract_conformance":"passed"}',
)
replace_once(
    R,
    "Report the four mandatory exact-head states only from artifacts Main supplies: CI as `ci`, CodeRabbit as `coderabbit`, Hermes/charter review as `charter_review`, and contract conformance as `contract_conformance`.",
    "Report the three mandatory exact-head states only from artifacts Main supplies: CI as `ci`, CodeRabbit as `coderabbit`, and contract conformance as `contract_conformance`. A clean `review_report` is itself the charter review; Main posts it on the pull request.",
)

S = ".omp/skills/cmtraceopen-dev/SKILL.md"
old_gate = '{"ci":"passed","coderabbit":"passed","charter_review":"passed","contract_conformance":"passed"}'
text = open(S, encoding="utf-8").read()
if text.count(old_gate) != 2:
    sys.exit(f"{S}: expected 2 gate strings, found {text.count(old_gate)}")
open(S, "w", encoding="utf-8").write(
    text.replace(old_gate, '{"ci":"passed","coderabbit":"passed","contract_conformance":"passed"}')
)
replace_once(
    S,
    "blocker, or stale artifact does not count.",
    "blocker, or stale artifact does not count. Main posts that clean report on the draft PR as the charter review.",
)
print("ok")
EOF
```

Expected: `ok`.

- [ ] **Step 5: Run the tests and confirm GREEN**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests 2>&1 | tail -1`
Expected: `OK`

Run: `git grep -n charter_review -- .omp .claude .Clairvoyance`
Expected: only the new rejection case in `test_validate_agent_output.py` (`{**clean_review_gate_states(), "charter_review": "passed"},`).

- [ ] **Step 6: Commit**

```bash
git add .omp
git commit -q -F - <<'EOF'
feat(omp): merge the charter_review gate into the code-review report

With Hermes gone, the charter review and the independent code review are
the same activity by the same role. The mandatory gate set is now ci,
coderabbit, and contract_conformance; Main posts the clean review report
on the draft PR, and a payload still carrying charter_review is rejected
as an extra gate.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 12: Stop OMP from installing skills from ~/.hermes

**Files:**
- Modify: `.omp/skills/cmtraceopen-dev/tests/test_write_project_config.py`
- Modify: `.omp/skills/cmtraceopen-dev/scripts/write_project_config.py`
- Modify: `.omp/config.yml`
- Delete: `.omp/skills/cmtraceopen-dev/scripts/setup_skillset.py`, `.omp/skills/cmtraceopen-dev/tests/test_setup_skillset.py`

- [ ] **Step 1: Change the expected config first**

In `.omp/skills/cmtraceopen-dev/tests/test_write_project_config.py`, replace:

```yaml
  enableAgentsProject: true
  customDirectories:
    - ~/.omp/agent/skillsets/cmtraceopen
```

with:

```yaml
  enableAgentsProject: false
```

- [ ] **Step 2: Run and confirm RED**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests -p 'test_write_project_config.py' 2>&1 | tail -3`
Expected: `FAILED`, including `test_validated_role_report_renders_exact_project_config` and `test_expected_config_matches_committed_project_config`.

- [ ] **Step 3: Change the template**

In `.omp/skills/cmtraceopen-dev/scripts/write_project_config.py`, make the same replacement: the three lines `  enableAgentsProject: true`, `  customDirectories:`, `    - ~/.omp/agent/skillsets/cmtraceopen` become the single line `  enableAgentsProject: false`.

- [ ] **Step 4: Make the committed config match**

In `.omp/config.yml`, make the same replacement.

- [ ] **Step 5: Delete the installer and its test**

Run: `git rm -q .omp/skills/cmtraceopen-dev/scripts/setup_skillset.py .omp/skills/cmtraceopen-dev/tests/test_setup_skillset.py`

- [ ] **Step 6: Verify**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests 2>&1 | tail -1`
Expected: `OK`

Run: `python3 .omp/skills/cmtraceopen-dev/scripts/write_project_config.py --check --report ~/.omp/agent/cmtraceopen/model-probe-report.json --repo-root "$PWD" --output .omp/config.yml`
Expected: `{"ok":true,"status":"unchanged"}`

Run: `git grep -n 'setup_skillset\|skillsets/cmtraceopen\|customDirectories' -- .omp .claude .Clairvoyance`
Expected: two lines in `.omp/skills/cmtraceopen-dev/SKILL.md` (preflight step 2 and the resolution table), which Task 13 removes.

- [ ] **Step 7: Commit**

```bash
git add .omp
git commit -q -F - <<'EOF'
feat(omp): load every skill from the repository

setup_skillset.py linked 15 skills from ~/.hermes into
~/.omp/agent/skillsets; most links had rotted and its --check failed.
Every skill the staff roles load is now checked in under .claude/skills,
so the installer, its test, and the customDirectories entry go. The
generated config and its template change together, so
write_project_config.py --check stays unchanged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 13: Route OMP to the in-repo execution charter and skills

**Files:**
- Modify: `.omp/skills/cmtraceopen-dev/SKILL.md`
- Modify: `.omp/AGENTS.md`
- Modify: `.Clairvoyance/staff/ceo-charter.md`
- Modify: `.Clairvoyance/kickoff-prompt.md`

- [ ] **Step 1: Rewrite the orchestrator preflight**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/tmp/cmtraceopen-vendor")
from edit_helpers import replace_between, replace_once

S = ".omp/skills/cmtraceopen-dev/SKILL.md"
CHARTER = ".claude/skills/cmtraceopen/references/execution-charter.md"
replace_once(S, "`~/.hermes/cmtrace-pm-charter.md`", f"`{CHARTER}`")
replace_between(
    S,
    "2. Run `python3 .omp/skills/cmtraceopen-dev/scripts/setup_skillset.py --check`",
    "4. Require the host print launcher",
    "2. Read `skill://cmtraceopen`, `skill://batch-issue-prs`, and `skill://branch-lane-verification`. "
    "Before dispatching a staff profile, also read and verify every skill in that profile's `autoloadSkills`. "
    "Every skill must resolve to the repository's `.claude/skills/<name>/SKILL.md`, with its files and Git "
    "index entries matching the current exact repository HEAD. A missing skill, a skill resolved from any "
    "other provider path, or a skill shadowed by another source blocks dispatch.\n",
)
replace_once(S, "\n4. Require the host print launcher", "\n3. Require the host print launcher")
replace_once(S, "\n5. Read `~/.omp/agent/cmtraceopen/model-probe-report.json`", "\n4. Read `~/.omp/agent/cmtraceopen/model-probe-report.json`")
replace_once(S, "\n6. Derive and store `PRIMARY_ROOT`", "\n5. Derive and store `PRIMARY_ROOT`")
replace_once(S, "\n7. Refresh the open issue", "\n6. Refresh the open issue")
replace_once(S, "Sourced Claude or Hermes commands express intent only.", "Sourced Claude commands express intent only.")

replace_once(
    ".omp/AGENTS.md",
    "must read its routed `~/.hermes/cmtrace-pm-charter.md` execution contract",
    f"must read its routed `{CHARTER}` execution contract",
)
replace_once(
    ".Clairvoyance/staff/ceo-charter.md",
    "The full operating contract lives at `~/.hermes/cmtrace-pm-charter.md` (checkpoint SHAs, recovery branch policy, per-slice gates, reporting style). "
    "The operator provisions this file and grants Main read access before the first orchestrated run; no orchestration or setup component creates or mutates it.",
    f"The full operating contract lives at `{CHARTER}` (recovery branch policy, per-slice gates, reporting style). "
    "It is checked in; no orchestration or setup component creates or mutates it outside a reviewed change.",
)
replace_once(
    ".Clairvoyance/kickoff-prompt.md",
    "then require and read the operator-provisioned `~/.hermes/cmtrace-pm-charter.md`;",
    f"then require and read `{CHARTER}`;",
)
print("ok")
EOF
```

Expected: `ok`.

- [ ] **Step 2: Verify the preflight reads cleanly**

Run: `awk 'NR>=13 && NR<=22 {print NR": "substr($0,1,100)}' .omp/skills/cmtraceopen-dev/SKILL.md`
Expected: steps numbered 1 through 6 with no gap, step 2 starting ``2. Read `skill://cmtraceopen` ``.

Run: `git grep -niE 'hermes|setup_skillset' -- .omp .Clairvoyance`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .omp/skills/cmtraceopen-dev/SKILL.md .omp/AGENTS.md .Clairvoyance/staff/ceo-charter.md .Clairvoyance/kickoff-prompt.md
git commit -q -F - <<'EOF'
docs(omp): route orchestration to the in-repo charter and skills

The preflight required ~/.hermes/cmtrace-pm-charter.md, which no longer
exists at that path, so orchestration had to fail closed. It now reads
the checked-in execution charter, and every skill resolves from
.claude/skills at the exact HEAD.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 14: Fix the staff autoload lists and close piece 1

**Files:**
- Modify: `.omp/agents/coder.md`
- Modify: `.omp/agents/tech-writer.md`

- [ ] **Step 1: Coder loads cmtraceopen in place of the retired scaffold skill**

In `.omp/agents/coder.md`, replace `autoloadSkills: [test-driven-development, systematic-debugging, cmtrace-scaffold-pipeline]` with `autoloadSkills: [test-driven-development, systematic-debugging, cmtraceopen]`.

- [ ] **Step 2: Tech writer drops mdbook-docs**

In `.omp/agents/tech-writer.md`, replace `autoloadSkills: [cmtraceopen, mdbook-docs]` with `autoloadSkills: [cmtraceopen]`.

- [ ] **Step 3: Verify piece 1 end to end**

Run: `node --test scripts/agent-context.test.mjs 2>&1 | tail -8`
Expected: `ℹ pass 3` and `ℹ fail 0`.

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests 2>&1 | tail -1`
Expected: `OK`

Run: `npx tsc --noEmit`
Expected: exit 0, no output.

Run: `git diff --check origin/main...HEAD && echo clean`
Expected: `clean`

- [ ] **Step 4: Commit**

```bash
git add .omp/agents/coder.md .omp/agents/tech-writer.md
git commit -q -F - <<'EOF'
fix(omp): point staff autoloads at checked-in skills

cmtrace-scaffold-pipeline became cmtraceopen's scaffold-pipeline
reference, and mdbook-docs has no mdBook in this repository to serve.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

---

## Piece 2: Claude staff subagents

### Task 15: Enforce each role's closed top-level output keys

**Files:**
- Modify: `.omp/skills/cmtraceopen-dev/tests/test_validate_agent_output.py`
- Modify: `.omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py`

- [ ] **Step 1: Add `tempfile` to the test imports**

In `test_validate_agent_output.py`, add the line `import tempfile` between `import importlib.util` and `import unittest`.

- [ ] **Step 2: Add a blocked payload per role**

Insert immediately above `class AgentOutputValidationTests(unittest.TestCase):`:

```python
def blocked_payloads() -> dict[str, dict[str, object]]:
    """One valid blocked payload per role, each with exactly its contract keys."""
    blockers = ["approved contract absent"]
    return {
        "coder": {
            "role": "coder",
            "phase": "blocked",
            "summary": "Missing contract",
            "implementation_proposals": [],
            "proposed_red_checks": [],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": blockers,
        },
        "ui-design": {
            "role": "ui-design",
            "phase": "blocked",
            "summary": "Missing contract",
            "edit_proposals": [],
            "proposed_browser_checks": [],
            "blockers": blockers,
        },
        "tech-writer": {
            "role": "tech-writer",
            "phase": "blocked",
            "summary": "Missing contract",
            "edit_proposals": [],
            "evidence_sources": [],
            "proposed_documentation_checks": [],
            "blockers": blockers,
        },
        "reducer-adversary": {
            "role": "reducer-adversary",
            "phase": "blocked",
            "adversarial_contracts": [],
            "fixture_proposals": [],
            "failure_scenarios": [],
            "blockers": blockers,
        },
        "code-review": {
            "role": "code-review",
            "phase": "blocked",
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "findings": [],
            "gate_states": {},
            "coverage": [],
            "blockers": blockers,
        },
        "reducer-contract": {
            "role": "reducer-contract",
            "phase": "blocked",
            "decisions": [],
            "evidence": [],
            "tests": [],
            "blockers": blockers,
        },
        "reducer-integration": {
            "role": "reducer-integration",
            "phase": "blocked",
            "heads": {},
            "gate_states": {},
            "blockers": blockers,
        },
    }


```

- [ ] **Step 3: Replace the future-role test and add the contract tests**

Replace the whole existing method `test_future_role_does_not_fall_through_to_integration` (from its `def` line through `validator.ROLES.remove(role)`) with:

```python
    def test_future_role_does_not_fall_through_to_integration(self) -> None:
        role = "future-role"
        with tempfile.TemporaryDirectory() as agents_dir:
            Path(agents_dir, f"{role}.md").write_text(
                "---\n"
                f"name: {role}\n"
                "output:\n"
                "  type: object\n"
                "  additionalProperties: false\n"
                "  required: [role, phase, blockers]\n"
                "---\n",
                encoding="utf-8",
            )
            original_agents_dir = validator.AGENTS_DIR
            validator.AGENTS_DIR = Path(agents_dir)
            validator.ROLES.add(role)
            validator.TEXT_LIST_KEYS[role] = ("blockers",)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    f"no validation contract for role: {role}",
                ):
                    validator.validate_output(
                        role,
                        {
                            "role": role,
                            "phase": "future-report",
                            "blockers": [],
                        },
                    )
            finally:
                validator.TEXT_LIST_KEYS.pop(role)
                validator.ROLES.remove(role)
                validator.AGENTS_DIR = original_agents_dir

    def test_output_keys_must_match_the_role_contract(self) -> None:
        for role, payload in blocked_payloads().items():
            with self.subTest(role=role, case="exact"):
                validator.validate_output(role, payload)
            with self.subTest(role=role, case="unexpected"):
                with self.assertRaisesRegex(
                    ValueError,
                    r"output keys must match its contract \(missing: \[\], "
                    r"unexpected: \['commands_run'\]\)",
                ):
                    validator.validate_output(
                        role,
                        {**payload, "commands_run": ["cargo test"]},
                    )
            for key in payload:
                if key == "role":
                    continue
                with self.subTest(role=role, case=f"missing {key}"):
                    missing = {k: v for k, v in payload.items() if k != key}
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"output keys must match its contract \(missing: \['{key}'\]",
                    ):
                        validator.validate_output(role, missing)

    def test_every_role_has_a_readable_output_contract(self) -> None:
        for role in sorted(validator.ROLES):
            with self.subTest(role=role):
                keys = validator.output_contract_keys(role)
                self.assertIn("role", keys)
                self.assertIn("phase", keys)
                self.assertIn("blockers", keys)
```

- [ ] **Step 4: Run and confirm RED**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests -p 'test_validate_agent_output.py' 2>&1 | grep -E 'AttributeError|^FAILED' | sort | uniq -c`
Expected: `AttributeError: module 'validate_agent_output' has no attribute 'AGENTS_DIR'` and `... no attribute 'output_contract_keys'`, then `FAILED`.

- [ ] **Step 5: Implement the check**

In `.omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py`:

1. Add the line `import re` between `import json` and `import sys`.

2. Insert immediately above `ROLES = {`:

```python
AGENTS_DIR = Path(__file__).resolve().parents[3] / "agents"
_TOP_LEVEL_REQUIRED = re.compile(r"^  required: \[([^\]]*)\]$")

```

3. Insert immediately above `def _list(payload: dict[str, object], key: str) -> list[object]:` (that is, right after the `_fail` function):

```python
def output_contract_keys(role: str) -> frozenset[str]:
    """Top-level keys of the role's `output` schema in `.omp/agents/<role>.md`.

    OMP enforces this schema at the provider; Claude subagents have no provider
    schema, so the broker enforces the closed top-level key set itself.
    """
    path = AGENTS_DIR / f"{role}.md"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        _fail(f"no output contract for role {role}: {path}")
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        _fail(f"output contract has no frontmatter: {path}")
    frontmatter = lines[1 : lines.index("---", 1)]
    if "output:" not in frontmatter:
        _fail(f"output contract has no output schema: {path}")
    block = []
    for line in frontmatter[frontmatter.index("output:") + 1 :]:
        if not line.startswith(" "):
            break
        block.append(line)
    if "  additionalProperties: false" not in block:
        _fail(f"output contract must close its top-level keys: {path}")
    required = [match for match in map(_TOP_LEVEL_REQUIRED.match, block) if match]
    if len(required) != 1:
        _fail(f"output contract needs exactly one top-level required list: {path}")
    keys = frozenset(name.strip() for name in required[0].group(1).split(","))
    if "" in keys:
        _fail(f"output contract has an empty required key: {path}")
    return keys


def _validate_contract_keys(role: str, payload: dict[str, object]) -> None:
    expected = output_contract_keys(role)
    missing = sorted(expected - payload.keys())
    unexpected = sorted(payload.keys() - expected)
    if missing or unexpected:
        _fail(
            f"{role} output keys must match its contract "
            f"(missing: {missing}, unexpected: {unexpected})"
        )


```

4. In `validate_output`, replace:

```python
    if payload.get("role") != role:
        _fail(f"role discriminator must equal {role}")
```

with:

```python
    if payload.get("role") != role:
        _fail(f"role discriminator must equal {role}")
    _validate_contract_keys(role, payload)
```

- [ ] **Step 6: Run and confirm GREEN**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests 2>&1 | tail -1`
Expected: `OK`

Run:

```bash
python3 -c 'import json; json.dump({"role": "code-review", "phase": "blocked", "head_sha": "a" * 40, "base_sha": "b" * 40, "findings": [], "gate_states": {}, "coverage": [], "blockers": ["x"], "commands_run": []}, open("/tmp/cmtraceopen-vendor/extra.json", "w"))'
python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role code-review --input /tmp/cmtraceopen-vendor/extra.json
```

Expected: `{"ok":false,"reason":"code-review output keys must match its contract (missing: [], unexpected: ['commands_run'])"}`

- [ ] **Step 7: Commit**

```bash
git add .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py .omp/skills/cmtraceopen-dev/tests/test_validate_agent_output.py
git commit -q -F - <<'EOF'
feat(omp): reject agent output whose top-level keys break the role contract

OMP relied on its provider to enforce each role's output schema; Claude
subagents have no provider-side schema, so an extra field such as a
claimed commands_run passed. The broker now reads the closed top-level
key set from .omp/agents/<role>.md, which stays the single source for
both runtimes.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 16: Parity guard (RED)

**Files:**
- Modify: `scripts/agent-context.test.mjs`

- [ ] **Step 1: Append the parity test**

Append to the end of `scripts/agent-context.test.mjs`:

```js

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
    assert.deepEqual(flowList(claude, "skills"), flowList(omp, "autoloadSkills"), claudePath);
    assert.ok(body(claudePath).includes(`\`${ompPath}\``), `${claudePath} must route to ${ompPath}`);
  }
  assert.deepEqual([...unmatched], [], "Claude subagents with no OMP staff role");
});
```

- [ ] **Step 2: Run and confirm RED**

Run: `node --test --test-name-pattern='OMP staff role' scripts/agent-context.test.mjs 2>&1 | grep -E 'has no|fail'`
Expected: `.omp/agents/code-review.md has no .claude/agents/cmtrace-code-review.md` and `ℹ fail 1`.

- [ ] **Step 3: Commit**

```bash
git add scripts/agent-context.test.mjs
git commit -q -F - <<'EOF'
test(agents): require a Claude subagent for every OMP staff role

Red until the cmtrace-* subagents land.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 17: Claude subagents, reasoning-heavy roles

**Files:**
- Create: `.claude/agents/cmtrace-coder.md`, `.claude/agents/cmtrace-code-review.md`, `.claude/agents/cmtrace-reducer-adversary.md`, `.claude/agents/cmtrace-reducer-contract.md`

- [ ] **Step 1: Create `.claude/agents/cmtrace-coder.md`**

```markdown
---
name: cmtrace-coder
description: CMTrace Open coder staff role. Use when Main needs one issue lane's change proposed RED-first as structured test, fixture, or production edit proposals for Main to apply; it never edits files itself.
tools: Read, Grep, Glob
model: sonnet
skills: [test-driven-development, systematic-debugging, cmtraceopen]
omitClaudeMd: true
---

You are the CMTrace Open `coder` staff role.

1. Read `.omp/agents/coder.md`. Its body is your governing instruction set; follow
   the charter and routes it names before acting.
2. The `output` schema in that file's frontmatter is the only permitted shape of your
   final message. Main checks it with
   `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role coder`.
3. End with that single JSON object and nothing else: no prose and no code fence.
```

- [ ] **Step 2: Create `.claude/agents/cmtrace-code-review.md`**

```markdown
---
name: cmtrace-code-review
description: CMTrace Open code-review staff role. Use when a cmtraceopen diff, branch, or PR needs its independent exact-head review against the repository's contracts and gates; returns a structured review report.
tools: Read, Grep, Glob
model: opus
skills: [cmtraceopen-code-review, coderabbit-review-loop, contract-scoped-review]
omitClaudeMd: true
---

You are the CMTrace Open `code-review` staff role.

1. Read `.omp/agents/code-review.md`. Its body is your governing instruction set; follow
   the charter and routes it names before acting.
2. The `output` schema in that file's frontmatter is the only permitted shape of your
   final message. Main checks it with
   `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role code-review`.
3. End with that single JSON object and nothing else: no prose and no code fence.
```

- [ ] **Step 3: Create `.claude/agents/cmtrace-reducer-adversary.md`**

```markdown
---
name: cmtrace-reducer-adversary
description: CMTrace Open reducer-adversary staff role. Use when a reducer change needs false-story attacks designed as adversarial RED contracts and fixture proposals; it never writes files.
tools: Read, Grep, Glob
model: opus
skills: [semantic-reducer-framework, semantic-reducer-development, test-driven-development]
omitClaudeMd: true
---

You are the CMTrace Open `reducer-adversary` staff role.

1. Read `.omp/agents/reducer-adversary.md`. Its body is your governing instruction set; follow
   the charter and routes it names before acting.
2. The `output` schema in that file's frontmatter is the only permitted shape of your
   final message. Main checks it with
   `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role reducer-adversary`.
3. End with that single JSON object and nothing else: no prose and no code fence.
```

- [ ] **Step 4: Create `.claude/agents/cmtrace-reducer-contract.md`**

```markdown
---
name: cmtrace-reducer-contract
description: CMTrace Open reducer-contract staff role. Use when a cross-lane reducer semantics question (evidence, identity, chronology, coverage, confidence, redaction) needs a contract decision grounded in the ADRs and evidence.
tools: Read, Grep, Glob
model: opus
skills: [semantic-reducer-framework, semantic-reducer-development, contract-scoped-review]
omitClaudeMd: true
---

You are the CMTrace Open `reducer-contract` staff role.

1. Read `.omp/agents/reducer-contract.md`. Its body is your governing instruction set; follow
   the charter and routes it names before acting.
2. The `output` schema in that file's frontmatter is the only permitted shape of your
   final message. Main checks it with
   `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role reducer-contract`.
3. End with that single JSON object and nothing else: no prose and no code fence.
```

- [ ] **Step 5: Verify the four files pass their share of the parity test**

Run: `git add .claude/agents && node --test --test-name-pattern='OMP staff role' scripts/agent-context.test.mjs 2>&1 | grep -E 'has no'`
Expected: `.omp/agents/reducer-integration.md has no .claude/agents/cmtrace-reducer-integration.md` (the first role not yet created; the four above pass).

- [ ] **Step 6: Commit**

```bash
git commit -q -F - <<'EOF'
feat(agents): add Claude subagents for coder, code-review, and reducer roles

Thin wrappers over .omp/agents/<role>.md, which stays the single source
of role instructions and output schemas.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 18: Remaining Claude subagents and the review skill's Claude path

**Files:**
- Create: `.claude/agents/cmtrace-reducer-integration.md`, `.claude/agents/cmtrace-tech-writer.md`, `.claude/agents/cmtrace-ui-design.md`
- Modify: `.claude/skills/cmtraceopen-code-review/SKILL.md`

- [ ] **Step 1: Create `.claude/agents/cmtrace-reducer-integration.md`**

```markdown
---
name: cmtrace-reducer-integration
description: CMTrace Open reducer-integration staff role. Use when Main needs a reducer lane's exact-head contract, conformance, review, native-lab, and mergeability evidence inspected and reported as separate gate states.
tools: Read, Grep, Glob
model: sonnet
skills: [branch-lane-verification, semantic-reducer-framework]
omitClaudeMd: true
---

You are the CMTrace Open `reducer-integration` staff role.

1. Read `.omp/agents/reducer-integration.md`. Its body is your governing instruction set; follow
   the charter and routes it names before acting.
2. The `output` schema in that file's frontmatter is the only permitted shape of your
   final message. Main checks it with
   `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role reducer-integration`.
3. End with that single JSON object and nothing else: no prose and no code fence.
```

- [ ] **Step 2: Create `.claude/agents/cmtrace-tech-writer.md`**

```markdown
---
name: cmtrace-tech-writer
description: CMTrace Open tech-writer staff role. Use when merged behavior needs documentation proposed from source, tests, fixtures, or real screenshots; returns structured edit proposals.
tools: Read, Grep, Glob
model: sonnet
effort: low
skills: [cmtraceopen]
omitClaudeMd: true
---

You are the CMTrace Open `tech-writer` staff role.

1. Read `.omp/agents/tech-writer.md`. Its body is your governing instruction set; follow
   the charter and routes it names before acting.
2. The `output` schema in that file's frontmatter is the only permitted shape of your
   final message. Main checks it with
   `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role tech-writer`.
3. End with that single JSON object and nothing else: no prose and no code fence.
```

- [ ] **Step 3: Create `.claude/agents/cmtrace-ui-design.md`**

```markdown
---
name: cmtrace-ui-design
description: CMTrace Open ui-design staff role. Use when an approved UI change needs structured edit proposals plus browser-check scenarios for Main to apply and run.
tools: Read, Grep, Glob
model: sonnet
skills: [frontend-design, test-driven-development, systematic-debugging]
omitClaudeMd: true
---

You are the CMTrace Open `ui-design` staff role.

1. Read `.omp/agents/ui-design.md`. Its body is your governing instruction set; follow
   the charter and routes it names before acting.
2. The `output` schema in that file's frontmatter is the only permitted shape of your
   final message. Main checks it with
   `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role ui-design`.
3. End with that single JSON object and nothing else: no prose and no code fence.
```

- [ ] **Step 4: Add the Claude path to the review skill**

Append to `.claude/skills/cmtraceopen-code-review/SKILL.md`:

```markdown

## Running it in Claude Code

Dispatch the `cmtrace-code-review` subagent with the target head, the base, and the
gate artifacts (CI result, the `coderabbit-review-loop` state snapshot, contract
conformance evidence). Write its final JSON to a temporary file and run
`python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role code-review --input <file>`;
only `{"ok":true,"role":"code-review"}` accepts it. Post a clean `review_report` on the
pull request as the charter review.
```

- [ ] **Step 5: Verify**

Run: `git add .claude && node --test scripts/agent-context.test.mjs 2>&1 | tail -8`
Expected: `ℹ pass 4` and `ℹ fail 0`.

- [ ] **Step 6: Commit**

```bash
git commit -q -F - <<'EOF'
feat(agents): complete the Claude staff subagents

Adds reducer-integration, tech-writer (Sonnet at low effort for the
scaffold tier), and ui-design, and documents how a Claude session runs a
charter review with cmtrace-code-review.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

### Task 19: Wire the guard into CI and verify everything

**Files:**
- Modify: `.github/workflows/cmtrace-ci.yml`

- [ ] **Step 1: Add the guard to the existing Node test step**

In `.github/workflows/cmtrace-ci.yml`, replace:

```yaml
        run: node --test scripts/ci-bundle-outputs.test.mjs scripts/ci-windows-provenance.test.mjs scripts/release-local-action-checkout.test.mjs scripts/ci-toolchain.test.mjs
```

with:

```yaml
        run: node --test scripts/ci-bundle-outputs.test.mjs scripts/ci-windows-provenance.test.mjs scripts/release-local-action-checkout.test.mjs scripts/ci-toolchain.test.mjs scripts/agent-context.test.mjs
```

- [ ] **Step 2: Run that exact CI command locally**

Run: `node --test scripts/ci-bundle-outputs.test.mjs scripts/ci-windows-provenance.test.mjs scripts/release-local-action-checkout.test.mjs scripts/ci-toolchain.test.mjs scripts/agent-context.test.mjs 2>&1 | tail -8`
Expected: `ℹ fail 0`.

- [ ] **Step 3: Prove the guard catches a regression**

Run: `printf '\nSee ~/.hermes/notes.md\n' >> soul.md && node --test scripts/agent-context.test.mjs 2>&1 | grep -E 'soul.md|fail '; git checkout -- soul.md`
Expected: a `soul.md:<line>: depends on Hermes` violation and `ℹ fail 1`; `soul.md` is restored afterwards.

- [ ] **Step 4: Full verification**

Run: `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests 2>&1 | tail -1`
Expected: `OK`

Run: `python3 .omp/skills/cmtraceopen-dev/scripts/write_project_config.py --check --report ~/.omp/agent/cmtraceopen/model-probe-report.json --repo-root "$PWD" --output .omp/config.yml`
Expected: `{"ok":true,"status":"unchanged"}`

Run: `npx tsc --noEmit`
Expected: exit 0.

Run: `git diff --check origin/main...HEAD && echo clean`
Expected: `clean`

- [ ] **Step 5: Live dispatch check (main session only; subagents cannot dispatch subagents)**

Start a new Claude Code session in this worktree so it loads `.claude/agents/`. Dispatch `cmtrace-code-review` with this brief: "Review head 558e93d5e8d1adc47c3b386809547db187b78229 against base ad29e01e7189783ae6e664e10d25f6bc367dfb60. No gate artifacts are supplied." Save its final message to `/tmp/cmtraceopen-vendor/review.json` and run:

`python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role code-review --input /tmp/cmtraceopen-vendor/review.json`

Expected: `{"ok":true,"role":"code-review"}` for a `phase: blocked` report whose blockers name the missing gate artifacts. If the output is not valid JSON or is rejected, record the reason; that is a finding for piece 3's design, not a reason to loosen the validator.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/cmtrace-ci.yml
git commit -q -F - <<'EOF'
ci: run the agent-context guard

Fails the build when agent context routes into Hermes or a workstation
path, when a loaded skill is not checked in, or when the OMP and Claude
staff definitions drift apart.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

- [ ] **Step 7: Clean up scratch**

Run: `rm -rf /tmp/cmtraceopen-vendor`

---

## Out of scope (tracked in the spec)

- Piece 3: Claude as Main for `cmtraceopen-dev`.
- `.Clairvoyance` dead parts (`staff/roger/`, `staff/theo/`, the empty `memory/index.md`).
- Running OMP's Python tests in CI.
