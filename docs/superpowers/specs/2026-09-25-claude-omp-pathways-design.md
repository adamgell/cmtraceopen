# Claude and OMP share one in-repo agent pathway

- **Date:** 2026-09-25
- **Status:** Approved in conversation; awaiting written-spec review
- **Branch:** `chore/agent-skill-in-repo`

## Problem

The CMTrace Open agent tooling depends on files that live on one workstation:

- The `cmtraceopen` agent skill and the OMP orchestrator route to
  `~/.hermes/cmtrace-pm-charter.md`, which no longer exists at that path.
- OMP staff agents autoload 15 curated skills through
  `~/.omp/agent/skillsets/cmtraceopen`, a directory of symlinks into
  `~/.hermes/skills/`. Most targets moved to a `default-old` Hermes profile, so
  the links dangle and `setup_skillset.py --check` fails today.
- Claude Code cannot use any OMP pathway: nothing under `.omp/` is visible to it.

A new dev machine therefore cannot run either runtime from a clone.

## Goals

1. Every skill, charter, and contract that Claude Code or OMP loads for this repo
   is checked into the repo.
2. Claude Code can dispatch the seven OMP staff roles with the same charters,
   output contracts, and skills OMP uses.
3. CI fails when an agent file routes outside the repo or when the two runtimes'
   staff definitions drift apart.

## Non-goals

- Hermes and Codex loading these skills. Only Claude Code and OMP are consumers.
- Claude acting as Main for the issue-to-draft-PR orchestration. That is piece 3,
  designed separately after piece 2 is verified.
- Moving OMP runtime state into the repo. The model-probe report under
  `~/.omp/agent/cmtraceopen/` is per-machine evidence that OMP regenerates, not a
  skill.

## Decisions

| Decision | Choice | Reason |
|---|---|---|
| Consumers | Claude Code and OMP only | Owner decision |
| Skill home | `.claude/skills/` only | Both consumers already read it; no mirror or sync needed. `.agents/` is retired. |
| Build order | Skills, then staff subagents, then orchestrator | Layered growth (`AGENTS.md`) |
| Staff model mapping | `@reasoning` to `opus`; `@mid` to `sonnet`; `@scaffold` to `sonnet` with `effort: low` | Haiku 4.5 is prior generation at half the price of Sonnet 5; the scaffold tier's known failure is invented log grammar, which the weakest model is most likely to produce |
| Symlinks | None | Windows checkouts break them, and `setup_skillset.py` already rejects them |
| Hermes as a reviewer | Removed | Owner decision: Hermes no longer runs or gates reviews. The `charter_review` gate key is dropped; the code-review agent's clean exact-head report is the charter review. |

## Baseline (Phase 1, done on this branch)

`.agents/skills/cmtraceopen/` was rewritten with repo-relative paths and gained
`references/execution-charter.md` (from the Hermes PM charter, stale checkpoint
SHAs and program order removed) and `references/scaffold-pipeline.md` (from the
Hermes `cmtrace-scaffold-pipeline` skill, with the CCM grammar corrected against
the fixture corpus). `soul.md` and `memory.md` lost every home-directory,
`/private/tmp`, local-model-server, and stale-checkpoint reference.

## Piece 1: skills in the repo

### Final `.claude/skills/` layout

| Skill | Source | Action |
|---|---|---|
| `cmtraceopen` | `.agents/skills/cmtraceopen` (Phase 1) | `git mv` to `.claude/skills/cmtraceopen`; update every path that names `.agents/skills/cmtraceopen`; drop its `metadata.hermes` block |
| `cmtraceopen-agent` | existing | Delete; `cmtraceopen` supersedes this thin loader |
| `cmtraceopen-code-review` | existing | Delete the "Delegating a review to Hermes" runbook; Hermes no longer reviews |
| `batch-issue-prs`, `coderabbit-review-loop`, `frontend-design` | existing | Unchanged |
| `branch-lane-verification` | `~/.hermes/profiles/default-old/skills/software-development/branch-lane-verification` | Vendor; rewrite the Hermes delegation and `hermes config` troubleshooting passages in `references/coderabbit-gates.md` and `references/recovery-branch-extraction.md` to runtime-neutral guidance |
| `contract-scoped-review` | `.../default-old/skills/software-development/contract-scoped-review` | Vendor; drop `metadata.hermes` |
| `semantic-reducer-framework` | `.../default-old/skills/.archive/semantic-reducer-framework` | Vendor; drop `metadata.hermes`; reword its two "Hermes mechanisms" passages to name the repository's own charters and skills |
| `semantic-reducer-development` | `.../default-old/skills/.archive/semantic-reducer-development` | Vendor; drop `metadata.hermes` |
| `test-driven-development` | `NousResearch/hermes-agent@4a2198bf5124f0c4d915cb958f141116ae8607f0` `skills/software-development/test-driven-development` | Vendor; replace the "Hermes Agent Integration" section (Hermes `terminal()` and `delegate_task()` calls) with runtime-neutral guidance; add a `LICENSE` notice (MIT, Nous Research; adapted from obra/superpowers, MIT; modified) |
| `systematic-debugging` | same commit, `skills/software-development/systematic-debugging` | Same as above, plus the inline `read_file`/`search_files` tool instructions become plain actions with `git grep` examples |
| `windows-lab-workers` | `.../default-old/skills/.archive/windows-lab-workers` | Vendor; drop `metadata.hermes` and the Hermes `author` line |
| `windows-remote-validation` | `.../default-old/skills/.archive/windows-remote-validation` | Vendor with the lab inventory replaced by placeholders (`<cm-server-host>`, `<client-host>`, `<lab-address>`, `<lab-account>`, `<ssh-identity-file>`); the repo is public |

Every vendored source was matched against the tree digest pinned in
`setup_skillset.py` before this design was approved, so the vendored content is
exactly what OMP last approved, before the edits listed above.

### Not vendored

| Skill | Reason |
|---|---|
| `cmtrace-scaffold-pipeline` | Replaced by `cmtraceopen/references/scaffold-pipeline.md`; the coder role autoloads `cmtraceopen` instead |
| `github-code-review`, `github-issues`, `github-pr-workflow` | No pathway autoloads them; `gh`, `batch-issue-prs`, and `coderabbit-review-loop` cover the work; they read tokens from `~/.hermes/.env` |
| `mdbook-docs` | The repo has no `book.toml`; removed from the tech-writer autoload |

### OMP retargeting

- Delete `.omp/skills/cmtraceopen-dev/scripts/setup_skillset.py` and
  `.omp/skills/cmtraceopen-dev/tests/test_setup_skillset.py`. Their only job was
  installing external skills, and no external skills remain.
- `.omp/config.yml`: remove `skills.customDirectories`; set
  `enableAgentsProject: false`. The file is generated: change the template in
  `scripts/write_project_config.py` and the expected text in
  `tests/test_write_project_config.py`, then make the committed file match, so
  `write_project_config.py --check` still reports `unchanged`.
- `.omp/skills/cmtraceopen-dev/SKILL.md`: remove preflight step 2; every row of
  the approved resolution table becomes repository `.claude/skills/<name>/SKILL.md`,
  authenticated by the exact repository HEAD like the existing Claude-project rows;
  the execution-contract route becomes
  `.claude/skills/cmtraceopen/references/execution-charter.md`.
- Same execution-contract route in `.omp/AGENTS.md`,
  `.Clairvoyance/staff/ceo-charter.md`, and `.Clairvoyance/kickoff-prompt.md`.
- `.omp/agents/coder.md`: autoload `cmtraceopen` in place of
  `cmtrace-scaffold-pipeline`. `.omp/agents/tech-writer.md`: drop `mdbook-docs`.

### Hermes review gate removal

Hermes no longer runs or gates reviews. Today a posted Hermes charter review is a
separate merge gate that the code-review agent reports as `charter_review`. With
Hermes gone, the charter review and the independent code review are the same
activity by the same role, so the gate merges into the review:

- Drop `charter_review` from `INDEPENDENT_REVIEW_GATE_STATES` in `lane_state.py`,
  from the `gate_states` schema in `.omp/agents/code-review.md`, and from the
  gate strings in `.omp/skills/cmtraceopen-dev/SKILL.md` step 8 and the readiness
  paragraph. The mandatory gate set becomes `ci`, `coderabbit`,
  `contract_conformance`.
- `cmtraceopen-dev` step 8 gains one duty: Main posts the clean `review_report` on
  the draft PR as the charter review.
- `.Clairvoyance/staff/code-review-charter.md`: remove the Hermes gate paragraph
  and the "posted Hermes charter review" gate; state that a clean report from this
  charter's reviewer, posted by Main, is the charter review.
- Tests: `test_lane_state.py` and `test_validate_agent_output.py` drop
  `charter_review` from their clean fixtures, and a payload that still carries
  `charter_review` is rejected as an extra gate.

## Piece 2: Claude staff subagents

### Files

One file per OMP role at `.claude/agents/cmtrace-<role>.md`:
`cmtrace-coder`, `cmtrace-code-review`, `cmtrace-reducer-adversary`,
`cmtrace-reducer-contract`, `cmtrace-reducer-integration`, `cmtrace-tech-writer`,
`cmtrace-ui-design`. The prefix keeps them distinct from generic agents and the
`/code-review` skill.

Each file has this frontmatter:

```yaml
---
name: cmtrace-<role>
description: <when Main should delegate to this role>
tools: Read, Grep, Glob
model: <per mapping>
effort: low            # tech-writer only
skills: [<same names as the OMP autoloadSkills>]
omitClaudeMd: true
---
```

and a body that does three things: read `.omp/agents/<role>.md`, treat its body
as the governing instructions and its frontmatter `output` schema as the only
permitted shape of the final message, and return that JSON object alone.
`omitClaudeMd` keeps `CLAUDE.md`'s verification directives (which require running
commands) away from a read-only agent; each charter already routes to `CLAUDE.md`
where it matters.

### Mapping

| OMP role | `model` | `skills` |
|---|---|---|
| `coder` | `sonnet` | `test-driven-development`, `systematic-debugging`, `cmtraceopen` |
| `code-review` | `opus` | `cmtraceopen-code-review`, `coderabbit-review-loop`, `contract-scoped-review` |
| `reducer-adversary` | `opus` | `semantic-reducer-framework`, `semantic-reducer-development`, `test-driven-development` |
| `reducer-contract` | `opus` | `semantic-reducer-framework`, `semantic-reducer-development`, `contract-scoped-review` |
| `reducer-integration` | `sonnet` | `branch-lane-verification`, `semantic-reducer-framework` |
| `tech-writer` | `sonnet`, `effort: low` | `cmtraceopen` |
| `ui-design` | `sonnet` | `frontend-design`, `test-driven-development`, `systematic-debugging` |

OMP's `advisor: true` has no Claude equivalent; `.omp/WATCHDOG.md` priorities
become Main's responsibility in piece 3.

### Validator change

OMP relies on its provider to enforce each role's `output` schema, and
`validate_agent_output.py` checks only the finer rules. It never checks top-level
keys. Claude has no provider-side schema, so an extra field would pass today.

`validate_agent_output.py` will read the role's top-level `output.required` list
and `output.additionalProperties: false` from `.omp/agents/<role>.md` at run
time and reject any payload whose key set differs. The agent file stays the single
source for both runtimes. New cases in `tests/test_validate_agent_output.py`
cover a missing required key and an extra key for every role.

## Guard

A new `scripts/agent-context.test.mjs`, added to the existing
`node --test scripts/...` step in `.github/workflows/cmtrace-ci.yml`, asserts:

1. No tracked file (`git ls-files`) under `.claude/skills/`, `.claude/agents/`,
   `.omp/`, or `.Clairvoyance/`, and neither `soul.md`, `memory.md`, nor
   `library.md`, contains `hermes` (any case), `/Users/`, or `/private/`. `LICENSE`
   files are exempt because they record where vendored text came from.
   Tracked-only matters because `.Clairvoyance/` also holds ignored app-session
   files.
2. `.agents/` does not exist.
3. Every name in an `.omp/agents/*.md` `autoloadSkills` list and every name in a
   `.claude/agents/*.md` `skills` list has `.claude/skills/<name>/SKILL.md`.
4. Every `.omp/agents/<role>.md` has `.claude/agents/cmtrace-<role>.md` and the
   reverse; each Claude agent's `tools` is exactly `Read, Grep, Glob`; its `model`
   and `effort` match the mapping for the OMP tier; its `skills` equal the OMP
   `autoloadSkills`.

## Verification

- `node --test scripts/agent-context.test.mjs` passes, and fails when a
  `~/.hermes` route or a skills-list mismatch is introduced.
- `python3 -m unittest discover -s .omp/skills/cmtraceopen-dev/tests` passes
  locally (these tests are not in CI today).
- The scratch closure check from Phase 1 reports no external routes from
  `.claude/skills/cmtraceopen/SKILL.md`.
- `npx tsc --noEmit` passes.
- Dispatch `cmtrace-code-review` against a merged commit and confirm
  `validate_agent_output.py --role code-review` accepts its output, and rejects it
  after adding an extra top-level key.

## Piece 3 (later)

Claude as Main for `cmtraceopen-dev`: dispatch the `cmtrace-*` subagents with the
Agent tool, keep `lane_state.py`, `run_repo_check.py`, `check_command_policy.py`,
and `validate_agent_output.py` as the shared brokers, and replace or drop the
OMP-only preflight steps (advisor launch evidence, the model-probe report). Its
own design follows piece 2's verification.

## Open items

- `.Clairvoyance` dead parts: `staff/roger/` and `staff/theo/` route only to
  notes that are not in the repo, and `memory/index.md` is empty. Removing them
  and their `.Clairvoyance/library.md` routes is a separate change awaiting
  approval.
- OMP's Python tests are not run by CI.
