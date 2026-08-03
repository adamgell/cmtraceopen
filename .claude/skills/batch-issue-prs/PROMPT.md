# Starter prompts

Copy one of these into a fresh chat.

## Standard batch

```
Use the batch-issue-prs skill.

Work a batch of open issues in this repo. Pick 2-4 that share a seam and have no
open PR against them, tell me which you picked and why before you start building.

One branch and one PR per issue, off origin/main. Establish a green baseline
before you touch anything.

Then for each PR in turn, converging one before starting the next:
  /code-review
  /coderabbit:autofix
  /loop the gh-copilot-review-loop skill until a cycle returns no new comments

Any subagent that writes code gets isolation: "worktree". Report what you did NOT
finish as plainly as what you did.
```

## Named issues

```
Use the batch-issue-prs skill.

Implement #<N>, #<N>, and #<N>. Read each issue in full first — they carry
acceptance criteria and required fixture matrices, and I want those met, not
approximated. If an issue is blocked or needs a corpus you don't have, build
everything that isn't blocked and tell me exactly what you left and why.

One branch and one PR per issue off origin/main. Per-PR review loop:
/code-review, then /coderabbit:autofix, then /loop gh-copilot-review-loop
until clean. Subagents that write code get isolation: "worktree".
```

## Review-only pass

```
Use the batch-issue-prs skill.

Don't write new features. Take the open PRs I own and drive each to a clean
review cycle: /code-review, /coderabbit:autofix, then /loop the
gh-copilot-review-loop skill until a completed cycle produces no new comments.

Re-run the real gates before you call any PR clean, and show me the output.
Tell me which review comments you rejected and why.
```

## Overnight / unattended

```
Use the batch-issue-prs skill. I'm going to be away, so work autonomously and
don't block on me.

Pick a batch of open issues with no PR against them. Build, review, and iterate.
Where a decision is genuinely mine to make, pick the reasonable default, state
the assumption in the PR body, and keep going rather than stopping.

Open PRs as drafts so nothing merges without me. Leave me one summary at the end
with: what landed, what's still open, what you assumed, and anything you hit that
needs a real Windows box or a log corpus you didn't have.
```
