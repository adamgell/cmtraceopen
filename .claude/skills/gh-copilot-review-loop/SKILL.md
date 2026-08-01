---
name: gh-copilot-review-loop
description: Address all actionable GitHub pull-request feedback, push verified fixes, resolve handled threads, request another GitHub Copilot review, and repeat until a completed review cycle produces no new comments. Use for requests such as "address PR comments and re-review until clean," "keep cycling Copilot review," or "fix every review comment and request another review."
---

# GitHub Copilot Review Loop

Drive a pull request from its current review state to one verified clean Copilot cycle. Preserve thread state and require evidence that the final review ran against the latest head commit.

## Workflow

1. Confirm `gh auth status`, the current branch, a clean understanding of the worktree, and the associated open PR.
2. Run `scripts/review_state.py` from the skill directory. Record `head_sha`, `copilot_review_count`, unresolved thread IDs, and the latest Copilot review commit.
3. Treat unresolved, non-outdated Copilot threads as actionable unless they are informational, duplicates, incorrect, or conflict with requirements. If the user said to address everything, fix all valid threads; otherwise present a numbered selection.
4. Implement the smallest behavior-preserving fixes. Add or update behavioral tests for regressions. Do not resolve threads while tests are failing.
5. Run checks proportional to the diff, inspect `git diff --check`, commit intentionally, and push the PR branch without force-pushing.
6. Reply to each handled thread with the fix commit and verification, then resolve it with GitHub's `resolveReviewThread` GraphQL mutation. Do not resolve rejected or ambiguous feedback; explain it instead.
7. Re-run `scripts/review_state.py`. Confirm the pushed `head_sha`, zero remaining actionable threads from the cycle, and the current Copilot review count.
8. Request Copilot again through GitHub's requested-reviewers API with the special reviewer login `copilot-pull-request-reviewer[bot]`. Record the request time, head SHA, and baseline Copilot review count.
9. Poll without blocking longer than 60 seconds at a time. A review cycle is complete only when the Copilot review count increases and the newest review targets the recorded head SHA.
10. Fetch thread-aware state again. If new actionable comments exist, repeat from step 3. Stop only when the new completed review targets the latest head SHA and adds no actionable comments.

## Commands

Inspect state:

```bash
python3 .claude/skills/gh-copilot-review-loop/scripts/review_state.py
```

Optionally target a specific PR instead of the current branch's:

```bash
python3 .claude/skills/gh-copilot-review-loop/scripts/review_state.py --repo jorgeasaurus/agent-skills --pr 123
```

Request Copilot review:

```bash
gh api --method POST "repos/{owner}/{repo}/pulls/{pr}/requested_reviewers" --input - <<'JSON'
{"reviewers":["copilot-pull-request-reviewer[bot]"]}
JSON
```

Resolve a handled thread:

```bash
gh api graphql -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}' -f id="$THREAD_ID"
```

Prefer the installed GitHub connector for PR metadata, replies, and ordinary PR mutations. Use `gh api graphql` for review-thread resolution and thread-aware state.

## Clean-Cycle Gate

Do not claim completion from resolved old threads alone. Require all of the following:

- local and remote branch heads match;
- relevant checks pass;
- every handled thread is resolved or explicitly dispositioned;
- a new Copilot review completed after the last review request;
- that review is anchored to the latest head SHA;
- it produced no new actionable threads.

Report the PR URL, final commit, review-cycle count, resolved threads, verification, and any non-actionable feedback left open.

## Provenance

Adapted from [`gh-copilot-review-loop`](https://github.com/jorgeasaurus/agent-skills/tree/72ef3d3322ee0ac8db02cf324c2030f13d3bb68d/gh-copilot-review-loop) by Jorge Suarez (`jorgeasaurus`). The upstream repository declares the work under the MIT License in its README. This copy pins upstream commit `72ef3d3322ee0ac8db02cf324c2030f13d3bb68d`; see `LICENSE.txt` in this directory for the preserved license and attribution.

Local changes use the repository-relative state-script path, add the explicit `--repo`/`--pr` example, and format the reviewer-request command on one line. `scripts/review_state.py` is byte-identical to the pinned upstream version.
