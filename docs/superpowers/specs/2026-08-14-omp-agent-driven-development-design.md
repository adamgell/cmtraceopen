# OMP Agent-Driven Development Design

**Date:** 2026-08-14
**Status:** Approved design; implementation plan ready
**Owner:** Adam Gell
**Execution manager:** Main OMP session

## Goal

Turn the existing `.Clairvoyance/` staff charters, repository knowledge routers, and Adam's project-relevant agent skills into an executable OMP development system for CMTrace Open.

The system will be delivered in stages:

1. configure and validate LLM Gateway model routing;
2. add a native OMP project overlay and prove it through a self-hosting configuration PR;
3. run three independent issue-to-draft-PR lanes concurrently;
4. enable continuing autonomous board refill only after the three-lane production pilot passes.

The finished system may create worktrees and branches, commit and push coherent issue-scoped work, open or update draft PRs, request reviews, and drive CodeRabbit and independent review to clean. Adam remains the only merge authority.

## Non-goals

- No general-purpose scheduler, daemon, or separate orchestration service.
- No compatibility layer for Claude or Hermes commands. OMP maps their intent to native skills, agents, Hub jobs, and tools.
- No copying charter text into agent definitions. `.Clairvoyance/staff/` remains canonical.
- No committed live dashboard of branches, agents, or review state.
- No automatic merge, issue closure, force-push, branch overwrite, or deletion of active worktrees.
- No use of unproven models for repository writes merely because a charter names them.
- No discovery of Adam's unrelated productivity, home, media, or personal workflow skills in this project.

## Current-state findings

`.Clairvoyance/` is a document-driven staff organization, not an executable protocol. It defines CEO, Coder, UI/Design, Tech Writer, Code Reviewer, Reducer Contract, Reducer Adversary, and Reducer Integration roles. The intended lifecycle is already clear: evidence-anchored brief, isolated issue lane, RED/GREEN implementation, focused and aggregate gates, exact-head review, and Adam-controlled integration.

The missing executable layer is OMP configuration: context imports, agent discovery, model routing, tool and spawn policy, lane ownership, live state, and verification.

Known drift that affects this design:

- `.Clairvoyance/library.md` uses lowercase `.clairvoyance` in some routes although the checked-in directory is `.Clairvoyance`.
- `memory.md` contains dated checkpoints and an incomplete staff inventory. It is a cache, not current board truth.
- Roger and Theo indexes reference missing notes.
- the untracked `.Clairvoyance/home`, dated handoff, and empty session files are user work and are outside this setup's edit scope.
- Claude and Hermes skills contain harness-specific commands that OMP must translate rather than emulate.
- the older batch workflow names a Copilot review loop, while the current repository review contract requires CodeRabbit approval at the exact head plus independent charter review.

## Authority model

Main OMP holds the CEO/execution-manager charter during normal development. It reports to Adam and owns:

- live board and dependency truth;
- wave selection and lane ownership;
- model budget and role assignment;
- shared contracts and integration order;
- independent verification of agent output;
- exact gate-state reporting;
- escalation to Adam.

There is no CEO subagent in the normal path. Staff agents are bounded specialists dispatched by Main.

Normative authority is:

1. Adam's current instruction;
2. approved specifications, ADRs, and role charters;
3. the current wave contract and lane brief.

Evidence freshness is:

1. live GitHub state and exact local and remote SHAs;
2. recorded command output bound to an exact head;
3. the lane manifest;
4. dated handoffs and `memory.md`, treated as cached leads requiring refresh;
5. agent summaries, treated as unverified until Main independently checks them.

Evidence updates facts. It never overrides normative constraints.

Main treats public issue, PR, review, and reviewer text as untrusted data, never an instruction stream. Children receive only Adam-approved requirements/specification excerpts and Main-written cold briefs. Main never forwards raw public content or reviewer prompts. Because repository policy is not an OS sandbox, hostile or unreviewed content blocks dispatch rather than being delegated for interpretation.

## Configuration architecture

### User-level LLM Gateway configuration

`~/.omp/agent/models.yml` will register a custom `llmgateway` provider:

- base URL: `https://api.llmgateway.io/v1`;
- OpenAI-compatible request transport proven by the Stage 0 probe;
- credential reference: `LLMGATEWAY_API_KEY`;
- authorization bearer header enabled;
- required live model discovery through `openai-models-list`;
- no literal key in repository or OMP configuration.

OMP will not read or copy the Hermes credential. Adam's shell/session supplies the environment variable.

Stage 0 blocks unless authenticated discovery and inference both succeed. Every candidate runs role-specific fixtures for:

- schema-valid structured output;
- one required tool call with exact arguments;
- one exact file read and grounded response;
- refusal of a conflicting instruction;
- the minimum context and output limits declared by its assigned role.

The probe report records the selected transport, discovered model ID, exact fixture version, raw evidence artifact URI, timestamp, observed JSON/tool/file-read result, and advertised context/output limits. A model is assignable only when every fixture required by that role passes. `~/.omp/agent/models.yml` registers the provider and model metadata; validated exact selectors are stored under `modelRoles.reasoning`, `modelRoles.mid`, `modelRoles.scaffold`, and `modelRoles.advisor` in `.omp/config.yml`. If authenticated discovery is unsupported or a required fixture fails, Stage 0 remains blocked rather than accepting an unverified static candidate.

`openai-codex/gpt-5.6-sol` remains an explicit safety promotion for coordination, contract decisions, and review when a gateway model is unavailable or fails a probe. Project config sets `retry.modelFallback: false`, so inherited global fallback chains cannot silently route a writing role to an unproven model; promotion is a validated manual role-map decision.

### Project-level OMP overlay

The repository will add:

- `.omp/AGENTS.md` — native context entry point;
- `.omp/config.yml` — task, isolation, concurrency, role, and skill-discovery settings;
- `.omp/agents/*.md` — charter-backed staff agent definitions;
- `.omp/skills/cmtraceopen-dev/SKILL.md` — the project orchestration workflow and lane-state contract;
- `.omp/skills/cmtraceopen-dev/scripts/lane_state.py` — a Python-standard-library helper that validates the manifest schema, performs atomic updates and head/base invalidation, and compares complete changed-path sets with a lane allowlist. It does not create worktrees or mutate GitHub.

`.omp/AGENTS.md` imports:

- `@../AGENTS.md`;
- `@../soul.md`;
- `@../.Clairvoyance/library.md`.
- `@../.Clairvoyance/staff/ceo-charter.md`.

Importing root `AGENTS.md` is mandatory because native `.omp/AGENTS.md` otherwise wins context-file precedence at the same project depth and could shadow the repository rules.

The overlay references canonical files. It does not duplicate `soul.md`, `memory.md`, the routing indexes, or staff charters. Main reads the CEO charter and then its routed `~/.hermes/cmtrace-pm-charter.md` execution contract before loading orchestration.

## Skill discovery and role loading

OMP will not scan whole Hermes category directories. Those directories contain unrelated immediate children, and OMP custom-directory discovery exposes every immediate skill it finds.

User setup creates a curated root at `~/.omp/agent/skillsets/cmtraceopen/`. It contains symlinks only to the approved external skill directories:

- `branch-lane-verification`;
- `cmtrace-scaffold-pipeline`;
- `cmtraceopen`;
- `cmtraceopen-code-review`;
- `contract-scoped-review`;
- `github-code-review`;
- `github-issues`;
- `github-pr-workflow`;
- `mdbook-docs`;
- `semantic-reducer-development`;
- `semantic-reducer-framework`;
- `systematic-debugging`;
- `test-driven-development`;
- `windows-lab-workers`;
- `windows-remote-validation`.

The symlinks are user-local and are not committed. Stage 1 must prove that OMP resolves each symlinked skill and its referenced assets before any role autoloads it. `.omp/config.yml` points `skills.customDirectories` only at this curated root. It disables Claude user-level skill discovery for this project while retaining Claude project skills and Agents user/project skills, so unrelated personal Claude skills do not enter the project session.

OMP's native, Agents, Claude-project, and enabled plugin providers remain available. The project will not apply a global `includeSkills` allow-list that could hide built-in safety or process skills.

The enabled Claude-project provider supplies the checked-in `.claude/skills/batch-issue-prs`, `.claude/skills/frontend-design`, and `.claude/skills/coderabbit-review-loop` skills. These exact project paths, not similarly named user or plugin skills, satisfy the role table below. Stage 1 records each resolved source path.

`cmtraceopen-dev` treats commands embedded in sourced Claude or Hermes skills as intent, not executable syntax. It maps issue fan-out to OMP Task/Hub plus explicit worktrees, frontend verification to OMP's designer/browser surfaces, and CodeRabbit state to the checked-in `review_state.py` plus GitHub tools. An unsupported harness command blocks dispatch; OMP never guesses or shell-emulates it.

Agents autoload only the skills needed for their role:

| Role | Autoloaded skills |
|---|---|
| Main CEO | `cmtraceopen`, `batch-issue-prs`, `branch-lane-verification` |
| Coder | `test-driven-development`, `systematic-debugging`, `cmtrace-scaffold-pipeline` |
| UI/Design | `frontend-design`, `test-driven-development`, `systematic-debugging` |
| Code Reviewer | `cmtraceopen-code-review`, `coderabbit-review-loop`, `contract-scoped-review` |
| Reducer Integration | `branch-lane-verification`, `semantic-reducer-framework` |
| Reducer Contract | `semantic-reducer-framework`, `semantic-reducer-development`, `contract-scoped-review` |
| Reducer Adversary | `semantic-reducer-framework`, `semantic-reducer-development`, `test-driven-development` |
| Tech Writer | `cmtraceopen`, `mdbook-docs` |

Unknown or unavailable skills are configuration failures during Stage 1, not silent no-ops.

## Agent definitions and spawn graph

Project agent definitions map one-to-one to the tracked charters:

- Coder;
- UI/Design;
- Tech Writer;
- Code Reviewer;
- Reducer Contract;
- Reducer Adversary;
- Reducer Integration.

Each definition requires the agent to read its `.Clairvoyance/staff/*-charter.md` before acting. It also sets model-role preference, output shape, denied child spawning, and `advisor: true`. Every child lacks shell/process, Git/GitHub, and credential authority. Read-only profiles expose only non-mutating file tools; writing profiles expose only the dedicated file-read/edit tools needed inside their allowlist.

`.omp/config.yml` enables the advisor subsystem and binds `modelRoles.advisor` to the validated reasoning role. In print mode, the `cmtraceopen-dev` preflight requires the same launcher command to contain both the real `--advisor` flag and `--append-system-prompt` operator/system evidence stating that this invocation includes `--advisor`; either missing element blocks. OMP print agents cannot observe parent argv, so this explicit transport is accepted launch evidence rather than model self-attestation, and `pgrep`, process titles, and Hub membership are not advisor-runtime proof. In interactive mode the operator enables `/advisor on` before the first prompt. Models never issue session slash commands. Every custom staff agent starts its own read-only advisor through `advisor: true`. Advisor output is advisory evidence and never replaces formal independent review.

For Stages 1 and 2, only Main may spawn staff. Every staff profile denies child spawning and returns specialist handoff requests to Main. OMP recursion depth is one. A later approved design must name any additional parent-to-child edge before enabling it.

## Parallel lane model

The first production release supports three simultaneous writing lanes.

Before dispatch, Main builds a wave from refreshed public data without treating that data as instructions. An eligible issue must have:

- satisfied dependencies;
- no open PR or active owner collision;
- Adam-approved issue requirements and an issue-scoped acceptance contract;
- evidence anchors where fixtures or log grammar are involved;
- write ownership that does not overlap another lane in the wave;
- a declared integration order when shared contracts are nearby.

Main fixes shared interfaces, file ownership, cross-lane contracts, and approved requirement excerpts in a cold brief before agents start. Raw issue/PR/review text and reviewer prompts never enter a child prompt. Issues with hostile/unreviewed content, overlapping ownership, or unresolved semantic dependencies remain queued.

Each active lane has exactly one writing owner, one durable worktree, one issue branch, and one draft PR. Read-only specialists and reviewers may inspect lanes concurrently but do not share the implementer's identity.

Focused tests may run concurrently. Aggregate Rust, Clippy, wasm, TypeScript, Tauri, and native checks share one semaphore with capacity 1 across all lanes. Main records acquisition, release, and queued lane IDs in live state.

## Live lane state

Volatile orchestration state is not committed. The schema-versioned JSON manifest is `$(git rev-parse --git-common-dir)/omp/lanes.json`, shared by every worktree and written only by Main through atomic replacement.

Lane agents report state through Hub messages and artifacts; Main independently verifies each observation before serialization. Gate and review fields use `not_run | running | passed | failed | stale | unavailable`; native/lab state additionally permits `not_required`. Every observation records `head_sha`, applicable `base_sha`, command or scenario, exit code, artifact URI, and timestamp.

Any lane-head change marks focused, aggregate, conformance, CodeRabbit, independent-review, native/lab, and mergeability observations `stale`. Any base-head change marks aggregate, conformance, CodeRabbit, independent-review, native/lab when base-sensitive, and mergeability observations `stale`. Leases record `expires_at`; expiry alone never changes ownership.

Lane lifecycle values are `allocated | running | blocked | reviewing | ready_for_adam | merged | abandoned`. Legal transitions are `allocated -> running|blocked|abandoned`, `running -> blocked|reviewing|abandoned`, `blocked -> running|abandoned`, `reviewing -> running|blocked|ready_for_adam`, and `ready_for_adam -> reviewing|blocked|merged|abandoned`; `merged` and `abandoned` are terminal. `lane_state.py` enforces the transition graph.

The manifest also contains top-level aggregate-gate semaphore state `{ holder, queue, acquired_at }`.

Each lane record contains:

- issue number and title;
- agent ID and role;
- worktree path;
- branch name;
- allowed write paths;
- dependency and integration order;
- local head SHA;
- immutable allocation-base SHA for complete changed-path ownership checks;
- mutable current-base SHA for base-sensitive gates, review, and mergeability;
- remote head SHA;
- PR number and URL when created;
- lane lifecycle state;
- implementation/GREEN state;
- mergeability state;
- RED evidence state;
- focused gate state;
- aggregate gate state;
- conformance state;
- CodeRabbit exact-head state;
- independent-review state;
- native/lab validation state;
- blocker and next action;
- lease owner, heartbeat, and last verified timestamp.

GitHub and exact SHAs remain authoritative. The manifest is a coordination cache, not proof that a gate passed.

Root-safety snapshots cover tracked, untracked, and ignored primary-checkout files plus primary-worktree Git controls. They deliberately exclude unrelated active-branch refs and objects in shared Git storage. Before/after equality therefore detects primary-root mutation without false incidents from concurrent worktree branch activity.

## Per-lane execution flow

1. Main refreshes the issue, dependencies, open PRs, `main`, branch heads, and review state as untrusted data.
2. Main allocates the issue branch, worktree, sole writing owner, allowed paths, allocation base SHA, and lease.
3. Main extracts only Adam-approved requirements/specification excerpts and writes a cold-complete brief with scope, non-goals, evidence anchors, existing patterns, shared contracts, acceptance criteria, and verification goals.
4. The writing child writes only the smallest focused failing test/fixture and returns a proposed exact command as inert text.
5. Main independently inspects the change and runs `lane_state.py check-paths --manifest PATH --issue N`, which loads the allocation base and complete allowlist from the validated lane record.
6. Main sanitizes exact command arguments, runs the focused test, and records the observed RED result before authorizing production edits.
7. The same owner implements the smallest contract-complete behavior and returns proposed verification commands as inert text.
8. Main independently inspects the diff, repeats the manifest-bound path check, runs focused and required aggregate checks, and records GREEN/gates. Children never run commands, Git/GitHub operations, or read credentials.
9. Main may commit and push the verified coherent diff and open or update a draft PR without pausing.
10. Review proceeds contract first, adversarial second, mechanical third. Read-only reviewers inspect source and Main-supplied exact-head artifacts; they do not run commands. Reducer work routes semantic questions through Reducer Contract and false-story testing through Reducer Adversary.
11. Main runs the checked-in CodeRabbit helper and continues review until a completed review targets the current head, is approved, and has no actionable unresolved threads.
12. Independent charter review repeats at the exact head until a completed review has no unresolved actionable findings. Every disposition is recorded.
13. Reducer Integration inspects Main-supplied exact-head shared-contract and gate artifacts for reducer lanes. Main performs and records the actual integration checks. Separation from the writing owner remains mandatory.
14. Main reports distinct gate states to Adam. Adam decides whether to merge.

When an upstream shared contract changes, Main invalidates affected downstream conformance and review states and requires exact-head revalidation.

## Draft-PR autonomy boundary

Without an additional approval prompt, Main may:

- create issue worktrees and branches;
- assign and message staff agents;
- commit issue-scoped coherent changes;
- push issue branches;
- open or update draft PRs;
- post issue/PR status evidence;
- request CodeRabbit and independent review;
- dispatch the lane's recorded writing owner to apply technically verified review fixes, then independently inspect, run manifest-bound path checks and gates, commit, and push the resulting diff. Main does not edit production files. To transfer ownership, Main first blocks the lane, records the new sole owner, issues a cold-complete brief, and invalidates all affected gate and review states.

Main may not:

- merge a PR;
- close an issue;
- force-push or overwrite a branch;
- reset, discard, or delete user work;
- delete an active or unmerged worktree or branch.
- waive P0, P1, or semantic findings;
- claim native Windows validation without the exact code running there.

The narrow deletion exceptions are: a writing owner may remove an obsolete tracked file only when the approved brief requires it and the file is inside the sole-owner allowlist; Main may remove the Task 11 disposable smoke worktree/branch only after verifying it contains no valuable or unpushed work and only the allowed scratch change.

## Durable memory policy

Durable knowledge belongs under `.Clairvoyance/memory/` only when it remains useful after the current lane ends. A memory note must include:

- date;
- provenance;
- issue, PR, and exact SHA where applicable;
- the condition under which an agent should read it;
- the verified fact or decision;
- any staleness boundary.

The same change adds its `IF ... -> read ...` route to `.Clairvoyance/memory/index.md`. Memory changes receive normal review. Agent transcripts, guessed conclusions, and volatile branch/review status never become durable memory automatically.

OMP local memory and session artifacts may retain heuristic workflow context, but live repository and GitHub evidence always override them.

## Failure and recovery behavior

### Gateway or model failure

Provider discovery or inference failure blocks Stage 0. After Stage 0, a runtime gateway outage may promote only Main, Reducer Contract, Reducer Adversary, and Code Reviewer roles to `openai-codex/gpt-5.6-sol`, and only after the same role fixture passes on that selector. Coder, UI/Design, Tech Writer, and Reducer Integration writing work blocks until its validated model route recovers.

### Agent or job failure

Preserve the worktree, branch, transcript, artifacts, and last verified head. Mark the lane blocked with the concrete error and next diagnostic action. Partial output is not success evidence.

### Lease expiry

Main checks Hub/process state and independently inspects the worktree, branch, local head, and remote head before reclaiming a lane. A timestamp alone never authorizes takeover.

### Shared-contract conflict

Stop affected writers. Reducer Contract or Main resolves the question as contract, evidence, consequence, and executable test. Resume only after the batch contract and invalidated lane states are updated.

### Unexpected primary-checkout mutation

Stop the wave and preserve evidence. Do not revert, reset, delete, or stash unexpected user changes without Adam's approval. Root safety is an explicit acceptance invariant.

### Gate failure

Fix the source in the owning lane, rerun the failed focused check, then rerun every aggregate or review gate invalidated by the change. Never suppress or relabel a failure as a coverage state unless the product contract genuinely defines it that way.

### Native and lab validation

Every issue contract marks native/lab validation `required` or `not_required` and records the reason. A run records platform, exact head SHA, command or scenario, and artifact. A required state other than `passed` makes mergeability false. Reports use `validated` only for `passed`, never for `unavailable` or `not_required`.

### Review disagreement

The current code and named contract override summaries and bot prose. Findings must be verified against code with file and line, mechanism, and concrete failure scenario. Unresolved semantic questions escalate to Adam.

### Cleanup

Clean up only after integration status is verified and no unpushed commits or active review work remain. Active/unmerged lanes are preserved.

## Clairvoyance changes in scope

Stage 1 may update tracked `.Clairvoyance` files only to:

- normalize path casing;
- establish the authority and staleness rules required by this design;
- route OMP agent loading without duplicating charters.

The untracked `.Clairvoyance/home`, `.Clairvoyance/handoff-2026-08-12.md`, and empty session files are not modified or deleted. Broken Roger/Theo memory routes are reported separately and are not silently removed.

## Delivery stages

### Stage 0: LLM Gateway bootstrap

Acceptance evidence:

- OMP provider config contains no literal secret;
- environment-backed authentication succeeds without printing the key;
- authenticated live catalog discovery records every discovered candidate ID;
- every role-required probe passes with a versioned fixture and raw evidence artifact;
- validated exact selectors are written to project `modelRoles` in `.omp/config.yml`; `models.yml` remains provider/model registration only;
- unproven candidates remain unassigned.

### Stage 1: self-hosting OMP overlay

Implement the overlay in an isolated feature worktree and use its configuration change as the pilot draft PR.

A fresh OMP session must demonstrate:

- `@` context imports resolve;
- root `AGENTS.md` remains active;
- project-relevant personal skills are discoverable;
- all seven staff agent profiles plus Main's CEO role are present;
- agents resolve to validated models;
- `/advisor status` shows an active advisor for Main and for every spawned staff agent before writes;
- every declared autoload skill and referenced asset resolves from the curated root or its named project path;
- one representative native OMP path executes successfully for each directly autoloaded harness-specific project skill; any unsupported embedded command blocks the route;
- Main can dispatch authorized staff from cold briefs without exposing raw public instructions;
- restricted staff cannot spawn outside policy, run commands/Git/GitHub, or read credentials;
- Hub exposes lifecycle and transcripts;
- reviewer work remains file-read-only and consumes Main-supplied exact-head gate artifacts;
- a contained bashless writer performs one allowed file write in its assigned disposable lane while Main checks and cleans it;
- the primary checkout is unchanged before and after;
- independent charter review and CodeRabbit review target the exact PR head.

The PR remains unmerged until Adam acts.

### Stage 2: three-lane production pilot

From refreshed GitHub state, select three genuinely independent real issues. Create three worktrees, branches, agents, and draft PRs. Run them concurrently while staggering aggregate gates.

The pilot must non-destructively exercise at least one named failure-and-recovery path. Preserve the precondition, observed blocked state, error artifact, recovery action, and post-recovery state as evidence. All three lanes must finish unblocked with every required gate in its terminal passing state before refill is enabled. Each lane must produce:

- ownership and exact-head manifest state;
- RED and GREEN evidence;
- focused and aggregate gate output;
- CodeRabbit exact-head state;
- independent-review state;
- local/remote SHA comparison;
- root-safety proof;
- issue-scoped native/lab applicability and observed state.

Automatic refill uses only open issues in `adamgell/cmtraceopen` carrying the `agent-ready` label. Main excludes issues with an open PR and issues that fail the lane eligibility contract. Deterministic order is `priority:P1`, then `priority:P2`, then unlabeled priority, with oldest issue number first inside each tier. An unavailable query, conflicting priority labels, or missing acceptance/evidence contract blocks selection. Adding or removing `agent-ready`, changing priority labels, or changing this selector requires Adam's instruction.

Only after the three production-pilot lanes satisfy this contract may Main refill available capacity from that configured source.

## Verification strategy

Configuration is verified by running the actual surfaces rather than inventing a project-wide configuration test suite:

- OMP model discovery and live inference;
- fresh-session context and skill discovery;
- actual custom-agent dispatch through Hub;
- actual worktree-confined writes;
- actual draft PR and review-state flow;
- scope-relevant repository tests and gates;
- root-safety artifacts prove equality of the primary checkout's before/after HEAD SHA, index tree SHA, tracked-worktree diff hash, and sorted nonignored untracked path-plus-content hashes. Each lane wave stores the artifact URI in live state.

Focused tests for `lane_state.py` cover schema rejection, atomic replacement, legal and illegal lifecycle transitions, sole-owner transfer, lease-expiry non-takeover, lane/base-head invalidation, semaphore state, and tracked-plus-untracked allowlist comparison. No test asserts source text or incidental configuration formatting.

## Final reporting contract

Every CEO report separates:

- lane assigned;
- RED recorded;
- implementation green;
- focused gates green;
- aggregate gates green;
- conformance green;
- committed;
- pushed;
- draft PR opened;
- CodeRabbit approved at exact head;
- independent review clean;
- native/lab requirement and observed state;
- mergeable on current GitHub state;
- merged by Adam.

No intermediate state is summarized as "done."
