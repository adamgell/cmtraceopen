---
name: windows-lab-workers
description: "Use for deterministic Windows lab workers and evidence."
version: 1.0.0
license: MIT
platforms: [windows, macos, linux]
---

# Deterministic Windows Lab Workers

Use this skill when building or reviewing repository-local lab tooling that probes Windows endpoints, runs over PowerShell remoting/SSH, collects provenance or security evidence, and packages sanitized JSON. Keep this class of tooling outside production application commands and IPC behavior.

## Contract-first workflow

1. Read repository `AGENTS.md` and inspect existing collection/evidence scripts and tests before designing a new worker.
2. Create a fresh isolated git worktree and branch from the requested repository state. Never edit the root checkout for delegated lab work.
3. Define a small JSON contract before implementation. At minimum include a schema version, operation/mode, `PASS`/`REWORK`/`NOT_APPLICABLE` status, target, ordered findings, and sanitized errors.
4. Write a focused Pester contract test first. Run it and confirm a meaningful RED failure before adding the worker.
5. Implement the smallest end-to-end slice, then add operations vertically: discovery, security probes, provenance, and packaging. Preserve deterministic ordering and bounded scope.
6. Run Pester, PowerShell parser validation, and ScriptAnalyzer errors. Run repository `npm run test` and `npm run build` when the worktree has a JS application, installing dependencies from the checked-in lockfile if needed.
7. Review `git diff --check`, verify the worktree is clean, commit the branch, and report the exact worktree path, branch, SHA, changed files, tests, build results, and limitations. Do not push or merge.

## Worker design rules

- Prefer a single PowerShell entry point with a `ValidateSet` for supported modes and `Set-StrictMode -Version Latest`.
- Support local execution for contract tests and explicit remote execution. For SSH, use PowerShell remoting's `Invoke-Command -HostName`, require an explicit username, and allow an optional key path. Keep WSMan as an explicitly selected alternative rather than silently changing transport.
- Make non-Windows execution return structured `NOT_APPLICABLE` JSON rather than emitting an unstructured platform error.
- Keep probes bounded and safe. Disposable security probes may create a uniquely named temporary file and attempt a hard-link/reparse/final-path observation, but must clean up in `finally`; do not mutate production paths or remediate the endpoint.
- Discovery should use read-only CIM/registry/path checks and identify SCCM/ConfigMgr and Intune locations without assuming they exist.
- Provenance should operate only on explicitly supplied paths, report presence/final path/hash/signature metadata, and never infer or invent installer provenance.
- Packaging must enforce input containment when an evidence root is provided, sanitize recursively, and hash canonical sanitized content. Redact URL query strings and common credential-bearing keys (`password`, `secret`, `token`, `apiKey`, `SAS`, etc.) before writing evidence.
- Emit one machine-readable JSON result. Avoid transcript/status chatter on stdout; errors belong in the JSON envelope and exit nonzero for `REWORK`.

## Testing and verification

Pester tests should exercise at least:

- non-Windows `NOT_APPLICABLE` behavior;
- every supported mode's schema and status envelope;
- recursive secret/URL-query redaction and stable package hashing;
- evidence-root path traversal rejection;
- SSH username validation without contacting a target;
- PowerShell parser validity and strict mode.

A passing Pester suite does not prove target permissions or endpoint state. State that live-lab validation limitation explicitly. Repository-wide tests/builds can expose unrelated warnings; report warnings separately from failures.

## Pitfalls

- Do not call a worker "SSH-based" while actually using default WSMan. Make transport explicit and test the SSH argument validation.
- Do not include timestamps, random IDs, unordered hash-table traversal, or environment-dependent paths in the canonical evidence digest unless they are explicitly part of the evidence contract.
- Do not treat redaction as perfect secrecy. Pattern-based sanitization is conservative but incomplete; document that limitation.
- Do not add production Tauri commands merely because the lab worker collects similar data. The worker is an external lab harness.
- Do not hardcode a lab hostname, account, or credential into the worker. Pass target and authentication explicitly.
- Do not claim live validation when only local/non-Windows contract tests ran.

## Reusable detail

See `references/powershell-worker-session.md` for a validated implementation shape, test command sequence, and the dependency-install verification note from the first worker implementation.
