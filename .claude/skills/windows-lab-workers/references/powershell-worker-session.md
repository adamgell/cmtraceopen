# Validated PowerShell worker session pattern

This reference captures a reusable pattern validated while implementing a CMTrace Open lab worker.

## Repository setup

```bash
git worktree add -b feat/windows-lab-worker ../cmtraceopen-lab-worker HEAD
```

Inspect `AGENTS.md`, then inspect existing collection scripts and Pester tests before writing new tooling. Keep all worker files under a lab-only directory such as `scripts/lab/`.

## RED → GREEN sequence

Create `scripts/lab/tests/WindowsLabWorker.Tests.ps1` first and run:

```powershell
pwsh -NoLogo -NoProfile -Command "Invoke-Pester -Path ./scripts/lab/tests/WindowsLabWorker.Tests.ps1 -Output Detailed"
```

The first run should fail because the worker entry point is absent. The useful contract cases are: structured non-Windows `NOT_APPLICABLE`; recursive redaction and package hash; evidence-root containment rejection; explicit SSH username validation; all supported modes; and PowerShell AST parsing.

Implement `Invoke-WindowsLabWorker.ps1` with strict mode, a mode `ValidateSet`, one JSON envelope, and no stdout chatter. Re-run Pester after each vertical slice.

## Verification sequence

```powershell
Invoke-Pester -Path ./scripts/lab/tests/WindowsLabWorker.Tests.ps1 -Output Minimal
Invoke-ScriptAnalyzer -Path ./scripts/lab/Invoke-WindowsLabWorker.ps1 -Severity Error
git diff --check
```

For repositories containing a JavaScript application, install from the lockfile if dependencies are absent, then run:

```bash
npm ci
npm run test
npm run build
```

A successful run observed for the CMTrace Open repository was 6 Pester tests, 51 Vitest files / 649 tests, and a successful Vite build. Vitest emitted expected test stderr and Vite emitted existing chunk/dynamic-import warnings; neither changed the exit status.

## Implementation details worth preserving

- SSH transport must use `Invoke-Command -HostName`; default WSMan is not equivalent. Require `-UserName`; make `-KeyFilePath` optional. Offer WSMan only as an explicit transport.
- For non-Windows local execution, return JSON rather than throwing. This lets macOS/Linux CI validate the contract.
- For security probes, create only a disposable temp file and hard-link candidate, inspect reparse/final-path metadata, and remove the probe directory in `finally`.
- For provenance, hash and inspect only caller-supplied files/directories. Do not infer installer provenance or change files.
- For package hashing, recursively redact credential-shaped property names and URL query strings, sort dictionary/property keys, serialize compact canonical JSON, and hash UTF-8 bytes of the sanitized representation.
- Enforce `EvidenceRoot` containment on the normalized full input path before reading it.

## Reporting checklist

Return: worktree path, branch, commit SHA, changed files, exact test/build commands and results, and explicit limitations. Mention that no live target was contacted unless that actually happened. Report target permissions, CIM availability, remoting configuration, endpoint state, and pattern-based redaction as unverified limitations when applicable. Do not push or merge.
