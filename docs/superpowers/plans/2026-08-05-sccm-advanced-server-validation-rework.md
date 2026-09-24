# SCCM Advanced Server Validation Rework Plan

**Goal:** Close the two independent P1 server-validation gaps on PR #500: production discovery must emit only genuinely observed advanced-source facts, and Windows capture must bind every read to a validated opened handle.

**Architecture:** Keep discovery facts derived from the existing trusted native role/root observations through a closed source allowlist. Keep capture path policy and I/O separate: snapshot the approved path identity, open with Windows non-follow semantics, validate the handle's identity, final path, root membership, link count, and reparse state, and only then read through that same handle. No compatibility or permissive fallback path is allowed.

**Tech Stack:** Rust 1.88, Windows API bindings already present in the workspace, Cargo tests, Tauri v2, React/TypeScript, GitHub Actions, `gh` CLI.

## Task 1: Production discovery facts

- [x] Add tests against the production environment assembly for complete, missing, partial, and tampered native observations.
- [x] Derive advanced facts from a closed role/root allowlist, emitting `Observed` only when both trusted observations match.
- [x] Prove test-only fact injection cannot satisfy the production assembly contract.

## Task 2: Opened-handle validation

- [x] Add deterministic seam tests for path swap, identity mismatch, final-path mismatch, hardlink/external target, reparse point, root escape, and zero reads before validation.
- [x] On Windows, open without following a reparse point and validate stable file identity, link count, final resolved path/root membership, and reparse state before reading.
- [x] Preserve byte/line budgets, provenance, and `parser_eligible=false` behavior.

## Task 3: Verification

- [x] Run focused privacy, intake, native discovery, advanced capture, UI, timestamp, full parser/app, clippy, TypeScript, scoped rustfmt, and diff gates.
- [x] Record any known repository-wide formatting baseline failure without changing unrelated files. Full `cargo fmt --all -- --check` remains red only on the pre-existing Intune, Jamf, and elevation drift; the three changed Rust files pass scoped rustfmt.

## Task 4: Freeze and hosted evidence

- [ ] Commit and push a new frozen SHA to `codex/sccm-advanced-server-capture`.
- [ ] Wait for exact-head hosted CI, download that run's MSI with `gh`, and independently record filename, size, SHA-256, workflow/run provenance.
- [ ] Post a sanitized evidence pack to PR #500. Do not merge and do not post raw SCCM evidence.
