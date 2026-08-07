# Workspace Knowledge Library

This is a routing index for Clairvoyance Staff, not a reading list.
WikiLinks in this file resolve to documents under `.clairvoyance/Docs/` or the repo root.
If no route matches, note the missing topic, write the doc when you learn it, and add the route in the same turn.

## When to read what

- IF full repo path/subject catalog → read [[library.md]] (repo root)
- IF agent conventions / no-compat / phased edits → read [[AGENTS.md]]
- IF build commands / module map / architecture → read [[CLAUDE.md]]
- IF product features / install / Full vs Lite → read [[README.md]]
- IF ESP design or evidence contract → read [[docs/superpowers/specs/2026-07-15-esp-diagnostics-workspace-design.md]]
- IF reducer semantics / correlation / chronology / confidence / conformance → read [[docs/superpowers/specs/2026-08-07-reducer-framework-v1-design.md]]
- IF planning or sequencing Reducer Framework v1 → read [[docs/superpowers/plans/2026-08-07-reducer-framework-v1.md]]
- IF cross-lane reducer architecture decision → read [[.Clairvoyance/staff/reducer-contract-charter.md]] and reducer ADRs
- IF adversarial reducer review / false-story testing → read [[.Clairvoyance/staff/reducer-adversary-charter.md]]
- IF reducer restack / exact-head conformance verification → read [[.Clairvoyance/staff/reducer-integration-charter.md]]
- IF log format reverse engineering → read [[references/REVERSE_ENGINEERING.md]]
- IF design system / Fluent tokens → read [[docs/design-system/SKILL.md]]
- IF evidence collection scripts → read [[scripts/collection/README.md]]
- IF reducer semantics / adversarial review → read [[docs/superpowers/specs/2026-08-07-reducer-framework-v1-design.md]], [[docs/architecture/decisions/README.md]], and [[docs/architecture/reducer-framework-v1-store-inventory.md]]
- IF parser crate layout / pure domain → read [[crates/cmtraceopen-parser/README.md]]
- IF loading the CMTrace Open specialist agent → read [[soul.md]] and [[memory.md]]

## Quick Reference

|| Path | Subject | Description |
||------|---------|-------------|
|| `library.md` (repo root) | Full catalog | Path/subject index for entire cmtraceopen tree |
|| `CLAUDE.md` | Architecture | Frontend/backend maps, commands, testing |
|| `AGENTS.md` | Agent rules | Simplicity and growth rules |
|| `soul.md` | Agent soul | CMTrace Open specialist identity and rules |
|| `memory.md` | Agent memory | Durable facts, checkpoints, execution order |
|| `src/` | Frontend | React workspaces, stores, components |
|| `src-tauri/src/` | Backend | Tauri IPC, native platform modules |
|| `crates/cmtraceopen-parser/` | Parser crate | Pure log/Intune/ESP/dsregcmd parsers |
|| `docs/superpowers/` | Specs & plans | Feature design + implementation plans |
|| `docs/superpowers/specs/2026-08-07-reducer-framework-v1-design.md` | Reducer semantics | Shared reducer contracts, conformance invariants, agent boundaries |
|| `docs/superpowers/plans/2026-08-07-reducer-framework-v1.md` | Reducer delivery | Ordered PR sequence and reducer-lane workflow |
|| `scripts/collection/` | Evidence ops | Diagnostic bootstrap and collection |
|| `bucket/`, `Casks/` | Packaging | Scoop and Homebrew |

## Memory

- Shared memory index: `.clairvoyance/memory/index.md`
- Staff memory lives under `.clairvoyance/staff/{name}/index.md`
