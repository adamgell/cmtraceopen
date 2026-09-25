# Superseded-Branch Reconciliation (cmtraceopen SUP lane, Aug 2026)

Session detail backing SKILL.md Step 1.6. The lane branch
`codex/sccm330-sup-coverage-review-fix-r150` (tip `ac4f8872`) looked like a normal
verify-and-merge target; it was actually a stale archive of a program main had
already converged.

## How the divergence was detected

```bash
git rev-list --left-right --count origin/main...HEAD   # 233 behind / 11 ahead
git merge-base origin/main HEAD                        # 09aafd4a (#455), 3 days stale
```

233-behind is the smell. Two histories had built the same subsystem in parallel.

## Proving which side is authoritative

1. **PR numbers → different SHAs.** Branch commits `bc5d4f85` (#458) and `83295227`
   (#459) appear on main as `2022b029` and `acf645db` — squash/rebased merges.
   `git log origin/main --grep='#458'` finds them; patch-ids confirm same change.
2. **Same file, incompatible content.** `software_update_point.rs`: branch 328
   lines (`CoverageRow`/`CoverageGap` model) vs main 1002 lines (richer model:
   `ExtractionProfile`, `RoleAssessment`, `CorrelationHandoff`). `private_fs.rs`:
   branch 2309L vs main 1075L. Larger-on-main + diverged-base = main rewrote it.
3. **Colliding same-named test files** on both sides → any cherry-pick conflicts or
   silently overwrites. Extraction is not viable; re-derivation would be.
4. **Verify coverage, don't assume.** Read main's implementation for the specific
   behaviors the branch added (here: conservative absent-source coverage gaps).
   Main had them natively (`role_assessment(sup_observed)`, explicit
   `CoverageAbsent`, sorted/deduped gap ids) — the branch's fixes were already
   expressed in main's model. Nothing to port.

## Artifact correction

A tracker issue filed for a CodeRabbit major found on the branch (fd-exhaustion in
the branch's `private_fs.rs`: `CreatedEntry{parent: File}` + cap 4096 vs 1024
RLIMIT_NOFILE) did not exist on main — main's rewrite has zero occurrences of that
shape (`git show origin/main:<file> | grep -c <pattern>` → 0). Issue was closed
with the evidence, not left as a phantom blocker.

## Outcome shape that satisfied "don't lose work"

Branch + remote refs preserved as archive; main treated as authoritative; no merge,
no rebase, no force-push. The reconciliation finding was recorded so the next
session doesn't re-verify the stale lane as if it were live.

**Lesson ordering:** run Step 1.6 BEFORE filing issues or planning merges for a
diverged branch — the whole session's plan (verify → CodeRabbit → merge) was built
on the branch being live, and had to be unwound.
