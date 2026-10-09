# Design System -- Open Questions

> Unresolved design decisions that need human judgment before implementation.
> Per Phase 2 constraints: genuine new design needs not covered by the system are
> documented here rather than invented ad hoc.

---

## Status legend

| Tag | Meaning |
|-----|---------|
| **OPEN** | Awaiting human decision |
| **DECIDED** | Decision recorded, implementation pending |
| **RESOLVED** | Implemented and merged |

---

## OQ-1: Dark theme explicit overrides

**Status:** RESOLVED -- deferred
**Filed:** 2026-04-27
**Resolved:** 2026-04-27
**Surfaces:** `src/lib/themes/theme-dark.ts`, `docs/design-system/tokens.css`

### Decision

**Option B: Keep algorithmic.** The `createDarkTheme` algorithm is stable and
well-tested. Pinning 200+ colors would be high maintenance for marginal benefit.
If a Fluent UI upgrade introduces visible regressions, we can revisit with
Option C (pin + snapshot test) at that time.

### Context

`theme-dark.ts` has zero explicit color overrides -- it relies entirely on
`createDarkTheme(tealBrand)`. This means:

- Any Fluent UI upgrade could silently change all dark theme colors.
- The `tokens.css` documents specific hex values (e.g. `--cmt-fg-1: #ffffff`,
  `--cmt-bg-1: #292929`) that may not match the algorithm's output after an
  upgrade.
- Other community themes (`solarized-dark`, `nord`, `dracula`) explicitly pin
  ~20 colors each, giving them stability guarantees the dark theme lacks.
- `theme-light.ts` already pins its semantic colors explicitly, creating an
  asymmetry between the two primary themes.

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Pin ~20 semantic colors** | Upgrade-safe, matches light theme pattern, `tokens.css` stays accurate | More maintenance when intentionally updating dark theme |
| **B. Keep algorithmic** | Zero maintenance, always "correct" per Fluent's intent | Silent drift on upgrades, `tokens.css` may go stale |
| **C. Pin + snapshot test** | Best of both -- pin values, add a test that fails if the algorithm diverges | Adds test infrastructure |

---

## OQ-2: Merge tab color palette

**Status:** RESOLVED
**Filed:** 2026-04-27
**Resolved:** 2026-04-27
**Surfaces:** `src/components/log-view/LogListView.tsx`, `src/lib/merge-entries.ts`

### Decision

**Option A: Semantic tokens per theme.** Added a `mergeColors` 8-element tuple
to `LogSeverityPalette` in `src/lib/constants.ts`. Each theme in
`src/lib/themes/palettes.ts` defines its own hand-tuned 8-color merge palette
with appropriate contrast for that theme's background.

- `LogListView.tsx` section palette now reads `severityPalette.mergeColors`.
- `merge-entries.ts` `assignFileColors()` accepts an optional palette parameter;
  the log store passes the active theme's merge palette at merge time.
- `MERGE_FILE_COLORS` is kept as a re-export of the light theme's palette for
  backward compatibility.

### Context

`LogListView.tsx` uses 8 hardcoded colors for merge tab identification:

```
"#3b82f6", "#a78bfa", "#f59e0b", "#10b981",
"#ef4444", "#ec4899", "#06b6d4", "#84cc16"
```

These colors do not exist in the token system. They are Tailwind palette values
used directly in component code. They need to work across all 8 themes with
sufficient contrast against each theme's background.

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Semantic tokens per theme** | Each theme gets hand-tuned tab colors with guaranteed contrast | 8 tokens x 8 themes = 64 values to maintain |
| **B. Fixed palette + contrast tests** | Single palette, automated verification, less maintenance | Some themes may need compromises; palette may not feel "native" to themed UIs |
| **C. Hybrid: fixed palette with per-theme overrides** | Default palette works everywhere, themes can opt in to customization | More complex token resolution logic |

---

## OQ-3: Whatif overlay colors

**Status:** RESOLVED
**Filed:** 2026-04-27
**Resolved:** 2026-04-27
**Surfaces:** `src/components/log-view/LogRow.tsx`

### Decision

**Option A: Semantic token per theme.** Added `whatifOverlay` (semi-transparent
background) and `whatifText` (opaque foreground) to `LogSeverityPalette`. Each
theme defines its own values tuned for visibility against that theme's
background. `LogRow.tsx` now reads these from `severityPalette` instead of using
hardcoded `#9333ea33` / `#9333ea`.

### Context

`LogRow.tsx` uses `#9333ea33` (semi-transparent purple, ~20% opacity) for whatif
overlays. This overlay must be visible across all 8 themes, which range from
pure white (`#ffffff`) to pure black (`#000000`) backgrounds.

A single semi-transparent color will have very different visual weight on light
vs. dark backgrounds.

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Semantic token per theme** | Tuned visibility on every background | 8 values to maintain; overlay is a niche feature |
| **B. Fixed semi-transparent value** | Simple, one value | May be invisible on some dark themes or too strong on light themes |
| **C. Two values (light/dark)** | Reasonable middle ground using `color-scheme` | Does not cover all 8 themes individually (e.g. solarized-dark vs. nord have different backgrounds) |

---

## OQ-4: Collection status indicator colors

**Status:** RESOLVED
**Filed:** 2026-04-27
**Resolved:** 2026-04-27
**Surfaces:** `src/components/dialogs/CollectionCompleteDialog.tsx`

### Decision

**Option D (variant): Add `status` palette to `LogSeverityPalette`.** Added a
`status` object with `success`, `warning`, and `error` sub-objects, each having
`foreground` and `background` colors. These are defined per-theme in
`palettes.ts` and used by `CollectionCompleteDialog.tsx` via the UI store's
active theme.

For light themes, the foreground colors map to the existing `--cmt-status-*-fg`
values. For dark/community themes, brighter foreground colors are used to
maintain readability against dark backgrounds. Background colors use the
foreground color at reduced opacity for subtle tinting.

### Context

`CollectionCompleteDialog.tsx` uses hardcoded green/yellow/red for
success/warning/error status indicators:

- Success: `#4ade80`
- Warning: `#facc15`
- Error: `#f87171`

These overlap with but are not identical to the existing severity palette:

| Purpose | Hardcoded | Severity token (light) | Status token (light) |
|---------|-----------|----------------------|---------------------|
| Success/green | `#4ade80` | -- | `--cmt-status-success-fg: #0e700e` |
| Warning/amber | `#facc15` | `--cmt-sev-warning-fg: #78350F` | `--cmt-status-warning-fg: #bc4b09` |
| Error/red | `#f87171` | `--cmt-sev-error-fg: #7F1D1D` | `--cmt-status-danger-fg: #b10e1c` |

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Map to existing `--cmt-status-*-fg` tokens** | No new tokens, consistent with system | Colors may be too dark for indicator dots/badges |
| **B. Map to existing `--cmt-status-*-border` tokens** | Slightly lighter, still in system | Border tokens were not designed for this purpose |
| **C. New `colorCollection*` tokens** | Purpose-built, correct brightness | Adds 3 tokens x 8 themes; risks palette sprawl |
| **D. Add `--cmt-status-*-indicator` tokens** | Reusable beyond collection dialog | Still adds tokens, but with broader applicability |

---

## OQ-5: Update dialog error color

**Status:** RESOLVED
**Filed:** 2026-04-27
**Resolved:** 2026-04-27
**Surfaces:** `src/components/dialogs/UpdateDialog.tsx`

### Decision

**Option B: Replace with Fluent `colorPaletteRedForeground1`.** The hardcoded
`#d13438` was replaced with `tokens.colorPaletteRedForeground1` from Fluent UI.
This is theme-aware via the Fluent provider and resolves correctly across all
themes. Since the update dialog is a standard Fluent UI component (not a log
viewer row), using Fluent's own palette token is more appropriate than the
CMTrace severity layer.

### Context

`UpdateDialog.tsx` uses `#d13438` for error text. This appears to be
`colorPaletteRedForeground1` from Fluent UI's palette, but it was hardcoded
instead of using a token reference.

The existing system already has `--cmt-status-danger-fg` (`#b10e1c` in light
theme) which serves the same semantic purpose.

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Replace with `--cmt-status-danger-fg`** | Consistent, no new tokens, theme-aware | Slightly different shade (`#b10e1c` vs `#d13438`) -- verify readability |
| **B. Replace with Fluent `colorPaletteRedForeground1`** | Uses Fluent's own token, theme-aware via Fluent provider | Bypasses the CMTrace semantic layer |
| **C. Keep as-is** | No change needed | Hardcoded value breaks in all non-light themes |

---

## OQ-6: Sequential data ramp for heat maps and density

**Status:** OPEN (awaiting human decision)
**Filed:** 2026-10-09
**Surfaces:** `src/workspaces/event-log/evtx-visual-tokens.ts` (`heatSteps`), `src/lib/constants.ts` (`LogSeverityPalette`), `src/lib/themes/palettes.ts`, `docs/design-system/tokens.css`
**Tracking:** #858, part of #823. Spec: `docs/superpowers/specs/2026-10-08-event-logs-workbench-ui-handoff-design.md` (D11, Q-3, section 15.2)

### Decision

None yet. The recommendation below is a proposal for the owner, not a decision.

### Context

The design system has categorical colors (`mergeColors`), severity colors and
status colors, but no sequential ramp: an ordered, low to high scale for
quantity. The Event Logs Charts heat map needs one. The spec's interim answer
(D11, Q-3) builds six fixed steps in `evtx-visual-tokens.ts` by mixing
`severityPalette.mergeColors[0]` into `colorNeutralBackground1` with
`color-mix(in srgb, ...)` at 15, 30, 45, 60, 75 and 90 percent. Q-3 and
section 15.2 require this open question so the interim can be replaced rather
than copied into other workspaces.

Problems with the interim:

- `mergeColors[0]` was tuned for tab identification, not for a ramp. Nothing
  guarantees monotonic lightness or distinguishable adjacent steps in every
  registered theme.
- Label legibility on each step is not guaranteed, because the step fills
  vary with the theme background.
- High-contrast behavior is not defined (a mix of two system colors is not a
  ramp).
- Any other density view (timeline density, sparkline fills) would have to
  copy the mix, spreading an unvetted derivation.

Requirements for any resolution:

1. A fixed number of steps (the interim uses 6), ordered low to high, defined
   for every registered theme.
2. Monotonic lightness across the steps in each theme.
3. Adjacent steps distinguishable from each other.
4. Text drawn on a step (counts, labels) meets the contrast floor the system
   already applies to other tokens.
5. A defined high-contrast behavior (system colors, not a mix).
6. Safe for common color vision deficiencies; lightness carries the order, not
   hue alone.
7. Must not read as severity: avoid the severity red, amber and green hues for
   quantity.

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Single-hue ramp per theme** (`severityPalette.sequential`, a fixed-length tuple, hand-tuned in `palettes.ts`) | Monotonic lightness is easy to guarantee and test, colorblind safe, matches how `mergeColors` is defined and tested | N steps x every registered theme to maintain; one hue may not suit every theme background |
| **B. Perceptually uniform multi-hue ramp** (generated or pinned per theme) | Best step separation across a wide range; familiar from common data-vis scales | Hue shifts can read as severity or categories; harder to keep legible on every theme background; more review per theme |
| **C. Keep `color-mix()` with guardrails** (shared helper, plus tests for monotonic lightness and label contrast) | No new per-theme palette values, zero extra maintenance, smallest change | Quality depends on `mergeColors[0]` and the background in each theme; some themes may fail the guardrails and need exceptions; high-contrast still needs a special case |

### Proposal (for the owner)

Option A: add `sequential` to `LogSeverityPalette` as a 6-tuple, faintest
first, defined in `src/lib/themes/palettes.ts` for every registered theme, with
a documented `--cmt-seq-1` to `--cmt-seq-6` mirror in `tokens.css`. The
high-contrast theme should map the steps to system colors with a stepped
pattern or outline cue rather than lightness alone. Keeping the interim until
a decision is made costs nothing, so Option C is the fallback if the owner
prefers not to add per-theme values.

### When resolved

1. Record the chosen option and rationale here and mark the entry **DECIDED**.
2. Replace the `color-mix()` derivation of `heatSteps` in
   `evtx-visual-tokens.ts` with the new token, and remove `HEAT_STEP_PERCENTAGES`.
3. Add token suite tests: step count, monotonic lightness per theme,
   adjacent-step distinctness, label contrast on every step, and the
   high-contrast mapping.
4. Update the D11 and Q-3 notes in the Event Logs spec, mark the entry
   **RESOLVED** with the PR link, and close #858.

---

## Process

When a question is decided:

1. Update the status to **DECIDED** and record the chosen option + rationale.
2. File a PR implementing the decision.
3. After the PR merges, update the status to **RESOLVED** with the PR link.
