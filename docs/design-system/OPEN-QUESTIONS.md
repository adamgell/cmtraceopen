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

**Status:** OPEN
**Filed:** 2026-04-27
**Surfaces:** `src/lib/themes/theme-dark.ts`, `docs/design-system/tokens.css`

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

### Question

Should `theme-dark.ts` pin its semantic colors explicitly like `theme-light.ts`
does?

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Pin ~20 semantic colors** | Upgrade-safe, matches light theme pattern, `tokens.css` stays accurate | More maintenance when intentionally updating dark theme |
| **B. Keep algorithmic** | Zero maintenance, always "correct" per Fluent's intent | Silent drift on upgrades, `tokens.css` may go stale |
| **C. Pin + snapshot test** | Best of both -- pin values, add a test that fails if the algorithm diverges | Adds test infrastructure |

---

## OQ-2: Merge tab color palette

**Status:** OPEN
**Filed:** 2026-04-27
**Surfaces:** `src/components/log-view/LogListView.tsx`

### Context

`LogListView.tsx` uses 8 hardcoded colors for merge tab identification:

```
"#3b82f6", "#a78bfa", "#f59e0b", "#10b981",
"#ef4444", "#ec4899", "#06b6d4", "#84cc16"
```

These colors do not exist in the token system. They are Tailwind palette values
used directly in component code. They need to work across all 8 themes with
sufficient contrast against each theme's background.

### Question

Should these be added as semantic tokens (`colorMergeTab1` through
`colorMergeTab8`) to each theme, or should they use a fixed palette that is
tested for contrast against all theme backgrounds?

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Semantic tokens per theme** | Each theme gets hand-tuned tab colors with guaranteed contrast | 8 tokens x 8 themes = 64 values to maintain |
| **B. Fixed palette + contrast tests** | Single palette, automated verification, less maintenance | Some themes may need compromises; palette may not feel "native" to themed UIs |
| **C. Hybrid: fixed palette with per-theme overrides** | Default palette works everywhere, themes can opt in to customization | More complex token resolution logic |

---

## OQ-3: Whatif overlay colors

**Status:** OPEN
**Filed:** 2026-04-27
**Surfaces:** `src/components/log-view/LogRow.tsx`

### Context

`LogRow.tsx` uses `#9333ea33` (semi-transparent purple, ~20% opacity) for whatif
overlays. This overlay must be visible across all 8 themes, which range from
pure white (`#ffffff`) to pure black (`#000000`) backgrounds.

A single semi-transparent color will have very different visual weight on light
vs. dark backgrounds.

### Question

Add a `colorWhatifOverlay` semantic token to each theme, or use a fixed
semi-transparent value?

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Semantic token per theme** | Tuned visibility on every background | 8 values to maintain; overlay is a niche feature |
| **B. Fixed semi-transparent value** | Simple, one value | May be invisible on some dark themes or too strong on light themes |
| **C. Two values (light/dark)** | Reasonable middle ground using `color-scheme` | Does not cover all 8 themes individually (e.g. solarized-dark vs. nord have different backgrounds) |

---

## OQ-4: Collection status indicator colors

**Status:** OPEN
**Filed:** 2026-04-27
**Surfaces:** `src/components/dns-dhcp/CollectionCompleteDialog.tsx`

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

The hardcoded values are much lighter/brighter than the existing tokens, which
were chosen for text readability. The collection dialog may be using them as
indicator dots or badges rather than text, which could justify a different
brightness.

### Question

Should these map to the existing severity/status palette tokens, or do they need
distinct `colorCollectionSuccess` / `colorCollectionWarning` /
`colorCollectionError` tokens?

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Map to existing `--cmt-status-*-fg` tokens** | No new tokens, consistent with system | Colors may be too dark for indicator dots/badges |
| **B. Map to existing `--cmt-status-*-border` tokens** | Slightly lighter, still in system | Border tokens were not designed for this purpose |
| **C. New `colorCollection*` tokens** | Purpose-built, correct brightness | Adds 3 tokens x 8 themes; risks palette sprawl |
| **D. Add `--cmt-status-*-indicator` tokens** | Reusable beyond collection dialog | Still adds tokens, but with broader applicability |

---

## OQ-5: Update dialog error color

**Status:** OPEN
**Filed:** 2026-04-27
**Surfaces:** `src/components/dialogs/UpdateDialog.tsx`

### Context

`UpdateDialog.tsx` uses `#d13438` for error text. This appears to be
`colorPaletteRedForeground1` from Fluent UI's palette, but it was hardcoded
instead of using a token reference.

The existing system already has `--cmt-status-danger-fg` (`#b10e1c` in light
theme) which serves the same semantic purpose.

### Question

Confirm this should map to `--cmt-status-danger-fg` (or the Fluent
`colorPaletteRedForeground1` token) and fix, or does the update dialog need its
own error token?

### Trade-offs

| Option | Pro | Con |
|--------|-----|-----|
| **A. Replace with `--cmt-status-danger-fg`** | Consistent, no new tokens, theme-aware | Slightly different shade (`#b10e1c` vs `#d13438`) -- verify readability |
| **B. Replace with Fluent `colorPaletteRedForeground1`** | Uses Fluent's own token, theme-aware via Fluent provider | Bypasses the CMTrace semantic layer |
| **C. Keep as-is** | No change needed | Hardcoded value breaks in all non-light themes |

**Recommendation (pending decision):** Option A is almost certainly correct.
`#d13438` and `#b10e1c` are both red foreground colors; the existing token is
already tuned for readability across themes. This is likely a simple oversight
rather than an intentional design choice.

---

## Process

When a question is decided:

1. Update the status to **DECIDED** and record the chosen option + rationale.
2. File a PR implementing the decision.
3. After the PR merges, update the status to **RESOLVED** with the PR link.
