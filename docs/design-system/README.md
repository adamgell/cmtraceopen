# CMTrace Open — Design System

This folder is the **canonical, human-readable design system** for CMTrace Open.

## Files

- **`SKILL.md`** -- read this first when designing anything new. Decision tree, six rules, anti-patterns, and a map from "I need X" to "look in file Y."
- **`tokens.css`** -- every color, type, spacing, radius, shadow, and motion token for all eight themes, exposed as CSS variables. Source-of-truth mirror of `src/lib/themes/*.ts`.
- **`OPEN-QUESTIONS.md`** -- unresolved design decisions that need human judgment. If you find a genuine new design need not covered by the system, document it here rather than inventing a token.

## How this relates to the codebase

The codebase wins. `src/lib/themes/*.ts` is the runtime source of truth — Fluent v9 theme objects assembled from `brand-ramps.ts`, `palettes.ts`, and the per-theme override files. `tokens.css` mirrors those values for:

1. Quick reference when designing in HTML/Figma
2. Use in standalone marketing pages, docs sites, or design prototypes that don't bootstrap Fluent
3. A single grep-able file to spot drift between design and code

If `tokens.css` and the TS files disagree, **the TS files win** — update `tokens.css` to match. There's a sister copy at `src/lib/themes/tokens.css` for the same reason.

## How to use the system in new work

1. Read `SKILL.md`. The decision tree tells you whether to extend an existing component, vary it, or build something new.
2. Default to **Light theme + Teal brand** (`#007768`). Everything else is a variation.
3. If you reach for a hex code that isn't in `tokens.css` for the active theme, stop — either the token should be added system-wide, or you're solving the wrong problem.
4. Use the live design-system project at https://claude.ai/design/p/019dcf99-e7fa-7599-bd90-3158839d5871 for visual reference (12 component cards + a full app-shell UI kit).

## Updating the system

When you change a theme in `src/lib/themes/`:

1. Update the matching block in `src/lib/themes/tokens.css` and `docs/design-system/tokens.css`
2. Update `SKILL.md` if the change affects a rule, anti-pattern, or "where things live" pointer
3. Sync the live design-system project (or ask "re-sync from the codebase")

## Eight themes

`light` · `dark` · `high-contrast` · `classic-cmtrace` · `solarized-dark` · `nord` · `dracula` · `hotdog-stand`

Switch in HTML with `<html data-cmt-theme="dark">`. Switch in the app via `useTheme()` from `src/lib/themes/`.
