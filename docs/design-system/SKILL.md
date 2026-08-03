# SKILL — Designing for CMTrace Open

> Read this file first when designing anything new for CMTrace Open.
> It tells you which surface to extend, which surface to copy, and the moves to avoid.

---

## What CMTrace Open is

A **free, open-source web reimagining of Microsoft's CMTrace.exe** — a log viewer for MEMCM/MECM admins, Intune admins, sysadmins, and Windows developers. The product promise:

> Drop in a log file and start reading. Errors highlight automatically.

CMTrace Open is **engineering-led**. Tokens, themes, components, and metrics all live in `cmtraceopen-web/cmtraceopen/src/` — this design system mirrors them. **The codebase is the source of truth.** When this system disagrees with the codebase, the codebase wins; update the system to match.

---

## Where things live

| You need… | Look here (codebase) | Mirrored in this DS |
|---|---|---|
| Theme objects, brand ramps | `src/lib/themes/*` | `02-color-themes.html`, `tokens.css` |
| Semantic color tokens | `src/lib/themes/*-theme.ts` | `03-color-tokens.html`, `tokens.css` |
| Type ramp & families | `src/lib/themes/typography.ts` | `04-typography.html` |
| Log row metrics | `src/lib/log-list-metrics.ts` (`getLogListMetrics()`) | `04-typography.html`, `09-components-log-grid.html` |
| Spacing / radius / shadow | `src/lib/themes/tokens.ts` | `05-spacing-radius-shadow.html` |
| Motion durations & curves | `src/lib/themes/motion.ts` | `06-motion.html` |
| Icons | `@fluentui/react-icons` | `07-iconography.html` |
| Buttons, inputs, badges | `src/components/ui/*` | `08-components-buttons-inputs.html` |
| Log row, gutter, markers | `src/components/log/LogRow.tsx`, `LogGutter.tsx` | `09-components-log-grid.html` |
| Toolbar, tabs, status bar | `src/components/chrome/*` | `10-components-chrome.html` |
| Dialogs, settings, find | `src/components/dialogs/*` | `11-components-dialogs.html` |
| Full app reference | `src/App.tsx` | `ui-kit.html` |

---

## The decision tree

When designing something new, ask in order:

1. **Does it already exist in the codebase?** → Use it as-is. Don't re-design.
2. **Is it a small variant of something in the codebase?** → Match the existing component's API and visual rhythm. Add a prop, don't fork.
3. **Is it genuinely new?** → Compose from primitives in this DS. Default to Light theme + Teal brand. Open a PR with a token entry alongside the component.

If you find yourself reaching for a hex code that isn't in `tokens.css`, stop. Either it should be added to the system, or you're solving the wrong problem.

---

## Setup (every new HTML file)

```html
<!doctype html>
<html lang="en" data-cmt-theme="light">
<head>
  <link rel="stylesheet" href="tokens.css">
</head>
<body>
  <!-- ... -->
</body>
</html>
```

Switch themes by changing the `data-cmt-theme` attribute. The eight valid IDs:
`light` · `dark` · `high-contrast` · `classic-cmtrace` · `solarized-dark` · `nord` · `dracula` · `hotdog-stand`

---

## The six rules

### 1. Severity colors are non-negotiable defaults
Errors are red row-wide. Warnings are amber row-wide. Info is the default surface. The user opens a 50MB log and the failures should be visible inside two seconds with **zero configuration**. Never gate severity behind a setting.

### 2. Tabular numbers, always
Counts, byte sizes, line numbers, timestamps, thread IDs — all use `var(--cmt-font-numeric)` (Bahnschrift). Mono content (the log itself) uses `var(--cmt-font-mono)` (Consolas). UI chrome uses `var(--cmt-font-ui)` (Segoe UI). Don't mix these up.

### 3. Density over comfort
The default log row is **23px** tall at 13px font. Toolbar buttons are **28px**. Status bar is **24px**. This is intentional — admins are scanning thousands of rows. Don't add breathing room to the grid; reserve generous spacing for dialogs and marketing.

### 4. Strokes do the work, not shadows
Use `--cmt-stroke-2` between regions. Reserve `shadow8` for popovers and `shadow16` for dialogs. Stacked shadows on cards-inside-cards-inside-cards are an anti-pattern here.

### 5. Brand teal is for accent, not decoration
`--cmt-brand-bg` (`#007768` light, `#009688` dark) appears on: the status bar, primary buttons, the active-tab underline, selected sidebar items, the logo. **It does not appear** on borders, hover states of unrelated controls, or as a "pop of color" anywhere else. Restraint is the design.

### 6. Don't soften technical errors
"Failed to parse line 487" beats "Hmm, we couldn't read that." Copy is direct, operational, and assumes the reader is debugging Windows. No emoji in product UI. No "oops." No exclamation marks.

---

## Common moves

### Adding a new dialog
1. 8px corner radius, `var(--cmt-shadow-16)`, 24px padding.
2. Title is 20px / 28px line-height, semibold.
3. Action row right-aligned, primary button last, 8px gap.
4. Cancel-on-Escape, focus the safe action by default (not the destructive one).

### Adding a new toolbar button
1. 28px tall, 8px horizontal padding, 4px radius, transparent until hover.
2. Icon is `20Regular` from `@fluentui/react-icons`, 16px in the rendered button.
3. Use `--cmt-bg-1-hover` for hover, `--cmt-bg-1-selected` + `--cmt-brand-fg` for active.
4. Group related buttons; separate groups with a 1px × 20px stroke divider.

### Adding a new log row decoration
Look at `LogRow.tsx` first. The row has fixed slots: gutter (line# + marker dot) · time · component · message · source · thread. Don't add a 7th column; either pack it into Inspector, or reuse an existing slot with a tooltip.

### Theming a new feature
If the feature has a new color need, add it as a semantic token in **all eight themes** before shipping. Never reference brand ramp stops directly from a component — go through a semantic layer (`--cmt-status-success-fg`, not `--cmt-teal-70`).

---

## Anti-patterns (hard no)

- **Inventing colors.** If it's not in `tokens.css` for the active theme, don't paint with it.
- **Rounded everything.** 12px+ radii are for marketing surfaces only; the app maxes at 8px.
- **Soft drop shadows on cards.** Use a stroke.
- **Emoji icons in product UI.** Fluent icons only.
- **Title-cased buttons.** Sentence case, with an ellipsis when the action opens a picker or another step.
- **Tabular UI in proportional fonts.** Counts in Segoe UI look broken.
- **Putting content in chrome.** The titlebar, status bar, and tab strip are signage, not editorial space.
- **Blocking interactions for animation.** Most transitions are 100–200ms; the log row uses `80ms linear`. Anything above 300ms should be justifiable.

---

## Sourcing assets

- **Logo:** `assets/cmtrace-logo.png` and `assets/splash-logo.png`. Reserved for splash, About dialog, marketing, favicon. Don't recolor or crop.
- **Icons:** Fluent UI System Icons via `@fluentui/react-icons`. `20Regular` / `16Regular` for chrome, `Filled` only for selected/active states.
- **Severity dots:** Not icons — 8px filled circles using semantic status colors. See `07-iconography.html`.
- **Marker dots:** 6px filled circles in the row gutter. Five colors (red, amber, teal, purple, blue). User-assignable.

---

## When in doubt

- Look at `LogRow.tsx`. It's the densest, most-considered component and sets the rhythm for everything else.
- Default to **Light theme + Teal brand**. It's the canonical surface; everything else is a variation.
- Ship it behind the existing eight themes. If your design only works in one theme, the design isn't done.
- The product is for people who read logs for a living. Respect their time.
