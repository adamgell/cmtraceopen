# Screenshots

Product screenshots used by the project [README](../README.md) and wiki.

These images are **generated**, not hand-captured, so they stay current and consistent.
The capture harness drives the real frontend in a headless browser and writes the PNGs here.

| File | Workspace |
|------|-----------|
| `log-viewer.png` | Log Viewer — a ConfigMgr (CCM) app-deployment log with severity coloring and error-code lookup |
| `intune-diagnostics.png` | Intune Diagnostics — color-coded event timeline with success/failure and download stats |
| `dsregcmd.png` | DSRegCmd Troubleshooting — device join posture, issue cards, and health summary |

## Regenerate

```bash
npm run screenshots
```

This starts the Vite dev server (or reuses one already on `:1420`), captures each workspace,
and overwrites the PNGs in this folder. Commit the updated images alongside the change that
affected them. No Rust build is required.

The harness lives in [`e2e/screenshots/capture.spec.ts`](../e2e/screenshots/capture.spec.ts) with its
own Playwright config, [`playwright.screenshots.config.ts`](../playwright.screenshots.config.ts). It is
intentionally excluded from the normal `npm run test:e2e` run.

## How the app gets populated

The app runs at `:1420` with the Tauri IPC shim ([`e2e/fixtures/tauri-shim.ts`](../e2e/fixtures/tauri-shim.ts)).

- **Log Viewer** is given a synthetic Windows path (`C:\Fixture\Logs\ConfigMgr_AppEnforce_demo.log`)
  and a mock parse result, so the sidebar shows the synthetic path and the grid shows parsed rows.
  The mirrored demo log is [`e2e/fixtures/demo/ConfigMgr_AppEnforce_demo.log`](../e2e/fixtures/demo/ConfigMgr_AppEnforce_demo.log).
- **Intune** and **DSRegCmd** are populated with curated **synthetic** data from
  [`e2e/fixtures/screenshot-data.ts`](../e2e/fixtures/screenshot-data.ts). The data is fictional
  (Contoso, placeholder GUIDs) on purpose — a real `dsregcmd` capture would bake the host's device
  and tenant identifiers into a public screenshot.

Captures never use the IPC bridge: requests to `127.0.0.1:1422` are blocked and the source is always mocked, so a running `npm run app:dev` cannot change a screenshot.
