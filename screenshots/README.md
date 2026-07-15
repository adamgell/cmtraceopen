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

- **Log Viewer** opens a committed demo log, [`e2e/fixtures/demo/ConfigMgr_AppEnforce_demo.log`](../e2e/fixtures/demo/ConfigMgr_AppEnforce_demo.log).
  If the real Rust backend is running (see below), the genuine parser parses it; otherwise a mock
  parse result stands in so the shot still works with no Rust build / in CI.
- **Intune** and **DSRegCmd** are populated with curated **synthetic** data from
  [`e2e/fixtures/screenshot-data.ts`](../e2e/fixtures/screenshot-data.ts). The data is fictional
  (Contoso, placeholder GUIDs) on purpose — a real `dsregcmd` capture would bake the host's device
  and tenant identifiers into a public screenshot.

### Higher-fidelity Log Viewer capture

Run the full app first, then capture in a second terminal:

```bash
npm run app:dev        # terminal 1 — starts the app + IPC bridge on :1422
npm run screenshots    # terminal 2 — reuses :1420, parses the demo log via the real backend
```

The shim auto-detects the bridge; no flags needed.
