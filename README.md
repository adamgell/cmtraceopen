# CMTrace Open

An open-source log viewer inspired by Microsoft's CMTrace.exe, built with Tauri v2 + React + TypeScript + Rust. Includes built-in diagnostics.

## Screenshots

### Main Window

![Main Window](references/main_window_wlog.png)

### Intune Analysis

![Intune Diagnostics](references/intune_diag.png)

## Features

### Log Viewer

- **Format support** — CCM (`<![LOG[...]LOG]!>`), simple (`$$<` delimited), and plain text with automatic detection
- **Real-time tailing** — live file watching with pause/resume
- **Virtual scrolling** — smooth performance with 100K+ line files
- **Severity color coding** — Error (red), Warning (yellow), Info (white)
- **Find & Filter** — Ctrl+F with F3 navigation; filter by message, component, thread, or timestamp
- **Highlight** — configurable text highlighting
- **Error Lookup** — 120+ embedded Windows, SCCM, and Intune error codes
- **Flexible input** — open from file, folder, drag & drop, or known platform source presets

### Diagnostics

- **IME log analysis** — parse a single IME log or an entire logs folder
- **Event timeline** — color-coded timeline covering Win32 apps, WinGet apps, PowerShell scripts, remediations, ESP, and sync sessions
- **Download statistics** — size, speed, and Delivery Optimization percentage
- **Summary dashboard** — event counts, success/failure rates, and log time span
- **GUID extraction** — automatic app and policy identifier detection

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/)

### Build

```bash
git clone https://github.com/adamgell/CMTraceOpen.git
cd CMTraceOpen
npm install
npm run tauri dev
```

### Install

Download the latest release from [Releases](https://github.com/adamgell/CMTraceOpen/releases).

## Disclaimer

CMTrace is a tool developed and distributed by Microsoft Corporation. CMTrace Open is an independent open-source project and is **not** affiliated with, endorsed by, or connected with Microsoft Corporation. See [DISCLAIMER.md](DISCLAIMER.md) for full details.

## License

[MIT](LICENSE)
