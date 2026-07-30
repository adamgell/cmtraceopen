# cmtrace-open

The desktop application crate for [CMTrace Open](https://cmtraceopen.com) — a free, open-source log viewer and Windows troubleshooting tool, built as a modern replacement for Microsoft's CMTrace.exe.

**Most people do not want to build this crate.** CMTrace Open ships as a signed, single-file download for Windows, macOS, and Linux, with no runtime dependencies:

**https://download.cmtraceopen.com**

## What this crate is

This is the Tauri v2 backend for the desktop app: IPC command handlers, file watching and real-time tailing, EVTX and registry readers, platform-gated Windows diagnostics, and the native application menu. It is published so the full source of a signed release is available from crates.io as well as GitHub, and so the workspace resolves for downstream tooling.

It is **not** a general-purpose library. It links Tauri, expects a WebView runtime, and bundles a React frontend that is built separately by Vite — building it from a bare `cargo install` requires the full [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform plus a built frontend in `../dist`.

## What you probably want instead

If you are writing your own tool and need to parse ConfigMgr/SCCM, Intune, CBS, DISM, MSI, or PSADT logs, use the parsing engine directly — it is a separate, dependency-light crate with no Tauri, no I/O, and no platform lock-in:

```bash
cargo add cmtraceopen-parser
```

See [cmtraceopen-parser](https://crates.io/crates/cmtraceopen-parser).

## Building from source

Build the whole app from the repository root, not this crate in isolation:

```bash
npm ci
npm run app:build:release
```

See [CONTRIBUTING.md](https://github.com/adamgell/cmtraceopen/blob/main/CONTRIBUTING.md) for development setup, build commands, and architecture.

## Features

The default `full` feature enables every workspace: Intune diagnostics, Autopilot ESP diagnostics, DSRegCmd, software deployment scanning, Windows Event Log, Sysmon, Secure Boot certificates, macOS diagnostics, and diagnostic collection. Building with `--no-default-features` produces the Lite edition — the core log viewer only.

## License

MIT. See [LICENSE](https://github.com/adamgell/cmtraceopen/blob/main/LICENSE).

## Disclaimer

CMTrace is a tool developed and distributed by Microsoft Corporation. CMTrace Open is an independent open-source project, **not** affiliated with, endorsed by, or connected with Microsoft Corporation.
