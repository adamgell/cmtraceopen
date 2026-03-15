# Build From Source

This document captures the Windows development setup needed to build and run
CMTrace Open from source on a fresh machine.

## Scope

This repo is a Tauri v2 desktop app with:

- React + TypeScript frontend
- Rust backend
- Windows packaging through Tauri bundles

The notes below are Windows-focused because the current handoff is to another
Windows development box.

## What To Install

Install these first:

1. Git
2. Node.js 20 LTS or newer
3. Rust via `rustup` using the MSVC toolchain
4. Visual Studio 2022 Build Tools or Visual Studio 2022 Community with
   `Desktop development with C++`
5. Windows SDK for desktop C++ builds
6. Microsoft Edge WebView2 Runtime

Install these if you need local Windows installer packaging:

1. VBSCRIPT Windows optional feature

## Winget Install Commands

These commands use the package IDs verified with `winget search` and
`winget show` on the current machine.

If you want the documented Windows prerequisite setup as a script, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Install-CMTraceOpenBuildPrereqs.ps1
```

Optional flags:

- `-VisualStudioSku Community` installs the full Visual Studio Community SKU
  instead of Build Tools.
- `-EnableVbScript` enables the Windows optional feature needed for local MSI
  packaging.
- `-InstallRepoDependencies` runs `npm ci` in the repo after the machine
  prerequisites are installed.

The script is safe to rerun and skips packages that are already installed. It
installs the Visual Studio C++ workload before `rustup` so Rust does not warn
about a missing MSVC toolchain prerequisite during setup.

Run these in an elevated terminal on the new box:

```bash
winget install --id Git.Git --exact --source winget --accept-source-agreements --accept-package-agreements
winget install --id OpenJS.NodeJS.LTS --exact --source winget \
  --accept-source-agreements --accept-package-agreements
winget install --id Rustlang.Rustup --exact --source winget \
  --accept-source-agreements --accept-package-agreements
winget install --id Microsoft.EdgeWebView2Runtime --exact --source winget \
  --accept-source-agreements --accept-package-agreements
```

Use this separate command for Visual Studio Build Tools:

```cmd
set VS_WORKLOAD=Microsoft.VisualStudio.Workload.VCTools
set VS_SDK=Microsoft.VisualStudio.Component.Windows11SDK.26100
winget install --id Microsoft.VisualStudio.2022.BuildTools --exact ^
  --source winget ^
  --override "--passive --add %VS_WORKLOAD% --add %VS_SDK%" ^
  --accept-source-agreements --accept-package-agreements
```

Notes:

- The Visual Studio Build Tools command installs the
  `Desktop development with C++` workload through
  `Microsoft.VisualStudio.Workload.VCTools`.
- The command also adds `Microsoft.VisualStudio.Component.Windows11SDK.26100`
  explicitly so the Windows SDK is not left to installer defaults.
- If you prefer the full Visual Studio IDE instead of Build Tools only, use this
  alternative command:

```bash
set VS_WORKLOAD=Microsoft.VisualStudio.Workload.VCTools
set VS_SDK=Microsoft.VisualStudio.Component.Windows11SDK.26100
winget install --id Microsoft.VisualStudio.2022.Community --exact ^
  --source winget ^
  --override "--passive --add %VS_WORKLOAD% --add %VS_SDK%" ^
  --accept-source-agreements --accept-package-agreements
```

- `VBSCRIPT` is not a winget package. If you need local MSI packaging support,
  enable it separately with Windows Features or:

```bash
dism /online /enable-feature /featurename:VBSCRIPT /all /norestart
```

- Restart the terminal after installing Node.js, Rust, or Visual Studio Build
  Tools so `node`, `cargo`, `cl`, and `link` are all on `PATH`.

## Why Each One Is Needed

### Git

Needed to clone the repo and pull updates.

Current box path:

- `C:\Program Files\Git\cmd\git.exe`

### Node.js

Needed for the Vite/React frontend and the local Tauri CLI dependency in
`package.json`.

Repo facts:

- `README.md` says Node.js `v18+`
- CI uses Node.js `20`
- Recommendation for the new box: install Node.js `20 LTS` to stay close to CI

Current box versions:

- `node -v` -> `v25.8.1`
- `npm -v` -> `11.11.0`

### Rust

Needed for the Tauri backend and native desktop build.

Repo facts:

- `src-tauri/Cargo.toml` sets `rust-version = "1.77.2"`
- Recommendation for the new box: install the latest stable MSVC toolchain
  through `rustup`

Current box versions:

- `rustc -V` -> `rustc 1.94.0 (4a4ef493e 2026-03-02)`
- `cargo -V` -> `cargo 1.94.0 (85eff7c80 2026-01-15)`
- `rustup show active-toolchain` -> `stable-x86_64-pc-windows-msvc (default)`

### Visual Studio C++ Build Tools

Needed because Tauri on Windows builds against the MSVC toolchain.

Install either:

- Visual Studio 2022 Build Tools
- Visual Studio 2022 Community

Required workload:

- `Desktop development with C++`

Required SDK:

- Windows SDK, ideally the Windows 11 SDK component installed by Visual Studio
  as `Microsoft.VisualStudio.Component.Windows11SDK.26100`

Current box evidence:

- `cl.exe` found under Visual Studio 2022 Community
- `link.exe` found under Visual Studio 2022 Community
- MSVC path includes version `14.44.35207`

Why the SDK matters:

- The MSVC compiler alone is not enough for a reliable native Windows build
- Missing SDK headers or libraries can block Tauri and Rust native linking on a
  fresh box
- This was a real setup pain point on the current machine, so the handoff should
  treat it as explicit, not implied

### WebView2 Runtime

Needed because Tauri uses Microsoft Edge WebView2 on Windows.

Notes:

- Windows 10 version 1803 and later usually already include it
- On a fresh or locked-down box, verify it is present before troubleshooting
  startup issues

### VBSCRIPT Optional Feature

Only needed if you want to build MSI installers locally.

Why this matters in this repo:

- `src-tauri/tauri.conf.json` sets `"bundle": { "targets": "all" }`
- Windows bundle config includes both NSIS and WiX targets
- Tauri documents that MSI creation can fail without the Windows `VBSCRIPT`
  optional feature enabled

If you only need local development with `npm run tauri dev`, this is not usually
required.

## What You Do Not Need To Install Separately

You do not need a separate global Tauri CLI install for normal repo work.

This repo already carries the CLI as a dev dependency:

- `@tauri-apps/cli` in `package.json`

After `npm ci` or `npm install`, use the local scripts from `package.json`.

If you only want the raw Windows executable and do not want NSIS or MSI
installers, use one of these instead of the full release bundle build:

```bash
npm run app:build:exe-only
```

or:

```powershell
.\scripts\Launch-CMTraceOpen.ps1 -Mode BuildExeOnly
```

That produces the app executable under `src-tauri\target\release\` without
running the Tauri bundling step.

## Fresh Machine Setup

### 1. Install the base tools

Install, in this order:

1. Git
2. Node.js 20 LTS
3. Visual Studio 2022 Build Tools or Community with
   `Desktop development with C++`
4. Confirm the Windows SDK component is installed with Visual Studio
5. WebView2 Runtime if it is not already present
6. Rust using `rustup`, keeping the default `stable-x86_64-pc-windows-msvc`
   toolchain

After installing Node.js and Rust, restart the terminal before validating
versions.

### 2. Verify the toolchain

Run these commands in a terminal:

```bash
git --version
node -v
npm -v
rustc -V
cargo -V
rustup show active-toolchain
where cl
where link
```

Expected shape:

- `node` resolves successfully
- `npm` resolves successfully
- active Rust toolchain is MSVC, not GNU
- `cl` and `link` resolve from Visual Studio
- Windows SDK is present in the Visual Studio installation

### 3. Clone and install dependencies

```bash
git clone https://github.com/adamgell/cmtraceopen.git
cd cmtraceopen
npm ci
```

Why `npm ci`:

- The repo has a `package-lock.json`
- CI uses `npm ci`
- It gives a cleaner, more reproducible dependency install on a new machine

### 4. Run the app in development mode

```bash
npm run tauri dev
```

Tauri will use:

- `npm run frontend:dev` for the Vite dev server
- the Rust backend in `src-tauri`

### 5. Build locally

Frontend-only build:

```bash
npm run frontend:build
```

Desktop debug build:

```bash
npm run app:build:debug
```

### VS Code live debugging on Windows

The repo includes a Windows-first F5 workflow in `.vscode/launch.json` and
`.vscode/tasks.json`.

Primary launch profile:

- `CMTrace Open: Debug (Windows)`

What it does:

1. Runs the `tauri:prepare-debug` task
2. Builds the Rust desktop target with
   `cargo build --manifest-path src-tauri/Cargo.toml`
3. Starts the Vite dev server on `http://localhost:1420`
4. Waits for the Vite server to advertise its local URL before launching the
   desktop app
5. Launches `src-tauri/target/debug/cmtrace-open.exe` under the VS Code debugger

This is the intended day-to-day live-debug path for the app on Windows. It gives
you Rust breakpoint support in the desktop process while still loading the dev
UI from Vite, so frontend edits continue to use live reload.

Optional secondary launch profile:

- `CMTrace Open: Frontend Debug (Edge)`

Use that only when you want browser-style frontend inspection against the Vite
dev server. It is intentionally secondary; the desktop F5 workflow remains the
source of truth for full-app debugging.

Recommended VS Code extensions:

- `ms-vscode.cpp-devtools`
- `rust-lang.rust-analyzer`

Common Windows debugging failure points:

1. Vite cannot bind to port `1420` because another process is already listening.
2. `WebView2 Runtime` is missing, so the Tauri desktop window cannot initialize.
3. The MSVC Rust toolchain or Visual Studio C++ build tools are not installed.
4. The debug executable under `src-tauri/target/debug/` is locked by a running
   app instance.
5. A previous terminal is still holding the Vite dev server open on the same
   port.

When F5 fails, check the `ui:dev` and `rust:build-debug` task output first. The
repo task configuration is designed so Vite startup and Rust compile failures
are visible in VS Code rather than failing silently.

Desktop release build:

```bash
npm run app:build:release
```

## Validation Commands

These are the repo validation commands reflected in CI.

TypeScript:

```bash
npx tsc --noEmit
```

Rust checks from `src-tauri`:

```bash
cd src-tauri
cargo check
cargo test
cargo clippy -- -D warnings
```

## Repo-Specific Notes

- CI is pinned to Node.js `20`, so matching that on the new box is the safest
  choice.
- `package-lock.json` and `src-tauri/Cargo.lock` are present, so dependency
  resolution is already pinned.
- `src-tauri/tauri.conf.json` uses `beforeDevCommand: "npm run frontend:dev"`
  and `beforeBuildCommand: "npm run frontend:build"`.
- Windows packaging is enabled through Tauri bundle targets, so
  packaging-related failures are usually toolchain or Windows-feature issues,
  not frontend issues.

## Troubleshooting

If `npm run tauri dev` fails early on a fresh Windows box, check these first:

1. `node`, `npm`, `cargo`, and `rustc` are on `PATH`
2. `rustup show active-toolchain` reports an MSVC toolchain
3. `cl.exe` resolves from Visual Studio
4. Windows SDK is installed in Visual Studio
5. WebView2 Runtime is installed
6. Terminal was restarted after installing Node.js or Rust

If MSI packaging fails, check the `VBSCRIPT` optional Windows feature next.

## Source References

These repo files were used as the source of truth for this setup note:

- `README.md`
- `package.json`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`
- `.github/workflows/cmtrace-ci.yml`
