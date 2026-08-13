Stable downloads: https://download.cmtraceopen.com/?source=github-release

## CMTrace Open {{TAG}}

Open-source CMTrace log viewer with built-in Intune diagnostics.

### Download shortlinks

Each shortlink always resolves to the current stable release, so it stays valid in
tickets, runbooks, and slides long after this page scrolls out of view.

| Platform | Shortlink |
|----------|-----------|
| Windows x64, portable EXE | https://win.cmtrace.net |
| Windows ARM64, portable EXE | https://winarm.cmtrace.net |
| Windows x64, Lite portable EXE | https://lite.cmtrace.net |
| Windows x64, MSI installer | https://msi.cmtrace.net |
| macOS Apple silicon, DMG | https://mac.cmtrace.net |
| Linux x64, AppImage | https://linux.cmtrace.net |

Nightly channel: https://nightly.cmtrace.net

### Artifacts in {{TAG}}

| Platform | Files |
|----------|-------|
| Windows x64 and ARM64 | signed `.msi`, signed portable `.exe` (Full and Lite), signed `-setup.exe` |
| macOS Apple silicon | signed and notarized `.dmg`, plus the `.app.tar.gz` updater archive |
| Linux x64 | `.AppImage`, `.deb`, `.rpm` |

The MSI installs both the Full and Lite editions. Portable EXEs require no installation.

CycloneDX SBOMs (`sbom-rust.cdx.json`, `sbom-npm.cdx.json`) and build provenance
attestations are published alongside the binaries.
