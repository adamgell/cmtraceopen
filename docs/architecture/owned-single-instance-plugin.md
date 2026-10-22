# Owned single-instance plugin

CMTrace Open owns the focused derivative in
`crates/tauri-plugin-single-instance`, based on the published Tauri plugin
2.4.5. Its local version is `2.4.5+cmtraceopen.1`. The application uses this
workspace package directly; no registry or Git fallback is configured.

Upstream source provenance: `tauri-apps/plugins-workspace`, commit
`5baf71a47292d8490f0ba3d53f15224e55c48327`, directory
`plugins/single-instance`. The upstream Apache-2.0 and MIT license files and
source notices are retained. The registry archive checksum is
`db817fe9295e19b7d8357e900af31edb93703dd9fb6de524b007b47b6afc63b0`. Windows and macOS implementations are unchanged
from the published source.

## Scope and runtime

The Linux backend uses maintained zbus 6 instead of the standalone
zvariant/zbus_names family reported by RUSTSEC-2026-0370, RUSTSEC-2026-0371
and RUSTSEC-2026-0372. Those advisories are not ignored. zbus 6 removes its
blocking API, so this is an asynchronous source port, rather than a version
constraint override.

The backend uses Tauri's existing Tokio runtime with explicit zbus Tokio and
service features. It preserves the per-application bus name and object path,
exclusive name ownership without replacement, argv/working-directory handoff
to the primary instance, and connection/name lifetime through shutdown. A
secondary process exits successfully only after handoff succeeds. D-Bus method
calls have a 15-second timeout; a timed-out handoff is a delivery error, not a
successful exit. If the session
bus cannot be reached or name ownership cannot be established, the application
retains the upstream startup behavior without instance enforcement and logs a
warning. A failure delivering arguments after an existing primary is detected
propagates as a setup error instead of reporting successful delivery. Private
bus identity, ownership and isolation checks in the test harness remain strict.
No network listeners, alternate IPC backend or security-policy changes are added.

The desktop compiler floor rises from Rust 1.88 to 1.89 for zbus 6. The normal
compiler remains pinned at 1.98.1; CI verifies the new floor on Linux and
Windows. Parser metadata and its separate compiler contract remain unchanged.
No Tauri update is necessary for this port. Windows/macOS supported versions
and the Ubuntu 22.04/24.04 package acceptance baselines remain unchanged.

## Ownership and upstream tracking

The CMTrace Open maintainers own this source and its updates. Track
[upstream issue 3716](https://github.com/tauri-apps/plugins-workspace/issues/3716)
for a maintained official zbus 6 implementation. Compare future upstream
changes against the documented source baseline, including Windows/macOS
security fixes, and repeat the regression/native matrix before adopting them.
An official release is a migration candidate only after its dependency graph
removes the advisory-covered family and its behavior passes the same gates.
This derivative has no automatic expiry or unreviewed upstream sync.

## Required verification

- Resolve the entire workspace and confirm no zbus 5, zvariant, zbus_names or
  zvariant_derive remains. Run cargo-deny and cargo-audit without new ignores.
- Run real private-session D-Bus tests for exclusive election, argv/cwd
  delivery, name nonreplacement, connection cleanup and failure propagation:
  `dbus-run-session -- cargo test --locked -p tauri-plugin-single-instance`.
  Local macOS protocol tests are useful source validation; they do not prove
  the installed Linux application or final AppImage behavior.
- Run full/Lite Rust tests, strict Clippy, MSRV, parser WASM and frontend gates.
- Verify unchanged Windows/macOS plugin source against the published baseline.
- Exercise two launches, file handoff and clean restart with the exact final
  signed packages on both Ubuntu baselines. Retain the existing Windows and
  macOS native/package acceptance gates as well.
