# CMTrace Open owned single-instance plugin

This unpublished local derivative of Tauri's `tauri-plugin-single-instance` 2.4.5
is maintained by CMTrace Open as `2.4.5+cmtraceopen.1`. It requires Rust 1.89.
The published source and original Apache-2.0/MIT licenses are retained. Windows
and macOS backend source bytes are unchanged.

The Linux backend uses maintained zbus 6 with Tokio on Tauri's existing async
runtime. It registers its activation interface before requesting exclusive
ownership, disallows replacement and queuing, and awaits the primary's reply
before a secondary exits. If the bus, interface, or name acquisition is unavailable
before an existing owner is established, startup continues with a warning and
without a managed single-instance lock. Once an existing owner is established,
failed delivery propagates through plugin setup; the secondary cannot report a
successful handoff. The managed primary connection remains alive until cleanup.

See [provenance and maintenance policy](../../docs/architecture/owned-single-instance-plugin.md).

Run `cargo test --locked -p tauri-plugin-single-instance` with `dbus-daemon`
installed. Tests start bounded private daemons, use explicit socket addresses,
and reap their own child processes. They never connect to the user's bus. The
ignored secondary-process fixture is launched by the handoff test itself.
On macOS, unit-test compilation also typechecks the Linux Tauri adapter; this
is source validation and does not replace supported Linux native acceptance.
