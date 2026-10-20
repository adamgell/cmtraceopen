// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

#[cfg(feature = "semver")]
use crate::semver_compat::semver_compat_string;

use crate::SingleInstanceCallback;
use tauri::{
    plugin::{self, TauriPlugin},
    Manager, RunEvent, Runtime,
};
#[path = "linux/dbus.rs"]
mod dbus;

struct ConnectionHandle(dbus::PrimaryInstance);

pub fn init<R: Runtime>(
    callback: Box<SingleInstanceCallback<R>>,
    dbus_id: Option<String>,
) -> TauriPlugin<R> {
    plugin::Builder::new("single-instance")
        .setup(move |app, _api| {
            let mut dbus_name = dbus_id.unwrap_or_else(|| app.config().identifier.clone());
            dbus_name.push_str(".SingleInstance");

            #[cfg(feature = "semver")]
            {
                dbus_name.push('_');
                dbus_name.push_str(semver_compat_string(&app.package_info().version).as_str());
            }

            let mut dbus_path = dbus_name.replace('.', "/").replace('-', "_");
            if !dbus_path.starts_with('/') {
                dbus_path = format!("/{dbus_path}");
            }

            let app_handle = app.clone();
            let mut callback = callback;
            let instance = tauri::async_runtime::block_on(dbus::claim_or_forward(
                zbus::connection::Builder::session()
                    .method_timeout(std::time::Duration::from_secs(15)),
                &dbus_name,
                &dbus_path,
                Box::new(move |argv, cwd| callback(&app_handle, argv, cwd)),
                std::env::args().collect(),
                std::env::current_dir()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
                    .to_owned(),
            ));
            match instance {
                Ok(dbus::Instance::Primary(primary)) => {
                    app.manage(ConnectionHandle(primary));
                }
                Ok(dbus::Instance::Secondary) => {
                    app.cleanup_before_exit();
                    std::process::exit(0);
                }
                Err(dbus::ClaimError::Unavailable(error)) => {
                    tracing::warn!(%error, "Single-instance D-Bus ownership unavailable; continuing startup");
                }
                Err(dbus::ClaimError::Delivery(error)) => return Err(error.into()),
            }

            Ok(())
        })
        .on_event(move |app, event| {
            if let RunEvent::Exit = event {
                destroy(app);
            }
        })
        .build()
}

pub fn destroy<R: Runtime, M: Manager<R>>(manager: &M) {
    if let Some(connection) = manager.try_state::<ConnectionHandle>() {
        let _ = tauri::async_runtime::block_on(connection.0.release());
    }
}
