//! Read-only native evidence acquisition for ESP diagnostics.
//!
//! Offline evidence normalization is portable. Live acquisition is exposed only
//! where the operating system provides the required Windows evidence sources.

pub mod archive;
pub mod discovery;
pub mod event_logs;
pub mod live_session;
pub mod process;
pub mod registry;
pub mod relaunch;
pub mod session;
pub mod system;
pub mod tailing;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspAcquisitionCapability {
    pub offline_analysis_supported: bool,
    pub live_acquisition_supported: bool,
    pub live_acquisition_detail: Option<String>,
}

pub fn acquisition_capability() -> EspAcquisitionCapability {
    EspAcquisitionCapability {
        offline_analysis_supported: true,
        live_acquisition_supported: cfg!(target_os = "windows"),
        live_acquisition_detail: if cfg!(target_os = "windows") {
            None
        } else {
            Some("Live ESP evidence acquisition is only supported on Windows".to_string())
        },
    }
}
