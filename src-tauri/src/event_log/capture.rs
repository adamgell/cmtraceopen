//! Provider-metadata capture seam.
//!
//! The provider-capture lane owns the Windows Event Log publisher traversal. This module keeps the
//! stable command-facing seam in the event-viewer foundation without fabricating provider rows when
//! that traversal is not present.

use std::path::Path;

#[derive(Debug)]
pub struct CaptureError(pub String);

impl std::fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CaptureError {}

#[cfg(target_os = "windows")]
pub fn capture_providers_to_db(_db_path: &Path) -> Result<(), CaptureError> {
    Err(CaptureError(
        "Provider capture traversal is not available in the event-viewer foundation build"
            .to_string(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn capture_providers_to_db(_db_path: &Path) -> Result<(), CaptureError> {
    Err(CaptureError(
        "Provider capture is only available on Windows".to_string(),
    ))
}
