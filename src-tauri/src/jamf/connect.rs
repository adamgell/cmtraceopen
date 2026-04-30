use std::path::Path;

use crate::error::AppError;
use crate::jamf::models::JamfConnectEvent;

pub fn parse_connect_log_impl(path: &Path) -> Result<Vec<JamfConnectEvent>, AppError> {
    let _ = path; // Implemented in Phase 4.
    Ok(Vec::new())
}
