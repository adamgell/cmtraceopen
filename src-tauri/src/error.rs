use thiserror::Error;

/// Structured error type for CMTrace Open backend.
///
/// All Tauri IPC commands should return `Result<T, AppError>` instead of
/// `Result<T, String>`. The `From<AppError> for tauri::ipc::InvokeError`
/// implementation ensures errors are serialized to the frontend as strings.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error in {file}: {reason}")]
    Parse { file: String, reason: String },

    #[error("{0}")]
    InvalidInput(String),

    #[error("State error: {0}")]
    State(String),

    #[error("Platform not supported: {0}")]
    PlatformUnsupported(String),

    #[error("Analysis failed: {0}")]
    Analysis(String),

    #[error("{0}")]
    Internal(String),

    /// A source failure the frontend is allowed to branch on structurally.
    ///
    /// Unlike every other variant this crosses the IPC boundary as an object
    /// rather than a string, so the elevation recovery prompt can key off a
    /// stable classification instead of matching localized OS text.
    #[error("{0}")]
    SourceAccess(#[from] crate::source_access::SourceAccessError),
}

impl From<AppError> for tauri::ipc::InvokeError {
    fn from(err: AppError) -> Self {
        match err {
            // Tauri's blanket `impl<T: Serialize> From<T> for InvokeError`
            // turns this into structured JSON. Everything else keeps the
            // string form every existing frontend consumer already expects.
            AppError::SourceAccess(detail) => tauri::ipc::InvokeError::from(detail),
            other => tauri::ipc::InvokeError::from(other.to_string()),
        }
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::Internal(s)
    }
}

impl From<&str> for AppError {
    fn from(s: &str) -> Self {
        AppError::Internal(s.to_string())
    }
}

/// Convenience alias for command return types.
pub type CmdResult<T> = Result<T, AppError>;
