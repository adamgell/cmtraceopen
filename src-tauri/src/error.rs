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
}

impl From<AppError> for tauri::ipc::InvokeError {
    fn from(err: AppError) -> Self {
        tauri::ipc::InvokeError::from(err.to_string())
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
