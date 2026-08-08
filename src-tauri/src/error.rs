use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Longest path echoed back to the frontend in an error payload.
///
/// The path in an `AccessDenied` is always one the caller just asked for, so it
/// leaks nothing new, but an unbounded string still has no business crossing the
/// IPC boundary into a dialog.
const MAX_ERROR_PATH_LEN: usize = 512;

/// Which source operation hit the failure.
///
/// The frontend uses this to word the recovery prompt. It is deliberately a
/// closed set: a new privileged workflow has to opt in here rather than
/// inheriting an elevation offer by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceOperation {
    ReadFile,
    ListFolder,
    OpenKnownSource,
    WorkspaceAction,
}

impl SourceOperation {
    fn subject(self) -> &'static str {
        match self {
            Self::ReadFile => "file",
            Self::ListFolder => "folder",
            Self::OpenKnownSource => "source",
            Self::WorkspaceAction => "workspace action",
        }
    }
}

/// True only when the operating system itself reported a permission failure.
///
/// Classification comes from the error kind and raw OS code, never from message
/// text: those strings are localized, so matching them would silently stop
/// working on a non-English Windows install and offer elevation for the wrong
/// failures.
///
/// # Callers must establish the path kind first
///
/// `ERROR_ACCESS_DENIED` (5) is not exclusively a permission verdict on Windows:
/// `CreateFileW` without `FILE_FLAG_BACKUP_SEMANTICS` returns it for a
/// *directory*, and std maps 5 to `ErrorKind::PermissionDenied`. Anything that
/// opens a user-supplied path must therefore stat it (`fs::metadata`, which does
/// pass `FILE_FLAG_BACKUP_SEMANTICS`) and reject a kind mismatch before asking
/// this function anything. Skipping that step turns every folder into an
/// elevation prompt that cannot succeed.
fn is_os_access_denied(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        return true;
    }

    // ERROR_ACCESS_DENIED (5) and ERROR_PRIVILEGE_NOT_HELD (1314). std already
    // maps 5 to PermissionDenied; 1314 has no stable ErrorKind, so it is matched
    // by code. Both mean the same thing to a user staring at a protected log.
    #[cfg(target_os = "windows")]
    {
        matches!(error.raw_os_error(), Some(5) | Some(1314))
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

const TRUNCATION_MARKER: &str = "…";

fn bounded_path(path: &str) -> String {
    if path.len() <= MAX_ERROR_PATH_LEN {
        return path.to_string();
    }
    // Reserve room for the marker so the result honours the cap rather than
    // overshooting it by the marker's width.
    let mut end = MAX_ERROR_PATH_LEN - TRUNCATION_MARKER.len();
    // Then walk back to a char boundary so the payload stays valid UTF-8.
    while end > 0 && !path.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATION_MARKER}", &path[..end])
}

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

    /// The operating system refused access to a source the user asked for.
    ///
    /// Carried separately from `Io` because this is the one failure the
    /// frontend may answer with an elevation offer, and it must be able to tell
    /// without reading message text.
    // Named after no particular OS: `is_os_access_denied` classifies
    // `ErrorKind::PermissionDenied` everywhere, so a root-owned log on macOS or
    // Linux reaches this variant too and "denied by Windows" would be a lie.
    #[error("Access to this {} was denied by the operating system.", operation.subject())]
    AccessDenied {
        operation: SourceOperation,
        path: Option<String>,
    },
}

impl AppError {
    /// Classifies an I/O failure against a source the user named.
    ///
    /// Returns `AccessDenied` only for a genuine OS permission refusal; every
    /// other I/O failure keeps its existing `Io` classification so a missing
    /// file or a malformed archive can never surface an elevation prompt.
    pub fn from_source_io(
        error: std::io::Error,
        operation: SourceOperation,
        path: Option<&str>,
    ) -> Self {
        if is_os_access_denied(&error) {
            return Self::AccessDenied {
                operation,
                path: path.map(bounded_path),
            };
        }
        Self::Io(error)
    }

    /// Builds the classification directly, for callers that already know the
    /// operation failed on permissions but have lost the original `io::Error`.
    pub fn access_denied(operation: SourceOperation, path: Option<&str>) -> Self {
        Self::AccessDenied {
            operation,
            path: path.map(bounded_path),
        }
    }
}

impl From<AppError> for tauri::ipc::InvokeError {
    fn from(err: AppError) -> Self {
        // Only Access Denied crosses the boundary as a structured payload. Every
        // other variant keeps its historical string shape, so this change cannot
        // turn an existing error message into "[object Object]" at the dozen or
        // so call sites that still do `String(error)`.
        //
        // The `message` field is the same text the string form would have
        // carried, which keeps `getSafeErrorMessage` producing identical copy.
        if let AppError::AccessDenied { operation, path } = &err {
            return tauri::ipc::InvokeError::from(serde_json::json!({
                "kind": "accessDenied",
                "operation": operation,
                "path": path,
                "message": err.to_string(),
            }));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    fn payload(err: AppError) -> serde_json::Value {
        tauri::ipc::InvokeError::from(err).0
    }

    #[test]
    fn permission_denied_is_classified_as_access_denied() {
        let error = AppError::from_source_io(
            IoError::new(ErrorKind::PermissionDenied, "denied"),
            SourceOperation::ReadFile,
            Some("C:\\Windows\\Logs\\CBS.log"),
        );

        assert!(matches!(
            error,
            AppError::AccessDenied {
                operation: SourceOperation::ReadFile,
                ..
            }
        ));
    }

    #[test]
    fn a_missing_file_never_becomes_access_denied() {
        // The whole point of classifying: a missing file must not offer to
        // restart the application as administrator.
        let error = AppError::from_source_io(
            IoError::new(ErrorKind::NotFound, "no such file"),
            SourceOperation::ReadFile,
            Some("/tmp/gone.log"),
        );

        assert!(matches!(error, AppError::Io(_)));
    }

    #[test]
    fn unrelated_io_failures_keep_their_io_classification() {
        for kind in [
            ErrorKind::InvalidData,
            ErrorKind::TimedOut,
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionRefused,
        ] {
            let error = AppError::from_source_io(
                IoError::new(kind, "boom"),
                SourceOperation::ListFolder,
                Some("/tmp/logs"),
            );
            assert!(matches!(error, AppError::Io(_)), "{kind:?} misclassified");
        }
    }

    #[test]
    fn access_denied_crosses_ipc_as_a_structured_payload() {
        let value = payload(AppError::access_denied(
            SourceOperation::ListFolder,
            Some("C:\\ProgramData\\Logs"),
        ));

        assert_eq!(value["kind"], "accessDenied");
        assert_eq!(value["operation"], "listFolder");
        assert_eq!(value["path"], "C:\\ProgramData\\Logs");
        // A human-readable message rides along so the existing frontend
        // normalizer keeps producing the same copy it always did.
        assert!(value["message"].as_str().is_some_and(|m| !m.is_empty()));
    }

    #[test]
    fn access_denied_without_a_path_serializes_a_null_path() {
        let value = payload(AppError::access_denied(SourceOperation::WorkspaceAction, None));

        assert_eq!(value["kind"], "accessDenied");
        assert!(value["path"].is_null());
    }

    #[test]
    fn every_other_variant_keeps_the_historical_string_shape() {
        // Guards the dozen call sites that still do `String(error)`: turning
        // these into objects would render "[object Object]" to the user.
        for error in [
            AppError::InvalidInput("bad".into()),
            AppError::State("locked".into()),
            AppError::Internal("boom".into()),
            AppError::Parse {
                file: "a.log".into(),
                reason: "bad".into(),
            },
            AppError::Io(IoError::new(ErrorKind::NotFound, "missing")),
        ] {
            let expected = error.to_string();
            assert_eq!(payload(error), serde_json::Value::String(expected));
        }
    }

    #[test]
    fn an_over_long_path_is_truncated_on_a_char_boundary() {
        let long = format!("C:\\{}\\é.log", "a".repeat(MAX_ERROR_PATH_LEN * 2));
        let value = payload(AppError::access_denied(
            SourceOperation::OpenKnownSource,
            Some(&long),
        ));

        let path = value["path"].as_str().expect("path present");
        // The cap is a cap: the marker must fit inside it, not extend past it.
        assert!(
            path.len() <= MAX_ERROR_PATH_LEN,
            "truncated path overshot the cap: {} bytes",
            path.len()
        );
        assert!(path.ends_with('…'));
    }

    #[test]
    fn a_path_exactly_at_the_cap_is_not_truncated() {
        let exact = "a".repeat(MAX_ERROR_PATH_LEN);
        let value = payload(AppError::access_denied(
            SourceOperation::ReadFile,
            Some(&exact),
        ));

        assert_eq!(value["path"], exact);
    }

    #[test]
    fn truncation_never_splits_a_multi_byte_character() {
        // Multi-byte chars straddling the cut point must not produce invalid
        // UTF-8; `is_char_boundary` walk-back is what prevents it.
        for pad in 0..8 {
            let long = format!("{}{}", "a".repeat(pad), "é".repeat(MAX_ERROR_PATH_LEN));
            let value = payload(AppError::access_denied(
                SourceOperation::ReadFile,
                Some(&long),
            ));
            let path = value["path"].as_str().expect("path present");
            assert!(path.len() <= MAX_ERROR_PATH_LEN, "pad {pad} overshot");
        }
    }

    #[test]
    fn the_access_denied_message_does_not_claim_a_particular_os() {
        // This variant is reachable on every platform: is_os_access_denied
        // classifies ErrorKind::PermissionDenied regardless of OS, so a
        // root-owned log on macOS or Linux lands here too.
        for operation in [
            SourceOperation::ReadFile,
            SourceOperation::ListFolder,
            SourceOperation::OpenKnownSource,
            SourceOperation::WorkspaceAction,
        ] {
            let message = AppError::access_denied(operation, None).to_string();
            for os in ["Windows", "macOS", "Linux"] {
                assert!(
                    !message.contains(os),
                    "{operation:?} names {os}: {message}"
                );
            }
        }
    }

    #[test]
    fn the_access_denied_message_names_the_operation_subject() {
        assert!(AppError::access_denied(SourceOperation::ReadFile, None)
            .to_string()
            .contains("file"));
        assert!(AppError::access_denied(SourceOperation::ListFolder, None)
            .to_string()
            .contains("folder"));
    }
}
