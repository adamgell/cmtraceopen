//! Stable, structured classification for log-source access failures.
//!
//! The frontend must never decide to offer elevation by matching localized
//! strings like "Access is denied" or "os error 5". Those vary by Windows
//! display language and by which layer produced the message. This module gives
//! the decision a typed answer instead.
//!
//! Only the operating system's own error kind promotes a failure to
//! `accessDenied`. A missing file, a malformed log, a parse failure, and a
//! network timeout all keep their existing classification and reach the
//! frontend as ordinary string errors, so the recovery prompt cannot appear for
//! a problem elevation would not fix.

use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Longest path echoed back to the frontend as context.
///
/// The path is shown to the user so they know which source failed, so it is
/// bounded rather than omitted. Anything longer is truncated from the left,
/// keeping the file name that actually identifies the source.
const MAX_CONTEXT_PATH_LEN: usize = 260;

/// Which source operation was refused.
///
/// This drives the recovery prompt's wording and lets the frontend rebuild the
/// exact restore intent, rather than guessing from whatever it last opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceOperation {
    ReadFile,
    ListFolder,
    OpenKnownSource,
    WorkspaceAction,
}

/// Bounded identification of the source that was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SourceContext {
    Path { path: String },
    KnownSource { source_id: String },
}

impl SourceContext {
    /// Identify a source by path, bounded and with control characters removed.
    pub fn path(path: impl AsRef<std::path::Path>) -> Self {
        Self::Path {
            path: bounded_path(&path.as_ref().to_string_lossy()),
        }
    }

    /// Identify a source by its catalog id.
    pub fn known_source(source_id: impl Into<String>) -> Self {
        let source_id: String = source_id.into();
        Self::KnownSource {
            source_id: source_id.chars().take(128).collect(),
        }
    }
}

/// A source failure the frontend is allowed to act on structurally.
///
/// Serialized with a `kind` tag so new classifications can be added without
/// breaking the frontend's exhaustiveness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SourceAccessError {
    #[error("{message}")]
    AccessDenied {
        operation: SourceOperation,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<SourceContext>,
        /// Safe, app-authored text. Never the raw OS message, which can embed
        /// an unrelated path or a command line.
        message: String,
    },
}

impl SourceAccessError {
    pub fn operation(&self) -> SourceOperation {
        match self {
            Self::AccessDenied { operation, .. } => *operation,
        }
    }
}

/// Promote an I/O error to `accessDenied`, or decline to classify it.
///
/// Returns `None` for every error the operating system did not report as a
/// permission failure. Callers keep their existing error for that case: a
/// missing file must never offer elevation, because elevation will not find it.
///
/// `ErrorKind::PermissionDenied` is the whole test. On Windows the Rust
/// standard library already maps `ERROR_ACCESS_DENIED` (5) and
/// `ERROR_PRIVILEGE_NOT_HELD` (1314) onto it, so matching the kind covers the
/// native codes without hardcoding them. A sharing violation is deliberately
/// excluded — a file locked by another process is not fixed by elevating.
pub fn classify_io_error(
    error: &io::Error,
    operation: SourceOperation,
    context: Option<SourceContext>,
) -> Option<SourceAccessError> {
    if error.kind() != io::ErrorKind::PermissionDenied {
        return None;
    }

    Some(SourceAccessError::AccessDenied {
        operation,
        context,
        message: message_for(operation),
    })
}

/// Classify a file that cannot be opened, before a string-typed read path
/// discards the operating system's error kind.
///
/// This is a classification probe, not an authorization check. If it succeeds
/// and the real read then fails, the caller's existing error still applies —
/// the only thing lost is the chance to offer elevation, which is the safe
/// direction to fail.
pub fn probe_file_access(path: &str) -> Option<SourceAccessError> {
    match std::fs::File::open(path) {
        Ok(_) => None,
        Err(error) => classify_io_error(
            &error,
            SourceOperation::ReadFile,
            Some(SourceContext::path(path)),
        ),
    }
}

fn message_for(operation: SourceOperation) -> String {
    match operation {
        SourceOperation::ReadFile => "CMTrace Open does not have permission to read this file.",
        SourceOperation::ListFolder => "CMTrace Open does not have permission to read this folder.",
        SourceOperation::OpenKnownSource => {
            "CMTrace Open does not have permission to open this source."
        }
        SourceOperation::WorkspaceAction => {
            "CMTrace Open does not have permission to complete this action."
        }
    }
    .to_string()
}

/// Bound a path for display, keeping the identifying tail.
fn bounded_path(path: &str) -> String {
    let cleaned: String = path.chars().filter(|c| !c.is_control()).collect();
    if cleaned.chars().count() <= MAX_CONTEXT_PATH_LEN {
        return cleaned;
    }
    // Keep the end: the file name identifies the source, the root rarely does.
    let tail: String = cleaned
        .chars()
        .skip(cleaned.chars().count() - MAX_CONTEXT_PATH_LEN)
        .collect();
    format!("…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Access is denied. (os error 5)",
        )
    }

    #[test]
    fn a_permission_failure_is_classified() {
        let classified = classify_io_error(
            &denied(),
            SourceOperation::ReadFile,
            Some(SourceContext::path("C:\\Windows\\CCM\\Logs\\ccmexec.log")),
        )
        .expect("permission denied must classify");

        assert_eq!(classified.operation(), SourceOperation::ReadFile);
    }

    #[test]
    fn non_permission_failures_are_not_classified() {
        // Elevation cannot conjure a missing file, fix malformed data, or
        // shorten a network timeout, so none of these may offer it.
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidData,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::AlreadyExists,
            io::ErrorKind::InvalidInput,
        ] {
            let error = io::Error::new(kind, "boom");
            assert!(
                classify_io_error(&error, SourceOperation::ReadFile, None).is_none(),
                "{kind:?} must not be classified as access denied"
            );
        }
    }

    #[test]
    fn the_message_never_carries_the_raw_os_text() {
        // The OS string can embed an unrelated path or a command line.
        let classified =
            classify_io_error(&denied(), SourceOperation::ReadFile, None).expect("classified");
        let SourceAccessError::AccessDenied { message, .. } = &classified;

        assert!(!message.contains("os error"));
        assert!(!message.contains("Access is denied"));
        assert_eq!(
            message,
            "CMTrace Open does not have permission to read this file."
        );
    }

    #[test]
    fn each_operation_has_its_own_wording() {
        let messages: Vec<String> = [
            SourceOperation::ReadFile,
            SourceOperation::ListFolder,
            SourceOperation::OpenKnownSource,
            SourceOperation::WorkspaceAction,
        ]
        .iter()
        .map(|operation| message_for(*operation))
        .collect();

        let mut unique = messages.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            messages.len(),
            "wording must be distinguishable"
        );
    }

    #[test]
    fn the_wire_contract_is_camel_case_and_tagged() {
        let classified = classify_io_error(
            &denied(),
            SourceOperation::ListFolder,
            Some(SourceContext::known_source("ccm-client-logs")),
        )
        .expect("classified");

        let value = serde_json::to_value(&classified).expect("serialize");
        assert_eq!(value["kind"], "accessDenied");
        assert_eq!(value["operation"], "listFolder");
        assert_eq!(value["context"]["kind"], "knownSource");
        assert_eq!(value["context"]["sourceId"], "ccm-client-logs");
        assert!(value["message"].is_string());
    }

    #[test]
    fn a_missing_context_is_omitted_rather_than_null() {
        let classified = classify_io_error(&denied(), SourceOperation::WorkspaceAction, None)
            .expect("classified");
        let value = serde_json::to_value(&classified).expect("serialize");

        assert!(value.get("context").is_none());
    }

    #[test]
    fn a_path_context_is_bounded_and_keeps_the_file_name() {
        let long = format!("C:\\{}\\ccmexec.log", "a".repeat(MAX_CONTEXT_PATH_LEN * 2));
        let SourceContext::Path { path } = SourceContext::path(&long) else {
            panic!("expected a path context");
        };

        assert!(path.chars().count() <= MAX_CONTEXT_PATH_LEN + 1);
        assert!(
            path.ends_with("ccmexec.log"),
            "the identifying file name must survive truncation"
        );
    }

    #[test]
    fn control_characters_are_stripped_from_path_context() {
        let SourceContext::Path { path } = SourceContext::path("C:\\Logs\\a\u{7}b.log") else {
            panic!("expected a path context");
        };

        assert_eq!(path, "C:\\Logs\\ab.log");
    }

    #[test]
    fn a_source_id_context_is_bounded() {
        let SourceContext::KnownSource { source_id } = SourceContext::known_source("x".repeat(500))
        else {
            panic!("expected a known-source context");
        };

        assert_eq!(source_id.chars().count(), 128);
    }
}
