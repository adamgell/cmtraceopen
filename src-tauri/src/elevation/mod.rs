//! Application-wide, user-initiated Windows elevation.
//!
//! One owner for restart-as-administrator across every workspace. The elevated
//! child receives an opaque one-time restore ticket identifier plus a closed
//! workspace fallback for over-the-shoulder elevation — never a source path,
//! token, filter, or serialized session. See `relaunch` for the platform
//! mechanics and `restore_ticket` for the handoff.

pub mod relaunch;
pub mod restore_ticket;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Longest accepted known-source identifier.
pub const MAX_SOURCE_ID_LEN: usize = 128;

/// Longest accepted restore path, in bytes of its lossy UTF-8 form.
///
/// Windows extended-length paths stop at 32767 wide chars; this is well above
/// any real log path while still bounding the ticket.
pub const MAX_RESTORE_PATH_LEN: usize = 4096;

/// Workspaces the elevated process may be asked to restore.
///
/// Mirrors `WorkspaceId` in `src/types/log.ts`. Restoration is an allowlist: a
/// ticket naming an unknown workspace is rejected, never forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppWorkspace {
    Log,
    Intune,
    NewIntune,
    Dsregcmd,
    MacosDiag,
    MacosJamf,
    Deployment,
    EventLog,
    EspDiagnostics,
    Secureboot,
    Sysmon,
    Timeline,
    DnsDhcp,
}

impl AppWorkspace {
    /// The frontend workspace identifier, matching `WorkspaceId`.
    pub fn as_id(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Intune => "intune",
            Self::NewIntune => "new-intune",
            Self::Dsregcmd => "dsregcmd",
            Self::MacosDiag => "macos-diag",
            Self::MacosJamf => "macos-jamf",
            Self::Deployment => "deployment",
            Self::EventLog => "event-log",
            Self::EspDiagnostics => "esp-diagnostics",
            Self::Secureboot => "secureboot",
            Self::Sysmon => "sysmon",
            Self::Timeline => "timeline",
            Self::DnsDhcp => "dns-dhcp",
        }
    }

    /// Resolve an untrusted startup value through the same closed workspace
    /// vocabulary used by restore tickets.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "log" => Some(Self::Log),
            "intune" => Some(Self::Intune),
            "new-intune" => Some(Self::NewIntune),
            "dsregcmd" => Some(Self::Dsregcmd),
            "macos-diag" => Some(Self::MacosDiag),
            "macos-jamf" => Some(Self::MacosJamf),
            "deployment" => Some(Self::Deployment),
            "event-log" => Some(Self::EventLog),
            "esp-diagnostics" => Some(Self::EspDiagnostics),
            "secureboot" => Some(Self::Secureboot),
            "sysmon" => Some(Self::Sysmon),
            "timeline" => Some(Self::Timeline),
            "dns-dhcp" => Some(Self::DnsDhcp),
            _ => None,
        }
    }
}

/// Why elevation was requested. Drives the confirmation copy and the retry
/// marker; it never widens what the elevated process is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ElevationReason {
    /// The global File menu action.
    ExplicitMenu,
    /// A source operation returned a confirmed access-denied classification.
    AccessDenied,
    /// The ESP banner's coverage recommendation.
    CoverageRecommended,
}

/// The source intent to reopen after elevation, alongside the workspace.
///
/// `Workspace` restores navigation only. The remaining variants each carry one
/// validated source reference and nothing else.
/// `rename_all_fields` is load-bearing: `rename_all` renames the variants only,
/// so without it `KnownSource` crossed the boundary as `source_id` while the
/// frontend sent `sourceId`, and every known-source request failed to
/// deserialize before the handler ran. Pinned by the wire-shape tests below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RestoreTarget {
    /// Restore the workspace with no source.
    Workspace,
    /// Reopen one file through the normal log-source path.
    File { path: PathBuf },
    /// Reopen one folder through the normal folder-source path.
    ///
    /// No aggregate/browser discriminator rides along. Opening a folder without
    /// a selected file always produces the aggregated view, and the frontend has
    /// no folder mode a `false` flag could select, so a flag here would be
    /// written and then ignored. Restoring the path reproduces exactly what
    /// opening that folder does.
    Folder { path: PathBuf },
    /// Reopen a catalog entry by stable identifier, not by expanded path.
    KnownSource { source_id: String },
}

/// A validated frontend elevation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElevationRequest {
    pub reason: ElevationReason,
    pub workspace: AppWorkspace,
    #[serde(default = "workspace_only")]
    pub target: RestoreTarget,
}

fn workspace_only() -> RestoreTarget {
    RestoreTarget::Workspace
}

/// Whether this build/process can offer elevation, and whether it already has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppElevationState {
    /// Elevation is only offered where the platform provides UAC.
    pub platform_supported: bool,
    /// True when the current process already holds an elevated token.
    pub is_elevated: bool,
    /// Present when the elevation state could not be determined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Whether this platform offers a user-initiated elevation mechanism.
///
/// Elevation is a Windows/UAC concept. Everywhere else the menu item is hidden
/// and the recovery prompt never appears, rather than failing at the last step.
pub fn is_elevation_supported() -> bool {
    cfg!(target_os = "windows")
}

/// Probe the current process's elevation, for menus and recovery prompts.
///
/// A probe failure reports `is_elevated: false` with a `detail`, so the UI can
/// still offer the action instead of disabling it on an unknown state.
pub fn current_elevation_state() -> AppElevationState {
    if !is_elevation_supported() {
        return AppElevationState {
            platform_supported: false,
            is_elevated: false,
            detail: Some("Restarting as administrator is only supported on Windows".to_string()),
        };
    }

    match relaunch::is_process_elevated() {
        Ok(is_elevated) => AppElevationState {
            platform_supported: true,
            is_elevated,
            detail: None,
        },
        Err(detail) => AppElevationState {
            platform_supported: true,
            is_elevated: false,
            detail: Some(detail),
        },
    }
}

/// Rejection reasons for an untrusted elevation request or restore ticket.
///
/// Every variant is a refusal to act. None of them is recoverable by retrying
/// with the same input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ElevationValidationError {
    #[error("the restore path is empty")]
    EmptyPath,
    #[error("the restore path is not absolute")]
    RelativePath,
    #[error("the restore path exceeds the maximum accepted length")]
    PathTooLong,
    #[error("the restore path contains an unsupported character")]
    UnsafePathCharacter,
    #[error("the known-source identifier is empty")]
    EmptySourceId,
    #[error("the known-source identifier exceeds the maximum accepted length")]
    SourceIdTooLong,
    #[error("the known-source identifier contains an unsupported character")]
    UnsafeSourceId,
}

impl ElevationRequest {
    /// Validate every untrusted field, returning a request safe to persist.
    ///
    /// Validation is total: a request that returns `Ok` has a bounded, absolute,
    /// control-character-free path or a bounded identifier drawn from a
    /// conservative character set.
    pub fn validated(self) -> Result<Self, ElevationValidationError> {
        let target = match self.target {
            RestoreTarget::Workspace => RestoreTarget::Workspace,
            RestoreTarget::File { path } => RestoreTarget::File {
                path: validate_restore_path(&path)?,
            },
            RestoreTarget::Folder { path } => RestoreTarget::Folder {
                path: validate_restore_path(&path)?,
            },
            RestoreTarget::KnownSource { source_id } => RestoreTarget::KnownSource {
                source_id: validate_source_id(&source_id)?,
            },
        };
        Ok(Self { target, ..self })
    }
}

/// Accept only absolute, bounded, control-character-free paths.
///
/// This is a shape check, not an authorization check: the elevated process
/// still opens the path through the ordinary log-source path, which applies
/// the same permission and existence rules it always has.
pub fn validate_restore_path(path: &Path) -> Result<PathBuf, ElevationValidationError> {
    let text = path.to_string_lossy();
    if text.is_empty() {
        return Err(ElevationValidationError::EmptyPath);
    }
    if text.len() > MAX_RESTORE_PATH_LEN {
        return Err(ElevationValidationError::PathTooLong);
    }
    if text.chars().any(|character| character.is_control()) {
        return Err(ElevationValidationError::UnsafePathCharacter);
    }
    if !path.is_absolute() {
        return Err(ElevationValidationError::RelativePath);
    }
    Ok(path.to_path_buf())
}

/// Accept only bounded known-source identifiers drawn from `[A-Za-z0-9._:-]`.
///
/// Catalog identifiers are app-authored slugs. Refusing separators keeps a
/// tampered ticket from steering the catalog lookup toward a path.
pub fn validate_source_id(source_id: &str) -> Result<String, ElevationValidationError> {
    if source_id.is_empty() {
        return Err(ElevationValidationError::EmptySourceId);
    }
    if source_id.len() > MAX_SOURCE_ID_LEN {
        return Err(ElevationValidationError::SourceIdTooLong);
    }
    if !source_id.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
    }) {
        return Err(ElevationValidationError::UnsafeSourceId);
    }
    Ok(source_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute(path: &str) -> PathBuf {
        PathBuf::from(path)
    }

    #[cfg(target_os = "windows")]
    const ABSOLUTE_FILE: &str = r"C:\ProgramData\CMTrace\app.log";
    #[cfg(not(target_os = "windows"))]
    const ABSOLUTE_FILE: &str = "/var/log/app.log";

    #[test]
    fn workspace_ids_match_the_frontend_union() {
        // Guards the Rust <-> TypeScript allowlist. A new workspace must be
        // added to both or restoration silently falls back to the default.
        let ids: Vec<&str> = [
            AppWorkspace::Log,
            AppWorkspace::Intune,
            AppWorkspace::NewIntune,
            AppWorkspace::Dsregcmd,
            AppWorkspace::MacosDiag,
            AppWorkspace::MacosJamf,
            AppWorkspace::Deployment,
            AppWorkspace::EventLog,
            AppWorkspace::EspDiagnostics,
            AppWorkspace::Secureboot,
            AppWorkspace::Sysmon,
            AppWorkspace::Timeline,
            AppWorkspace::DnsDhcp,
        ]
        .iter()
        .map(|workspace| workspace.as_id())
        .collect();

        assert_eq!(
            ids,
            vec![
                "log",
                "intune",
                "new-intune",
                "dsregcmd",
                "macos-diag",
                "macos-jamf",
                "deployment",
                "event-log",
                "esp-diagnostics",
                "secureboot",
                "sysmon",
                "timeline",
                "dns-dhcp",
            ]
        );
    }

    #[test]
    fn workspace_serializes_to_the_frontend_identifier() {
        let json = serde_json::to_string(&AppWorkspace::EspDiagnostics).expect("serialize");
        assert_eq!(json, "\"esp-diagnostics\"");
        let parsed: AppWorkspace = serde_json::from_str("\"dns-dhcp\"").expect("deserialize");
        assert_eq!(parsed, AppWorkspace::DnsDhcp);
    }

    #[test]
    fn unknown_workspace_is_rejected() {
        let parsed = serde_json::from_str::<AppWorkspace>("\"not-a-workspace\"");
        assert!(
            parsed.is_err(),
            "unknown workspace ids must not deserialize"
        );
    }

    #[test]
    fn startup_workspace_ids_round_trip_through_the_closed_allowlist() {
        for workspace in [
            AppWorkspace::Log,
            AppWorkspace::Intune,
            AppWorkspace::NewIntune,
            AppWorkspace::Dsregcmd,
            AppWorkspace::MacosDiag,
            AppWorkspace::MacosJamf,
            AppWorkspace::Deployment,
            AppWorkspace::EventLog,
            AppWorkspace::EspDiagnostics,
            AppWorkspace::Secureboot,
            AppWorkspace::Sysmon,
            AppWorkspace::Timeline,
            AppWorkspace::DnsDhcp,
        ] {
            assert_eq!(AppWorkspace::from_id(workspace.as_id()), Some(workspace));
        }

        for untrusted in ["", "INTUNE", "future-workspace", "../intune"] {
            assert_eq!(AppWorkspace::from_id(untrusted), None, "{untrusted:?}");
        }
    }

    #[test]
    fn relative_restore_path_is_rejected() {
        let error = validate_restore_path(Path::new("relative/app.log")).unwrap_err();
        assert_eq!(error, ElevationValidationError::RelativePath);
    }

    #[test]
    fn empty_restore_path_is_rejected() {
        let error = validate_restore_path(Path::new("")).unwrap_err();
        assert_eq!(error, ElevationValidationError::EmptyPath);
    }

    #[test]
    fn oversized_restore_path_is_rejected() {
        let long = format!("{}{}", ABSOLUTE_FILE, "a".repeat(MAX_RESTORE_PATH_LEN));
        let error = validate_restore_path(Path::new(&long)).unwrap_err();
        assert_eq!(error, ElevationValidationError::PathTooLong);
    }

    #[test]
    fn control_characters_in_restore_path_are_rejected() {
        // A NUL would truncate the path at the Win32 boundary; reject the whole
        // control range rather than only the byte that happens to be fatal.
        let error = validate_restore_path(Path::new("/var/log/app\u{0}.log")).unwrap_err();
        assert_eq!(error, ElevationValidationError::UnsafePathCharacter);
    }

    #[test]
    fn absolute_restore_path_is_accepted() {
        let path = validate_restore_path(Path::new(ABSOLUTE_FILE)).expect("absolute path");
        assert_eq!(path, absolute(ABSOLUTE_FILE));
    }

    #[test]
    fn source_id_rejects_traversal_and_separators() {
        for candidate in ["../escape", "a/b", "a\\b", "a b", ""] {
            assert!(
                validate_source_id(candidate).is_err(),
                "source id {candidate:?} must be rejected"
            );
        }
    }

    #[test]
    fn source_id_accepts_catalog_slugs() {
        for candidate in ["company-portal-logs", "esp.bundle_1", "ns:source-2"] {
            assert!(
                validate_source_id(candidate).is_ok(),
                "source id {candidate:?} must be accepted"
            );
        }
    }

    #[test]
    fn oversized_source_id_is_rejected() {
        let error = validate_source_id(&"a".repeat(MAX_SOURCE_ID_LEN + 1)).unwrap_err();
        assert_eq!(error, ElevationValidationError::SourceIdTooLong);
    }

    #[test]
    fn request_validation_rewrites_only_the_target() {
        let request = ElevationRequest {
            reason: ElevationReason::AccessDenied,
            workspace: AppWorkspace::Log,
            target: RestoreTarget::File {
                path: absolute(ABSOLUTE_FILE),
            },
        };

        let validated = request.clone().validated().expect("valid request");

        assert_eq!(validated.reason, request.reason);
        assert_eq!(validated.workspace, request.workspace);
        assert_eq!(
            validated.target,
            RestoreTarget::File {
                path: absolute(ABSOLUTE_FILE)
            }
        );
    }

    #[test]
    fn request_validation_rejects_an_unsafe_target() {
        let request = ElevationRequest {
            reason: ElevationReason::ExplicitMenu,
            workspace: AppWorkspace::Log,
            target: RestoreTarget::KnownSource {
                source_id: "../../etc/passwd".to_string(),
            },
        };

        assert_eq!(
            request.validated().unwrap_err(),
            ElevationValidationError::UnsafeSourceId
        );
    }

    /// Pins the literal wire shape of every `RestoreTarget` variant.
    ///
    /// `rename_all` on an enum renames the VARIANTS only; struct-variant fields
    /// need `rename_all_fields`. Without it `KnownSource` crossed the boundary as
    /// `source_id` while the frontend sent `sourceId`, so every known-source
    /// elevation request failed to deserialize before the handler ran. Neither
    /// clippy nor tsc can see across that boundary, so it is pinned here.
    #[test]
    fn restore_targets_cross_the_ipc_boundary_in_camel_case() {
        let known = RestoreTarget::KnownSource {
            source_id: "ccm-logs".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&known).expect("serialize"),
            serde_json::json!({ "kind": "knownSource", "sourceId": "ccm-logs" })
        );

        assert_eq!(
            serde_json::to_value(RestoreTarget::Workspace).expect("serialize"),
            serde_json::json!({ "kind": "workspace" })
        );
        assert_eq!(
            serde_json::to_value(RestoreTarget::File {
                path: absolute("/logs/a.log")
            })
            .expect("serialize"),
            serde_json::json!({ "kind": "file", "path": "/logs/a.log" })
        );
    }

    #[test]
    fn a_camel_case_known_source_request_deserializes() {
        let target: RestoreTarget =
            serde_json::from_value(serde_json::json!({ "kind": "knownSource", "sourceId": "ccm-logs" }))
                .expect("camelCase is the wire contract");

        assert_eq!(
            target,
            RestoreTarget::KnownSource {
                source_id: "ccm-logs".to_string()
            }
        );
    }

    #[test]
    fn the_snake_case_known_source_form_is_rejected_rather_than_tolerated() {
        // Accepting both would let the contract drift back without a test failing.
        let result: Result<RestoreTarget, _> =
            serde_json::from_value(serde_json::json!({ "kind": "knownSource", "source_id": "ccm-logs" }));

        assert!(result.is_err(), "snake_case must not be accepted");
    }
}
