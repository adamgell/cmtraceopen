//! Tauri IPC for application-wide restart as administrator.
//!
//! This is the only place the application decides to relaunch itself elevated.
//! Every workspace, the global menu, and the Access Denied recovery prompt go
//! through `restart_as_administrator`; none of them owns a relaunch of its own.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use thiserror::Error;

use crate::elevation::relaunch::{
    restart_with_provider, NativeRelaunchProvider, RelaunchError, RelaunchReason, RelaunchResult,
};
use crate::elevation::restore_ticket::{
    consume_ticket, discard_ticket, prune_expired, ticket_directory, ticket_for, RestoreTicket,
    TicketError,
};
use crate::elevation::{AppElevationState, ElevationRequest, ElevationValidationError};
use crate::state::app_state::AppState;

/// Guards against a double-click or two workspaces racing the same prompt.
///
/// Only one request may be in flight: a second concurrent call is refused
/// rather than queued, so the user cannot stack UAC prompts.
static REQUEST_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Releases the in-flight guard however the request ends, including on an early
/// return or a panic unwinding through the command.
struct InFlightGuard;

impl InFlightGuard {
    fn acquire() -> Option<Self> {
        REQUEST_IN_FLIGHT
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        REQUEST_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

/// Why a restart request could not be carried out.
///
/// Nested causes stay nested rather than flattened: both this enum and its
/// sources are internally tagged on `kind`, so flattening would collide.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ElevationCommandError {
    #[error("another administrator restart is already in progress")]
    AlreadyInProgress,
    #[error("the elevation request was rejected: {reason}")]
    InvalidRequest { reason: ElevationValidationError },
    #[error("the elevation restore ticket could not be prepared")]
    TicketUnavailable,
    #[error("{source}")]
    Relaunch { source: RelaunchError },
    #[error("the application state directory is unavailable")]
    StateDirectoryUnavailable,
}

impl ElevationCommandError {
    fn kind(&self) -> &'static str {
        match self {
            Self::AlreadyInProgress => "alreadyInProgress",
            Self::InvalidRequest { .. } => "invalidRequest",
            Self::TicketUnavailable => "ticketUnavailable",
            Self::Relaunch { .. } => "relaunch",
            Self::StateDirectoryUnavailable => "stateDirectoryUnavailable",
        }
    }
}

/// Serialized by hand so a top-level `message` always rides along.
///
/// The derived internally-tagged form emitted only `kind` plus a nested cause,
/// and the frontend's error normalizer reads only own, top-level string
/// properties: it never recurses. A launch failure therefore reached the user as
/// the humanized variant name, the bare word "Relaunch", with the real reason
/// stranded inside `source`. The nested cause is still emitted for callers that
/// want it; `message` is what actually gets rendered.
impl Serialize for ElevationCommandError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("kind", self.kind())?;
        map.serialize_entry("message", &self.to_string())?;
        match self {
            Self::InvalidRequest { reason } => map.serialize_entry("reason", reason)?,
            Self::Relaunch { source } => map.serialize_entry("source", source)?,
            Self::AlreadyInProgress
            | Self::TicketUnavailable
            | Self::StateDirectoryUnavailable => {}
        }
        map.end()
    }
}

impl From<ElevationValidationError> for ElevationCommandError {
    fn from(reason: ElevationValidationError) -> Self {
        Self::InvalidRequest { reason }
    }
}

impl From<RelaunchError> for ElevationCommandError {
    fn from(source: RelaunchError) -> Self {
        Self::Relaunch { source }
    }
}

/// Report whether elevation can be offered and whether it is already held.
#[tauri::command]
pub fn get_app_elevation_state() -> AppElevationState {
    crate::elevation::current_elevation_state()
}

/// Relaunch elevated, restoring only the requested workspace and source.
///
/// The current process exits only after Windows confirms the elevated child
/// started. Cancelling UAC, running on an unsupported platform, and already
/// being elevated all return normally with `launched: false` so the caller
/// keeps its state.
#[tauri::command]
pub async fn restart_as_administrator(
    app: AppHandle,
    request: ElevationRequest,
) -> Result<RelaunchResult, ElevationCommandError> {
    let Some(_in_flight) = InFlightGuard::acquire() else {
        return Err(ElevationCommandError::AlreadyInProgress);
    };

    let request = request.validated()?;

    // Answer the cheap, no-side-effect outcomes before writing anything: an
    // unsupported platform or an already-elevated process must not leave a
    // ticket behind.
    let state = crate::elevation::current_elevation_state();
    if !state.platform_supported {
        return Ok(RelaunchResult {
            launched: false,
            reason: RelaunchReason::UnsupportedPlatform,
        });
    }
    if state.is_elevated {
        return Ok(RelaunchResult {
            launched: false,
            reason: RelaunchReason::AlreadyElevated,
        });
    }

    let directory = ticket_directory(
        &app.path()
            .app_local_data_dir()
            .map_err(|_| ElevationCommandError::StateDirectoryUnavailable)?,
    );
    let ticket = ticket_for(request.workspace, request.target, request.reason, now_ms());
    let ticket_id = crate::elevation::restore_ticket::write_ticket(&directory, &ticket)
        .map_err(|_| ElevationCommandError::TicketUnavailable)?;

    let launch_id = ticket_id.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        restart_with_provider(&NativeRelaunchProvider, Some(&launch_id))
    })
    .await
    .map_err(|_| {
        ElevationCommandError::from(RelaunchError::LaunchFailed {
            message: "administrator restart task failed".to_string(),
        })
    })?;

    match outcome {
        Ok(result) if result.launched => {
            app.exit(0);
            Ok(result)
        }
        // Cancelled, unsupported, or already elevated: the ticket was never
        // read, so remove it rather than leaving it to expire.
        Ok(result) => {
            discard_ticket(&directory, &ticket_id);
            Ok(result)
        }
        Err(error) => {
            discard_ticket(&directory, &ticket_id);
            Err(error.into())
        }
    }
}

/// Claim the restore ticket this elevated process was started with, if any.
///
/// Returns `Ok(None)` for every unusable case — no ticket, expired, malformed,
/// or already consumed. A failed restore is never fatal: the application starts
/// normally, which is why this reports absence rather than an error.
#[tauri::command]
pub fn get_initial_elevation_restore(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<RestoreTicket>, crate::error::AppError> {
    let ticket_id = {
        let mut guard = state
            .initial_elevation_restore
            .lock()
            .map_err(|error| crate::error::AppError::State(error.to_string()))?;
        guard.take()
    };

    let Ok(app_data) = app.path().app_local_data_dir() else {
        return Ok(None);
    };
    let directory = ticket_directory(&app_data);

    // Clear abandoned tickets from cancelled prompts on the way past.
    prune_expired(&directory);

    let Some(ticket_id) = ticket_id else {
        return Ok(None);
    };

    match consume_ticket(&directory, &ticket_id, now_ms()) {
        Ok(ticket) => Ok(Some(ticket)),
        Err(error) => {
            log::warn!(
                "[elevation] ignoring restore ticket: {}",
                ticket_summary(&error)
            );
            Ok(None)
        }
    }
}

/// A bounded description of why a ticket was ignored, safe for the app log.
fn ticket_summary(error: &TicketError) -> &'static str {
    match error {
        TicketError::MalformedId => "malformed identifier",
        TicketError::NotFound => "not found",
        TicketError::NotARegularFile => "not a regular file",
        TicketError::TooLarge => "too large",
        TicketError::Unreadable => "unreadable",
        TicketError::Unwritable => "unwritable",
        TicketError::Malformed => "malformed contents",
        TicketError::UnsupportedSchema => "unsupported schema",
        TicketError::Expired => "expired",
        TicketError::InvalidContents => "invalid contents",
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_in_flight_guard_admits_one_request_at_a_time() {
        let first = InFlightGuard::acquire().expect("first request proceeds");
        assert!(
            InFlightGuard::acquire().is_none(),
            "a concurrent request must be refused"
        );
        drop(first);
        assert!(
            InFlightGuard::acquire().is_some(),
            "the guard must release once the request finishes"
        );
    }

    #[test]
    fn elevation_state_matches_platform_support() {
        let state = get_app_elevation_state();
        assert_eq!(state.platform_supported, cfg!(target_os = "windows"));
        if !cfg!(target_os = "windows") {
            assert!(
                !state.is_elevated,
                "a platform without UAC never reports an elevated token"
            );
        }
    }

    #[test]
    fn every_ticket_rejection_has_a_bounded_summary() {
        for error in [
            TicketError::MalformedId,
            TicketError::NotFound,
            TicketError::NotARegularFile,
            TicketError::TooLarge,
            TicketError::Unreadable,
            TicketError::Unwritable,
            TicketError::Malformed,
            TicketError::UnsupportedSchema,
            TicketError::Expired,
            TicketError::InvalidContents,
        ] {
            let summary = ticket_summary(&error);
            assert!(!summary.is_empty());
            assert!(summary.len() < 64, "summaries stay short for the app log");
        }
    }

    #[test]
    fn command_errors_serialize_with_a_stable_kind() {
        let error = ElevationCommandError::AlreadyInProgress;
        let json = serde_json::to_value(&error).expect("serialize");
        assert_eq!(json["kind"], "alreadyInProgress");

        let error = ElevationCommandError::from(ElevationValidationError::RelativePath);
        let json = serde_json::to_value(&error).expect("serialize");
        assert_eq!(json["kind"], "invalidRequest");
    }

    #[test]
    fn every_command_error_carries_a_top_level_message() {
        // The frontend normalizer reads only own, top-level string properties and
        // never recurses into a nested cause. Without `message` here the user was
        // shown the humanized variant name, i.e. the bare word "Relaunch".
        let errors = [
            ElevationCommandError::AlreadyInProgress,
            ElevationCommandError::from(ElevationValidationError::RelativePath),
            ElevationCommandError::TicketUnavailable,
            ElevationCommandError::from(RelaunchError::LaunchFailed {
                message: "administrator restart task failed".to_string(),
            }),
            ElevationCommandError::StateDirectoryUnavailable,
        ];

        for error in errors {
            let expected = error.to_string();
            let json = serde_json::to_value(&error).expect("serialize");

            assert_eq!(
                json["message"], expected,
                "{} lost its message",
                error.kind()
            );
            assert!(
                json["message"].as_str().is_some_and(|m| !m.is_empty()),
                "{} serialized an empty message",
                error.kind()
            );
        }
    }

    #[test]
    fn a_nested_cause_is_still_available_alongside_the_message() {
        let error = ElevationCommandError::from(RelaunchError::LaunchFailed {
            message: "ShellExecute refused".to_string(),
        });
        let json = serde_json::to_value(&error).expect("serialize");

        assert_eq!(json["kind"], "relaunch");
        assert_eq!(json["source"]["kind"], "launchFailed");
        // The rendered text is the flat one, and it carries the real reason.
        assert!(json["message"]
            .as_str()
            .expect("message")
            .contains("ShellExecute refused"));
    }
}
