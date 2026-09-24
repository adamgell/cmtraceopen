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
///
/// The one exception is a successful launch, where `latch` holds the guard for
/// the remaining life of the process. `app.exit(0)` is not instantaneous, so
/// releasing there would leave a window in which a late duplicate IPC call
/// could mint a second ticket and raise a second UAC prompt during teardown.
/// This mirrors the frontend coordinator, which keeps its own guard set after a
/// launch for the same reason.
struct InFlightGuard {
    release_on_drop: bool,
}

impl InFlightGuard {
    fn acquire() -> Option<Self> {
        REQUEST_IN_FLIGHT
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self {
                release_on_drop: true,
            })
    }

    /// Hold the latch permanently: the process is on its way out.
    fn latch(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.release_on_drop {
            REQUEST_IN_FLIGHT.store(false, Ordering::SeqCst);
        }
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
            Self::AlreadyInProgress | Self::TicketUnavailable | Self::StateDirectoryUnavailable => {
            }
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

/// Relaunch elevated with a one-time source ticket and closed workspace fallback.
///
/// A same-account child can consume the per-user ticket and restore the exact
/// source. An over-the-shoulder child runs under another profile, so only the
/// allowlisted workspace fallback remains available there.
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
    let Some(mut in_flight) = InFlightGuard::acquire() else {
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
    let workspace = request.workspace;
    let ticket = ticket_for(workspace, request.target, request.reason, now_ms());
    let ticket_id = write_ticket_off_thread(directory.clone(), ticket).await?;

    let launch_id = ticket_id.clone();
    let joined = tauri::async_runtime::spawn_blocking(move || {
        restart_with_provider(&NativeRelaunchProvider, Some(&launch_id), Some(workspace))
    })
    .await;

    let outcome = match joined {
        Ok(outcome) => outcome,
        // The task panicked or was cancelled, so no relaunch happened and the
        // ticket was never read. Remove it here rather than leaving restore
        // state on disk until the TTL sweep catches it.
        Err(_) => {
            discard_ticket_off_thread(directory.clone(), ticket_id.clone()).await;
            return Err(ElevationCommandError::from(RelaunchError::LaunchFailed {
                message: "administrator restart task failed".to_string(),
            }));
        }
    };

    match outcome {
        Ok(result) if result.launched => {
            // Windows has the elevated child. Hold the latch rather than
            // releasing it on the way out of this scope: the exit below is not
            // instantaneous, and a duplicate call landing in that window would
            // mint a second ticket and prompt for UAC again.
            in_flight.latch();
            app.exit(0);
            Ok(result)
        }
        // Cancelled, unsupported, or already elevated: the ticket was never
        // read, so remove it rather than leaving it to expire.
        Ok(result) => {
            discard_ticket_off_thread(directory.clone(), ticket_id.clone()).await;
            Ok(result)
        }
        Err(error) => {
            discard_ticket_off_thread(directory, ticket_id).await;
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
pub async fn get_initial_elevation_restore(
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

    match consume_initial_ticket_off_thread(directory, ticket_id, now_ms())
        .await
        .map(|outcome| outcome.ticket)
    {
        Some(Ok(ticket)) => Ok(ticket),
        Some(Err(error)) => {
            log::warn!(
                "[elevation] ignoring restore ticket: {}",
                ticket_summary(&error)
            );
            Ok(None)
        }
        None => {
            log::warn!("[elevation] restore ticket worker did not complete");
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

/// Run filesystem work on Tauri's blocking pool rather than an async command
/// worker. A join failure is deliberately separate from the operation's own
/// result so callers retain their existing bounded error mapping.
async fn run_blocking_operation<F, R>(operation: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation).await.ok()
}

async fn write_ticket_off_thread(
    directory: std::path::PathBuf,
    ticket: RestoreTicket,
) -> Result<String, ElevationCommandError> {
    run_blocking_operation(move || {
        crate::elevation::restore_ticket::write_ticket(&directory, &ticket)
    })
    .await
    .ok_or(ElevationCommandError::TicketUnavailable)?
    .map_err(|_| ElevationCommandError::TicketUnavailable)
}

async fn discard_ticket_off_thread(directory: std::path::PathBuf, ticket_id: String) {
    let _ = run_blocking_operation(move || discard_ticket(&directory, &ticket_id)).await;
}

struct InitialTicketIo {
    ticket: Result<Option<RestoreTicket>, TicketError>,
    #[cfg(test)]
    worker_thread: std::thread::ThreadId,
}

async fn consume_initial_ticket_off_thread(
    directory: std::path::PathBuf,
    ticket_id: Option<String>,
    now_ms: i64,
) -> Option<InitialTicketIo> {
    run_blocking_operation(move || InitialTicketIo {
        ticket: match ticket_id {
            Some(ticket_id) => consume_initial_ticket(&directory, &ticket_id, now_ms).map(Some),
            None => {
                // No requested ticket can be lost, so this startup can sweep
                // abandoned tickets immediately.
                prune_expired(&directory);
                Ok(None)
            }
        },
        #[cfg(test)]
        worker_thread: std::thread::current().id(),
    })
    .await
}

/// Claim the one ticket named by this startup before sweeping its directory.
/// A future or unreadable filesystem mtime must not make pruning erase the
/// requested ticket before its content timestamp is validated.
fn consume_initial_ticket(
    directory: &std::path::Path,
    ticket_id: &str,
    now_ms: i64,
) -> Result<RestoreTicket, TicketError> {
    let result = consume_ticket(directory, ticket_id, now_ms);
    prune_expired(directory);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, FileTimes};
    use std::thread;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    const TEST_NOW_MS: i64 = 1_760_000_000_000;

    #[test]
    fn ticket_operations_run_on_the_blocking_pool() {
        let caller = thread::current().id();
        let worker =
            tauri::async_runtime::block_on(run_blocking_operation(|| thread::current().id()))
                .expect("blocking worker completes");

        assert_ne!(worker, caller, "ticket I/O must leave the calling thread");
    }

    #[test]
    fn startup_ticket_claim_and_prune_run_on_the_blocking_pool() {
        let directory = TempDir::new().expect("temp dir");
        let ticket = ticket_for(
            crate::elevation::AppWorkspace::Log,
            crate::elevation::RestoreTarget::Workspace,
            crate::elevation::ElevationReason::ExplicitMenu,
            TEST_NOW_MS,
        );
        let id = crate::elevation::restore_ticket::write_ticket(directory.path(), &ticket)
            .expect("write ticket");
        let caller = thread::current().id();
        let outcome = tauri::async_runtime::block_on(consume_initial_ticket_off_thread(
            directory.path().to_path_buf(),
            Some(id),
            TEST_NOW_MS,
        ))
        .expect("blocking worker completes");
        let restored = outcome
            .ticket
            .expect("ticket operation succeeds")
            .expect("ticket is restored");

        assert_ne!(
            outcome.worker_thread, caller,
            "startup ticket I/O must leave the caller"
        );
        assert_eq!(restored, ticket);
    }

    #[test]
    fn startup_claims_the_requested_ticket_before_pruning_the_directory() {
        let directory = TempDir::new().expect("temp dir");
        let ticket = ticket_for(
            crate::elevation::AppWorkspace::Log,
            crate::elevation::RestoreTarget::Workspace,
            crate::elevation::ElevationReason::ExplicitMenu,
            TEST_NOW_MS,
        );
        let id = crate::elevation::restore_ticket::write_ticket(directory.path(), &ticket)
            .expect("write ticket");
        let path = directory.path().join(format!("{id}.json"));
        File::options()
            .write(true)
            .open(&path)
            .expect("open ticket")
            .set_times(FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(60)))
            .expect("set future mtime");

        let abandoned = ticket_for(
            crate::elevation::AppWorkspace::Log,
            crate::elevation::RestoreTarget::Workspace,
            crate::elevation::ElevationReason::ExplicitMenu,
            TEST_NOW_MS,
        );
        let abandoned_id =
            crate::elevation::restore_ticket::write_ticket(directory.path(), &abandoned)
                .expect("write abandoned ticket");
        let abandoned_path = directory.path().join(format!("{abandoned_id}.json"));
        File::options()
            .write(true)
            .open(&abandoned_path)
            .expect("open abandoned ticket")
            .set_times(FileTimes::new().set_modified(
                SystemTime::now()
                    - Duration::from_millis(
                        (crate::elevation::restore_ticket::TICKET_TTL_MS + 1_000) as u64,
                    ),
            ))
            .expect("age abandoned ticket");

        let restored = tauri::async_runtime::block_on(consume_initial_ticket_off_thread(
            directory.path().to_path_buf(),
            Some(id),
            TEST_NOW_MS,
        ))
        .expect("blocking worker completes")
        .ticket
        .expect("ticket operation succeeds")
        .expect("the requested ticket is consumed before the sweep");

        assert_eq!(restored, ticket);
        assert!(
            !abandoned_path.exists(),
            "claim-first ordering must not disable the ordinary expired-ticket sweep"
        );
    }

    // Both behaviours live in one test on purpose: `REQUEST_IN_FLIGHT` is
    // process-global, so splitting them would let the two cases race when the
    // harness runs them in parallel.
    #[test]
    fn the_in_flight_guard_admits_one_request_and_latches_after_a_launch() {
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

        // A launched restart keeps the latch for the life of the process:
        // app.exit(0) is not instantaneous, and a duplicate call landing in
        // that window would mint a second ticket and prompt for UAC again.
        let mut launched = InFlightGuard::acquire().expect("a fresh request proceeds");
        launched.latch();
        drop(launched);
        assert!(
            InFlightGuard::acquire().is_none(),
            "a latched guard must outlive its own drop"
        );

        // Leave the process-global latch as this test found it.
        REQUEST_IN_FLIGHT.store(false, Ordering::SeqCst);
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
                json["message"],
                expected,
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
