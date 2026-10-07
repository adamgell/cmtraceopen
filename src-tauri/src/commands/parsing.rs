use crate::models::log_entry::{LogEntry, LogFormat, ParserKind};
use crate::state::app_state::AppState;
use crate::watcher::{
    firewall::{self, FirewallControlToken, FirewallDecodingStatus, StartAdmission},
    tail::{self, TailEntryAmendment},
};
use cmtraceopen_parser::{
    models::firewall::FirewallCoverage, parser::firewall_stream::FirewallRowReplacement,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Emitter, State};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailPayload {
    pub entries: Vec<LogEntry>,
    pub amendments: Vec<TailEntryAmendment>,
    pub file_path: String,
    pub parse_errors: u32,
    pub observed_through_line: Option<u32>,
    pub reset: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_control: Option<FirewallControlToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_replacements: Option<Vec<FirewallRowReplacement>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_coverage: Option<FirewallCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_decoding: Option<FirewallDecodingStatus>,
}
impl TailPayload {
    pub(crate) fn firewall(
        path: String,
        control: FirewallControlToken,
        batch: firewall::FirewallBatch,
    ) -> Self {
        Self {
            entries: batch.entries,
            amendments: vec![],
            file_path: path,
            parse_errors: batch.coverage.parse_errors(),
            observed_through_line: Some(batch.observed_through_line),
            reset: batch.reset,
            firewall_control: Some(control),
            firewall_replacements: Some(batch.replacements),
            firewall_coverage: Some(batch.coverage),
            firewall_decoding: Some(batch.decoding),
        }
    }
}

enum TailLaunch {
    Ordinary(tail::TailStart),
    Firewall,
}
#[derive(Clone, Copy)]
enum TailControl {
    Stop,
    Pause,
    Resume,
}

/// Lock order is always open_files then tail_sessions. No worker joins occur
/// under either lock. Admission and replacement are one atomic operation.
fn admit_tail_start(
    state: &AppState,
    path: &Path,
    control: Option<&FirewallControlToken>,
    byte_offset: u64,
    next_id: u64,
    next_line: u32,
    launch: impl FnOnce(TailLaunch) -> Result<tail::TailSession, crate::error::AppError>,
) -> Result<(), crate::error::AppError> {
    let mut files = state
        .open_files
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;
    let opened = files.get_mut(path).ok_or_else(|| {
        crate::error::AppError::InvalidInput(format!("file is not open: {}", path.display()))
    })?;
    let start = if let Some(owner) = opened.firewall.as_mut() {
        if owner.start(control) != StartAdmission::Started {
            return Ok(());
        }
        TailLaunch::Firewall
    } else {
        if control.is_some() {
            return Ok(());
        }
        if opened.parser_selection.parser == ParserKind::WindowsFirewall {
            return Err(crate::error::AppError::State(
                "Firewall continuation is unavailable; reopen the source".into(),
            ));
        }
        TailLaunch::Ordinary(tail::TailStart {
            byte_offset,
            next_id,
            next_line,
            parser_selection: opened.parser_selection.clone(),
            file_identity: opened.file_identity,
            initial_logical_record: (opened.byte_offset == byte_offset)
                .then(|| opened.initial_logical_record.take())
                .flatten(),
        })
    };
    let mut sessions = state
        .tail_sessions
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;
    let session = match launch(start) {
        Ok(session) => session,
        Err(error) => {
            if let Some(owner) = opened.firewall.as_mut() {
                owner.stop(control);
            }
            return Err(error);
        }
    };
    if let Some(old) = sessions.insert(path.to_path_buf(), session) {
        old.stop();
    }
    Ok(())
}
fn control_tail(
    state: &AppState,
    path: &Path,
    control: Option<&FirewallControlToken>,
    action: TailControl,
) -> Result<(), crate::error::AppError> {
    let mut files = state
        .open_files
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;
    match files
        .get_mut(path)
        .and_then(|opened| opened.firewall.as_mut())
    {
        Some(owner) => {
            let accepted = match action {
                TailControl::Stop => owner.stop(control),
                TailControl::Pause => owner.set_paused(control, true),
                TailControl::Resume => owner.set_paused(control, false),
            };
            if !accepted {
                return Ok(());
            }
        }
        None if control.is_some() => return Ok(()),
        None => {}
    }
    let mut sessions = state
        .tail_sessions
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;
    match action {
        TailControl::Stop => {
            if let Some(session) = sessions.remove(path) {
                session.stop();
            }
        }
        TailControl::Pause | TailControl::Resume => {
            if let Some(session) = sessions.get(path) {
                session.set_paused(matches!(action, TailControl::Pause));
            }
        }
    }
    Ok(())
}

// Tauri injects app/state; retain the ordinary IPC arguments alongside the firewall token.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn start_tail(
    path: String,
    _format: LogFormat,
    byte_offset: u64,
    next_id: u64,
    next_line: u32,
    firewall_control: Option<FirewallControlToken>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), crate::error::AppError> {
    let path_buf = PathBuf::from(&path);
    admit_tail_start(
        &state,
        &path_buf,
        firewall_control.as_ref(),
        byte_offset,
        next_id,
        next_line,
        |launch| match launch {
            TailLaunch::Firewall => firewall::start_session(
                path_buf.clone(),
                firewall_control.clone().expect("admitted firewall control"),
                app,
            ),
            TailLaunch::Ordinary(start) => {
                tail::start_tail_session(path_buf.clone(), start, move |batch| {
                    let payload = TailPayload {
                        entries: batch.entries,
                        amendments: batch.amendments,
                        file_path: path.clone(),
                        parse_errors: batch.parse_errors,
                        observed_through_line: batch.observed_through_line,
                        reset: batch.reset,
                        firewall_control: None,
                        firewall_replacements: None,
                        firewall_coverage: None,
                        firewall_decoding: None,
                    };
                    if let Err(error) = app.emit("tail-new-entries", &payload) {
                        log::error!("Failed to emit tail entries: {error}");
                    }
                })
            }
        },
    )
}
#[tauri::command]
pub fn stop_tail(
    path: String,
    firewall_control: Option<FirewallControlToken>,
    state: State<'_, AppState>,
) -> Result<(), crate::error::AppError> {
    control_tail(
        &state,
        Path::new(&path),
        firewall_control.as_ref(),
        TailControl::Stop,
    )
}
#[tauri::command]
pub fn pause_tail(
    path: String,
    firewall_control: Option<FirewallControlToken>,
    state: State<'_, AppState>,
) -> Result<(), crate::error::AppError> {
    control_tail(
        &state,
        Path::new(&path),
        firewall_control.as_ref(),
        TailControl::Pause,
    )
}
#[tauri::command]
pub fn resume_tail(
    path: String,
    firewall_control: Option<FirewallControlToken>,
    state: State<'_, AppState>,
) -> Result<(), crate::error::AppError> {
    control_tail(
        &state,
        Path::new(&path),
        firewall_control.as_ref(),
        TailControl::Resume,
    )
}

#[cfg(test)]
mod firewall_control_tests {
    use super::*;
    use crate::state::app_state::OpenFile;
    use crate::watcher::firewall::*;
    fn state() -> (AppState, tempfile::TempDir, PathBuf, FirewallControlToken) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.log");
        std::fs::write(&path, "#Software: Microsoft Windows Firewall\n").unwrap();
        let a = crate::parser::parse_file_with_artifacts(path.to_str().unwrap()).unwrap();
        let owner = FirewallOwner::new(a.firewall.unwrap(), a.identity);
        let token = FirewallControlToken {
            source_session_id: owner.session_id.clone(),
            watch_epoch: 2,
        };
        let state = AppState::new(vec![]);
        state.open_files.lock().unwrap().insert(
            path.clone(),
            OpenFile {
                path: path.clone(),
                parser_selection: a.selection,
                initial_logical_record: None,
                byte_offset: a.result.byte_offset,
                file_identity: a.identity,
                firewall: Some(owner),
            },
        );
        (state, dir, path, token)
    }
    #[test]
    fn firewall_command_admission_precedes_worker_replacement() {
        let (state, _dir, path, current) = state();
        let mut stop = None;
        admit_tail_start(&state, &path, Some(&current), 999, 999, 999, |launch| {
            assert!(matches!(launch, TailLaunch::Firewall));
            let (session, flag) = tail::TailSession::controlled();
            stop = Some(flag);
            Ok(session)
        })
        .unwrap();
        let older = FirewallControlToken {
            watch_epoch: 1,
            ..current.clone()
        };
        for token in [None, Some(&older), Some(&current)] {
            admit_tail_start(&state, &path, token, 999, 999, 999, |_| {
                panic!("must not launch")
            })
            .unwrap();
        }
        assert!(!stop
            .as_ref()
            .unwrap()
            .load(std::sync::atomic::Ordering::Relaxed));
        control_tail(&state, &path, Some(&older), TailControl::Stop).unwrap();
        assert!(!stop
            .as_ref()
            .unwrap()
            .load(std::sync::atomic::Ordering::Relaxed));
        control_tail(&state, &path, Some(&current), TailControl::Stop).unwrap();
        assert!(stop.unwrap().load(std::sync::atomic::Ordering::Relaxed));
        admit_tail_start(&state, &path, Some(&current), 0, 0, 0, |_| {
            panic!("cancelled epoch")
        })
        .unwrap();
    }
    #[test]
    fn firewall_late_control_cannot_touch_reopened_ordinary_source() {
        let (state, _dir, path, old) = state();
        {
            let mut files = state.open_files.lock().unwrap();
            let opened = files.get_mut(&path).unwrap();
            opened.firewall = None;
            opened.parser_selection = crate::parser::ResolvedParser::plain_text();
        }
        let (session, stopped) = tail::TailSession::controlled();
        state
            .tail_sessions
            .lock()
            .unwrap()
            .insert(path.clone(), session);
        control_tail(&state, &path, Some(&old), TailControl::Stop).unwrap();
        assert!(!stopped.load(std::sync::atomic::Ordering::Relaxed));
        admit_tail_start(&state, &path, Some(&old), 0, 0, 0, |_| panic!("old source")).unwrap();
    }
}
