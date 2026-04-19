use std::collections::HashSet;

use tauri::{AppHandle, Manager, State};

use crate::state::app_state::AppState;
use crate::timeline::builder::{build_timeline, SourceRequest, DEFAULT_ENTRY_LIMIT};
use crate::timeline::incidents::redetect_from_signals;
use crate::timeline::models::*;
use crate::timeline::query::{
    query_incident_details as q_incident, query_lane_buckets as q_lane,
    query_timeline_entries as q_entries, IncidentDetail, QueryContext, SourceRuntime,
};

/// Per-timeline runtime map kept outside `AppState.timelines` so the
/// `HashMap<String, Timeline>` stays free of non-serializable parser
/// runtime state that would break any future persistence work.
pub struct TimelineRuntimeMap(
    pub  std::sync::Mutex<
        std::collections::HashMap<String, std::collections::HashMap<u16, SourceRuntime>>,
    >,
);

impl TimelineRuntimeMap {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(std::collections::HashMap::new()))
    }
}

impl Default for TimelineRuntimeMap {
    fn default() -> Self {
        Self::new()
    }
}

#[tauri::command]
pub async fn build_timeline_cmd(
    app: AppHandle,
    sources: Vec<SourceRequest>,
) -> Result<TimelineBundle, TimelineError> {
    let (timeline, runtimes) = tokio::task::spawn_blocking(move || {
        build_timeline(&sources, DEFAULT_ENTRY_LIMIT, Vec::new())
    })
    .await
    .map_err(|e| TimelineError::Internal {
        message: e.to_string(),
    })??;

    let state: State<AppState> = app.state();
    let rt_state: State<TimelineRuntimeMap> = app.state();
    let id = timeline.bundle.id.clone();
    let bundle = timeline.bundle.clone();
    state.timelines.lock().unwrap().insert(id.clone(), timeline);
    rt_state.0.lock().unwrap().insert(id.clone(), runtimes);
    Ok(bundle)
}

#[tauri::command]
pub async fn query_timeline_entries_cmd(
    app: AppHandle,
    id: String,
    range_ms: Option<(i64, i64)>,
    source_filter: Option<Vec<u16>>,
    offset: u64,
    limit: u32,
) -> Result<Vec<TimelineEntry>, TimelineError> {
    let state: State<AppState> = app.state();
    let rt_state: State<TimelineRuntimeMap> = app.state();
    let tls = state.timelines.lock().unwrap();
    let rts = rt_state.0.lock().unwrap();

    let timeline = tls
        .get(&id)
        .ok_or(TimelineError::NotFound { id: id.clone() })?;
    let runtimes = rts
        .get(&id)
        .ok_or(TimelineError::NotFound { id: id.clone() })?;
    let filter_set: Option<HashSet<u16>> = source_filter.map(|v| v.into_iter().collect());
    let ctx = QueryContext {
        timeline,
        runtimes,
    };
    Ok(q_entries(&ctx, range_ms, filter_set.as_ref(), offset, limit))
}

#[tauri::command]
pub async fn query_lane_buckets_cmd(
    app: AppHandle,
    id: String,
    bucket_count: u32,
    range_ms: Option<(i64, i64)>,
) -> Result<Vec<LaneBucket>, TimelineError> {
    let state: State<AppState> = app.state();
    let tls = state.timelines.lock().unwrap();
    let timeline = tls.get(&id).ok_or(TimelineError::NotFound { id })?;
    Ok(q_lane(timeline, bucket_count, range_ms))
}

#[tauri::command]
pub async fn query_incident_details_cmd(
    app: AppHandle,
    id: String,
    incident_id: u32,
) -> Result<IncidentDetail, TimelineError> {
    let state: State<AppState> = app.state();
    let rt_state: State<TimelineRuntimeMap> = app.state();
    let tls = state.timelines.lock().unwrap();
    let rts = rt_state.0.lock().unwrap();
    let timeline = tls
        .get(&id)
        .ok_or(TimelineError::NotFound { id: id.clone() })?;
    let runtimes = rts
        .get(&id)
        .ok_or(TimelineError::NotFound { id: id.clone() })?;
    let ctx = QueryContext {
        timeline,
        runtimes,
    };
    q_incident(&ctx, incident_id).ok_or(TimelineError::NotFound {
        id: format!("incident:{}", incident_id),
    })
}

#[tauri::command]
pub async fn update_timeline_tunables_cmd(
    app: AppHandle,
    id: String,
    tunables: TimelineTunables,
) -> Result<Vec<Incident>, TimelineError> {
    let state: State<AppState> = app.state();
    let rt_state: State<TimelineRuntimeMap> = app.state();
    let mut tls = state.timelines.lock().unwrap();
    let rts = rt_state.0.lock().unwrap();
    let timeline = tls
        .get_mut(&id)
        .ok_or(TimelineError::NotFound { id: id.clone() })?;
    let runtimes = rts
        .get(&id)
        .ok_or(TimelineError::NotFound { id: id.clone() })?;
    let denied: HashSet<String> = timeline.bundle.denied_guids.iter().cloned().collect();

    let indexes = timeline.indexes.clone();
    let materialize = |src: u16, eref: u32| -> Option<String> {
        let ei = indexes.get(&src).and_then(|v| v.get(eref as usize))?;
        let rt = runtimes.get(&src)?;
        crate::timeline::query::materialize_msg(&rt.path, &rt.parser, ei)
    };
    let incidents = redetect_from_signals(
        &timeline.raw_signals,
        &timeline.ime_events,
        &tunables,
        &denied,
        &materialize,
    );
    timeline.bundle.tunables = tunables;
    timeline.bundle.incidents = incidents.clone();
    Ok(incidents)
}

#[tauri::command]
pub async fn close_timeline_cmd(
    app: AppHandle,
    id: String,
) -> Result<(), TimelineError> {
    let state: State<AppState> = app.state();
    let rt_state: State<TimelineRuntimeMap> = app.state();
    state.timelines.lock().unwrap().remove(&id);
    rt_state.0.lock().unwrap().remove(&id);
    Ok(())
}
