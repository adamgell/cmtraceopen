//! Windows process snapshots backed by a fixed, read-only WMI query.

use std::time::Duration;

use super::{ProcessProvider, ProcessReadError, ProcessSnapshotBatch, RawProcessSnapshot};
use crate::esp::system::{query_wmi, SystemReadError, WmiRequest};

pub struct LiveProcessProvider;

impl ProcessProvider for LiveProcessProvider {
    fn snapshot(
        &self,
        allowed_image_names: &[String],
        timeout: Duration,
        max_records: usize,
    ) -> ProcessSnapshotBatch {
        let batch = query_wmi(
            WmiRequest::Processes(allowed_image_names.to_vec()),
            timeout,
            max_records,
        );
        let snapshots = batch
            .rows
            .into_iter()
            .filter_map(|row| {
                let pid = row.get("ProcessId")?.parse().ok()?;
                let image_name = row.get("Name")?.trim();
                let start_time_utc = row.get("CreationDate")?.trim();
                if image_name.is_empty() || start_time_utc.is_empty() {
                    return None;
                }
                let parent_pid = row
                    .get("ParentProcessId")
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|pid| *pid != 0);
                let command_line = row
                    .get("CommandLine")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
                Some(RawProcessSnapshot {
                    pid,
                    parent_pid,
                    image_name: image_name.to_string(),
                    start_time_utc: start_time_utc.to_string(),
                    command_line,
                })
            })
            .take(max_records)
            .collect();
        ProcessSnapshotBatch {
            snapshots,
            completion: batch.completion.map_err(map_system_error),
        }
    }
}

fn map_system_error(error: SystemReadError) -> ProcessReadError {
    match error {
        SystemReadError::Missing => ProcessReadError::Missing,
        SystemReadError::PermissionDenied => ProcessReadError::PermissionDenied,
        SystemReadError::TimedOut => ProcessReadError::TimedOut,
        SystemReadError::Failed(detail) => ProcessReadError::Failed(detail),
        SystemReadError::Unsupported => ProcessReadError::Unsupported,
    }
}
