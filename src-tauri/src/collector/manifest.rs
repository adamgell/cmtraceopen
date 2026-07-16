use std::fs;
use std::path::Path;

use chrono::Utc;
use serde_json::json;

use crate::collector::types::{ArtifactCounts, ArtifactResult, ArtifactStatus, CollectionProfile};

/// Write `manifest.json` into the bundle root, compatible with the existing
/// `inspect_evidence_bundle` logic in `file_ops.rs`.
pub fn write_manifest(
    bundle_root: &Path,
    bundle_id: &str,
    profile: &CollectionProfile,
    results: &[ArtifactResult],
    counts: &ArtifactCounts,
    duration_ms: u64,
) -> Result<(), crate::error::AppError> {
    let now = Utc::now();
    let hostname = hostname();

    let gaps: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| !matches!(r.status, ArtifactStatus::Collected))
        .map(|r| {
            json!({
                "artifactId": r.id,
                "category": r.category,
                "status": format!("{:?}", r.status),
                "reason": r.error.as_deref().unwrap_or("unknown"),
            })
        })
        .collect();

    let collected_utc = now.to_rfc3339();
    let mut artifacts: Vec<serde_json::Value> = results
        .iter()
        .flat_map(|result| {
            result.files.iter().filter_map(|file| {
                let relative_path = canonical_root_relative_path(bundle_root, &file.relative_path)?;
                Some(json!({
                    "artifactId": result.id,
                    "category": result.category,
                    "family": result.family,
                    "relativePath": relative_path,
                    "originPath": file.origin_path,
                    "collectedUtc": collected_utc,
                    "status": "collected",
                    "parseHints": result.parse_hints,
                    "bytesCopied": file.bytes_copied,
                    "notes": result.notes,
                }))
            })
        })
        .collect();
    artifacts.sort_by(|left, right| {
        let left_path = left
            .get("relativePath")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let right_path = right
            .get("relativePath")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let left_id = left
            .get("artifactId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let right_id = right
            .get("artifactId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        left_path
            .cmp(right_path)
            .then_with(|| left_id.cmp(right_id))
    });

    let manifest = json!({
        "bundle": {
            "bundleId": bundle_id,
            "bundleLabel": "cmtrace-diagnostics",
            "createdUtc": now.to_rfc3339(),
            "summary": format!(
                "Diagnostics collected by CMTrace Open in {:.1}s",
                duration_ms as f64 / 1000.0
            ),
            "device": {
                "deviceName": hostname,
                "platform": "Windows",
            },
        },
        "collection": {
            "collectorProfile": profile.profile_name,
            "collectorVersion": profile.profile_version,
            "collectedUtc": now.to_rfc3339(),
            "durationMs": duration_ms,
            "results": {
                "artifactCounts": {
                    "collected": counts.collected,
                    "missing": counts.missing,
                    "failed": counts.failed,
                    "skipped": 0,
                },
                "gaps": gaps,
            },
        },
        "artifacts": artifacts,
        "intakeHints": {
            "notesPath": "notes.md",
            "evidenceRoot": "evidence",
            "primaryEntryPoints": [
                "evidence/logs",
                "evidence/registry",
                "evidence/event-logs",
                "evidence/exports",
                "evidence/command-output",
            ],
        },
    });

    let manifest_path = bundle_root.join("manifest.json");
    let json_str = serde_json::to_string_pretty(&manifest)
        .map_err(|e| crate::error::AppError::Internal(format!("failed to serialize manifest: {e}")))?;
    fs::write(&manifest_path, json_str)
        .map_err(crate::error::AppError::Io)?;

    Ok(())
}

/// Write `notes.md` into the bundle root with collection summary.
pub fn write_notes(
    bundle_root: &Path,
    profile: &CollectionProfile,
    counts: &ArtifactCounts,
    duration_ms: u64,
) -> Result<(), crate::error::AppError> {
    let now = Utc::now();
    let hostname = hostname();

    let notes = format!(
"# Evidence Collection Notes

- **Collected by:** CMTrace Open (Rust collector)
- **Profile:** {} v{}
- **Device:** {}
- **Timestamp:** {}
- **Duration:** {:.1}s

## Summary

| Metric | Count |
|--------|-------|
| Collected | {} |
| Missing | {} |
| Failed | {} |
| **Total** | **{}** |

## Structure

```
evidence/
├── logs/           Log files (IME, Panther, CBS, MSI, etc.)
├── registry/       Registry exports (.reg)
├── event-logs/     Event log copies (.evtx)
├── exports/        Configuration files and diagnostic outputs
└── command-output/ Command stdout captures
```
",
        profile.profile_name,
        profile.profile_version,
        hostname,
        now.format("%Y-%m-%d %H:%M:%S UTC"),
        duration_ms as f64 / 1000.0,
        counts.collected,
        counts.missing,
        counts.failed,
        counts.total,
    );

    let notes_path = bundle_root.join("notes.md");
    fs::write(&notes_path, notes)
        .map_err(crate::error::AppError::Io)?;

    Ok(())
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn canonical_root_relative_path(bundle_root: &Path, relative_path: &str) -> Option<String> {
    let relative_path = Path::new(relative_path);
    if relative_path.is_absolute() {
        return None;
    }

    let canonical_root = bundle_root.canonicalize().ok()?;
    let canonical_file = bundle_root.join(relative_path).canonicalize().ok()?;
    if !canonical_file.is_file() || !canonical_file.starts_with(&canonical_root) {
        return None;
    }

    Some(
        canonical_file
            .strip_prefix(&canonical_root)
            .ok()?
            .to_string_lossy()
            .replace('\\', "/"),
    )
}
