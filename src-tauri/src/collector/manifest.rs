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
            result.files.iter().map(|file| {
                let relative_path = canonical_root_relative_path(bundle_root, &file.relative_path)?;
                Ok(json!({
                    "artifactId": result.id,
                    "category": result.category,
                    "family": result.family,
                    "relativePath": relative_path,
                    "originPath": file.origin_path,
                    "collectedUtc": collected_utc,
                    "status": artifact_status_name(&result.status),
                    "parseHints": result.parse_hints,
                    "bytesCopied": file.bytes_copied,
                    "notes": result.notes,
                }))
            })
        })
        .collect::<Result<Vec<_>, crate::error::AppError>>()?;
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

fn artifact_status_name(status: &ArtifactStatus) -> &'static str {
    match status {
        ArtifactStatus::Collected => "collected",
        ArtifactStatus::Missing => "missing",
        ArtifactStatus::Failed => "failed",
    }
}

fn canonical_root_relative_path(
    bundle_root: &Path,
    relative_path: &str,
) -> Result<String, crate::error::AppError> {
    let relative_path = Path::new(relative_path);
    if relative_path.is_absolute() {
        return Err(manifest_artifact_path_error(
            relative_path,
            "path is absolute",
        ));
    }

    let canonical_root = bundle_root.canonicalize().map_err(|error| {
        manifest_artifact_path_error(
            relative_path,
            &format!("bundle root could not be canonicalized: {error}"),
        )
    })?;
    let canonical_file = bundle_root
        .join(relative_path)
        .canonicalize()
        .map_err(|error| {
            manifest_artifact_path_error(
                relative_path,
                &format!("file could not be canonicalized: {error}"),
            )
        })?;
    if !canonical_file.is_file() {
        return Err(manifest_artifact_path_error(
            relative_path,
            "path is not a file",
        ));
    }
    if !canonical_file.starts_with(&canonical_root) {
        return Err(manifest_artifact_path_error(
            relative_path,
            "canonical path escapes the bundle root",
        ));
    }

    let root_relative = canonical_file
        .strip_prefix(&canonical_root)
        .map_err(|error| {
            manifest_artifact_path_error(
                relative_path,
                &format!("canonical path is not root-relative: {error}"),
            )
        })?;
    Ok(root_relative.to_string_lossy().replace('\\', "/"))
}

fn manifest_artifact_path_error(relative_path: &Path, reason: &str) -> crate::error::AppError {
    crate::error::AppError::Internal(format!(
        "cannot include collected artifact '{}' in manifest: {reason}",
        relative_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::write_manifest;
    use crate::collector::types::{
        ArtifactCounts, ArtifactResult, ArtifactStatus, CollectedArtifactFile, CollectionProfile,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn write_manifest_rejects_a_collected_file_that_cannot_be_enumerated() {
        let bundle_root = temp_bundle_root("manifest-missing-collected-file");
        let result = ArtifactResult {
            id: "missing-collected-file".to_string(),
            category: "logs".to_string(),
            family: "intune-ime".to_string(),
            parse_hints: vec!["cmtrace".to_string()],
            notes: Some("must not disappear from artifacts".to_string()),
            status: ArtifactStatus::Collected,
            files: vec![CollectedArtifactFile {
                relative_path: "evidence/logs/missing.log".to_string(),
                origin_path: Some("C:\\Windows\\Temp\\missing.log".to_string()),
                bytes_copied: 42,
            }],
            error: None,
        };

        let error = write_manifest(
            &bundle_root,
            "CMTRACE-TEST",
            &CollectionProfile::embedded(),
            &[result],
            &ArtifactCounts {
                collected: 1,
                missing: 0,
                failed: 0,
                total: 1,
            },
            5,
        )
        .expect_err("an unenumerated collected file must fail manifest creation");

        assert!(
            error.to_string().contains("missing.log"),
            "error must identify the omitted collected file: {error}"
        );
        assert!(!bundle_root.join("manifest.json").exists());
        fs::remove_dir_all(bundle_root).expect("remove temp bundle root");
    }

    #[test]
    fn write_manifest_preserves_failed_status_for_a_copied_file() {
        let bundle_root = temp_bundle_root("manifest-failed-copied-file");
        let relative_path = "evidence/command-output/failed.json";
        let copied_path = bundle_root.join(relative_path);
        fs::create_dir_all(copied_path.parent().expect("copied file parent"))
            .expect("create copied file parent");
        fs::write(&copied_path, "{\"partial\":true}").expect("write copied file");
        let result = ArtifactResult {
            id: "failed-command".to_string(),
            category: "command".to_string(),
            family: "system".to_string(),
            parse_hints: vec!["json".to_string()],
            notes: Some("output exists despite failed command".to_string()),
            status: ArtifactStatus::Failed,
            files: vec![CollectedArtifactFile {
                relative_path: relative_path.to_string(),
                origin_path: None,
                bytes_copied: 16,
            }],
            error: Some("command exited with code 1".to_string()),
        };

        write_manifest(
            &bundle_root,
            "CMTRACE-TEST",
            &CollectionProfile::embedded(),
            &[result],
            &ArtifactCounts {
                collected: 0,
                missing: 0,
                failed: 1,
                total: 1,
            },
            5,
        )
        .expect("write manifest with failed copied file");

        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(bundle_root.join("manifest.json")).expect("read manifest"),
        )
        .expect("parse manifest");
        assert_eq!(manifest["artifacts"][0]["relativePath"], relative_path);
        assert_eq!(manifest["artifacts"][0]["status"], "failed");
        assert_eq!(manifest["collection"]["results"]["gaps"][0]["status"], "Failed");
        fs::remove_dir_all(bundle_root).expect("remove temp bundle root");
    }

    fn temp_bundle_root(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{nonce}"));
        fs::create_dir_all(&path).expect("create temp bundle root");
        path
    }
}
