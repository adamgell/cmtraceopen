use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifiedSource {
    LogFile(PathBuf),
    ImeLogsFolder(PathBuf),
}

/// Walk the given root (one level deep) and classify what we find.
/// Produces log files for every recognized log path plus at most one
/// IME-events source per IME folder detected.
pub fn classify_folder(root: &Path) -> Vec<ClassifiedSource> {
    let mut out: Vec<ClassifiedSource> = Vec::new();
    if !root.is_dir() {
        return out;
    }

    let ime_hint_files = ["AgentExecutor.log", "IntuneManagementExtension.log"];
    let mut contains_ime_logs = false;

    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if ime_hint_files.contains(&name) {
                    contains_ime_logs = true;
                }
                if is_log_file(name) {
                    out.push(ClassifiedSource::LogFile(path));
                }
            }
        }
    }
    if contains_ime_logs {
        out.push(ClassifiedSource::ImeLogsFolder(root.to_path_buf()));
    }
    out
}

fn is_log_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".log")
        || lower.ends_with(".cmtlog")
        || lower.ends_with(".txt")
        || lower == "setupact.log"
        || lower == "setupapi.app.log"
        || lower == "setupapi.dev.log"
}

#[cfg(test)]
mod tests_classify {
    use super::*;

    #[test]
    fn classifies_plain_log_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.log"), b"hello\n").unwrap();
        std::fs::write(dir.path().join("bar.txt"), b"bye\n").unwrap();
        std::fs::write(dir.path().join("ignore.bin"), b"x").unwrap();
        let mut out = classify_folder(dir.path());
        out.sort_by_key(|c| format!("{:?}", c));
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], ClassifiedSource::LogFile(_)));
        assert!(matches!(out[1], ClassifiedSource::LogFile(_)));
    }

    #[test]
    fn detects_ime_folder_when_agentexecutor_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("AgentExecutor.log"), b"hello\n").unwrap();
        std::fs::write(dir.path().join("IntuneManagementExtension.log"), b"hi\n").unwrap();
        let out = classify_folder(dir.path());
        assert!(out.iter().any(|c| matches!(c, ClassifiedSource::ImeLogsFolder(_))));
        assert_eq!(
            out.iter()
                .filter(|c| matches!(c, ClassifiedSource::LogFile(_)))
                .count(),
            2
        );
    }
}
