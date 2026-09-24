//! Identity of an open file, so a replacement can be told from an append.
//!
//! A reader that tracks only a byte offset cannot see a rotation in which the
//! replacement file is already larger than the offset held for the previous one.
//! The size test (`file_size < byte_offset`) is false in that case, so the reader
//! seeks to the old offset inside a *different* file: the head of the new
//! generation is never read and the first entry can be a partial line. Comparing
//! the file's identity detects the replacement regardless of size.
//!
//! Identity is `None` when the platform cannot supply it. Callers must treat that
//! as "unknown" rather than as a change, so a platform without identity support
//! falls back to whatever other signal it has instead of resetting every read.

use std::fs::{File, Metadata};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    volume: u64,
    index: u64,
}

#[cfg(unix)]
pub fn file_identity(_file: &File, metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity {
        volume: metadata.dev(),
        index: metadata.ino(),
    })
}

#[cfg(target_os = "windows")]
pub fn file_identity(file: &File, _metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is borrowed from the live `File`, and the output
    // points to a valid initialized structure for the duration of the call.
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information).ok()?;
    }
    Some(FileIdentity {
        volume: information.dwVolumeSerialNumber as u64,
        index: ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
    })
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn file_identity(_file: &File, _metadata: &Metadata) -> Option<FileIdentity> {
    None
}

/// True only when both identities are known and differ. An unknown identity on
/// either side is not evidence of a replacement.
pub fn identities_differ(previous: Option<FileIdentity>, current: Option<FileIdentity>) -> bool {
    matches!((previous, current), (Some(left), Some(right)) if left != right)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: FileIdentity = FileIdentity {
        volume: 1,
        index: 2,
    };
    const SECOND: FileIdentity = FileIdentity {
        volume: 1,
        index: 3,
    };

    #[test]
    fn a_different_identity_at_the_same_path_is_a_replacement() {
        assert!(identities_differ(Some(FIRST), Some(SECOND)));
        assert!(!identities_differ(Some(FIRST), Some(FIRST)));
    }

    #[test]
    fn an_unknown_identity_is_not_a_replacement() {
        // A platform that cannot supply identity must fall back to its other
        // signal. Treating unknown as a change would reset on every read.
        assert!(!identities_differ(None, None));
        assert!(!identities_differ(None, Some(FIRST)));
        assert!(!identities_differ(Some(FIRST), None));
    }

    #[test]
    fn a_rename_over_the_same_path_reports_a_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        std::fs::write(&path, b"first\n").unwrap();
        let before = {
            let file = std::fs::File::open(&path).unwrap();
            file_identity(&file, &file.metadata().unwrap())
        };

        let staging = dir.path().join("staging.log");
        std::fs::write(&staging, b"second generation\n").unwrap();
        std::fs::rename(&staging, &path).unwrap();

        let after = {
            let file = std::fs::File::open(&path).unwrap();
            file_identity(&file, &file.metadata().unwrap())
        };

        assert_ne!(before, after, "a rotated-in file is a different file");
        assert!(identities_differ(before, after));
    }
}
