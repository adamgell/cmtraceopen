use super::{read_session_file_blocking, MAX_SESSION_BYTES};
use std::cell::RefCell;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    AfterPrecheck,
    AfterOpen,
    BeforeRead,
}

type Hook = Box<dyn FnMut(Stage, &Path)>;
thread_local! {
    static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
}

pub(super) fn at_stage(stage: Stage, path: &Path) {
    HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(stage, path);
        }
    });
}

struct HookGuard;
impl HookGuard {
    fn install(hook: impl FnMut(Stage, &Path) + 'static) -> Self {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        Self
    }
}
impl Drop for HookGuard {
    fn drop(&mut self) {
        HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

fn read(path: &Path) -> Result<String, crate::error::AppError> {
    read_session_file_blocking(path.to_str().expect("fixture path is UTF-8"))
}

#[test]
fn read_session_file_preserves_the_text_contract_and_case_insensitive_extension() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["saved.cmtrace", "saved.CmTrAcE"] {
        let path = dir.path().join(name);
        // Session shape belongs to validateSession, not this native reader.
        fs::write(&path, "ordinary UTF-8, not JSON: café").unwrap();
        assert_eq!(read(&path).unwrap(), "ordinary UTF-8, not JSON: café");
    }
}

#[test]
fn read_session_file_rejects_wrong_extension_missing_file_directory_and_invalid_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let other = dir.path().join("other.txt");
    fs::write(&other, "fixture text").unwrap();
    let directory = dir.path().join("folder.cmtrace");
    fs::create_dir(&directory).unwrap();
    let invalid = dir.path().join("invalid.cmtrace");
    fs::write(&invalid, [0xff]).unwrap();
    for path in [
        other,
        dir.path().join("missing.cmtrace"),
        directory,
        invalid,
    ] {
        assert!(read(&path).is_err(), "must reject {}", path.display());
    }
}

#[test]
fn read_session_file_enforces_the_exact_byte_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    let content = "a".repeat(MAX_SESSION_BYTES as usize);
    fs::write(&path, &content).unwrap();
    assert_eq!(read(&path).unwrap(), content);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_SESSION_BYTES + 1)
        .unwrap();
    assert!(read(&path).is_err());
}

#[test]
fn read_session_file_rejects_a_hard_linked_entry() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("other.txt");
    let path = dir.path().join("saved.cmtrace");
    fs::write(&target, "fixture target").unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(read(&path).is_err());
}

#[test]
fn read_session_file_checks_the_opened_link_count_after_precheck() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    fs::write(&path, "fixture target").unwrap();
    let _hook = HookGuard::install(|stage, path| {
        if stage == Stage::AfterPrecheck {
            fs::hard_link(path, path.with_extension("txt")).unwrap();
        }
    });
    assert!(read(&path).is_err());
}

#[test]
fn read_session_file_rechecks_size_on_the_opened_file_before_reading() {
    use std::rc::Rc;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    fs::write(&path, "small fixture").unwrap();
    let reached_read = Rc::new(RefCell::new(false));
    let observed = Rc::clone(&reached_read);
    let _hook = HookGuard::install(move |stage, path| {
        if stage == Stage::AfterOpen {
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(MAX_SESSION_BYTES + 1)
                .unwrap();
        } else if stage == Stage::BeforeRead {
            *observed.borrow_mut() = true;
        }
    });
    assert!(read(&path).is_err());
    assert!(
        !*reached_read.borrow(),
        "oversized opened object must not be read"
    );
}

#[test]
fn read_session_file_remains_bounded_when_the_opened_file_grows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    fs::write(&path, "small fixture").unwrap();
    let _hook = HookGuard::install(|stage, path| {
        if stage == Stage::BeforeRead {
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(MAX_SESSION_BYTES + 1)
                .unwrap();
        }
    });
    assert!(read(&path).is_err());
}

#[test]
fn read_session_file_keeps_the_opened_object_after_path_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    fs::write(&path, "original fixture").unwrap();
    let _hook = HookGuard::install(|stage, path| {
        if stage == Stage::BeforeRead {
            fs::rename(path, path.with_extension("retired")).unwrap();
            fs::write(path, "replacement fixture").unwrap();
        }
    });
    assert_eq!(read(&path).unwrap(), "original fixture");
}

#[test]
fn read_session_file_rejects_a_directory_substituted_after_precheck() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    fs::write(&path, "fixture").unwrap();
    let _hook = HookGuard::install(|stage, path| {
        if stage == Stage::AfterPrecheck {
            fs::remove_file(path).unwrap();
            fs::create_dir(path).unwrap();
        }
    });
    assert!(read(&path).is_err());
}

#[cfg(unix)]
#[test]
fn read_session_file_rejects_final_symlinks_regardless_of_target_shape() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("saved.cmtrace");
    let other = dir.path().join("other.txt");
    let session = dir.path().join("real.cmtrace");
    fs::write(&other, "fixture text").unwrap();
    fs::write(&session, r#"{"version":1,"workspace":"log","tabs":[]}"#).unwrap();
    for target in [
        other,
        session,
        dir.path().join("absent"),
        dir.path().to_owned(),
    ] {
        symlink(target, &link).unwrap();
        assert!(read(&link).is_err());
        fs::remove_file(&link).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn read_session_file_rejects_a_symlink_substituted_after_precheck() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    fs::write(&path, "original fixture").unwrap();
    let _hook = HookGuard::install(|stage, path| {
        if stage == Stage::AfterPrecheck {
            let target = path.with_extension("txt");
            fs::write(&target, "replacement fixture").unwrap();
            fs::remove_file(path).unwrap();
            std::os::unix::fs::symlink(target, path).unwrap();
        }
    });
    assert!(read(&path).is_err());
}

#[cfg(unix)]
#[test]
fn read_session_file_preserves_parent_directory_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    let alias = dir.path().join("alias");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("saved.cmtrace"), "fixture").unwrap();
    std::os::unix::fs::symlink(real, &alias).unwrap();
    assert_eq!(read(&alias.join("saved.cmtrace")).unwrap(), "fixture");
}

#[cfg(unix)]
fn fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is NUL-terminated and the fixture is confined to its tempdir.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
}

#[cfg(unix)]
#[test]
#[ignore = "only run by the parent regression with a process deadline"]
fn read_session_file_fifo_child() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.cmtrace");
    let case = std::env::var("CMTRACE_SESSION_FIFO_CASE").unwrap();
    let _hook = if case == "swap" {
        fs::write(&path, "fixture").unwrap();
        Some(HookGuard::install(|stage, path| {
            if stage == Stage::AfterPrecheck {
                fs::remove_file(path).unwrap();
                fifo(path);
            }
        }))
    } else {
        fifo(&path);
        None
    };
    assert!(read(&path).is_err());
}

#[cfg(unix)]
#[test]
fn read_session_file_refuses_initial_and_substituted_fifos_without_waiting() {
    use std::time::{Duration, Instant};
    for case in ["initial", "swap"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "commands::file_ops::session_file_tests::read_session_file_fifo_child",
                "--nocapture",
            ])
            .env("CMTRACE_SESSION_FIFO_CASE", case)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "FIFO case {case} failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("FIFO case {case} waited for a writer");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(windows)]
#[test]
fn read_session_file_rejects_alternate_stream_and_device_paths() {
    for path in [
        r"C:\fixtures\other.txt:saved.cmtrace",
        r"saved:stream.cmtrace",
        r"\\.\pipe\saved.cmtrace",
        r"\\?\GLOBALROOT\Device\saved.cmtrace",
        r"\\localhost\pipe\saved.cmtrace",
        r"\\?\C:\fixtures\other.txt:stream.cmtrace",
        r"C:\fixtures\COM1.cmtrace",
        r"C:\fixtures\LPT¹.cmtrace",
        "NUL.cmtrace",
    ] {
        assert!(
            matches!(
                read(Path::new(path)),
                Err(crate::error::AppError::InvalidInput(_))
            ),
            "must reject {path} before filesystem access"
        );
    }
}

#[cfg(windows)]
#[test]
fn read_session_file_allows_ordinary_windows_path_spellings() {
    for path in [
        r"saved.cmtrace",
        r"..\a folder\saved.cmtrace",
        r"C:\fixtures\saved.cmtrace",
        r"\\server\share\saved.cmtrace",
        r"\\?\C:\fixtures\saved.cmtrace",
        r"\\?\UNC\server\share\saved.cmtrace",
        r"\\CON\AUX\saved.cmtrace",
    ] {
        super::validate_session_windows_path(Path::new(path))
            .unwrap_or_else(|error| panic!("ordinary file spelling {path}: {error}"));
    }
}

#[cfg(windows)]
#[test]
#[ignore = "requires existing symlink privilege; run explicitly on an authorized Windows host"]
fn read_session_file_rejects_windows_reparse_entries_and_preserves_parent_aliases() {
    use std::os::windows::fs::{symlink_dir, symlink_file};
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    let alias = dir.path().join("alias");
    fs::create_dir(&real).unwrap();
    let target = real.join("saved.cmtrace");
    fs::write(&target, "fixture").unwrap();
    symlink_dir(&real, &alias).expect("existing symlink privilege is required");
    assert_eq!(read(&alias.join("saved.cmtrace")).unwrap(), "fixture");
    let link = dir.path().join("linked.cmtrace");
    symlink_file(&target, &link).unwrap();
    assert!(read(&link).is_err());
    let _hook = HookGuard::install(|stage, path| {
        if stage == Stage::AfterPrecheck {
            let retired = path.with_extension("txt");
            fs::rename(path, &retired).unwrap();
            symlink_file(retired, path).unwrap();
        }
    });
    assert!(read(&target).is_err());
}
