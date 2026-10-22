//! AppRun changes cwd to APPDIR/usr; only its proven launch context uses OWD.
#![cfg(unix)]
#[path = "../src/platform_impl/linux/launch_directory.rs"]
mod launch_directory;

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

fn selected(exe: &str, image: Option<&str>, appdir: Option<&str>, owd: Option<&str>) -> PathBuf {
    launch_directory::select(
        Path::new("/tmp/secondary-mount/usr"),
        Some(Path::new(exe)),
        image.map(OsStr::new),
        appdir.map(OsStr::new),
        owd.map(OsStr::new),
    )
}

#[test]
fn packaged_secondary_preserves_callers_spaced_relative_file_from_another_directory() {
    let cwd = selected(
        "/tmp/secondary-mount/usr/bin/cmtrace-open",
        Some("/downloads/CMTrace Open.AppImage"),
        Some("/tmp/secondary-mount"),
        Some("/fixtures/second launch"),
    );
    assert_eq!(
        cwd.join("handoff fixture.log"),
        Path::new("/fixtures/second launch/handoff fixture.log")
    );
}

#[test]
fn ordinary_linux_ignores_ambient_original_directory() {
    assert_eq!(
        selected("/usr/bin/cmtrace-open", None, None, Some("/unrelated")),
        Path::new("/tmp/secondary-mount/usr")
    );
}

#[test]
fn unrelated_executable_does_not_trust_appimage_environment() {
    for exe in [
        "/usr/bin/cmtrace-open",
        "/tmp/secondary-mount-other/usr/bin/cmtrace-open",
    ] {
        assert_eq!(
            selected(
                exe,
                Some("/downloads/app.AppImage"),
                Some("/tmp/secondary-mount"),
                Some("/unrelated")
            ),
            Path::new("/tmp/secondary-mount/usr")
        );
    }
}

#[test]
fn missing_or_relative_packaging_values_preserve_process_directory() {
    for (image, appdir, owd) in [
        (None, Some("/tmp/secondary-mount"), Some("/fixtures")),
        (
            Some("relative.AppImage"),
            Some("/tmp/secondary-mount"),
            Some("/fixtures"),
        ),
        (Some("/downloads/app.AppImage"), None, Some("/fixtures")),
        (
            Some("/downloads/app.AppImage"),
            Some("relative-mount"),
            Some("/fixtures"),
        ),
        (
            Some("/downloads/app.AppImage"),
            Some("/tmp/secondary-mount"),
            None,
        ),
        (
            Some("/downloads/app.AppImage"),
            Some("/tmp/secondary-mount"),
            Some(""),
        ),
        (
            Some("/downloads/app.AppImage"),
            Some("/tmp/secondary-mount"),
            Some("relative"),
        ),
    ] {
        assert_eq!(
            selected(
                "/tmp/secondary-mount/usr/bin/cmtrace-open",
                image,
                appdir,
                owd
            ),
            Path::new("/tmp/secondary-mount/usr")
        );
    }
}

#[test]
fn executable_presence_without_apprun_cwd_does_not_change_launch_directory() {
    let ordinary = Path::new("/somewhere/ordinary");
    assert_eq!(
        launch_directory::select(
            ordinary,
            Some(Path::new("/tmp/secondary-mount/usr/bin/cmtrace-open")),
            Some(OsStr::new("/downloads/app.AppImage")),
            Some(OsStr::new("/tmp/secondary-mount")),
            Some(OsStr::new("/unrelated"))
        ),
        ordinary
    );
}

#[test]
fn absent_or_relative_executable_preserves_process_directory() {
    let cwd = Path::new("/tmp/secondary-mount/usr");
    for exe in [None, Some(Path::new("usr/bin/cmtrace-open"))] {
        assert_eq!(
            launch_directory::select(
                cwd,
                exe,
                Some(OsStr::new("/downloads/app.AppImage")),
                Some(OsStr::new("/tmp/secondary-mount")),
                Some(OsStr::new("/fixtures"))
            ),
            cwd
        );
    }
}

#[test]
fn failed_current_directory_lookup_remains_empty() {
    let cwd = Path::new("");
    assert_eq!(
        launch_directory::select(
            cwd,
            Some(Path::new("/tmp/secondary-mount/usr/bin/cmtrace-open")),
            Some(OsStr::new("/downloads/app.AppImage")),
            Some(OsStr::new("/tmp/secondary-mount")),
            Some(OsStr::new("/fixtures"))
        ),
        cwd
    );
}
