#[cfg(not(windows))]
compile_error!("provider_capture is only supported on Windows");

use std::{
    iter::once,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

fn publish_no_replace(source: &Path, destination: &Path) -> Result<(), String> {
    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(once(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| {
        format!(
            "cannot publish provider database {} as {} without replacing an existing path: {error}",
            source.display(),
            destination.display()
        )
    })
}

fn capture_verify_and_publish(capture_path: PathBuf, destination: PathBuf) -> Result<i64, String> {
    app_lib::event_log::capture::capture_providers_to_db(&capture_path)
        .map_err(|error| format!("PROVIDER_CAPTURE_FAILED {error:?}"))?;

    let connection = rusqlite::Connection::open_with_flags(
        &capture_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("PROVIDER_CAPTURE_VERIFY_FAILED {error:?}"))?;
    let provider_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM ProviderDetails", [], |row| row.get(0))
        .map_err(|error| format!("PROVIDER_CAPTURE_VERIFY_FAILED {error:?}"))?;
    if provider_count <= 100 {
        return Err("PROVIDER_CAPTURE_VERIFY_FAILED insufficient provider rows".to_owned());
    }
    drop(connection);

    publish_no_replace(&capture_path, &destination)
        .map_err(|error| format!("PROVIDER_CAPTURE_FAILED {error}"))?;
    Ok(provider_count)
}

#[cfg(test)]
mod tests {
    use super::publish_no_replace;

    #[test]
    fn publish_no_replace_preserves_existing_destination() {
        let directory = tempfile::tempdir().expect("create publication-test directory");
        let source = directory.path().join("captured.db");
        let destination = directory.path().join("existing.db");
        std::fs::write(&source, b"verified capture").expect("write publication-test source");
        std::fs::write(&destination, b"existing destination")
            .expect("write publication-test destination");

        publish_no_replace(&source, &destination)
            .expect_err("publication must refuse an existing destination");
        assert_eq!(
            std::fs::read(&source).expect("read refused source"),
            b"verified capture"
        );
        assert_eq!(
            std::fs::read(&destination).expect("read preserved destination"),
            b"existing destination"
        );
    }
}

fn run() -> Result<(), (i32, String)> {
    let destination = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| (2, "usage: provider_capture <destination.db>".to_owned()))?;

    let destination_parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staging_directory = tempfile::Builder::new()
        .prefix(".cmtraceopen-provider-capture-")
        .tempdir_in(destination_parent)
        .map_err(|error| {
            (
                2,
                format!("PROVIDER_CAPTURE_FAILED cannot create staging directory: {error}"),
            )
        })?;
    let capture_path = staging_directory.path().join("provider.db");

    let capture_result = capture_verify_and_publish(capture_path, destination);
    if let Err(error) = staging_directory.close() {
        eprintln!("PROVIDER_CAPTURE_STAGING_RESIDUE cannot remove staging directory: {error}");
    }

    match capture_result {
        Ok(provider_count) => {
            println!("PROVIDER_CAPTURE_OK providerCount={provider_count}");
            Ok(())
        }
        Err(message) => Err((1, message)),
    }
}

fn main() {
    if let Err((exit_code, message)) = run() {
        eprintln!("{message}");
        std::process::exit(exit_code);
    }
}
