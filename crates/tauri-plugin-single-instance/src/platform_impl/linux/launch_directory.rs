//! Select the cwd reported with a Linux secondary launch, without changing it.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

pub fn select(
    current_dir: &Path,
    current_exe: Option<&Path>,
    appimage: Option<&OsStr>,
    appdir: Option<&OsStr>,
    original_dir: Option<&OsStr>,
) -> PathBuf {
    if let (Some(exe), Some(image), Some(root), Some(original)) =
        (current_exe, appimage, appdir, original_dir)
    {
        let (image, root, original) = (Path::new(image), Path::new(root), Path::new(original));
        // AppImage's runtime records the caller in OWD before AppRun changes
        // cwd to APPDIR/usr. Ignore ambient OWD for ordinary Linux binaries.
        if image.is_absolute()
            && root.is_absolute()
            && original.is_absolute()
            && exe.is_absolute()
            && root.parent().is_some()
            && image.file_name().is_some()
            && exe.starts_with(root)
            && current_dir == root.join("usr")
        {
            return original.to_path_buf();
        }
    }
    current_dir.to_path_buf()
}
