use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path};

#[cfg(unix)]
use std::ffi::{CString, OsStr, OsString};
#[cfg(unix)]
use std::path::PathBuf;

use crate::error::AppError;

/// A bundle root whose identity remains bound for the lifetime of a native read.
///
/// Unix keeps an open directory descriptor and never re-resolves descendants by
/// pathname. Windows keeps a non-followed directory handle and opens each
/// component relative to that handle.
pub(super) struct VerifiedBundleRoot {
    #[cfg(unix)]
    directory: File,
    #[cfg(windows)]
    directory: File,
}

pub(super) fn verify_bundle_root(bundle_root: &Path) -> Result<VerifiedBundleRoot, AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(bundle_root)
            .map_err(|_| {
                AppError::InvalidInput("SCCM bundle root is unavailable or unsafe".to_owned())
            })?;
        let metadata = directory.metadata().map_err(|_| {
            AppError::InvalidInput("SCCM bundle root metadata cannot be verified".to_owned())
        })?;
        if is_reparse_point(&metadata) || !metadata.is_dir() {
            return Err(AppError::InvalidInput(
                "SCCM bundle root must be a real directory".to_owned(),
            ));
        }
        verify_private_directory(bundle_root, &metadata)?;
        Ok(VerifiedBundleRoot { directory })
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let directory = OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(bundle_root)
            .map_err(|_| {
                AppError::InvalidInput("SCCM bundle root is unavailable or unsafe".to_owned())
            })?;
        require_real_windows_directory(&directory).map_err(|_| {
            AppError::InvalidInput("SCCM bundle root must be a real directory".to_owned())
        })?;
        verify_private_directory(&directory)?;
        Ok(VerifiedBundleRoot { directory })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = bundle_root;
        Err(AppError::InvalidInput(
            "native SCCM manifest reading requires handle-bound directory traversal on this platform"
                .to_owned(),
        ))
    }
}

impl VerifiedBundleRoot {
    pub(super) fn open_relative_file(&self, relative: &Path) -> io::Result<File> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            open_relative_file_no_follow(self.directory.as_raw_fd(), relative)
        }

        #[cfg(windows)]
        {
            open_relative_file_no_follow(&self.directory, relative)
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = relative;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "handle-bound directory traversal is unavailable",
            ))
        }
    }
}

const MAX_PRIVATE_CAPTURE_FILES: usize = 4_096;
const MAX_PRIVATE_CAPTURE_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PRIVATE_CAPTURE_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivateCaptureLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl PrivateCaptureLimits {
    fn is_valid(self) -> bool {
        self.max_files != 0
            && self.max_files <= MAX_PRIVATE_CAPTURE_FILES
            && self.max_file_bytes != 0
            && self.max_file_bytes <= MAX_PRIVATE_CAPTURE_ARTIFACT_BYTES
            && self.max_total_bytes != 0
            && self.max_total_bytes <= MAX_PRIVATE_CAPTURE_TOTAL_BYTES
            && self.max_file_bytes <= self.max_total_bytes
    }
}

/// Non-forgeable destination authority rooted at a no-follow directory handle.
///
/// The source-capture seam deliberately does not exist yet. Native enumeration
/// must eventually produce an equivalent handle-bound source token before any
/// evidence-copy API can be added safely.
#[derive(Debug)]
struct PrivateCaptureRoot {
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    visibility: Vec<DirectoryAnchor>,
}

fn open_private_capture_root(path: &Path) -> io::Result<PrivateCaptureRoot> {
    #[cfg(unix)]
    {
        let (directory, visibility) = open_absolute_directory_no_follow(path)?;
        let metadata = directory.metadata()?;
        verify_private_directory(path, &metadata).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SCCM capture destination root is not private",
            )
        })?;
        Ok(PrivateCaptureRoot {
            directory,
            visibility,
        })
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "handle-bound SCCM destination publication is not implemented on this platform",
        ))
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
#[derive(Debug)]
struct DirectoryAnchor {
    parent: File,
    name: OsString,
    identity: FileIdentity,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreatedEntryKind {
    File,
    Directory,
}

#[cfg(unix)]
#[derive(Debug)]
struct CreatedEntry {
    parent: File,
    name: OsString,
    relative: PathBuf,
    identity: FileIdentity,
    kind: CreatedEntryKind,
}

#[cfg(unix)]
struct PendingCreatedEntry<'a> {
    parent: &'a File,
    name: OsString,
    identity: FileIdentity,
    kind: CreatedEntryKind,
    armed: bool,
}

#[cfg(unix)]
struct PendingUnidentifiedEntry<'a> {
    parent: &'a File,
    name: OsString,
    kind: CreatedEntryKind,
    armed: bool,
}

#[cfg(unix)]
impl PendingUnidentifiedEntry<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for PendingUnidentifiedEntry<'_> {
    fn drop(&mut self) {
        if self.armed {
            remove_private_name(self.parent, &self.name, self.kind);
            let _ = self.parent.sync_all();
        }
    }
}

#[cfg(unix)]
impl PendingCreatedEntry<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for PendingCreatedEntry<'_> {
    fn drop(&mut self) {
        if self.armed {
            remove_name_if_identity(self.parent, &self.name, self.identity, self.kind);
            let _ = self.parent.sync_all();
        }
    }
}

/// A create-new destination transaction. Every mutation and rollback operation
/// remains relative to verified open directory handles. Detected namespace
/// replacement fails closed and may leave an inert private directory behind;
/// cleanup never intentionally removes an observed replacement object. Root
/// admission excludes lower-privilege namespace mutation; malicious same-euid
/// or root mutation remains outside this primitive's threat boundary.
#[derive(Debug)]
struct PrivateBundleTransaction {
    #[cfg(unix)]
    destination_visibility: Vec<DirectoryAnchor>,
    #[cfg(unix)]
    parent: File,
    #[cfg(unix)]
    root: File,
    #[cfg(unix)]
    root_name: OsString,
    #[cfg(unix)]
    root_identity: FileIdentity,
    #[cfg(unix)]
    created_entries: Vec<CreatedEntry>,
    #[cfg(unix)]
    file_count: usize,
    #[cfg(unix)]
    total_bytes: u64,
    limits: PrivateCaptureLimits,
    poisoned: bool,
    committed: bool,
}

fn begin_private_bundle_transaction(
    private_root: &PrivateCaptureRoot,
    bundle_name: &str,
    limits: PrivateCaptureLimits,
) -> io::Result<PrivateBundleTransaction> {
    if !limits.is_valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM private publication limits are invalid",
        ));
    }
    let bundle_component = validate_single_component(bundle_name)?;

    #[cfg(unix)]
    {
        let name = bundle_component.as_os_str();
        let transaction_parent = private_root.directory.try_clone()?;
        let destination_visibility = clone_directory_anchors(&private_root.visibility)?;
        create_directory_at(&private_root.directory, name)?;
        let mut unidentified = PendingUnidentifiedEntry {
            parent: &private_root.directory,
            name: name.to_os_string(),
            kind: CreatedEntryKind::Directory,
            armed: true,
        };
        let root = open_directory_at(&private_root.directory, name)?;
        let identity = file_identity(&root)?;
        if identity_at(&private_root.directory, name)? != identity {
            unidentified.disarm();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCCM destination identity changed during creation",
            ));
        }
        let mut pending = PendingCreatedEntry {
            parent: &private_root.directory,
            name: name.to_os_string(),
            identity,
            kind: CreatedEntryKind::Directory,
            armed: true,
        };
        unidentified.disarm();
        drop(unidentified);
        invoke_private_create_hook()?;
        let metadata = root.metadata()?;
        verify_private_directory(Path::new("."), &metadata).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SCCM destination bundle is not private",
            )
        })?;
        private_root.directory.sync_all()?;
        pending.disarm();
        Ok(PrivateBundleTransaction {
            destination_visibility,
            parent: transaction_parent,
            root,
            root_name: name.to_os_string(),
            root_identity: identity,
            created_entries: Vec::new(),
            file_count: 0,
            total_bytes: 0,
            limits,
            poisoned: false,
            committed: false,
        })
    }

    #[cfg(not(unix))]
    {
        let _ = (private_root, bundle_component);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "handle-bound SCCM destination publication is not implemented on this platform",
        ))
    }
}

impl PrivateBundleTransaction {
    fn write_new_file(&mut self, relative: &Path, bytes: &[u8]) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "SCCM destination transaction is already poisoned",
            ));
        }

        #[cfg(unix)]
        {
            validate_relative_path(relative)?;
            let byte_count = u64::try_from(bytes.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "SCCM artifact is too large")
            })?;
            let next_total = self.total_bytes.checked_add(byte_count).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "SCCM byte budget overflow")
            })?;
            if self.file_count >= self.limits.max_files
                || byte_count > self.limits.max_file_bytes
                || next_total > self.limits.max_total_bytes
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SCCM destination publication limit exceeded",
                ));
            }

            let result = self.write_new_file_inner(relative, bytes, byte_count);
            if result.is_err() {
                self.poisoned = true;
                return result;
            }
            self.file_count += 1;
            self.total_bytes = next_total;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            let _ = (relative, bytes);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "handle-bound SCCM destination publication is not implemented on this platform",
            ))
        }
    }

    fn commit(mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "poisoned SCCM destination transaction cannot be committed",
            ));
        }
        #[cfg(unix)]
        {
            self.validate_visible_namespace()?;
            self.root.sync_all()?;
            self.parent.sync_all()?;
            self.validate_visible_namespace()?;
        }
        self.committed = true;
        Ok(())
    }

    #[cfg(unix)]
    fn write_new_file_inner(
        &mut self,
        relative: &Path,
        bytes: &[u8],
        byte_count: u64,
    ) -> io::Result<()> {
        use std::io::Write as _;

        let mut output = self.create_new_relative_file(relative)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        if output.metadata()?.len() != byte_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCCM destination size changed during publication",
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn create_new_relative_file(&mut self, relative: &Path) -> io::Result<File> {
        let components = relative.components().collect::<Vec<_>>();
        let mut directory = self.root.try_clone()?;
        let mut accumulated = PathBuf::new();
        for component in &components[..components.len() - 1] {
            let Component::Normal(name) = component else {
                unreachable!("validated relative path")
            };
            accumulated.push(name);
            let existing = self.created_entries.iter().find(|entry| {
                entry.kind == CreatedEntryKind::Directory && entry.relative == accumulated
            });
            if let Some(existing) = existing {
                let opened = open_directory_at(&directory, name)?;
                if file_identity(&opened)? != existing.identity {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SCCM destination ancestor identity changed",
                    ));
                }
                directory = opened;
                continue;
            }

            let tracked_parent = directory.try_clone()?;
            create_directory_at(&directory, name)?;
            let mut unidentified = PendingUnidentifiedEntry {
                parent: &directory,
                name: name.to_os_string(),
                kind: CreatedEntryKind::Directory,
                armed: true,
            };
            let opened = open_directory_at(&directory, name)?;
            let identity = file_identity(&opened)?;
            if identity_at(&directory, name)? != identity {
                unidentified.disarm();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SCCM destination ancestor identity changed during creation",
                ));
            }
            let mut pending = PendingCreatedEntry {
                parent: &directory,
                name: name.to_os_string(),
                identity,
                kind: CreatedEntryKind::Directory,
                armed: true,
            };
            unidentified.disarm();
            drop(unidentified);
            directory.sync_all()?;
            self.created_entries.push(CreatedEntry {
                parent: tracked_parent,
                name: name.to_os_string(),
                relative: accumulated.clone(),
                identity,
                kind: CreatedEntryKind::Directory,
            });
            pending.disarm();
            drop(pending);
            directory = opened;
        }

        let Component::Normal(name) = components.last().expect("validated relative path") else {
            unreachable!("validated relative path")
        };
        let tracked_parent = directory.try_clone()?;
        let output = create_file_at(&directory, name)?;
        let mut unidentified = PendingUnidentifiedEntry {
            parent: &directory,
            name: name.to_os_string(),
            kind: CreatedEntryKind::File,
            armed: true,
        };
        let identity = file_identity(&output)?;
        if identity_at(&directory, name)? != identity {
            unidentified.disarm();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCCM destination file identity changed during creation",
            ));
        }
        let mut pending = PendingCreatedEntry {
            parent: &directory,
            name: name.to_os_string(),
            identity,
            kind: CreatedEntryKind::File,
            armed: true,
        };
        unidentified.disarm();
        drop(unidentified);
        directory.sync_all()?;
        self.created_entries.push(CreatedEntry {
            parent: tracked_parent,
            name: name.to_os_string(),
            relative: relative.to_path_buf(),
            identity,
            kind: CreatedEntryKind::File,
        });
        pending.disarm();
        Ok(output)
    }

    #[cfg(unix)]
    fn validate_visible_namespace(&self) -> io::Result<()> {
        validate_directory_anchors(&self.destination_visibility)?;
        for directory in [&self.parent, &self.root] {
            let metadata = directory.metadata()?;
            verify_private_directory(Path::new("."), &metadata).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SCCM destination transaction directory is no longer private",
                )
            })?;
        }
        if identity_at(&self.parent, &self.root_name)? != self.root_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCCM destination bundle is no longer visible at its committed name",
            ));
        }
        for entry in &self.created_entries {
            if identity_at(&entry.parent, &entry.name)? != entry.identity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SCCM destination entry is no longer visible at its committed name",
                ));
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn rollback(&mut self) {
        for entry in self.created_entries.iter().rev() {
            remove_name_if_identity(&entry.parent, &entry.name, entry.identity, entry.kind);
            let _ = entry.parent.sync_all();
        }
        let _ = self.root.sync_all();
        remove_name_if_identity(
            &self.parent,
            &self.root_name,
            self.root_identity,
            CreatedEntryKind::Directory,
        );
        let _ = self.parent.sync_all();
    }
}

impl Drop for PrivateBundleTransaction {
    fn drop(&mut self) {
        if !self.committed {
            #[cfg(unix)]
            self.rollback();
        }
    }
}

fn validate_single_component(value: &str) -> io::Result<OsString> {
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    let validated = if value.is_empty() || value.len() > 160 || components.len() != 1 {
        None
    } else {
        match components[0] {
            Component::Normal(component) if path.as_os_str() == component => {
                Some(component.to_os_string())
            }
            _ => None,
        }
    };
    validated
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "SCCM bundle name is unsafe"))
}

fn validate_relative_path(relative: &Path) -> io::Result<()> {
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > 32
        || relative.as_os_str().len() > 1024
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle relative path is unsafe",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_absolute_directory_no_follow(path: &Path) -> io::Result<(File, Vec<DirectoryAnchor>)> {
    use std::os::fd::FromRawFd;

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM capture destination root must be absolute",
        ));
    }
    let descriptor = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut directory = unsafe { File::from_raw_fd(descriptor) };
    let mut visibility = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let parent = directory.try_clone()?;
                let opened = open_directory_at(&directory, name)?;
                let identity = file_identity(&opened)?;
                if identity_at(&directory, name)? != identity {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SCCM capture destination identity changed while opening",
                    ));
                }
                verify_trusted_namespace_anchor(&directory, &opened)?;
                visibility.push(DirectoryAnchor {
                    parent,
                    name: name.to_os_string(),
                    identity,
                });
                directory = opened;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SCCM capture destination path is unsafe",
                ));
            }
        }
    }
    Ok((directory, visibility))
}

#[cfg(unix)]
fn clone_directory_anchors(anchors: &[DirectoryAnchor]) -> io::Result<Vec<DirectoryAnchor>> {
    anchors
        .iter()
        .map(|anchor| {
            Ok(DirectoryAnchor {
                parent: anchor.parent.try_clone()?,
                name: anchor.name.clone(),
                identity: anchor.identity,
            })
        })
        .collect()
}

#[cfg(unix)]
fn validate_directory_anchors(anchors: &[DirectoryAnchor]) -> io::Result<()> {
    for anchor in anchors {
        let opened = open_directory_at(&anchor.parent, &anchor.name)?;
        if file_identity(&opened)? != anchor.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCCM capture destination is no longer visible at its verified path",
            ));
        }
        verify_trusted_namespace_anchor(&anchor.parent, &opened)?;
    }
    Ok(())
}

#[cfg(unix)]
fn verify_trusted_namespace_anchor(parent: &File, child: &File) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let parent_metadata = parent.metadata()?;
    let child_metadata = child.metadata()?;
    let effective_user = unsafe { libc::geteuid() };
    let trusted_owner = |uid| uid == 0 || uid == effective_user;
    if !trusted_owner(parent_metadata.uid()) || !trusted_owner(child_metadata.uid()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SCCM capture destination has an untrusted namespace owner",
        ));
    }

    let parent_mode = parent_metadata.permissions().mode();
    let lower_privilege_writable = parent_mode & 0o022 != 0;
    let sticky = parent_mode & 0o1000 != 0;
    if lower_privilege_writable && !sticky {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SCCM capture destination has a mutable ancestor namespace",
        ));
    }

    verify_platform_namespace_security(parent)?;
    verify_platform_namespace_security(child)
}

#[cfg(target_os = "linux")]
fn verify_platform_namespace_security(_directory: &File) -> io::Result<()> {
    // Linux access-ACL grants are bounded by the group-class mode mask checked
    // above. A writable class is rejected unless sticky-directory ownership
    // rules protect the trusted-owned child entry.
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_ownership_ignore_mask(flag: libc::c_int) -> io::Result<u32> {
    u32::try_from(flag).map_err(|_| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "SCCM capture destination filesystem flags cannot be validated",
        )
    })
}

#[cfg(target_os = "macos")]
fn verify_platform_namespace_security(directory: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let mut file_system = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(directory.as_raw_fd(), file_system.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let file_system = unsafe { file_system.assume_init() };
    if file_system.f_flags & macos_ownership_ignore_mask(libc::MNT_IGNORE_OWNERSHIP)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SCCM capture destination filesystem ignores ownership",
        ));
    }
    reject_macos_extended_acl(directory)
}

#[cfg(target_os = "macos")]
fn reject_macos_extended_acl(directory: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    extern "C" {
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
        fn acl_valid(acl: *mut libc::c_void) -> libc::c_int;
    }

    struct OwnedAcl(*mut libc::c_void);

    impl Drop for OwnedAcl {
        fn drop(&mut self) {
            unsafe {
                let _ = acl_free(self.0);
            }
        }
    }

    let acl = unsafe { acl_get_fd_np(directory.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let acl = OwnedAcl(acl);
    if unsafe { acl_valid(acl.0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut entry = std::ptr::null_mut();
    // macOS acl_get_entry(3) returns 0 for an entry and -1 with EINVAL when
    // ACL_FIRST_ENTRY finds no entry. It does not use Linux libacl's positive
    // end-of-list sentinel, and every unexpected errno remains an error.
    unsafe {
        *libc::__error() = 0;
    }
    if unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SCCM capture destination has an extended ACL",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINVAL) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn verify_platform_namespace_security(_directory: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCCM capture destination namespace validation is unavailable on this platform",
    ))
}

#[cfg(unix)]
fn create_directory_at(parent: &File, name: &OsStr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM path contains an interior NUL",
        )
    })?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM path contains an interior NUL",
        )
    })?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let metadata = directory.metadata()?;
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCCM path component is not a real directory",
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn create_file_at(parent: &File, name: &OsStr) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM path contains an interior NUL",
        )
    })?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn file_identity(file: &File) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn identity_at(parent: &File, name: &OsStr) -> io::Result<FileIdentity> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM path contains an interior NUL",
        )
    })?;
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let status = unsafe { status.assume_init() };
    Ok(FileIdentity {
        device: status.st_dev as u64,
        inode: status.st_ino,
    })
}

#[cfg(unix)]
fn remove_name_if_identity(
    parent: &File,
    name: &OsStr,
    expected: FileIdentity,
    kind: CreatedEntryKind,
) {
    if identity_at(parent, name).ok() != Some(expected) {
        return;
    }
    remove_private_name(parent, name, kind);
}

/// Removes a name created by this transaction from an euid-owned, mode-0700
/// directory. POSIX has no conditional unlink-by-file-identity operation, so a
/// malicious same-euid (or root) namespace mutator is outside this primitive's
/// trust boundary. Every observable identity mismatch fails closed instead.
#[cfg(unix)]
fn remove_private_name(parent: &File, name: &OsStr, kind: CreatedEntryKind) {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let Ok(name) = CString::new(name.as_bytes()) else {
        return;
    };
    let flags = if kind == CreatedEntryKind::Directory {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
}

#[cfg(all(test, unix))]
thread_local! {
    static FAIL_PRIVATE_CREATE_AFTER_MKDIR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
#[derive(Debug)]
struct PrivateCreateHookGuard;

#[cfg(all(test, unix))]
impl PrivateCreateHookGuard {
    fn fail_after_mkdir() -> Self {
        FAIL_PRIVATE_CREATE_AFTER_MKDIR.with(|fail| fail.set(true));
        Self
    }
}

#[cfg(all(test, unix))]
impl Drop for PrivateCreateHookGuard {
    fn drop(&mut self) {
        FAIL_PRIVATE_CREATE_AFTER_MKDIR.with(|fail| fail.set(false));
    }
}

#[cfg(all(test, unix))]
fn invoke_private_create_hook() -> io::Result<()> {
    if FAIL_PRIVATE_CREATE_AFTER_MKDIR.with(std::cell::Cell::get) {
        Err(io::Error::other(
            "injected SCCM destination creation failure",
        ))
    } else {
        Ok(())
    }
}

#[cfg(all(unix, not(test)))]
fn invoke_private_create_hook() -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn verify_private_directory(_path: &Path, metadata: &fs::Metadata) -> Result<(), AppError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and reads process identity only.
    let effective_user = unsafe { libc::geteuid() };
    if metadata.uid() != 0 && metadata.uid() != effective_user {
        return Err(AppError::InvalidInput(
            "SCCM bundle directory is not owned by the capture user".to_owned(),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AppError::InvalidInput(
            "SCCM bundle directory is not private".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsAclTrustee {
    Owner,
    LocalSystem,
    BuiltinAdministrators,
    CreatorOwner,
    Other,
}

#[cfg(windows)]
fn windows_allow_ace_is_restricted(trustee: WindowsAclTrustee, inherit_only: bool) -> bool {
    matches!(
        trustee,
        WindowsAclTrustee::Owner
            | WindowsAclTrustee::LocalSystem
            | WindowsAclTrustee::BuiltinAdministrators
    ) || (trustee == WindowsAclTrustee::CreatorOwner && inherit_only)
}

#[cfg(windows)]
fn verify_private_directory(directory: &File) -> Result<(), AppError> {
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetExplicitEntriesFromAclW, GetSecurityInfo, GRANT_ACCESS, SET_ACCESS, SE_FILE_OBJECT,
        TRUSTEE_IS_SID,
    };
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, IsValidSid, IsWellKnownSid, TokenUser,
        WinBuiltinAdministratorsSid, WinCreatorOwnerSid, WinLocalSystemSid, ACL,
        DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const MAX_ACL_ENTRIES: u32 = 4096;

    struct LocalAllocation(*mut core::ffi::c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0)));
                }
            }
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn owner_is_current_process_user(owner: PSID) -> Result<bool, AppError> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(
            |_| {
                AppError::InvalidInput(
                    "SCCM bundle root ACL owner could not be verified".to_owned(),
                )
            },
        )?;
        let _token = OwnedHandle(token);
        let mut required = 0_u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
        if required < std::mem::size_of::<TOKEN_USER>() as u32 {
            return Err(AppError::InvalidInput(
                "SCCM bundle root ACL owner token information is unavailable".to_owned(),
            ));
        }
        let word_bytes = std::mem::size_of::<usize>();
        let word_count = (required as usize).div_ceil(word_bytes);
        let mut buffer = vec![0_usize; word_count];
        let mut returned = required;
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required,
                &mut returned,
            )
        }
        .map_err(|_| {
            AppError::InvalidInput(
                "SCCM bundle root ACL owner token information could not be read".to_owned(),
            )
        })?;
        if returned > required {
            return Err(AppError::InvalidInput(
                "SCCM bundle root ACL owner token information changed during validation".to_owned(),
            ));
        }
        let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let token_sid = token_user.User.Sid;
        if token_sid.is_invalid() || !unsafe { IsValidSid(token_sid).as_bool() } {
            return Err(AppError::InvalidInput(
                "SCCM bundle root ACL owner token contains an invalid SID".to_owned(),
            ));
        }
        Ok(unsafe { EqualSid(owner, token_sid).is_ok() })
    }

    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(directory.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    };
    let _descriptor = LocalAllocation(descriptor.0);
    if status != ERROR_SUCCESS {
        return Err(AppError::InvalidInput(format!(
            "SCCM bundle root ACL could not be verified (Win32 error {})",
            status.0
        )));
    }
    if owner.is_invalid() || !unsafe { IsValidSid(owner).as_bool() } || dacl.is_null() {
        return Err(AppError::InvalidInput(
            "SCCM bundle root ACL has no valid owner or has a null DACL".to_owned(),
        ));
    }
    let owner_is_current_user = owner_is_current_process_user(owner)?;
    let owner_is_local_system = unsafe { IsWellKnownSid(owner, WinLocalSystemSid).as_bool() };
    let owner_is_builtin_administrator =
        unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool() };
    if !(owner_is_current_user || owner_is_local_system || owner_is_builtin_administrator) {
        return Err(AppError::InvalidInput(
            "SCCM bundle root ACL owner is not the capture user, LocalSystem, or Administrators"
                .to_owned(),
        ));
    }

    let mut entry_count = 0_u32;
    let mut entries = std::ptr::null_mut();
    let status = unsafe { GetExplicitEntriesFromAclW(dacl, &mut entry_count, &mut entries) };
    let _entries = LocalAllocation(entries.cast());
    if status != ERROR_SUCCESS {
        return Err(AppError::InvalidInput(format!(
            "SCCM bundle root ACL entries could not be verified (Win32 error {})",
            status.0
        )));
    }
    if entry_count > MAX_ACL_ENTRIES || (entry_count != 0 && entries.is_null()) {
        return Err(AppError::InvalidInput(
            "SCCM bundle root ACL has an unsafe entry count".to_owned(),
        ));
    }
    let entries = if entry_count == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(entries, entry_count as usize) }
    };
    for entry in entries {
        if entry.grfAccessPermissions == 0
            || !matches!(entry.grfAccessMode, GRANT_ACCESS | SET_ACCESS)
        {
            continue;
        }
        if entry.Trustee.TrusteeForm != TRUSTEE_IS_SID || entry.Trustee.ptstrName.is_null() {
            return Err(AppError::InvalidInput(
                "SCCM bundle root ACL contains an unverifiable allow trustee".to_owned(),
            ));
        }
        let sid = PSID(entry.Trustee.ptstrName.0.cast());
        if !unsafe { IsValidSid(sid).as_bool() } {
            return Err(AppError::InvalidInput(
                "SCCM bundle root ACL contains an invalid allow trustee".to_owned(),
            ));
        }
        let trustee = if unsafe { EqualSid(sid, owner).is_ok() } {
            WindowsAclTrustee::Owner
        } else if unsafe { IsWellKnownSid(sid, WinLocalSystemSid).as_bool() } {
            WindowsAclTrustee::LocalSystem
        } else if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() } {
            WindowsAclTrustee::BuiltinAdministrators
        } else if unsafe { IsWellKnownSid(sid, WinCreatorOwnerSid).as_bool() } {
            WindowsAclTrustee::CreatorOwner
        } else {
            WindowsAclTrustee::Other
        };
        let inherit_only = entry.grfInheritance.0 & INHERIT_ONLY_ACE.0 != 0;
        if !windows_allow_ace_is_restricted(trustee, inherit_only) {
            return Err(AppError::InvalidInput(
                "SCCM bundle root ACL grants access to a non-privileged trustee".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(all(unix, test))]
pub(super) fn open_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let file = require_regular_file(file)?;
    clear_nonblock(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn clear_nonblock(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let descriptor = file.as_raw_fd();
    // SAFETY: `descriptor` is borrowed from the live `File`; both fcntl calls
    // operate only on its status flags and preserve every flag except NONBLOCK.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn open_relative_file_no_follow(root_fd: std::os::fd::RawFd, relative: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle relative path is unsafe",
        ));
    }

    // Duplicate the root so every descriptor remains owned locally while each
    // `openat` call is bound to the directory identity opened above.
    let duplicate = unsafe { libc::fcntl(root_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut directory = unsafe { File::from_raw_fd(duplicate) };
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("unsafe components were rejected above");
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCCM bundle path contains an interior NUL",
            )
        })?;
        let final_component = index + 1 == components.len();
        let flags = if final_component {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC
        };
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let opened = unsafe { File::from_raw_fd(descriptor) };
        if final_component {
            let opened = require_regular_file(opened)?;
            clear_nonblock(&opened)?;
            return Ok(opened);
        }
        let metadata = opened.metadata()?;
        if is_reparse_point(&metadata) || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCCM bundle ancestor is not a real directory",
            ));
        }
        #[cfg(test)]
        invoke_open_component_hook(name.as_c_str());
        directory = opened;
    }
    unreachable!("non-empty relative paths always return from their final component")
}

#[cfg(windows)]
fn open_relative_file_no_follow(root: &File, relative: &Path) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows::core::PWSTR;
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Wdk::Storage::FileSystem::{
        NtCreateFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows::Win32::Foundation::{
        RtlNtStatusToDosError, HANDLE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    use windows::Win32::System::IO::IO_STATUS_BLOCK;

    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle relative path is unsafe",
        ));
    }

    let mut held_directories = Vec::new();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("unsafe components were rejected above");
        };
        let mut wide_name = name.encode_wide().collect::<Vec<_>>();
        let wide_bytes = wide_name
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SCCM bundle path component is too long",
                )
            })?;
        if wide_name.is_empty()
            || wide_name.contains(&0)
            || wide_name.contains(&(b':' as u16))
            || wide_bytes > u16::MAX as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCCM bundle path contains an invalid component",
            ));
        }
        let mut object_name = UNICODE_STRING {
            Length: wide_bytes as u16,
            MaximumLength: wide_bytes as u16,
            Buffer: PWSTR(wide_name.as_mut_ptr()),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: held_directories.last().map_or_else(
                || HANDLE(root.as_raw_handle()),
                |directory: &File| HANDLE(directory.as_raw_handle()),
            ),
            ObjectName: &mut object_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let final_component = index + 1 == components.len();
        let options = if final_component {
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
        };
        let mut handle = HANDLE::default();
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_GENERIC_READ,
                &object_attributes,
                &mut io_status,
                None,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                options,
                None,
                0,
            )
        };
        if status.0 < 0 || handle.0.is_null() || handle.is_invalid() {
            if status.0 < 0 {
                // SAFETY: RtlNtStatusToDosError converts the NTSTATUS returned
                // by NtCreateFile without dereferencing caller-owned memory.
                return Err(io::Error::from_raw_os_error(unsafe {
                    RtlNtStatusToDosError(status) as i32
                }));
            }
            return Err(io::Error::other(
                "SCCM bundle entry could not be opened safely",
            ));
        }
        // SAFETY: a successful NtCreateFile returns an owned handle. This File
        // owns it until it is returned or replaced by the next live ancestor.
        let opened = unsafe { File::from_raw_handle(handle.0) };
        if final_component {
            return require_regular_file(opened);
        }
        require_real_windows_directory(&opened)?;
        held_directories.push(opened);
        #[cfg(test)]
        invoke_open_component_hook(name);
    }
    unreachable!("non-empty relative paths always return from their final component")
}

fn require_regular_file(file: File) -> io::Result<File> {
    #[cfg(windows)]
    {
        require_real_windows_file(&file)?;
        Ok(file)
    }

    #[cfg(not(windows))]
    {
        let metadata = file.metadata()?;
        if is_reparse_point(&metadata) || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCCM bundle entry is not a regular file",
            ));
        }
        require_single_link(&file)?;
        Ok(file)
    }
}

#[cfg(unix)]
fn require_single_link(file: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if file.metadata()?.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle entry must be a single-link file",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> io::Result<windows::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(
            windows::Win32::Foundation::HANDLE(file.as_raw_handle()),
            &mut information,
        )
    }
    .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(information)
}

#[cfg(windows)]
fn require_real_windows_directory(file: &File) -> io::Result<()> {
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let information = windows_file_information(file)?;
    let attributes = information.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle ancestor is not a real directory",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_real_windows_file(file: &File) -> io::Result<()> {
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let information = windows_file_information(file)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle entry is not a regular file",
        ));
    }
    if information.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle entry must be a single-link file",
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn require_single_link(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCCM bundle link count cannot be verified",
    ))
}

pub(super) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

#[cfg(all(test, unix))]
type OpenComponentHook = Box<dyn FnMut(&std::ffi::CStr)>;

#[cfg(all(test, unix))]
thread_local! {
    static OPEN_COMPONENT_HOOK: std::cell::RefCell<Option<OpenComponentHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
fn set_open_component_hook(hook: Option<OpenComponentHook>) {
    OPEN_COMPONENT_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(all(test, any(unix, windows)))]
struct OpenComponentHookGuard;

#[cfg(all(test, any(unix, windows)))]
impl OpenComponentHookGuard {
    fn install(hook: OpenComponentHook) -> Self {
        set_open_component_hook(Some(hook));
        Self
    }
}

#[cfg(all(test, any(unix, windows)))]
impl Drop for OpenComponentHookGuard {
    fn drop(&mut self) {
        set_open_component_hook(None);
    }
}

#[cfg(all(test, unix))]
fn invoke_open_component_hook(component: &std::ffi::CStr) {
    OPEN_COMPONENT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(component);
        }
    });
}

#[cfg(all(test, windows))]
type OpenComponentHook = Box<dyn FnMut(&std::ffi::OsStr)>;

#[cfg(all(test, windows))]
thread_local! {
    static OPEN_COMPONENT_HOOK: std::cell::RefCell<Option<OpenComponentHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, windows))]
fn set_open_component_hook(hook: Option<OpenComponentHook>) {
    OPEN_COMPONENT_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(all(test, windows))]
fn invoke_open_component_hook(component: &std::ffi::OsStr) {
    OPEN_COMPONENT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(component);
        }
    });
}

#[cfg(all(test, unix))]
mod tests {
    use std::cell::RefCell;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;

    use tempfile::tempdir;

    use super::*;

    fn private_capture_root() -> (tempfile::TempDir, PathBuf, PrivateCaptureRoot) {
        let temporary = tempdir().expect("temporary root");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private temporary root");
        let canonical = temporary
            .path()
            .canonicalize()
            .expect("canonical test root");
        let root = open_private_capture_root(&canonical).expect("handle-bound private root");
        (temporary, canonical, root)
    }

    fn test_limits() -> PrivateCaptureLimits {
        PrivateCaptureLimits {
            max_files: 1,
            max_file_bytes: 8,
            max_total_bytes: 10,
        }
    }

    #[test]
    fn private_capture_root_rejects_a_symlinked_parent_component() {
        let temporary = tempdir().expect("temporary root");
        let canonical_temporary = temporary.path().canonicalize().expect("canonical root");
        let actual_parent = canonical_temporary.join("actual-parent");
        let private_root = actual_parent.join("private-root");
        fs::create_dir_all(&private_root).expect("real private root");
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let linked_parent = canonical_temporary.join("linked-parent");
        std::os::unix::fs::symlink(&actual_parent, &linked_parent).expect("parent symlink");

        open_private_capture_root(&private_root)
            .expect("control path reaches the real root before testing the parent symlink");
        let error = open_private_capture_root(&linked_parent.join("private-root"))
            .expect_err("capture-root traversal never follows a parent symlink");
        assert!(
            matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::ENOTDIR),
            "expected a no-follow component rejection, got {error:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_ownership_flag_mask_conversion_fails_closed() {
        assert_ne!(
            macos_ownership_ignore_mask(libc::MNT_IGNORE_OWNERSHIP)
                .expect("platform ownership flag is representable"),
            0
        );
        assert_eq!(
            macos_ownership_ignore_mask(-1)
                .expect_err("negative flag must not disable the ownership check")
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn private_capture_root_rejects_a_world_writable_nonsticky_parent() {
        let temporary = tempdir().expect("temporary root");
        let canonical_temporary = temporary.path().canonicalize().expect("canonical root");
        let mutable_parent = canonical_temporary.join("mutable-parent");
        let private_root = mutable_parent.join("private-root");
        fs::create_dir_all(&private_root).expect("private root");
        fs::set_permissions(&mutable_parent, fs::Permissions::from_mode(0o777))
            .expect("mutable parent permissions");
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
            .expect("private root permissions");

        let error = open_private_capture_root(&private_root)
            .expect_err("lower-privilege mutable parent is rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("mutable ancestor namespace"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_capture_root_rejects_a_parent_with_an_extended_allow_acl() {
        let temporary = tempdir().expect("temporary root");
        let canonical_temporary = temporary.path().canonicalize().expect("canonical root");
        let acl_parent = canonical_temporary.join("acl-parent");
        let private_root = acl_parent.join("private-root");
        fs::create_dir_all(&private_root).expect("private root");
        fs::set_permissions(&acl_parent, fs::Permissions::from_mode(0o700))
            .expect("acl parent permissions");
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
            .expect("private root permissions");
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow delete_child")
            .arg(&acl_parent)
            .status()
            .expect("invoke chmod for ACL fixture");
        assert!(status.success(), "install extended ACL fixture");

        let error = open_private_capture_root(&private_root)
            .expect_err("extended allow ACL on an anchor parent is rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("extended ACL"));
    }

    #[test]
    fn destination_limits_fail_before_creating_the_rejected_entry() {
        let (_temporary, path, root) = private_capture_root();
        let mut transaction = begin_private_bundle_transaction(&root, "capture-001", test_limits())
            .expect("new transaction");

        transaction
            .write_new_file(Path::new("too-large.log"), b"123456789")
            .expect_err("per-file cap is checked before creation");
        assert!(!path.join("capture-001/too-large.log").exists());

        transaction
            .write_new_file(Path::new("first.log"), b"123456")
            .expect("first destination file");
        transaction
            .write_new_file(Path::new("second.log"), b"1")
            .expect_err("global file count is checked before creation");
        assert!(!path.join("capture-001/second.log").exists());

        drop(transaction);
        let mut aggregate_transaction = begin_private_bundle_transaction(
            &root,
            "capture-002",
            PrivateCaptureLimits {
                max_files: 2,
                max_file_bytes: 8,
                max_total_bytes: 10,
            },
        )
        .expect("aggregate-limit transaction");
        aggregate_transaction
            .write_new_file(Path::new("first.log"), b"123456")
            .expect("first aggregate file");
        aggregate_transaction
            .write_new_file(Path::new("aggregate.log"), b"12345")
            .expect_err("aggregate cap is checked before creation");
        assert!(!path.join("capture-002/aggregate.log").exists());
    }

    #[test]
    fn bundle_name_requires_the_exact_validated_component() {
        let (_temporary, path, root) = private_capture_root();

        let error = begin_private_bundle_transaction(&root, "capture-001/", test_limits())
            .expect_err("a normalized spelling must not reach handle-relative syscalls");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("bundle name is unsafe"));
        assert!(!path.join("capture-001").exists());
    }

    #[test]
    fn production_security_ceilings_cannot_be_relaxed_by_a_caller() {
        assert_eq!(MAX_PRIVATE_CAPTURE_ARTIFACT_BYTES, 256 * 1024 * 1024);
        assert_eq!(MAX_PRIVATE_CAPTURE_TOTAL_BYTES, 1024 * 1024 * 1024);
        assert_eq!(MAX_PRIVATE_CAPTURE_FILES, 4_096);
        let (_temporary, path, root) = private_capture_root();
        let relaxed = PrivateCaptureLimits {
            max_files: MAX_PRIVATE_CAPTURE_FILES + 1,
            max_file_bytes: MAX_PRIVATE_CAPTURE_ARTIFACT_BYTES + 1,
            max_total_bytes: MAX_PRIVATE_CAPTURE_TOTAL_BYTES + 1,
        };

        begin_private_bundle_transaction(&root, "capture-001", relaxed)
            .expect_err("immutable security ceilings reject relaxed limits");

        assert!(!path.join("capture-001").exists());
    }

    #[test]
    fn rollback_uses_open_handles_after_the_visible_bundle_name_is_replaced() {
        let (_temporary, path, root) = private_capture_root();
        let mut transaction = begin_private_bundle_transaction(&root, "capture-001", test_limits())
            .expect("new transaction");
        transaction
            .write_new_file(Path::new("evidence/original.log"), b"owned")
            .expect("transaction-owned evidence");

        let replacement = path.join("replacement");
        fs::create_dir(&replacement).expect("replacement directory");
        fs::write(replacement.join("sentinel"), b"existing").expect("replacement sentinel");
        let retired = path.join("retired");
        fs::rename(path.join("capture-001"), &retired).expect("retire transaction root");
        fs::rename(&replacement, path.join("capture-001")).expect("install replacement root");

        transaction
            .commit()
            .expect_err("commit fails when the visible bundle identity is replaced");

        assert_eq!(
            fs::read(path.join("capture-001/sentinel")).expect("replacement survives"),
            b"existing"
        );
        assert!(!retired.join("evidence/original.log").exists());
    }

    #[test]
    fn commit_rejects_a_replaced_destination_root_component() {
        let temporary = tempdir().expect("temporary root");
        let canonical_temporary = temporary.path().canonicalize().expect("canonical root");
        let destination = canonical_temporary.join("private");
        fs::create_dir(&destination).expect("private destination");
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("private destination permissions");
        let root = open_private_capture_root(&destination).expect("handle-bound destination");
        let mut transaction = begin_private_bundle_transaction(&root, "capture-001", test_limits())
            .expect("new transaction");
        transaction
            .write_new_file(Path::new("evidence/original.log"), b"owned")
            .expect("transaction-owned evidence");

        let replacement = canonical_temporary.join("replacement");
        fs::create_dir(&replacement).expect("replacement destination");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))
            .expect("replacement destination permissions");
        fs::write(replacement.join("sentinel"), b"existing").expect("replacement sentinel");
        let retired = canonical_temporary.join("retired");
        fs::rename(&destination, &retired).expect("retire destination root");
        fs::rename(&replacement, &destination).expect("install replacement destination");

        transaction
            .commit()
            .expect_err("commit fails when a destination-root component is replaced");

        assert_eq!(
            fs::read(destination.join("sentinel")).expect("replacement survives"),
            b"existing"
        );
        assert!(!retired.join("capture-001/evidence/original.log").exists());
    }

    #[test]
    fn injected_creation_failure_removes_the_directory_created_by_this_attempt() {
        let (_temporary, path, root) = private_capture_root();
        let _hook = PrivateCreateHookGuard::fail_after_mkdir();

        begin_private_bundle_transaction(&root, "capture-001", test_limits())
            .expect_err("injected post-mkdir failure");

        assert!(!path.join("capture-001").exists());
    }

    #[test]
    fn committed_destination_transaction_retains_only_create_new_files() {
        let (_temporary, path, root) = private_capture_root();
        let mut transaction = begin_private_bundle_transaction(&root, "capture-001", test_limits())
            .expect("new transaction");
        transaction
            .write_new_file(Path::new("evidence/policy.log"), b"policy")
            .expect("new evidence");
        transaction.commit().expect("durable commit");

        assert_eq!(
            fs::read(path.join("capture-001/evidence/policy.log")).expect("committed evidence"),
            b"policy"
        );
    }

    #[test]
    fn no_follow_open_rejects_a_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let temporary = tempdir().expect("temporary root");
        let canonical_temporary = temporary.path().canonicalize().expect("canonical root");
        let fifo = canonical_temporary.join("synthetic-fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let error =
            open_file_no_follow(&fifo).expect_err("FIFO is rejected through a nonblocking open");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "SCCM bundle entry is not a regular file");
    }

    #[test]
    fn safe_open_returns_only_regular_blocking_files() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("manifest.json");
        fs::write(&path, b"{}").expect("synthetic manifest");

        let file = open_file_no_follow(&path).expect("regular file");
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "opened descriptor flags are readable");
        assert_eq!(flags & libc::O_NONBLOCK, 0);

        open_file_no_follow(root.path()).expect_err("directories are rejected after opening");
    }

    #[test]
    fn handle_relative_open_returns_a_blocking_final_descriptor() {
        let root = tempdir().expect("temporary root");
        let bundle = root.path().join("bundle");
        fs::create_dir_all(bundle.join("evidence")).expect("private bundle");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o700)).expect("private root");
        fs::write(bundle.join("evidence/manifest.json"), b"{}").expect("synthetic manifest");

        let verified = verify_bundle_root(&bundle).expect("verified root");
        let file = verified
            .open_relative_file(Path::new("evidence/manifest.json"))
            .expect("regular nested file");
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "opened descriptor flags are readable");
        assert_eq!(flags & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn open_component_hook_guard_clears_the_hook_after_unwinding() {
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _hook = OpenComponentHookGuard::install(Box::new(|_| {
                panic!("stale hook must not survive this scope")
            }));
            panic!("test unwind");
        }));
        assert!(unwind.is_err());

        let component = std::ffi::CString::new("evidence").expect("test component");
        invoke_open_component_hook(component.as_c_str());
    }

    #[test]
    fn verified_root_keeps_reading_the_original_directory_after_root_replacement() {
        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        let replacement = temp.path().join("replacement");
        fs::create_dir_all(root.join("nested")).expect("create original bundle");
        fs::create_dir_all(replacement.join("nested")).expect("create replacement bundle");
        fs::write(root.join("nested/evidence.log"), b"original").expect("original evidence");
        fs::write(replacement.join("nested/evidence.log"), b"replacement")
            .expect("replacement evidence");
        for directory in [&root, &replacement] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private root");
        }

        let verified = verify_bundle_root(&root).expect("open original root");
        fs::rename(&root, temp.path().join("retired")).expect("move original root");
        fs::rename(&replacement, &root).expect("install replacement root");

        let mut opened = verified
            .open_relative_file(Path::new("nested/evidence.log"))
            .expect("bound root remains readable");
        let mut contents = String::new();
        opened
            .read_to_string(&mut contents)
            .expect("read bound evidence");
        assert_eq!(contents, "original");
    }

    #[test]
    fn verified_root_keeps_an_opened_ancestor_after_a_deterministic_swap() {
        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        let replacement = temp.path().join("replacement-evidence");
        fs::create_dir_all(root.join("evidence/nested")).expect("create original evidence");
        fs::create_dir_all(replacement.join("nested")).expect("create replacement evidence");
        fs::write(root.join("evidence/nested/evidence.log"), b"original")
            .expect("original evidence");
        fs::write(replacement.join("nested/evidence.log"), b"replacement")
            .expect("replacement evidence");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");

        let verified = verify_bundle_root(&root).expect("open original root");
        let retired = temp.path().join("retired-evidence");
        let fired = Rc::new(RefCell::new(false));
        let fired_in_hook = Rc::clone(&fired);
        let _hook = OpenComponentHookGuard::install(Box::new(move |component| {
            if component.to_bytes() == b"evidence" && !*fired_in_hook.borrow() {
                *fired_in_hook.borrow_mut() = true;
                fs::rename(root.join("evidence"), &retired).expect("retire opened ancestor");
                fs::rename(&replacement, root.join("evidence"))
                    .expect("install replacement ancestor");
            }
        }));

        let mut opened = verified
            .open_relative_file(Path::new("evidence/nested/evidence.log"))
            .expect("opened ancestor remains bound");
        let mut contents = String::new();
        opened
            .read_to_string(&mut contents)
            .expect("read bound evidence");
        assert!(*fired.borrow(), "test hook ran after ancestor open");
        assert_eq!(contents, "original");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::cell::RefCell;
    use std::io::Read;
    use std::rc::Rc;

    use tempfile::tempdir;

    use super::*;

    fn make_private_directory(path: &Path) {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};

        use windows::core::PWSTR;
        use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
        use windows::Win32::Security::Authorization::{
            GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
            NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        };
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        };
        use windows::Win32::Storage::FileSystem::{
            FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL, WRITE_DAC,
        };

        fs::create_dir_all(path).expect("create bundle directory");
        // READ_CONTROL is required for GetSecurityInfo (owner query).
        // WRITE_DAC is required for SetSecurityInfo (DACL write); it is NOT included
        // in GENERIC_READ, so using .read(true) alone produces ERROR_ACCESS_DENIED.
        let directory = OpenOptions::new()
            .access_mode(READ_CONTROL.0 | WRITE_DAC.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(path)
            .expect("open bundle directory for DACL fixture");
        let mut owner = PSID::default();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetSecurityInfo(
                HANDLE(directory.as_raw_handle()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "read fixture owner");
        let fixture_access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: windows::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: PWSTR(owner.0.cast()),
            },
        };
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let status = unsafe { SetEntriesInAclW(Some(&[fixture_access]), None, &mut dacl) };
        assert_eq!(status, ERROR_SUCCESS, "build restrictive fixture DACL");
        let status = unsafe {
            SetSecurityInfo(
                HANDLE(directory.as_raw_handle()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            let _ = LocalFree(Some(HLOCAL(dacl.cast())));
        }
        assert_eq!(status, ERROR_SUCCESS, "install restrictive fixture DACL");
    }

    #[test]
    fn missing_final_component_preserves_not_found_for_legacy_fallback() {
        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        make_private_directory(&root);

        let verified = verify_bundle_root(&root).expect("open private root");
        let error = verified
            .open_relative_file(Path::new("sccm-manifest.json"))
            .expect_err("missing native manifest is reported to the legacy fallback");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn relative_component_rejects_alternate_data_streams() {
        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        make_private_directory(&root);
        fs::write(root.join("manifest.json"), b"{}\n").expect("create manifest");

        let verified = verify_bundle_root(&root).expect("open private root");
        let error = verified
            .open_relative_file(Path::new("manifest.json:alternate"))
            .expect_err("alternate data streams cannot be opened as bundle entries");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn verified_root_keeps_reading_the_original_directory_after_root_replacement() {
        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        let replacement = temp.path().join("replacement");
        make_private_directory(&root);
        make_private_directory(&replacement);
        fs::create_dir_all(root.join("nested")).expect("create original bundle");
        fs::create_dir_all(replacement.join("nested")).expect("create replacement bundle");
        fs::write(root.join("nested/evidence.log"), b"original").expect("original evidence");
        fs::write(replacement.join("nested/evidence.log"), b"replacement")
            .expect("replacement evidence");

        let verified = verify_bundle_root(&root).expect("open original root");
        fs::rename(&root, temp.path().join("retired")).expect("move original root");
        fs::rename(&replacement, &root).expect("install replacement root");

        let mut opened = verified
            .open_relative_file(Path::new("nested/evidence.log"))
            .expect("bound root remains readable");
        let mut contents = String::new();
        opened
            .read_to_string(&mut contents)
            .expect("read bound evidence");
        assert_eq!(contents, "original");
    }

    #[test]
    fn verified_root_keeps_an_opened_ancestor_after_a_deterministic_swap() {
        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        let replacement = temp.path().join("replacement-evidence");
        make_private_directory(&root);
        make_private_directory(&replacement);
        fs::create_dir_all(root.join("evidence/nested")).expect("create original evidence");
        fs::create_dir_all(replacement.join("nested")).expect("create replacement evidence");
        fs::write(root.join("evidence/nested/evidence.log"), b"original")
            .expect("original evidence");
        fs::write(replacement.join("nested/evidence.log"), b"replacement")
            .expect("replacement evidence");

        let verified = verify_bundle_root(&root).expect("open original root");
        let retired = temp.path().join("retired-evidence");
        let fired = Rc::new(RefCell::new(false));
        let fired_in_hook = Rc::clone(&fired);
        let _hook = OpenComponentHookGuard::install(Box::new(move |component| {
            if component.eq_ignore_ascii_case("evidence") && !*fired_in_hook.borrow() {
                *fired_in_hook.borrow_mut() = true;
                fs::rename(root.join("evidence"), &retired).expect("retire opened ancestor");
                fs::rename(&replacement, root.join("evidence"))
                    .expect("install replacement ancestor");
            }
        }));

        let mut opened = verified
            .open_relative_file(Path::new("evidence/nested/evidence.log"))
            .expect("opened ancestor remains bound");
        let mut contents = String::new();
        opened
            .read_to_string(&mut contents)
            .expect("read bound evidence");
        assert!(*fired.borrow(), "test hook ran after ancestor open");
        assert_eq!(contents, "original");
    }

    #[test]
    fn verified_root_rejects_a_hard_linked_final_entry() {
        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        make_private_directory(&root);
        let manifest = root.join("manifest.json");
        let second_link = root.join("manifest-copy.json");
        fs::write(&manifest, b"{}\n").expect("manifest");
        fs::hard_link(&manifest, &second_link).expect("create hard link");

        let verified = verify_bundle_root(&root).expect("open private root");
        let error = verified
            .open_relative_file(Path::new("manifest.json"))
            .expect_err("hard-linked entries are unsafe");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn verified_root_rejects_a_reparse_final_entry_when_symlinks_are_available() {
        use std::os::windows::fs::symlink_file;

        let temp = tempdir().expect("temporary root");
        let root = temp.path().join("bundle");
        make_private_directory(&root);
        let target = temp.path().join("outside-manifest.json");
        fs::write(&target, b"outside").expect("outside manifest");
        if symlink_file(&target, root.join("manifest.json")).is_err() {
            // Windows systems without Developer Mode or SeCreateSymbolicLinkPrivilege
            // cannot create this fixture. The hosted Windows job covers the real path.
            return;
        }

        let verified = verify_bundle_root(&root).expect("open private root");
        let error = verified
            .open_relative_file(Path::new("manifest.json"))
            .expect_err("reparse entries are unsafe");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
