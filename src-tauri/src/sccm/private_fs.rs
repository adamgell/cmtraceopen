use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path};

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
    use std::rc::Rc;

    use tempfile::tempdir;

    use super::*;

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
        use windows::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS};

        fs::create_dir_all(path).expect("create bundle directory");
        let directory = OpenOptions::new()
            .read(true)
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
        fs::create_dir_all(&root).expect("create bundle");
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
        fs::create_dir_all(&root).expect("create bundle");
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
