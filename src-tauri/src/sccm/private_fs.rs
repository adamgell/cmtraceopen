use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::error::AppError;

pub(super) fn verify_bundle_root(bundle_root: &Path) -> Result<PathBuf, AppError> {
    let metadata = fs::symlink_metadata(bundle_root).map_err(|_| {
        AppError::InvalidInput("SCCM bundle root is unavailable or unsafe".to_owned())
    })?;
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(AppError::InvalidInput(
            "SCCM bundle root must be a real directory".to_owned(),
        ));
    }
    verify_private_directory(bundle_root, &metadata)?;
    bundle_root.canonicalize().map_err(|_| {
        AppError::InvalidInput("SCCM bundle root cannot be resolved safely".to_owned())
    })
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
fn verify_private_directory(path: &Path, _metadata: &fs::Metadata) -> Result<(), AppError> {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetExplicitEntriesFromAclW, GetNamedSecurityInfoW, GRANT_ACCESS, SET_ACCESS,
        SE_FILE_OBJECT, TRUSTEE_IS_SID,
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

    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
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

#[cfg(not(any(unix, windows)))]
fn verify_private_directory(_path: &Path, _metadata: &fs::Metadata) -> Result<(), AppError> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn open_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let file = require_regular_file(file)?;
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
    Ok(file)
}

#[cfg(windows)]
pub(super) fn open_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    require_regular_file(file)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_file_no_follow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).open(path)?;
    require_regular_file(file)
}

fn require_regular_file(file: File) -> io::Result<File> {
    let metadata = file.metadata()?;
    if is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCCM bundle entry is not a regular file",
        ));
    }
    Ok(file)
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
mod tests {
    use std::os::fd::AsRawFd;

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
}
