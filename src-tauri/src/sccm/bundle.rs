use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use cmtraceopen_parser::sccm::SccmRole;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::AppError;

use super::intake::{
    discover_client_sources, is_reparse_point, source_snapshot, SccmClientDiscoveredArtifact,
    SccmClientDiscoveryInput,
};
use super::manifest::{
    compare_manifest_artifacts, compare_manifest_capture_gaps, expected_bundle_group,
    expected_marker_artifact_id, expected_physical_artifact_id, manifest_to_client_intake_bundle,
    rotation_segment, validate_client_capture_context, write_sccm_manifest_v1,
    SccmBundleManifestV1, SccmManifestArtifact, SccmManifestCaptureGap, SccmManifestCoverageScope,
    SccmManifestSourceState,
};

const HOST_HANDLE_HMAC_DOMAIN: &[u8] = b"cmtraceopen.sccm.host-handle.v1\0";

#[derive(Clone)]
pub struct SccmHostPseudonymKey(Zeroizing<[u8; 32]>);

impl SccmHostPseudonymKey {
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, AppError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(AppError::InvalidInput(
                "SCCM capture host pseudonym key is missing".to_owned(),
            ));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SccmHostPseudonymKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SccmHostPseudonymKey([REDACTED])")
    }
}

#[derive(Clone)]
pub struct SccmClientCaptureRequest {
    pub bundle_root: PathBuf,
    /// Raw host context is accepted only to derive a versioned opaque handle.
    /// It is never written to the public manifest.
    pub host: String,
    /// Secret 32-byte key scoped to the bundle's retention record. Callers
    /// must generate it outside this manifest boundary and must not serialize
    /// it into the bundle. Reusing a key intentionally makes host handles
    /// linkable across captures; a distinct key keeps captures unlinkable.
    pub host_pseudonym_key: SccmHostPseudonymKey,
    pub collected_at_utc: String,
    pub configmgr_version: Option<String>,
    pub encoding: Option<String>,
    pub discovery: SccmClientDiscoveryInput,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientCaptureResult {
    pub manifest: SccmBundleManifestV1,
}

pub fn capture_client_bundle(
    request: &SccmClientCaptureRequest,
) -> Result<SccmClientCaptureResult, AppError> {
    capture_client_bundle_with_publisher(request, write_sccm_manifest_v1)
}

fn capture_client_bundle_with_publisher<F>(
    request: &SccmClientCaptureRequest,
    publisher: F,
) -> Result<SccmClientCaptureResult, AppError>
where
    F: FnOnce(&Path, &SccmBundleManifestV1) -> Result<(), AppError>,
{
    validate_client_capture_context(
        &request.collected_at_utc,
        request.configmgr_version.as_deref(),
        request.encoding.as_deref(),
    )?;
    let host_handle = host_handle(&request.host, request.host_pseudonym_key.as_bytes())?;
    let discovery = discover_client_sources(&request.discovery)?;
    let mut manifest = SccmBundleManifestV1::native_client(
        host_handle,
        request.collected_at_utc.clone(),
        request.discovery.max_files_per_source,
        request.discovery.max_bytes_per_source,
    );
    let prepared = prepare_bundle_root(&request.bundle_root)?;
    let mut transaction = CaptureTransaction::default();
    let result = (|| {
        for artifact in discovery.artifacts {
            if artifact.is_unretained_cap_gap() {
                manifest.capture_gaps.push(capture_gap(&artifact));
            } else {
                manifest.artifacts.push(capture_artifact(
                    &prepared.path,
                    &artifact,
                    request,
                    &mut transaction,
                ));
            }
        }

        for state in discovery.source_states {
            if state.state.is_physical() {
                continue;
            }
            manifest.artifacts.push(SccmManifestArtifact {
                artifact_id: expected_marker_artifact_id(
                    &state.catalog_entry_id,
                    state.state,
                    &state.rotation,
                    &state.basename,
                    state.path_fingerprint.as_deref(),
                ),
                catalog_entry_id: state.catalog_entry_id,
                logical_artifact_ids: state.logical_artifact_ids,
                role: SccmRole::Client,
                source_handle: state.source_handle,
                root_handle: state.root_handle,
                path_fingerprint: state.path_fingerprint,
                rotation_lineage: state.rotation_lineage,
                relative_path: None,
                basename: state.basename,
                rotation: state.rotation,
                state: state.state,
                coverage_scope: state.coverage_scope,
                capture_limit_kind: None,
                bytes_copied: 0,
                limit_applied: None,
                content_sha256: None,
                fragment_complete: false,
                configmgr_version: request.configmgr_version.clone(),
                collected_at_utc: Some(request.collected_at_utc.clone()),
                encoding: request.encoding.clone(),
            });
        }
        manifest.artifacts.sort_by(compare_manifest_artifacts);
        manifest.capture_gaps.sort_by(compare_manifest_capture_gaps);

        // The pure contract is the final semantic validation boundary. This
        // rejects semantic inconsistencies before the manifest is published.
        manifest_to_client_intake_bundle(&manifest)?;
        publisher(&prepared.path, &manifest)?;
        Ok(SccmClientCaptureResult { manifest })
    })();
    if result.is_err() {
        if prepared.created {
            cleanup_created_bundle_root(&prepared);
        } else {
            transaction.rollback_all();
        }
    }
    result
}

fn capture_gap(artifact: &SccmClientDiscoveredArtifact) -> SccmManifestCaptureGap {
    SccmManifestCaptureGap {
        artifact_id: expected_marker_artifact_id(
            &artifact.catalog_entry_id,
            artifact.state,
            &artifact.rotation,
            &artifact.basename,
            Some(&artifact.path_fingerprint),
        ),
        catalog_entry_id: artifact.catalog_entry_id.clone(),
        logical_artifact_ids: artifact.logical_artifact_ids.clone(),
        source_handle: artifact.source_handle.clone(),
        root_handle: artifact.root_handle.clone(),
        path_fingerprint: artifact.path_fingerprint.clone(),
        rotation_lineage: artifact.rotation_lineage.clone(),
        basename: artifact.basename.clone(),
        rotation: artifact.rotation.clone(),
        state: artifact.state,
        capture_limit_kind: artifact
            .capture_limit_kind
            .expect("unretained cap gaps always carry exact cap provenance"),
        source_bytes: artifact.source_bytes,
        bytes_retained: 0,
    }
}

fn capture_artifact(
    bundle_root: &Path,
    artifact: &SccmClientDiscoveredArtifact,
    request: &SccmClientCaptureRequest,
    transaction: &mut CaptureTransaction,
) -> SccmManifestArtifact {
    let relative_path = bundle_relative_path(artifact);
    let destination = bundle_root.join(&relative_path);
    let checkpoint = transaction.checkpoint();
    let capture =
        secure_destination_parent(bundle_root, &relative_path, transaction).and_then(|()| {
            copy_bounded_source(
                artifact,
                &destination,
                artifact.state == SccmManifestSourceState::Capped
                    || artifact.copy_bytes < artifact.source_bytes,
            )
        });

    match capture {
        Ok(fragment) => {
            transaction.created_files.push(destination);
            SccmManifestArtifact {
                catalog_entry_id: artifact.catalog_entry_id.clone(),
                logical_artifact_ids: artifact.logical_artifact_ids.clone(),
                artifact_id: expected_physical_artifact_id(
                    &artifact.path_fingerprint,
                    &artifact.rotation,
                    &artifact.basename,
                ),
                role: SccmRole::Client,
                source_handle: Some(artifact.source_handle.clone()),
                root_handle: Some(artifact.root_handle.clone()),
                path_fingerprint: Some(artifact.path_fingerprint.clone()),
                rotation_lineage: Some(artifact.rotation_lineage.clone()),
                relative_path: Some(relative_path),
                basename: artifact.basename.clone(),
                rotation: artifact.rotation.clone(),
                state: artifact.state,
                coverage_scope: SccmManifestCoverageScope::Source,
                capture_limit_kind: artifact.capture_limit_kind,
                bytes_copied: fragment.bytes_copied,
                limit_applied: (artifact.capture_limit_kind.is_some()
                    || artifact.copy_bytes < artifact.source_bytes)
                    .then_some(artifact.copy_bytes),
                content_sha256: Some(fragment.content_sha256),
                // The native copier proves byte completeness, not CCM
                // logical-record boundary completeness. Remain conservative.
                fragment_complete: false,
                configmgr_version: request.configmgr_version.clone(),
                collected_at_utc: Some(request.collected_at_utc.clone()),
                encoding: request.encoding.clone(),
            }
        }
        Err(_) => {
            transaction.rollback_since(checkpoint);
            SccmManifestArtifact {
                catalog_entry_id: artifact.catalog_entry_id.clone(),
                logical_artifact_ids: artifact.logical_artifact_ids.clone(),
                artifact_id: expected_marker_artifact_id(
                    &artifact.catalog_entry_id,
                    SccmManifestSourceState::FailedUnknownDetail,
                    &artifact.rotation,
                    &artifact.basename,
                    Some(&artifact.path_fingerprint),
                ),
                role: SccmRole::Client,
                source_handle: Some(artifact.source_handle.clone()),
                root_handle: Some(artifact.root_handle.clone()),
                path_fingerprint: Some(artifact.path_fingerprint.clone()),
                rotation_lineage: Some(artifact.rotation_lineage.clone()),
                relative_path: None,
                basename: artifact.basename.clone(),
                rotation: artifact.rotation.clone(),
                state: SccmManifestSourceState::FailedUnknownDetail,
                coverage_scope: SccmManifestCoverageScope::Source,
                capture_limit_kind: None,
                bytes_copied: 0,
                limit_applied: None,
                content_sha256: None,
                fragment_complete: false,
                configmgr_version: request.configmgr_version.clone(),
                collected_at_utc: Some(request.collected_at_utc.clone()),
                encoding: request.encoding.clone(),
            }
        }
    }
}

fn bundle_relative_path(artifact: &SccmClientDiscoveredArtifact) -> String {
    format!(
        "evidence/sccm/client/{}/{}/{}/{}",
        expected_bundle_group(&artifact.logical_artifact_ids),
        artifact.root_handle,
        rotation_segment(&artifact.rotation),
        artifact.basename
    )
}

fn copy_bounded_source(
    artifact: &SccmClientDiscoveredArtifact,
    destination: &Path,
    intentionally_capped: bool,
) -> Result<CapturedFragment, AppError> {
    let source_metadata = fs::symlink_metadata(&artifact.canonical_path)?;
    if is_reparse_point(&source_metadata) || !source_metadata.is_file() {
        return Err(AppError::InvalidInput(
            "SCCM source became an unsafe path before capture".to_owned(),
        ));
    }
    let recanonicalized = artifact.canonical_path.canonicalize()?;
    if recanonicalized != artifact.canonical_path
        || !recanonicalized.starts_with(&artifact.canonical_root)
    {
        return Err(AppError::InvalidInput(
            "SCCM source escaped its approved root before capture".to_owned(),
        ));
    }

    let mut input = open_source_without_following_links(&artifact.canonical_path)?;
    let opened_metadata = input.metadata()?;
    if is_reparse_point(&opened_metadata) || !opened_metadata.is_file() {
        return Err(AppError::InvalidInput(
            "SCCM source is not a regular file at capture time".to_owned(),
        ));
    }
    if source_snapshot(&input, &opened_metadata) != artifact.source_snapshot
        || opened_metadata.len() != artifact.source_bytes
        || opened_metadata.len() < artifact.copy_bytes
    {
        return Err(AppError::State(
            "SCCM source size changed before bounded capture".to_owned(),
        ));
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open_private(destination)?;
    let result = copy_exact_fragment(
        &mut input,
        &mut output,
        artifact.copy_bytes,
        intentionally_capped,
    )
    .and_then(|written| {
        let post_metadata = input.metadata()?;
        if source_snapshot(&input, &post_metadata) != artifact.source_snapshot {
            return Err(AppError::State(
                "SCCM source changed during bounded capture".to_owned(),
            ));
        }
        let current = open_source_without_following_links(&artifact.canonical_path)?;
        let current_metadata = current.metadata()?;
        if source_snapshot(&current, &current_metadata) != artifact.source_snapshot
            || artifact.canonical_path.canonicalize()? != artifact.canonical_path
        {
            return Err(AppError::State(
                "SCCM source identity changed during bounded capture".to_owned(),
            ));
        }
        output.sync_all()?;
        Ok(written)
    });
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(destination);
    }
    result
}

fn copy_exact_fragment(
    input: &mut File,
    output: &mut File,
    expected_bytes: u64,
    intentionally_capped: bool,
) -> Result<CapturedFragment, AppError> {
    let source_len = input.metadata()?.len();
    if source_len < expected_bytes || expected_bytes > i64::MAX as u64 {
        return Err(AppError::State(
            "SCCM source size changed before bounded capture".to_owned(),
        ));
    }
    input.seek(SeekFrom::Start(0))?;

    let mut first_digest = Sha256::new();
    let mut remaining = expected_bytes;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded buffer length fits usize");
        let read = input.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(AppError::State(format!(
                "SCCM source shrank during capture: expected {expected_bytes} bytes"
            )));
        }
        output.write_all(&buffer[..read])?;
        first_digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    if !intentionally_capped {
        let mut probe = [0_u8; 1];
        if input.read(&mut probe)? != 0 {
            return Err(AppError::State(
                "SCCM source grew during capture".to_owned(),
            ));
        }
    }

    input.seek(SeekFrom::Start(0))?;
    let mut second_digest = Sha256::new();
    let mut remaining = expected_bytes;
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded buffer length fits usize");
        let read = input.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(AppError::State(
                "SCCM source changed while capture was verified".to_owned(),
            ));
        }
        second_digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let first_digest = first_digest.finalize();
    let second_digest = second_digest.finalize();
    if first_digest != second_digest {
        return Err(AppError::State(
            "SCCM source bytes changed during bounded capture".to_owned(),
        ));
    }
    Ok(CapturedFragment {
        bytes_copied: expected_bytes,
        content_sha256: first_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

struct CapturedFragment {
    bytes_copied: u64,
    content_sha256: String,
}

struct PreparedBundleRoot {
    path: PathBuf,
    created: bool,
}

#[derive(Default)]
struct CaptureTransaction {
    created_files: Vec<PathBuf>,
    created_dirs: Vec<PathBuf>,
}

impl CaptureTransaction {
    fn checkpoint(&self) -> (usize, usize) {
        (self.created_files.len(), self.created_dirs.len())
    }

    fn rollback_since(&mut self, checkpoint: (usize, usize)) {
        for path in self.created_files[checkpoint.0..].iter().rev() {
            let _ = fs::remove_file(path);
        }
        self.created_files.truncate(checkpoint.0);
        for path in self.created_dirs[checkpoint.1..].iter().rev() {
            let _ = fs::remove_dir(path);
        }
        self.created_dirs.truncate(checkpoint.1);
    }

    fn rollback_all(&mut self) {
        self.rollback_since((0, 0));
    }
}

fn prepare_bundle_root(bundle_root: &Path) -> Result<PreparedBundleRoot, AppError> {
    let created = match fs::symlink_metadata(bundle_root) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(windows)]
            {
                return Err(AppError::InvalidInput(
                    "SCCM bundle root must be pre-created with a restricted inherited ACL"
                        .to_owned(),
                ));
            }
            #[cfg(not(windows))]
            {
                create_private_dir_all(bundle_root)?;
                true
            }
        }
        Err(error) => return Err(AppError::Io(error)),
    };
    let metadata = fs::symlink_metadata(bundle_root)?;
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(AppError::InvalidInput(
            "SCCM bundle root must be a real directory".to_owned(),
        ));
    }
    verify_private_directory(bundle_root, &metadata)?;
    Ok(PreparedBundleRoot {
        path: bundle_root.canonicalize()?,
        created,
    })
}

fn cleanup_created_bundle_root(prepared: &PreparedBundleRoot) {
    let Ok(metadata) = fs::symlink_metadata(&prepared.path) else {
        return;
    };
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return;
    }
    if prepared.path.canonicalize().ok().as_deref() == Some(prepared.path.as_path()) {
        let _ = fs::remove_dir_all(&prepared.path);
    }
}

trait PrivateOpenOptions {
    fn open_private(&mut self, path: &Path) -> std::io::Result<File>;
}

impl PrivateOpenOptions for OpenOptions {
    fn open_private(&mut self, path: &Path) -> std::io::Result<File> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600);
        }
        self.open(path)
    }
}

#[cfg(unix)]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn verify_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AppError::InvalidInput(format!(
            "SCCM bundle directory {} is not private",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsAclTrustee {
    Owner,
    LocalSystem,
    BuiltinAdministrators,
    CreatorOwner,
    Other,
}

#[cfg(any(windows, test))]
fn windows_allow_ace_is_restricted(trustee: WindowsAclTrustee, inherit_only: bool) -> bool {
    matches!(
        trustee,
        WindowsAclTrustee::Owner
            | WindowsAclTrustee::LocalSystem
            | WindowsAclTrustee::BuiltinAdministrators
    ) || (trustee == WindowsAclTrustee::CreatorOwner && inherit_only)
}

#[cfg(any(windows, test))]
fn windows_owner_is_restricted(
    is_current_user: bool,
    is_local_system: bool,
    is_builtin_administrator: bool,
) -> bool {
    is_current_user || is_local_system || is_builtin_administrator
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
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|error| {
            AppError::InvalidInput(format!(
                "SCCM bundle root ACL owner could not be verified against the capture identity: {error}"
            ))
        })?;
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
        .map_err(|error| {
            AppError::InvalidInput(format!(
                "SCCM bundle root ACL owner token information could not be read: {error}"
            ))
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
    if !windows_owner_is_restricted(
        owner_is_current_user,
        owner_is_local_system,
        owner_is_builtin_administrator,
    ) {
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

fn secure_destination_parent(
    bundle_root: &Path,
    relative_path: &str,
    transaction: &mut CaptureTransaction,
) -> Result<(), AppError> {
    let relative = Path::new(relative_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::InvalidInput(
            "SCCM destination path is not bundle-relative".to_owned(),
        ));
    }
    let parent = relative.parent().ok_or_else(|| {
        AppError::InvalidInput("SCCM destination has no relative parent".to_owned())
    })?;
    let mut current = bundle_root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(segment) = component else {
            return Err(AppError::InvalidInput(
                "SCCM destination contains an unsafe component".to_owned(),
            ));
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if is_reparse_point(&metadata) || !metadata.is_dir() {
                    return Err(AppError::InvalidInput(
                        "SCCM destination parent contains a symlink or reparse point".to_owned(),
                    ));
                }
                verify_private_directory(&current, &metadata)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_dir(&current)?;
                transaction.created_dirs.push(current.clone());
            }
            Err(error) => return Err(AppError::Io(error)),
        }
        if !current.canonicalize()?.starts_with(bundle_root) {
            return Err(AppError::InvalidInput(
                "SCCM destination parent escaped the bundle root".to_owned(),
            ));
        }
    }
    Ok(())
}

fn host_handle(host: &str, pseudonym_key: &[u8; 32]) -> Result<Option<String>, AppError> {
    if host.is_empty() {
        return Ok(None);
    }
    if host != host.trim() || host.len() > 255 || host.chars().any(char::is_control) {
        return Err(AppError::InvalidInput(
            "SCCM capture host context is malformed".to_owned(),
        ));
    }
    let mut scoped_host = Zeroizing::new(Vec::with_capacity(
        HOST_HANDLE_HMAC_DOMAIN.len() + host.len(),
    ));
    scoped_host.extend_from_slice(HOST_HANDLE_HMAC_DOMAIN);
    scoped_host.extend(host.bytes().map(|byte| byte.to_ascii_lowercase()));
    Ok(Some(format!(
        "cmtraceopen.host.hmac-sha256.v1:{}",
        hmac_sha256(pseudonym_key, &scoped_host)
    )))
}

pub(super) fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    const BLOCK_BYTES: usize = 64;
    let mut normalized_key = Zeroizing::new([0_u8; BLOCK_BYTES]);
    if key.len() > BLOCK_BYTES {
        let mut digest = Sha256::digest(key);
        normalized_key[..digest.len()].copy_from_slice(&digest);
        let digest_bytes: &mut [u8] = digest.as_mut();
        digest_bytes.zeroize();
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = Zeroizing::new([0x36_u8; BLOCK_BYTES]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; BLOCK_BYTES]);
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    let inner_digest_input: &[u8] = inner_digest.as_ref();
    outer.update(inner_digest_input);
    let inner_digest_bytes: &mut [u8] = inner_digest.as_mut();
    inner_digest_bytes.zeroize();
    let mut tag = outer.finalize();
    let encoded = tag.iter().map(|byte| format!("{byte:02x}")).collect();
    let tag_bytes: &mut [u8] = tag.as_mut();
    tag_bytes.zeroize();
    encoded
}

#[cfg(unix)]
fn open_source_without_following_links(path: &Path) -> Result<File, AppError> {
    use std::os::unix::fs::OpenOptionsExt;

    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?)
}

#[cfg(windows)]
fn open_source_without_following_links(path: &Path) -> Result<File, AppError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_source_without_following_links(path: &Path) -> Result<File, AppError> {
    Ok(OpenOptions::new().read(true).open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccm::{SccmClientSourceSpec, SCCM_MANIFEST_FILE_NAME};
    use std::collections::BTreeMap;
    use std::io::Write;

    fn policy_capture_request(
        bundle_root: PathBuf,
        source_root: PathBuf,
    ) -> SccmClientCaptureRequest {
        SccmClientCaptureRequest {
            bundle_root,
            host: "LAB-CLIENT-01".to_owned(),
            host_pseudonym_key: SccmHostPseudonymKey::from_secret_bytes([0xa5; 32])
                .expect("host key"),
            collected_at_utc: "2026-07-30T15:00:00Z".to_owned(),
            configmgr_version: Some("5.00.TEST.0000".to_owned()),
            encoding: Some("utf-8".to_owned()),
            discovery: SccmClientDiscoveryInput {
                candidate_roots: vec![source_root],
                source_catalog: vec![SccmClientSourceSpec {
                    catalog_entry_id: "sccm-client-group:v1:client-policy-agent".to_owned(),
                    logical_artifact_id: "client-policy-agent".to_owned(),
                    basenames: vec!["PolicyAgent.log".to_owned()],
                    enabled: true,
                }],
                max_files_per_source: 8,
                max_bytes_per_source: 1024,
                provenance_pseudonym_key: SccmHostPseudonymKey::from_secret_bytes([0xa5; 32])
                    .expect("provenance key"),
                access_status_overrides: BTreeMap::new(),
                enumeration_status_overrides: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_test_case_one() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Sha256>();
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn windows_host_identity_is_ascii_case_insensitive() {
        let key = [0xa5; 32];
        assert_eq!(
            host_handle("LAB-Client-01", &key).expect("mixed-case host"),
            host_handle("lab-client-01", &key).expect("lower-case host")
        );
    }

    #[test]
    fn windows_acl_policy_rejects_non_privileged_allow_trustees() {
        assert!(windows_allow_ace_is_restricted(
            WindowsAclTrustee::Owner,
            false
        ));
        assert!(windows_allow_ace_is_restricted(
            WindowsAclTrustee::LocalSystem,
            false
        ));
        assert!(windows_allow_ace_is_restricted(
            WindowsAclTrustee::BuiltinAdministrators,
            false
        ));
        assert!(windows_allow_ace_is_restricted(
            WindowsAclTrustee::CreatorOwner,
            true
        ));
        assert!(!windows_allow_ace_is_restricted(
            WindowsAclTrustee::CreatorOwner,
            false
        ));
        assert!(!windows_allow_ace_is_restricted(
            WindowsAclTrustee::Other,
            false
        ));
        assert!(windows_owner_is_restricted(true, false, false));
        assert!(windows_owner_is_restricted(false, true, false));
        assert!(windows_owner_is_restricted(false, false, true));
        assert!(!windows_owner_is_restricted(false, false, false));
    }

    #[cfg(windows)]
    #[test]
    fn windows_capture_rejects_a_broadly_readable_precreated_root() {
        let temp = tempfile::tempdir().expect("temporary capture root");
        let bundle_root = temp.path().join("broad-bundle");
        fs::create_dir(&bundle_root).expect("bundle root");
        let output = std::process::Command::new("icacls.exe")
            .arg(&bundle_root)
            .arg("/grant")
            .arg("*S-1-1-0:(OI)(CI)RX")
            .output()
            .expect("icacls is available on supported Windows");
        assert!(
            output.status.success(),
            "failed to create broad synthetic ACL: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let error = prepare_bundle_root(&bundle_root).expect_err("broad ACL must fail closed");
        assert!(error.to_string().contains("non-privileged trustee"));
    }

    #[test]
    fn exact_copy_detects_growth_but_retains_an_explicit_prefix_and_digest() {
        let temp = tempfile::tempdir().expect("temporary copy root");
        let source = temp.path().join("source.log");
        let grown_destination = temp.path().join("grown.log");
        let capped_destination = temp.path().join("capped.log");
        fs::write(&source, b"0123456789").expect("source");

        let mut input = File::open(&source).expect("source input");
        let mut output = File::create(&grown_destination).expect("grown output");
        assert!(copy_exact_fragment(&mut input, &mut output, 4, false).is_err());

        let mut input = File::open(&source).expect("source input");
        let mut output = File::create(&capped_destination).expect("capped output");
        let captured =
            copy_exact_fragment(&mut input, &mut output, 4, true).expect("bounded prefix");
        assert_eq!(captured.bytes_copied, 4);
        assert_eq!(
            captured.content_sha256,
            crate::sccm::intake::sha256_bytes(b"0123")
        );
        drop(output);
        assert_eq!(fs::read(capped_destination).expect("prefix"), b"0123");
    }

    #[test]
    fn stale_discovery_size_fails_before_creating_a_partial_destination() {
        let temp = tempfile::tempdir().expect("temporary copy root");
        let root = temp.path().join("source-root");
        fs::create_dir_all(&root).expect("source root");
        let source = root.join("PolicyAgent.log");
        let destination = temp.path().join("destination.log");
        fs::write(&source, b"0123456789").expect("source");
        let canonical_root = root.canonicalize().expect("canonical root");
        let canonical_path = source.canonicalize().expect("canonical source");
        let discovered_file = File::open(&source).expect("discovered source");
        let discovered_metadata = discovered_file.metadata().expect("discovered metadata");
        let artifact = SccmClientDiscoveredArtifact {
            catalog_entry_id: "test-catalog".to_owned(),
            logical_artifact_ids: vec!["client-policy-agent".to_owned()],
            source_handle: "test-source".to_owned(),
            root_handle: "test-root".to_owned(),
            path_fingerprint: "test-path".to_owned(),
            rotation_lineage: "test-lineage".to_owned(),
            basename: "PolicyAgent.log".to_owned(),
            canonical_basename: "PolicyAgent.log".to_owned(),
            rotation: cmtraceopen_parser::sccm::SccmRotation::Current,
            state: SccmManifestSourceState::Captured,
            source_bytes: 4,
            copy_bytes: 4,
            capture_limit_kind: None,
            retained: true,
            source_snapshot: source_snapshot(&discovered_file, &discovered_metadata),
            canonical_root,
            canonical_path,
        };

        assert!(copy_bounded_source(&artifact, &destination, false).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn same_size_path_replacement_is_rejected_before_capture() {
        let temp = tempfile::tempdir().expect("temporary copy root");
        let root = temp.path().join("source-root");
        fs::create_dir_all(&root).expect("source root");
        let source = root.join("PolicyAgent.log");
        let replaced = root.join("PolicyAgent.replaced.log");
        let destination = temp.path().join("destination.log");
        fs::write(&source, b"0123456789").expect("source");
        let canonical_root = root.canonicalize().expect("canonical root");
        let canonical_path = source.canonicalize().expect("canonical source");
        let discovered_file = File::open(&source).expect("discovered source");
        let discovered_metadata = discovered_file.metadata().expect("discovered metadata");
        let artifact = SccmClientDiscoveredArtifact {
            catalog_entry_id: "test-catalog".to_owned(),
            logical_artifact_ids: vec!["client-policy-agent".to_owned()],
            source_handle: "test-source".to_owned(),
            root_handle: "test-root".to_owned(),
            path_fingerprint: "test-path".to_owned(),
            rotation_lineage: "test-lineage".to_owned(),
            basename: "PolicyAgent.log".to_owned(),
            canonical_basename: "PolicyAgent.log".to_owned(),
            rotation: cmtraceopen_parser::sccm::SccmRotation::Current,
            state: SccmManifestSourceState::Captured,
            source_bytes: 10,
            copy_bytes: 10,
            capture_limit_kind: None,
            retained: true,
            source_snapshot: source_snapshot(&discovered_file, &discovered_metadata),
            canonical_root,
            canonical_path,
        };
        fs::rename(&source, &replaced).expect("move discovered source");
        fs::write(&source, b"abcdefghij").expect("same-size replacement");

        assert!(copy_bounded_source(&artifact, &destination, false).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn capped_source_growth_after_discovery_is_rejected() {
        let temp = tempfile::tempdir().expect("temporary copy root");
        let root = temp.path().join("source-root");
        fs::create_dir_all(&root).expect("source root");
        let source = root.join("PolicyAgent.log");
        let destination = temp.path().join("destination.log");
        fs::write(&source, b"0123456789").expect("source");
        let canonical_root = root.canonicalize().expect("canonical root");
        let canonical_path = source.canonicalize().expect("canonical source");
        let discovered_file = File::open(&source).expect("discovered source");
        let discovered_metadata = discovered_file.metadata().expect("discovered metadata");
        let artifact = SccmClientDiscoveredArtifact {
            catalog_entry_id: "test-catalog".to_owned(),
            logical_artifact_ids: vec!["client-policy-agent".to_owned()],
            source_handle: "test-source".to_owned(),
            root_handle: "test-root".to_owned(),
            path_fingerprint: "test-path".to_owned(),
            rotation_lineage: "test-lineage".to_owned(),
            basename: "PolicyAgent.log".to_owned(),
            canonical_basename: "PolicyAgent.log".to_owned(),
            rotation: cmtraceopen_parser::sccm::SccmRotation::Current,
            state: SccmManifestSourceState::Capped,
            source_bytes: 10,
            copy_bytes: 4,
            capture_limit_kind: Some(crate::sccm::SccmCaptureLimitKind::Bytes),
            retained: true,
            source_snapshot: source_snapshot(&discovered_file, &discovered_metadata),
            canonical_root,
            canonical_path,
        };
        OpenOptions::new()
            .append(true)
            .open(&source)
            .expect("append source")
            .write_all(b"x")
            .expect("grow source");

        assert!(copy_bounded_source(&artifact, &destination, true).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn publication_failure_removes_only_a_bundle_root_created_by_this_call() {
        let temp = tempfile::tempdir().expect("temporary capture root");
        let source_root = temp.path().join("logs");
        let bundle_root = temp.path().join("new-bundle");
        fs::create_dir_all(&source_root).expect("source root");
        fs::write(source_root.join("PolicyAgent.log"), "policy").expect("source");
        let request = policy_capture_request(bundle_root.clone(), source_root);

        let result = capture_client_bundle_with_publisher(&request, |_root, _manifest| {
            Err(AppError::State("synthetic publication failure".to_owned()))
        });

        assert!(result.is_err());
        assert!(!bundle_root.exists());
    }

    #[test]
    fn publication_failure_removes_only_new_output_from_a_preexisting_bundle_root() {
        let temp = tempfile::tempdir().expect("temporary capture root");
        let source_root = temp.path().join("logs");
        let bundle_root = temp.path().join("existing-bundle");
        fs::create_dir_all(&source_root).expect("source root");
        fs::create_dir_all(&bundle_root).expect("bundle root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bundle_root, fs::Permissions::from_mode(0o700))
                .expect("private bundle root");
        }
        let sentinel = bundle_root.join("caller-owned.txt");
        fs::write(&sentinel, "keep").expect("sentinel");
        fs::write(source_root.join("PolicyAgent.log"), "policy").expect("source");
        let request = policy_capture_request(bundle_root.clone(), source_root);

        let result = capture_client_bundle_with_publisher(&request, |_root, _manifest| {
            Err(AppError::State("synthetic publication failure".to_owned()))
        });

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(sentinel).expect("sentinel remains"),
            "keep"
        );
        assert!(bundle_root.exists());
        assert!(!bundle_root.join("evidence").exists());
        assert!(!bundle_root.join(SCCM_MANIFEST_FILE_NAME).exists());
        assert_eq!(
            fs::read_dir(&bundle_root)
                .expect("bundle root")
                .map(|entry| entry.expect("bundle entry").file_name())
                .collect::<Vec<_>>(),
            vec![std::ffi::OsString::from("caller-owned.txt")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn publication_failure_after_a_source_copy_failure_removes_earlier_evidence_only() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary capture root");
        let source_root = temp.path().join("logs");
        let bundle_root = temp.path().join("existing-bundle");
        fs::create_dir_all(&source_root).expect("source root");
        create_private_dir_all(&bundle_root).expect("private bundle root");
        let sentinel = bundle_root.join("caller-owned.txt");
        fs::write(&sentinel, "keep").expect("sentinel");
        fs::write(source_root.join("AppEnforce.log"), "application").expect("first source");
        fs::write(source_root.join("PolicyAgent.log"), "policy").expect("second source");

        let mut request = policy_capture_request(bundle_root.clone(), source_root);
        request.discovery.source_catalog.push(SccmClientSourceSpec {
            catalog_entry_id: "sccm-client-group:v1:client-app-enforce".to_owned(),
            logical_artifact_id: "client-app-enforce".to_owned(),
            basenames: vec!["AppEnforce.log".to_owned()],
            enabled: true,
        });
        let discovered = discover_client_sources(&request.discovery).expect("discovery");
        let earlier = discovered
            .artifacts
            .iter()
            .find(|artifact| artifact.basename == "AppEnforce.log")
            .expect("earlier source");
        let blocked = discovered
            .artifacts
            .iter()
            .find(|artifact| artifact.basename == "PolicyAgent.log")
            .expect("blocked source");
        let earlier_destination = bundle_root.join(bundle_relative_path(earlier));
        let blocked_destination = bundle_root.join(bundle_relative_path(blocked));
        create_private_dir_all(blocked_destination.parent().expect("blocked parent"))
            .expect("blocked destination tree");
        let outside = temp.path().join("outside.log");
        fs::write(&outside, "outside").expect("outside sentinel");
        symlink(&outside, &blocked_destination).expect("blocked destination");

        let result = capture_client_bundle_with_publisher(&request, |_root, manifest| {
            assert!(earlier_destination.is_file(), "earlier evidence was copied");
            assert!(manifest.artifacts.iter().any(|artifact| {
                artifact.basename == "PolicyAgent.log"
                    && artifact.state == SccmManifestSourceState::FailedUnknownDetail
            }));
            Err(AppError::State("synthetic publication failure".to_owned()))
        });

        assert!(result.is_err());
        assert!(!earlier_destination.exists());
        assert!(fs::symlink_metadata(&blocked_destination).is_ok());
        assert_eq!(
            fs::read_to_string(&outside).expect("outside remains"),
            "outside"
        );
        assert_eq!(
            fs::read_to_string(&sentinel).expect("sentinel remains"),
            "keep"
        );
        assert!(!bundle_root.join(SCCM_MANIFEST_FILE_NAME).exists());
    }
}
