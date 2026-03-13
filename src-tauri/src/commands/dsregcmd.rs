use crate::dsregcmd::{analyze_text, DsregcmdAnalysisResult};

#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::ptr::{null, null_mut};

#[tauri::command]
pub fn analyze_dsregcmd(input: String) -> Result<DsregcmdAnalysisResult, String> {
    eprintln!(
        "event=dsregcmd_analysis_start input_chars={} input_lines={}",
        input.len(),
        input.lines().count()
    );

    let result = analyze_text(&input)?;

    eprintln!(
        "event=dsregcmd_analysis_complete diagnostics_count={} join_type={:?}",
        result.diagnostics.len(),
        result.derived.join_type
    );

    Ok(result)
}

#[tauri::command]
pub fn capture_dsregcmd() -> Result<String, String> {
    capture_dsregcmd_impl()
}

#[cfg(target_os = "windows")]
fn capture_dsregcmd_impl() -> Result<String, String> {
    eprintln!("event=dsregcmd_capture_start platform=windows");

    let dsregcmd_path = resolve_system32_binary("dsregcmd.exe")?;
    verify_dsregcmd_signature(&dsregcmd_path)?;

    let output = std::process::Command::new(&dsregcmd_path)
        .arg("/status")
        .output()
        .map_err(|error| {
            format!(
                "Failed to execute '{}' /status: {}",
                dsregcmd_path.display(),
                error
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let exit_code = output.status.code().unwrap_or_default();
        return Err(if stderr.is_empty() {
            format!("dsregcmd.exe /status failed with exit code {}", exit_code)
        } else {
            format!(
                "dsregcmd.exe /status failed with exit code {}: {}",
                exit_code, stderr
            )
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    eprintln!(
        "event=dsregcmd_capture_complete platform=windows stdout_chars={} stdout_lines={}",
        stdout.len(),
        stdout.lines().count()
    );
    Ok(stdout)
}

#[cfg(not(target_os = "windows"))]
fn capture_dsregcmd_impl() -> Result<String, String> {
    Err("dsregcmd capture is only supported on Windows.".to_string())
}

#[cfg(target_os = "windows")]
fn resolve_system32_binary(file_name: &str) -> Result<PathBuf, String> {
    let Some(windir) = std::env::var_os("WINDIR") else {
        return Err("WINDIR is not set; could not resolve the Windows system path.".to_string());
    };

    let path = PathBuf::from(windir).join("System32").join(file_name);
    if !path.is_file() {
        return Err(format!(
            "Expected Windows system binary was not found at '{}'.",
            path.display()
        ));
    }

    Ok(path)
}

#[cfg(target_os = "windows")]
fn verify_dsregcmd_signature(dsregcmd_path: &Path) -> Result<(), String> {
    let mut wide_path = dsregcmd_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let mut file_info = WinTrustFileInfo {
        cbStruct: std::mem::size_of::<WinTrustFileInfo>() as u32,
        pcwszFilePath: wide_path.as_mut_ptr(),
        hFile: 0,
        pgKnownSubject: null(),
    };

    let mut trust_data = WinTrustData {
        cbStruct: std::mem::size_of::<WinTrustData>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WinTrustDataChoice {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: 0,
        pwszURLReference: null(),
        dwProvFlags: 0,
        dwUIContext: 0,
        pSignatureSettings: null_mut(),
    };

    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data as *mut _ as *mut c_void,
        )
    };

    if status == 0 {
        return Ok(());
    }

    Err(format!(
        "Refusing to execute '{}': expected a valid Authenticode signature but WinVerifyTrust returned {}.",
        dsregcmd_path.display(),
        format_winverifytrust_status(status)
    ))
}

#[cfg(target_os = "windows")]
fn format_winverifytrust_status(status: i32) -> String {
    match status as u32 {
        0x800B0100 => "0x800B0100 (TRUST_E_NOSIGNATURE)".to_string(),
        0x800B0101 => "0x800B0101 (CERT_E_EXPIRED)".to_string(),
        0x800B0109 => "0x800B0109 (CERT_E_UNTRUSTEDROOT)".to_string(),
        0x80096010 => "0x80096010 (TRUST_E_BAD_DIGEST)".to_string(),
        code => format!("0x{code:08X}"),
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WinTrustFileInfo {
    cbStruct: u32,
    pcwszFilePath: *mut u16,
    hFile: isize,
    pgKnownSubject: *const Guid,
}

#[cfg(target_os = "windows")]
#[repr(C)]
union WinTrustDataChoice {
    pFile: *mut WinTrustFileInfo,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct WinTrustData {
    cbStruct: u32,
    pPolicyCallbackData: *mut c_void,
    pSIPClientData: *mut c_void,
    dwUIChoice: u32,
    fdwRevocationChecks: u32,
    dwUnionChoice: u32,
    Anonymous: WinTrustDataChoice,
    dwStateAction: u32,
    hWVTStateData: isize,
    pwszURLReference: *const u16,
    dwProvFlags: u32,
    dwUIContext: u32,
    pSignatureSettings: *mut c_void,
}

#[cfg(target_os = "windows")]
const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
    data1: 0x00AAC56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[cfg(target_os = "windows")]
const WTD_UI_NONE: u32 = 2;
#[cfg(target_os = "windows")]
const WTD_REVOKE_NONE: u32 = 0;
#[cfg(target_os = "windows")]
const WTD_CHOICE_FILE: u32 = 1;
#[cfg(target_os = "windows")]
const WTD_STATEACTION_IGNORE: u32 = 0;

#[cfg(target_os = "windows")]
extern "system" {
    fn WinVerifyTrust(hwnd: *mut c_void, pg_action_id: *const Guid, p_wvt_data: *mut c_void) -> i32;
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    use super::capture_dsregcmd;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn capture_command_returns_clear_error_on_unsupported_platform() {
        let error = capture_dsregcmd().expect_err("expected unsupported platform error");
        assert!(error.contains("only supported on Windows"));
    }
}
