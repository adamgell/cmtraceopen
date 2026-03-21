use super::models::{
    MacosEnrollmentStatus, MacosMdmPayload, MacosMdmProfile, MacosProfilesResult,
};

// ---------------------------------------------------------------------------
// Parsing helpers (cross-platform, always compiled, fully testable)
// ---------------------------------------------------------------------------

/// Parses the text output of `profiles status -type enrollment`.
///
/// Example output:
/// ```text
/// Enrolled via DEP: Yes
/// MDM server: https://manage.microsoft.com/...
/// ```
pub fn parse_enrollment_status(output: &str) -> MacosEnrollmentStatus {
    let mut enrolled = false;
    let mut mdm_server: Option<String> = None;
    let mut enrollment_type: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();

        if let Some(val) = line.strip_prefix("Enrolled via DEP:") {
            let val = val.trim();
            if val.eq_ignore_ascii_case("yes") {
                enrolled = true;
                enrollment_type = Some("DEP".to_string());
            } else if val.eq_ignore_ascii_case("no") {
                // Enrolled, but not via DEP — still could be user-enrolled
            }
        }

        if let Some(val) = line.strip_prefix("MDM server:") {
            let val = val.trim();
            if !val.is_empty() {
                mdm_server = Some(val.to_string());
                // Having an MDM server indicates enrollment regardless of DEP status
                enrolled = true;
            }
        }

        // Some versions spell it differently
        if let Some(val) = line.strip_prefix("MDM enrollment:") {
            let val = val.trim();
            if val.eq_ignore_ascii_case("yes") {
                enrolled = true;
            }
        }

        if (line.to_lowercase().contains("user approved")
            || line.to_lowercase().contains("user enrollment"))
            && enrollment_type.is_none()
        {
            enrollment_type = Some("User".to_string());
        }
    }

    MacosEnrollmentStatus {
        enrolled,
        mdm_server,
        enrollment_type,
        raw_output: output.to_string(),
    }
}

/// Parses the plist XML output of `profiles list -output stdout-xml` (or `profiles show -all`)
/// into a list of MDM profiles.
///
/// The plist is a dictionary whose top-level key `_computerlevel` contains an
/// array of profile dictionaries. Each profile dict contains keys like
/// `ProfileIdentifier`, `ProfileDisplayName`, `ProfileItems` (array of payload
/// dicts), etc.
fn parse_profiles_plist(data: &[u8]) -> Vec<MacosMdmProfile> {
    let root: plist::Value = match plist::from_bytes(data) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse profiles plist: {}", e);
            return Vec::new();
        }
    };

    let root_dict = match root.as_dictionary() {
        Some(d) => d,
        None => return Vec::new(),
    };

    let mut profiles = Vec::new();

    // The profiles command may emit profiles under `_computerlevel` and/or
    // `_userlevel` arrays.
    for section_key in &["_computerlevel", "_userlevel"] {
        let section_arr = match root_dict.get(section_key).and_then(|v| v.as_array()) {
            Some(a) => a,
            None => continue,
        };

        let is_managed_section = *section_key == "_computerlevel";

        for profile_val in section_arr {
            let dict = match profile_val.as_dictionary() {
                Some(d) => d,
                None => continue,
            };

            let get_str = |key: &str| -> Option<String> {
                dict.get(key).and_then(|v| v.as_string()).map(|s| s.to_string())
            };

            let profile_identifier =
                get_str("ProfileIdentifier").unwrap_or_else(|| "unknown".to_string());
            let profile_display_name =
                get_str("ProfileDisplayName").unwrap_or_else(|| profile_identifier.clone());

            // Parse payload items
            let payloads = dict
                .get("ProfileItems")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| {
                            let d = item.as_dictionary()?;
                            let payload_identifier = d
                                .get("PayloadIdentifier")
                                .and_then(|v| v.as_string())
                                .unwrap_or("unknown")
                                .to_string();
                            let payload_type = d
                                .get("PayloadType")
                                .and_then(|v| v.as_string())
                                .unwrap_or("unknown")
                                .to_string();
                            Some(MacosMdmPayload {
                                payload_identifier,
                                payload_display_name: d
                                    .get("PayloadDisplayName")
                                    .and_then(|v| v.as_string())
                                    .map(|s| s.to_string()),
                                payload_type,
                                payload_uuid: d
                                    .get("PayloadUUID")
                                    .and_then(|v| v.as_string())
                                    .map(|s| s.to_string()),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let verification_state = get_str("ProfileVerificationState");

            // Try to extract install date as string
            let install_date = dict
                .get("ProfileInstallDate")
                .and_then(|v| {
                    // plist dates come through as Date type; try to_string
                    v.as_date().map(|d| format!("{:?}", d))
                })
                .or_else(|| get_str("ProfileInstallDate"));

            profiles.push(MacosMdmProfile {
                profile_identifier,
                profile_display_name,
                profile_organization: get_str("ProfileOrganization"),
                profile_type: get_str("ProfileType"),
                profile_uuid: get_str("ProfileUUID"),
                install_date,
                payloads,
                is_managed: is_managed_section,
                verification_state,
            });
        }
    }

    profiles
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn list_profiles_impl() -> Result<MacosProfilesResult, String> {
    use std::process::Command;

    log::info!("Listing macOS MDM profiles");

    // --- Collect profiles via plist output ---
    let profiles = {
        let output = Command::new("profiles")
            .args(["show", "-all", "-output", "stdout-xml"])
            .output();

        match output {
            Ok(out) if out.status.success() => parse_profiles_plist(&out.stdout),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!(
                    "profiles show exited with status {}: {}",
                    out.status,
                    stderr
                );
                // Fall back to `profiles list` text output
                let list_out = Command::new("profiles")
                    .args(["list", "-output", "stdout-xml"])
                    .output();
                match list_out {
                    Ok(lo) if lo.status.success() => parse_profiles_plist(&lo.stdout),
                    _ => Vec::new(),
                }
            }
            Err(e) => {
                log::warn!("Failed to run profiles command: {}", e);
                Vec::new()
            }
        }
    };

    // --- Collect raw text output for display ---
    let raw_output = Command::new("profiles")
        .args(["list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // --- Enrollment status ---
    let enrollment_status = {
        let output = Command::new("profiles")
            .args(["status", "-type", "enrollment"])
            .output();
        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                parse_enrollment_status(&stdout)
            }
            Err(e) => {
                log::warn!("Failed to run profiles status: {}", e);
                MacosEnrollmentStatus {
                    enrolled: false,
                    mdm_server: None,
                    enrollment_type: None,
                    raw_output: format!("Error: {}", e),
                }
            }
        }
    };

    Ok(MacosProfilesResult {
        profiles,
        enrollment_status,
        raw_output,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn list_profiles_impl() -> Result<MacosProfilesResult, String> {
    Err("macOS Diagnostics is only available on macOS.".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_enrollment_enrolled_dep() {
        let input = "Enrolled via DEP: Yes\nMDM server: https://manage.microsoft.com/abc\n";
        let status = parse_enrollment_status(input);
        assert!(status.enrolled);
        assert_eq!(status.mdm_server.as_deref(), Some("https://manage.microsoft.com/abc"));
        assert_eq!(status.enrollment_type.as_deref(), Some("DEP"));
    }

    #[test]
    fn test_parse_enrollment_not_enrolled() {
        let input = "Enrolled via DEP: No\n";
        let status = parse_enrollment_status(input);
        assert!(!status.enrolled);
        assert!(status.mdm_server.is_none());
    }

    #[test]
    fn test_parse_enrollment_empty() {
        let status = parse_enrollment_status("");
        assert!(!status.enrolled);
        assert!(status.mdm_server.is_none());
        assert!(status.enrollment_type.is_none());
    }

    #[test]
    fn test_parse_enrollment_mdm_server_only() {
        let input = "MDM server: https://example.com/mdm\n";
        let status = parse_enrollment_status(input);
        assert!(status.enrolled);
        assert_eq!(status.mdm_server.as_deref(), Some("https://example.com/mdm"));
    }

    #[test]
    fn test_parse_profiles_plist_empty() {
        let profiles = parse_profiles_plist(b"not valid plist data");
        assert!(profiles.is_empty());
    }
}
