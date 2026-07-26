use super::models::{MacosEnrollmentStatus, MacosProfilesResult};
#[cfg(any(target_os = "macos", test))]
use super::models::{MacosMdmPayload, MacosMdmProfile};

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

#[cfg(any(target_os = "macos", test))]
/// Extracts the ISO date portion from a system_profiler install date string.
///
/// system_profiler formats dates like:
/// `"Sunday, January 11, 2026 at 8:40:06 PM (2026-01-12 01:40:06 +0000)"`
///
/// This function extracts the parenthesized ISO portion: `"2026-01-12 01:40:06 +0000"`.
/// If no parenthesized segment is found, returns the original string as-is.
fn extract_iso_date(raw: &str) -> String {
    if let Some(start) = raw.find('(') {
        if let Some(end) = raw[start..].find(')') {
            return raw[start + 1..start + end].trim().to_string();
        }
    }
    raw.trim().to_string()
}

#[cfg(any(target_os = "macos", test))]
/// Parses the plist XML output of
/// `system_profiler SPConfigurationProfileDataType -xml`
/// into a list of MDM profiles.
///
/// The plist structure is:
///   root array → first dict → `_items` array → first dict (section) →
///   `_items` array of profile dicts.  Each profile dict may contain a nested
///   `_items` array of payload dicts.
fn parse_system_profiler_plist(data: &[u8]) -> Vec<MacosMdmProfile> {
    let root: plist::Value = match plist::from_bytes(data) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse system_profiler plist: {}", e);
            return Vec::new();
        }
    };

    // root array → first dict
    let root_arr = match root.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let top_dict = match root_arr.first().and_then(|v| v.as_dictionary()) {
        Some(d) => d,
        None => return Vec::new(),
    };

    // top dict → _items array → first dict (section)
    let section_items = match top_dict.get("_items").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    let section_dict = match section_items.first().and_then(|v| v.as_dictionary()) {
        Some(d) => d,
        None => return Vec::new(),
    };

    // section dict → _items array of profile dicts
    let profile_items = match section_dict.get("_items").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut profiles = Vec::new();

    for profile_val in profile_items {
        let dict = match profile_val.as_dictionary() {
            Some(d) => d,
            None => continue,
        };

        let get_str = |key: &str| -> Option<String> {
            dict.get(key)
                .and_then(|v| v.as_string())
                .map(|s| s.to_string())
        };

        let profile_identifier =
            get_str("spconfigprofile_profile_identifier").unwrap_or_else(|| "unknown".to_string());
        let profile_display_name = get_str("_name").unwrap_or_else(|| profile_identifier.clone());

        let install_date = get_str("spconfigprofile_install_date").map(|s| extract_iso_date(&s));

        let verification_state = get_str("spconfigprofile_verification_state");
        let description = get_str("spconfigprofile_description");
        let source = get_str("spconfigprofile_install_source");
        let removal_disallowed =
            get_str("spconfigprofile_RemovalDisallowed").map(|s| s.eq_ignore_ascii_case("yes"));

        // Parse payload items from nested _items
        let payloads = dict
            .get("_items")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let d = item.as_dictionary()?;
                        let get_payload_str = |key: &str| -> Option<String> {
                            d.get(key)
                                .and_then(|v| v.as_string())
                                .map(|s| s.to_string())
                        };
                        let payload_type =
                            get_payload_str("_name").unwrap_or_else(|| "unknown".to_string());
                        let payload_identifier =
                            get_payload_str("spconfigprofile_payload_identifier")
                                .unwrap_or_else(|| "unknown".to_string());
                        let payload_version = d
                            .get("spconfigprofile_payload_version")
                            .and_then(|v| v.as_string())
                            .and_then(|s| s.parse::<u32>().ok());
                        Some(MacosMdmPayload {
                            payload_identifier,
                            payload_display_name: get_payload_str(
                                "spconfigprofile_payload_display_name",
                            ),
                            payload_type,
                            payload_uuid: get_payload_str("spconfigprofile_payload_uuid"),
                            payload_data: get_payload_str("spconfigprofile_payload_data"),
                            payload_description: get_payload_str("spconfigprofile_description"),
                            payload_version,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        profiles.push(MacosMdmProfile {
            profile_identifier,
            profile_display_name,
            profile_organization: get_str("spconfigprofile_organization"),
            profile_type: None,
            profile_uuid: get_str("spconfigprofile_profile_uuid"),
            install_date,
            payloads,
            is_managed: true,
            verification_state,
            description,
            source,
            removal_disallowed,
        });
    }

    profiles
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn list_profiles_impl() -> Result<MacosProfilesResult, crate::error::AppError> {
    use std::process::Command;

    log::info!("Listing macOS MDM profiles via system_profiler");

    // --- Collect profiles via system_profiler XML plist output ---
    let profiles = {
        let output = Command::new("system_profiler")
            .args(["SPConfigurationProfileDataType", "-xml"])
            .output();

        match output {
            Ok(out) if out.status.success() => parse_system_profiler_plist(&out.stdout),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!(
                    "system_profiler exited with status {}: {}",
                    out.status,
                    stderr
                );
                Vec::new()
            }
            Err(e) => {
                log::warn!("Failed to run system_profiler: {}", e);
                Vec::new()
            }
        }
    };

    // --- Collect raw text output for display ---
    let raw_output = Command::new("system_profiler")
        .args(["SPConfigurationProfileDataType"])
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
pub fn list_profiles_impl() -> Result<MacosProfilesResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "macOS Diagnostics is only available on macOS.".to_string(),
    ))
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
        assert_eq!(
            status.mdm_server.as_deref(),
            Some("https://manage.microsoft.com/abc")
        );
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
        assert_eq!(
            status.mdm_server.as_deref(),
            Some("https://example.com/mdm")
        );
    }

    #[test]
    fn test_parse_system_profiler_plist() {
        // Realistic system_profiler SPConfigurationProfileDataType -xml fixture
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>_items</key>
    <array>
      <dict>
        <key>_name</key>
        <string>Configuration Profiles</string>
        <key>_items</key>
        <array>
          <dict>
            <key>_name</key>
            <string>MDM Profile</string>
            <key>spconfigprofile_profile_identifier</key>
            <string>com.microsoft.wdav</string>
            <key>spconfigprofile_organization</key>
            <string>Contoso</string>
            <key>spconfigprofile_description</key>
            <string>MDM managed profile</string>
            <key>spconfigprofile_profile_uuid</key>
            <string>AAAA-BBBB-CCCC</string>
            <key>spconfigprofile_install_date</key>
            <string>Sunday, January 11, 2026 at 8:40:06 PM (2026-01-12 01:40:06 +0000)</string>
            <key>spconfigprofile_verification_state</key>
            <string>verified</string>
            <key>spconfigprofile_install_source</key>
            <string>MDM</string>
            <key>spconfigprofile_RemovalDisallowed</key>
            <string>yes</string>
            <key>_items</key>
            <array>
              <dict>
                <key>_name</key>
                <string>com.apple.ManagedClient.preferences</string>
                <key>spconfigprofile_payload_identifier</key>
                <string>com.microsoft.wdav.atp</string>
                <key>spconfigprofile_payload_display_name</key>
                <string>WDAV Config</string>
                <key>spconfigprofile_payload_uuid</key>
                <string>1111-2222-3333</string>
                <key>spconfigprofile_payload_data</key>
                <string>antivirusEngine: passive mode</string>
                <key>spconfigprofile_description</key>
                <string>Defender configuration</string>
                <key>spconfigprofile_payload_version</key>
                <string>1</string>
              </dict>
            </array>
          </dict>
          <dict>
            <key>_name</key>
            <string>Wi-Fi Profile</string>
            <key>spconfigprofile_profile_identifier</key>
            <string>com.contoso.wifi</string>
            <key>spconfigprofile_organization</key>
            <string>Contoso IT</string>
            <key>spconfigprofile_profile_uuid</key>
            <string>DDDD-EEEE-FFFF</string>
            <key>spconfigprofile_install_date</key>
            <string>Monday, February 3, 2026 at 10:00:00 AM (2026-02-03 15:00:00 +0000)</string>
            <key>spconfigprofile_verification_state</key>
            <string>verified</string>
            <key>_items</key>
            <array>
              <dict>
                <key>_name</key>
                <string>com.apple.wifi.managed</string>
                <key>spconfigprofile_payload_identifier</key>
                <string>com.contoso.wifi.payload</string>
                <key>spconfigprofile_payload_display_name</key>
                <string>Corporate Wi-Fi</string>
                <key>spconfigprofile_payload_uuid</key>
                <string>4444-5555-6666</string>
              </dict>
              <dict>
                <key>_name</key>
                <string>com.apple.security.certificateroot</string>
                <key>spconfigprofile_payload_identifier</key>
                <string>com.contoso.cert</string>
                <key>spconfigprofile_payload_display_name</key>
                <string>Root CA</string>
                <key>spconfigprofile_payload_uuid</key>
                <string>7777-8888-9999</string>
                <key>spconfigprofile_payload_version</key>
                <string>2</string>
              </dict>
            </array>
          </dict>
        </array>
      </dict>
    </array>
  </dict>
</array>
</plist>"#;

        let profiles = parse_system_profiler_plist(xml.as_bytes());
        assert_eq!(profiles.len(), 2);

        // First profile — has payload_data on its payload
        let p0 = &profiles[0];
        assert_eq!(p0.profile_display_name, "MDM Profile");
        assert_eq!(p0.profile_identifier, "com.microsoft.wdav");
        assert_eq!(p0.profile_organization.as_deref(), Some("Contoso"));
        assert_eq!(p0.description.as_deref(), Some("MDM managed profile"));
        assert_eq!(p0.profile_uuid.as_deref(), Some("AAAA-BBBB-CCCC"));
        assert_eq!(
            p0.install_date.as_deref(),
            Some("2026-01-12 01:40:06 +0000")
        );
        assert_eq!(p0.verification_state.as_deref(), Some("verified"));
        assert_eq!(p0.source.as_deref(), Some("MDM"));
        assert_eq!(p0.removal_disallowed, Some(true));
        assert!(p0.is_managed);
        assert!(p0.profile_type.is_none());
        assert_eq!(p0.payloads.len(), 1);

        let pay0 = &p0.payloads[0];
        assert_eq!(pay0.payload_type, "com.apple.ManagedClient.preferences");
        assert_eq!(pay0.payload_identifier, "com.microsoft.wdav.atp");
        assert_eq!(pay0.payload_display_name.as_deref(), Some("WDAV Config"));
        assert_eq!(pay0.payload_uuid.as_deref(), Some("1111-2222-3333"));
        assert_eq!(
            pay0.payload_data.as_deref(),
            Some("antivirusEngine: passive mode")
        );
        assert_eq!(
            pay0.payload_description.as_deref(),
            Some("Defender configuration")
        );
        assert_eq!(pay0.payload_version, Some(1));

        // Second profile — 2 payloads, no payload_data
        let p1 = &profiles[1];
        assert_eq!(p1.profile_display_name, "Wi-Fi Profile");
        assert_eq!(p1.profile_identifier, "com.contoso.wifi");
        assert_eq!(p1.payloads.len(), 2);
        assert!(p1.description.is_none());
        assert!(p1.source.is_none());
        assert!(p1.removal_disallowed.is_none());

        let pay1a = &p1.payloads[0];
        assert_eq!(pay1a.payload_type, "com.apple.wifi.managed");
        assert!(pay1a.payload_data.is_none());
        assert!(pay1a.payload_description.is_none());
        assert!(pay1a.payload_version.is_none());

        let pay1b = &p1.payloads[1];
        assert_eq!(pay1b.payload_type, "com.apple.security.certificateroot");
        assert_eq!(pay1b.payload_version, Some(2));
    }

    #[test]
    fn test_parse_system_profiler_plist_invalid() {
        let profiles = parse_system_profiler_plist(b"not valid plist data");
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_parse_system_profiler_plist_empty_dict() {
        // Valid plist but with empty _items
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>_items</key>
    <array>
      <dict>
        <key>_name</key>
        <string>Configuration Profiles</string>
        <key>_items</key>
        <array/>
      </dict>
    </array>
  </dict>
</array>
</plist>"#;
        let profiles = parse_system_profiler_plist(xml.as_bytes());
        assert!(profiles.is_empty());
    }
}
