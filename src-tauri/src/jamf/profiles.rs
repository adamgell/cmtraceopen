use crate::error::AppError;
use crate::jamf::models::JamfProfilesResult;
use crate::macos_diag::models::MacosMdmProfile;

const JAMF_PAYLOAD_TYPE_PREFIXES: &[&str] = &["com.jamfsoftware.", "com.jamf."];

pub fn filter_jamf_profiles_impl(
    all_profiles: Vec<MacosMdmProfile>,
    expected_org: Option<&str>,
) -> Result<JamfProfilesResult, AppError> {
    let matched: Vec<MacosMdmProfile> = all_profiles
        .into_iter()
        .filter(|p| matches_jamf(p, expected_org))
        .collect();

    Ok(JamfProfilesResult {
        matched_organization: expected_org.map(str::to_string),
        profiles: matched,
    })
}

fn matches_jamf(profile: &MacosMdmProfile, expected_org: Option<&str>) -> bool {
    if let Some(org) = expected_org {
        if let Some(profile_org) = profile.profile_organization.as_deref() {
            if profile_org.eq_ignore_ascii_case(org) {
                return true;
            }
        }
    }
    profile.payloads.iter().any(|p| {
        JAMF_PAYLOAD_TYPE_PREFIXES
            .iter()
            .any(|prefix| p.payload_type.starts_with(prefix))
    })
}
