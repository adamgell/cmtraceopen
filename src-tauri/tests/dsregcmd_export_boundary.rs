//! End-to-end guard for the dsregcmd IPC boundary (issue #556).
//!
//! The workspace copies what `analyze_dsregcmd` returns, so the command's
//! return value is the last place the guarantee can be observed before the
//! value reaches a clipboard. This test calls the command the way the frontend
//! does and asserts no planted identifier survives into the JSON it gets.
//!
//! The capture bundle's own disk writes are Windows-only, so they are not
//! exercised here; what they may contain is decided by the projection the
//! parser crate applies, which
//! `cmtraceopen-parser/tests/dsregcmd_export_boundary.rs` covers.

#![cfg(feature = "dsregcmd")]

use app_lib::commands::dsregcmd::analyze_dsregcmd;

// Synthetic values. Nothing here belongs to a real tenant, device or user.
const UPN: &str = "adele.vance@contoso.onmicrosoft.com";
const USER_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const TENANT_ID: &str = "8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90";
const TENANT_DOMAIN: &str = "contoso.onmicrosoft.com";
const ON_PREM_DOMAIN: &str = "corp.contoso.com";
const DEVICE_ID: &str = "4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b";
const THUMBPRINT: &str = "8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D";

const PLANTED_IDENTIFIERS: &[(&str, &str)] = &[
    ("user principal name", UPN),
    ("user SID", USER_SID),
    ("tenant id", TENANT_ID),
    ("tenant domain", TENANT_DOMAIN),
    ("on-premises domain", ON_PREM_DOMAIN),
    ("device id", DEVICE_ID),
    ("certificate thumbprint", THUMBPRINT),
];

const STATUS_CAPTURE: &str = r#"
 AzureAdJoined : YES
 DomainJoined : YES
 TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 TenantName : contoso.onmicrosoft.com
 DomainName : corp.contoso.com
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 Thumbprint : 8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D
 AzureAdPrt : YES
 AzureAdPrtAuthority : https://login.microsoftonline.com/8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90/
 User Identity : S-1-5-21-1111111111-2222222222-3333333333-1001
 DeviceAuthStatus : SUCCESS
 Server Message : AADSTS50126 Invalid username or password for adele.vance@contoso.onmicrosoft.com
"#;

fn ipc_json() -> String {
    let analysis = analyze_dsregcmd(STATUS_CAPTURE.to_string(), None)
        .expect("the dsregcmd capture analyzes as JSON");
    serde_json::to_string(&analysis).expect("a dsregcmd analysis serializes")
}

#[test]
fn the_ipc_analysis_carries_no_planted_identity() {
    let published = ipc_json();

    for (label, marker) in PLANTED_IDENTIFIERS {
        assert!(
            !published.contains(marker),
            "the analyzed value the workspace receives leaks the {label} ({marker})"
        );
    }
}

#[test]
fn the_ipc_analysis_still_carries_the_diagnosis() {
    let published = ipc_json();

    assert!(
        published.contains("AADSTS50126"),
        "over-masking: the diagnostic error code was lost from the IPC value"
    );
}
