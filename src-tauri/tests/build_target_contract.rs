#[path = "../build_target.rs"]
mod build_target;

use build_target::uses_msvc_manifest_linker;

#[test]
fn manual_manifest_linker_arguments_are_msvc_only() {
    assert!(uses_msvc_manifest_linker(Some("windows"), Some("msvc")));
    assert!(!uses_msvc_manifest_linker(Some("windows"), Some("gnu")));
    assert!(!uses_msvc_manifest_linker(Some("linux"), Some("gnu")));
    assert!(!uses_msvc_manifest_linker(Some("windows"), None));
}
