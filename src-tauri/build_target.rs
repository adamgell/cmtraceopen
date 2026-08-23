pub(crate) fn uses_msvc_manifest_linker(target_os: Option<&str>, target_env: Option<&str>) -> bool {
    target_os == Some("windows") && target_env == Some("msvc")
}
