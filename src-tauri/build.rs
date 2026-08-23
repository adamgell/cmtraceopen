use std::path::Path;

mod build_target;

use build_target::uses_msvc_manifest_linker;

fn main() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").ok();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").ok();
    let windows = if uses_msvc_manifest_linker(target_os.as_deref(), target_env.as_deref()) {
        // tauri-build's resource compiler emits a bins-only link argument. The
        // app's unit and integration test executables need the same manifest.
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg=/MANIFESTINPUT:{}",
            manifest_path.display()
        );
        tauri_build::WindowsAttributes::new_without_app_manifest()
    } else {
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows-app-manifest.xml"))
    };
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("failed to run Tauri build script");
}
