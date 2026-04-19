fn main() {
    // tauri_build::build() configures Tauri-specific linker flags and env vars.
    // It must not run when this crate is being compiled as a dependency by the
    // cmtrace-wasm WASM target — in that context the Tauri config is irrelevant.
    let target = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target != "wasm32" {
        tauri_build::build()
    }
}

