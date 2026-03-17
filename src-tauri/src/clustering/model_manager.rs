use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MODEL_DIR_NAME: &str = "all-MiniLM-L6-v2";
const MODEL_FILENAME: &str = "model.onnx";
const TOKENIZER_FILENAME: &str = "tokenizer.json";

const MODEL_URL: &str =
    "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx";
const TOKENIZER_URL: &str =
    "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json";

/// Returns the base directory for storing ML models.
fn models_base_dir() -> Result<PathBuf, String> {
    // Use platform-appropriate data directory
    let base = if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .ok()
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
            .ok()
    } else {
        // Linux/other: XDG_DATA_HOME or ~/.local/share
        std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .ok()
            .or_else(|| {
                std::env::var("HOME")
                    .map(|h| PathBuf::from(h).join(".local").join("share"))
                    .ok()
            })
    };

    let base = base.ok_or_else(|| "Could not determine app data directory".to_string())?;
    Ok(base.join("cmtrace-open").join("models"))
}

/// Returns the path to the model directory, creating it if needed.
pub fn model_dir() -> Result<PathBuf, String> {
    let dir = models_base_dir()?.join(MODEL_DIR_NAME);
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create model directory: {}", e))?;
    Ok(dir)
}

/// Returns the path to the ONNX model file.
pub fn model_path() -> Result<PathBuf, String> {
    Ok(model_dir()?.join(MODEL_FILENAME))
}

/// Returns the path to the tokenizer file.
pub fn tokenizer_path() -> Result<PathBuf, String> {
    Ok(model_dir()?.join(TOKENIZER_FILENAME))
}

/// Checks if the model files are already downloaded.
pub fn is_model_available() -> bool {
    model_path()
        .and_then(|p| tokenizer_path().map(|t| (p, t)))
        .map(|(m, t)| m.exists() && t.exists())
        .unwrap_or(false)
}

/// Downloads a file from a URL to the given path, reporting progress via callback.
fn download_file<F>(url: &str, dest: &Path, progress_fn: &F) -> Result<(), String>
where
    F: Fn(&str, f32),
{
    let filename = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");

    progress_fn(
        &format!("Downloading {}...", filename),
        0.0,
    );

    let response = ureq::get(url)
        .call()
        .map_err(|e| format!("Failed to download {}: {}", filename, e))?;

    let content_length = response
        .header("Content-Length")
        .and_then(|s| s.parse::<u64>().ok());

    let mut reader = response.into_reader();
    let tmp_path = dest.with_extension("tmp");
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| format!("Failed to create file {}: {}", tmp_path.display(), e))?;

    let mut buf = [0u8; 65536];
    let mut downloaded: u64 = 0;

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Download read error: {}", e))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .map_err(|e| format!("Write error: {}", e))?;
        downloaded += n as u64;

        if let Some(total) = content_length {
            let pct = (downloaded as f32 / total as f32) * 100.0;
            progress_fn(
                &format!("Downloading {} ({:.1} MB / {:.1} MB)", filename, downloaded as f32 / 1e6, total as f32 / 1e6),
                pct,
            );
        }
    }

    file.flush()
        .map_err(|e| format!("Flush error: {}", e))?;
    drop(file);

    fs::rename(&tmp_path, dest)
        .map_err(|e| format!("Failed to finalize download: {}", e))?;

    progress_fn(&format!("Downloaded {}", filename), 100.0);
    Ok(())
}

/// Ensures the model and tokenizer files are available, downloading if needed.
pub fn ensure_model<F>(progress_fn: F) -> Result<(PathBuf, PathBuf), String>
where
    F: Fn(&str, f32),
{
    let model = model_path()?;
    let tokenizer = tokenizer_path()?;

    if !model.exists() {
        download_file(MODEL_URL, &model, &progress_fn)?;
    }

    if !tokenizer.exists() {
        download_file(TOKENIZER_URL, &tokenizer, &progress_fn)?;
    }

    Ok((model, tokenizer))
}
