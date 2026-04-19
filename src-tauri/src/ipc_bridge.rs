//! Development-only HTTP IPC bridge.
//!
//! Starts a minimal HTTP server on `127.0.0.1:1422` so a Playwright browser
//! loaded against the Vite dev server at `:1420` can make real Rust IPC calls
//! instead of relying on the fake shim defaults.
//!
//! Endpoints:
//!   GET  /           → `{"ok":true}` health probe
//!   POST /invoke     → `{"cmd":"…","args":{…}}` → `{"result":…}` or `{"error":"…"}`
//!   POST /upload     → multipart/form-data with `files` field
//!                      Writes each file to a temp dir; returns `{"paths":["…"]}`
//!
//! CORS headers allow all origins so the browser at `:1420` can reach `:1422`.
//! The bridge only starts when compiled in debug mode (`debug_assertions`).

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::parser::ResolvedParser;

/// Lightweight state for open-file tracking in bridge sessions.
struct BridgeState {
    open_files: Mutex<HashMap<PathBuf, (ResolvedParser, u64)>>,
    /// Temp dir that persists for the lifetime of the bridge.
    temp_dir: tempfile::TempDir,
}

/// Start the IPC bridge server. Runs forever; spawn with `tokio::spawn`.
pub async fn start(port: u16) {
    let temp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("ipc_bridge: failed to create temp dir — {e}");
            return;
        }
    };

    let state = Arc::new(BridgeState {
        open_files: Mutex::new(HashMap::new()),
        temp_dir,
    });

    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")).await {
        Ok(l) => {
            log::info!("ipc_bridge: listening on 127.0.0.1:{port}");
            l
        }
        Err(e) => {
            log::warn!("ipc_bridge: failed to bind 127.0.0.1:{port} — {e}");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((socket, _addr)) => {
                let state = Arc::clone(&state);
                tokio::spawn(handle_connection(socket, state));
            }
            Err(e) => log::error!("ipc_bridge: accept error — {e}"),
        }
    }
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(mut socket: TcpStream, state: Arc<BridgeState>) {
    // Read until we have the full HTTP request. For large uploads we keep
    // reading until we've consumed Content-Length bytes beyond the header.
    let mut buf = Vec::with_capacity(65536);
    let mut tmp = [0u8; 8192];

    // Read headers first (stop at \r\n\r\n)
    let headers_end;
    loop {
        match socket.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_header_end(&buf) {
                    headers_end = pos;
                    break;
                }
                if buf.len() > 1024 * 1024 { return; } // safety limit
            }
        }
    }

    // Parse request line and headers — copy owned strings so we release the buf borrow
    // before mutating buf to read the body.
    let (method, path, content_length, content_type_header) = {
        let header_str = String::from_utf8_lossy(&buf[..headers_end]);
        let mut lines = header_str.lines();
        let first_line = lines.next().unwrap_or("").to_string();
        let mut parts = first_line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_ascii_uppercase();
        let path = parts.next().unwrap_or("/").to_string();

        let mut content_length: usize = 0;
        let mut content_type_header = String::new();
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                content_length = line[15..].trim().parse().unwrap_or(0);
            }
            if lower.starts_with("content-type:") {
                content_type_header = line[13..].trim().to_string();
            }
        }
        (method, path, content_length, content_type_header)
    };

    // Read remaining body bytes
    let already_have = buf.len() - headers_end - 4; // bytes after \r\n\r\n already in buf
    let body_start = headers_end + 4;
    if content_length > already_have {
        let remaining = content_length - already_have;
        let needed = buf.len() + remaining;
        buf.resize(needed, 0);
        let fill_start = needed - remaining;
        let _ = socket.read_exact(&mut buf[fill_start..]).await;
    }
    let body_end = (body_start + content_length).min(buf.len());
    let body = &buf[body_start..body_end];

    let cors = "Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type\r\n";

    let (status, response_body, resp_content_type) = match method.as_str() {
        "OPTIONS" => ("204 No Content", String::new(), ""),
        "GET"     => ("200 OK", r#"{"ok":true}"#.to_string(), "application/json"),
        "POST"    => {
            let result = match path.as_str() {
                "/invoke" => {
                    let body_str = std::str::from_utf8(body).unwrap_or("");
                    dispatch(body_str, &state)
                }
                "/upload" => handle_upload(body, &content_type_header, &state),
                _ => r#"{"error":"unknown endpoint"}"#.to_string(),
            };
            ("200 OK", result, "application/json")
        }
        _ => ("405 Method Not Allowed", String::new(), ""),
    };

    let response = if resp_content_type.is_empty() {
        format!("HTTP/1.1 {status}\r\n{cors}Content-Length: 0\r\n\r\n")
    } else {
        format!(
            "HTTP/1.1 {status}\r\n{cors}Content-Type: {resp_content_type}\r\nContent-Length: {}\r\n\r\n{response_body}",
            response_body.len()
        )
    };

    let _ = socket.write_all(response.as_bytes()).await;
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

// ── File upload ───────────────────────────────────────────────────────────────

fn handle_upload(body: &[u8], content_type: &str, state: &Arc<BridgeState>) -> String {
    // Extract boundary from Content-Type: multipart/form-data; boundary=----XYZ
    let boundary = match content_type
        .split(';')
        .find_map(|p| {
            let t = p.trim();
            t.strip_prefix("boundary=").map(|b| b.trim_matches('"').to_string())
        })
    {
        Some(b) => b,
        None => return err_json("missing multipart boundary"),
    };

    let delimiter = format!("--{boundary}");
    let body_str = String::from_utf8_lossy(body);

    let mut paths: Vec<String> = Vec::new();

    for part in body_str.split(&delimiter) {
        if part.starts_with("--") || part.trim().is_empty() { continue; }

        // Find the blank line separating headers from content
        let sep = match part.find("\r\n\r\n") {
            Some(i) => i,
            None => continue,
        };
        let part_headers = &part[..sep];
        let part_body = &part[sep + 4..];
        // Strip final \r\n before next boundary
        let part_content = part_body.trim_end_matches("\r\n");

        // Extract filename from Content-Disposition header
        let filename = part_headers.lines()
            .find(|l| l.to_ascii_lowercase().contains("content-disposition"))
            .and_then(|l| {
                l.split(';').find_map(|p| {
                    let t = p.trim();
                    t.strip_prefix("filename=")
                        .or_else(|| t.strip_prefix("filename*=UTF-8''"))
                        .map(|f| f.trim_matches('"').to_string())
                })
            });

        let filename = match filename {
            Some(f) if !f.is_empty() => f,
            _ => continue,
        };

        // Write to temp dir
        let dest = state.temp_dir.path().join(&filename);
        match std::fs::File::create(&dest) {
            Ok(mut f) => {
                if f.write_all(part_content.as_bytes()).is_ok() {
                    paths.push(dest.to_string_lossy().into_owned());
                }
            }
            Err(e) => log::warn!("ipc_bridge: upload write failed for {filename}: {e}"),
        }
    }

    if paths.is_empty() {
        return err_json("no files received");
    }

    log::info!("ipc_bridge: uploaded {} file(s) to temp dir", paths.len());
    serde_json::json!({ "paths": paths }).to_string()
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IpcRequest {
    cmd: String,
    #[serde(default)]
    args: serde_json::Value,
}

fn dispatch(body: &str, state: &Arc<BridgeState>) -> String {
    let req: IpcRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return err_json(&format!("request parse error: {e}")),
    };

    log::debug!("ipc_bridge: cmd={}", req.cmd);

    match req.cmd.as_str() {
        // ── File parsing ────────────────────────────────────────────────────
        "open_log_file" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return err_json("missing `path` argument"),
            };
            match crate::parser::parse_file(&path) {
                Ok((result, parser_selection)) => {
                    state.open_files.lock().unwrap().insert(
                        PathBuf::from(&path),
                        (parser_selection, result.byte_offset),
                    );
                    ok_json(&result)
                }
                Err(e) => err_json(&e),
            }
        }

        "parse_files_batch" => {
            let paths: Vec<String> = match req.args.get("paths")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(p) => p,
                None => return err_json("missing `paths` argument"),
            };

            let mut results = Vec::with_capacity(paths.len());
            let mut open_files = state.open_files.lock().unwrap();

            for path in &paths {
                match crate::parser::parse_file(path) {
                    Ok((result, parser_selection)) => {
                        open_files.insert(
                            PathBuf::from(path),
                            (parser_selection, result.byte_offset),
                        );
                        results.push(serde_json::to_value(&result).unwrap_or(serde_json::Value::Null));
                    }
                    Err(e) => return err_json(&e),
                }
            }
            ok_json(&results)
        }

        // ── App config (trivial) ────────────────────────────────────────────
        "get_app_version" => {
            ok_json(&env!("CARGO_PKG_VERSION"))
        }

        "get_available_workspaces" => {
            ok_json(&crate::commands::app_config::get_available_workspaces())
        }

        "get_file_association_prompt_status" => {
            ok_json(&"dismissed")
        }

        "get_initial_file_paths" => {
            ok_json(&Vec::<String>::new())
        }

        "get_known_log_sources" => {
            ok_json(&Vec::<String>::new())
        }

        // ── Filesystem helpers ──────────────────────────────────────────────
        "list_log_folder" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return err_json("missing `path` argument"),
            };
            match crate::commands::file_ops::list_log_folder(path) {
                Ok(result) => ok_json(&result),
                Err(e) => err_json(&e.to_string()),
            }
        }

        "inspect_path_kind" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return err_json("missing `path` argument"),
            };
            match crate::commands::file_ops::inspect_path_kind(path) {
                Ok(result) => ok_json(&result),
                Err(e) => err_json(&e.to_string()),
            }
        }

        // ── Error lookup ────────────────────────────────────────────────────
        "lookup_error_code" => {
            let code = match req.args.get("code").and_then(|v| v.as_str()) {
                Some(c) => c.to_string(),
                None => return err_json("missing `code` argument"),
            };
            let result = crate::commands::error_lookup::lookup_error_code(code);
            ok_json(&result)
        }

        "search_error_codes" => {
            let query = match req.args.get("query").and_then(|v| v.as_str()) {
                Some(q) => q.to_string(),
                None => return err_json("missing `query` argument"),
            };
            let result = crate::commands::error_lookup::search_error_codes(query);
            ok_json(&result)
        }

        // ── Unknown / not bridged ───────────────────────────────────────────
        _ => {
            log::debug!("ipc_bridge: unknown cmd={} — returning null", req.cmd);
            r#"{"result":null}"#.to_string()
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ok_json<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_string(&serde_json::json!({ "result": value })) {
        Ok(s) => s,
        Err(e) => err_json(&format!("serialization error: {e}")),
    }
}

fn err_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}
