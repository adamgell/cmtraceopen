//! Development-only HTTP IPC bridge.
//!
//! Starts a minimal HTTP server on `127.0.0.1:1422` so a Playwright browser
//! loaded against the Vite dev server at `:1420` can make real Rust IPC calls
//! instead of relying on the fake shim defaults.
//!
//! Protocol: `POST /invoke` with `Content-Type: application/json`
//! Body:     `{"cmd": "open_log_file", "args": {"path": "/abs/path.log"}}`
//! Response: `{"result": <value>}` or `{"error": "<message>"}`
//!
//! CORS headers allow all origins so the browser at `:1420` can reach `:1422`.
//! The bridge only starts when compiled in debug mode (`debug_assertions`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::parser::ResolvedParser;

/// Lightweight state for open-file tracking in bridge sessions.
struct BridgeState {
    open_files: Mutex<HashMap<PathBuf, (ResolvedParser, u64)>>,
}

/// Start the IPC bridge server. Runs forever; spawn with `tokio::spawn`.
pub async fn start(port: u16) {
    let state = Arc::new(BridgeState {
        open_files: Mutex::new(HashMap::new()),
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
    let mut buf = vec![0u8; 65536];
    let n = match socket.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let raw = String::from_utf8_lossy(&buf[..n]);
    let first_line = raw.lines().next().unwrap_or("");
    let method = first_line.split_whitespace().next().unwrap_or("");

    let (status_line, body, content_type) = match method {
        "OPTIONS" => ("204 No Content", String::new(), ""),
        "GET" => ("200 OK", r#"{"ok":true}"#.to_string(), "application/json"),
        "POST" => {
            let body_str = raw.find("\r\n\r\n")
                .map(|i| raw[i + 4..].trim_end_matches('\0'))
                .unwrap_or("");
            let result = dispatch(body_str, &state);
            ("200 OK", result, "application/json")
        }
        _ => ("405 Method Not Allowed", String::new(), ""),
    };

    let cors = "Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type\r\n";

    let response = if content_type.is_empty() {
        format!(
            "HTTP/1.1 {status_line}\r\n{cors}Content-Length: 0\r\n\r\n"
        )
    } else {
        format!(
            "HTTP/1.1 {status_line}\r\n{cors}Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };

    let _ = socket.write_all(response.as_bytes()).await;
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

        #[cfg(feature = "esp-diagnostics")]
        "get_esp_diagnostics_capability" => {
            ok_json(&crate::esp::acquisition_capability())
        }

        #[cfg(feature = "esp-diagnostics")]
        "graph_fetch_esp_diagnostics" | "graph_cancel_esp_diagnostics" => {
            err_json("ESP Graph commands are unavailable through the debug IPC bridge")
        }

        #[cfg(feature = "esp-diagnostics")]
        "analyze_esp_evidence"
        | "start_esp_diagnostics_session"
        | "get_esp_diagnostics_session"
        | "stop_esp_diagnostics_session"
        | "restart_esp_as_administrator" => err_json(
            "ESP native commands require the Tauri runtime and are unavailable through the debug IPC bridge",
        ),

        "get_file_association_prompt_status" => {
            // Match the real command's response shape so the frontend can
            // safely read `isAssociated` etc. in dev/browser mode.
            ok_json(&serde_json::json!({
                "supported": false,
                "shouldPrompt": false,
                "isAssociated": false,
            }))
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

#[cfg(all(test, feature = "esp-diagnostics"))]
mod tests {
    use super::{dispatch, BridgeState};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn state() -> Arc<BridgeState> {
        Arc::new(BridgeState {
            open_files: Mutex::new(HashMap::new()),
        })
    }

    #[test]
    fn debug_bridge_explicitly_rejects_esp_graph_commands() {
        for command in [
            "graph_fetch_esp_diagnostics",
            "graph_cancel_esp_diagnostics",
        ] {
            let response = dispatch(
                &serde_json::json!({ "cmd": command, "args": {} }).to_string(),
                &state(),
            );
            let value: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert_eq!(
                value["error"],
                "ESP Graph commands are unavailable through the debug IPC bridge"
            );
        }
    }
}
