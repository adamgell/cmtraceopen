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

    serve(listener).await;
}

/// Accepts and serves connections until the listener fails. Split from `start`
/// so a test can drive the real handler on an OS-assigned port.
async fn serve(listener: TcpListener) {
    let state = Arc::new(BridgeState {
        open_files: Mutex::new(HashMap::new()),
    });

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

/// Largest request the development bridge accepts. The body is a small JSON
/// envelope, so anything larger is a client bug rather than traffic to buffer.
const MAX_REQUEST_BYTES: usize = 1 << 20;

/// Reads one request, waiting until the declared `Content-Length` body arrives.
///
/// A single `read` is not a request: TCP may deliver the head and the body in
/// separate segments, and parsing the first segment alone made the bridge answer
/// `request parse error: EOF while parsing a value` (or reset the connection)
/// for a perfectly well-formed call.
async fn read_request(socket: &mut TcpStream) -> Option<String> {
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];

    loop {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len() > MAX_REQUEST_BYTES {
            log::warn!("ipc_bridge: request exceeded {MAX_REQUEST_BYTES} bytes");
            return None;
        }

        if let Some(headers_end) = find_headers_end(&raw) {
            let expected = declared_content_length(&raw[..headers_end]);
            if raw.len() >= headers_end + 4 + expected {
                break;
            }
        }
    }

    Some(String::from_utf8_lossy(&raw).into_owned())
}

/// Byte offset of the header terminator, if the headers have arrived.
fn find_headers_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

/// `Content-Length` of the request head, or 0 when absent or unparsable.
fn declared_content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(mut socket: TcpStream, state: Arc<BridgeState>) {
    let raw = match read_request(&mut socket).await {
        Some(raw) => raw,
        None => return,
    };

    let headers_end = raw.find("\r\n\r\n");
    let head = match headers_end {
        Some(index) => &raw[..index],
        None => raw.as_str(),
    };
    let method = head
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("");

    let (status_line, body, content_type) = match method {
        "OPTIONS" => ("204 No Content", String::new(), ""),
        "GET" => ("200 OK", r#"{"ok":true}"#.to_string(), "application/json"),
        "POST" => {
            let body_str = headers_end
                .map(|index| raw[index + 4..].trim_end_matches('\0'))
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
        format!("HTTP/1.1 {status_line}\r\n{cors}Content-Length: 0\r\n\r\n")
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
        "get_esp_elevation_state" => {
            ok_json(&crate::esp::system::current_elevation_state())
        }

        #[cfg(feature = "esp-diagnostics")]
        "graph_fetch_esp_diagnostics" | "graph_cancel_esp_diagnostics" => {
            err_json("ESP Graph commands are unavailable through the debug IPC bridge")
        }

        "graph_authenticate"
        | "graph_reserve_interactive_operation"
        | "graph_cancel_authentication"
        | "graph_request_missing_permissions" => {
            err_json("Microsoft Graph sign-in is unavailable through the debug IPC bridge")
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
            // safely read `isRegistered` etc. in dev/browser mode.
            ok_json(&serde_json::json!({
                "supported": false,
                "shouldPrompt": false,
                "isRegistered": false,
            }))
        }

        "register_log_file_handler" | "open_windows_default_apps" => err_json(
            "Windows file association commands require the Tauri runtime and are unavailable through the debug IPC bridge",
        ),

        "get_initial_file_paths" => {
            ok_json(&Vec::<String>::new())
        }

        "get_initial_workspace" => {
            ok_json(&Option::<String>::None)
        }

        // ── Browser-session startup ─────────────────────────────────────────
        // These answer "nothing is pending", which is what the real backend
        // answers when no second launch, no elevation restore ticket and no
        // native menu exist. Leaving them unimplemented made the app log
        // console errors while booting against the bridge, and the smoke
        // suite's no-JS-errors assertion failed whenever `npm run app:dev` was
        // running alongside it.
        "take_second_launch_paths" => ok_json(&Vec::<String>::new()),

        "get_initial_elevation_restore" => ok_json(&serde_json::Value::Null),

        // A browser session has no native application menu to synchronize.
        "sync_app_menu_state" => ok_json(&serde_json::Value::Null),

        // The real command reads HKCU on Windows and returns the ISO defaults
        // elsewhere; the bridge runs on the development host, so it answers
        // exactly what that command answers here.
        "get_system_date_time_preferences" => {
            match crate::commands::system_preferences::get_system_date_time_preferences() {
                Ok(preferences) => ok_json(&preferences),
                Err(error) => err_json(&error.to_string()),
            }
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

        #[cfg(feature = "dsregcmd")]
        "redact_dsregcmd_status_text" => {
            let input = req.args.get("input").and_then(|v| v.as_str()).unwrap_or("");
            ok_json(&crate::commands::dsregcmd::redact_dsregcmd_status_text(
                input.to_string(),
            ))
        }

        // ── Unknown / not bridged ───────────────────────────────────────────
        _ => err_json(&format!(
            "debug IPC bridge does not implement command `{}`",
            req.cmd
        )),
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
    use super::{dispatch, serve, BridgeState};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn state() -> Arc<BridgeState> {
        Arc::new(BridgeState {
            open_files: Mutex::new(HashMap::new()),
        })
    }

    /// Serves one request through the real handler on an OS-assigned port.
    fn round_trip(request: &str, split_at: Option<usize>) -> String {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(serve(listener));

            let mut socket = TcpStream::connect(addr).await.expect("connect");
            match split_at {
                Some(index) => {
                    // Two writes with a pause: the first read can only see the
                    // first segment, which is exactly what a real client can do.
                    socket
                        .write_all(&request.as_bytes()[..index])
                        .await
                        .expect("write head");
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    socket
                        .write_all(&request.as_bytes()[index..])
                        .await
                        .expect("write tail");
                }
                None => socket.write_all(request.as_bytes()).await.expect("write"),
            }

            let mut response = Vec::new();
            socket.read_to_end(&mut response).await.expect("read");
            String::from_utf8_lossy(&response).into_owned()
        })
    }

    fn post(body: &str) -> String {
        format!(
            "POST /invoke HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn request_split_across_writes_is_served_in_full() {
        let body = serde_json::json!({ "cmd": "get_app_version", "args": {} }).to_string();
        let request = post(&body);
        // Split inside the body, past the header terminator.
        let split = request.len() - body.len() / 2;
        let response = round_trip(&request, Some(split));
        assert!(
            response.contains("\"result\""),
            "a request split across two writes must still be dispatched: {response}"
        );
    }

    #[test]
    fn whole_request_in_one_write_is_served() {
        let body = serde_json::json!({ "cmd": "get_app_version", "args": {} }).to_string();
        let response = round_trip(&post(&body), None);
        assert!(response.contains("\"result\""), "response was {response}");
    }

    #[test]
    fn bodyless_get_is_served() {
        let response = round_trip("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", None);
        assert!(
            response.contains(r#"{"ok":true}"#),
            "response was {response}"
        );
    }

    #[test]
    fn debug_bridge_answers_browser_session_startup_commands() {
        // Without these the app logs console errors while booting against the
        // bridge (no second launch, no restore ticket, no native menu), which
        // failed the smoke suite's no-JS-errors assertion whenever the app ran.
        for command in [
            "take_second_launch_paths",
            "get_initial_elevation_restore",
            "sync_app_menu_state",
            "get_system_date_time_preferences",
        ] {
            let response = dispatch(
                &serde_json::json!({ "cmd": command, "args": {} }).to_string(),
                &state(),
            );
            let value: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert!(
                value.get("error").is_none(),
                "{command} must answer without an error: {response}"
            );
            assert!(value.get("result").is_some(), "{command}: {response}");
        }
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

    #[test]
    fn debug_bridge_rejects_graph_permission_upgrade_with_or_without_caller_scopes() {
        for args in [
            serde_json::json!({}),
            serde_json::json!({
                "scopes": [
                    "DeviceManagementManagedDevices.ReadWrite.All",
                    "https://attacker.example/.default"
                ]
            }),
        ] {
            let response = dispatch(
                &serde_json::json!({
                    "cmd": "graph_request_missing_permissions",
                    "args": args
                })
                .to_string(),
                &state(),
            );
            let value: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert_eq!(
                value["error"],
                "Microsoft Graph sign-in is unavailable through the debug IPC bridge"
            );
            assert!(value.get("result").is_none());
        }
    }

    #[test]
    fn debug_bridge_rejects_native_association_and_unknown_commands() {
        for command in ["register_log_file_handler", "open_windows_default_apps"] {
            let response = dispatch(
                &serde_json::json!({ "cmd": command, "args": {} }).to_string(),
                &state(),
            );
            let value: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert_eq!(
                value["error"],
                "Windows file association commands require the Tauri runtime and are unavailable through the debug IPC bridge"
            );
            assert!(value.get("result").is_none());
        }

        let response = dispatch(
            &serde_json::json!({ "cmd": "definitely_not_a_command", "args": {} }).to_string(),
            &state(),
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            value["error"],
            "debug IPC bridge does not implement command `definitely_not_a_command`"
        );
        assert!(value.get("result").is_none());
    }
}
