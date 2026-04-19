/**
 * Tauri IPC shim for Playwright e2e tests.
 *
 * When the app runs in a plain browser (Vite dev server, no Tauri WebView),
 * `window.__TAURI_INTERNALS__` is absent. The `@tauri-apps/api` package checks
 * for this global before making IPC calls and will throw if it's missing.
 *
 * Inject this shim with `page.addInitScript()` before any page scripts run so
 * the app boots cleanly.
 *
 * IPC bridge (`:1422`)
 * --------------------
 * When the full Tauri app is also running (e.g. `npm run app:dev`), it starts
 * a lightweight HTTP IPC bridge on `127.0.0.1:1422`. The shim probes that port
 * at startup. If the bridge is up, all `invoke()` calls are forwarded to it so
 * the browser gets real Rust responses — real log parsing, real workspaces, real
 * error codes. If the bridge is unreachable the shim falls back to static defaults
 * so tests still work with just `npm run frontend:dev`.
 *
 * Per-test overrides
 * ------------------
 * Push handler functions into `window.__e2e_ipc_overrides__` to control specific
 * command responses regardless of bridge availability:
 *
 *   await page.evaluate(() => {
 *     window.__e2e_ipc_overrides__["open_log_file"] = () => ({ entries: [], ... });
 *   });
 */

/** Default responses keyed by Tauri command name. */
const DEFAULT_RESPONSES: Record<string, unknown> = {
  parse_file: { entries: [], parse_quality: "Unstructured", parser_kind: "PlainText" },
  get_recent_files: [],
  get_file_info: null,
  tail_file: null,
  stop_tail: null,
  get_error_details: null,
  parse_intune_logs: { timeline: [], downloads: [], events: [] },
  get_app_version: "0.0.0-e2e",
  // Startup commands — must return valid values so the app fully renders
  get_initial_file_paths: [],
  get_available_workspaces: [
    "log",
    "intune",
    "new-intune",
    "dsregcmd",
    "deployment",
    "event-log",
    "sysmon",
    "secureboot",
  ],
  get_known_log_sources: [],
  get_file_association_prompt_status: "dismissed",
};

/** Script string injected into the browser page before React loads. */
export const TAURI_SHIM_SCRIPT = `
(function () {
  if (window.__TAURI_INTERNALS__) return; // Already set by a real Tauri WebView

  window.__e2e_ipc_overrides__ = {};

  const defaults = ${JSON.stringify(DEFAULT_RESPONSES)};

  // IPC bridge URL — set to a live value when the bridge probe succeeds.
  // Commands dispatched before the probe resolves fall back to defaults.
  let bridgeUrl = null;

  // Probe the IPC bridge at :1422. Fire-and-forget; result updates bridgeUrl.
  fetch('http://127.0.0.1:1422/', { method: 'GET', signal: AbortSignal.timeout(500) })
    .then(r => {
      if (r.ok) {
        bridgeUrl = 'http://127.0.0.1:1422';
        console.info('[tauri-shim] IPC bridge connected at', bridgeUrl);
      }
    })
    .catch(() => {
      console.info('[tauri-shim] IPC bridge not available — using static defaults');
    });

  // Callback registry used by Channel and event listeners
  const callbacks = new Map();
  let nextId = 1;

  function registerCallback(callback, once) {
    const id = nextId++;
    callbacks.set(id, (data) => {
      if (once) callbacks.delete(id);
      callback(data);
    });
    return id;
  }

  function unregisterCallback(id) {
    callbacks.delete(id);
  }

  function runCallback(id, data) {
    const cb = callbacks.get(id);
    if (cb) cb(data);
  }

  // plugin:dialog|open — show a real browser <input type="file"> picker.
  // Returns an array of absolute-looking paths. In a browser we only get File
  // objects (name + content), not OS paths. We write each file to the IPC bridge
  // (/upload) so the Rust side can persist them to a temp dir and return real paths.
  function handleDialogOpen(args) {
    const opts = (args && args.options) || {};
    return new Promise((resolve) => {
      const input = document.createElement('input');
      input.type = 'file';
      input.multiple = !!opts.multiple;
      if (opts.directory) input.setAttribute('webkitdirectory', '');
      // Build accept string from filters
      if (opts.filters && opts.filters.length) {
        const exts = opts.filters.flatMap(f => f.extensions || []);
        if (exts.length && !exts.includes('*')) {
          input.accept = exts.map(e => '.' + e).join(',');
        }
      }
      input.style.display = 'none';
      document.body.appendChild(input);

      input.onchange = async () => {
        const files = Array.from(input.files || []);
        document.body.removeChild(input);
        if (!files.length) { resolve(null); return; }

        // If bridge is up: upload files so Rust can write them to a temp dir
        // and give us real absolute paths for parsing.
        if (bridgeUrl) {
          try {
            const fd = new FormData();
            files.forEach(f => fd.append('files', f, f.name));
            const res = await fetch(bridgeUrl + '/upload', { method: 'POST', body: fd });
            const data = await res.json();
            if (data.paths && data.paths.length) {
              resolve(opts.multiple ? data.paths : data.paths[0]);
              return;
            }
          } catch (e) {
            console.warn('[tauri-shim] upload failed:', e.message);
          }
        }

        // Fallback: return blob URLs (no real parsing, but UI won't hang)
        const urls = files.map(f => URL.createObjectURL(f));
        resolve(opts.multiple ? urls : urls[0]);
      };

      input.oncancel = () => {
        document.body.removeChild(input);
        resolve(null);
      };

      input.click();
    });
  }

  // Handle plugin:event|* commands used by listen()/emit()/unlisten()
  function handleEventPlugin(cmd, args) {
    switch (cmd) {
      case 'plugin:event|listen': {
        const handler = args && args.handler;
        return Promise.resolve(handler != null ? handler : 0);
      }
      case 'plugin:event|unlisten':
      case 'plugin:event|emit':
        return Promise.resolve(null);
      default:
        return Promise.resolve(null);
    }
  }

  // Forward an invoke call to the real Rust IPC bridge.
  async function callBridge(cmd, args) {
    const res = await fetch(bridgeUrl + '/invoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cmd, args }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await res.json();
    if (data.error) throw new Error('[IPC bridge] ' + data.error);
    return data.result;
  }

  window.__TAURI_INTERNALS__ = {
    ipc: function () { /* no-op transport */ },
    invoke: async function (cmd, args) {
      if (cmd.startsWith('plugin:event|')) return handleEventPlugin(cmd, args);
      if (cmd === 'plugin:dialog|open') return handleDialogOpen(args);
      if (cmd === 'plugin:dialog|save' || cmd === 'plugin:dialog|message' || cmd === 'plugin:dialog|ask' || cmd === 'plugin:dialog|confirm') return Promise.resolve(null);

      // 1. Per-test overrides take highest precedence
      const override = window.__e2e_ipc_overrides__[cmd];
      if (override) return override(args);

      // 2. If the IPC bridge is up, use the real Rust backend
      if (bridgeUrl) {
        try {
          return await callBridge(cmd, args);
        } catch (e) {
          console.warn('[tauri-shim] bridge call failed for', cmd, '—', e.message, '— falling back to default');
        }
      }

      // 3. Static defaults (bridge not running or call failed)
      return defaults[cmd] !== undefined ? defaults[cmd] : null;
    },
    transformCallback: registerCallback,
    unregisterCallback: unregisterCallback,
    runCallback: runCallback,
    callbacks: callbacks,
    convertFileSrc: function (filePath) { return filePath; },
    metadata: {
      currentWindow: { label: "main" },
      currentWebview: { windowLabel: "main", label: "main" },
      windows: [{ label: "main" }],
      plugins: [],
    },
  };

  // Required by @tauri-apps/api/event for listen()/unlisten() cleanup
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
    unregisterListener: function (_event, id) { unregisterCallback(id); },
  };

  // Stub plugin globals expected by @tauri-apps/plugin-os
  window.__TAURI_OS_PLUGIN_INTERNALS__ = { platform: "windows" };
})();
`;
