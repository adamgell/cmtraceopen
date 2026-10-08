#!/bin/bash
# SessionStart hook for Claude Code cloud sessions: installs what CI needs so
# cargo/clippy/vitest/tsc work out of the box. Idempotent and non-interactive.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

# Tauri v2 Linux build dependencies (mirrors .github/workflows/cmtrace-ci.yml).
# Skipped when already present so cached containers start fast.
if ! dpkg -s libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev patchelf >/dev/null 2>&1; then
  SUDO=""
  [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  export DEBIAN_FRONTEND=noninteractive
  # Never let sudo prompt: without passwordless sudo, warn and continue so the
  # Rust and npm setup below still runs (cargo will lack the GTK/WebKit libs).
  if [ -n "$SUDO" ] && ! sudo -n true 2>/dev/null; then
    echo "warning: passwordless sudo unavailable; skipping apt package install" >&2
  else
    $SUDO apt-get update -qq
    $SUDO apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
      librsvg2-dev patchelf pkg-config
  fi
fi

# Rust: rust-toolchain.toml pins the channel and clippy; add the wasm target
# that the parser-purity check uses.
rustup show active-toolchain >/dev/null 2>&1 || rustup toolchain install
rustup target add wasm32-unknown-unknown

# Frontend dependencies. npm ci (not install): npm 10 rewrites package-lock.json
# (drops the "libc" fields), which would leave every session with a dirty tree.
npm ci --no-audit --no-fund

# Warm the Rust dependency cache; non-fatal if the network hiccups.
(cd src-tauri && cargo fetch --locked) || echo "cargo fetch failed (non-fatal)" >&2
