#!/usr/bin/env bash
set -euo pipefail

write_step() {
  printf '==> %s\n' "$1"
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  ./Launch-CMTraceOpen.sh [dev|build|build-and-run] [--install-dependencies]
  ./scripts/Launch-CMTraceOpen.sh [dev|build|build-and-run] [--install-dependencies]
  ./scripts/Launch-CMTraceOpen.sh --mode <dev|build|build-and-run> [--install-dependencies]

Modes:
  dev            Run `npm run app:dev` with Vite hot reload for frontend changes.
  build          Run `npm run app:build:release`.
  build-and-run  Build the macOS app bundle and open it with `open`.

Accepted aliases:
  dev, Dev
  build, Build
  build-and-run, buildandrun, BuildAndRun

Options:
  --install-dependencies  Force `npm install` before running.
  -h, --help              Show this help text.
EOF
}

ensure_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Required command not found on PATH: $1"
  fi
}

invoke_checked_command() {
  local command_display
  command_display="$*"
  write_step "$command_display"

  if ! "$@"; then
    fail "Command failed: ${command_display}"
  fi
}

resolve_mode_script() {
  case "$1" in
    Dev)
      printf 'app:dev\n'
      ;;
    Build|BuildAndRun)
      printf 'app:build:release\n'
      ;;
    *)
      fail "Invalid mode '$1'. Expected one of: Dev, Build, or BuildAndRun."
      ;;
  esac
}

resolve_built_artifact_path() {
  local app_root="$1"
  local bundle_dir="${app_root}/src-tauri/target/release/bundle/macos"
  local default_app="${bundle_dir}/CMTrace Open.app"
  local discovered_app

  if [ -d "${default_app}" ]; then
    printf '%s\n' "${default_app}"
    return 0
  fi

  if [ ! -d "${bundle_dir}" ]; then
    fail "Built app bundle directory was not found at '${bundle_dir}'."
  fi

  discovered_app="$(find "${bundle_dir}" -maxdepth 1 -type d -name '*.app' | head -n 1)"
  if [ -n "${discovered_app}" ]; then
    printf '%s\n' "${discovered_app}"
    return 0
  fi

  fail "No built macOS app bundle was found in '${bundle_dir}'."
}

validate_mode() {
  case "$1" in
    dev|Dev|build|Build|build-and-run|buildandrun|BuildAndRun)
      ;;
    *)
      fail "Invalid mode '$1'. Expected one of: dev, build, or build-and-run."
      ;;
  esac
}

normalize_mode() {
  case "$1" in
    dev|Dev)
      printf 'Dev\n'
      ;;
    build|Build)
      printf 'Build\n'
      ;;
    build-and-run|buildandrun|BuildAndRun)
      printf 'BuildAndRun\n'
      ;;
    *)
      fail "Invalid mode '$1'. Expected one of: dev, build, or build-and-run."
      ;;
  esac
}

if [ "$(uname -s)" != "Darwin" ]; then
  fail "This launcher is intended for macOS. Use the existing Windows launcher or run npm/Tauri commands directly on other platforms."
fi

mode="Dev"
install_dependencies=0
mode_set=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    dev|Dev|build|Build|build-and-run|buildandrun|BuildAndRun)
      if [ "${mode_set}" -eq 1 ]; then
        fail "Mode was specified more than once."
      fi
      mode="$(normalize_mode "$1")"
      mode_set=1
      ;;
    --mode)
      shift
      if [ "$#" -eq 0 ]; then
        fail "--mode requires a value."
      fi
      validate_mode "$1"
      if [ "${mode_set}" -eq 1 ]; then
        fail "Mode was specified more than once."
      fi
      mode="$(normalize_mode "$1")"
      mode_set=1
      ;;
    --install-dependencies)
      install_dependencies=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
  shift
done

script_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
app_root="$(cd "${script_root}/.." && pwd)"
node_modules_path="${app_root}/node_modules"

ensure_command npm

if [ "${mode}" = "BuildAndRun" ]; then
  ensure_command open
fi

cd "${app_root}"

if [ "${install_dependencies}" -eq 1 ] || [ ! -d "${node_modules_path}" ]; then
  invoke_checked_command npm install
else
  write_step "Skipping npm install because node_modules already exists. Use --install-dependencies to force reinstall."
fi

npm_script="$(resolve_mode_script "${mode}")"
invoke_checked_command npm run "${npm_script}"

case "${mode}" in
  BuildAndRun)
    built_app="$(resolve_built_artifact_path "${app_root}")"
    write_step "Launching built app from '${built_app}'"
    invoke_checked_command open "${built_app}"
    ;;
esac
