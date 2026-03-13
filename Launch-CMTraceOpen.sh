#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH_SCRIPT="${SCRIPT_DIR}/scripts/Launch-CMTraceOpen.sh"

if [ ! -f "${LAUNCH_SCRIPT}" ]; then
  echo "Launcher script not found: ${LAUNCH_SCRIPT}" >&2
  exit 1
fi

exec /usr/bin/env bash "${LAUNCH_SCRIPT}" "$@"
