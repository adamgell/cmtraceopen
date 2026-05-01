#!/usr/bin/env bash
# Build CMTrace Open for macOS with Developer ID signing (and optional notarization).
#
# All credentials come from environment variables — nothing is hardcoded so the
# script is safe to commit and contributors can configure their own identity.
#
# Required:
#   APPLE_SIGNING_IDENTITY    Full identity string from `security find-identity
#                             -v -p codesigning`, e.g.
#                             "Developer ID Application: Jane Doe (ABC1234567)"
#
# Optional (for notarization):
#   APPLE_API_KEY             App Store Connect API key ID
#   APPLE_API_ISSUER          App Store Connect API issuer UUID
#   APPLE_API_KEY_PATH        Path to the .p8 private key file
#
#   --- OR (legacy, less preferred) ---
#   APPLE_ID                  Apple ID email
#   APPLE_PASSWORD            App-specific password
#   APPLE_TEAM_ID             10-character team ID
#
# Notarization is automatic if the credentials are present; otherwise the
# script signs but skips notarization. A Developer ID-signed but unnotarized
# build will Gatekeeper-warn on first launch (right-click → Open accepts it).
#
# Why this script overrides via --config rather than the env var directly:
# tauri.conf.json keeps "signingIdentity": "-" as the default so contributors
# without an Apple Developer cert can still produce ad-hoc-signed builds. The
# JSON value takes precedence over APPLE_SIGNING_IDENTITY when both are set,
# so this script forwards a `--config` overlay that swaps the identity at
# build time without touching the file on disk.
#
# Usage:
#   ./scripts/build-mac-signed.sh                # release: signed .app + DMG
#   ./scripts/build-mac-signed.sh --debug        # debug: signed .app + DMG
#
# Note: --no-bundle is intentionally NOT supported. On macOS the signing
# happens at the .app bundle level (the bundled Mach-O is signed, then the
# .app envelope is signed). A bare unbundled binary isn't a normal macOS
# distribution shape, so there's no signed "exe-only" mode.

set -euo pipefail

# ── Resolve repo root from script location ─────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# ── Auto-load .env.local if present ────────────────────────────────────────
# Convention: developers copy .env.example → .env.local (gitignored) and
# fill in their signing/notarization credentials there. We source it before
# validating env vars below so they take effect for this build.
if [[ -f "${REPO_ROOT}/.env.local" ]]; then
    # shellcheck disable=SC1091
    set -a; source "${REPO_ROOT}/.env.local"; set +a
    echo "info: loaded credentials from ${REPO_ROOT}/.env.local"
fi

# ── Validate signing identity ──────────────────────────────────────────────
if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
    cat >&2 <<'EOF'
error: APPLE_SIGNING_IDENTITY is not set.

Pick an identity from your keychain:
    security find-identity -v -p codesigning

Then export it:
    export APPLE_SIGNING_IDENTITY="Developer ID Application: Jane Doe (ABC1234567)"

For unsigned ad-hoc builds (which is what contributors without a cert get
by default), use `npm run app:build:release` instead — it reads the
"signingIdentity": "-" entry in tauri.conf.json.
EOF
    exit 1
fi

# ── Detect notarization mode ───────────────────────────────────────────────
NOTARIZE_MODE="none"
if [[ -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_ISSUER:-}" && -n "${APPLE_API_KEY_PATH:-}" ]]; then
    NOTARIZE_MODE="api-key"
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then
    NOTARIZE_MODE="apple-id"
fi

# ── Build the --config overlay JSON ────────────────────────────────────────
# Use python rather than ad-hoc string concat so identity values containing
# parentheses, spaces, or quotes survive the round-trip safely.
CONFIG_OVERLAY=$(
    python3 -c '
import json, os, sys
overlay = {
    "bundle": {
        "macOS": {
            "signingIdentity": os.environ["APPLE_SIGNING_IDENTITY"]
        }
    }
}
json.dump(overlay, sys.stdout)
'
)

# ── Echo plan ──────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────────"
echo "  CMTrace Open: signed macOS build"
echo "──────────────────────────────────────────────────────────────────"
echo "  Identity:     ${APPLE_SIGNING_IDENTITY}"
echo "  Notarize:     ${NOTARIZE_MODE}"
echo "  Tauri args:   $*"
echo "──────────────────────────────────────────────────────────────────"

# ── Run Tauri build ────────────────────────────────────────────────────────
# Tauri reads APPLE_API_KEY*, APPLE_ID/PASSWORD/TEAM_ID directly from the
# environment for notarization. We pass the signing identity via --config
# so it overrides the on-disk default of "-".
exec npx tauri build --config "${CONFIG_OVERLAY}" "$@"
