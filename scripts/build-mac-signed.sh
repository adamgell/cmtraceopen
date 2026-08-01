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
# Note: --no-bundle is intentionally NOT supported and is rejected with exit
# 2 rather than forwarded. On macOS the signing happens at the .app bundle
# level (the bundled Mach-O is signed, then the .app envelope is signed). A
# bare unbundled binary isn't a normal macOS distribution shape, so there's
# no signed "exe-only" mode.

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

# ── Inspect the forwarded Tauri args ───────────────────────────────────────
# --no-bundle is rejected rather than forwarded: signing happens at the .app
# bundle level, so a bundle-less build has nothing to sign and would
# otherwise exit 0 having produced no distributable artifact.
# --debug and --target/-t decide where Tauri writes the bundle, which the
# post-build validation below needs in order to find it.
BUILD_PROFILE="release"
BUILD_TARGET=""
PREV_ARG=""
for arg in "$@"; do
    case "${arg}" in
        --no-bundle)
            echo "error: --no-bundle is not supported by this signed build flow." >&2
            echo "       See the note at the top of this script." >&2
            exit 2
            ;;
        --debug)
            BUILD_PROFILE="debug"
            ;;
        --target=*)
            BUILD_TARGET="${arg#--target=}"
            ;;
        *)
            if [[ "${PREV_ARG}" == "--target" || "${PREV_ARG}" == "-t" ]]; then
                BUILD_TARGET="${arg}"
            fi
            ;;
    esac
    PREV_ARG="${arg}"
done

# ── Build the --config overlay JSON ────────────────────────────────────────
# Built with node rather than ad-hoc string concat so identity values
# containing parentheses, spaces, or quotes survive the round-trip safely.
# node is used in preference to python3 because this script already requires
# it for `npx tauri`, so the overlay adds no new runtime dependency.
CONFIG_OVERLAY=$(
    node -e 'process.stdout.write(JSON.stringify({
        bundle: { macOS: { signingIdentity: process.env.APPLE_SIGNING_IDENTITY } }
    }))'
)

# ── Write config overlay to a temp file ────────────────────────────────────
# `tauri build --config` expects a file path, not an inline JSON string.
CONFIG_FILE=$(mktemp "${TMPDIR:-/tmp}/cmtrace_tauri_conf_XXXXXX.json")
printf '%s' "${CONFIG_OVERLAY}" > "${CONFIG_FILE}"

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

# A reference file created immediately before the build. An artifact only
# counts as this build's output if it is newer than the stamp, so a stale
# bundle from an earlier run can never stand in for one this build failed to
# produce. `-newer` is used rather than `-mmin` because BSD find (macOS) has
# no -mmin. The build log is captured so the soft-fail below can confirm
# *which* failure it is looking at.
BUILD_STAMP=$(mktemp "${TMPDIR:-/tmp}/cmtrace_build_stamp_XXXXXX")
BUILD_LOG=$(mktemp "${TMPDIR:-/tmp}/cmtrace_build_log_XXXXXX")
trap 'rm -f "${CONFIG_FILE}" "${BUILD_STAMP}" "${BUILD_LOG}"' EXIT

set +e
npx tauri build --config "${CONFIG_FILE}" "$@" 2>&1 | tee "${BUILD_LOG}"
TAURI_EXIT=${PIPESTATUS[0]}
set -e

# ── Locate this build's deliverables ───────────────────────────────────────
if [[ -n "${BUILD_TARGET}" ]]; then
    BUNDLE_DIR="${REPO_ROOT}/src-tauri/target/${BUILD_TARGET}/${BUILD_PROFILE}/bundle"
else
    BUNDLE_DIR="${REPO_ROOT}/src-tauri/target/${BUILD_PROFILE}/bundle"
fi

APP_PATH=$(find "${BUNDLE_DIR}/macos" -maxdepth 1 -name "*.app" -type d \
    -newer "${BUILD_STAMP}" 2>/dev/null | head -1)
DMG_PATH=$(find "${BUNDLE_DIR}/dmg" -maxdepth 1 -name "*.dmg" \
    -newer "${BUILD_STAMP}" 2>/dev/null | head -1)

# ── Validate the deliverables ──────────────────────────────────────────────
# This runs on the success path as well, because a zero exit from Tauri is
# not by itself evidence that a *signed* .app was produced. Shipping an
# unsigned or unnotarized build to direct download is the failure this
# guards against. `codesign` alone is the right check when notarization was
# not attempted, which is the documented signed-but-not-notarized fallback.
validate_deliverables() {
    if [[ -z "${APP_PATH}" ]]; then
        echo "error: no .app newer than the build stamp under ${BUNDLE_DIR}/macos." >&2
        return 1
    fi
    if ! codesign --verify --deep --strict "${APP_PATH}" >/dev/null 2>&1; then
        echo "error: code signature missing or invalid: ${APP_PATH}" >&2
        return 1
    fi
    if [[ "${NOTARIZE_MODE}" != "none" ]] \
        && ! xcrun stapler validate "${APP_PATH}" >/dev/null 2>&1; then
        echo "error: notarization ticket missing or invalid: ${APP_PATH}" >&2
        return 1
    fi
    if [[ -z "${DMG_PATH}" ]]; then
        echo "warning: no .dmg newer than the build stamp under ${BUNDLE_DIR}/dmg." >&2
    fi
    return 0
}

# ── Soft-fail handling for the updater signing step ────────────────────────
# With "createUpdaterArtifacts": true, Tauri runs an updater-signing step
# after the DMG is built. It fails when TAURI_SIGNING_PRIVATE_KEY isn't set,
# even though the .app and .dmg are already signed (and notarized). ONLY that
# specific failure is downgraded to a warning, identified by the variable
# being unset *and* named in the build output. Every other non-zero exit is a
# real build failure and is propagated unchanged, so an unrelated error can
# never be reported as a successful build.
if [[ ${TAURI_EXIT} -ne 0 ]]; then
    if [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]] \
        || ! grep -qi "TAURI_SIGNING_PRIVATE_KEY" "${BUILD_LOG}"; then
        echo "error: tauri build failed with exit ${TAURI_EXIT}." >&2
        exit "${TAURI_EXIT}"
    fi

    validate_deliverables || exit "${TAURI_EXIT}"

    cat >&2 <<EOF
warning: tauri build exited ${TAURI_EXIT}, but the signed .app is present and
         its signature is valid. The exit code is from the updater-bundle
         signing step (TAURI_SIGNING_PRIVATE_KEY is not set).
         Treating as success.
EOF
else
    validate_deliverables || exit 1
fi

echo
echo "Built artifacts:"
echo "  ${APP_PATH}"
if [[ -n "${DMG_PATH}" ]]; then
    echo "  ${DMG_PATH}"
fi
