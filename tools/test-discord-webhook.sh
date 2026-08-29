#!/usr/bin/env bash

set -euo pipefail

repository="${GITHUB_REPOSITORY:-adamgell/cmtraceopen}"
webhook_id="${GITHUB_WEBHOOK_ID:-671906967}"
hook_endpoint="repos/${repository}/hooks/${webhook_id}"

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required to send a real webhook test delivery." >&2
  exit 1
fi

if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated. Run: gh auth login" >&2
  exit 1
fi

hook_active="$(gh api "${hook_endpoint}" --jq '.active')"
if [[ "${hook_active}" != "true" ]]; then
  echo "GitHub webhook ${webhook_id} is not active." >&2
  exit 1
fi

subscribes_to_push="$(
  gh api "${hook_endpoint}" \
    --jq 'if (.events | index("push")) != null then "true" else "false" end'
)"
if [[ "${subscribes_to_push}" != "true" ]]; then
  echo "GitHub webhook ${webhook_id} is not subscribed to push events." >&2
  exit 1
fi

uses_github_endpoint="$(
  gh api "${hook_endpoint}" \
    --jq 'if (((.config.url // "") | rtrimstr("/")) | endswith("/github")) then "true" else "false" end'
)"
if [[ "${uses_github_endpoint}" != "true" ]]; then
  echo "GitHub webhook ${webhook_id} does not target the Discord GitHub endpoint." >&2
  exit 1
fi

echo "Triggering the latest real push delivery for ${repository}."
gh api --method POST "${hook_endpoint}/tests" >/dev/null
echo "GitHub accepted the test delivery. Check Discord #github-commits for the notification."
