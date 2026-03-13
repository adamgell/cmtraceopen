#!/usr/bin/env bash
set -euo pipefail

PATTERN_FILE=".github/no-ai-attribution-patterns.txt"

if [[ ! -f "$PATTERN_FILE" ]]; then
  echo "Pattern file not found: $PATTERN_FILE"
  exit 1
fi

mapfile -t PATTERNS < <(grep -vE '^\s*#|^\s*$' "$PATTERN_FILE")

if [[ ${#PATTERNS[@]} -eq 0 ]]; then
  echo "No active patterns found in $PATTERN_FILE"
  exit 1
fi

VIOLATIONS=0

check_text_block() {
  local source="$1"
  local text="$2"

  local idx=0
  while IFS= read -r line; do
    idx=$((idx + 1))
    for pattern in "${PATTERNS[@]}"; do
      if echo "$line" | grep -Eiq "$pattern"; then
        echo "::error title=No AI Attribution Policy::$source line $idx matches blocked pattern '$pattern': $line"
        VIOLATIONS=1
      fi
    done
  done <<< "$text"
}

event_name="${GITHUB_EVENT_NAME:-}"
event_path="${GITHUB_EVENT_PATH:-}"

if [[ -z "$event_name" || -z "$event_path" ]]; then
  echo "Missing GitHub event context."
  exit 1
fi

range=""

if [[ "$event_name" == "pull_request" ]]; then
  base_ref="$(jq -r '.pull_request.base.ref' "$event_path")"
  git fetch --no-tags --depth=1 origin "$base_ref"
  range="origin/$base_ref..HEAD"

  pr_title="$(jq -r '.pull_request.title // ""' "$event_path")"
  pr_body="$(jq -r '.pull_request.body // ""' "$event_path")"

  check_text_block "PR title" "$pr_title"
  check_text_block "PR body" "$pr_body"
else
  before_sha="$(jq -r '.before // ""' "$event_path")"
  after_sha="$(jq -r '.after // ""' "$event_path")"

  if [[ -z "$after_sha" ]]; then
    echo "Unable to determine push range from event payload."
    exit 1
  fi

  if [[ -z "$before_sha" || "$before_sha" == "0000000000000000000000000000000000000000" ]]; then
    range="$after_sha"
  else
    range="$before_sha..$after_sha"
  fi
fi

commit_messages="$(git log --format='%H%n%s%n%b%n---' $range || true)"
check_text_block "Commit messages ($range)" "$commit_messages"

if [[ "$VIOLATIONS" -ne 0 ]]; then
  echo "Policy check failed: explicit AI attribution markers were found."
  exit 1
fi

echo "Policy check passed: no blocked AI attribution markers found."
