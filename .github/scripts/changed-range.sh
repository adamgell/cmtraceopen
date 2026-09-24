#!/usr/bin/env bash
#
# Print the range the changed-range whitespace check should diff.
#
# Extracted from the workflow so the selection rule can be **executed** in a test
# rather than grepped out of the YAML. The rule is about which base is usable, and
# a test that only reads the workflow text cannot tell whether a valid root-commit
# base is being reclassified as missing.
#
# Usage: changed-range.sh <event-name> <before-sha> <pr-base-sha>
#
# Prints one of:
#   <sha>..HEAD           push, valid base
#   <sha>...HEAD          pull request, valid base
#   --empty-tree          no usable base: diff the empty tree against HEAD
#
# The contract, per the ruling on #589:
#
#   event          base              range
#   pull_request   ordinary commit   base...HEAD
#   pull_request   root commit       base...HEAD
#   merge_group    ordinary commit   base...HEAD
#   merge_group    root commit       base...HEAD
#   push           ordinary commit   base..HEAD
#   push           root commit       base..HEAD
#
# A merge group is the merge queue's temporary merge commit: it carries a base
# the same way a pull request does, and reporting the same range keeps the
# whitespace check meaningful there rather than widening it to the whole tree.
#   either         all-zero base     empty tree -> HEAD
#   either         missing base      empty tree -> HEAD
#
# A root commit is a *valid* base even though it has no parent, so it must never be
# reclassified as unavailable. Only an all-zero or unresolvable base is.
set -euo pipefail

event="${1:-}"
before="${2:-}"
pr_base="${3:-}"

if [[ "$event" == "pull_request" || "$event" == "merge_group" ]]; then
  base="$pr_base"
  separator="..."
else
  base="$before"
  separator=".."
fi

# An all-zero base means "no previous commit" (a new branch), which is a missing
# base rather than the root commit: there is nothing to compare against.
if [[ ! "$base" =~ ^[0-9a-f]{40}$ ]] || [[ "$base" =~ ^0+$ ]]; then
  printf '%s\n' "--empty-tree"
  exit 0
fi

if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  printf '%s\n' "--empty-tree"
  exit 0
fi

printf '%s%sHEAD\n' "$base" "$separator"
