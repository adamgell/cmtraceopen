#!/usr/bin/env python3
"""Fetch thread-aware PR review state and summarize CodeRabbit review cycles."""

from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any
from urllib.parse import urlparse

CODERABBIT_BOT_LOGINS = frozenset({
    "coderabbitai",
    "coderabbitai[bot]",
})
SUBPROCESS_TIMEOUT_SECONDS = 60


QUERY = r"""
query($owner: String!, $repo: String!, $number: Int!, $threads: String, $reviews: String, $skipThreads: Boolean!, $skipReviews: Boolean!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      number
      url
      headRefOid
      baseRefOid
      isDraft
      reviewDecision
      reviews(first: 100, after: $reviews) @skip(if: $skipReviews) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          state
          body
          submittedAt
          author { login }
          commit { oid }
        }
      }
      reviewThreads(first: 100, after: $threads) @skip(if: $skipThreads) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          resolvedBy { login }
          comments(first: 100) {
            pageInfo { hasNextPage endCursor }
            nodes {
              id
              body
              createdAt
              author { login }
            }
          }
        }
      }
    }
  }
}
"""

COMMENTS_QUERY = r"""
query($id: ID!, $comments: String) {
  node(id: $id) {
    ... on PullRequestReviewThread {
      comments(first: 100, after: $comments) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          body
          createdAt
          author { login }
        }
      }
    }
  }
}
"""


def run_json(command: list[str], stdin: str | None = None) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise SystemExit(
            f"command timed out after {SUBPROCESS_TIMEOUT_SECONDS} seconds"
        ) from error
    if result.returncode:
        raise SystemExit(result.stderr.strip() or "command failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("command returned invalid JSON") from error
    if not isinstance(payload, dict):
        raise SystemExit("command must return a JSON object")
    return payload


def _next_page_cursor(
    page_info: object,
    seen_cursors: set[str],
    label: str,
) -> str | None:
    if not isinstance(page_info, dict):
        raise SystemExit(f"{label} pageInfo is invalid")
    has_next_page = page_info.get("hasNextPage")
    if not isinstance(has_next_page, bool):
        raise SystemExit(f"{label} hasNextPage is invalid")
    if not has_next_page:
        return None
    cursor = page_info.get("endCursor")
    if (
        not isinstance(cursor, str)
        or not cursor
        or cursor in seen_cursors
    ):
        raise SystemExit(f"{label} pagination cursor is invalid")
    seen_cursors.add(cursor)
    return cursor


def current_pr() -> tuple[str, str, int]:
    data = run_json([
        "gh", "pr", "view", "--json",
        "number,url",
    ])
    path = urlparse(data["url"]).path.strip("/").split("/")
    if len(path) < 4 or path[-2] != "pull":
        raise SystemExit(f"unexpected pull request URL: {data['url']}")
    return path[-4], path[-3], int(data["number"])


def _pull_request_metadata(pr: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": pr["number"],
        "url": pr["url"],
        "head_sha": pr["headRefOid"],
        "base_sha": pr["baseRefOid"],
        "is_draft": pr["isDraft"],
        "review_decision": pr["reviewDecision"],
    }


def _complete_thread_comments(thread: dict[str, Any]) -> dict[str, Any]:
    page = thread["comments"]
    comments = list(page.get("nodes") or [])
    seen_cursors: set[str] = set()
    cursor = _next_page_cursor(
        page["pageInfo"],
        seen_cursors,
        "review thread comments",
    )
    while cursor is not None:
        command = [
            "gh", "api", "graphql",
            "-F", "query=@-",
            "-f", f"id={thread['id']}",
            "-f", f"comments={cursor}",
        ]
        payload = run_json(command, COMMENTS_QUERY)
        if payload.get("errors"):
            raise SystemExit(json.dumps(payload["errors"], indent=2))
        node = payload.get("data", {}).get("node")
        if not isinstance(node, dict):
            raise SystemExit(f"review thread disappeared: {thread['id']}")
        page = node["comments"]
        comments.extend(page.get("nodes") or [])
        cursor = _next_page_cursor(
            page["pageInfo"],
            seen_cursors,
            "review thread comments",
        )
    completed = dict(thread)
    completed["comments"] = {
        "nodes": list(
            {comment["id"]: comment for comment in comments}.values()
        ),
    }
    return completed


def _fetch_complete_snapshot(
    owner: str,
    repo: str,
    number: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    reviews: list[dict[str, Any]] = []
    threads: list[dict[str, Any]] = []
    reviews_cursor: str | None = None
    threads_cursor: str | None = None
    reviews_cursors: set[str] = set()
    threads_cursors: set[str] = set()
    reviews_done = False
    threads_done = False
    metadata: dict[str, Any] | None = None

    while True:
        command = [
            "gh", "api", "graphql",
            "-F", "query=@-",
            "-f", f"owner={owner}",
            "-f", f"repo={repo}",
            "-F", f"number={number}",
            "-F", f"skipReviews={'true' if reviews_done else 'false'}",
            "-F", f"skipThreads={'true' if threads_done else 'false'}",
        ]
        if reviews_cursor:
            command += ["-f", f"reviews={reviews_cursor}"]
        if threads_cursor:
            command += ["-f", f"threads={threads_cursor}"]

        payload = run_json(command, QUERY)
        if payload.get("errors"):
            raise SystemExit(json.dumps(payload["errors"], indent=2))

        pr = payload["data"]["repository"]["pullRequest"]
        page_metadata = _pull_request_metadata(pr)
        if metadata is None:
            metadata = page_metadata
        elif page_metadata != metadata:
            raise SystemExit("pull request changed during pagination")

        if not reviews_done:
            review_page = pr["reviews"]
            reviews.extend(review_page.get("nodes") or [])
            reviews_cursor = _next_page_cursor(
                review_page["pageInfo"],
                reviews_cursors,
                "reviews",
            )
            reviews_done = reviews_cursor is None
        if not threads_done:
            thread_page = pr["reviewThreads"]
            threads.extend(thread_page.get("nodes") or [])
            threads_cursor = _next_page_cursor(
                thread_page["pageInfo"],
                threads_cursors,
                "review threads",
            )
            threads_done = threads_cursor is None
        if reviews_done and threads_done:
            break

    assert metadata is not None
    reviews = list({review["id"]: review for review in reviews}.values())
    threads = list({thread["id"]: thread for thread in threads}.values())
    threads = [_complete_thread_comments(thread) for thread in threads]
    return metadata, reviews, threads


def _snapshot_identity(
    metadata: dict[str, Any],
    reviews: list[dict[str, Any]],
    threads: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized_threads = []
    for thread in sorted(threads, key=lambda item: item["id"]):
        normalized_thread = dict(thread)
        normalized_thread["comments"] = {
            "nodes": sorted(
                thread["comments"]["nodes"],
                key=lambda comment: comment["id"],
            ),
        }
        normalized_threads.append(normalized_thread)
    return {
        "pull_request": metadata,
        "reviews": sorted(reviews, key=lambda review: review["id"]),
        "threads": normalized_threads,
    }


def fetch(owner: str, repo: str, number: int) -> dict[str, Any]:
    first = _fetch_complete_snapshot(owner, repo, number)
    second = _fetch_complete_snapshot(owner, repo, number)
    if first[0] != second[0]:
        raise SystemExit("pull request changed during pagination")
    if _snapshot_identity(*first) != _snapshot_identity(*second):
        raise SystemExit("pull request review state changed during pagination")

    metadata, reviews, threads = second
    coderabbit_reviews = [
        review for review in reviews
        if is_coderabbit(review.get("author")) and review.get("submittedAt") is not None
    ]
    coderabbit_reviews.sort(key=lambda review: review.get("submittedAt") or "")
    unresolved = [thread for thread in threads if not thread["isResolved"]]
    unresolved_coderabbit = [
        thread
        for thread in unresolved
        if not thread["isOutdated"] and thread_has_coderabbit(thread)
    ]
    latest = coderabbit_reviews[-1] if coderabbit_reviews else None
    approved_at_head = bool(
        latest
        and latest.get("state") == "APPROVED"
        and (latest.get("commit") or {}).get("oid") == metadata["head_sha"]
    )

    return {
        "pull_request": metadata,
        "summary": {
            "review_count": len(reviews),
            "coderabbit_review_count": len(coderabbit_reviews),
            "unresolved_thread_count": len(unresolved),
            "unresolved_coderabbit_thread_count": len(unresolved_coderabbit),
            "latest_coderabbit_review": latest,
            "latest_coderabbit_review_state": latest.get("state") if latest else None,
            "approved_at_head": approved_at_head,
        },
        "unresolved_threads": unresolved,
        "reviews": reviews,
    }


def is_coderabbit(author: dict[str, Any] | None) -> bool:
    login = (author or {}).get("login")
    return (
        isinstance(login, str)
        and login.casefold() in CODERABBIT_BOT_LOGINS
    )


def thread_has_coderabbit(thread: dict[str, Any]) -> bool:
    return any(
        is_coderabbit(comment.get("author"))
        for comment in thread["comments"]["nodes"]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help="owner/name; defaults to current branch PR")
    parser.add_argument("--pr", type=int, help="PR number; defaults to current branch PR")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.repo or args.pr:
        if not args.repo or not args.pr:
            raise SystemExit("--repo and --pr must be provided together")
        owner, repo = args.repo.split("/", 1)
        number = args.pr
    else:
        owner, repo, number = current_pr()

    print(json.dumps(fetch(owner, repo, number), indent=2))


if __name__ == "__main__":
    main()
