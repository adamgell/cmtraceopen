#!/usr/bin/env python3
"""Fetch thread-aware PR review state and summarize Copilot review cycles."""

from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any


QUERY = r"""
query($owner: String!, $repo: String!, $number: Int!, $threads: String, $reviews: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      number
      url
      headRefOid
      isDraft
      reviewDecision
      reviews(first: 100, after: $reviews) {
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
      reviewThreads(first: 100, after: $threads) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          resolvedBy { login }
          comments(first: 100) {
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


def run_json(command: list[str], stdin: str | None = None) -> dict[str, Any]:
    result = subprocess.run(command, input=stdin, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or "command failed")
    return json.loads(result.stdout)


def current_pr() -> tuple[str, str, int]:
    data = run_json([
        "gh", "pr", "view", "--json",
        "number,headRepositoryOwner,headRepository",
    ])
    return (
        data["headRepositoryOwner"]["login"],
        data["headRepository"]["name"],
        int(data["number"]),
    )


def fetch(owner: str, repo: str, number: int) -> dict[str, Any]:
    reviews: list[dict[str, Any]] = []
    threads: list[dict[str, Any]] = []
    reviews_cursor: str | None = None
    threads_cursor: str | None = None
    metadata: dict[str, Any] | None = None

    while True:
        command = [
            "gh", "api", "graphql",
            "-F", "query=@-",
            "-F", f"owner={owner}",
            "-F", f"repo={repo}",
            "-F", f"number={number}",
        ]
        if reviews_cursor:
            command += ["-F", f"reviews={reviews_cursor}"]
        if threads_cursor:
            command += ["-F", f"threads={threads_cursor}"]

        payload = run_json(command, QUERY)
        if payload.get("errors"):
            raise SystemExit(json.dumps(payload["errors"], indent=2))

        pr = payload["data"]["repository"]["pullRequest"]
        if metadata is None:
            metadata = {
                "number": pr["number"],
                "url": pr["url"],
                "head_sha": pr["headRefOid"],
                "is_draft": pr["isDraft"],
                "review_decision": pr["reviewDecision"],
            }

        review_page = pr["reviews"]
        thread_page = pr["reviewThreads"]
        reviews.extend(review_page.get("nodes") or [])
        threads.extend(thread_page.get("nodes") or [])
        reviews_cursor = (
            review_page["pageInfo"]["endCursor"]
            if review_page["pageInfo"]["hasNextPage"] else None
        )
        threads_cursor = (
            thread_page["pageInfo"]["endCursor"]
            if thread_page["pageInfo"]["hasNextPage"] else None
        )
        if not reviews_cursor and not threads_cursor:
            break

    assert metadata is not None
    reviews = list({review["id"]: review for review in reviews}.values())
    threads = list({thread["id"]: thread for thread in threads}.values())
    copilot_reviews = [review for review in reviews if is_copilot(review.get("author"))]
    copilot_reviews.sort(key=lambda review: review.get("submittedAt") or "")
    unresolved = [thread for thread in threads if not thread["isResolved"]]
    unresolved_copilot = [thread for thread in unresolved if thread_has_copilot(thread)]

    return {
        "pull_request": metadata,
        "summary": {
            "review_count": len(reviews),
            "copilot_review_count": len(copilot_reviews),
            "unresolved_thread_count": len(unresolved),
            "unresolved_copilot_thread_count": len(unresolved_copilot),
            "latest_copilot_review": copilot_reviews[-1] if copilot_reviews else None,
        },
        "unresolved_threads": unresolved,
        "reviews": reviews,
    }


def is_copilot(author: dict[str, Any] | None) -> bool:
    return "copilot" in (author or {}).get("login", "").lower()


def thread_has_copilot(thread: dict[str, Any]) -> bool:
    return any(
        is_copilot(comment.get("author"))
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
