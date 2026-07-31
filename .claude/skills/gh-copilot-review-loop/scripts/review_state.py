#!/usr/bin/env python3
"""Fetch thread-aware PR review state and summarize Copilot review cycles."""

from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any


REVIEWS_QUERY = r"""
query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      number
      url
      headRefOid
      isDraft
      reviewDecision
      reviews(first: 100, after: $cursor) {
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
    }
  }
}
"""

THREADS_QUERY = r"""
query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $cursor) {
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


def paginate(query: str, owner: str, repo: str, number: int, connection_path: tuple[str, ...]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = []
    metadata: dict[str, Any] | None = None
    cursor: str | None = None

    while True:
        command = [
            "gh", "api", "graphql",
            "-F", "query=@-",
            "-F", f"owner={owner}",
            "-F", f"repo={repo}",
            "-F", f"number={number}",
        ]
        if cursor:
            command += ["-F", f"cursor={cursor}"]

        payload = run_json(command, query)
        if payload.get("errors"):
            raise SystemExit(json.dumps(payload["errors"], indent=2))

        pr = payload["data"]["repository"]["pullRequest"]
        if metadata is None:
            metadata = pr

        connection = pr
        for key in connection_path:
            connection = connection[key]
        nodes.extend(connection.get("nodes") or [])
        cursor = (
            connection["pageInfo"]["endCursor"]
            if connection["pageInfo"]["hasNextPage"] else None
        )
        if not cursor:
            break

    assert metadata is not None
    return metadata, nodes


def fetch(owner: str, repo: str, number: int) -> dict[str, Any]:
    pr_metadata, reviews = paginate(REVIEWS_QUERY, owner, repo, number, ("reviews",))
    _, threads = paginate(THREADS_QUERY, owner, repo, number, ("reviewThreads",))

    metadata = {
        "number": pr_metadata["number"],
        "url": pr_metadata["url"],
        "head_sha": pr_metadata["headRefOid"],
        "is_draft": pr_metadata["isDraft"],
        "review_decision": pr_metadata["reviewDecision"],
    }

    reviews = list({review["id"]: review for review in reviews}.values())
    threads = list({thread["id"]: thread for thread in threads}.values())
    copilot_reviews = [review for review in reviews if is_copilot(review.get("author"))]
    copilot_reviews.sort(key=lambda review: review.get("submittedAt") or "")
    unresolved = [
        thread for thread in threads
        if not thread["isResolved"] and not thread["isOutdated"]
    ]
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
